use std::collections::HashMap;

use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::crash::BreadcrumbRing;
use crate::diag::EnvDiag;
use crate::error::EmuResult;
use crate::jni::handler::{DefaultJniHandler, JniContext, JniHandler};
use crate::jni::types::{
    FieldDesc, JObject, JObjectRef, JValue, MethodDesc, ObjectTable, RegisteredNative, JNI_ABORT,
    JNI_ERR, JNI_FALSE, JNI_OK, JNI_TRUE, JNI_VERSION_1_6,
};
use crate::jni::va_list::{
    read_varargs_direct, read_varargs_jvalue_array, read_varargs_va_list,
};
use crate::loader::dex::{is_system_or_array_class, DexIndex, DexValue};
use crate::memory::{read_guest_cstr, read_guest_u64, MemoryManager, PAGE_SIZE};
use crate::os::DeviceProfile;

/// `JavaVM` 指针与 `JNIInvokeInterface` 虚函数表基址
pub const JNI_VM_BASE: u64 = 0x1800_0000;
/// `JNIEnv` 指针与 `JNINativeInterface` 虚函数表基址
pub const JNI_ENV_BASE: u64 = 0x1800_1000;
/// JNI 跳板区基址与大小（所有 JNI 函数指针均指向此处 4 字节 `RET` 槽位）
pub const JNI_TRAMPOLINE_BASE: u64 = 0x1801_0000;
pub const JNI_TRAMPOLINE_SIZE: u64 = 0x0001_0000;

/// `JNIInvokeInterface` 槽位数（标准 8 项）
const VM_SLOT_COUNT: usize = 8;
/// `JNINativeInterface` 槽位数（JNI 1.6 标准 233 项，含 slot 232 `GetObjectRefType`）
const ENV_SLOT_COUNT: usize = 233;
/// `JNIEnv` 跳板在 `JNI_TRAMPOLINE_BASE` 中的起始槽位偏移（前 16 个槽位留给 `JavaVM`）
const ENV_TRAMPOLINE_SLOT_OFFSET: usize = 16;

/// ARM64 `RET` 机器码
const ARM64_RET_INSN: u32 = 0xD65F_03C0;

/// 单条结构化 JNI 调用事件（供全量导出与实时订阅，默认关闭零开销）
#[derive(Debug, Clone)]
pub struct JniTraceEvent {
    pub seq: u64,
    pub op: String,
    pub class_name: String,
    pub target_ref: u64,
    pub member: String,
    pub sig: String,
    pub args: Vec<String>,
    pub ret: String,
    pub is_null: bool,
}

pub type JniTraceListener = Box<dyn FnMut(&JniTraceEvent)>;

/// 可开关的 JNI 事件追踪器（默认 `enabled = false`，关闭时仅 1 次布尔判断、零分配）
pub struct JniTracer {
    pub enabled: bool,
    pub max_str_len: usize,
    pub max_events: usize,
    events: Vec<JniTraceEvent>,
    next_seq: u64,
    listener: Option<JniTraceListener>,
}

impl Default for JniTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl JniTracer {
    pub fn new() -> Self {
        Self {
            enabled: false,
            max_str_len: 64,
            max_events: 0,
            events: Vec::new(),
            next_seq: 1,
            listener: None,
        }
    }

    pub fn start(&mut self, max_str_len: usize, max_events: usize) {
        self.enabled = true;
        self.max_str_len = max_str_len.max(8);
        self.max_events = max_events;
    }

    pub fn stop(&mut self) {
        self.enabled = false;
    }

    pub fn clear(&mut self) {
        self.events.clear();
        self.next_seq = 1;
    }

    pub fn events(&self) -> &[JniTraceEvent] {
        &self.events
    }

    pub fn set_listener(&mut self, cb: Option<JniTraceListener>) {
        if cb.is_some() {
            self.enabled = true;
        }
        self.listener = cb;
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        op: impl Into<String>,
        class_name: impl Into<String>,
        target_ref: u64,
        member: impl Into<String>,
        sig: impl Into<String>,
        args: Vec<String>,
        ret: impl Into<String>,
        is_null: bool,
    ) {
        if !self.enabled {
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let ev = JniTraceEvent {
            seq,
            op: op.into(),
            class_name: class_name.into(),
            target_ref,
            member: member.into(),
            sig: sig.into(),
            args,
            ret: ret.into(),
            is_null,
        };
        if let Some(mut cb) = self.listener.take() {
            cb(&ev);
            if self.listener.is_none() {
                self.listener = Some(cb);
            }
        }
        if self.max_events == 0 || self.events.len() < self.max_events {
            self.events.push(ev);
        }
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…(+{}B)", &s[..end], s.len() - end)
    }
}

fn format_jobject_summary(objects: &ObjectTable, r: JObjectRef, max_str_len: usize) -> String {
    if r.is_null() {
        return "NULL".to_string();
    }
    match objects.get(r) {
        Some(JObject::String(s)) => format!("{:?}", truncate_str(s, max_str_len)),
        Some(JObject::Class { name }) => format!("class({name})@0x{:x}", r.0),
        Some(JObject::ByteArray(b)) => format!("byte[{}]@0x{:x}", b.len(), r.0),
        Some(JObject::CharArray(c)) => {
            let preview = String::from_utf16_lossy(&c[..c.len().min(max_str_len)]);
            format!("char[{}]({:?})@0x{:x}", c.len(), preview, r.0)
        }
        Some(JObject::IntArray(v)) => format!("int[{}]@0x{:x}", v.len(), r.0),
        Some(JObject::LongArray(v)) => format!("long[{}]@0x{:x}", v.len(), r.0),
        Some(JObject::ObjectArray(v)) => format!("Object[{}]@0x{:x}", v.len(), r.0),
        Some(obj) => format!("{}@0x{:x}", obj.class_name(), r.0),
        None => format!("0x{:x}", r.0),
    }
}

fn format_jvalue_summary(objects: &ObjectTable, val: &JValue, max_str_len: usize) -> String {
    match *val {
        JValue::Void => "void".to_string(),
        JValue::Boolean(b) => b.to_string(),
        JValue::Byte(v) => v.to_string(),
        JValue::Char(v) => format!("'{}'({v})", char::from_u32(u32::from(v)).unwrap_or('?')),
        JValue::Short(v) => v.to_string(),
        JValue::Int(v) => v.to_string(),
        JValue::Long(v) => format!("{v}L"),
        JValue::Float(v) => format!("{v}f"),
        JValue::Double(v) => format!("{v}d"),
        JValue::Object(r) => format_jobject_summary(objects, r, max_str_len),
    }
}

fn format_call_return_summary(
    objects: &ObjectTable,
    base_slot: usize,
    ret: u64,
    max_str_len: usize,
) -> (String, bool) {
    match base_slot {
        34 | 64 | 114 => {
            let r = JObjectRef(ret);
            (format_jobject_summary(objects, r, max_str_len), r.is_null())
        }
        37 | 67 | 117 => ((ret != 0).to_string(), false),
        40 | 70 | 120 => ((ret as i8).to_string(), false),
        43 | 73 | 123 => ((ret as u16).to_string(), false),
        46 | 76 | 126 => ((ret as i16).to_string(), false),
        49 | 79 | 129 => ((ret as i32).to_string(), false),
        52 | 82 | 132 => (format!("{}L", ret as i64), false),
        55 | 85 | 135 => (format!("{}f", f32::from_bits(ret as u32)), false),
        58 | 88 | 138 => (format!("{}d", f64::from_bits(ret)), false),
        _ => ("void".to_string(), false),
    }
}

fn call_op_name(base_slot: usize) -> &'static str {
    match base_slot {
        34 => "CallObjectMethod",
        37 => "CallBooleanMethod",
        40 => "CallByteMethod",
        43 => "CallCharMethod",
        46 => "CallShortMethod",
        49 => "CallIntMethod",
        52 => "CallLongMethod",
        55 => "CallFloatMethod",
        58 => "CallDoubleMethod",
        61 => "CallVoidMethod",
        114 => "CallStaticObjectMethod",
        117 => "CallStaticBooleanMethod",
        120 => "CallStaticByteMethod",
        123 => "CallStaticCharMethod",
        126 => "CallStaticShortMethod",
        129 => "CallStaticIntMethod",
        132 => "CallStaticLongMethod",
        135 => "CallStaticFloatMethod",
        138 => "CallStaticDoubleMethod",
        141 => "CallStaticVoidMethod",
        _ => "CallMethod",
    }
}

/// JNI 运行时可变状态快照（供 `EmuSnapshot` 完整回滚对象表与临时缓冲映射）
#[derive(Debug, Clone)]
pub struct JniSnapshot {
    pub objects: ObjectTable,
    pub pending_exception: JObjectRef,
    pub utf_buffers: HashMap<u64, JObjectRef>,
    pub array_buffers: HashMap<u64, (JObjectRef, usize)>,
    pub static_fields: HashMap<(String, String), JValue>,
}

/// 纯 Rust 伪造的 Dalvik/ART JNI 虚拟机桥接层
pub struct JniVm {
    pub objects: ObjectTable,
    pub registered_natives: Vec<RegisteredNative>,
    pub package_name: String,
    pub device_profile: DeviceProfile,

    methods: HashMap<u64, MethodDesc>,
    method_lookup: HashMap<(String, String, String, bool), u64>,
    next_method_id: u64,

    fields: HashMap<u64, FieldDesc>,
    field_lookup: HashMap<(String, String, String, bool), u64>,
    next_field_id: u64,

    /// 类静态字段表：`(normalized_class_name, field_name) -> JValue`
    static_fields: HashMap<(String, String), JValue>,

    /// 轻量 DEX 元数据索引（类继承链、方法/字段签名、静态常量初值）
    pub dex_index: DexIndex,
    /// `FindClass` 严格模式：开启且已加载 DEX 时，非系统类不存在返回 `NULL` 并挂 `ClassNotFoundException`
    pub strict_find_class: bool,
    pub diag: EnvDiag,
    pub breadcrumbs: BreadcrumbRing,
    pub jni_tracer: JniTracer,

    pending_exception: JObjectRef,
    /// 记录 `GetStringUTFChars` 分配的缓冲区，供 `ReleaseStringUTFChars` 追踪
    utf_buffers: HashMap<u64, JObjectRef>,
    /// 记录 `GetByteArrayElements` 分配的 `(jbyteArray, len)`，供 `ReleaseByteArrayElements` 回写
    array_buffers: HashMap<u64, (JObjectRef, usize)>,

    handler: Box<dyn JniHandler>,
    initialized: bool,
}

impl Default for JniVm {
    fn default() -> Self {
        Self::new(Box::new(DefaultJniHandler))
    }
}

impl JniVm {
    pub fn new(handler: Box<dyn JniHandler>) -> Self {
        Self {
            objects: ObjectTable::new(),
            registered_natives: Vec::new(),
            package_name: "com.example.app".to_string(),
            device_profile: DeviceProfile::default(),
            methods: HashMap::new(),
            method_lookup: HashMap::new(),
            next_method_id: 0x2000_0001,
            fields: HashMap::new(),
            field_lookup: HashMap::new(),
            next_field_id: 0x3000_0001,
            static_fields: HashMap::new(),
            dex_index: DexIndex::new(),
            strict_find_class: false,
            diag: EnvDiag::new(),
            breadcrumbs: BreadcrumbRing::new(),
            jni_tracer: JniTracer::new(),
            pending_exception: JObjectRef::NULL,
            utf_buffers: HashMap::new(),
            array_buffers: HashMap::new(),
            handler,
            initialized: false,
        }
    }

    /// 设置类静态字段（类名自动归一化 `.` -> `/`；对象引用自动持有 GlobalRef 避免被 PopLocalFrame 回收）
    pub fn set_static_field(&mut self, class_name: &str, field_name: &str, val: JValue) {
        let cls = class_name.replace('.', "/");
        if let JValue::Object(r) = val {
            if !r.is_null() {
                self.objects.new_global(r);
            }
        }
        self.static_fields.insert((cls, field_name.to_string()), val);
    }

    /// 查询类静态字段
    pub fn get_static_field(&self, class_name: &str, field_name: &str) -> Option<&JValue> {
        let cls = class_name.replace('.', "/");
        self.static_fields.get(&(cls, field_name.to_string()))
    }

    /// 设置实例对象（`JObject::Custom`）字段（对象引用自动升级 GlobalRef 避免被 PopLocalFrame 回收）
    pub fn set_instance_field(&mut self, obj: JObjectRef, field_name: &str, val: JValue) {
        if let JValue::Object(r) = val {
            if !r.is_null() {
                self.objects.new_global(r);
            }
        }
        if let Some(JObject::Custom { fields, .. }) = self.objects.get_mut(obj) {
            fields.insert(field_name.to_string(), val);
        }
    }

    /// 查询实例对象（`JObject::Custom`）字段
    pub fn get_instance_field(&self, obj: JObjectRef, field_name: &str) -> Option<JValue> {
        if let Some(JObject::Custom { fields, .. }) = self.objects.get(obj) {
            fields.get(field_name).copied()
        } else {
            None
        }
    }

    /// 按 FieldID 反查字段描述（含所属类名、字段名、签名与是否静态；ID 仅在当前进程有效）
    pub fn describe_field(&self, id: u64) -> Option<&FieldDesc> {
        self.fields.get(&id)
    }

    /// 列出本次运行内已 intern 的全部字段（按 FieldID 升序）
    pub fn list_fields(&self) -> Vec<(u64, &FieldDesc)> {
        let mut items: Vec<(u64, &FieldDesc)> = self.fields.iter().map(|(&k, v)| (k, v)).collect();
        items.sort_by_key(|(id, _)| *id);
        items
    }

    /// 按 MethodID 反查方法描述（含所属类名、方法名、签名与是否静态；ID 仅在当前进程有效）
    pub fn describe_method(&self, id: u64) -> Option<&MethodDesc> {
        self.methods.get(&id)
    }

    /// 列出本次运行内已 intern 的全部方法（按 MethodID 升序）
    pub fn list_methods(&self) -> Vec<(u64, &MethodDesc)> {
        let mut items: Vec<(u64, &MethodDesc)> = self.methods.iter().map(|(&k, v)| (k, v)).collect();
        items.sort_by_key(|(id, _)| *id);
        items
    }

    /// 按 `jobject` / `jclass` 句柄反查 `(class_name, kind)`
    pub fn describe_object(&self, r: JObjectRef) -> Option<(String, &'static str)> {
        let obj = self.objects.get(r)?;
        let kind = match obj {
            JObject::Class { .. } => "class",
            JObject::String(_) => "string",
            JObject::BooleanArray(_) => "boolean[]",
            JObject::ByteArray(_) => "byte[]",
            JObject::CharArray(_) => "char[]",
            JObject::ShortArray(_) => "short[]",
            JObject::IntArray(_) => "int[]",
            JObject::LongArray(_) => "long[]",
            JObject::FloatArray(_) => "float[]",
            JObject::DoubleArray(_) => "double[]",
            JObject::ObjectArray(_) => "object[]",
            JObject::DirectBuffer { .. } => "directBuffer",
            JObject::Custom { .. } => "custom",
            _ => "builtin",
        };
        Some((obj.class_name().to_string(), kind))
    }

    /// 捕获 JNI 对象引用表与临时缓冲区映射快照
    pub fn snapshot_state(&self) -> JniSnapshot {
        JniSnapshot {
            objects: self.objects.clone(),
            pending_exception: self.pending_exception,
            utf_buffers: self.utf_buffers.clone(),
            array_buffers: self.array_buffers.clone(),
            static_fields: self.static_fields.clone(),
        }
    }

    /// 恢复 JNI 对象引用表与临时缓冲区映射快照
    pub fn restore_state(&mut self, snap: &JniSnapshot) {
        self.objects = snap.objects.clone();
        self.pending_exception = snap.pending_exception;
        self.utf_buffers = snap.utf_buffers.clone();
        self.array_buffers = snap.array_buffers.clone();
        self.static_fields = snap.static_fields.clone();
    }

    /// 弹出 JNI 局部引用帧，并顺带回收帧内已销毁 `jstring`/`jarray` 遗留的未释放 guest 缓冲区
    pub fn pop_local_frame(&mut self, mem: &mut MemoryManager, keep: JObjectRef) -> usize {
        let removed = self.objects.pop_local_frame(keep);
        let orphan_utf: Vec<u64> = self
            .utf_buffers
            .iter()
            .filter_map(|(&addr, &obj_ref)| {
                self.objects.get(obj_ref).is_none().then_some(addr)
            })
            .collect();
        for addr in orphan_utf {
            self.utf_buffers.remove(&addr);
            mem.free_heap(addr);
        }
        let orphan_arr: Vec<u64> = self
            .array_buffers
            .iter()
            .filter_map(|(&addr, &(obj_ref, _))| {
                self.objects.get(obj_ref).is_none().then_some(addr)
            })
            .collect();
        for addr in orphan_arr {
            self.array_buffers.remove(&addr);
            mem.free_heap(addr);
        }
        removed
    }

    pub fn with_package_name(mut self, pkg: impl Into<String>) -> Self {
        self.package_name = pkg.into();
        self
    }

    pub fn set_device_profile(&mut self, profile: DeviceProfile) {
        self.device_profile = profile;
    }

    /// 替换业务 `JniHandler` 实现
    pub fn set_handler(&mut self, handler: Box<dyn JniHandler>) {
        self.handler = handler;
    }

    /// 在 Unicorn 内存中初始化 `JavaVM*`、`JNIEnv*` 虚函数表与 `RET` 跳板区
    pub fn init<D>(&mut self, uc: &mut Unicorn<'_, D>, mem: &mut MemoryManager) -> EmuResult<()> {
        if self.initialized {
            return Ok(());
        }

        // 1. 映射 vtable 页（JavaVM + JNIEnv 共 2 页，只读）
        mem.map_labeled(
            uc,
            JNI_VM_BASE,
            PAGE_SIZE * 2,
            Prot::READ,
            "[emu:jni_vtables]",
            0,
        )?;

        // 2. 映射 JNI 跳板代码页（RX）
        mem.map_labeled(
            uc,
            JNI_TRAMPOLINE_BASE,
            JNI_TRAMPOLINE_SIZE,
            Prot::READ | Prot::EXEC,
            "[emu:jni_trampoline]",
            0,
        )?;

        // 3. 写入 JavaVM 实例及 JNIInvokeInterface 虚表
        let vm_vtable_addr = JNI_VM_BASE + 0x10;
        mem.write_u64(uc, JNI_VM_BASE, vm_vtable_addr)?;
        for slot in 0..VM_SLOT_COUNT {
            let tramp = JNI_TRAMPOLINE_BASE + (slot as u64) * 4;
            mem.write_u32(uc, tramp, ARM64_RET_INSN)?;
            mem.write_u64(uc, vm_vtable_addr + (slot as u64) * 8, tramp)?;
        }

        // 4. 写入 JNIEnv 实例及 JNINativeInterface 虚表
        let env_vtable_addr = JNI_ENV_BASE + 0x10;
        mem.write_u64(uc, JNI_ENV_BASE, env_vtable_addr)?;
        for slot in 0..ENV_SLOT_COUNT {
            let tramp = JNI_TRAMPOLINE_BASE + ((ENV_TRAMPOLINE_SLOT_OFFSET + slot) as u64) * 4;
            mem.write_u32(uc, tramp, ARM64_RET_INSN)?;
            mem.write_u64(uc, env_vtable_addr + (slot as u64) * 8, tramp)?;
        }

        self.initialized = true;
        Ok(())
    }

    #[inline]
    pub const fn java_vm_ptr(&self) -> u64 {
        JNI_VM_BASE
    }

    #[inline]
    pub const fn jni_env_ptr(&self) -> u64 {
        JNI_ENV_BASE
    }

    /// 查询通过 `RegisterNatives` 动态注册的本地方法
    pub fn find_registered_native(&self, class_name: &str, name: &str) -> Option<&RegisteredNative> {
        let norm = class_name.replace('.', "/");
        self.registered_natives
            .iter()
            .find(|r| r.class_name == norm && r.name == name)
    }

    fn intern_method(
        &mut self,
        class_name: String,
        name: String,
        sig: String,
        is_static: bool,
    ) -> u64 {
        let key = (class_name.clone(), name.clone(), sig.clone(), is_static);
        if let Some(&id) = self.method_lookup.get(&key) {
            return id;
        }
        let id = self.next_method_id;
        self.next_method_id += 1;
        self.methods.insert(
            id,
            MethodDesc {
                class_name,
                name,
                sig,
                is_static,
            },
        );
        self.method_lookup.insert(key, id);
        id
    }

    fn intern_field(
        &mut self,
        class_name: String,
        name: String,
        sig: String,
        is_static: bool,
    ) -> u64 {
        let key = (class_name.clone(), name.clone(), sig.clone(), is_static);
        if let Some(&id) = self.field_lookup.get(&key) {
            return id;
        }
        let id = self.next_field_id;
        self.next_field_id += 1;
        self.fields.insert(
            id,
            FieldDesc {
                class_name,
                name,
                sig,
                is_static,
            },
        );
        self.field_lookup.insert(key, id);
        id
    }

    fn resolve_class_name(&self, class_ref: JObjectRef) -> String {
        match self.objects.get(class_ref) {
            Some(JObject::Class { name }) => name.clone(),
            Some(other) => other.class_name().to_string(),
            None => "<unknown>".to_string(),
        }
    }
}

/// 统一读取 JNI 三联槽位（`Call*Method` / `V` / `A` 及 `CallNonvirtual*Method`）的变参列表
#[inline]
fn read_jni_call_args<D>(
    uc: &Unicorn<'_, D>,
    slot: usize,
    base_slot: usize,
    ptr_reg: u64,
    sig: &str,
) -> Vec<JValue> {
    read_jni_call_args_at(uc, slot, base_slot, 3, ptr_reg, sig)
}

#[inline]
fn read_jni_call_args_at<D>(
    uc: &Unicorn<'_, D>,
    slot: usize,
    base_slot: usize,
    first_reg: usize,
    ptr_reg: u64,
    sig: &str,
) -> Vec<JValue> {
    match slot - base_slot {
        0 => read_varargs_direct(uc, first_reg, sig),
        1 => read_varargs_va_list(uc, ptr_reg, sig),
        _ => read_varargs_jvalue_array(uc, ptr_reg, sig),
    }
}

/// 挂载 JNI 跳板区 Code Hook
pub fn attach_jni_hook<'a, D, F>(
    uc: &mut Unicorn<'a, D>,
    mut get_state: F,
) -> EmuResult<UcHookId>
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager) + 'a,
{
    let hook_id = uc.add_code_hook(
        JNI_TRAMPOLINE_BASE,
        JNI_TRAMPOLINE_BASE + JNI_TRAMPOLINE_SIZE,
        move |uc, addr, _size| {
            if addr < JNI_TRAMPOLINE_BASE || !(addr - JNI_TRAMPOLINE_BASE).is_multiple_of(4) {
                return;
            }
            let raw_slot = ((addr - JNI_TRAMPOLINE_BASE) / 4) as usize;
            let env_range = ENV_TRAMPOLINE_SLOT_OFFSET..ENV_TRAMPOLINE_SLOT_OFFSET + ENV_SLOT_COUNT;
            if raw_slot < VM_SLOT_COUNT {
                dispatch_java_vm(uc, raw_slot, &mut get_state);
            } else if env_range.contains(&raw_slot) {
                dispatch_jni_env(uc, raw_slot - ENV_TRAMPOLINE_SLOT_OFFSET, &mut get_state);
            }
        },
    )?;

    Ok(hook_id)
}

/// 分派 `JavaVM` (`JNIInvokeInterface`) 方法
fn dispatch_java_vm<D, F>(uc: &mut Unicorn<'_, D>, slot: usize, get_state: &mut F)
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager),
{
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
    let ret: i32 = match slot {
        // 3: DestroyJavaVM, 5: DetachCurrentThread
        3 | 5 => JNI_OK,
        // 4: AttachCurrentThread, 6: GetEnv, 7: AttachCurrentThreadAsDaemon
        4 | 6 | 7 => {
            let env_ptr = {
                let (vm, _) = get_state(uc.get_data_mut());
                vm.jni_env_ptr()
            };
            if x1 != 0 {
                let _ = uc.mem_write(x1, &env_ptr.to_le_bytes());
                JNI_OK
            } else {
                JNI_ERR
            }
        }
        _ => {
            tracing::warn!(target: "runidbg::jni", "[JNI] 未实现的 JavaVM 槽位: slot={slot}");
            JNI_ERR
        }
    };

    let _ = uc.reg_write(RegisterARM64::X0, ret as i64 as u64);
}

/// 分派 `JNIEnv` (`JNINativeInterface`) 方法
fn dispatch_jni_env<D, F>(uc: &mut Unicorn<'_, D>, slot: usize, get_state: &mut F)
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager),
{
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
    let x2 = uc.reg_read(RegisterARM64::X2).unwrap_or(0);
    let x3 = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
    let x4 = uc.reg_read(RegisterARM64::X4).unwrap_or(0);

    let ret: u64 = match slot {
        // 4: GetVersion
        4 => JNI_VERSION_1_6 as u64,

        // 5: DefineClass
        5 => {
            let name = read_guest_cstr(uc, x1, 512);
            get_state(uc.get_data_mut())
                .0
                .objects
                .find_or_create_class(&name)
                .0
        }

        // 6: FindClass
        6 => {
            let name = read_guest_cstr(uc, x1, 512);
            let (vm, _) = get_state(uc.get_data_mut());
            let out = if vm.strict_find_class
                && !vm.dex_index.is_empty()
                && !is_system_or_array_class(&name)
                && !vm.dex_index.has_class(&name)
            {
                let exc = vm
                    .objects
                    .add_string(format!("java.lang.ClassNotFoundException: {name}"));
                vm.pending_exception = exc;
                vm.breadcrumbs
                    .push(format!("[JNI] FindClass({name}) -> NULL (ClassNotFound)"));
                0
            } else {
                let mut ctx = JniContext {
                    objects: &mut vm.objects,
                    package_name: &vm.package_name,
                };
                vm.handler.find_class(&mut ctx, &name).0
            };
            if vm.jni_tracer.enabled {
                let max_len = vm.jni_tracer.max_str_len;
                let ret_s = format_jobject_summary(&vm.objects, JObjectRef(out), max_len);
                vm.jni_tracer.record(
                    "FindClass",
                    name.clone(),
                    out,
                    "",
                    "",
                    vec![format!("{name:?}")],
                    ret_s,
                    out == 0,
                );
            }
            out
        }

        // 7: FromReflectedMethod
        7 => match get_state(uc.get_data_mut()).0.objects.get(JObjectRef(x1)) {
            Some(JObject::ReflectedMethod { method_id }) => *method_id,
            _ => x1,
        },

        // 8: FromReflectedField
        8 => match get_state(uc.get_data_mut()).0.objects.get(JObjectRef(x1)) {
            Some(JObject::ReflectedField { field_id }) => *field_id,
            _ => x1,
        },

        // 9: ToReflectedMethod
        9 => get_state(uc.get_data_mut())
            .0
            .objects
            .add_local(JObject::ReflectedMethod { method_id: x2 })
            .0,

        // 10: GetSuperclass
        10 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if cls == "java/lang/Object" || cls == "<unknown>" {
                0
            } else if let Some(super_cls) = vm.dex_index.get_superclass(&cls).map(str::to_string) {
                vm.objects.find_or_create_class(&super_cls).0
            } else {
                vm.objects.find_or_create_class("java/lang/Object").0
            }
        }

        // 11: IsAssignableFrom
        11 => {
            if x1 == x2 {
                JNI_TRUE
            } else {
                let (vm, _) = get_state(uc.get_data_mut());
                let sub = vm.resolve_class_name(JObjectRef(x1));
                let sup = vm.resolve_class_name(JObjectRef(x2));
                if sup == "java/lang/Object" {
                    JNI_TRUE
                } else if let Some(ok) = vm.dex_index.is_assignable_from(&sub, &sup) {
                    if ok { JNI_TRUE } else { JNI_FALSE }
                } else {
                    JNI_FALSE
                }
            }
        }

        // 12: ToReflectedField
        12 => get_state(uc.get_data_mut())
            .0
            .objects
            .add_local(JObject::ReflectedField { field_id: x2 })
            .0,

        // 13: Throw
        13 => {
            let (vm, _) = get_state(uc.get_data_mut());
            vm.pending_exception = JObjectRef(x1);
            JNI_OK as u64
        }

        // 14: ThrowNew
        14 => {
            let msg = read_guest_cstr(uc, x2, 512);
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            tracing::warn!(target: "runidbg::jni", "[JNI] ThrowNew({cls}, \"{msg}\")");
            let exc = vm.objects.add_string(format!("{cls}: {msg}"));
            vm.pending_exception = exc;
            JNI_OK as u64
        }

        // 15: ExceptionOccurred
        15 => get_state(uc.get_data_mut()).0.pending_exception.0,

        // 16: ExceptionDescribe
        16 => {
            let exc = get_state(uc.get_data_mut()).0.pending_exception;
            if !exc.is_null() {
                let desc = get_state(uc.get_data_mut())
                    .0
                    .objects
                    .get_string(exc)
                    .unwrap_or("<exception>")
                    .to_string();
                tracing::warn!(target: "runidbg::jni", "[JNI] ExceptionDescribe: {desc}");
            }
            0
        }

        // 17: ExceptionClear
        17 => {
            get_state(uc.get_data_mut()).0.pending_exception = JObjectRef::NULL;
            0
        }

        // 18: FatalError
        18 => {
            let msg = read_guest_cstr(uc, x1, 512);
            tracing::error!(target: "runidbg::jni", "FatalError: {msg}");
            let _ = uc.emu_stop();
            0
        }

        // 19: PushLocalFrame
        19 => {
            get_state(uc.get_data_mut()).0.objects.push_local_frame();
            JNI_OK as u64
        }

        // 26: EnsureLocalCapacity
        26 => JNI_OK as u64,

        // 20: PopLocalFrame
        20 => {
            let (vm, mem) = get_state(uc.get_data_mut());
            vm.pop_local_frame(mem, JObjectRef(x1));
            x1
        }

        // 25: NewLocalRef
        25 => x1,

        // 21: NewGlobalRef / 226: NewWeakGlobalRef
        21 | 226 => get_state(uc.get_data_mut())
            .0
            .objects
            .new_global(JObjectRef(x1))
            .0,

        // 22: DeleteGlobalRef / 227: DeleteWeakGlobalRef
        22 | 227 => {
            get_state(uc.get_data_mut())
                .0
                .objects
                .delete_global(JObjectRef(x1));
            0
        }

        // 23: DeleteLocalRef
        23 => {
            get_state(uc.get_data_mut())
                .0
                .objects
                .delete_local(JObjectRef(x1));
            0
        }

        // 24: IsSameObject
        24 => {
            if x1 == x2 {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        }

        // 27: AllocObject
        27 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            vm.objects
                .add_local(JObject::Custom {
                    class_name: cls,
                    fields: HashMap::new(),
                })
                .0
        }

        // 28..=30: NewObject / V / A
        28..=30 => dispatch_static_call(uc, slot, 28, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
            h.new_object(ctx, cls, m, a).0
        }),

        // 31: GetObjectClass
        31 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            vm.objects.find_or_create_class(&cls).0
        }

        // 32: IsInstanceOf
        32 => {
            if x1 == 0 {
                JNI_TRUE
            } else {
                let (vm, _) = get_state(uc.get_data_mut());
                let obj_cls = vm.resolve_class_name(JObjectRef(x1));
                let target_cls = vm.resolve_class_name(JObjectRef(x2));
                if obj_cls == target_cls || target_cls == "java/lang/Object" {
                    JNI_TRUE
                } else {
                    JNI_FALSE
                }
            }
        }

        // 33: GetMethodID / 113: GetStaticMethodID
        33 | 113 => {
            let name = read_guest_cstr(uc, x2, 256);
            let sig = read_guest_cstr(uc, x3, 512);
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            let kind = if slot == 113 {
                "GetStaticMethodID"
            } else {
                "GetMethodID"
            };
            let mid = vm.intern_method(cls.clone(), name.clone(), sig.clone(), slot == 113);
            vm.breadcrumbs
                .push(format!("[JNI] {kind} {cls}.{name}{sig} -> 0x{mid:x}"));
            if vm.jni_tracer.enabled {
                vm.jni_tracer.record(
                    kind,
                    cls,
                    x1,
                    name,
                    sig,
                    Vec::new(),
                    format!("0x{mid:x}"),
                    mid == 0,
                );
            }
            mid
        }

        // 实例方法三联调用 (34..=63)
        34..=36 => dispatch_instance_call(uc, slot, 34, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            h.call_object_method(ctx, o, m, a).0
        }),
        37..=39 => dispatch_instance_call(uc, slot, 37, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            u64::from(h.call_boolean_method(ctx, o, m, a))
        }),
        40..=42 => dispatch_instance_call(uc, slot, 40, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            h.call_byte_method(ctx, o, m, a) as i64 as u64
        }),
        43..=45 => dispatch_instance_call(uc, slot, 43, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            u64::from(h.call_char_method(ctx, o, m, a))
        }),
        46..=48 => dispatch_instance_call(uc, slot, 46, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            h.call_short_method(ctx, o, m, a) as i64 as u64
        }),
        49..=51 => dispatch_instance_call(uc, slot, 49, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            h.call_int_method(ctx, o, m, a) as i64 as u64
        }),
        52..=54 => dispatch_instance_call(uc, slot, 52, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            h.call_long_method(ctx, o, m, a) as u64
        }),
        55..=57 => {
            let bits = dispatch_instance_call(uc, slot, 55, x1, x2, x3, get_state, |h, ctx, o, m, a| {
                u64::from(h.call_float_method(ctx, o, m, a).to_bits())
            });
            let _ = uc.reg_write(RegisterARM64::S0, bits);
            bits
        }
        58..=60 => {
            let bits = dispatch_instance_call(uc, slot, 58, x1, x2, x3, get_state, |h, ctx, o, m, a| {
                h.call_double_method(ctx, o, m, a).to_bits()
            });
            let _ = uc.reg_write(RegisterARM64::D0, bits);
            bits
        }
        61..=63 => dispatch_instance_call(uc, slot, 61, x1, x2, x3, get_state, |h, ctx, o, m, a| {
            h.call_void_method(ctx, o, m, a);
            0
        }),

        // Nonvirtual 实例方法三联调用 (64..=93): x1=obj, x2=clazz, x3=methodID, x4=varargs
        64..=66 => dispatch_nonvirtual_call(uc, slot, 64, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            h.call_object_method(ctx, o, m, a).0
        }),
        67..=69 => dispatch_nonvirtual_call(uc, slot, 67, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            u64::from(h.call_boolean_method(ctx, o, m, a))
        }),
        70..=72 => dispatch_nonvirtual_call(uc, slot, 70, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            h.call_byte_method(ctx, o, m, a) as i64 as u64
        }),
        73..=75 => dispatch_nonvirtual_call(uc, slot, 73, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            u64::from(h.call_char_method(ctx, o, m, a))
        }),
        76..=78 => dispatch_nonvirtual_call(uc, slot, 76, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            h.call_short_method(ctx, o, m, a) as i64 as u64
        }),
        79..=81 => dispatch_nonvirtual_call(uc, slot, 79, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            h.call_int_method(ctx, o, m, a) as i64 as u64
        }),
        82..=84 => dispatch_nonvirtual_call(uc, slot, 82, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            h.call_long_method(ctx, o, m, a) as u64
        }),
        85..=87 => {
            let bits = dispatch_nonvirtual_call(uc, slot, 85, x1, x3, x4, get_state, |h, ctx, o, m, a| {
                u64::from(h.call_float_method(ctx, o, m, a).to_bits())
            });
            let _ = uc.reg_write(RegisterARM64::S0, bits);
            bits
        }
        88..=90 => {
            let bits = dispatch_nonvirtual_call(uc, slot, 88, x1, x3, x4, get_state, |h, ctx, o, m, a| {
                h.call_double_method(ctx, o, m, a).to_bits()
            });
            let _ = uc.reg_write(RegisterARM64::D0, bits);
            bits
        }
        91..=93 => dispatch_nonvirtual_call(uc, slot, 91, x1, x3, x4, get_state, |h, ctx, o, m, a| {
            h.call_void_method(ctx, o, m, a);
            0
        }),

        // 94: GetFieldID / 144: GetStaticFieldID
        94 | 144 => {
            let name = read_guest_cstr(uc, x2, 256);
            let sig = read_guest_cstr(uc, x3, 512);
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            let kind = if slot == 144 {
                "GetStaticFieldID"
            } else {
                "GetFieldID"
            };
            let fid = vm.intern_field(cls.clone(), name.clone(), sig.clone(), slot == 144);
            vm.breadcrumbs
                .push(format!("[JNI] {kind} {cls}.{name}({sig}) -> 0x{fid:x}"));
            if vm.jni_tracer.enabled {
                vm.jni_tracer.record(
                    kind,
                    cls,
                    x1,
                    name,
                    sig,
                    Vec::new(),
                    format!("0x{fid:x}"),
                    fid == 0,
                );
            }
            fid
        }

        // 实例字段读取 (95..=103)
        95 => {
            let (vm, _) = get_state(uc.get_data_mut());
            if let Some(field) = vm.fields.get(&x2).cloned() {
                let o = JObjectRef(x1);
                let out = if let Some(JObject::Custom { fields, .. }) = vm.objects.get(o) {
                    if let Some(JValue::Object(r)) = fields.get(&field.name).copied() {
                        r.0
                    } else {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_object_field(&mut ctx, o, &field).0
                    }
                } else {
                    let mut ctx = JniContext {
                        objects: &mut vm.objects,
                        package_name: &vm.package_name,
                    };
                    vm.handler.get_object_field(&mut ctx, o, &field).0
                };
                if out == 0 {
                    let key = format!("{}.{}({})", field.class_name, field.name, field.sig);
                    vm.diag.record_missing_jni_field(&key);
                    vm.breadcrumbs
                        .push(format!("[JNI] GetObjectField {key} -> NULL"));
                }
                if vm.jni_tracer.enabled {
                    let max_len = vm.jni_tracer.max_str_len;
                    let obj_cls = vm
                        .objects
                        .get(o)
                        .map(|obj| obj.class_name().to_string())
                        .unwrap_or_else(|| field.class_name.clone());
                    let ret_s = format_jobject_summary(&vm.objects, JObjectRef(out), max_len);
                    vm.jni_tracer.record(
                        "GetObjectField",
                        obj_cls,
                        x1,
                        field.name,
                        field.sig,
                        Vec::new(),
                        ret_s,
                        out == 0,
                    );
                }
                out
            } else {
                0
            }
        }
        96 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                if let Some(JValue::Boolean(b)) = fields.get(&f.name).copied() {
                    return u64::from(b);
                }
            }
            u64::from(h.get_boolean_field(ctx, o, f))
        }),
        97 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                if let Some(JValue::Byte(v)) = fields.get(&f.name).copied() {
                    return v as i64 as u64;
                }
            }
            h.get_byte_field(ctx, o, f) as i64 as u64
        }),
        98 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                if let Some(JValue::Char(v)) = fields.get(&f.name).copied() {
                    return u64::from(v);
                }
            }
            u64::from(h.get_char_field(ctx, o, f))
        }),
        99 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                if let Some(JValue::Short(v)) = fields.get(&f.name).copied() {
                    return v as i64 as u64;
                }
            }
            h.get_short_field(ctx, o, f) as i64 as u64
        }),
        100 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                if let Some(JValue::Int(v)) = fields.get(&f.name).copied() {
                    return v as i64 as u64;
                }
            }
            h.get_int_field(ctx, o, f) as i64 as u64
        }),
        101 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                if let Some(JValue::Long(v)) = fields.get(&f.name).copied() {
                    return v as u64;
                }
            }
            h.get_long_field(ctx, o, f) as u64
        }),
        102 => {
            let bits = dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
                if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                    if let Some(JValue::Float(v)) = fields.get(&f.name).copied() {
                        return u64::from(v.to_bits());
                    }
                }
                u64::from(h.get_float_field(ctx, o, f).to_bits())
            });
            let _ = uc.reg_write(RegisterARM64::S0, bits);
            bits
        }
        103 => {
            let bits = dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
                if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(o) {
                    if let Some(JValue::Double(v)) = fields.get(&f.name).copied() {
                        return v.to_bits();
                    }
                }
                h.get_double_field(ctx, o, f).to_bits()
            });
            let _ = uc.reg_write(RegisterARM64::D0, bits);
            bits
        }

        // 实例字段写入 (104..=112)
        104..=112 => {
            let val = match slot {
                104 => JValue::Object(JObjectRef(x3)),
                105 => JValue::Boolean(x3 != 0),
                106 => JValue::Byte(x3 as i8),
                107 => JValue::Char(x3 as u16),
                108 => JValue::Short(x3 as i16),
                109 => JValue::Int(x3 as i32),
                110 => JValue::Long(x3 as i64),
                111 => {
                    let bits = uc.reg_read(RegisterARM64::S0).unwrap_or(0) as u32;
                    JValue::Float(f32::from_bits(bits))
                }
                _ => {
                    let bits = uc.reg_read(RegisterARM64::D0).unwrap_or(0);
                    JValue::Double(f64::from_bits(bits))
                }
            };
            let (vm, _) = get_state(uc.get_data_mut());
            if let Some(field) = vm.fields.get(&x2).cloned() {
                let obj = JObjectRef(x1);
                vm.set_instance_field(obj, &field.name, val);
                if vm.jni_tracer.enabled {
                    let max_len = vm.jni_tracer.max_str_len;
                    let obj_cls = vm
                        .objects
                        .get(obj)
                        .map(|o| o.class_name().to_string())
                        .unwrap_or_else(|| field.class_name.clone());
                    let val_s = format_jvalue_summary(&vm.objects, &val, max_len);
                    vm.jni_tracer.record(
                        "SetField",
                        obj_cls,
                        x1,
                        field.name.clone(),
                        field.sig.clone(),
                        vec![val_s],
                        "void",
                        false,
                    );
                }
                let mut ctx = JniContext {
                    objects: &mut vm.objects,
                    package_name: &vm.package_name,
                };
                vm.handler.set_field(&mut ctx, obj, &field, val);
            }
            0
        }

        // 静态方法三联调用 (114..=143)
        114..=116 => {
            dispatch_static_call(uc, slot, 114, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                h.call_static_object_method(ctx, cls, m, a).0
            })
        }
        117..=119 => {
            dispatch_static_call(uc, slot, 117, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                u64::from(h.call_static_boolean_method(ctx, cls, m, a))
            })
        }
        120..=122 => {
            dispatch_static_call(uc, slot, 120, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                h.call_static_byte_method(ctx, cls, m, a) as i64 as u64
            })
        }
        123..=125 => {
            dispatch_static_call(uc, slot, 123, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                u64::from(h.call_static_char_method(ctx, cls, m, a))
            })
        }
        126..=128 => {
            dispatch_static_call(uc, slot, 126, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                h.call_static_short_method(ctx, cls, m, a) as i64 as u64
            })
        }
        129..=131 => {
            dispatch_static_call(uc, slot, 129, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                h.call_static_int_method(ctx, cls, m, a) as i64 as u64
            })
        }
        132..=134 => {
            dispatch_static_call(uc, slot, 132, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                h.call_static_long_method(ctx, cls, m, a) as u64
            })
        }
        135..=137 => {
            let bits =
                dispatch_static_call(uc, slot, 135, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                    u64::from(h.call_static_float_method(ctx, cls, m, a).to_bits())
                });
            let _ = uc.reg_write(RegisterARM64::S0, bits);
            bits
        }
        138..=140 => {
            let bits =
                dispatch_static_call(uc, slot, 138, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                    h.call_static_double_method(ctx, cls, m, a).to_bits()
                });
            let _ = uc.reg_write(RegisterARM64::D0, bits);
            bits
        }
        141..=143 => {
            dispatch_static_call(uc, slot, 141, x1, x2, x3, get_state, |h, ctx, cls, m, a| {
                h.call_static_void_method(ctx, cls, m, a);
                0
            })
        }

        // 静态字段读取 (145..=153)
        // 优先级：用户显式 setStaticField > handler/JS Hook > DEX static_values > 内置 Build 表
        145 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                let out = if let Some(JValue::Object(r)) =
                    vm.get_static_field(&cls, &field.name).copied()
                {
                    r.0
                } else {
                    let ret = {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_static_object_field(&mut ctx, &cls, &field)
                    };
                    if !ret.is_null() {
                        ret.0
                    } else if let Some(dv) =
                        vm.dex_index.get_static_value(&cls, &field.name).cloned()
                    {
                        let r = dex_value_to_jobject(&mut vm.objects, &dv, &field.sig);
                        if !r.is_null() {
                            r.0
                        } else {
                            resolve_builtin_build_object_field(
                                &mut vm.objects,
                                &vm.device_profile,
                                &cls,
                                &field,
                            )
                            .0
                        }
                    } else {
                        resolve_builtin_build_object_field(
                            &mut vm.objects,
                            &vm.device_profile,
                            &cls,
                            &field,
                        )
                        .0
                    }
                };
                if out == 0 {
                    let key = format!("{cls}.{}({})", field.name, field.sig);
                    vm.diag.record_missing_jni_field(&key);
                    vm.breadcrumbs
                        .push(format!("[JNI] GetStaticObjectField {key} -> NULL"));
                }
                if vm.jni_tracer.enabled {
                    let max_len = vm.jni_tracer.max_str_len;
                    let ret_s = format_jobject_summary(&vm.objects, JObjectRef(out), max_len);
                    vm.jni_tracer.record(
                        "GetStaticObjectField",
                        cls,
                        x1,
                        field.name,
                        field.sig,
                        Vec::new(),
                        ret_s,
                        out == 0,
                    );
                }
                out
            } else {
                0
            }
        }
        146 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                if let Some(JValue::Boolean(b)) = vm.get_static_field(&cls, &field.name).copied() {
                    u64::from(b)
                } else {
                    let v = {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_static_boolean_field(&mut ctx, &cls, &field)
                    };
                    if v {
                        1
                    } else if let Some(DexValue::Boolean(b)) =
                        vm.dex_index.get_static_value(&cls, &field.name)
                    {
                        u64::from(*b)
                    } else {
                        0
                    }
                }
            } else {
                0
            }
        }
        147 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                if let Some(JValue::Byte(v)) = vm.get_static_field(&cls, &field.name).copied() {
                    v as i64 as u64
                } else {
                    let v = {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_static_byte_field(&mut ctx, &cls, &field)
                    };
                    if v != 0 {
                        v as i64 as u64
                    } else if let Some(DexValue::Byte(b)) =
                        vm.dex_index.get_static_value(&cls, &field.name)
                    {
                        *b as i64 as u64
                    } else {
                        0
                    }
                }
            } else {
                0
            }
        }
        148 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                if let Some(JValue::Char(v)) = vm.get_static_field(&cls, &field.name).copied() {
                    u64::from(v)
                } else {
                    let v = {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_static_char_field(&mut ctx, &cls, &field)
                    };
                    if v != 0 {
                        u64::from(v)
                    } else if let Some(DexValue::Char(c)) =
                        vm.dex_index.get_static_value(&cls, &field.name)
                    {
                        u64::from(*c)
                    } else {
                        0
                    }
                }
            } else {
                0
            }
        }
        149 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                if let Some(JValue::Short(v)) = vm.get_static_field(&cls, &field.name).copied() {
                    v as i64 as u64
                } else {
                    let v = {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_static_short_field(&mut ctx, &cls, &field)
                    };
                    if v != 0 {
                        v as i64 as u64
                    } else if let Some(DexValue::Short(s)) =
                        vm.dex_index.get_static_value(&cls, &field.name)
                    {
                        *s as i64 as u64
                    } else {
                        0
                    }
                }
            } else {
                0
            }
        }
        150 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                if let Some(JValue::Int(v)) = vm.get_static_field(&cls, &field.name).copied() {
                    v as i64 as u64
                } else {
                    let val = {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_static_int_field(&mut ctx, &cls, &field)
                    };
                    if val != 0 {
                        val as i64 as u64
                    } else if let Some(DexValue::Int(i)) =
                        vm.dex_index.get_static_value(&cls, &field.name)
                    {
                        *i as i64 as u64
                    } else if cls == "android/os/Build$VERSION" && field.name == "SDK_INT" {
                        (vm.device_profile.sdk_int as i32) as i64 as u64
                    } else {
                        0
                    }
                }
            } else {
                0
            }
        }
        151 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                if let Some(JValue::Long(v)) = vm.get_static_field(&cls, &field.name).copied() {
                    v as u64
                } else {
                    let v = {
                        let mut ctx = JniContext {
                            objects: &mut vm.objects,
                            package_name: &vm.package_name,
                        };
                        vm.handler.get_static_long_field(&mut ctx, &cls, &field)
                    };
                    if v != 0 {
                        v as u64
                    } else if let Some(DexValue::Long(l)) =
                        vm.dex_index.get_static_value(&cls, &field.name)
                    {
                        *l as u64
                    } else {
                        0
                    }
                }
            } else {
                0
            }
        }
        152 => {
            let bits = {
                let (vm, _) = get_state(uc.get_data_mut());
                let cls = vm.resolve_class_name(JObjectRef(x1));
                if let Some(field) = vm.fields.get(&x2).cloned() {
                    if let Some(JValue::Float(v)) = vm.get_static_field(&cls, &field.name).copied()
                    {
                        u64::from(v.to_bits())
                    } else {
                        let v = {
                            let mut ctx = JniContext {
                                objects: &mut vm.objects,
                                package_name: &vm.package_name,
                            };
                            vm.handler.get_static_float_field(&mut ctx, &cls, &field)
                        };
                        if v != 0.0 {
                            u64::from(v.to_bits())
                        } else if let Some(DexValue::Float(f)) =
                            vm.dex_index.get_static_value(&cls, &field.name)
                        {
                            u64::from(f.to_bits())
                        } else {
                            0
                        }
                    }
                } else {
                    0
                }
            };
            let _ = uc.reg_write(RegisterARM64::S0, bits);
            bits
        }
        153 => {
            let bits = {
                let (vm, _) = get_state(uc.get_data_mut());
                let cls = vm.resolve_class_name(JObjectRef(x1));
                if let Some(field) = vm.fields.get(&x2).cloned() {
                    if let Some(JValue::Double(v)) =
                        vm.get_static_field(&cls, &field.name).copied()
                    {
                        v.to_bits()
                    } else {
                        let v = {
                            let mut ctx = JniContext {
                                objects: &mut vm.objects,
                                package_name: &vm.package_name,
                            };
                            vm.handler.get_static_double_field(&mut ctx, &cls, &field)
                        };
                        if v != 0.0 {
                            v.to_bits()
                        } else if let Some(DexValue::Double(d)) =
                            vm.dex_index.get_static_value(&cls, &field.name)
                        {
                            d.to_bits()
                        } else {
                            0
                        }
                    }
                } else {
                    0
                }
            };
            let _ = uc.reg_write(RegisterARM64::D0, bits);
            bits
        }

        // 静态字段写入 (154..=162)
        154..=162 => {
            let val = match slot {
                154 => JValue::Object(JObjectRef(x3)),
                155 => JValue::Boolean(x3 != 0),
                156 => JValue::Byte(x3 as i8),
                157 => JValue::Char(x3 as u16),
                158 => JValue::Short(x3 as i16),
                159 => JValue::Int(x3 as i32),
                160 => JValue::Long(x3 as i64),
                161 => {
                    let bits = uc.reg_read(RegisterARM64::S0).unwrap_or(0) as u32;
                    JValue::Float(f32::from_bits(bits))
                }
                _ => {
                    let bits = uc.reg_read(RegisterARM64::D0).unwrap_or(0);
                    JValue::Double(f64::from_bits(bits))
                }
            };
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                vm.set_static_field(&cls, &field.name, val);
                if vm.jni_tracer.enabled {
                    let max_len = vm.jni_tracer.max_str_len;
                    let val_s = format_jvalue_summary(&vm.objects, &val, max_len);
                    vm.jni_tracer.record(
                        "SetStaticField",
                        cls.clone(),
                        x1,
                        field.name.clone(),
                        field.sig.clone(),
                        vec![val_s],
                        "void",
                        false,
                    );
                }
                let mut ctx = JniContext {
                    objects: &mut vm.objects,
                    package_name: &vm.package_name,
                };
                vm.handler.set_static_field(&mut ctx, &cls, &field, val);
            }
            0
        }

        // 163: NewString (UTF-16)
        163 => {
            let len = (x2 as i32).max(0) as usize;
            let mut raw = vec![0u8; len.saturating_mul(2)];
            if !raw.is_empty() && x1 != 0 {
                let _ = uc.mem_read(x1, &mut raw);
            }
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            let s = String::from_utf16_lossy(&units);
            get_state(uc.get_data_mut()).0.objects.add_string(s).0
        }

        // 164: GetStringLength (UTF-16 code units)
        164 => get_state(uc.get_data_mut())
            .0
            .objects
            .get_string(JObjectRef(x1))
            .map(|s| s.encode_utf16().count() as u64)
            .unwrap_or(0),

        // 165: GetStringChars (UTF-16) / 224: GetStringCritical
        165 | 224 => {
            let (raw_bytes, buf_addr) = {
                let (vm, mem) = get_state(uc.get_data_mut());
                let Some(s) = vm.objects.get_string(JObjectRef(x1)) else {
                    let _ = uc.reg_write(RegisterARM64::X0, 0);
                    return;
                };
                let mut raw: Vec<u8> = s
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect();
                raw.extend_from_slice(&[0, 0]);
                let addr = mem.alloc_heap(raw.len() as u64).unwrap_or(0);
                if addr != 0 {
                    vm.utf_buffers.insert(addr, JObjectRef(x1));
                }
                (raw, addr)
            };
            if buf_addr != 0 {
                let _ = uc.mem_write(buf_addr, &raw_bytes);
                if x2 != 0 {
                    let _ = uc.mem_write(x2, &[1u8]);
                }
            }
            buf_addr
        }

        // 166: ReleaseStringChars / 225: ReleaseStringCritical
        166 | 225 => {
            get_state(uc.get_data_mut()).0.utf_buffers.remove(&x2);
            0
        }

        // 167: NewStringUTF
        167 => {
            let s = read_guest_cstr(uc, x1, 64 * 1024);
            get_state(uc.get_data_mut()).0.objects.add_string(s).0
        }

        // 168: GetStringUTFLength
        168 => get_state(uc.get_data_mut())
            .0
            .objects
            .get_string(JObjectRef(x1))
            .map(|s| s.len() as u64)
            .unwrap_or(0),

        // 169: GetStringUTFChars
        169 => {
            let (bytes, buf_addr) = {
                let (vm, mem) = get_state(uc.get_data_mut());
                let Some(s) = vm.objects.get_string(JObjectRef(x1)) else {
                    let _ = uc.reg_write(RegisterARM64::X0, 0);
                    return;
                };
                let mut raw = s.as_bytes().to_vec();
                raw.push(0);
                let addr = mem.alloc_heap(raw.len() as u64).unwrap_or(0);
                if addr != 0 {
                    vm.utf_buffers.insert(addr, JObjectRef(x1));
                }
                (raw, addr)
            };
            if buf_addr != 0 {
                let _ = uc.mem_write(buf_addr, &bytes);
                if x2 != 0 {
                    let _ = uc.mem_write(x2, &[1u8]);
                }
            }
            buf_addr
        }

        // 170: ReleaseStringUTFChars
        170 => {
            let (vm, mem) = get_state(uc.get_data_mut());
            if vm.utf_buffers.remove(&x2).is_some() {
                mem.free_heap(x2);
            }
            0
        }

        // 171: GetArrayLength (支持全部 8 种基础数组 + ObjectArray)
        171 => get_state(uc.get_data_mut())
            .0
            .objects
            .get(JObjectRef(x1))
            .and_then(JObject::array_len)
            .unwrap_or(0) as u64,

        // 172: NewObjectArray
        172 => {
            let len = (x1 as i32).max(0) as usize;
            get_state(uc.get_data_mut())
                .0
                .objects
                .add_local(JObject::ObjectArray(vec![JObjectRef(x3); len]))
                .0
        }

        // 173: GetObjectArrayElement
        173 => {
            let idx = (x2 as i32).max(0) as usize;
            match get_state(uc.get_data_mut()).0.objects.get(JObjectRef(x1)) {
                Some(JObject::ObjectArray(arr)) => {
                    arr.get(idx).copied().unwrap_or(JObjectRef::NULL).0
                }
                _ => 0,
            }
        }

        // 174: SetObjectArrayElement
        174 => {
            let idx = (x2 as i32).max(0) as usize;
            if let Some(JObject::ObjectArray(arr)) =
                get_state(uc.get_data_mut()).0.objects.get_mut(JObjectRef(x1))
            {
                if let Some(slot_ref) = arr.get_mut(idx) {
                    *slot_ref = JObjectRef(x3);
                }
            }
            0
        }

        // 175..=182: NewBooleanArray / Byte / Char / Short / Int / Long / Float / Double
        175..=182 => {
            let len = (x1 as i32).max(0) as usize;
            let obj = match slot {
                175 => JObject::BooleanArray(vec![0u8; len]),
                176 => JObject::ByteArray(vec![0u8; len]),
                177 => JObject::CharArray(vec![0u16; len]),
                178 => JObject::ShortArray(vec![0i16; len]),
                179 => JObject::IntArray(vec![0i32; len]),
                180 => JObject::LongArray(vec![0i64; len]),
                181 => JObject::FloatArray(vec![0.0f32; len]),
                _ => JObject::DoubleArray(vec![0.0f64; len]),
            };
            get_state(uc.get_data_mut()).0.objects.add_local(obj).0
        }

        // 183..=190: Get*ArrayElements / 222: GetPrimitiveArrayCritical
        183..=190 | 222 => {
            let (data, buf_addr) = {
                let (vm, mem) = get_state(uc.get_data_mut());
                let Some(copy) = vm
                    .objects
                    .get(JObjectRef(x1))
                    .and_then(JObject::to_primitive_bytes)
                else {
                    let _ = uc.reg_write(RegisterARM64::X0, 0);
                    return;
                };
                let addr = mem.alloc_heap(copy.len().max(1) as u64).unwrap_or(0);
                if addr != 0 {
                    vm.array_buffers.insert(addr, (JObjectRef(x1), copy.len()));
                }
                (copy, addr)
            };
            if buf_addr != 0 {
                if !data.is_empty() {
                    let _ = uc.mem_write(buf_addr, &data);
                }
                if x2 != 0 {
                    let _ = uc.mem_write(x2, &[1u8]);
                }
            }
            buf_addr
        }

        // 191..=198: Release*ArrayElements / 223: ReleasePrimitiveArrayCritical
        191..=198 | 223 => {
            let mode = x3 as i32;
            let meta = get_state(uc.get_data_mut()).0.array_buffers.remove(&x2);
            if let Some((arr_ref, byte_len)) = meta {
                if mode != JNI_ABORT && byte_len > 0 {
                    let mut updated = vec![0u8; byte_len];
                    if uc.mem_read(x2, &mut updated).is_ok() {
                        if let Some(obj) =
                            get_state(uc.get_data_mut()).0.objects.get_mut(arr_ref)
                        {
                            obj.write_primitive_bytes(0, &updated);
                        }
                    }
                }
                get_state(uc.get_data_mut()).1.free_heap(x2);
            }
            0
        }

        // 199..=206: Get*ArrayRegion (Boolean..Double)
        199..=206 => {
            let start = (x2 as i32).max(0) as usize;
            let len = (x3 as i32).max(0) as usize;
            let slice = get_state(uc.get_data_mut())
                .0
                .objects
                .get(JObjectRef(x1))
                .and_then(|obj| {
                    let elem = obj.primitive_elem_size()?;
                    let raw = obj.to_primitive_bytes()?;
                    let byte_start = start.saturating_mul(elem);
                    let byte_end = byte_start.saturating_add(len.saturating_mul(elem));
                    raw.get(byte_start..byte_end).map(|s| s.to_vec())
                });
            if let Some(data) = slice {
                if x4 != 0 && !data.is_empty() {
                    let _ = uc.mem_write(x4, &data);
                }
            }
            0
        }

        // 207..=214: Set*ArrayRegion (Boolean..Double)
        207..=214 => {
            let start = (x2 as i32).max(0) as usize;
            let len = (x3 as i32).max(0) as usize;
            let elem = get_state(uc.get_data_mut())
                .0
                .objects
                .get(JObjectRef(x1))
                .and_then(JObject::primitive_elem_size)
                .unwrap_or(0);
            let byte_len = len.saturating_mul(elem);
            if x4 != 0 && byte_len > 0 {
                let mut src = vec![0u8; byte_len];
                if uc.mem_read(x4, &mut src).is_ok() {
                    if let Some(obj) = get_state(uc.get_data_mut())
                        .0
                        .objects
                        .get_mut(JObjectRef(x1))
                    {
                        obj.write_primitive_bytes(start, &src);
                    }
                }
            }
            0
        }

        // 215: RegisterNatives
        215 => {
            let count = (x3 as i32).max(0) as usize;
            let mut entries = Vec::with_capacity(count);
            for i in 0..count {
                let base = x2 + (i as u64) * 24;
                let name = read_guest_cstr(uc, read_guest_u64(uc, base), 256);
                let sig = read_guest_cstr(uc, read_guest_u64(uc, base + 8), 512);
                let fn_ptr = read_guest_u64(uc, base + 16);
                entries.push((name, sig, fn_ptr));
            }
            let (vm, _) = get_state(uc.get_data_mut());
            let class_name = vm.resolve_class_name(JObjectRef(x1));
            for (name, sig, fn_ptr) in entries {
                vm.registered_natives.push(RegisteredNative {
                    class_name: class_name.clone(),
                    name,
                    sig,
                    fn_ptr,
                });
            }
            JNI_OK as u64
        }

        // 216: UnregisterNatives
        216 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            vm.registered_natives.retain(|r| r.class_name != cls);
            JNI_OK as u64
        }

        // 217: MonitorEnter / 218: MonitorExit
        217 | 218 => JNI_OK as u64,

        // 219: GetJavaVM
        219 => {
            let vm_ptr = get_state(uc.get_data_mut()).0.java_vm_ptr();
            if x1 != 0 {
                let _ = uc.mem_write(x1, &vm_ptr.to_le_bytes());
                JNI_OK as u64
            } else {
                JNI_ERR as i64 as u64
            }
        }

        // 220: GetStringRegion (UTF-16)
        220 => {
            let start = (x2 as i32).max(0) as usize;
            let len = (x3 as i32).max(0) as usize;
            let chunk: Option<Vec<u8>> = get_state(uc.get_data_mut())
                .0
                .objects
                .get_string(JObjectRef(x1))
                .map(|s| {
                    let units: Vec<u16> = s.encode_utf16().collect();
                    let end = start.saturating_add(len).min(units.len());
                    if start < units.len() {
                        units[start..end]
                            .iter()
                            .flat_map(|u| u.to_le_bytes())
                            .collect()
                    } else {
                        Vec::new()
                    }
                });
            if let Some(bytes) = chunk {
                if x4 != 0 && !bytes.is_empty() {
                    let _ = uc.mem_write(x4, &bytes);
                }
            }
            0
        }

        // 221: GetStringUTFRegion
        221 => {
            let start = (x2 as i32).max(0) as usize;
            let len = (x3 as i32).max(0) as usize;
            let chunk = get_state(uc.get_data_mut())
                .0
                .objects
                .get_string(JObjectRef(x1))
                .map(|s| {
                    let b = s.as_bytes();
                    let end = start.saturating_add(len).min(b.len());
                    let mut v = if start < b.len() {
                        b[start..end].to_vec()
                    } else {
                        Vec::new()
                    };
                    v.push(0);
                    v
                });
            if let Some(bytes) = chunk {
                if x4 != 0 {
                    let _ = uc.mem_write(x4, &bytes);
                }
            }
            0
        }

        // 228: ExceptionCheck
        228 => {
            if get_state(uc.get_data_mut()).0.pending_exception.is_null() {
                JNI_FALSE
            } else {
                JNI_TRUE
            }
        }

        // 229: NewDirectByteBuffer(env, address, capacity)
        229 => {
            let cap = (x2 as i64).max(0) as usize;
            get_state(uc.get_data_mut())
                .0
                .objects
                .add_local(JObject::DirectBuffer {
                    addr: x1,
                    capacity: cap,
                })
                .0
        }

        // 230: GetDirectBufferAddress
        230 => match get_state(uc.get_data_mut()).0.objects.get(JObjectRef(x1)) {
            Some(JObject::DirectBuffer { addr, .. }) => *addr,
            _ => 0,
        },

        // 231: GetDirectBufferCapacity
        231 => match get_state(uc.get_data_mut()).0.objects.get(JObjectRef(x1)) {
            Some(JObject::DirectBuffer { capacity, .. }) => *capacity as i64 as u64,
            _ => (-1i64) as u64,
        },

        // 232: GetObjectRefType
        232 => get_state(uc.get_data_mut())
            .0
            .objects
            .ref_type(JObjectRef(x1)),

        _ => {
            tracing::warn!(target: "runidbg::jni", "[JNI] 未实现的 JNIEnv 槽位: slot={slot}");
            0
        }
    };

    let _ = uc.reg_write(RegisterARM64::X0, ret);
}

#[allow(clippy::too_many_arguments)]
fn dispatch_nonvirtual_call<D, F, H>(
    uc: &mut Unicorn<'_, D>,
    slot: usize,
    base_slot: usize,
    obj_raw: u64,
    mid_raw: u64,
    x4: u64,
    get_state: &mut F,
    invoke: H,
) -> u64
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager),
    H: FnOnce(&mut dyn JniHandler, &mut JniContext<'_>, JObjectRef, &MethodDesc, &[JValue]) -> u64,
{
    let Some(method) = get_state(uc.get_data_mut()).0.methods.get(&mid_raw).cloned() else {
        return 0;
    };
    let args = read_jni_call_args_at(uc, slot, base_slot, 4, x4, &method.sig);
    let (vm, _) = get_state(uc.get_data_mut());
    let mut ctx = JniContext {
        objects: &mut vm.objects,
        package_name: &vm.package_name,
    };
    invoke(vm.handler.as_mut(), &mut ctx, JObjectRef(obj_raw), &method, &args)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_instance_call<D, F, H>(
    uc: &mut Unicorn<'_, D>,
    slot: usize,
    base_slot: usize,
    obj_raw: u64,
    mid_raw: u64,
    x3: u64,
    get_state: &mut F,
    invoke: H,
) -> u64
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager),
    H: FnOnce(&mut dyn JniHandler, &mut JniContext<'_>, JObjectRef, &MethodDesc, &[JValue]) -> u64,
{
    let Some(method) = get_state(uc.get_data_mut()).0.methods.get(&mid_raw).cloned() else {
        return 0;
    };
    let args = read_jni_call_args(uc, slot, base_slot, x3, &method.sig);
    let (vm, _) = get_state(uc.get_data_mut());
    let ret = {
        let mut ctx = JniContext {
            objects: &mut vm.objects,
            package_name: &vm.package_name,
        };
        invoke(vm.handler.as_mut(), &mut ctx, JObjectRef(obj_raw), &method, &args)
    };
    if vm.jni_tracer.enabled {
        let max_len = vm.jni_tracer.max_str_len;
        let obj_cls = vm
            .objects
            .get(JObjectRef(obj_raw))
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| method.class_name.clone());
        let arg_strs: Vec<String> = args
            .iter()
            .map(|a| format_jvalue_summary(&vm.objects, a, max_len))
            .collect();
        let (ret_s, is_null) = format_call_return_summary(&vm.objects, base_slot, ret, max_len);
        vm.jni_tracer.record(
            call_op_name(base_slot),
            obj_cls,
            obj_raw,
            method.name,
            method.sig,
            arg_strs,
            ret_s,
            is_null,
        );
    }
    ret
}

#[allow(clippy::too_many_arguments)]
fn dispatch_static_call<D, F, H>(
    uc: &mut Unicorn<'_, D>,
    slot: usize,
    base_slot: usize,
    cls_raw: u64,
    mid_raw: u64,
    x3: u64,
    get_state: &mut F,
    invoke: H,
) -> u64
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager),
    H: FnOnce(&mut dyn JniHandler, &mut JniContext<'_>, &str, &MethodDesc, &[JValue]) -> u64,
{
    let (class_name, method) = {
        let (vm, _) = get_state(uc.get_data_mut());
        (
            vm.resolve_class_name(JObjectRef(cls_raw)),
            vm.methods.get(&mid_raw).cloned(),
        )
    };
    let Some(method) = method else {
        return 0;
    };
    let args = read_jni_call_args(uc, slot, base_slot, x3, &method.sig);
    let (vm, _) = get_state(uc.get_data_mut());
    let ret = {
        let mut ctx = JniContext {
            objects: &mut vm.objects,
            package_name: &vm.package_name,
        };
        invoke(vm.handler.as_mut(), &mut ctx, &class_name, &method, &args)
    };
    if vm.jni_tracer.enabled {
        let max_len = vm.jni_tracer.max_str_len;
        let arg_strs: Vec<String> = args
            .iter()
            .map(|a| format_jvalue_summary(&vm.objects, a, max_len))
            .collect();
        let (ret_s, is_null) = format_call_return_summary(&vm.objects, base_slot, ret, max_len);
        vm.jni_tracer.record(
            call_op_name(base_slot),
            class_name,
            cls_raw,
            method.name,
            method.sig,
            arg_strs,
            ret_s,
            is_null,
        );
    }
    ret
}

fn dispatch_instance_field<D, F, H>(
    uc: &mut Unicorn<'_, D>,
    obj_raw: u64,
    fid_raw: u64,
    get_state: &mut F,
    invoke: H,
) -> u64
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager),
    H: FnOnce(&mut dyn JniHandler, &mut JniContext<'_>, JObjectRef, &FieldDesc) -> u64,
{
    let (vm, _) = get_state(uc.get_data_mut());
    let Some(field) = vm.fields.get(&fid_raw).cloned() else {
        return 0;
    };
    let mut ctx = JniContext {
        objects: &mut vm.objects,
        package_name: &vm.package_name,
    };
    invoke(vm.handler.as_mut(), &mut ctx, JObjectRef(obj_raw), &field)
}

/// 将 `DeviceProfile` 自动映射到 `android/os/Build` 与 `android/os/Build$VERSION` 静态字段
fn resolve_builtin_build_object_field(
    objects: &mut ObjectTable,
    dp: &DeviceProfile,
    cls: &str,
    field: &FieldDesc,
) -> JObjectRef {
    match (cls, field.name.as_str()) {
        ("android/os/Build", "BRAND") => objects.add_string(&dp.brand),
        ("android/os/Build", "MANUFACTURER") => objects.add_string(&dp.manufacturer),
        ("android/os/Build", "MODEL") => objects.add_string(&dp.model),
        ("android/os/Build", "DEVICE") => objects.add_string(&dp.device),
        ("android/os/Build", "PRODUCT") => objects.add_string(&dp.product),
        ("android/os/Build", "BOARD") => objects.add_string(&dp.board),
        ("android/os/Build", "HARDWARE") => objects.add_string(&dp.hardware),
        ("android/os/Build", "FINGERPRINT") => objects.add_string(&dp.fingerprint),
        ("android/os/Build", "ID") => objects.add_string(&dp.build_id),
        ("android/os/Build", "DISPLAY") => objects.add_string(&dp.build_display),
        ("android/os/Build", "SERIAL") => objects.add_string(&dp.serial_no),
        ("android/os/Build", "CPU_ABI") => objects.add_string(&dp.abi),
        ("android/os/Build", "TYPE") => objects.add_string("user"),
        ("android/os/Build", "TAGS") => objects.add_string("release-keys"),
        ("android/os/Build", "SUPPORTED_ABIS") | ("android/os/Build", "SUPPORTED_64_BIT_ABIS") => {
            let refs: Vec<JObjectRef> = dp
                .abi_list
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| objects.add_string(s.trim()))
                .collect();
            objects.add_local(JObject::ObjectArray(refs))
        }
        ("android/os/Build$VERSION", "RELEASE") => objects.add_string(&dp.android_release),
        ("android/os/Build$VERSION", "INCREMENTAL") => objects.add_string(&dp.incremental),
        ("android/os/Build$VERSION", "SECURITY_PATCH") => objects.add_string(&dp.security_patch),
        ("android/os/Build$VERSION", "CODENAME") => objects.add_string("REL"),
        // Java 基础包装类原始类型 Class 常量（JNA 等库在 JNI_OnLoad 阶段高频读取）
        ("java/lang/Void", "TYPE") => objects.find_or_create_class("void"),
        ("java/lang/Boolean", "TYPE") => objects.find_or_create_class("boolean"),
        ("java/lang/Byte", "TYPE") => objects.find_or_create_class("byte"),
        ("java/lang/Character", "TYPE") => objects.find_or_create_class("char"),
        ("java/lang/Short", "TYPE") => objects.find_or_create_class("short"),
        ("java/lang/Integer", "TYPE") => objects.find_or_create_class("int"),
        ("java/lang/Long", "TYPE") => objects.find_or_create_class("long"),
        ("java/lang/Float", "TYPE") => objects.find_or_create_class("float"),
        ("java/lang/Double", "TYPE") => objects.find_or_create_class("double"),
        ("java/lang/Boolean", "TRUE") => {
            let mut fields = HashMap::new();
            fields.insert("value".to_string(), JValue::Boolean(true));
            objects.add_local(JObject::Custom {
                class_name: "java/lang/Boolean".to_string(),
                fields,
            })
        }
        ("java/lang/Boolean", "FALSE") => {
            let mut fields = HashMap::new();
            fields.insert("value".to_string(), JValue::Boolean(false));
            objects.add_local(JObject::Custom {
                class_name: "java/lang/Boolean".to_string(),
                fields,
            })
        }
        _ => JObjectRef::NULL,
    }
}

/// 将 DEX `static_values` 中的对象/数组常量转换为 JNI `JObjectRef`
fn dex_value_to_jobject(objects: &mut ObjectTable, val: &DexValue, field_sig: &str) -> JObjectRef {
    match val {
        DexValue::String(s) => {
            if field_sig == "[C" {
                objects.add_char_array(s.encode_utf16().collect::<Vec<u16>>())
            } else {
                objects.add_string(s.clone())
            }
        }
        DexValue::Type(cls) => objects.find_or_create_class(cls),
        DexValue::Array(elems) => match field_sig {
            "[C" => {
                let chars: Vec<u16> = elems
                    .iter()
                    .map(|e| match e {
                        DexValue::Char(c) => *c,
                        DexValue::Int(i) => *i as u16,
                        DexValue::Byte(b) => *b as u8 as u16,
                        _ => 0,
                    })
                    .collect();
                objects.add_char_array(chars)
            }
            "[B" => {
                let bytes: Vec<u8> = elems
                    .iter()
                    .map(|e| match e {
                        DexValue::Byte(b) => *b as u8,
                        DexValue::Int(i) => *i as u8,
                        _ => 0,
                    })
                    .collect();
                objects.add_byte_array(bytes)
            }
            "[I" => {
                let ints: Vec<i32> = elems
                    .iter()
                    .map(|e| match e {
                        DexValue::Int(i) => *i,
                        DexValue::Short(s) => i32::from(*s),
                        DexValue::Byte(b) => i32::from(*b),
                        _ => 0,
                    })
                    .collect();
                objects.add_int_array(ints)
            }
            "[J" => {
                let longs: Vec<i64> = elems
                    .iter()
                    .map(|e| match e {
                        DexValue::Long(l) => *l,
                        DexValue::Int(i) => i64::from(*i),
                        _ => 0,
                    })
                    .collect();
                objects.add_long_array(longs)
            }
            "[Z" => {
                let bools: Vec<u8> = elems
                    .iter()
                    .map(|e| u8::from(matches!(e, DexValue::Boolean(true))))
                    .collect();
                objects.add_local(JObject::BooleanArray(bools))
            }
            "[S" => {
                let shorts: Vec<i16> = elems
                    .iter()
                    .map(|e| match e {
                        DexValue::Short(s) => *s,
                        DexValue::Int(i) => *i as i16,
                        _ => 0,
                    })
                    .collect();
                objects.add_local(JObject::ShortArray(shorts))
            }
            "[F" => {
                let floats: Vec<f32> = elems
                    .iter()
                    .map(|e| match e {
                        DexValue::Float(f) => *f,
                        _ => 0.0,
                    })
                    .collect();
                objects.add_local(JObject::FloatArray(floats))
            }
            "[D" => {
                let doubles: Vec<f64> = elems
                    .iter()
                    .map(|e| match e {
                        DexValue::Double(d) => *d,
                        _ => 0.0,
                    })
                    .collect();
                objects.add_local(JObject::DoubleArray(doubles))
            }
            _ => {
                let refs: Vec<JObjectRef> = elems
                    .iter()
                    .map(|e| dex_value_to_jobject(objects, e, ""))
                    .collect();
                objects.add_local(JObject::ObjectArray(refs))
            }
        },
        _ => JObjectRef::NULL,
    }
}
