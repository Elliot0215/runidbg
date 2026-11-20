use std::collections::HashMap;

use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::error::EmuResult;
use crate::jni::handler::{DefaultJniHandler, JniContext, JniHandler};
use crate::jni::types::{
    FieldDesc, JObject, JObjectRef, JValue, MethodDesc, ObjectTable, RegisteredNative, JNI_ABORT,
    JNI_ERR, JNI_FALSE, JNI_OK, JNI_TRUE, JNI_VERSION_1_6,
};
use crate::jni::va_list::{
    read_varargs_direct, read_varargs_jvalue_array, read_varargs_va_list,
};
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
            pending_exception: JObjectRef::NULL,
            utf_buffers: HashMap::new(),
            array_buffers: HashMap::new(),
            handler,
            initialized: false,
        }
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
            let mut ctx = JniContext {
                objects: &mut vm.objects,
                package_name: &vm.package_name,
            };
            vm.handler.find_class(&mut ctx, &name).0
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
                if vm.resolve_class_name(JObjectRef(x2)) == "java/lang/Object" {
                    JNI_TRUE
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

        // 19: PushLocalFrame / 26: EnsureLocalCapacity
        19 | 26 => JNI_OK as u64,

        // 20: PopLocalFrame / 25: NewLocalRef
        20 | 25 => x1,

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
            vm.intern_method(cls, name, sig, slot == 113)
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
            vm.intern_field(cls, name, sig, slot == 144)
        }

        // 实例字段读取 (95..=103)
        95 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            h.get_object_field(ctx, o, f).0
        }),
        96 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            u64::from(h.get_boolean_field(ctx, o, f))
        }),
        97 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            h.get_byte_field(ctx, o, f) as i64 as u64
        }),
        98 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            u64::from(h.get_char_field(ctx, o, f))
        }),
        99 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            h.get_short_field(ctx, o, f) as i64 as u64
        }),
        100 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            h.get_int_field(ctx, o, f) as i64 as u64
        }),
        101 => dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
            h.get_long_field(ctx, o, f) as u64
        }),
        102 => {
            let bits = dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
                u64::from(h.get_float_field(ctx, o, f).to_bits())
            });
            let _ = uc.reg_write(RegisterARM64::S0, bits);
            bits
        }
        103 => {
            let bits = dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
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
            dispatch_instance_field(uc, x1, x2, get_state, |h, ctx, o, f| {
                h.set_field(ctx, o, f, val);
                0
            })
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
        145 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                let ret = {
                    let mut ctx = JniContext {
                        objects: &mut vm.objects,
                        package_name: &vm.package_name,
                    };
                    vm.handler.get_static_object_field(&mut ctx, &cls, &field)
                };
                if !ret.is_null() {
                    ret.0
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
                0
            }
        }
        146 => dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
            u64::from(h.get_static_boolean_field(ctx, cls, f))
        }),
        147 => dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
            h.get_static_byte_field(ctx, cls, f) as i64 as u64
        }),
        148 => dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
            u64::from(h.get_static_char_field(ctx, cls, f))
        }),
        149 => dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
            h.get_static_short_field(ctx, cls, f) as i64 as u64
        }),
        150 => {
            let (vm, _) = get_state(uc.get_data_mut());
            let cls = vm.resolve_class_name(JObjectRef(x1));
            if let Some(field) = vm.fields.get(&x2).cloned() {
                let val = {
                    let mut ctx = JniContext {
                        objects: &mut vm.objects,
                        package_name: &vm.package_name,
                    };
                    vm.handler.get_static_int_field(&mut ctx, &cls, &field)
                };
                if val != 0 {
                    val as i64 as u64
                } else if cls == "android/os/Build$VERSION" && field.name == "SDK_INT" {
                    (vm.device_profile.sdk_int as i32) as i64 as u64
                } else {
                    0
                }
            } else {
                0
            }
        }
        151 => dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
            h.get_static_long_field(ctx, cls, f) as u64
        }),
        152 => {
            let bits = dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
                u64::from(h.get_static_float_field(ctx, cls, f).to_bits())
            });
            let _ = uc.reg_write(RegisterARM64::S0, bits);
            bits
        }
        153 => {
            let bits = dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
                h.get_static_double_field(ctx, cls, f).to_bits()
            });
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
            dispatch_static_field(uc, x1, x2, get_state, |h, ctx, cls, f| {
                h.set_static_field(ctx, cls, f, val);
                0
            })
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
            get_state(uc.get_data_mut()).0.utf_buffers.remove(&x2);
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
    let mut ctx = JniContext {
        objects: &mut vm.objects,
        package_name: &vm.package_name,
    };
    invoke(vm.handler.as_mut(), &mut ctx, JObjectRef(obj_raw), &method, &args)
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
    let mut ctx = JniContext {
        objects: &mut vm.objects,
        package_name: &vm.package_name,
    };
    invoke(vm.handler.as_mut(), &mut ctx, &class_name, &method, &args)
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

fn dispatch_static_field<D, F, H>(
    uc: &mut Unicorn<'_, D>,
    cls_raw: u64,
    fid_raw: u64,
    get_state: &mut F,
    invoke: H,
) -> u64
where
    F: FnMut(&mut D) -> (&mut JniVm, &mut MemoryManager),
    H: FnOnce(&mut dyn JniHandler, &mut JniContext<'_>, &str, &FieldDesc) -> u64,
{
    let (vm, _) = get_state(uc.get_data_mut());
    let cls = vm.resolve_class_name(JObjectRef(cls_raw));
    let Some(field) = vm.fields.get(&fid_raw).cloned() else {
        return 0;
    };
    let mut ctx = JniContext {
        objects: &mut vm.objects,
        package_name: &vm.package_name,
    };
    invoke(vm.handler.as_mut(), &mut ctx, &cls, &field)
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
        _ => JObjectRef::NULL,
    }
}
