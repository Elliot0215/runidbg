use std::collections::{HashMap, HashSet};

/// JNI 标准状态码与常量
pub const JNI_OK: i32 = 0;
pub const JNI_ERR: i32 = -1;
pub const JNI_VERSION_1_6: i32 = 0x0001_0006;
pub const JNI_FALSE: u64 = 0;
pub const JNI_TRUE: u64 = 1;
/// Release*ArrayElements 模式：释放缓冲但不回写
pub const JNI_ABORT: i32 = 2;

/// 伪造 Java 对象句柄（jobject / jclass / jstring / jbyteArray）
/// 约定：0 代表 Java `null`，有效句柄从 `0x1000_0001` 递增分配，便于调试区分指针与句柄
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct JObjectRef(pub u64);

impl JObjectRef {
    pub const NULL: Self = Self(0);

    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// JNI 方法参数与返回值统一封装（对应 C 侧 `jvalue` union）
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JValue {
    Void,
    Boolean(bool),
    Byte(i8),
    Char(u16),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Object(JObjectRef),
}

impl JValue {
    /// 转换为 AAPCS64 通用寄存器 `X0` 编码值
    pub fn as_u64(&self) -> u64 {
        match *self {
            Self::Void => 0,
            Self::Boolean(b) => u64::from(b),
            Self::Byte(v) => v as i64 as u64,
            Self::Char(v) => u64::from(v),
            Self::Short(v) => v as i64 as u64,
            Self::Int(v) => v as i64 as u64,
            Self::Long(v) => v as u64,
            Self::Float(v) => u64::from(v.to_bits()),
            Self::Double(v) => v.to_bits(),
            Self::Object(r) => r.0,
        }
    }

    pub fn as_object(&self) -> Option<JObjectRef> {
        match *self {
            Self::Object(r) => Some(r),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i32> {
        match *self {
            Self::Int(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_long(&self) -> Option<i64> {
        match *self {
            Self::Long(v) => Some(v),
            Self::Int(v) => Some(i64::from(v)),
            _ => None,
        }
    }
}

/// 内置 Android/Java 常见对象模型
#[derive(Debug, Clone)]
pub enum JObject {
    /// `java/lang/String`
    String(String),
    /// `[Z` (`jbooleanArray`)
    BooleanArray(Vec<u8>),
    /// `[B` (`jbyteArray`)
    ByteArray(Vec<u8>),
    /// `[C` (`jcharArray`)
    CharArray(Vec<u16>),
    /// `[S` (`jshortArray`)
    ShortArray(Vec<i16>),
    /// `[I` (`jintArray`)
    IntArray(Vec<i32>),
    /// `[J` (`jlongArray`)
    LongArray(Vec<i64>),
    /// `[F` (`jfloatArray`)
    FloatArray(Vec<f32>),
    /// `[D` (`jdoubleArray`)
    DoubleArray(Vec<f64>),
    /// `java/nio/DirectByteBuffer`
    DirectBuffer { addr: u64, capacity: usize },
    /// `java/lang/reflect/Method`
    ReflectedMethod { method_id: u64 },
    /// `java/lang/reflect/Field`
    ReflectedField { field_id: u64 },
    /// `java/lang/Class` (`jclass`)
    Class { name: String },
    /// `android/content/Context`
    Context { package_name: String },
    /// `android/content/pm/PackageManager`
    PackageManager,
    /// `android/content/pm/PackageInfo`
    PackageInfo {
        package_name: String,
        version_name: String,
        version_code: i32,
    },
    /// `android/content/pm/Signature`
    Signature(Vec<u8>),
    /// `[Ljava/lang/Object;`
    ObjectArray(Vec<JObjectRef>),
    /// `java/lang/StringBuilder` / `java/lang/StringBuffer`
    StringBuilder(String),
    /// `java/util/ArrayList` / `LinkedList` / `HashSet` / `List` / `Set`
    List {
        class_name: String,
        items: Vec<JObjectRef>,
    },
    /// `java/util/HashMap` / `LinkedHashMap` / `Map`
    Map {
        class_name: String,
        entries: Vec<(JObjectRef, JObjectRef)>,
    },
    /// `java/util/Iterator`
    Iterator {
        items: Vec<JObjectRef>,
        pos: usize,
    },
    /// 用户自定义对象模型，支持按字段名挂载任意 `JValue`
    Custom {
        class_name: String,
        fields: HashMap<String, JValue>,
    },
}

impl JObject {
    /// 返回对象对应的 JNI 内部类名（如 `java/lang/String`）
    pub fn class_name(&self) -> &str {
        match self {
            Self::String(_) => "java/lang/String",
            Self::BooleanArray(_) => "[Z",
            Self::ByteArray(_) => "[B",
            Self::CharArray(_) => "[C",
            Self::ShortArray(_) => "[S",
            Self::IntArray(_) => "[I",
            Self::LongArray(_) => "[J",
            Self::FloatArray(_) => "[F",
            Self::DoubleArray(_) => "[D",
            Self::DirectBuffer { .. } => "java/nio/DirectByteBuffer",
            Self::ReflectedMethod { .. } => "java/lang/reflect/Method",
            Self::ReflectedField { .. } => "java/lang/reflect/Field",
            Self::Class { name } => name.as_str(),
            Self::Context { .. } => "android/content/Context",
            Self::PackageManager => "android/content/pm/PackageManager",
            Self::PackageInfo { .. } => "android/content/pm/PackageInfo",
            Self::Signature(_) => "android/content/pm/Signature",
            Self::ObjectArray(_) => "[Ljava/lang/Object;",
            Self::StringBuilder(_) => "java/lang/StringBuilder",
            Self::List { class_name, .. } | Self::Map { class_name, .. } => class_name.as_str(),
            Self::Iterator { .. } => "java/util/Iterator",
            Self::Custom { class_name, .. } => class_name.as_str(),
        }
    }

    /// 返回数组长度（非数组对象返回 `None`）
    pub fn array_len(&self) -> Option<usize> {
        match self {
            Self::BooleanArray(v) | Self::ByteArray(v) => Some(v.len()),
            Self::CharArray(v) => Some(v.len()),
            Self::ShortArray(v) => Some(v.len()),
            Self::IntArray(v) => Some(v.len()),
            Self::LongArray(v) => Some(v.len()),
            Self::FloatArray(v) => Some(v.len()),
            Self::DoubleArray(v) => Some(v.len()),
            Self::ObjectArray(v) => Some(v.len()),
            _ => None,
        }
    }

    /// 返回基础类型数组的单个元素字节大小
    pub fn primitive_elem_size(&self) -> Option<usize> {
        match self {
            Self::BooleanArray(_) | Self::ByteArray(_) => Some(1),
            Self::CharArray(_) | Self::ShortArray(_) => Some(2),
            Self::IntArray(_) | Self::FloatArray(_) => Some(4),
            Self::LongArray(_) | Self::DoubleArray(_) => Some(8),
            _ => None,
        }
    }

    /// 将任意基础类型数组序列化为小端字节数组（供 `Get*ArrayElements` / `Get*ArrayRegion` 共用）
    pub fn to_primitive_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::BooleanArray(v) | Self::ByteArray(v) => Some(v.clone()),
            Self::CharArray(v) => Some(v.iter().flat_map(|x| x.to_le_bytes()).collect()),
            Self::ShortArray(v) => Some(v.iter().flat_map(|x| x.to_le_bytes()).collect()),
            Self::IntArray(v) => Some(v.iter().flat_map(|x| x.to_le_bytes()).collect()),
            Self::LongArray(v) => Some(v.iter().flat_map(|x| x.to_le_bytes()).collect()),
            Self::FloatArray(v) => Some(v.iter().flat_map(|x| x.to_le_bytes()).collect()),
            Self::DoubleArray(v) => Some(v.iter().flat_map(|x| x.to_le_bytes()).collect()),
            _ => None,
        }
    }

    /// 将小端字节切片回写到基础类型数组的指定元素偏移（供 `Release*ArrayElements` / `Set*ArrayRegion` 共用）
    pub fn write_primitive_bytes(&mut self, offset_elems: usize, bytes: &[u8]) -> bool {
        match self {
            Self::BooleanArray(v) | Self::ByteArray(v) => {
                let end = (offset_elems + bytes.len()).min(v.len());
                if offset_elems <= end {
                    v[offset_elems..end].copy_from_slice(&bytes[..end - offset_elems]);
                }
                true
            }
            Self::CharArray(v) => {
                for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
                    if let Some(slot) = v.get_mut(offset_elems + i) {
                        *slot = u16::from_le_bytes(*chunk);
                    }
                }
                true
            }
            Self::ShortArray(v) => {
                for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
                    if let Some(slot) = v.get_mut(offset_elems + i) {
                        *slot = i16::from_le_bytes(*chunk);
                    }
                }
                true
            }
            Self::IntArray(v) => {
                for (i, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
                    if let Some(slot) = v.get_mut(offset_elems + i) {
                        *slot = i32::from_le_bytes(*chunk);
                    }
                }
                true
            }
            Self::LongArray(v) => {
                for (i, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
                    if let Some(slot) = v.get_mut(offset_elems + i) {
                        *slot = i64::from_le_bytes(*chunk);
                    }
                }
                true
            }
            Self::FloatArray(v) => {
                for (i, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
                    if let Some(slot) = v.get_mut(offset_elems + i) {
                        *slot = f32::from_le_bytes(*chunk);
                    }
                }
                true
            }
            Self::DoubleArray(v) => {
                for (i, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
                    if let Some(slot) = v.get_mut(offset_elems + i) {
                        *slot = f64::from_le_bytes(*chunk);
                    }
                }
                true
            }
            _ => false,
        }
    }
}

/// `jmethodID` 元数据描述
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDesc {
    pub class_name: String,
    pub name: String,
    pub sig: String,
    pub is_static: bool,
}

/// `jfieldID` 元数据描述
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDesc {
    pub class_name: String,
    pub name: String,
    pub sig: String,
    pub is_static: bool,
}

/// 通过 `RegisterNatives` 动态注册的本地方法记录
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredNative {
    pub class_name: String,
    pub name: String,
    pub sig: String,
    pub fn_ptr: u64,
}

/// JNI 对象引用表：统一管理 LocalRef 与 GlobalRef 生命周期
#[derive(Debug, Clone)]
pub struct ObjectTable {
    next_handle: u64,
    objects: HashMap<u64, JObject>,
    local_refs: HashSet<u64>,
    global_refs: HashMap<u64, usize>,
    class_cache: HashMap<String, JObjectRef>,
    /// `PushLocalFrame` / `PopLocalFrame` 帧水位栈（记录进入帧时的 `next_handle`）
    local_frames: Vec<u64>,
}

impl Default for ObjectTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectTable {
    pub fn new() -> Self {
        Self {
            next_handle: 0x1000_0001,
            objects: HashMap::new(),
            local_refs: HashSet::new(),
            global_refs: HashMap::new(),
            class_cache: HashMap::new(),
            local_frames: Vec::new(),
        }
    }

    /// 压入一层 JNI 局部引用帧（与 `pop_local_frame` 配对，用于常驻 RPC 批量回收单次请求产生的临时 LocalRef）
    pub fn push_local_frame(&mut self) {
        self.local_frames.push(self.next_handle);
    }

    /// 弹出当前局部引用帧，回收该帧内创建的全部无 GlobalRef 持有的 LocalRef（可选保留一个返回值句柄 `keep`）
    pub fn pop_local_frame(&mut self, keep: JObjectRef) -> usize {
        let Some(watermark) = self.local_frames.pop() else {
            return 0;
        };
        let keep_id = keep.0;
        let to_drop_local: Vec<u64> = self
            .local_refs
            .iter()
            .copied()
            .filter(|&h| h >= watermark && h != keep_id)
            .collect();
        for &h in &to_drop_local {
            self.local_refs.remove(&h);
        }

        // 若保留对象是容器（如 ObjectArray），保护其内部元素不被清理
        let mut protected: HashSet<u64> = HashSet::new();
        if keep_id != 0 {
            protected.insert(keep_id);
            if let Some(obj) = self.objects.get(&keep_id) {
                match obj {
                    JObject::ObjectArray(elems) => {
                        for e in elems {
                            if !e.is_null() {
                                protected.insert(e.0);
                            }
                        }
                    }
                    JObject::Custom { fields, .. } => {
                        for v in fields.values() {
                            if let Some(r) = v.as_object() {
                                if !r.is_null() {
                                    protected.insert(r.0);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // 也保护仍被帧外对象或 GlobalRef 引用的对象
        for (&id, obj) in &self.objects {
            if id < watermark || self.global_refs.contains_key(&id) {
                match obj {
                    JObject::ObjectArray(elems) => {
                        for e in elems {
                            if !e.is_null() {
                                protected.insert(e.0);
                            }
                        }
                    }
                    JObject::Custom { fields, .. } => {
                        for v in fields.values() {
                            if let Some(r) = v.as_object() {
                                if !r.is_null() {
                                    protected.insert(r.0);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut removed = 0usize;
        let candidates: Vec<u64> = self
            .objects
            .keys()
            .copied()
            .filter(|&h| h >= watermark && h != keep_id)
            .collect();
        for h in candidates {
            if !self.global_refs.contains_key(&h)
                && !protected.contains(&h)
                && self.objects.remove(&h).is_some()
            {
                removed += 1;
            }
        }
        removed
    }

    /// 分配一个 LocalRef 句柄
    pub fn add_local(&mut self, obj: JObject) -> JObjectRef {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.objects.insert(handle, obj);
        self.local_refs.insert(handle);
        JObjectRef(handle)
    }

    /// 便捷创建 `jstring` LocalRef
    pub fn add_string(&mut self, s: impl Into<String>) -> JObjectRef {
        self.add_local(JObject::String(s.into()))
    }

    /// 便捷创建 `jbyteArray` LocalRef
    pub fn add_byte_array(&mut self, bytes: impl Into<Vec<u8>>) -> JObjectRef {
        self.add_local(JObject::ByteArray(bytes.into()))
    }

    /// 便捷创建 `jcharArray` (`[C`, UTF-16) LocalRef
    pub fn add_char_array(&mut self, chars: impl Into<Vec<u16>>) -> JObjectRef {
        self.add_local(JObject::CharArray(chars.into()))
    }

    /// 便捷创建 `jintArray` (`[I`) LocalRef
    pub fn add_int_array(&mut self, ints: impl Into<Vec<i32>>) -> JObjectRef {
        self.add_local(JObject::IntArray(ints.into()))
    }

    /// 便捷创建 `jlongArray` (`[J`) LocalRef
    pub fn add_long_array(&mut self, longs: impl Into<Vec<i64>>) -> JObjectRef {
        self.add_local(JObject::LongArray(longs.into()))
    }

    /// 查找或缓存 `jclass` 句柄（类名统一归一化为斜杠格式，如 `com/test/Native`）
    pub fn find_or_create_class(&mut self, name: &str) -> JObjectRef {
        let normalized = name.replace('.', "/");
        if let Some(&existing) = self.class_cache.get(&normalized) {
            return existing;
        }
        let r = self.add_local(JObject::Class {
            name: normalized.clone(),
        });
        // Class 对象默认常驻 GlobalRef，防止被 DeleteLocalRef 误回收
        self.new_global(r);
        self.class_cache.insert(normalized, r);
        r
    }

    /// 为已有对象增加 GlobalRef 计数
    pub fn new_global(&mut self, r: JObjectRef) -> JObjectRef {
        if r.is_null() || !self.objects.contains_key(&r.0) {
            return JObjectRef::NULL;
        }
        *self.global_refs.entry(r.0).or_insert(0) += 1;
        r
    }

    /// 释放 LocalRef；若无 GlobalRef 持有则销毁底层对象
    fn is_referenced_by_container(&self, r: JObjectRef) -> bool {
        self.objects.values().any(|obj| match obj {
            JObject::ObjectArray(elems) => elems.contains(&r),
            JObject::List { items, .. } | JObject::Iterator { items, .. } => items.contains(&r),
            JObject::Map { entries, .. } => entries.iter().any(|(k, v)| *k == r || *v == r),
            JObject::Custom { fields, .. } => fields.values().any(|v| v.as_object() == Some(r)),
            _ => false,
        })
    }

    pub fn delete_local(&mut self, r: JObjectRef) {
        if r.is_null() {
            return;
        }
        self.local_refs.remove(&r.0);
        if !self.global_refs.contains_key(&r.0) && !self.is_referenced_by_container(r) {
            self.objects.remove(&r.0);
        }
    }

    /// 减少 GlobalRef 计数；计数归零且无 LocalRef 持有则销毁底层对象
    pub fn delete_global(&mut self, r: JObjectRef) {
        if r.is_null() {
            return;
        }
        if let Some(cnt) = self.global_refs.get_mut(&r.0) {
            if *cnt <= 1 {
                self.global_refs.remove(&r.0);
            } else {
                *cnt -= 1;
            }
        }
        if !self.global_refs.contains_key(&r.0) && !self.local_refs.contains(&r.0) {
            self.objects.remove(&r.0);
        }
    }

    pub fn get(&self, r: JObjectRef) -> Option<&JObject> {
        if r.is_null() {
            None
        } else {
            self.objects.get(&r.0)
        }
    }

    pub fn get_mut(&mut self, r: JObjectRef) -> Option<&mut JObject> {
        if r.is_null() {
            None
        } else {
            self.objects.get_mut(&r.0)
        }
    }

    pub fn get_string(&self, r: JObjectRef) -> Option<&str> {
        match self.get(r)? {
            JObject::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn get_bytes(&self, r: JObjectRef) -> Option<&[u8]> {
        match self.get(r)? {
            JObject::ByteArray(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn get_chars(&self, r: JObjectRef) -> Option<&[u16]> {
        match self.get(r)? {
            JObject::CharArray(c) => Some(c.as_slice()),
            _ => None,
        }
    }

    pub fn get_ints(&self, r: JObjectRef) -> Option<&[i32]> {
        match self.get(r)? {
            JObject::IntArray(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn get_longs(&self, r: JObjectRef) -> Option<&[i64]> {
        match self.get(r)? {
            JObject::LongArray(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// 返回 JNI `jobjectRefType`: 0=Invalid, 1=Local, 2=Global
    pub fn ref_type(&self, r: JObjectRef) -> u64 {
        if r.is_null() || !self.objects.contains_key(&r.0) {
            0
        } else if self.global_refs.contains_key(&r.0) {
            2
        } else if self.local_refs.contains(&r.0) {
            1
        } else {
            0
        }
    }

    pub(crate) fn export_raw(&self) -> ObjectTableRaw {
        ObjectTableRaw {
            next_handle: self.next_handle,
            objects: self.objects.iter().map(|(&k, v)| (k, v.clone())).collect(),
            local_refs: self.local_refs.iter().copied().collect(),
            global_refs: self.global_refs.iter().map(|(&k, &v)| (k, v)).collect(),
            class_cache: self
                .class_cache
                .iter()
                .map(|(k, &v)| (k.clone(), v))
                .collect(),
            local_frames: self.local_frames.clone(),
        }
    }

    pub(crate) fn from_raw(raw: ObjectTableRaw) -> Self {
        Self {
            next_handle: raw.next_handle,
            objects: raw.objects.into_iter().collect(),
            local_refs: raw.local_refs.into_iter().collect(),
            global_refs: raw.global_refs.into_iter().collect(),
            class_cache: raw.class_cache.into_iter().collect(),
            local_frames: raw.local_frames,
        }
    }
}

/// `ObjectTable` 原始可序列化表示（供 `.rtape` 磁带使用）
#[derive(Debug, Clone)]
pub(crate) struct ObjectTableRaw {
    pub next_handle: u64,
    pub objects: Vec<(u64, JObject)>,
    pub local_refs: Vec<u64>,
    pub global_refs: Vec<(u64, usize)>,
    pub class_cache: Vec<(String, JObjectRef)>,
    pub local_frames: Vec<u64>,
}
