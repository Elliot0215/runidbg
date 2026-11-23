use std::collections::HashMap;
use std::path::Path;

use crate::error::{EmuError, EmuResult};

const NO_INDEX: u32 = 0xFFFF_FFFF;

/// DEX 中解析出的编译期静态字段初值（`static_values_off` / `encoded_array_item`）
#[derive(Debug, Clone, PartialEq)]
pub enum DexValue {
    Null,
    Boolean(bool),
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(String),
    Type(String),
    Array(Vec<DexValue>),
}

/// DEX 字段描述
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexFieldInfo {
    pub name: String,
    pub sig: String,
    pub access_flags: u32,
    pub is_static: bool,
}

/// DEX 方法描述
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexMethodInfo {
    pub name: String,
    pub sig: String,
    pub access_flags: u32,
    pub is_direct: bool,
}

/// 单个类的 DEX 元数据摘要
#[derive(Debug, Clone, Default)]
pub struct DexClassInfo {
    pub name: String,
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub access_flags: u32,
    pub fields: Vec<DexFieldInfo>,
    pub methods: Vec<DexMethodInfo>,
    pub static_values: HashMap<String, DexValue>,
}

/// 多 DEX 聚合索引（支持 `classes.dex`、`classes2.dex`...）
#[derive(Debug, Clone, Default)]
pub struct DexIndex {
    classes: HashMap<String, DexClassInfo>,
    dex_count: usize,
}

impl DexIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    pub fn dex_count(&self) -> usize {
        self.dex_count
    }

    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    pub(crate) fn export_raw(&self) -> (usize, Vec<DexClassInfo>) {
        (self.dex_count, self.classes.values().cloned().collect())
    }

    pub(crate) fn from_raw(dex_count: usize, classes: Vec<DexClassInfo>) -> Self {
        let mut map = HashMap::with_capacity(classes.len());
        for cls in classes {
            map.insert(cls.name.clone(), cls);
        }
        Self {
            classes: map,
            dex_count,
        }
    }

    /// 从磁盘路径解析并合并一个 `.dex` 文件
    pub fn add_dex_path(&mut self, path: impl AsRef<Path>) -> EmuResult<usize> {
        let bytes = std::fs::read(path)?;
        self.add_dex_bytes(&bytes)
    }

    /// 从字节流解析并合并一个 `.dex` 文件，返回本次新增/更新的类数量
    pub fn add_dex_bytes(&mut self, data: &[u8]) -> EmuResult<usize> {
        let parsed = parse_dex_classes(data)?;
        let count = parsed.len();
        for cls in parsed {
            self.classes.insert(cls.name.clone(), cls);
        }
        self.dex_count += 1;
        Ok(count)
    }

    /// 判断类是否存在于已索引的 DEX 中（自动归一化 `.` -> `/`）
    pub fn has_class(&self, class_name: &str) -> bool {
        let norm = normalize_class_name(class_name);
        self.classes.contains_key(&norm)
    }

    /// 获取指定类的完整元数据
    pub fn get_class(&self, class_name: &str) -> Option<&DexClassInfo> {
        let norm = normalize_class_name(class_name);
        self.classes.get(&norm)
    }

    /// 查询类的直接父类名（如 `java/lang/Object`）
    pub fn get_superclass(&self, class_name: &str) -> Option<&str> {
        self.get_class(class_name)?.super_class.as_deref()
    }

    /// 判断 `sub` 是否可赋值给 `sup`（支持父类链与接口检查）
    pub fn is_assignable_from(&self, sub: &str, sup: &str) -> Option<bool> {
        let sub_n = normalize_class_name(sub);
        let sup_n = normalize_class_name(sup);
        if sub_n == sup_n || sup_n == "java/lang/Object" {
            return Some(true);
        }
        if !self.classes.contains_key(&sub_n) {
            return None;
        }
        let mut stack = vec![sub_n];
        let mut visited = std::collections::HashSet::new();
        while let Some(cur) = stack.pop() {
            if !visited.insert(cur.clone()) {
                continue;
            }
            if cur == sup_n {
                return Some(true);
            }
            if let Some(info) = self.classes.get(&cur) {
                if let Some(ref sc) = info.super_class {
                    stack.push(sc.clone());
                }
                for iface in &info.interfaces {
                    stack.push(iface.clone());
                }
            }
        }
        Some(false)
    }

    /// 查询类静态字段的编译期初值（沿父类链回退）
    pub fn get_static_value(&self, class_name: &str, field_name: &str) -> Option<&DexValue> {
        let mut cur = Some(normalize_class_name(class_name));
        let mut hops = 0usize;
        while let Some(name) = cur {
            if hops > 32 {
                break;
            }
            hops += 1;
            let info = self.classes.get(&name)?;
            if let Some(v) = info.static_values.get(field_name) {
                return Some(v);
            }
            cur = info.super_class.clone();
        }
        None
    }

    /// 按前缀列出已索引类名（已排序）
    pub fn list_classes(&self, prefix: Option<&str>) -> Vec<String> {
        let norm_prefix = prefix.map(normalize_class_name);
        let mut out: Vec<String> = self
            .classes
            .keys()
            .filter(|k| match &norm_prefix {
                Some(p) if !p.is_empty() => k.starts_with(p.as_str()),
                _ => true,
            })
            .cloned()
            .collect();
        out.sort();
        out
    }
}

/// 将 `Lcom/foo/Bar;` 或 `com.foo.Bar` 归一化为 JNI 斜杠格式 `com/foo/Bar`
pub fn normalize_class_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = if trimmed.starts_with('L') && trimmed.ends_with(';') && trimmed.len() >= 2 {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    stripped.replace('.', "/")
}

/// 判断给定类名是否属于 Android/Java 系统类或数组类型（供 `FindClass` 严格模式放行）
pub fn is_system_or_array_class(class_name: &str) -> bool {
    let norm = normalize_class_name(class_name);
    norm.starts_with('[')
        || norm.starts_with("java/")
        || norm.starts_with("javax/")
        || norm.starts_with("android/")
        || norm.starts_with("dalvik/")
        || norm.starts_with("sun/")
        || norm.starts_with("org/apache/")
        || norm.starts_with("org/json/")
        || norm.starts_with("org/xml/")
        || norm.starts_with("org/w3c/")
        || norm.starts_with("com/android/")
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(off..off + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_uleb128(data: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        let b = *data.get(*pos)?;
        *pos += 1;
        result |= u32::from(b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

/// 解码 DEX MUTF-8 字符串（兼容 ASCII、多字节 UTF-8 及 `0xC0 0x80` 编码的 NUL）
fn decode_mutf8(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if !bytes.windows(2).any(|w| w == [0xC0, 0x80]) {
            return s.to_string();
        }
    }
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let a = bytes[i];
        if a < 0x80 {
            units.push(u16::from(a));
            i += 1;
        } else if (a & 0xE0) == 0xC0 && i + 1 < bytes.len() {
            let b = bytes[i + 1];
            units.push(((u16::from(a & 0x1F)) << 6) | u16::from(b & 0x3F));
            i += 2;
        } else if (a & 0xF0) == 0xE0 && i + 2 < bytes.len() {
            let b = bytes[i + 1];
            let c = bytes[i + 2];
            units.push(
                ((u16::from(a & 0x0F)) << 12)
                    | ((u16::from(b & 0x3F)) << 6)
                    | u16::from(c & 0x3F),
            );
            i += 3;
        } else {
            units.push(0xFFFD);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

fn read_type_list(data: &[u8], off: usize, types: &[String]) -> Vec<String> {
    if off == 0 {
        return Vec::new();
    }
    let Some(size) = read_u32(data, off) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity((size as usize).min(64));
    for i in 0..(size as usize) {
        if let Some(idx) = read_u16(data, off + 4 + i * 2) {
            if let Some(t) = types.get(idx as usize) {
                out.push(t.clone());
            }
        }
    }
    out
}

fn read_signed_le(data: &[u8], pos: &mut usize, len: usize) -> Option<i64> {
    let slice = data.get(*pos..*pos + len)?;
    *pos += len;
    if slice.is_empty() || len > 8 {
        return None;
    }
    let mut val = 0i64;
    for (i, &b) in slice.iter().enumerate() {
        val |= i64::from(b) << (i * 8);
    }
    let shift = (8 - len) * 8;
    Some((val << shift) >> shift)
}

fn read_unsigned_le(data: &[u8], pos: &mut usize, len: usize) -> Option<u64> {
    let slice = data.get(*pos..*pos + len)?;
    *pos += len;
    if slice.is_empty() || len > 8 {
        return None;
    }
    let mut val = 0u64;
    for (i, &b) in slice.iter().enumerate() {
        val |= u64::from(b) << (i * 8);
    }
    Some(val)
}

fn parse_encoded_value(
    data: &[u8],
    pos: &mut usize,
    strings: &[String],
    types: &[String],
    depth: usize,
) -> Option<DexValue> {
    if depth > 16 {
        return None;
    }
    let header = *data.get(*pos)?;
    *pos += 1;
    let value_type = header & 0x1F;
    let value_arg = (header >> 5) as usize;
    let byte_len = value_arg + 1;

    match value_type {
        0x00 => {
            // VALUE_BYTE
            let v = *data.get(*pos)? as i8;
            *pos += 1;
            Some(DexValue::Byte(v))
        }
        0x02 => {
            // VALUE_SHORT
            let v = read_signed_le(data, pos, byte_len)? as i16;
            Some(DexValue::Short(v))
        }
        0x03 => {
            // VALUE_CHAR
            let v = read_unsigned_le(data, pos, byte_len)? as u16;
            Some(DexValue::Char(v))
        }
        0x04 => {
            // VALUE_INT
            let v = read_signed_le(data, pos, byte_len)? as i32;
            Some(DexValue::Int(v))
        }
        0x06 => {
            // VALUE_LONG
            let v = read_signed_le(data, pos, byte_len)?;
            Some(DexValue::Long(v))
        }
        0x10 => {
            // VALUE_FLOAT (right-zero-extended into high bytes of LE f32)
            let slice = data.get(*pos..*pos + byte_len)?;
            *pos += byte_len;
            if byte_len > 4 {
                return None;
            }
            let mut buf = [0u8; 4];
            buf[4 - byte_len..4].copy_from_slice(slice);
            Some(DexValue::Float(f32::from_le_bytes(buf)))
        }
        0x11 => {
            // VALUE_DOUBLE (right-zero-extended into high bytes of LE f64)
            let slice = data.get(*pos..*pos + byte_len)?;
            *pos += byte_len;
            if byte_len > 8 {
                return None;
            }
            let mut buf = [0u8; 8];
            buf[8 - byte_len..8].copy_from_slice(slice);
            Some(DexValue::Double(f64::from_le_bytes(buf)))
        }
        0x17 => {
            // VALUE_STRING
            let idx = read_unsigned_le(data, pos, byte_len)? as usize;
            let s = strings.get(idx).cloned().unwrap_or_default();
            Some(DexValue::String(s))
        }
        0x18 => {
            // VALUE_TYPE
            let idx = read_unsigned_le(data, pos, byte_len)? as usize;
            let t = types
                .get(idx)
                .map(|s| normalize_class_name(s))
                .unwrap_or_default();
            Some(DexValue::Type(t))
        }
        0x15 | 0x16 | 0x19 | 0x1A | 0x1B => {
            // METHOD_TYPE / METHOD_HANDLE / FIELD / METHOD / ENUM -> 跳过句柄索引
            let _ = read_unsigned_le(data, pos, byte_len)?;
            Some(DexValue::Null)
        }
        0x1C => {
            // VALUE_ARRAY
            let arr = parse_encoded_array(data, pos, strings, types, depth + 1)?;
            Some(DexValue::Array(arr))
        }
        0x1D => {
            // VALUE_ANNOTATION -> 跳过
            let _type_idx = read_uleb128(data, pos)?;
            let count = read_uleb128(data, pos)? as usize;
            for _ in 0..count {
                let _name_idx = read_uleb128(data, pos)?;
                let _ = parse_encoded_value(data, pos, strings, types, depth + 1)?;
            }
            Some(DexValue::Null)
        }
        0x1E => Some(DexValue::Null),
        0x1F => Some(DexValue::Boolean(value_arg != 0)),
        _ => None,
    }
}

fn parse_encoded_array(
    data: &[u8],
    pos: &mut usize,
    strings: &[String],
    types: &[String],
    depth: usize,
) -> Option<Vec<DexValue>> {
    let size = read_uleb128(data, pos)? as usize;
    let mut elems = Vec::with_capacity(size.min(1024));
    for _ in 0..size {
        elems.push(parse_encoded_value(data, pos, strings, types, depth)?);
    }
    Some(elems)
}

fn parse_dex_classes(data: &[u8]) -> EmuResult<Vec<DexClassInfo>> {
    if data.len() < 112 || &data[0..4] != b"dex\n" || data[7] != 0 {
        return Err(EmuError::InvalidElf("无效的 DEX 文件头魔数".to_string()));
    }

    let string_ids_size = read_u32(data, 56).unwrap_or(0) as usize;
    let string_ids_off = read_u32(data, 60).unwrap_or(0) as usize;
    let type_ids_size = read_u32(data, 64).unwrap_or(0) as usize;
    let type_ids_off = read_u32(data, 68).unwrap_or(0) as usize;
    let proto_ids_size = read_u32(data, 72).unwrap_or(0) as usize;
    let proto_ids_off = read_u32(data, 76).unwrap_or(0) as usize;
    let field_ids_size = read_u32(data, 80).unwrap_or(0) as usize;
    let field_ids_off = read_u32(data, 84).unwrap_or(0) as usize;
    let method_ids_size = read_u32(data, 88).unwrap_or(0) as usize;
    let method_ids_off = read_u32(data, 92).unwrap_or(0) as usize;
    let class_defs_size = read_u32(data, 96).unwrap_or(0) as usize;
    let class_defs_off = read_u32(data, 100).unwrap_or(0) as usize;

    // 1. string_ids
    let mut strings = Vec::with_capacity(string_ids_size);
    for i in 0..string_ids_size {
        let Some(str_off) = read_u32(data, string_ids_off + i * 4) else {
            strings.push(String::new());
            continue;
        };
        let mut pos = str_off as usize;
        if read_uleb128(data, &mut pos).is_none() || pos > data.len() {
            strings.push(String::new());
            continue;
        }
        let end = data[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| pos + p)
            .unwrap_or(data.len());
        strings.push(decode_mutf8(&data[pos..end]));
    }

    // 2. type_ids (原始描述符，如 "Lcom/foo/Bar;" / "[C" / "I")
    let mut types = Vec::with_capacity(type_ids_size);
    for i in 0..type_ids_size {
        let s = read_u32(data, type_ids_off + i * 4)
            .and_then(|idx| strings.get(idx as usize))
            .cloned()
            .unwrap_or_default();
        types.push(s);
    }

    // 3. proto_ids -> JNI 方法签名 "(args)ret"
    let mut protos = Vec::with_capacity(proto_ids_size);
    for i in 0..proto_ids_size {
        let base = proto_ids_off + i * 12;
        let ret_idx = read_u32(data, base + 4).unwrap_or(0) as usize;
        let params_off = read_u32(data, base + 8).unwrap_or(0) as usize;
        let params = read_type_list(data, params_off, &types);
        let ret = types.get(ret_idx).map(String::as_str).unwrap_or("V");
        let mut sig = String::with_capacity(params.len() * 8 + ret.len() + 2);
        sig.push('(');
        for p in params {
            sig.push_str(&p);
        }
        sig.push(')');
        sig.push_str(ret);
        protos.push(sig);
    }

    // 4. field_ids -> (type_sig, name)
    let mut field_ids: Vec<(String, String)> = Vec::with_capacity(field_ids_size);
    for i in 0..field_ids_size {
        let base = field_ids_off + i * 8;
        let type_idx = read_u16(data, base + 2).unwrap_or(0) as usize;
        let name_idx = read_u32(data, base + 4).unwrap_or(0) as usize;
        let sig = types.get(type_idx).cloned().unwrap_or_default();
        let name = strings.get(name_idx).cloned().unwrap_or_default();
        field_ids.push((sig, name));
    }

    // 5. method_ids -> (proto_sig, name)
    let mut method_ids: Vec<(String, String)> = Vec::with_capacity(method_ids_size);
    for i in 0..method_ids_size {
        let base = method_ids_off + i * 8;
        let proto_idx = read_u16(data, base + 2).unwrap_or(0) as usize;
        let name_idx = read_u32(data, base + 4).unwrap_or(0) as usize;
        let sig = protos.get(proto_idx).cloned().unwrap_or_default();
        let name = strings.get(name_idx).cloned().unwrap_or_default();
        method_ids.push((sig, name));
    }

    // 6. class_defs
    let mut classes = Vec::with_capacity(class_defs_size);
    for i in 0..class_defs_size {
        let base = class_defs_off + i * 32;
        let Some(class_idx) = read_u32(data, base) else {
            break;
        };
        let access_flags = read_u32(data, base + 4).unwrap_or(0);
        let superclass_idx = read_u32(data, base + 8).unwrap_or(NO_INDEX);
        let interfaces_off = read_u32(data, base + 12).unwrap_or(0) as usize;
        let class_data_off = read_u32(data, base + 24).unwrap_or(0) as usize;
        let static_values_off = read_u32(data, base + 28).unwrap_or(0) as usize;

        let Some(raw_cls) = types.get(class_idx as usize) else {
            continue;
        };
        let cls_name = normalize_class_name(raw_cls);
        let super_class = if superclass_idx == NO_INDEX {
            None
        } else {
            types
                .get(superclass_idx as usize)
                .map(|s| normalize_class_name(s))
        };
        let interfaces = read_type_list(data, interfaces_off, &types)
            .into_iter()
            .map(|s| normalize_class_name(&s))
            .collect();

        let mut fields = Vec::new();
        let mut methods = Vec::new();
        let mut static_field_names = Vec::new();

        if class_data_off != 0 && class_data_off < data.len() {
            let mut pos = class_data_off;
            if let (Some(sf_cnt), Some(if_cnt), Some(dm_cnt), Some(vm_cnt)) = (
                read_uleb128(data, &mut pos),
                read_uleb128(data, &mut pos),
                read_uleb128(data, &mut pos),
                read_uleb128(data, &mut pos),
            ) {
                let mut f_idx = 0u32;
                for _ in 0..sf_cnt {
                    let (Some(diff), Some(flags)) =
                        (read_uleb128(data, &mut pos), read_uleb128(data, &mut pos))
                    else {
                        break;
                    };
                    f_idx = f_idx.wrapping_add(diff);
                    if let Some((sig, name)) = field_ids.get(f_idx as usize) {
                        static_field_names.push(name.clone());
                        fields.push(DexFieldInfo {
                            name: name.clone(),
                            sig: sig.clone(),
                            access_flags: flags,
                            is_static: true,
                        });
                    }
                }
                let mut if_idx = 0u32;
                for _ in 0..if_cnt {
                    let (Some(diff), Some(flags)) =
                        (read_uleb128(data, &mut pos), read_uleb128(data, &mut pos))
                    else {
                        break;
                    };
                    if_idx = if_idx.wrapping_add(diff);
                    if let Some((sig, name)) = field_ids.get(if_idx as usize) {
                        fields.push(DexFieldInfo {
                            name: name.clone(),
                            sig: sig.clone(),
                            access_flags: flags,
                            is_static: false,
                        });
                    }
                }
                let mut dm_idx = 0u32;
                for _ in 0..dm_cnt {
                    let (Some(diff), Some(flags), Some(_code_off)) = (
                        read_uleb128(data, &mut pos),
                        read_uleb128(data, &mut pos),
                        read_uleb128(data, &mut pos),
                    ) else {
                        break;
                    };
                    dm_idx = dm_idx.wrapping_add(diff);
                    if let Some((sig, name)) = method_ids.get(dm_idx as usize) {
                        methods.push(DexMethodInfo {
                            name: name.clone(),
                            sig: sig.clone(),
                            access_flags: flags,
                            is_direct: true,
                        });
                    }
                }
                let mut vm_idx = 0u32;
                for _ in 0..vm_cnt {
                    let (Some(diff), Some(flags), Some(_code_off)) = (
                        read_uleb128(data, &mut pos),
                        read_uleb128(data, &mut pos),
                        read_uleb128(data, &mut pos),
                    ) else {
                        break;
                    };
                    vm_idx = vm_idx.wrapping_add(diff);
                    if let Some((sig, name)) = method_ids.get(vm_idx as usize) {
                        methods.push(DexMethodInfo {
                            name: name.clone(),
                            sig: sig.clone(),
                            access_flags: flags,
                            is_direct: false,
                        });
                    }
                }
            }
        }

        let mut static_values = HashMap::new();
        if static_values_off != 0 && static_values_off < data.len() {
            let mut pos = static_values_off;
            if let Some(vals) = parse_encoded_array(data, &mut pos, &strings, &types, 0) {
                for (fname, val) in static_field_names.into_iter().zip(vals) {
                    static_values.insert(fname, val);
                }
            }
        }

        classes.push(DexClassInfo {
            name: cls_name,
            super_class,
            interfaces,
            access_flags,
            fields,
            methods,
            static_values,
        });
    }

    Ok(classes)
}
