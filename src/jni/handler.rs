use std::collections::HashMap;

use crate::jni::types::{FieldDesc, JObject, JObjectRef, JValue, MethodDesc, ObjectTable};

/// 传递给 `JniHandler` 的上下文，提供对象表与基础环境信息
pub struct JniContext<'a> {
    pub objects: &'a mut ObjectTable,
    pub package_name: &'a str,
}

/// 纯 Rust JNI 业务回调接口（对标 unidbg 的 `AbstractJni`）
///
/// 使用方只需实现关心的业务类方法（如签名校验、设备指纹、加密密钥获取），
/// 未覆盖的通用 Android/JDK 方法将自动回落到内置默认实现。
pub trait JniHandler {
    fn find_class(&mut self, ctx: &mut JniContext<'_>, name: &str) -> JObjectRef {
        ctx.objects.find_or_create_class(name)
    }

    fn call_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        default_call_object_method(ctx, obj, method, args)
    }

    fn call_static_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        if let Some(r) = default_call_static_object_method(ctx, class_name, method, args) {
            return r;
        }
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 CallStaticObjectMethod: {}.{}{}",
            class_name, method.name, method.sig
        );
        JObjectRef::NULL
    }

    fn call_int_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i32 {
        default_call_int_method(ctx, obj, method, args)
    }

    fn call_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        default_call_long_method(ctx, obj, method, args)
    }

    fn call_boolean_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> bool {
        default_call_boolean_method(ctx, obj, method, args)
    }

    fn call_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        default_call_void_method(ctx, obj, method, args);
    }

    fn get_object_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> JObjectRef {
        default_get_object_field(ctx, obj, field)
    }

    fn get_static_object_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> JObjectRef {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 GetStaticObjectField: {}.{} ({})",
            class_name, field.name, field.sig
        );
        JObjectRef::NULL
    }

    fn new_object(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        default_new_object(ctx, class_name, method, args)
    }

    fn call_static_boolean_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> bool {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 CallStaticBooleanMethod: {}.{}{}",
            class_name, method.name, method.sig
        );
        false
    }

    fn call_static_int_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> i32 {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 CallStaticIntMethod: {}.{}{}",
            class_name, method.name, method.sig
        );
        0
    }

    fn call_static_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        default_call_static_long_method(ctx, class_name, method, args)
    }

    fn call_static_void_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 CallStaticVoidMethod: {}.{}{}",
            class_name, method.name, method.sig
        );
    }

    fn get_boolean_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> bool {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Boolean(b)) => *b,
                _ => false,
            },
            _ => false,
        }
    }

    fn get_int_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i32 {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Int(v)) => *v,
                _ => 0,
            },
            Some(JObject::PackageInfo { version_code, .. }) if field.name == "versionCode" => {
                *version_code
            }
            _ => 0,
        }
    }

    fn get_long_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i64 {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Long(v)) => *v,
                _ => 0,
            },
            _ => 0,
        }
    }

    fn get_static_boolean_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> bool {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 GetStaticBooleanField: {}.{}",
            class_name, field.name
        );
        false
    }

    fn get_static_int_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i32 {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 GetStaticIntField: {}.{}",
            class_name, field.name
        );
        0
    }

    fn get_static_long_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i64 {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 GetStaticLongField: {}.{}",
            class_name, field.name
        );
        0
    }

    fn call_byte_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> i8 {
        if method.name == "byteValue" {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(obj) {
                if let Some(JValue::Byte(v)) = fields.get("value") {
                    return *v;
                }
            }
        }
        0
    }

    fn call_char_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> u16 {
        default_call_char_method(ctx, obj, method, args)
    }

    fn call_short_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> i16 {
        if method.name == "shortValue" {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(obj) {
                if let Some(JValue::Short(v)) = fields.get("value") {
                    return *v;
                }
            }
        }
        0
    }

    fn call_float_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> f32 {
        if method.name == "floatValue" {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(obj) {
                if let Some(JValue::Float(v)) = fields.get("value") {
                    return *v;
                }
            }
        }
        0.0
    }

    fn call_double_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> f64 {
        if method.name == "doubleValue" {
            if let Some(JObject::Custom { fields, .. }) = ctx.objects.get(obj) {
                if let Some(JValue::Double(v)) = fields.get("value") {
                    return *v;
                }
            }
        }
        0.0
    }

    fn call_static_byte_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> i8 {
        0
    }

    fn call_static_char_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> u16 {
        0
    }

    fn call_static_short_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> i16 {
        0
    }

    fn call_static_float_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> f32 {
        0.0
    }

    fn call_static_double_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> f64 {
        0.0
    }

    fn get_byte_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i8 {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Byte(v)) => *v,
                _ => 0,
            },
            _ => 0,
        }
    }

    fn get_char_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> u16 {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Char(v)) => *v,
                _ => 0,
            },
            _ => 0,
        }
    }

    fn get_short_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i16 {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Short(v)) => *v,
                _ => 0,
            },
            _ => 0,
        }
    }

    fn get_float_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f32 {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Float(v)) => *v,
                _ => 0.0,
            },
            _ => 0.0,
        }
    }

    fn get_double_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f64 {
        match ctx.objects.get(obj) {
            Some(JObject::Custom { fields, .. }) => match fields.get(&field.name) {
                Some(JValue::Double(v)) => *v,
                _ => 0.0,
            },
            _ => 0.0,
        }
    }

    fn set_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
        value: JValue,
    ) {
        if let Some(JObject::Custom { fields, .. }) = ctx.objects.get_mut(obj) {
            fields.insert(field.name.clone(), value);
        }
    }

    fn get_static_byte_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _field: &FieldDesc,
    ) -> i8 {
        0
    }

    fn get_static_char_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _field: &FieldDesc,
    ) -> u16 {
        0
    }

    fn get_static_short_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _field: &FieldDesc,
    ) -> i16 {
        0
    }

    fn get_static_float_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _field: &FieldDesc,
    ) -> f32 {
        0.0
    }

    fn get_static_double_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _field: &FieldDesc,
    ) -> f64 {
        0.0
    }

    fn set_static_field(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _class_name: &str,
        _field: &FieldDesc,
        _value: JValue,
    ) {
    }
}

/// 开箱即用的默认 `JniHandler`（仅包含内置 Android/JDK 通用模型）
#[derive(Debug, Default)]
pub struct DefaultJniHandler;

impl JniHandler for DefaultJniHandler {}

/// 内部工具：将任意 `JValue` 格式化为 Java `String.valueOf` / `StringBuilder.append` 字符串
fn jvalue_to_java_string(ctx: &JniContext<'_>, val: &JValue) -> String {
    match *val {
        JValue::Void => String::new(),
        JValue::Boolean(b) => b.to_string(),
        JValue::Byte(v) => v.to_string(),
        JValue::Char(c) => char::from_u32(u32::from(c)).unwrap_or('\u{FFFD}').to_string(),
        JValue::Short(v) => v.to_string(),
        JValue::Int(v) => v.to_string(),
        JValue::Long(v) => v.to_string(),
        JValue::Float(v) => v.to_string(),
        JValue::Double(v) => v.to_string(),
        JValue::Object(r) => {
            if r.is_null() {
                return "null".to_string();
            }
            match ctx.objects.get(r) {
                Some(JObject::String(s)) | Some(JObject::StringBuilder(s)) => s.clone(),
                Some(JObject::CharArray(c)) => String::from_utf16_lossy(c),
                Some(JObject::Custom { fields, .. }) => match fields.get("value") {
                    Some(v) => jvalue_to_java_string(ctx, v),
                    None => format!("{}@{:x}", ctx.objects.get(r).map(|o| o.class_name()).unwrap_or("Object"), r.0),
                },
                Some(o) => format!("{}@{:x}", o.class_name(), r.0),
                None => "null".to_string(),
            }
        }
    }
}

/// 内部工具：比较两个 `JObjectRef` 是否逻辑相等（`String` 按内容比较，其余按句柄比较）
fn jobject_keys_equal(objects: &crate::jni::ObjectTable, a: JObjectRef, b: JObjectRef) -> bool {
    if a == b {
        return true;
    }
    match (objects.get_string(a), objects.get_string(b)) {
        (Some(sa), Some(sb)) => sa == sb,
        _ => false,
    }
}

/// 内部工具：推进 `java/util/Random` 的 48-bit LCG 种子
fn random_next_bits(ctx: &mut JniContext<'_>, obj: JObjectRef, bits: u32) -> u32 {
    if let Some(JObject::Custom { fields, .. }) = ctx.objects.get_mut(obj) {
        let seed = match fields.get("seed") {
            Some(JValue::Long(s)) => *s as u64,
            _ => 0x5DEE_CE66D_u64,
        };
        let next = (seed.wrapping_mul(0x5DEE_CE66D).wrapping_add(0xB)) & ((1u64 << 48) - 1);
        fields.insert("seed".to_string(), JValue::Long(next as i64));
        (next >> (48 - bits)) as u32
    } else {
        0
    }
}

/// 纯 Rust Base64 编码（支持 `android.util.Base64` 标志位：`NO_PADDING=1`, `NO_WRAP=2`, `URL_SAFE=8`）
fn android_base64_encode(input: &[u8], flags: i32) -> String {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alphabet = if (flags & 8) != 0 { URL } else { STD };
    let no_padding = (flags & 1) != 0;
    let no_wrap = (flags & 2) != 0;

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4 + 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[((triple >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < input.len() {
            out.push(alphabet[((triple >> 6) & 0x3F) as usize] as char);
        } else if !no_padding {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(alphabet[(triple & 0x3F) as usize] as char);
        } else if !no_padding {
            out.push('=');
        }
        i += 3;
    }
    if !no_wrap && !out.is_empty() {
        out.push('\n');
    }
    out
}

/// 纯 Rust Base64 解码（同时兼容标准与 URL_SAFE 字符表）
fn android_base64_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in input {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// 内置高频 `CallObjectMethod` 默认分发
pub fn default_call_object_method(
    ctx: &mut JniContext<'_>,
    obj: JObjectRef,
    method: &MethodDesc,
    args: &[JValue],
) -> JObjectRef {
    let target = ctx.objects.get(obj).cloned();
    match (target, method.name.as_str()) {
        (Some(JObject::String(s)), "getBytes") => ctx.objects.add_byte_array(s.into_bytes()),
        (Some(JObject::String(s)), "toCharArray") => {
            ctx.objects.add_char_array(s.encode_utf16().collect::<Vec<u16>>())
        }
        (Some(JObject::String(s)), "substring") => {
            let units: Vec<u16> = s.encode_utf16().collect();
            let start = args.first().and_then(|v| v.as_int()).unwrap_or(0).max(0) as usize;
            let end = args
                .get(1)
                .and_then(|v| v.as_int())
                .map(|e| e.max(0) as usize)
                .unwrap_or(units.len())
                .min(units.len());
            let sub = if start <= end {
                String::from_utf16_lossy(&units[start..end])
            } else {
                String::new()
            };
            ctx.objects.add_string(sub)
        }
        (Some(JObject::String(s)), "trim") => ctx.objects.add_string(s.trim().to_string()),
        (Some(JObject::String(s)), "toLowerCase") => ctx.objects.add_string(s.to_lowercase()),
        (Some(JObject::String(s)), "toUpperCase") => ctx.objects.add_string(s.to_uppercase()),
        (Some(JObject::String(mut s)), "concat") => {
            if let Some(other) = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
            {
                s.push_str(other);
            }
            ctx.objects.add_string(s)
        }
        (Some(JObject::String(_)), "toString") => obj,
        (Some(JObject::StringBuilder(_)), "append") => {
            let text = args
                .first()
                .map(|v| jvalue_to_java_string(ctx, v))
                .unwrap_or_default();
            if let Some(JObject::StringBuilder(buf)) = ctx.objects.get_mut(obj) {
                buf.push_str(&text);
            }
            obj
        }
        (Some(JObject::StringBuilder(s)), "toString") => ctx.objects.add_string(s),
        (Some(JObject::List { items, .. }), "get") => {
            let idx = args.first().and_then(|v| v.as_int()).unwrap_or(-1);
            if idx >= 0 {
                items.get(idx as usize).copied().unwrap_or(JObjectRef::NULL)
            } else {
                JObjectRef::NULL
            }
        }
        (Some(JObject::List { .. }), "set") => {
            let idx = args.first().and_then(|v| v.as_int()).unwrap_or(-1);
            let elem = args
                .get(1)
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            if idx >= 0 {
                if let Some(JObject::List { items, .. }) = ctx.objects.get_mut(obj) {
                    if let Some(slot) = items.get_mut(idx as usize) {
                        let prev = *slot;
                        *slot = elem;
                        return prev;
                    }
                }
            }
            JObjectRef::NULL
        }
        (Some(JObject::List { .. }), "remove") => {
            let idx = args.first().and_then(|v| v.as_int()).unwrap_or(-1);
            if idx >= 0 {
                if let Some(JObject::List { items, .. }) = ctx.objects.get_mut(obj) {
                    if (idx as usize) < items.len() {
                        return items.remove(idx as usize);
                    }
                }
            }
            JObjectRef::NULL
        }
        (Some(JObject::List { items, .. }), "toArray") => {
            ctx.objects.add_local(JObject::ObjectArray(items))
        }
        (Some(JObject::List { items, .. }), "iterator") => {
            ctx.objects.add_local(JObject::Iterator { items, pos: 0 })
        }
        (Some(JObject::Map { entries, .. }), "get") => {
            let key = args
                .first()
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            entries
                .iter()
                .find(|(k, _)| jobject_keys_equal(ctx.objects, *k, key))
                .map(|(_, v)| *v)
                .unwrap_or(JObjectRef::NULL)
        }
        (Some(JObject::Map { entries, .. }), "put") => {
            let key = args
                .first()
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            let val = args
                .get(1)
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            let existing_idx = entries
                .iter()
                .position(|(k, _)| jobject_keys_equal(ctx.objects, *k, key));
            if let Some(JObject::Map { entries: map_e, .. }) = ctx.objects.get_mut(obj) {
                if let Some(idx) = existing_idx {
                    let prev = map_e[idx].1;
                    map_e[idx].1 = val;
                    return prev;
                }
                map_e.push((key, val));
            }
            JObjectRef::NULL
        }
        (Some(JObject::Map { entries, .. }), "remove") => {
            let key = args
                .first()
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            let existing_idx = entries
                .iter()
                .position(|(k, _)| jobject_keys_equal(ctx.objects, *k, key));
            if let Some(idx) = existing_idx {
                if let Some(JObject::Map { entries: map_e, .. }) = ctx.objects.get_mut(obj) {
                    return map_e.remove(idx).1;
                }
            }
            JObjectRef::NULL
        }
        (Some(JObject::Map { entries, .. }), "keySet") => {
            let keys: Vec<JObjectRef> = entries.into_iter().map(|(k, _)| k).collect();
            ctx.objects.add_local(JObject::List {
                class_name: "java/util/HashSet".to_string(),
                items: keys,
            })
        }
        (Some(JObject::Map { entries, .. }), "values") => {
            let vals: Vec<JObjectRef> = entries.into_iter().map(|(_, v)| v).collect();
            ctx.objects.add_local(JObject::List {
                class_name: "java/util/ArrayList".to_string(),
                items: vals,
            })
        }
        (Some(JObject::Iterator { .. }), "next") => {
            if let Some(JObject::Iterator { items, pos }) = ctx.objects.get_mut(obj) {
                if *pos < items.len() {
                    let item = items[*pos];
                    *pos += 1;
                    return item;
                }
            }
            JObjectRef::NULL
        }
        (Some(JObject::Context { package_name }), "getPackageName") => {
            ctx.objects.add_string(package_name)
        }
        (Some(JObject::Context { .. }), "getPackageManager") => {
            ctx.objects.add_local(JObject::PackageManager)
        }
        (Some(JObject::PackageManager), "getPackageInfo") => {
            let pkg = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or(ctx.package_name)
                .to_string();
            ctx.objects.add_local(JObject::PackageInfo {
                package_name: pkg,
                version_name: "1.0.0".to_string(),
                version_code: 1,
            })
        }
        (Some(JObject::Signature(cert)), "toByteArray") => ctx.objects.add_byte_array(cert),
        (_, "loadClass") => {
            let cls_name = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("")
                .replace('.', "/");
            if cls_name.is_empty() {
                JObjectRef::NULL
            } else {
                ctx.objects.find_or_create_class(&cls_name)
            }
        }
        (Some(JObject::Custom { class_name, .. }), "getName")
            if class_name == "java/lang/Thread" =>
        {
            ctx.objects.add_string("main")
        }
        (Some(JObject::Custom { class_name, .. }), "getThreadGroup")
            if class_name == "java/lang/Thread" =>
        {
            ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/ThreadGroup".to_string(),
                fields: Default::default(),
            })
        }
        (Some(JObject::Custom { class_name, .. }), "getStackTrace")
            if class_name == "java/lang/Thread" =>
        {
            ctx.objects.add_local(JObject::ObjectArray(Vec::new()))
        }
        _ => {
            tracing::warn!(target: "runidbg::jni", 
                "[JNI] 未处理的 CallObjectMethod: {}.{}{}",
                method.class_name, method.name, method.sig
            );
            JObjectRef::NULL
        }
    }
}

/// 内置高频 `CallIntMethod` 默认分发
pub fn default_call_int_method(
    ctx: &mut JniContext<'_>,
    obj: JObjectRef,
    method: &MethodDesc,
    args: &[JValue],
) -> i32 {
    let target = ctx.objects.get(obj).cloned();
    match (target, method.name.as_str()) {
        (Some(JObject::String(s)), "length") => s.encode_utf16().count() as i32,
        (Some(JObject::String(s)), "hashCode") => {
            let mut h: i32 = 0;
            for u in s.encode_utf16() {
                h = h.wrapping_mul(31).wrapping_add(i32::from(u));
            }
            h
        }
        (Some(JObject::String(s)), "indexOf") => {
            if let Some(sub) = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
            {
                s.find(sub)
                    .map(|byte_idx| s[..byte_idx].encode_utf16().count() as i32)
                    .unwrap_or(-1)
            } else if let Some(ch) = args.first().and_then(|v| v.as_int()) {
                s.encode_utf16()
                    .position(|u| i32::from(u) == ch)
                    .map(|i| i as i32)
                    .unwrap_or(-1)
            } else {
                -1
            }
        }
        (Some(JObject::String(s)), "compareTo") => {
            if let Some(other) = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
            {
                match s.as_str().cmp(other) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                }
            } else {
                0
            }
        }
        (Some(JObject::StringBuilder(s)), "length") => s.encode_utf16().count() as i32,
        (Some(JObject::List { items, .. }), "size") => items.len() as i32,
        (Some(JObject::Map { entries, .. }), "size") => entries.len() as i32,
        (Some(JObject::Custom { class_name, .. }), "nextInt")
            if class_name == "java/util/Random" =>
        {
            let bits = random_next_bits(ctx, obj, 31) as i32;
            if let Some(bound) = args.first().and_then(|v| v.as_int()) {
                if bound > 0 {
                    bits.abs() % bound
                } else {
                    0
                }
            } else {
                bits
            }
        }
        (Some(JObject::Custom { fields, .. }), "intValue") => match fields.get("value") {
            Some(JValue::Int(v)) => *v,
            _ => 0,
        },
        _ => {
            tracing::warn!(target: "runidbg::jni", 
                "[JNI] 未处理的 CallIntMethod: {}.{}{}",
                method.class_name, method.name, method.sig
            );
            0
        }
    }
}

/// 内置高频 `CallCharMethod` 默认分发
pub fn default_call_char_method(
    ctx: &mut JniContext<'_>,
    obj: JObjectRef,
    method: &MethodDesc,
    args: &[JValue],
) -> u16 {
    match (ctx.objects.get(obj), method.name.as_str()) {
        (Some(JObject::String(s)) | Some(JObject::StringBuilder(s)), "charAt") => {
            let idx = args.first().and_then(|v| v.as_int()).unwrap_or(-1);
            if idx >= 0 {
                s.encode_utf16().nth(idx as usize).unwrap_or(0)
            } else {
                0
            }
        }
        (Some(JObject::Custom { fields, .. }), "charValue") => match fields.get("value") {
            Some(JValue::Char(v)) => *v,
            _ => 0,
        },
        _ => 0,
    }
}

/// 内置高频 `CallLongMethod` 默认分发
pub fn default_call_long_method(
    ctx: &mut JniContext<'_>,
    obj: JObjectRef,
    method: &MethodDesc,
    _args: &[JValue],
) -> i64 {
    let target = ctx.objects.get(obj).cloned();
    match (target, method.name.as_str()) {
        (Some(JObject::Custom { class_name, fields }), "getTime")
            if class_name == "java/util/Date" =>
        {
            match fields.get("time") {
                Some(JValue::Long(ms)) => *ms,
                _ => 1_700_000_000_000,
            }
        }
        (Some(JObject::Custom { class_name, .. }), "nextLong")
            if class_name == "java/util/Random" =>
        {
            let hi = i64::from(random_next_bits(ctx, obj, 32) as i32);
            let lo = i64::from(random_next_bits(ctx, obj, 32) as i32);
            (hi << 32).wrapping_add(lo)
        }
        (Some(JObject::Custom { fields, .. }), "longValue") => match fields.get("value") {
            Some(JValue::Long(v)) => *v,
            _ => 0,
        },
        _ => {
            tracing::warn!(target: "runidbg::jni", 
                "[JNI] 未处理的 CallLongMethod: {}.{}{}",
                method.class_name, method.name, method.sig
            );
            0
        }
    }
}

/// 内置高频 `CallStaticLongMethod` 默认分发
pub fn default_call_static_long_method(
    _ctx: &mut JniContext<'_>,
    class_name: &str,
    method: &MethodDesc,
    _args: &[JValue],
) -> i64 {
    match (class_name, method.name.as_str()) {
        ("java/lang/System", "currentTimeMillis") => 1_700_000_000_000,
        ("java/lang/System", "nanoTime") => 1_700_000_000_000_000_000,
        _ => {
            tracing::warn!(target: "runidbg::jni", 
                "[JNI] 未处理的 CallStaticLongMethod: {}.{}{}",
                class_name, method.name, method.sig
            );
            0
        }
    }
}

/// 内置高频 `CallVoidMethod` 默认分发
pub fn default_call_void_method(
    ctx: &mut JniContext<'_>,
    obj: JObjectRef,
    method: &MethodDesc,
    args: &[JValue],
) {
    let target = ctx.objects.get(obj).cloned();
    match (target, method.name.as_str()) {
        (Some(JObject::StringBuilder(_)), "setLength") => {
            let new_len = args.first().and_then(|v| v.as_int()).unwrap_or(0).max(0) as usize;
            if let Some(JObject::StringBuilder(s)) = ctx.objects.get_mut(obj) {
                let units: Vec<u16> = s.encode_utf16().take(new_len).collect();
                *s = String::from_utf16_lossy(&units);
            }
        }
        (Some(JObject::List { .. }), "clear") => {
            if let Some(JObject::List { items, .. }) = ctx.objects.get_mut(obj) {
                items.clear();
            }
        }
        (Some(JObject::List { .. }), "add") if args.len() >= 2 => {
            let idx = args[0].as_int().unwrap_or(0).max(0) as usize;
            let elem = args[1].as_object().unwrap_or(JObjectRef::NULL);
            if let Some(JObject::List { items, .. }) = ctx.objects.get_mut(obj) {
                let pos = idx.min(items.len());
                items.insert(pos, elem);
            }
        }
        (Some(JObject::Map { .. }), "clear") => {
            if let Some(JObject::Map { entries, .. }) = ctx.objects.get_mut(obj) {
                entries.clear();
            }
        }
        (Some(JObject::Custom { class_name, .. }), "setSeed")
            if class_name == "java/util/Random" =>
        {
            if let Some(seed) = args.first().and_then(|v| v.as_long()) {
                let scrambled = ((seed as u64) ^ 0x5DEE_CE66D) & ((1u64 << 48) - 1);
                if let Some(JObject::Custom { fields, .. }) = ctx.objects.get_mut(obj) {
                    fields.insert("seed".to_string(), JValue::Long(scrambled as i64));
                }
            }
        }
        (Some(JObject::Custom { class_name, .. }), "nextBytes")
            if class_name == "java/util/Random" =>
        {
            if let Some(arr_ref) = args.first().and_then(|v| v.as_object()) {
                let len = ctx
                    .objects
                    .get_bytes(arr_ref)
                    .map(|b| b.len())
                    .unwrap_or(0);
                let mut filled = Vec::with_capacity(len);
                for _ in 0..len {
                    filled.push((random_next_bits(ctx, obj, 8) & 0xFF) as u8);
                }
                if let Some(JObject::ByteArray(b)) = ctx.objects.get_mut(arr_ref) {
                    *b = filled;
                }
            }
        }
        _ => {
            tracing::warn!(target: "runidbg::jni", 
                "[JNI] 未处理的 CallVoidMethod: {}.{}{}",
                method.class_name, method.name, method.sig
            );
        }
    }
}

/// 内置高频 `CallBooleanMethod` 默认分发
pub fn default_call_boolean_method(
    ctx: &mut JniContext<'_>,
    obj: JObjectRef,
    method: &MethodDesc,
    args: &[JValue],
) -> bool {
    let target = ctx.objects.get(obj).cloned();
    match (target, method.name.as_str()) {
        (Some(JObject::String(lhs)), "equals") => {
            let rhs = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r));
            rhs == Some(lhs.as_str())
        }
        (Some(JObject::String(s)), "isEmpty") => s.is_empty(),
        (Some(JObject::String(s)), "startsWith") => args
            .first()
            .and_then(|v| v.as_object())
            .and_then(|r| ctx.objects.get_string(r))
            .is_some_and(|p| s.starts_with(p)),
        (Some(JObject::String(s)), "endsWith") => args
            .first()
            .and_then(|v| v.as_object())
            .and_then(|r| ctx.objects.get_string(r))
            .is_some_and(|p| s.ends_with(p)),
        (Some(JObject::String(s)), "contains") => args
            .first()
            .and_then(|v| v.as_object())
            .and_then(|r| ctx.objects.get_string(r))
            .is_some_and(|p| s.contains(p)),
        (Some(JObject::List { class_name, items }), "add") => {
            let elem = args
                .first()
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            let is_set = class_name.ends_with("Set");
            if is_set && items.iter().any(|&it| jobject_keys_equal(ctx.objects, it, elem)) {
                return false;
            }
            if let Some(JObject::List { items: vec, .. }) = ctx.objects.get_mut(obj) {
                vec.push(elem);
            }
            true
        }
        (Some(JObject::List { items, .. }), "isEmpty") => items.is_empty(),
        (Some(JObject::List { items, .. }), "contains") => {
            let elem = args
                .first()
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            items.iter().any(|&it| jobject_keys_equal(ctx.objects, it, elem))
        }
        (Some(JObject::List { items, .. }), "remove") => {
            let elem = args
                .first()
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            if let Some(idx) = items
                .iter()
                .position(|&it| jobject_keys_equal(ctx.objects, it, elem))
            {
                if let Some(JObject::List { items: vec, .. }) = ctx.objects.get_mut(obj) {
                    vec.remove(idx);
                }
                true
            } else {
                false
            }
        }
        (Some(JObject::Map { entries, .. }), "isEmpty") => entries.is_empty(),
        (Some(JObject::Map { entries, .. }), "containsKey") => {
            let key = args
                .first()
                .and_then(|v| v.as_object())
                .unwrap_or(JObjectRef::NULL);
            entries
                .iter()
                .any(|(k, _)| jobject_keys_equal(ctx.objects, *k, key))
        }
        (Some(JObject::Iterator { items, pos }), "hasNext") => pos < items.len(),
        (Some(JObject::Custom { fields, .. }), "booleanValue") => match fields.get("value") {
            Some(JValue::Boolean(v)) => *v,
            _ => false,
        },
        _ => {
            tracing::warn!(target: "runidbg::jni", 
                "[JNI] 未处理的 CallBooleanMethod: {}.{}{}",
                method.class_name, method.name, method.sig
            );
            false
        }
    }
}

/// 内置高频 `GetObjectField` 默认分发
pub fn default_get_object_field(
    ctx: &mut JniContext<'_>,
    obj: JObjectRef,
    field: &FieldDesc,
) -> JObjectRef {
    match ctx.objects.get(obj) {
        Some(JObject::Custom { fields, .. }) => fields
            .get(&field.name)
            .and_then(|v| v.as_object())
            .unwrap_or(JObjectRef::NULL),
        Some(JObject::PackageInfo {
            package_name,
            version_name,
            ..
        }) => {
            let pkg = package_name.clone();
            let ver = version_name.clone();
            match field.name.as_str() {
                "packageName" => ctx.objects.add_string(pkg),
                "versionName" => ctx.objects.add_string(ver),
                _ => JObjectRef::NULL,
            }
        }
        _ => JObjectRef::NULL,
    }
}

/// 内置高频 `CallStaticObjectMethod` 默认分发
pub fn default_call_static_object_method(
    ctx: &mut JniContext<'_>,
    class_name: &str,
    method: &MethodDesc,
    args: &[JValue],
) -> Option<JObjectRef> {
    match (class_name, method.name.as_str()) {
        ("java/lang/Thread", "currentThread") => Some(ctx.objects.add_local(JObject::Custom {
            class_name: "java/lang/Thread".to_string(),
            fields: Default::default(),
        })),
        ("java/lang/String", "valueOf") => {
            let text = args
                .first()
                .map(|v| jvalue_to_java_string(ctx, v))
                .unwrap_or_else(|| "null".to_string());
            Some(ctx.objects.add_string(text))
        }
        ("java/lang/System", "getProperty") => {
            let key = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("");
            let def = args
                .get(1)
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .map(str::to_string);
            let val = match key {
                "os.name" => Some("Linux".to_string()),
                "os.arch" => Some("aarch64".to_string()),
                "os.version" => Some("5.15.104-android14".to_string()),
                "java.vm.version" => Some("2.1.0".to_string()),
                "java.vm.name" => Some("Dalvik".to_string()),
                "file.separator" => Some("/".to_string()),
                "line.separator" => Some("\n".to_string()),
                "http.agent" => Some("Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/AP2A.240805.005)".to_string()),
                _ => def,
            };
            Some(match val {
                Some(s) => ctx.objects.add_string(s),
                None => JObjectRef::NULL,
            })
        }
        ("android/provider/Settings$Secure", "getString") => {
            let key = args
                .get(1)
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("");
            match key {
                "android_id" => Some(ctx.objects.add_string("9774d56d682e549c")),
                _ => Some(JObjectRef::NULL),
            }
        }
        ("android/util/Base64", "encodeToString") => {
            let bytes = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_bytes(r))
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let flags = args.get(1).and_then(|v| v.as_int()).unwrap_or(0);
            Some(ctx.objects.add_string(android_base64_encode(&bytes, flags)))
        }
        ("android/util/Base64", "encode") => {
            let bytes = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_bytes(r))
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let flags = args.get(1).and_then(|v| v.as_int()).unwrap_or(0);
            Some(
                ctx.objects
                    .add_byte_array(android_base64_encode(&bytes, flags).into_bytes()),
            )
        }
        ("android/util/Base64", "decode") => {
            let raw = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| match ctx.objects.get(r) {
                    Some(JObject::String(s)) => Some(s.as_bytes().to_vec()),
                    Some(JObject::ByteArray(b)) => Some(b.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            Some(ctx.objects.add_byte_array(android_base64_decode(&raw)))
        }
        ("java/lang/Boolean", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Boolean(false));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Boolean".to_string(),
                fields,
            }))
        }
        ("java/lang/Byte", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Byte(0));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Byte".to_string(),
                fields,
            }))
        }
        ("java/lang/Character", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Char(0));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Character".to_string(),
                fields,
            }))
        }
        ("java/lang/Short", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Short(0));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Short".to_string(),
                fields,
            }))
        }
        ("java/lang/Integer", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Int(0));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Integer".to_string(),
                fields,
            }))
        }
        ("java/lang/Long", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Long(0));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Long".to_string(),
                fields,
            }))
        }
        ("java/lang/Float", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Float(0.0));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Float".to_string(),
                fields,
            }))
        }
        ("java/lang/Double", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Double(0.0));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Double".to_string(),
                fields,
            }))
        }
        _ => None,
    }
}

/// 内置高频 `NewObject` 默认分发（支持 `java/lang/String` 从 `byte[]`/`String` 构造）
pub fn default_new_object(
    ctx: &mut JniContext<'_>,
    class_name: &str,
    method: &MethodDesc,
    args: &[JValue],
) -> JObjectRef {
    if class_name == "java/lang/String" {
        if method.sig.starts_with("([BII") {
            let bytes = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| match ctx.objects.get(r) {
                    Some(JObject::ByteArray(b)) => Some(b.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            let offset = args.get(1).and_then(|v| v.as_int()).unwrap_or(0).max(0) as usize;
            let count = args.get(2).and_then(|v| v.as_int()).unwrap_or(0).max(0) as usize;
            let end = offset.saturating_add(count).min(bytes.len());
            let slice = if offset <= end { &bytes[offset..end] } else { &[] };
            return ctx
                .objects
                .add_string(String::from_utf8_lossy(slice).into_owned());
        }
        if method.sig.starts_with("([B") {
            let bytes = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| match ctx.objects.get(r) {
                    Some(JObject::ByteArray(b)) => Some(b.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            return ctx
                .objects
                .add_string(String::from_utf8_lossy(&bytes).into_owned());
        }
        if method.sig == "(Ljava/lang/String;)V" {
            let s = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("")
                .to_string();
            return ctx.objects.add_string(s);
        }
        if method.sig == "()V" {
            return ctx.objects.add_string("");
        }
        if method.sig.starts_with("([CII") {
            let chars = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_chars(r))
                .map(|c| c.to_vec())
                .unwrap_or_default();
            let offset = args.get(1).and_then(|v| v.as_int()).unwrap_or(0).max(0) as usize;
            let count = args.get(2).and_then(|v| v.as_int()).unwrap_or(0).max(0) as usize;
            let end = offset.saturating_add(count).min(chars.len());
            let slice = if offset <= end { &chars[offset..end] } else { &[] };
            return ctx.objects.add_string(String::from_utf16_lossy(slice));
        }
        if method.sig.starts_with("([C") {
            let chars = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_chars(r))
                .map(|c| c.to_vec())
                .unwrap_or_default();
            return ctx.objects.add_string(String::from_utf16_lossy(&chars));
        }
    }
    if matches!(
        class_name,
        "java/lang/StringBuilder" | "java/lang/StringBuffer"
    ) {
        let init = if method.sig == "(Ljava/lang/String;)V"
            || method.sig == "(Ljava/lang/CharSequence;)V"
        {
            args.first()
                .map(|v| jvalue_to_java_string(ctx, v))
                .unwrap_or_default()
        } else {
            String::new()
        };
        return ctx.objects.add_local(JObject::StringBuilder(init));
    }
    if matches!(
        class_name,
        "java/util/ArrayList"
            | "java/util/LinkedList"
            | "java/util/Vector"
            | "java/util/HashSet"
            | "java/util/LinkedHashSet"
    ) {
        return ctx.objects.add_local(JObject::List {
            class_name: class_name.to_string(),
            items: Vec::new(),
        });
    }
    if matches!(
        class_name,
        "java/util/HashMap" | "java/util/LinkedHashMap" | "java/util/TreeMap"
    ) {
        return ctx.objects.add_local(JObject::Map {
            class_name: class_name.to_string(),
            entries: Vec::new(),
        });
    }
    if class_name == "java/util/Date" {
        let ms = args
            .first()
            .and_then(|v| v.as_long())
            .unwrap_or(1_700_000_000_000);
        let mut fields = HashMap::new();
        fields.insert("time".to_string(), JValue::Long(ms));
        return ctx.objects.add_local(JObject::Custom {
            class_name: class_name.to_string(),
            fields,
        });
    }
    if class_name == "java/util/Random" {
        let seed = args
            .first()
            .and_then(|v| v.as_long())
            .map(|s| ((s as u64) ^ 0x5DEE_CE66D) & ((1u64 << 48) - 1))
            .unwrap_or(0x0000_1234_ABCD_330E);
        let mut fields = HashMap::new();
        fields.insert("seed".to_string(), JValue::Long(seed as i64));
        return ctx.objects.add_local(JObject::Custom {
            class_name: class_name.to_string(),
            fields,
        });
    }
    if matches!(
        class_name,
        "java/lang/Boolean"
            | "java/lang/Byte"
            | "java/lang/Character"
            | "java/lang/Short"
            | "java/lang/Integer"
            | "java/lang/Long"
            | "java/lang/Float"
            | "java/lang/Double"
    ) {
        let mut fields = HashMap::new();
        if let Some(v) = args.first().cloned() {
            fields.insert("value".to_string(), v);
        }
        return ctx.objects.add_local(JObject::Custom {
            class_name: class_name.to_string(),
            fields,
        });
    }
    ctx.objects.add_local(JObject::Custom {
        class_name: class_name.to_string(),
        fields: Default::default(),
    })
}
