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
        _ctx: &mut JniContext<'_>,
        _obj: JObjectRef,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> i64 {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 CallLongMethod: {}.{}{}",
            method.class_name, method.name, method.sig
        );
        0
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
        _ctx: &mut JniContext<'_>,
        _obj: JObjectRef,
        method: &MethodDesc,
        _args: &[JValue],
    ) {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 CallVoidMethod: {}.{}{}",
            method.class_name, method.name, method.sig
        );
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
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> i64 {
        tracing::warn!(target: "runidbg::jni", 
            "[JNI] 未处理的 CallStaticLongMethod: {}.{}{}",
            class_name, method.name, method.sig
        );
        0
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
        _ctx: &mut JniContext<'_>,
        _obj: JObjectRef,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> i8 {
        0
    }

    fn call_char_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _obj: JObjectRef,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> u16 {
        0
    }

    fn call_short_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _obj: JObjectRef,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> i16 {
        0
    }

    fn call_float_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _obj: JObjectRef,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> f32 {
        0.0
    }

    fn call_double_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        _obj: JObjectRef,
        _method: &MethodDesc,
        _args: &[JValue],
    ) -> f64 {
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
        (Some(JObject::String(_)), "toString") => obj,
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
    _args: &[JValue],
) -> i32 {
    match (ctx.objects.get(obj), method.name.as_str()) {
        (Some(JObject::String(s)), "length") => s.chars().count() as i32,
        _ => {
            tracing::warn!(target: "runidbg::jni", 
                "[JNI] 未处理的 CallIntMethod: {}.{}{}",
                method.class_name, method.name, method.sig
            );
            0
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
    match (ctx.objects.get(obj), method.name.as_str()) {
        (Some(JObject::String(lhs)), "equals") => {
            let rhs = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r));
            rhs == Some(lhs.as_str())
        }
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
        ("java/lang/Boolean", "valueOf") => {
            let mut fields = HashMap::new();
            let v = args.first().cloned().unwrap_or(JValue::Boolean(false));
            fields.insert("value".to_string(), v);
            Some(ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/Boolean".to_string(),
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
    }
    ctx.objects.add_local(JObject::Custom {
        class_name: class_name.to_string(),
        fields: Default::default(),
    })
}
