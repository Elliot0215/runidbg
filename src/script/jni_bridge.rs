use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::rc::Rc;

use rquickjs::function::Args;
use rquickjs::qjs::JSContext;
use rquickjs::{Ctx, Function, Object, Persistent, TypedArray, Value};

use crate::crash::BreadcrumbRing;
use crate::diag::EnvDiag;
use crate::jni::handler::{
    default_call_object_method, default_call_static_object_method,
    try_default_call_boolean_method, try_default_call_char_method, try_default_call_int_method,
    try_default_call_long_method, try_default_call_static_long_method,
    try_default_call_void_method,
};
use crate::jni::{
    FieldDesc, JObjectRef, JValue, JniContext, JniHandler, MethodDesc, ObjectTable,
};

thread_local! {
    pub(crate) static CURRENT_JS_CTX: Cell<Option<NonNull<JSContext>>> = const { Cell::new(None) };
    static ACTIVE_OBJECTS: Cell<Option<NonNull<ObjectTable>>> = const { Cell::new(None) };
}

/// RAII 守卫：在 Rust 调入 Unicorn 执行期间暴露当前线程的 QuickJS `JSContext`
pub(crate) struct JsCtxGuard {
    prev: Option<NonNull<JSContext>>,
}

impl JsCtxGuard {
    pub fn enter(ctx: &Ctx<'_>) -> Self {
        let prev = CURRENT_JS_CTX.with(|cell| cell.replace(Some(ctx.as_raw())));
        Self { prev }
    }
}

impl Drop for JsCtxGuard {
    fn drop(&mut self) {
        CURRENT_JS_CTX.with(|cell| cell.set(self.prev));
    }
}

/// 获取当前线程活跃的 QuickJS 上下文指针
pub(crate) fn current_js_ctx() -> Option<NonNull<JSContext>> {
    CURRENT_JS_CTX.with(Cell::get)
}

/// RAII 守卫：在 JS JNI 回调执行期间暴露当前活跃的 `ObjectTable`，避免 `ScriptHost` 重入借用冲突
struct ActiveObjectsGuard {
    prev: Option<NonNull<ObjectTable>>,
}

impl ActiveObjectsGuard {
    fn enter(objects: &mut ObjectTable) -> Self {
        let ptr = NonNull::from(objects);
        let prev = ACTIVE_OBJECTS.with(|cell| cell.replace(Some(ptr)));
        Self { prev }
    }
}

impl Drop for ActiveObjectsGuard {
    fn drop(&mut self) {
        ACTIVE_OBJECTS.with(|cell| cell.set(self.prev));
    }
}

/// 若当前正处于 JS JNI 回调或 Unicorn 原生 Hook 回调内部，直接借用活跃 `ObjectTable` 执行闭包
pub(crate) fn with_active_objects<R>(f: impl FnOnce(&mut ObjectTable) -> R) -> Option<R> {
    if let Some(mut ptr) = ACTIVE_OBJECTS.with(Cell::get) {
        // SAFETY: `ActiveObjectsGuard` 保证在单线程同步回调期间指针有效且无别名可变引用
        let obj_ref = unsafe { ptr.as_mut() };
        return Some(f(obj_ref));
    }
    crate::script::hooks::with_active_uc(|uc| f(&mut uc.get_data_mut().jni.objects))
}

/// `list_hooks()` 返回的已注册 Hook 摘要
pub(crate) struct RegisteredHookInfo {
    pub id: u64,
    pub kind: &'static str,
    pub class_name: String,
    pub name: String,
    pub sig: Option<String>,
    pub hits: u64,
}

/// 单条已注册 JS JNI Hook 元数据（携带唯一 ID 与命中计数）
pub(crate) struct HookEntry {
    pub id: u64,
    pub func: Persistent<Function<'static>>,
    pub hits: Cell<u64>,
}

/// 存储每个模拟器实例注册的 JS JNI 回调表
///
/// 按 `field_hooks`（字段专属）、`method_hooks`（方法专属，支持精确签名重载）与
/// `hooks`（历史兼容的按名通用表）分表存储，彻底消除同名字段与方法互相劫持。
#[derive(Default)]
pub(crate) struct JsHookTable {
    pub hooks: HashMap<(String, String), HookEntry>,
    pub field_hooks: HashMap<(String, String, Option<String>), HookEntry>,
    pub method_hooks: HashMap<(String, String, Option<String>), HookEntry>,
    next_hook_id: u64,
    pub unhandled: Option<Persistent<Function<'static>>>,
    pub diag: EnvDiag,
    pub breadcrumbs: BreadcrumbRing,
}

impl JsHookTable {
    fn alloc_entry(&mut self, func: Persistent<Function<'static>>) -> HookEntry {
        self.next_hook_id += 1;
        HookEntry {
            id: self.next_hook_id,
            func,
            hits: Cell::new(0),
        }
    }

    /// 智能注册：
    /// - 含 `(`（如 `"g()Lcas/c0;"`）→ 方法专属 + 精确签名；
    /// - 含 `:`（如 `"g:[C"` 或 `"field:g"`）→ 字段专属（可选签名）；
    /// - 纯名称（如 `"getValue"`）→ 兼容旧版通用表。
    pub fn insert_hook(
        &mut self,
        class_name: &str,
        key: &str,
        func: Persistent<Function<'static>>,
    ) {
        if key.contains('(') {
            self.insert_method_hook(class_name, key, func);
        } else if let Some(rest) = key.strip_prefix("field:") {
            self.insert_field_hook(class_name, rest, func);
        } else if key.contains(':') {
            self.insert_field_hook(class_name, key, func);
        } else {
            let norm = class_name.replace('.', "/");
            let entry = self.alloc_entry(func);
            self.hooks.insert((norm, key.to_string()), entry);
        }
    }

    /// 显式注册字段 Hook（支持 `"name"` 或 `"name:sig"`，绝不劫持同名方法）
    pub fn insert_field_hook(
        &mut self,
        class_name: &str,
        key: &str,
        func: Persistent<Function<'static>>,
    ) {
        let norm = class_name.replace('.', "/");
        let (name, sig) = match key.split_once(':') {
            Some((n, s)) if !s.is_empty() => (n.to_string(), Some(s.to_string())),
            _ => (key.to_string(), None),
        };
        let entry = self.alloc_entry(func);
        self.field_hooks.insert((norm, name, sig), entry);
    }

    /// 显式注册方法 Hook（支持 `"name"` 或 `"name(args)ret"` 精确重载签名，绝不劫持同名字段）
    pub fn insert_method_hook(
        &mut self,
        class_name: &str,
        key: &str,
        func: Persistent<Function<'static>>,
    ) {
        let norm = class_name.replace('.', "/");
        let (name, sig) = match key.find('(') {
            Some(idx) => (key[..idx].to_string(), Some(key[idx..].to_string())),
            None => (key.to_string(), None),
        };
        let entry = self.alloc_entry(func);
        self.method_hooks.insert((norm, name, sig), entry);
    }

    /// 查找字段或方法 Hook（按 精确签名 > 同类无签名 > 声明类精确签名 > 声明类无签名 > 旧版通用表）
    /// 命中时自动累加命中计数并返回 `(hook_id, func)`
    pub fn lookup(
        &self,
        norm_cls: &str,
        decl_cls: &str,
        name: &str,
        sig: &str,
        is_field: bool,
    ) -> Option<(u64, Persistent<Function<'static>>)> {
        let hit = |entry: &HookEntry| -> (u64, Persistent<Function<'static>>) {
            entry.hits.set(entry.hits.get() + 1);
            (entry.id, entry.func.clone())
        };
        let typed_map = if is_field {
            &self.field_hooks
        } else {
            &self.method_hooks
        };
        let sig_opt = (!sig.is_empty()).then(|| sig.to_string());
        if let Some(ref s) = sig_opt {
            if let Some(e) = typed_map.get(&(norm_cls.to_string(), name.to_string(), Some(s.clone()))) {
                return Some(hit(e));
            }
        }
        if let Some(e) = typed_map.get(&(norm_cls.to_string(), name.to_string(), None)) {
            return Some(hit(e));
        }
        if decl_cls != norm_cls {
            if let Some(ref s) = sig_opt {
                if let Some(e) = typed_map.get(&(decl_cls.to_string(), name.to_string(), Some(s.clone()))) {
                    return Some(hit(e));
                }
            }
            if let Some(e) = typed_map.get(&(decl_cls.to_string(), name.to_string(), None)) {
                return Some(hit(e));
            }
        }
        if let Some(e) = self.hooks.get(&(norm_cls.to_string(), name.to_string())) {
            return Some(hit(e));
        }
        if decl_cls != norm_cls {
            if let Some(e) = self.hooks.get(&(decl_cls.to_string(), name.to_string())) {
                return Some(hit(e));
            }
        }
        None
    }

    /// 枚举全部已注册 Hook（按 ID 升序）
    pub fn list_hooks(&self) -> Vec<RegisteredHookInfo> {
        let mut out = Vec::with_capacity(
            self.field_hooks.len() + self.method_hooks.len() + self.hooks.len(),
        );
        for ((cls, name, sig), e) in &self.field_hooks {
            out.push(RegisteredHookInfo {
                id: e.id,
                kind: "field",
                class_name: cls.clone(),
                name: name.clone(),
                sig: sig.clone(),
                hits: e.hits.get(),
            });
        }
        for ((cls, name, sig), e) in &self.method_hooks {
            out.push(RegisteredHookInfo {
                id: e.id,
                kind: "method",
                class_name: cls.clone(),
                name: name.clone(),
                sig: sig.clone(),
                hits: e.hits.get(),
            });
        }
        for ((cls, name), e) in &self.hooks {
            out.push(RegisteredHookInfo {
                id: e.id,
                kind: "any",
                class_name: cls.clone(),
                name: name.clone(),
                sig: None,
                hits: e.hits.get(),
            });
        }
        out.sort_by_key(|item| item.id);
        out
    }

    pub fn clear_all(&mut self) {
        self.hooks.clear();
        self.field_hooks.clear();
        self.method_hooks.clear();
        self.unhandled = None;
    }

    pub fn set_unhandled(&mut self, func: Persistent<Function<'static>>) {
        self.unhandled = Some(func);
    }
}

/// 将 `JniHandler` 回调桥接到 QuickJS 函数
pub(crate) struct JsJniHandler {
    table: Rc<RefCell<JsHookTable>>,
}

impl JsJniHandler {
    pub fn new(table: Rc<RefCell<JsHookTable>>) -> Self {
        Self { table }
    }

    fn invoke_hook<'js>(
        &self,
        ctx_jni: &mut JniContext<'_>,
        class_name: &str,
        obj: Option<JObjectRef>,
        method: &MethodDesc,
        args: &[JValue],
        f: impl FnOnce(&Ctx<'js>, Value<'js>, &mut ObjectTable),
    ) -> bool {
        let Some(raw_ctx) = CURRENT_JS_CTX.with(Cell::get) else {
            crate::jni::env::set_last_jni_hook_id(None);
            return false;
        };
        let norm_cls = class_name.replace('.', "/");
        let decl_cls = method.class_name.replace('.', "/");
        let is_field = !method.sig.starts_with('(');
        let hook_match = self
            .table
            .borrow()
            .lookup(&norm_cls, &decl_cls, &method.name, &method.sig, is_field);
        let Some((hook_id, pfn)) = hook_match else {
            crate::jni::env::set_last_jni_hook_id(None);
            return false;
        };

        // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 指向当前线程存活的 QuickJS 上下文
        let js_ctx: Ctx<'js> = unsafe { Ctx::from_raw(raw_ctx) };
        let _obj_guard = ActiveObjectsGuard::enter(ctx_jni.objects);

        if let Ok(func) = pfn.restore(&js_ctx) {
            let mut call_args = Args::new(js_ctx.clone(), args.len() + usize::from(obj.is_some()));
            if let Ok(this_meta) = Object::new(js_ctx.clone()) {
                let _ = this_meta.set("ref", obj.map(|r| r.0 as f64).unwrap_or(0.0));
                let _ = this_meta.set("className", norm_cls.as_str());
                let _ = this_meta.set("declaringClass", decl_cls.as_str());
                let _ = this_meta.set("name", method.name.as_str());
                let _ = this_meta.set("sig", method.sig.as_str());
                let _ = this_meta.set("isStatic", method.is_static);
                let _ = this_meta.set("hookId", hook_id as f64);
                let _ = call_args.this(this_meta);
            }
            if let Some(this_obj) = obj {
                let _ = call_args.push_arg(this_obj.0 as f64);
            }
            for a in args {
                if let Ok(v) = jvalue_to_js(&js_ctx, a, ctx_jni.objects) {
                    let _ = call_args.push_arg(v);
                }
            }
            match func.call_arg::<Value<'js>>(call_args) {
                Ok(ret) => {
                    f(&js_ctx, ret, ctx_jni.objects);
                    crate::jni::env::set_last_jni_hook_id(Some(hook_id));
                    return true;
                }
                Err(err) => {
                    tracing::error!(
                        target: "runidbg::jni",
                        class = %norm_cls,
                        method = %method.name,
                        sig = %method.sig,
                        error = %err,
                        "JS JNI 回调异常"
                    );
                    crate::jni::env::set_last_jni_hook_id(Some(hook_id));
                    return true;
                }
            }
        }
        crate::jni::env::set_last_jni_hook_id(None);
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_unhandled<'js>(
        &self,
        ctx_jni: &mut JniContext<'_>,
        kind: &str,
        class_name: &str,
        obj: Option<JObjectRef>,
        method: &MethodDesc,
        args: &[JValue],
        f: impl FnOnce(&Ctx<'js>, Value<'js>, &mut ObjectTable),
    ) -> bool {
        let norm_cls = class_name.replace('.', "/");
        let sig_desc = format!("{norm_cls}.{}{}", method.name, method.sig);
        {
            let tbl = self.table.borrow();
            tbl.diag.record_missing_jni(&sig_desc);
            tbl.breadcrumbs.push(format!("[JNI {kind}] {sig_desc}"));
        }

        let Some(raw_ctx) = CURRENT_JS_CTX.with(Cell::get) else {
            return false;
        };
        let Some(pfn) = self.table.borrow().unhandled.clone() else {
            return false;
        };

        // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 指向当前线程存活的 QuickJS 上下文
        let js_ctx: Ctx<'js> = unsafe { Ctx::from_raw(raw_ctx) };
        let _obj_guard = ActiveObjectsGuard::enter(ctx_jni.objects);

        if let Ok(func) = pfn.restore(&js_ctx) {
            if let Ok(info) = Object::new(js_ctx.clone()) {
                let _ = info.set("kind", kind);
                let _ = info.set("className", norm_cls.as_str());
                let _ = info.set("thisObj", obj.map(|r| r.0 as f64).unwrap_or(0.0));
                let _ = info.set("name", method.name.as_str());
                let _ = info.set("sig", method.sig.as_str());
                let _ = info.set("isStatic", method.is_static);
                if let Ok(js_args) = rquickjs::Array::new(js_ctx.clone()) {
                    for (i, a) in args.iter().enumerate() {
                        if let Ok(v) = jvalue_to_js(&js_ctx, a, ctx_jni.objects) {
                            let _ = js_args.set(i, v);
                        }
                    }
                    let _ = info.set("args", js_args);
                }
                if let Ok(ret) = func.call::<_, Value<'js>>((info,)) {
                    if !ret.is_undefined() {
                        f(&js_ctx, ret, ctx_jni.objects);
                        return true;
                    }
                }
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_js<'js>(
        &self,
        ctx_jni: &mut JniContext<'_>,
        kind: &str,
        class_name: &str,
        obj: Option<JObjectRef>,
        method: &MethodDesc,
        args: &[JValue],
        f: impl FnOnce(&Ctx<'js>, Value<'js>, &mut ObjectTable),
    ) -> bool {
        let mut cb = Some(f);
        if self.invoke_hook(ctx_jni, class_name, obj, method, args, |c, v, o| {
            if let Some(func) = cb.take() {
                func(c, v, o);
            }
        }) {
            return true;
        }
        if let Some(func) = cb {
            return self.invoke_unhandled(ctx_jni, kind, class_name, obj, method, args, func);
        }
        false
    }
}

fn jvalue_to_js<'js>(
    ctx: &Ctx<'js>,
    val: &JValue,
    objects: &ObjectTable,
) -> rquickjs::Result<Value<'js>> {
    match *val {
        JValue::Void => Ok(Value::new_undefined(ctx.clone())),
        JValue::Boolean(b) => Ok(Value::new_bool(ctx.clone(), b)),
        JValue::Byte(v) => Ok(Value::new_int(ctx.clone(), i32::from(v))),
        JValue::Char(v) => Ok(Value::new_int(ctx.clone(), i32::from(v))),
        JValue::Short(v) => Ok(Value::new_int(ctx.clone(), i32::from(v))),
        JValue::Int(v) => Ok(Value::new_int(ctx.clone(), v)),
        JValue::Long(v) => Ok(Value::new_number(ctx.clone(), v as f64)),
        JValue::Float(v) => Ok(Value::new_float(ctx.clone(), f64::from(v))),
        JValue::Double(v) => Ok(Value::new_float(ctx.clone(), v)),
        JValue::Object(r) => {
            if r.is_null() {
                Ok(Value::new_null(ctx.clone()))
            } else if let Some(s) = objects.get_string(r) {
                Ok(rquickjs::String::from_str(ctx.clone(), s)?.into_value())
            } else {
                Ok(Value::new_number(ctx.clone(), r.0 as f64))
            }
        }
    }
}

fn js_to_jobject<'js>(val: Value<'js>, objects: &mut ObjectTable) -> JObjectRef {
    if val.is_null() || val.is_undefined() {
        return JObjectRef::NULL;
    }
    if let Some(s) = val.as_string() {
        if let Ok(rust_s) = s.to_string() {
            return objects.add_string(rust_s);
        }
    }
    if let Some(n) = val.as_number() {
        return JObjectRef(n as u64);
    }
    if let Some(bi) = val.as_big_int() {
        if let Ok(v) = bi.clone().to_i64() {
            return JObjectRef(v as u64);
        }
    }
    if let Ok(ta) = TypedArray::<u8>::from_value(val.clone()) {
        if let Some(slice) = ta.as_bytes() {
            return objects.add_byte_array(slice.to_vec());
        }
    }
    if let Ok(ta) = TypedArray::<u16>::from_value(val.clone()) {
        if let Some(raw) = ta.as_bytes() {
            let chars: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            return objects.add_char_array(chars);
        }
    }
    if let Ok(ta) = TypedArray::<i32>::from_value(val.clone()) {
        if let Some(raw) = ta.as_bytes() {
            let ints: Vec<i32> = raw
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&c| i32::from_le_bytes(c))
                .collect();
            return objects.add_int_array(ints);
        }
    }
    if let Ok(ta) = TypedArray::<i64>::from_value(val.clone()) {
        if let Some(raw) = ta.as_bytes() {
            let longs: Vec<i64> = raw
                .as_chunks::<8>()
                .0
                .iter()
                .map(|&c| i64::from_le_bytes(c))
                .collect();
            return objects.add_long_array(longs);
        }
    }
    if let Some(arr) = val.as_array() {
        let mut elems = Vec::with_capacity(arr.len());
        for i in 0..arr.len() {
            let elem = arr
                .get::<Value<'js>>(i)
                .map(|v| js_to_jobject(v, objects))
                .unwrap_or(JObjectRef::NULL);
            elems.push(elem);
        }
        return objects.add_local(crate::jni::JObject::ObjectArray(elems));
    }
    JObjectRef::NULL
}

fn js_to_bool(val: &Value<'_>) -> bool {
    if let Some(b) = val.as_bool() {
        b
    } else if let Some(n) = val.as_number() {
        n != 0.0
    } else {
        false
    }
}

fn js_to_i64(val: &Value<'_>) -> i64 {
    if let Some(i) = val.as_int() {
        i64::from(i)
    } else if let Some(n) = val.as_number() {
        n as i64
    } else if let Some(bi) = val.as_big_int() {
        bi.clone().to_i64().unwrap_or(0)
    } else if let Some(b) = val.as_bool() {
        i64::from(b)
    } else {
        0
    }
}

fn js_to_f64(val: &Value<'_>) -> f64 {
    val.as_number().unwrap_or(0.0)
}

impl JniHandler for JsJniHandler {
    fn call_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| method.class_name.clone());
        let mut out = JObjectRef::NULL;
        if self.invoke_hook(ctx, &cls, Some(obj), method, args, |_, v, objs| {
            out = js_to_jobject(v, objs);
        }) {
            return out;
        }
        let default_ret = default_call_object_method(ctx, obj, method, args);
        if !default_ret.is_null() {
            return default_ret;
        }
        if self.invoke_unhandled(ctx, "CallObjectMethod", &cls, Some(obj), method, args, |_, v, objs| {
            out = js_to_jobject(v, objs);
        }) {
            return out;
        }
        JObjectRef::NULL
    }

    fn call_static_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        let mut out = JObjectRef::NULL;
        if self.invoke_hook(ctx, class_name, None, method, args, |_, v, objs| {
            out = js_to_jobject(v, objs);
        }) {
            return out;
        }
        if let Some(default_ret) = default_call_static_object_method(ctx, class_name, method, args)
        {
            return default_ret;
        }
        if self.invoke_unhandled(
            ctx,
            "CallStaticObjectMethod",
            class_name,
            None,
            method,
            args,
            |_, v, objs| {
                out = js_to_jobject(v, objs);
            },
        ) {
            return out;
        }
        JObjectRef::NULL
    }

    fn call_boolean_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> bool {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| method.class_name.clone());
        let mut out = false;
        if self.invoke_hook(ctx, &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_bool(&v);
        }) {
            return out;
        }
        if let Some(v) = try_default_call_boolean_method(ctx, obj, method, args) {
            return v;
        }
        self.invoke_unhandled(ctx, "CallBooleanMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_bool(&v);
        });
        out
    }

    fn call_static_boolean_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> bool {
        let mut out = false;
        self.invoke_js(
            ctx,
            "CallStaticBooleanMethod",
            class_name,
            None,
            method,
            args,
            |_, v, _| out = js_to_bool(&v),
        );
        out
    }

    fn call_byte_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i8 {
        let cls = method.class_name.clone();
        let mut out = 0i8;
        self.invoke_js(ctx, "CallByteMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v) as i8;
        });
        out
    }

    fn call_char_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> u16 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| method.class_name.clone());
        let mut out = 0u16;
        if self.invoke_hook(ctx, &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v) as u16;
        }) {
            return out;
        }
        if let Some(v) = try_default_call_char_method(ctx, obj, method, args) {
            return v;
        }
        self.invoke_unhandled(ctx, "CallCharMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v) as u16;
        });
        out
    }

    fn call_short_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i16 {
        let cls = method.class_name.clone();
        let mut out = 0i16;
        self.invoke_js(ctx, "CallShortMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v) as i16;
        });
        out
    }

    fn call_int_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i32 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| method.class_name.clone());
        let mut out = 0i32;
        if self.invoke_hook(ctx, &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v) as i32;
        }) {
            return out;
        }
        if let Some(v) = try_default_call_int_method(ctx, obj, method, args) {
            return v;
        }
        self.invoke_unhandled(ctx, "CallIntMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v) as i32;
        });
        out
    }

    fn call_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| method.class_name.clone());
        let mut out = 0i64;
        if self.invoke_hook(ctx, &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v);
        }) {
            return out;
        }
        if let Some(v) = try_default_call_long_method(ctx, obj, method, args) {
            return v;
        }
        self.invoke_unhandled(ctx, "CallLongMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_i64(&v);
        });
        out
    }

    fn call_float_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f32 {
        let cls = method.class_name.clone();
        let mut out = 0.0f32;
        self.invoke_js(ctx, "CallFloatMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_f64(&v) as f32;
        });
        out
    }

    fn call_double_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f64 {
        let cls = method.class_name.clone();
        let mut out = 0.0f64;
        self.invoke_js(ctx, "CallDoubleMethod", &cls, Some(obj), method, args, |_, v, _| {
            out = js_to_f64(&v);
        });
        out
    }

    fn call_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| method.class_name.clone());
        if self.invoke_hook(ctx, &cls, Some(obj), method, args, |_, _, _| {}) {
            return;
        }
        if try_default_call_void_method(ctx, obj, method, args) {
            return;
        }
        self.invoke_unhandled(ctx, "CallVoidMethod", &cls, Some(obj), method, args, |_, _, _| {});
    }

    fn call_static_byte_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i8 {
        let mut out = 0i8;
        self.invoke_js(ctx, "CallStaticByteMethod", class_name, None, method, args, |_, v, _| {
            out = js_to_i64(&v) as i8;
        });
        out
    }

    fn call_static_char_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> u16 {
        let mut out = 0u16;
        self.invoke_js(ctx, "CallStaticCharMethod", class_name, None, method, args, |_, v, _| {
            out = js_to_i64(&v) as u16;
        });
        out
    }

    fn call_static_short_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i16 {
        let mut out = 0i16;
        self.invoke_js(ctx, "CallStaticShortMethod", class_name, None, method, args, |_, v, _| {
            out = js_to_i64(&v) as i16;
        });
        out
    }

    fn call_static_int_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i32 {
        let mut out = 0i32;
        self.invoke_js(ctx, "CallStaticIntMethod", class_name, None, method, args, |_, v, _| {
            out = js_to_i64(&v) as i32;
        });
        out
    }

    fn call_static_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        let mut out = 0i64;
        if self.invoke_hook(ctx, class_name, None, method, args, |_, v, _| {
            out = js_to_i64(&v);
        }) {
            return out;
        }
        if let Some(v) = try_default_call_static_long_method(ctx, class_name, method, args) {
            return v;
        }
        self.invoke_unhandled(
            ctx,
            "CallStaticLongMethod",
            class_name,
            None,
            method,
            args,
            |_, v, _| out = js_to_i64(&v),
        );
        out
    }

    fn call_static_float_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f32 {
        let mut out = 0.0f32;
        self.invoke_js(ctx, "CallStaticFloatMethod", class_name, None, method, args, |_, v, _| {
            out = js_to_f64(&v) as f32;
        });
        out
    }

    fn call_static_double_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f64 {
        let mut out = 0.0f64;
        self.invoke_js(ctx, "CallStaticDoubleMethod", class_name, None, method, args, |_, v, _| {
            out = js_to_f64(&v);
        });
        out
    }

    fn call_static_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        self.invoke_js(
            ctx,
            "CallStaticVoidMethod",
            class_name,
            None,
            method,
            args,
            |_, _, _| {},
        );
    }

    fn new_object(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        let mut out = JObjectRef::NULL;
        if self.invoke_js(ctx, "NewObject", class_name, None, method, args, |_, v, objs| {
            out = js_to_jobject(v, objs);
        }) {
            return out;
        }
        crate::jni::handler::default_new_object(ctx, class_name, method, args)
    }

    fn get_object_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> JObjectRef {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = JObjectRef::NULL;
        let is_char_array = field.sig == "[C";
        if self.invoke_hook(ctx, &cls, Some(obj), &pseudo, &[], |_, v, objs| {
            if is_char_array {
                if let Some(s) = v.as_string() {
                    if let Ok(rust_s) = s.to_string() {
                        out = objs.add_char_array(rust_s.encode_utf16().collect::<Vec<u16>>());
                        return;
                    }
                }
            }
            out = js_to_jobject(v, objs);
        }) {
            return out;
        }
        let default_ret = crate::jni::handler::default_get_object_field(ctx, obj, field);
        if !default_ret.is_null() {
            return default_ret;
        }
        if self.invoke_unhandled(ctx, "GetObjectField", &cls, Some(obj), &pseudo, &[], |_, v, objs| {
            if is_char_array {
                if let Some(s) = v.as_string() {
                    if let Ok(rust_s) = s.to_string() {
                        out = objs.add_char_array(rust_s.encode_utf16().collect::<Vec<u16>>());
                        return;
                    }
                }
            }
            out = js_to_jobject(v, objs);
        }) {
            return out;
        }
        JObjectRef::NULL
    }

    fn get_boolean_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> bool {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = false;
        self.invoke_js(ctx, "GetBooleanField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_bool(&v);
        });
        out
    }

    fn get_byte_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i8 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = 0i8;
        self.invoke_js(ctx, "GetByteField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_i64(&v) as i8;
        });
        out
    }

    fn get_char_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> u16 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = 0u16;
        self.invoke_js(ctx, "GetCharField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_i64(&v) as u16;
        });
        out
    }

    fn get_short_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i16 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = 0i16;
        self.invoke_js(ctx, "GetShortField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_i64(&v) as i16;
        });
        out
    }

    fn get_int_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i32 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = 0i32;
        self.invoke_js(ctx, "GetIntField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_i64(&v) as i32;
        });
        out
    }

    fn get_long_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i64 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = 0i64;
        self.invoke_js(ctx, "GetLongField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_i64(&v);
        });
        out
    }

    fn get_float_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f32 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = 0.0f32;
        self.invoke_js(ctx, "GetFloatField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_f64(&v) as f32;
        });
        out
    }

    fn get_double_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f64 {
        let cls = ctx
            .objects
            .get(obj)
            .map(|o| o.class_name().to_string())
            .unwrap_or_else(|| field.class_name.clone());
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: false,
        };
        let mut out = 0.0f64;
        self.invoke_js(ctx, "GetDoubleField", &cls, Some(obj), &pseudo, &[], |_, v, _| {
            out = js_to_f64(&v);
        });
        out
    }

    fn get_static_object_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> JObjectRef {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = JObjectRef::NULL;
        let is_char_array = field.sig == "[C";
        if self.invoke_js(
            ctx,
            "GetStaticObjectField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, objs| {
                if is_char_array {
                    if let Some(s) = v.as_string() {
                        if let Ok(rust_s) = s.to_string() {
                            out = objs.add_char_array(rust_s.encode_utf16().collect::<Vec<u16>>());
                            return;
                        }
                    }
                }
                out = js_to_jobject(v, objs);
            },
        ) {
            return out;
        }
        JObjectRef::NULL
    }

    fn get_static_boolean_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> bool {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = false;
        self.invoke_js(
            ctx,
            "GetStaticBooleanField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_bool(&v),
        );
        out
    }

    fn get_static_byte_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i8 {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = 0i8;
        self.invoke_js(
            ctx,
            "GetStaticByteField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_i64(&v) as i8,
        );
        out
    }

    fn get_static_char_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> u16 {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = 0u16;
        self.invoke_js(
            ctx,
            "GetStaticCharField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_i64(&v) as u16,
        );
        out
    }

    fn get_static_short_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i16 {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = 0i16;
        self.invoke_js(
            ctx,
            "GetStaticShortField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_i64(&v) as i16,
        );
        out
    }

    fn get_static_int_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i32 {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = 0i32;
        self.invoke_js(
            ctx,
            "GetStaticIntField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_i64(&v) as i32,
        );
        out
    }

    fn get_static_long_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i64 {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = 0i64;
        self.invoke_js(
            ctx,
            "GetStaticLongField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_i64(&v),
        );
        out
    }

    fn get_static_float_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> f32 {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = 0.0f32;
        self.invoke_js(
            ctx,
            "GetStaticFloatField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_f64(&v) as f32,
        );
        out
    }

    fn get_static_double_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> f64 {
        let pseudo = MethodDesc {
            class_name: field.class_name.clone(),
            name: field.name.clone(),
            sig: field.sig.clone(),
            is_static: true,
        };
        let mut out = 0.0f64;
        self.invoke_js(
            ctx,
            "GetStaticDoubleField",
            class_name,
            None,
            &pseudo,
            &[],
            |_, v, _| out = js_to_f64(&v),
        );
        out
    }
}
