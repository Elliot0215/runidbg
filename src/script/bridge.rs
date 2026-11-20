use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rquickjs::{
    Array, BigInt, Ctx, Error as JsError, Exception, Function, Object, Persistent, TypedArray,
    Value,
};
use unicorn_engine::Unicorn;

use crate::emulator::{EmuState, DEFAULT_HEAP_BASE};
use crate::jni::{JObject, JObjectRef, JValue};
use crate::memory::read_guest_cstr;
use crate::tracer::{BinaryTracer, TraceLevel};
use crate::AndroidEmulator;

use super::hooks::{
    dump_regs, encode_arm64_nop, encode_arm64_ret, parse_hex_pattern, parse_reg_name, scan_memory,
    with_active_uc, JsNativeHookTable, SYSCALL_WILDCARD,
};
use super::jni_bridge::{with_active_objects, JsCtxGuard, JsHookTable, JsJniHandler};
use super::{EmuEntry, SharedHost, SharedLogSink};

/// 统一可重入 `Unicorn` 访问器：
/// 在原生 Hook 回调期间直接复用线程局部 `ACTIVE_UC`，非回调期间借用 `ScriptHost`。
fn with_uc<R>(
    ctx: &Ctx<'_>,
    host: &SharedHost,
    emu_id: usize,
    f: impl FnOnce(&mut Unicorn<'static, EmuState>) -> rquickjs::Result<R>,
) -> rquickjs::Result<R> {
    let mut f = Some(f);
    if let Some(res) = with_active_uc(|uc| (f.take().unwrap())(uc)) {
        return res;
    }
    let mut h = host.borrow_mut();
    let entry = h
        .emus
        .get_mut(emu_id)
        .ok_or_else(|| throw_err(ctx, "无效的 emuId"))?;
    (f.take().unwrap())(entry.emu.uc_mut())
}

fn throw_err(ctx: &Ctx<'_>, msg: impl std::fmt::Display) -> JsError {
    Exception::throw_message(ctx, &msg.to_string())
}

fn js_val_to_jvalue(v: &Value<'_>) -> JValue {
    if let Some(b) = v.as_bool() {
        JValue::Boolean(b)
    } else if let Some(i) = v.as_int() {
        JValue::Int(i)
    } else if let Some(n) = v.as_number() {
        JValue::Double(n)
    } else if let Some(bi) = v.as_big_int() {
        JValue::Long(bi.clone().to_i64().unwrap_or(0))
    } else {
        JValue::Object(JObjectRef::NULL)
    }
}

fn js_val_to_u64(ctx: &Ctx<'_>, v: &Value<'_>) -> rquickjs::Result<u64> {
    if let Some(i) = v.as_int() {
        Ok(i as i64 as u64)
    } else if let Some(n) = v.as_number() {
        Ok(n as i64 as u64)
    } else if let Some(bi) = v.as_big_int() {
        bi.clone()
            .to_i64()
            .map(|x| x as u64)
            .map_err(|e| throw_err(ctx, format!("BigInt 转换 u64 失败: {e}")))
    } else if let Some(b) = v.as_bool() {
        Ok(u64::from(b))
    } else {
        Err(throw_err(ctx, "期望 number 或 bigint"))
    }
}

pub(super) fn register_native_bridge<'js>(
    ctx: &Ctx<'js>,
    host: &SharedHost,
    log_sink: &SharedLogSink,
    cli_args: &[String],
) -> rquickjs::Result<()> {
    let globals = ctx.globals();
    let native = Object::new(ctx.clone())?;

    // 全局 args 数组
    let js_args = Array::new(ctx.clone())?;
    for (i, a) in cli_args.iter().enumerate() {
        js_args.set(i, a.as_str())?;
    }
    globals.set("args", js_args)?;

    // print(level, msg)
    {
        let sink = Rc::clone(log_sink);
        native.set(
            "print",
            Function::new(ctx.clone(), move |level: String, msg: String| {
                if sink.capture {
                    sink.buf.borrow_mut().push(format!("[{level}] {msg}"));
                } else {
                    match level.as_str() {
                        "warn" | "error" => eprintln!("{msg}"),
                        _ => println!("{msg}"),
                    }
                }
            })?,
        )?;
    }

    // emuCreate(packageName, searchPaths, hleAccel, heapSize) -> emuId
    {
        let host = Rc::clone(host);
        native.set(
            "emuCreate",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      pkg: String,
                      search_paths: Vec<String>,
                      hle_accel: bool,
                      heap_size: f64|
                      -> rquickjs::Result<usize> {
                    let hooks = Rc::new(RefCell::new(JsHookTable::default()));
                    let mut builder = AndroidEmulator::builder()
                        .package_name(pkg)
                        .hle_accel(hle_accel)
                        .heap(DEFAULT_HEAP_BASE, (heap_size as u64).max(4 * 1024 * 1024))
                        .jni_handler(Box::new(JsJniHandler::new(Rc::clone(&hooks))));
                    for p in search_paths {
                        builder = builder.add_search_path(p);
                    }
                    let emu = builder.build().map_err(|e| throw_err(&ctx, e))?;
                    {
                        let mut hb = hooks.borrow_mut();
                        hb.diag = emu.diag().clone();
                        hb.breadcrumbs = emu.breadcrumbs().clone();
                    }
                    let mut h = host.borrow_mut();
                    let id = h.emus.len();
                    h.emus.push(EmuEntry {
                        emu,
                        hooks,
                        native_hooks: JsNativeHookTable::default(),
                        modules: Vec::new(),
                        snapshots: Vec::new(),
                    });
                    Ok(id)
                },
            )?,
        )?;
    }

    // emuLoad(emuId, path) -> { id, name, base, size }
    {
        let host = Rc::clone(host);
        native.set(
            "emuLoad",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, path: String| -> rquickjs::Result<Object<'js>> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .emu
                        .load_library(&path)
                        .map_err(|e| throw_err(&ctx, e))?;
                    let mod_id = entry.modules.len();
                    let obj = Object::new(ctx.clone())?;
                    obj.set("id", mod_id)?;
                    obj.set("name", module.name.as_str())?;
                    obj.set("base", module.base_addr as f64)?;
                    obj.set("size", module.image_size as f64)?;
                    entry.modules.push(module);
                    Ok(obj)
                },
            )?,
        )?;
    }

    // emuJniOnLoad(emuId, modId) -> version or -1
    {
        let host = Rc::clone(host);
        native.set(
            "emuJniOnLoad",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, mod_id: usize| -> rquickjs::Result<i32> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .modules
                        .get(mod_id)
                        .cloned()
                        .ok_or_else(|| throw_err(&ctx, "无效的 modId"))?;
                    let ver = entry
                        .emu
                        .call_jni_onload(&module)
                        .map_err(|e| throw_err(&ctx, e))?;
                    Ok(ver.unwrap_or(-1))
                },
            )?,
        )?;
    }

    // modSymbol(emuId, modId, name) -> addr or 0
    {
        let host = Rc::clone(host);
        native.set(
            "modSymbol",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      mod_id: usize,
                      name: String|
                      -> rquickjs::Result<f64> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .modules
                        .get(mod_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 modId"))?;
                    Ok(module.find_symbol(&name).unwrap_or(0) as f64)
                },
            )?,
        )?;
    }

    // modExports(emuId, modId) -> string[]
    {
        let host = Rc::clone(host);
        native.set(
            "modExports",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, mod_id: usize| -> rquickjs::Result<Vec<String>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .modules
                        .get(mod_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 modId"))?;
                    let mut names: Vec<String> = module.symbols.keys().cloned().collect();
                    names.sort();
                    Ok(names)
                },
            )?,
        )?;
    }

    // modCallSymbol(emuId, modId, sym, args[]) -> f64
    {
        let host = Rc::clone(host);
        native.set(
            "modCallSymbol",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      mod_id: usize,
                      sym: String,
                      raw_args: Vec<f64>|
                      -> rquickjs::Result<f64> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let module = entry
                        .modules
                        .get(mod_id)
                        .cloned()
                        .ok_or_else(|| throw_err(&ctx, "无效的 modId"))?;
                    let args_u64: Vec<u64> = raw_args.into_iter().map(|v| v as u64).collect();
                    let _ret = entry
                        .emu
                        .call_symbol(&module, &sym, &args_u64)
                        .map_err(|e| throw_err(&ctx, e))?;
                    entry
                        .native_hooks
                        .flush_ret_magic_leaves(emu_id, entry.emu.uc_mut());
                    let final_ret = entry
                        .emu
                        .uc()
                        .reg_read(unicorn_engine::RegisterARM64::X0)
                        .unwrap_or(_ret);
                    Ok(final_ret as f64)
                },
            )?,
        )?;
    }

    // emuCallAddr(emuId, addr, args[]) -> f64
    {
        let host = Rc::clone(host);
        native.set(
            "emuCallAddr",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      raw_args: Vec<f64>|
                      -> rquickjs::Result<f64> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let args_u64: Vec<u64> = raw_args.into_iter().map(|v| v as u64).collect();
                    let _ret = entry
                        .emu
                        .call_address(addr as u64, &args_u64)
                        .map_err(|e| throw_err(&ctx, e))?;
                    entry
                        .native_hooks
                        .flush_ret_magic_leaves(emu_id, entry.emu.uc_mut());
                    let final_ret = entry
                        .emu
                        .uc()
                        .reg_read(unicorn_engine::RegisterARM64::X0)
                        .unwrap_or(_ret);
                    Ok(final_ret as f64)
                },
            )?,
        )?;
    }

    // jniHook(emuId, className, methodName, fn)
    {
        let host = Rc::clone(host);
        native.set(
            "jniHook",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      method: String,
                      func: Function<'js>|
                      -> rquickjs::Result<()> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let pfn = Persistent::save(&ctx, func);
                    entry.hooks.borrow_mut().insert_hook(&cls, &method, pfn);
                    Ok(())
                },
            )?,
        )?;
    }

    // jniOnUnhandled(emuId, fn)
    {
        let host = Rc::clone(host);
        native.set(
            "jniOnUnhandled",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, func: Function<'js>| -> rquickjs::Result<()> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let pfn = Persistent::save(&ctx, func);
                    entry.hooks.borrow_mut().set_unhandled(pfn);
                    Ok(())
                },
            )?,
        )?;
    }

    // jniRegisteredNatives(emuId) -> [{ className, name, sig, fnPtr }]
    {
        let host = Rc::clone(host);
        native.set(
            "jniRegisteredNatives",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Array<'js>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let arr = Array::new(ctx.clone())?;
                    for (i, reg) in entry.emu.jni().registered_natives.iter().enumerate() {
                        let o = Object::new(ctx.clone())?;
                        o.set("className", reg.class_name.as_str())?;
                        o.set("name", reg.name.as_str())?;
                        o.set("sig", reg.sig.as_str())?;
                        o.set("fnPtr", reg.fn_ptr as f64)?;
                        arr.set(i, o)?;
                    }
                    Ok(arr)
                },
            )?,
        )?;
    }

    // jniCallNative(emuId, className, methodName, extraArgs[]) -> f64
    {
        let host = Rc::clone(host);
        native.set(
            "jniCallNative",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      cls: String,
                      method: String,
                      raw_args: Vec<f64>|
                      -> rquickjs::Result<f64> {
                    let _guard = JsCtxGuard::enter(&ctx);
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let args_u64: Vec<u64> = raw_args.into_iter().map(|v| v as u64).collect();
                    let ret = entry
                        .emu
                        .call_registered_native(&cls, &method, &args_u64)
                        .map_err(|e| throw_err(&ctx, e))?;
                    Ok(ret as f64)
                },
            )?,
        )?;
    }

    // jniNewString(emuId, str) -> handle (支持在 JNI 回调内部重入调用)
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, s: String| -> rquickjs::Result<f64> {
                    if let Some(r) = with_active_objects(|objs| objs.add_string(s.clone())) {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.new_jstring(s).0 as f64)
                },
            )?,
        )?;
    }

    // jniNewByteArray(emuId, Uint8Array) -> handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewByteArray",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<f64> {
                    let vec = bytes.as_bytes().unwrap_or(&[]).to_vec();
                    if let Some(r) = with_active_objects(|objs| objs.add_byte_array(vec.clone())) {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.new_jbyte_array(vec).0 as f64)
                },
            )?,
        )?;
    }

    // jniNewObject(emuId, className, fieldsObj?) -> handle
    {
        let host = Rc::clone(host);
        native.set(
            "jniNewObject",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      cls: String,
                      fields_val: Value<'js>|
                      -> rquickjs::Result<f64> {
                    let mut fields = HashMap::new();
                    if let Some(obj) = fields_val.as_object() {
                        for (k, v) in obj.props::<String, Value<'js>>().flatten() {
                            fields.insert(k, js_val_to_jvalue(&v));
                        }
                    }
                    let jobj = JObject::Custom {
                        class_name: cls.replace('.', "/"),
                        fields,
                    };
                    if let Some(r) = with_active_objects(|objs| objs.add_local(jobj.clone())) {
                        return Ok(r.0 as f64);
                    }
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.jni_mut().objects.add_local(jobj).0 as f64)
                },
            )?,
        )?;
    }

    // jniGetString(emuId, ref) -> string | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, r: f64| -> rquickjs::Result<Option<String>> {
                    let jref = JObjectRef(r as u64);
                    if let Some(res) =
                        with_active_objects(|objs| objs.get_string(jref).map(str::to_string))
                    {
                        return Ok(res);
                    }
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.read_jstring(jref).map(str::to_string))
                },
            )?,
        )?;
    }

    // jniGetBytes(emuId, ref) -> Uint8Array | null
    {
        let host = Rc::clone(host);
        native.set(
            "jniGetBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      r: f64|
                      -> rquickjs::Result<Option<TypedArray<'js, u8>>> {
                    let jref = JObjectRef(r as u64);
                    let bytes = if let Some(res) =
                        with_active_objects(|objs| objs.get_bytes(jref).map(|b| b.to_vec()))
                    {
                        res
                    } else {
                        let h = host.borrow();
                        let entry = h
                            .emus
                            .get(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        entry.emu.jni().objects.get_bytes(jref).map(|b| b.to_vec())
                    };
                    match bytes {
                        Some(v) => Ok(Some(TypedArray::new(ctx.clone(), v)?)),
                        None => Ok(None),
                    }
                },
            )?,
        )?;
    }

    // ---- Memory APIs (支持原生 Hook 内重入) ----
    {
        let host = Rc::clone(host);
        native.set(
            "memAlloc",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, size: f64| -> rquickjs::Result<f64> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let addr = uc
                            .get_data_mut()
                            .mem
                            .alloc_heap((size as u64).max(1))
                            .map_err(|e| throw_err(&ctx, e))?;
                        Ok(addr as f64)
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      len: usize|
                      -> rquickjs::Result<TypedArray<'js, u8>> {
                    let buf = with_uc(&ctx, &host, emu_id, |uc| {
                        let mut buf = vec![0u8; len];
                        if len > 0 {
                            uc.mem_read(addr as u64, &mut buf)
                                .map_err(|e| throw_err(&ctx, format!("mem_read 失败: {e:?}")))?;
                        }
                        Ok(buf)
                    })?;
                    TypedArray::new(ctx.clone(), buf)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<()> {
                    let slice = bytes.as_bytes().unwrap_or(&[]);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        if !slice.is_empty() {
                            uc.mem_write(addr as u64, slice)
                                .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        }
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadCString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      max_len: usize|
                      -> rquickjs::Result<String> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        Ok(read_guest_cstr(uc, addr as u64, max_len))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteCString",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      s: String|
                      -> rquickjs::Result<usize> {
                    let mut bytes = s.into_bytes();
                    bytes.push(0);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.mem_write(addr as u64, &bytes)
                            .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadU32",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, addr: f64| -> rquickjs::Result<f64> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let mut b = [0u8; 4];
                        uc.mem_read(addr as u64, &mut b)
                            .map_err(|e| throw_err(&ctx, format!("mem_read 失败: {e:?}")))?;
                        Ok(f64::from(u32::from_le_bytes(b)))
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteU32",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, addr: f64, v: f64| -> rquickjs::Result<()> {
                    let raw = (v as i64) as u32;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.mem_write(addr as u64, &raw.to_le_bytes())
                            .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memReadU64",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, addr: f64| -> rquickjs::Result<BigInt<'js>> {
                    let val = with_uc(&ctx, &host, emu_id, |uc| {
                        let mut b = [0u8; 8];
                        uc.mem_read(addr as u64, &mut b)
                            .map_err(|e| throw_err(&ctx, format!("mem_read 失败: {e:?}")))?;
                        Ok(u64::from_le_bytes(b))
                    })?;
                    BigInt::from_u64(ctx.clone(), val)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "memWriteU64",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      v: BigInt<'js>|
                      -> rquickjs::Result<()> {
                    let raw = v.to_i64().unwrap_or(0) as u64;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.mem_write(addr as u64, &raw.to_le_bytes())
                            .map_err(|e| throw_err(&ctx, format!("mem_write 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    // V2: memScan(emuId, start, len, pattern) -> number[]
    {
        let host = Rc::clone(host);
        native.set(
            "memScan",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      start: f64,
                      len: f64,
                      pattern: String|
                      -> rquickjs::Result<Vec<f64>> {
                    let pat = parse_hex_pattern(&pattern).map_err(|e| throw_err(&ctx, e))?;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let hits = scan_memory(uc, start as u64, len.max(0.0) as u64, &pat);
                        Ok(hits.into_iter().map(|a| a as f64).collect())
                    })
                },
            )?,
        )?;
    }

    // V2: memPatch(emuId, addr, bytes) -> writtenLen
    {
        let host = Rc::clone(host);
        native.set(
            "memPatch",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<usize> {
                    let slice = bytes.as_bytes().unwrap_or(&[]);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        if !slice.is_empty() {
                            let a = addr as u64;
                            uc.mem_write(a, slice)
                                .map_err(|e| throw_err(&ctx, format!("memPatch 失败: {e:?}")))?;
                            let _ = uc.ctl_remove_cache(a, a.saturating_add(slice.len() as u64));
                        }
                        Ok(slice.len())
                    })
                },
            )?,
        )?;
    }

    // V2: memNop(emuId, addr, count) -> writtenBytes
    {
        let host = Rc::clone(host);
        native.set(
            "memNop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, addr: f64, count: usize| -> rquickjs::Result<usize> {
                    let bytes = encode_arm64_nop(count.max(1));
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let a = addr as u64;
                        uc.mem_write(a, &bytes)
                            .map_err(|e| throw_err(&ctx, format!("memNop 失败: {e:?}")))?;
                        let _ = uc.ctl_remove_cache(a, a.saturating_add(bytes.len() as u64));
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    // V2: memRet(emuId, addr, hasVal, val) -> writtenBytes
    {
        let host = Rc::clone(host);
        native.set(
            "memRet",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      addr: f64,
                      has_val: bool,
                      val: Value<'_>|
                      -> rquickjs::Result<usize> {
                    let retval = if has_val {
                        Some(js_val_to_u64(&ctx, &val)? as i64)
                    } else {
                        None
                    };
                    let bytes = encode_arm64_ret(retval);
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let a = addr as u64;
                        uc.mem_write(a, &bytes)
                            .map_err(|e| throw_err(&ctx, format!("memRet 失败: {e:?}")))?;
                        let _ = uc.ctl_remove_cache(a, a.saturating_add(bytes.len() as u64));
                        Ok(bytes.len())
                    })
                },
            )?,
        )?;
    }

    // ---- VFS APIs ----
    {
        let host = Rc::clone(host);
        native.set(
            "vfsSetProperty",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, k: String, v: String| -> rquickjs::Result<()> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().set_property(k, v);
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsWriteText",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      path: String,
                      text: String|
                      -> rquickjs::Result<()> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().add_overlay_file(path, text.into_bytes());
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsWriteBytes",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String,
                      bytes: TypedArray<'js, u8>|
                      -> rquickjs::Result<()> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry
                        .emu
                        .vfs_mut()
                        .add_overlay_file(path, bytes.as_bytes().unwrap_or(&[]).to_vec());
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsReadFile",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      path: String|
                      -> rquickjs::Result<Option<TypedArray<'js, u8>>> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    match entry.emu.uc().get_data().vfs.get_overlay_file(&path) {
                        Some(data) => Ok(Some(TypedArray::new(ctx.clone(), data.to_vec())?)),
                        None => Ok(None),
                    }
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "vfsMountOverlay",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      guest_dir: String,
                      host_dir: String|
                      -> rquickjs::Result<()> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.vfs_mut().mount_readonly(guest_dir, host_dir);
                    Ok(())
                },
            )?,
        )?;
    }

    // ---- Trace & Snapshot APIs ----
    {
        let host = Rc::clone(host);
        native.set(
            "traceStart",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      output: String,
                      level_str: String,
                      start: f64,
                      end: f64,
                      capacity: usize|
                      -> rquickjs::Result<()> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let level = match level_str.as_str() {
                        "fast" => TraceLevel::Fast,
                        "full" => TraceLevel::Full,
                        _ => TraceLevel::RegDelta,
                    };
                    let mut tracer = if output.is_empty() {
                        BinaryTracer::new_in_memory_with_level(capacity.max(1024), level)
                    } else if level == TraceLevel::Full {
                        let ext = format!("{output}.ext");
                        BinaryTracer::new_dual_mmap(
                            &output,
                            &ext,
                            capacity.max(1024),
                            capacity.max(1024),
                            level,
                        )
                        .map_err(|e| throw_err(&ctx, e))?
                    } else {
                        let mut t = BinaryTracer::new_mmap(&output, capacity.max(1024))
                            .map_err(|e| throw_err(&ctx, e))?;
                        t.set_level(level);
                        t
                    };
                    let begin = start.max(0.0) as u64;
                    let finish = if end < 0.0 { u64::MAX } else { end as u64 };
                    if begin > 0 || finish < u64::MAX {
                        tracer.filter_mut().allow_range(begin, finish);
                    }
                    entry.emu.set_tracer(tracer).map_err(|e| throw_err(&ctx, e))?;
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "traceStop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.detach_tracer().map_err(|e| throw_err(&ctx, e))?;
                    let obj = Object::new(ctx.clone())?;
                    obj.set("records", entry.emu.tracer().records().len())?;
                    obj.set("extRecords", entry.emu.tracer().ext_records().len())?;
                    Ok(obj)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuSnapshot",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<usize> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let snap = entry
                        .emu
                        .capture_snapshot()
                        .map_err(|e| throw_err(&ctx, e))?;
                    let id = entry.snapshots.len();
                    entry.snapshots.push(snap);
                    Ok(id)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuRestore",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, snap_id: usize| -> rquickjs::Result<()> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let snap = entry
                        .snapshots
                        .get(snap_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 snapshotId"))?;
                    entry
                        .emu
                        .restore_snapshot(snap)
                        .map_err(|e| throw_err(&ctx, e))?;
                    Ok(())
                },
            )?,
        )?;
    }

    // ---- V2: CPU 寄存器 & 仿真控制 ----
    {
        let host = Rc::clone(host);
        native.set(
            "regGet",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, name: String| -> rquickjs::Result<f64> {
                    let reg = parse_reg_name(&name)
                        .ok_or_else(|| throw_err(&ctx, format!("未知寄存器: {name}")))?;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        let v = uc
                            .reg_read(reg)
                            .map_err(|e| throw_err(&ctx, format!("reg_read 失败: {e:?}")))?;
                        Ok(v as f64)
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "regGetBigInt",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, name: String| -> rquickjs::Result<BigInt<'js>> {
                    let reg = parse_reg_name(&name)
                        .ok_or_else(|| throw_err(&ctx, format!("未知寄存器: {name}")))?;
                    let val = with_uc(&ctx, &host, emu_id, |uc| {
                        uc.reg_read(reg)
                            .map_err(|e| throw_err(&ctx, format!("reg_read 失败: {e:?}")))
                    })?;
                    BigInt::from_u64(ctx.clone(), val)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "regSet",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      name: String,
                      val: Value<'_>|
                      -> rquickjs::Result<()> {
                    let reg = parse_reg_name(&name)
                        .ok_or_else(|| throw_err(&ctx, format!("未知寄存器: {name}")))?;
                    let raw = js_val_to_u64(&ctx, &val)?;
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.reg_write(reg, raw)
                            .map_err(|e| throw_err(&ctx, format!("reg_write 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "regDump",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let pairs = with_uc(&ctx, &host, emu_id, |uc| Ok(dump_regs(uc)))?;
                    let obj = Object::new(ctx.clone())?;
                    for (name, val) in pairs {
                        obj.set(name, val as f64)?;
                    }
                    Ok(obj)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuStop",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                    with_uc(&ctx, &host, emu_id, |uc| {
                        uc.get_data_mut().manual_stop = true;
                        uc.emu_stop()
                            .map_err(|e| throw_err(&ctx, format!("emu_stop 失败: {e:?}")))?;
                        Ok(())
                    })
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuSetLimits",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>,
                      emu_id: usize,
                      timeout_ms: f64,
                      max_insns: f64|
                      -> rquickjs::Result<()> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    let timeout_us = if timeout_ms > 0.0 {
                        (timeout_ms * 1000.0) as u64
                    } else {
                        0
                    };
                    let max_instructions = if max_insns > 0.0 {
                        max_insns as usize
                    } else {
                        0
                    };
                    entry.emu.set_execution_limits(timeout_us, max_instructions);
                    Ok(())
                },
            )?,
        )?;
    }

    // ---- Phase 2: EnvDiag (缺环境自动诊断与模板生成) ----
    {
        let host = Rc::clone(host);
        native.set(
            "diagSetEnabled",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, enabled: bool| -> rquickjs::Result<()> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    if enabled {
                        entry.emu.diag().enable();
                    } else {
                        entry.emu.diag().disable();
                    }
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "diagClear",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<()> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry.emu.diag().clear();
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "diagReport",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Object<'js>> {
                    let snap = {
                        let h = host.borrow();
                        let entry = h
                            .emus
                            .get(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        entry.emu.diag().snapshot()
                    };
                    let out = Object::new(ctx.clone())?;
                    let files = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_files {
                        files.set(k, v as f64)?;
                    }
                    let props = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_properties {
                        props.set(k, v as f64)?;
                    }
                    let syscalls = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_syscalls {
                        syscalls.set(k.to_string(), v as f64)?;
                    }
                    let jni = Object::new(ctx.clone())?;
                    for (k, v) in snap.missing_jni {
                        jni.set(k, v as f64)?;
                    }
                    out.set("missingFiles", files)?;
                    out.set("missingProperties", props)?;
                    out.set("missingSyscalls", syscalls)?;
                    out.set("missingJni", jni)?;
                    Ok(out)
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "diagGeneratePatchJs",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize| -> rquickjs::Result<String> {
                    let h = host.borrow();
                    let entry = h
                        .emus
                        .get(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.emu.diag().generate_patch_js())
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuLastCrash",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize| -> rquickjs::Result<Value<'js>> {
                    let report = {
                        let h = host.borrow();
                        let entry = h
                            .emus
                            .get(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        entry.emu.last_crash().cloned()
                    };
                    let Some(r) = report else {
                        return Ok(Value::new_null(ctx.clone()));
                    };
                    let obj = Object::new(ctx.clone())?;
                    obj.set("reason", r.reason.as_str())?;
                    obj.set("pc", r.pc as f64)?;
                    obj.set("pcHex", format!("0x{:016x}", r.pc))?;
                    obj.set("pcLocation", r.pc_location.as_str())?;
                    obj.set("lr", r.lr as f64)?;
                    obj.set("lrLocation", r.lr_location.as_str())?;
                    obj.set("sp", r.sp as f64)?;
                    obj.set("fp", r.fp as f64)?;

                    let disasm_arr = Array::new(ctx.clone())?;
                    for (i, d) in r.disasm.iter().enumerate() {
                        let item = Object::new(ctx.clone())?;
                        item.set("addr", format!("0x{:016x}", d.addr))?;
                        item.set("word", format!("0x{:08x}", d.word))?;
                        item.set("asm", d.asm.as_str())?;
                        item.set("isPc", d.is_pc)?;
                        disasm_arr.set(i, item)?;
                    }
                    obj.set("disasm", disasm_arr)?;

                    let bt_arr = Array::new(ctx.clone())?;
                    for (i, f) in r.backtrace.iter().enumerate() {
                        let item = Object::new(ctx.clone())?;
                        item.set("index", f.index as f64)?;
                        item.set("addr", format!("0x{:016x}", f.addr))?;
                        item.set("location", f.location.as_str())?;
                        bt_arr.set(i, item)?;
                    }
                    obj.set("backtrace", bt_arr)?;

                    let bc_arr = Array::new(ctx.clone())?;
                    for (i, b) in r.breadcrumbs.iter().enumerate() {
                        bc_arr.set(i, b.as_str())?;
                    }
                    obj.set("breadcrumbs", bc_arr)?;
                    obj.set("formatted", r.format_pretty())?;
                    Ok(obj.into_value())
                },
            )?,
        )?;
    }

    // ---- Phase 2: APK 一键加载 ----
    {
        let host = Rc::clone(host);
        native.set(
            "emuLoadApk",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, emu_id: usize, path: String| -> rquickjs::Result<Object<'js>> {
                    #[cfg(feature = "apk")]
                    {
                        let mut h = host.borrow_mut();
                        let entry = h
                            .emus
                            .get_mut(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        let apk = entry
                            .emu
                            .load_apk(&path)
                            .map_err(|e| throw_err(&ctx, e))?;
                        let obj = Object::new(ctx.clone())?;
                        if let Some(pkg) = apk.package_name {
                            obj.set("packageName", pkg)?;
                        } else {
                            obj.set("packageName", Value::new_null(ctx.clone()))?;
                        }
                        obj.set("abi", apk.abi)?;
                        let libs = Array::new(ctx.clone())?;
                        for (i, name) in apk.native_libs.keys().enumerate() {
                            libs.set(i, name.as_str())?;
                        }
                        obj.set("libs", libs)?;
                        let assets = Array::new(ctx.clone())?;
                        for (i, name) in apk.assets.keys().enumerate() {
                            assets.set(i, name.as_str())?;
                        }
                        obj.set("assets", assets)?;
                        obj.set(
                            "signatureSize",
                            apk.signature_cert.as_ref().map_or(0usize, Vec::len) as f64,
                        )?;
                        Ok(obj)
                    }
                    #[cfg(not(feature = "apk"))]
                    {
                        let _ = (&host, emu_id, path);
                        Err(throw_err(
                            &ctx,
                            "当前构建未启用 `apk` feature，无法调用 loadApk",
                        ))
                    }
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "emuLoadApkLib",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      lib_name: String|
                      -> rquickjs::Result<Object<'js>> {
                    #[cfg(feature = "apk")]
                    {
                        let _guard = JsCtxGuard::enter(&ctx);
                        let mut h = host.borrow_mut();
                        let entry = h
                            .emus
                            .get_mut(emu_id)
                            .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                        let module = entry
                            .emu
                            .load_apk_library(&lib_name)
                            .map_err(|e| throw_err(&ctx, e))?;
                        let mod_id = entry.modules.len();
                        let name = module.name.clone();
                        let base = module.base_addr;
                        let size = module.image_size;
                        entry.modules.push(module);
                        let obj = Object::new(ctx.clone())?;
                        obj.set("id", mod_id)?;
                        obj.set("name", name)?;
                        obj.set("base", base as f64)?;
                        obj.set("size", size as f64)?;
                        Ok(obj)
                    }
                    #[cfg(not(feature = "apk"))]
                    {
                        let _ = (&host, emu_id, lib_name);
                        Err(throw_err(
                            &ctx,
                            "当前构建未启用 `apk` feature，无法调用 loadApkLib",
                        ))
                    }
                },
            )?,
        )?;
    }

    // ---- V2: Native Hooks (code / mem / replace / attach / syscall / detach) ----
    {
        let host = Rc::clone(host);
        native.set(
            "hookCode",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      begin: f64,
                      end: f64,
                      max_hits: f64,
                      func: Function<'js>|
                      -> rquickjs::Result<usize> {
                    let persistent = Persistent::save(&ctx, func);
                    let limit = if max_hits < 0.0 {
                        None
                    } else {
                        Some(max_hits as u64)
                    };
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry
                        .native_hooks
                        .add_code_hook(
                            emu_id,
                            entry.emu.uc_mut(),
                            begin as u64,
                            end as u64,
                            limit,
                            persistent,
                        )
                        .map_err(|e| throw_err(&ctx, e))
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "hookMem",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      begin: f64,
                      end: f64,
                      read: bool,
                      write: bool,
                      func: Function<'js>|
                      -> rquickjs::Result<usize> {
                    let persistent = Persistent::save(&ctx, func);
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry
                        .native_hooks
                        .add_mem_hook(
                            emu_id,
                            entry.emu.uc_mut(),
                            begin as u64,
                            end as u64,
                            read,
                            write,
                            persistent,
                        )
                        .map_err(|e| throw_err(&ctx, e))
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "hookReplace",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      func: Function<'js>|
                      -> rquickjs::Result<usize> {
                    let persistent = Persistent::save(&ctx, func);
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry
                        .native_hooks
                        .add_replace_hook(emu_id, entry.emu.uc_mut(), addr as u64, persistent)
                        .map_err(|e| throw_err(&ctx, e))
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "hookAttach",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      addr: f64,
                      on_enter: Value<'js>,
                      on_leave: Value<'js>|
                      -> rquickjs::Result<usize> {
                    let enter_fn = if on_enter.is_function() {
                        Some(Persistent::save(
                            &ctx,
                            on_enter
                                .into_function()
                                .ok_or_else(|| throw_err(&ctx, "onEnter 不是函数"))?,
                        ))
                    } else {
                        None
                    };
                    let leave_fn = if on_leave.is_function() {
                        Some(Persistent::save(
                            &ctx,
                            on_leave
                                .into_function()
                                .ok_or_else(|| throw_err(&ctx, "onLeave 不是函数"))?,
                        ))
                    } else {
                        None
                    };
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    entry
                        .native_hooks
                        .add_attach_hook(
                            emu_id,
                            entry.emu.uc_mut(),
                            addr as u64,
                            enter_fn,
                            leave_fn,
                        )
                        .map_err(|e| throw_err(&ctx, e))
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "hookSyscall",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      emu_id: usize,
                      nr: f64,
                      func: Function<'js>|
                      -> rquickjs::Result<usize> {
                    let persistent = Persistent::save(&ctx, func);
                    let key = if nr < 0.0 { SYSCALL_WILDCARD } else { nr as u64 };
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry
                        .native_hooks
                        .add_syscall_hook(emu_id, entry.emu.uc_mut(), key, persistent))
                },
            )?,
        )?;
    }

    {
        let host = Rc::clone(host);
        native.set(
            "hookDetach",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'_>, emu_id: usize, hook_id: usize| -> rquickjs::Result<bool> {
                    let mut h = host.borrow_mut();
                    let entry = h
                        .emus
                        .get_mut(emu_id)
                        .ok_or_else(|| throw_err(&ctx, "无效的 emuId"))?;
                    Ok(entry.native_hooks.detach(hook_id, entry.emu.uc_mut()))
                },
            )?,
        )?;
    }

    // ---- V2: 宿主机文件 I/O (fs) ----
    native.set(
        "fsReadBytes",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String| -> rquickjs::Result<TypedArray<'js, u8>> {
                let data = fs::read(&path)
                    .map_err(|e| throw_err(&ctx, format!("读取文件失败 {path}: {e}")))?;
                TypedArray::new(ctx.clone(), data)
            },
        )?,
    )?;

    native.set(
        "fsReadText",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'_>, path: String| -> rquickjs::Result<String> {
                fs::read_to_string(&path)
                    .map_err(|e| throw_err(&ctx, format!("读取文本失败 {path}: {e}")))
            },
        )?,
    )?;

    native.set(
        "fsWriteBytes",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, path: String, bytes: TypedArray<'js, u8>| -> rquickjs::Result<()> {
                let slice = bytes.as_bytes().unwrap_or(&[]);
                fs::write(&path, slice)
                    .map_err(|e| throw_err(&ctx, format!("写入文件失败 {path}: {e}")))
            },
        )?,
    )?;

    native.set(
        "fsWriteText",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'_>, path: String, text: String| -> rquickjs::Result<()> {
                fs::write(&path, text)
                    .map_err(|e| throw_err(&ctx, format!("写入文本失败 {path}: {e}")))
            },
        )?,
    )?;

    native.set(
        "fsExists",
        Function::new(ctx.clone(), move |path: String| -> bool {
            Path::new(&path).exists()
        })?,
    )?;

    // ---- V2: CommonJS require(specifier) ----
    {
        let host = Rc::clone(host);
        native.set(
            "requireModule",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, specifier: String| -> rquickjs::Result<Value<'js>> {
                    let base_dir = host
                        .borrow()
                        .script_dir_stack
                        .last()
                        .cloned()
                        .unwrap_or_else(|| PathBuf::from("."));
                    let raw_path = Path::new(&specifier);
                    let mut candidate = if raw_path.is_absolute() {
                        raw_path.to_path_buf()
                    } else {
                        base_dir.join(raw_path)
                    };
                    if !candidate.exists() && candidate.extension().is_none() {
                        let with_js = candidate.with_extension("js");
                        if with_js.exists() {
                            candidate = with_js;
                        }
                    }
                    let canonical = fs::canonicalize(&candidate).map_err(|e| {
                        throw_err(&ctx, format!("require(\"{specifier}\") 找不到模块: {e}"))
                    })?;

                    if let Some(cached) = host.borrow().module_cache.get(&canonical).cloned() {
                        return cached.restore(&ctx);
                    }

                    let src = fs::read_to_string(&canonical).map_err(|e| {
                        throw_err(
                            &ctx,
                            format!("读取模块失败 {}: {e}", canonical.display()),
                        )
                    })?;
                    let mod_dir = canonical
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| PathBuf::from("."));

                    let exports_obj = Object::new(ctx.clone())?;
                    let module_obj = Object::new(ctx.clone())?;
                    module_obj.set("exports", exports_obj.clone())?;
                    module_obj.set("filename", canonical.to_string_lossy().as_ref())?;

                    let wrapped = format!(
                        "(function(exports, require, module, __filename, __dirname) {{\n{src}\n}})"
                    );
                    let factory: Function<'js> = ctx.eval(wrapped)?;
                    let require_fn: Function<'js> = ctx.globals().get("require")?;

                    host.borrow_mut().script_dir_stack.push(mod_dir.clone());
                    let call_res = factory.call::<_, Value<'js>>((
                        exports_obj,
                        require_fn,
                        module_obj.clone(),
                        canonical.to_string_lossy().as_ref(),
                        mod_dir.to_string_lossy().as_ref(),
                    ));
                    host.borrow_mut().script_dir_stack.pop();
                    call_res?;

                    let final_exports: Value<'js> = module_obj.get("exports")?;
                    let persistent = Persistent::save(&ctx, final_exports.clone());
                    host.borrow_mut().module_cache.insert(canonical, persistent);
                    Ok(final_exports)
                },
            )?,
        )?;
    }

    globals.set("__native", native)?;
    Ok(())
}
