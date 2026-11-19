use std::collections::HashMap;

use anyhow::{ensure, Result};
use arm64_emu_tracer::jni::{JObject, JObjectRef, JValue, JniContext, JniHandler, MethodDesc};
use arm64_emu_tracer::memory::read_guest_cstr;
use arm64_emu_tracer::AndroidEmulator;

struct CronetJniHandler;

impl JniHandler for CronetJniHandler {
    fn call_static_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> JObjectRef {
        if class_name == "org/chromium/base/JNIUtils" && method.name == "getSplitClassLoader" {
            return ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/ClassLoader".to_string(),
                fields: HashMap::new(),
            });
        }
        if class_name == "internal/org/jni_zero/JniInit" && method.name == "init" {
            let empty_map = ctx.objects.add_local(JObject::Custom {
                class_name: "java/util/Collections$EmptyMap".to_string(),
                fields: HashMap::new(),
            });
            return ctx
                .objects
                .add_local(JObject::ObjectArray(vec![empty_map, JObjectRef::NULL]));
        }
        JObjectRef::NULL
    }
}

fn main() -> Result<()> {
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.cronetdemo")
        .jni_handler(Box::new(CronetJniHandler))
        .build()?;

    let module = emu.load_library("samples/libcronet.so")?;
    println!(
        "[+] 加载 Chromium 143 libcronet.so @ 0x{:016x} (size=0x{:x}, symbols={}, init_array={})",
        module.base_addr,
        module.image_size,
        module.symbols.len(),
        module.init_array.len()
    );

    // 1. JNI_OnLoad
    if let Some(ver) = emu.call_jni_onload(&module)? {
        println!(
            "[+] JNI_OnLoad 返回: 0x{ver:08x} (RegisterNatives={})",
            emu.jni().registered_natives.len()
        );
    }

    // 2. Cronet_Engine_Create & Cronet_Engine_GetVersionString
    let engine = emu.call_symbol(&module, "Cronet_Engine_Create", &[])?;
    println!("[+] Cronet_Engine_Create() => 0x{engine:016x}");
    ensure!(engine != 0, "Cronet_Engine_Create 返回 NULL");

    let ver_ptr = emu.call_symbol(&module, "Cronet_Engine_GetVersionString", &[engine])?;
    let ver = read_guest_cstr(emu.uc(), ver_ptr, 64);
    println!("[+] Cronet_Engine_GetVersionString() = \"{ver}\"");
    ensure!(ver.starts_with("143.0."), "预期 143.0.x，实际 {ver}");

    // 3. Cronet_EngineParams 读写闭环
    let params = emu.call_symbol(&module, "Cronet_EngineParams_Create", &[])?;
    ensure!(params != 0);
    let lang = "zh-CN,en-US;q=0.9\0";
    let lang_addr = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(lang.len() as u64)?;
    emu.uc_mut().mem_write(lang_addr, lang.as_bytes())?;
    emu.call_symbol(&module, "Cronet_EngineParams_accept_language_set", &[params, lang_addr])?;
    emu.call_symbol(&module, "Cronet_EngineParams_enable_brotli_set", &[params, 1])?;

    let got_lang_ptr = emu.call_symbol(&module, "Cronet_EngineParams_accept_language_get", &[params])?;
    let got_lang = read_guest_cstr(emu.uc(), got_lang_ptr, 128);
    let got_brotli = emu.call_symbol(&module, "Cronet_EngineParams_enable_brotli_get", &[params])?;
    println!("[+] EngineParams: accept_language=\"{got_lang}\", enable_brotli={got_brotli}");
    ensure!(got_lang == "zh-CN,en-US;q=0.9" && got_brotli == 1);
    emu.call_symbol(&module, "Cronet_EngineParams_Destroy", &[params])?;

    // 4. Cronet_Buffer 分配、写入、读取、销毁闭环
    let buf = emu.call_symbol(&module, "Cronet_Buffer_Create", &[])?;
    ensure!(buf != 0);
    emu.call_symbol(&module, "Cronet_Buffer_InitWithAlloc", &[buf, 4096])?;
    let buf_sz = emu.call_symbol(&module, "Cronet_Buffer_GetSize", &[buf])?;
    let buf_data = emu.call_symbol(&module, "Cronet_Buffer_GetData", &[buf])?;
    println!("[+] Cronet_Buffer: ptr=0x{buf_data:016x}, size={buf_sz}");
    ensure!(buf_sz == 4096 && buf_data != 0);
    emu.call_symbol(&module, "Cronet_Buffer_Destroy", &[buf])?;

    // 5. Cronet_Engine_Destroy
    emu.call_symbol(&module, "Cronet_Engine_Destroy", &[engine])?;
    println!("[SUCCESS] 官方 Chromium 143 libcronet.so (6.50 MB) 全链路验证通过!");
    Ok(())
}
