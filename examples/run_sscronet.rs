use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, ensure, Result};
use arm64_emu_tracer::jni::{JObject, JObjectRef, JValue, JniContext, JniHandler, MethodDesc};
use arm64_emu_tracer::memory::read_guest_cstr;
use arm64_emu_tracer::AndroidEmulator;

struct SsCronetJniHandler;

impl JniHandler for SsCronetJniHandler {
    fn call_static_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> JObjectRef {
        if (class_name == "org/chromium/base/JNIUtils"
            || class_name == "com/ttnet/org/chromium/base/JNIUtils")
            && method.name == "getSplitClassLoader"
        {
            return ctx.objects.add_local(JObject::Custom {
                class_name: "java/lang/ClassLoader".to_string(),
                fields: HashMap::new(),
            });
        }
        if class_name == "com/ttnet/org/chromium/net/impl/CronetLibraryLoader"
            && method.name == "getDefaultUserAgent"
        {
            return ctx.objects.add_local(JObject::String(
                "TTNet/107.0.5273.2 (Linux; Android 13; Pixel 7)".to_string(),
            ));
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
        println!(
            "[JNI static obj] {class_name}.{}{}",
            method.name, method.sig
        );
        JObjectRef::NULL
    }

    fn call_static_void_method(
        &mut self,
        _ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) {
        if class_name == "com/ttnet/org/chromium/net/impl/CronetLibraryLoader"
            && method.name == "ensureInitializedFromNative"
        {
            return;
        }
        println!(
            "[JNI static void] {class_name}.{}{}",
            method.name, method.sig
        );
    }
}

fn main() -> Result<()> {
    let sysroot = Path::new("/tmp/sscronet_sysroot");
    let so_path = sysroot.join("libsscronet.so");
    if !so_path.exists() {
        bail!("未找到 {}, 请先准备 libsscronet.so 及其依赖", so_path.display());
    }

    let mut emu = AndroidEmulator::builder()
        .package_name("com.ss.android.ugc.aweme")
        .add_search_path(sysroot)
        .jni_handler(Box::new(SsCronetJniHandler))
        .build()?;

    let module = emu.load_library(&so_path)?;
    println!(
        "[+] 加载 libsscronet.so @ 0x{:016x} (size=0x{:x}, symbols={}, init_array={})",
        module.base_addr,
        module.image_size,
        module.symbols.len(),
        module.init_array.len()
    );
    println!("[+] 已加载模块链 (拓扑顺序): {:?}", emu.linker().load_order());

    // 1. JNI_OnLoad
    if let Some(ver) = emu.call_jni_onload(&module)? {
        println!(
            "[+] JNI_OnLoad 返回: 0x{ver:08x} (RegisterNatives={})",
            emu.jni().registered_natives.len()
        );
        for (i, reg) in emu.jni().registered_natives.iter().take(10).enumerate() {
            println!("    [{i}] {}.{}{}", reg.class_name, reg.name, reg.sig);
        }
    }

    // 2. Cronet_Engine_Create / GetVersionString / GetDefaultUserAgent
    let engine = emu.call_symbol(&module, "Cronet_Engine_Create", &[])?;
    println!("[+] Cronet_Engine_Create() => 0x{engine:016x}");
    ensure!(engine != 0, "Cronet_Engine_Create 返回 NULL");

    let ver_ptr = emu.call_symbol(&module, "Cronet_Engine_GetVersionString", &[engine])?;
    let ver = read_guest_cstr(emu.uc(), ver_ptr, 128);
    println!("[+] Cronet_Engine_GetVersionString() = \"{ver}\"");
    ensure!(!ver.is_empty(), "version string 为空");

    let ua_ptr = emu.call_symbol(&module, "Cronet_Engine_GetDefaultUserAgent", &[engine])?;
    let ua = read_guest_cstr(emu.uc(), ua_ptr, 256);
    println!("[+] Cronet_Engine_GetDefaultUserAgent() = \"{ua}\"");

    // 3. Cronet_AuthCredentials 读写闭环
    let creds = emu.call_symbol(&module, "Cronet_AuthCredentials_Create", &[])?;
    ensure!(creds != 0, "Cronet_AuthCredentials_Create 返回 NULL");
    let user = "ttnet_tester\0";
    let user_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(user.len() as u64)?;
    emu.uc_mut().mem_write(user_addr, user.as_bytes())?;
    emu.call_symbol(
        &module,
        "Cronet_AuthCredentials_username_set",
        &[creds, user_addr],
    )?;
    let got_user_ptr = emu.call_symbol(&module, "Cronet_AuthCredentials_username_get", &[creds])?;
    let got_user = read_guest_cstr(emu.uc(), got_user_ptr, 128);
    println!("[+] Cronet_AuthCredentials.username = \"{got_user}\"");
    ensure!(got_user == "ttnet_tester");
    emu.call_symbol(&module, "Cronet_AuthCredentials_Destroy", &[creds])?;

    // 4. Cronet_Engine_Destroy
    emu.call_symbol(&module, "Cronet_Engine_Destroy", &[engine])?;
    println!("[SUCCESS] 字节跳动 libsscronet.so 全链路验证通过!");
    Ok(())
}
