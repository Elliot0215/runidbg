use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use anyhow::{bail, Result};
use arm64_emu_tracer::jni::{JObject, JObjectRef, JValue, JniContext, JniHandler, MethodDesc};
use arm64_emu_tracer::AndroidEmulator;

struct ProbeJniHandler;

impl JniHandler for ProbeJniHandler {
    fn call_static_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        _args: &[JValue],
    ) -> JObjectRef {
        if method.name == "getSplitClassLoader" {
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
        if method.sig.ends_with("Ljava/lang/String;") {
            return ctx.objects.add_local(JObject::String(String::new()));
        }
        JObjectRef::NULL
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        bail!("usage: probe_so <sysroot_dir> <so_path>");
    }
    let sysroot = PathBuf::from(&args[1]);
    let so_path = PathBuf::from(&args[2]);

    let mut emu = AndroidEmulator::builder()
        .package_name("com.ss.android.ugc.aweme")
        .add_search_path(&sysroot)
        .jni_handler(Box::new(ProbeJniHandler))
        .build()?;

    let module = match emu.load_library(&so_path) {
        Ok(m) => m,
        Err(e) => {
            println!("FAIL|load|{e}");
            std::process::exit(2);
        }
    };
    let dep_count = emu.linker().load_order().len();
    let has_jni = module.symbols.contains_key("JNI_OnLoad");

    if has_jni {
        match emu.call_jni_onload(&module) {
            Ok(Some(ver)) => {
                let reg = emu.jni().registered_natives.len();
                println!("PASS|deps={dep_count}|jni=0x{ver:x}|reg={reg}");
            }
            Ok(None) => {
                println!("PASS|deps={dep_count}|jni=none|reg=0");
            }
            Err(e) => {
                let pc = emu.uc().reg_read(unicorn_engine::RegisterARM64::PC).unwrap_or(0);
                let lr = emu.uc().reg_read(unicorn_engine::RegisterARM64::LR).unwrap_or(0);
                let x0 = emu.uc().reg_read(unicorn_engine::RegisterARM64::X0).unwrap_or(0);
                eprintln!("[DIAG] PC=0x{pc:016x} LR=0x{lr:016x} X0=0x{x0:016x} base=0x{:016x}", module.base_addr);
                println!("FAIL|jni_onload|{e}");
                std::process::exit(3);
            }
        }
    } else {
        println!("PASS|deps={dep_count}|jni=no_symbol|reg=0");
    }
    Ok(())
}
