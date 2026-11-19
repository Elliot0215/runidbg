use std::collections::HashMap;
use std::path::Path;

use arm64_emu_tracer::jni::{JObject, JValue};
use arm64_emu_tracer::memory::read_guest_cstr;
use arm64_emu_tracer::AndroidEmulator;

#[test]
fn official_zstd_compress_decompress_roundtrip() {
    let so_path = Path::new("samples/libzstd-jni-1.5.7-28.so");
    if !so_path.exists() {
        return;
    }
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()
        .unwrap();
    let module = emu.load_library(so_path).unwrap();

    let ver_ptr = emu.call_symbol(&module, "ZSTD_versionString", &[]).unwrap();
    assert!(read_guest_cstr(emu.uc(), ver_ptr, 64).starts_with("1.5."));

    let payload = b"ARM64_EMU_TRACER_ZSTD_COMPAT_TEST_PAYLOAD_0123456789!@#$".repeat(300);
    let bound = emu
        .call_symbol(&module, "ZSTD_compressBound", &[payload.len() as u64])
        .unwrap();

    let src = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(payload.len() as u64)
        .unwrap();
    let dst = emu.uc_mut().get_data_mut().mem.alloc_heap(bound).unwrap();
    let out = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(payload.len() as u64)
        .unwrap();
    emu.uc_mut().mem_write(src, &payload).unwrap();

    let comp_sz = emu
        .call_symbol(
            &module,
            "ZSTD_compress",
            &[dst, bound, src, payload.len() as u64, 3],
        )
        .unwrap();
    assert!(comp_sz > 0 && comp_sz < payload.len() as u64);

    let decomp_sz = emu
        .call_symbol(
            &module,
            "ZSTD_decompress",
            &[out, payload.len() as u64, dst, comp_sz],
        )
        .unwrap();
    assert_eq!(decomp_sz, payload.len() as u64);

    let mut out_buf = vec![0u8; payload.len()];
    emu.uc().mem_read(out, &mut out_buf).unwrap();
    assert_eq!(out_buf, payload);
}

#[test]
fn official_sqlite3_file_db_sql_roundtrip() {
    let so_path = Path::new("samples/libsqliteJni.so");
    if !so_path.exists() {
        return;
    }
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()
        .unwrap();
    let module = emu.load_library(so_path).unwrap();

    let ver_ptr = emu.call_symbol(&module, "sqlite3_libversion", &[]).unwrap();
    assert!(read_guest_cstr(emu.uc(), ver_ptr, 64).starts_with("3."));

    let db_path = "/data/user/0/com.example.sdksuite/files/test.db\0";
    let path_addr = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(db_path.len() as u64)
        .unwrap();
    let db_ptr_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(8).unwrap();
    emu.uc_mut()
        .mem_write(path_addr, db_path.as_bytes())
        .unwrap();

    assert_eq!(
        emu.call_symbol(&module, "sqlite3_open", &[path_addr, db_ptr_addr])
            .unwrap() as i32,
        0
    );
    let mut db_bytes = [0u8; 8];
    emu.uc().mem_read(db_ptr_addr, &mut db_bytes).unwrap();
    let db = u64::from_le_bytes(db_bytes);
    assert_ne!(db, 0);

    let sql = "CREATE TABLE bench (id INTEGER PRIMARY KEY, sdk TEXT, score INT);\
               INSERT INTO bench VALUES (1,'mmkv',95),(2,'zstd',98),(3,'sqlite',99);\0";
    let sql_addr = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(sql.len() as u64)
        .unwrap();
    emu.uc_mut().mem_write(sql_addr, sql.as_bytes()).unwrap();
    assert_eq!(
        emu.call_symbol(&module, "sqlite3_exec", &[db, sql_addr, 0, 0, 0])
            .unwrap() as i32,
        0
    );

    let query = "SELECT COUNT(*), SUM(score), MAX(sdk) FROM bench;\0";
    let q_addr = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(query.len() as u64)
        .unwrap();
    let stmt_ptr_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(8).unwrap();
    emu.uc_mut().mem_write(q_addr, query.as_bytes()).unwrap();
    assert_eq!(
        emu.call_symbol(
            &module,
            "sqlite3_prepare_v2",
            &[db, q_addr, (-1i32) as u64, stmt_ptr_addr, 0],
        )
        .unwrap() as i32,
        0
    );

    let mut stmt_bytes = [0u8; 8];
    emu.uc().mem_read(stmt_ptr_addr, &mut stmt_bytes).unwrap();
    let stmt = u64::from_le_bytes(stmt_bytes);
    assert_eq!(
        emu.call_symbol(&module, "sqlite3_step", &[stmt]).unwrap() as i32,
        100
    );
    assert_eq!(
        emu.call_symbol(&module, "sqlite3_column_int", &[stmt, 0])
            .unwrap() as i32,
        3
    );
    assert_eq!(
        emu.call_symbol(&module, "sqlite3_column_int", &[stmt, 1])
            .unwrap() as i32,
        292
    );
    let max_sdk_ptr = emu
        .call_symbol(&module, "sqlite3_column_text", &[stmt, 2])
        .unwrap();
    assert_eq!(read_guest_cstr(emu.uc(), max_sdk_ptr, 64), "zstd");

    emu.call_symbol(&module, "sqlite3_finalize", &[stmt])
        .unwrap();
    emu.call_symbol(&module, "sqlite3_close", &[db]).unwrap();
}

#[test]
fn official_webp_lossless_rgba_decode() {
    let so_path = Path::new("samples/libstatic-webp.so");
    if !so_path.exists() {
        return;
    }
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()
        .unwrap();
    let module = emu.load_library(so_path).unwrap();

    assert_ne!(
        emu.call_symbol(&module, "WebPGetDecoderVersion", &[])
            .unwrap(),
        0
    );

    let webp_data: [u8; 52] = [
        82, 73, 70, 70, 44, 0, 0, 0, 87, 69, 66, 80, 86, 80, 56, 76, 31, 0, 0, 0, 47, 1, 64, 0, 0,
        31, 32, 16, 72, 218, 31, 122, 141, 249, 23, 16, 20, 249, 63, 218, 252, 7, 95, 36, 224, 7,
        8, 17, 253, 15, 1, 0,
    ];
    let data_addr = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(webp_data.len() as u64)
        .unwrap();
    let w_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(4).unwrap();
    let h_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(4).unwrap();
    emu.uc_mut().mem_write(data_addr, &webp_data).unwrap();

    assert_eq!(
        emu.call_symbol(
            &module,
            "WebPGetInfo",
            &[data_addr, webp_data.len() as u64, w_addr, h_addr],
        )
        .unwrap() as i32,
        1
    );
    let mut wb = [0u8; 4];
    let mut hb = [0u8; 4];
    emu.uc().mem_read(w_addr, &mut wb).unwrap();
    emu.uc().mem_read(h_addr, &mut hb).unwrap();
    assert_eq!((i32::from_le_bytes(wb), i32::from_le_bytes(hb)), (2, 2));

    let rgba_ptr = emu
        .call_symbol(
            &module,
            "WebPDecodeRGBA",
            &[data_addr, webp_data.len() as u64, w_addr, h_addr],
        )
        .unwrap();
    assert_ne!(rgba_ptr, 0);
    let mut rgba = [0u8; 16];
    emu.uc().mem_read(rgba_ptr, &mut rgba).unwrap();
    assert_eq!(
        rgba,
        [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 0, 255]
    );
    emu.call_symbol(&module, "WebPFree", &[rgba_ptr]).unwrap();
}

#[test]
fn official_conscrypt_boringssl_sha256_and_rand() {
    let so_path = Path::new("samples/libconscrypt_jni.so");
    if !so_path.exists() {
        return;
    }
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()
        .unwrap();
    let module = emu.load_library(so_path).unwrap();
    assert_eq!(emu.call_jni_onload(&module).unwrap(), Some(0x0001_0006));
    assert!(emu.jni().registered_natives.len() >= 300);

    const CLS: &str = "org/conscrypt/NativeCrypto";

    let rand_arr = emu.new_jbyte_array(vec![0u8; 16]);
    emu.call_registered_native(CLS, "RAND_bytes", &[rand_arr.0])
        .unwrap();
    let rand_bytes = match emu.jni().objects.get(rand_arr) {
        Some(JObject::ByteArray(b)) => b.clone(),
        _ => Vec::new(),
    };
    assert!(rand_bytes.iter().any(|&b| b != 0));

    let algo = emu.new_jstring("sha256");
    let evp_md = emu
        .call_registered_native(CLS, "EVP_get_digestbyname", &[algo.0])
        .unwrap();
    assert_ne!(evp_md, 0);

    let md_ctx_ptr = emu
        .call_registered_native(CLS, "EVP_MD_CTX_create", &[])
        .unwrap();
    assert_ne!(md_ctx_ptr, 0);

    let mut fields = HashMap::new();
    fields.insert("address".to_string(), JValue::Long(md_ctx_ptr as i64));
    let ctx_ref = emu.jni_mut().objects.add_local(JObject::Custom {
        class_name: "org/conscrypt/NativeRef$EVP_MD_CTX".to_string(),
        fields,
    });

    assert_eq!(
        emu.call_registered_native(CLS, "EVP_DigestInit_ex", &[ctx_ref.0, evp_md])
            .unwrap() as i32,
        1
    );
    let msg = b"hello arm64-emu-tracer";
    let msg_arr = emu.new_jbyte_array(msg.to_vec());
    emu.call_registered_native(
        CLS,
        "EVP_DigestUpdate",
        &[ctx_ref.0, msg_arr.0, 0, msg.len() as u64],
    )
    .unwrap();

    let out_arr = emu.new_jbyte_array(vec![0u8; 32]);
    assert_eq!(
        emu.call_registered_native(CLS, "EVP_DigestFinal_ex", &[ctx_ref.0, out_arr.0, 0])
            .unwrap() as i32,
        32
    );
    let digest_hex: String = match emu.jni().objects.get(out_arr) {
        Some(JObject::ByteArray(b)) => b.iter().map(|x| format!("{x:02x}")).collect(),
        _ => String::new(),
    };
    assert_eq!(
        digest_hex,
        "faa5350e1990f7a9ac3dc87e907de931f10b83c8e203ff053f54f0c62fcf7ac5"
    );
    emu.call_registered_native(CLS, "EVP_MD_CTX_destroy", &[md_ctx_ptr])
        .unwrap();
}

struct CronetTestJniHandler;

impl arm64_emu_tracer::jni::JniHandler for CronetTestJniHandler {
    fn call_static_object_method(
        &mut self,
        ctx: &mut arm64_emu_tracer::jni::JniContext<'_>,
        class_name: &str,
        method: &arm64_emu_tracer::jni::MethodDesc,
        _args: &[JValue],
    ) -> arm64_emu_tracer::jni::JObjectRef {
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
            return ctx.objects.add_local(JObject::ObjectArray(vec![
                empty_map,
                arm64_emu_tracer::jni::JObjectRef::NULL,
            ]));
        }
        arm64_emu_tracer::jni::JObjectRef::NULL
    }
}

#[test]
fn official_chromium_cronet_143_full_lifecycle() {
    let so_path = Path::new("samples/libcronet.so");
    if !so_path.exists() {
        return;
    }
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.cronetdemo")
        .jni_handler(Box::new(CronetTestJniHandler))
        .build()
        .unwrap();
    let module = emu.load_library(so_path).unwrap();
    assert_eq!(emu.call_jni_onload(&module).unwrap(), Some(0x0001_0006));
    assert!(emu.jni().registered_natives.len() >= 100);

    let engine = emu.call_symbol(&module, "Cronet_Engine_Create", &[]).unwrap();
    assert_ne!(engine, 0);
    let ver_ptr = emu
        .call_symbol(&module, "Cronet_Engine_GetVersionString", &[engine])
        .unwrap();
    assert!(read_guest_cstr(emu.uc(), ver_ptr, 64).starts_with("143.0."));

    let params = emu
        .call_symbol(&module, "Cronet_EngineParams_Create", &[])
        .unwrap();
    assert_ne!(params, 0);
    let lang = "zh-CN,en-US;q=0.9\0";
    let lang_addr = emu
        .uc_mut()
        .get_data_mut()
        .mem
        .alloc_heap(lang.len() as u64)
        .unwrap();
    emu.uc_mut().mem_write(lang_addr, lang.as_bytes()).unwrap();
    emu.call_symbol(
        &module,
        "Cronet_EngineParams_accept_language_set",
        &[params, lang_addr],
    )
    .unwrap();
    emu.call_symbol(
        &module,
        "Cronet_EngineParams_enable_brotli_set",
        &[params, 1],
    )
    .unwrap();
    let got_lang_ptr = emu
        .call_symbol(&module, "Cronet_EngineParams_accept_language_get", &[params])
        .unwrap();
    assert_eq!(
        read_guest_cstr(emu.uc(), got_lang_ptr, 128),
        "zh-CN,en-US;q=0.9"
    );
    assert_eq!(
        emu.call_symbol(&module, "Cronet_EngineParams_enable_brotli_get", &[params])
            .unwrap(),
        1
    );
    emu.call_symbol(&module, "Cronet_EngineParams_Destroy", &[params])
        .unwrap();

    let buf = emu.call_symbol(&module, "Cronet_Buffer_Create", &[]).unwrap();
    assert_ne!(buf, 0);
    emu.call_symbol(&module, "Cronet_Buffer_InitWithAlloc", &[buf, 4096])
        .unwrap();
    assert_eq!(
        emu.call_symbol(&module, "Cronet_Buffer_GetSize", &[buf])
            .unwrap(),
        4096
    );
    assert_ne!(
        emu.call_symbol(&module, "Cronet_Buffer_GetData", &[buf])
            .unwrap(),
        0
    );
    emu.call_symbol(&module, "Cronet_Buffer_Destroy", &[buf])
        .unwrap();
    emu.call_symbol(&module, "Cronet_Engine_Destroy", &[engine])
        .unwrap();
}
