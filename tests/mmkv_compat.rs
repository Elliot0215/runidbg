use std::path::Path;

use arm64_emu_tracer::jni::{JObject, JObjectRef};
use arm64_emu_tracer::AndroidEmulator;

#[test]
fn official_libmmkv_aes_and_resize_roundtrip() {
    let so_path = Path::new("samples/libmmkv.so");
    if !so_path.exists() {
        return;
    }

    let mut emu = AndroidEmulator::builder()
        .package_name("com.tencent.mmkvdemo")
        .build()
        .expect("build emulator");

    let module = emu.load_library(so_path).expect("load libmmkv.so");
    let jni_ver = emu
        .call_jni_onload(&module)
        .expect("call JNI_OnLoad")
        .expect("JNI_OnLoad symbol");
    assert_eq!(jni_ver, 0x0001_0006);
    assert_eq!(emu.jni().registered_natives.len(), 76);

    const CLS: &str = "com/tencent/mmkv/MMKV";

    let ver_ref = JObjectRef(emu.call_registered_native(CLS, "version", &[]).unwrap());
    assert_eq!(emu.read_jstring(ver_ref), Some("v1.3.9"));

    let root_dir = emu.new_jstring("/data/user/0/com.tencent.mmkvdemo/files/mmkv");
    let cache_dir = emu.new_jstring("/data/user/0/com.tencent.mmkvdemo/cache");
    emu.call_registered_native(CLS, "jniInitialize", &[root_dir.0, cache_dir.0, 2, 0])
        .unwrap();
    assert_eq!(
        emu.call_registered_native(CLS, "pageSize", &[]).unwrap() as i32,
        4096
    );

    let crypt_key = emu.new_jstring("my_aes_128_key!!");
    let handle = emu
        .call_registered_native(CLS, "getDefaultMMKV", &[1, crypt_key.0])
        .unwrap();
    assert_ne!(handle, 0);

    // String round-trip
    let k_str = emu.new_jstring("greeting");
    let v_str = emu.new_jstring("Hello from Rust ARM64 Emulator!");
    let fallback = emu.new_jstring("fallback");
    assert_ne!(
        emu.call_registered_native(CLS, "encodeString", &[handle, k_str.0, v_str.0])
            .unwrap(),
        0
    );
    let dec_str = JObjectRef(
        emu.call_registered_native(CLS, "decodeString", &[handle, k_str.0, fallback.0])
            .unwrap(),
    );
    assert_eq!(
        emu.read_jstring(dec_str),
        Some("Hello from Rust ARM64 Emulator!")
    );

    // Int round-trip
    let k_int = emu.new_jstring("answer");
    assert_ne!(
        emu.call_registered_native(CLS, "encodeInt", &[handle, k_int.0, 42])
            .unwrap(),
        0
    );
    assert_eq!(
        emu.call_registered_native(CLS, "decodeInt", &[handle, k_int.0, (-1i32) as u64])
            .unwrap() as i32,
        42
    );

    // ByteArray round-trip (exercises GetPrimitiveArrayCritical / ReleasePrimitiveArrayCritical)
    let k_bytes = emu.new_jstring("raw_bin");
    let expected = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0xAA, 0x55];
    let v_bytes = emu.new_jbyte_array(expected.clone());
    assert_ne!(
        emu.call_registered_native(CLS, "encodeBytes", &[handle, k_bytes.0, v_bytes.0])
            .unwrap(),
        0
    );
    let dec_bytes_ref = JObjectRef(
        emu.call_registered_native(CLS, "decodeBytes", &[handle, k_bytes.0])
            .unwrap(),
    );
    assert!(matches!(
        emu.jni().objects.get(dec_bytes_ref),
        Some(JObject::ByteArray(b)) if b == &expected
    ));

    // >4KB payload (exercises munmap -> ftruncate -> mmap resize + AES-CFB + crc32)
    let k_big = emu.new_jstring("large_payload");
    let big_val = "ARM64_MMKV_STRESS_".repeat(300);
    let v_big = emu.new_jstring(big_val.clone());
    assert_ne!(
        emu.call_registered_native(CLS, "encodeString", &[handle, k_big.0, v_big.0])
            .unwrap(),
        0
    );
    let dec_big = JObjectRef(
        emu.call_registered_native(CLS, "decodeString", &[handle, k_big.0, fallback.0])
            .unwrap(),
    );
    assert_eq!(emu.read_jstring(dec_big), Some(big_val.as_str()));

    assert_eq!(
        emu.call_registered_native(CLS, "count", &[handle, 0])
            .unwrap(),
        4
    );
}
