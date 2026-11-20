use anyhow::{ensure, Result};
use runidbg_arm64_emu_tracer::jni::{JObject, JObjectRef, JValue, JniContext, JniHandler, MethodDesc};
use runidbg_arm64_emu_tracer::AndroidEmulator;

/// 捕获 MMKV 内部日志回调 `MMKV.mmkvLogImp`
struct MmkvJniHandler;

impl JniHandler for MmkvJniHandler {
    fn call_static_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        if class_name == "com/tencent/mmkv/MMKV" && method.name == "mmkvLogImp" {
            let level = match args.first() {
                Some(JValue::Int(v)) => *v,
                _ => 0,
            };
            let file = args
                .get(1)
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("");
            let line = match args.get(2) {
                Some(JValue::Int(v)) => *v,
                _ => 0,
            };
            let func = args
                .get(3)
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("");
            let msg = args
                .get(4)
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("");
            println!("    [MMKV Log L{level}] {file}:{line} <{func}> {msg}");
        }
    }
}

fn main() -> Result<()> {
    let mut emu = AndroidEmulator::builder()
        .package_name("com.tencent.mmkvdemo")
        .jni_handler(Box::new(MmkvJniHandler))
        .build()?;

    let module = emu.load_library("samples/libmmkv.so")?;
    println!(
        "[+] 成功加载官方 libmmkv.so @ 0x{:016x} (size=0x{:x}, symbols={}, init_array={})",
        module.base_addr,
        module.image_size,
        module.symbols.len(),
        module.init_array.len()
    );

    let jni_ver = emu.call_jni_onload(&module)?.unwrap_or(0);
    println!(
        "[+] JNI_OnLoad 返回: 0x{jni_ver:08x} (RegisterNatives={})",
        emu.jni().registered_natives.len()
    );
    ensure!(jni_ver == 0x0001_0006, "JNI_OnLoad 版本号异常");

    const CLS: &str = "com/tencent/mmkv/MMKV";

    // 1. MMKV.version()
    let ver_ref = JObjectRef(emu.call_registered_native(CLS, "version", &[])?);
    let ver_str = emu.read_jstring(ver_ref).unwrap_or("").to_string();
    println!("[+] MMKV.version() = \"{ver_str}\"");
    ensure!(ver_str == "v1.3.9", "预期 v1.3.9，实际 {ver_str}");

    // 2. MMKV.jniInitialize(rootDir, cacheDir, logLevel=2, logReDirecting=false)
    let root_dir = emu.new_jstring("/data/user/0/com.tencent.mmkvdemo/files/mmkv");
    let cache_dir = emu.new_jstring("/data/user/0/com.tencent.mmkvdemo/cache");
    emu.call_registered_native(CLS, "jniInitialize", &[root_dir.0, cache_dir.0, 2, 0])?;
    let page_sz = emu.call_registered_native(CLS, "pageSize", &[])? as i32;
    println!("[+] MMKV.jniInitialize() 完成, pageSize() = {page_sz}");
    ensure!(page_sz == 4096, "预期 pageSize=4096，实际 {page_sz}");

    // 3. MMKV.getDefaultMMKV(SINGLE_PROCESS_MODE=1, cryptKey="my_aes_128_key!!")
    let crypt_key = emu.new_jstring("my_aes_128_key!!");
    let handle = emu.call_registered_native(CLS, "getDefaultMMKV", &[1, crypt_key.0])?;
    println!("[+] MMKV.getDefaultMMKV(AES-CFB) => nativeHandle = 0x{handle:016x}");
    ensure!(handle != 0, "getDefaultMMKV 返回空句柄");

    // 4. encodeString / decodeString
    let k_str = emu.new_jstring("greeting");
    let v_str = emu.new_jstring("Hello from Rust ARM64 Emulator!");
    let ok = emu.call_registered_native(CLS, "encodeString", &[handle, k_str.0, v_str.0])?;
    ensure!(ok != 0, "encodeString 失败");

    let fallback = emu.new_jstring("fallback");
    let decoded_ref = JObjectRef(emu.call_registered_native(
        CLS,
        "decodeString",
        &[handle, k_str.0, fallback.0],
    )?);
    let decoded_str = emu.read_jstring(decoded_ref).unwrap_or("").to_string();
    println!("[+] encodeString/decodeString 闭环: \"{decoded_str}\"");
    ensure!(decoded_str == "Hello from Rust ARM64 Emulator!");

    // 5. encodeInt / decodeInt
    let k_int = emu.new_jstring("answer");
    let ok = emu.call_registered_native(CLS, "encodeInt", &[handle, k_int.0, 42])?;
    ensure!(ok != 0, "encodeInt 失败");
    let decoded_int =
        emu.call_registered_native(CLS, "decodeInt", &[handle, k_int.0, (-1i32) as u64])? as i32;
    println!("[+] encodeInt/decodeInt 闭环: {decoded_int}");
    ensure!(decoded_int == 42);

    // 6. encodeBytes / decodeBytes
    let k_bytes = emu.new_jstring("raw_bin");
    let expected_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0xAA, 0x55];
    let v_bytes = emu.new_jbyte_array(expected_bytes.clone());
    let ok = emu.call_registered_native(CLS, "encodeBytes", &[handle, k_bytes.0, v_bytes.0])?;
    ensure!(ok != 0, "encodeBytes 失败");
    let decoded_bytes_ref = JObjectRef(emu.call_registered_native(
        CLS,
        "decodeBytes",
        &[handle, k_bytes.0],
    )?);
    let decoded_bytes = match emu.jni().objects.get(decoded_bytes_ref) {
        Some(JObject::ByteArray(b)) => b.clone(),
        _ => Vec::new(),
    };
    println!("[+] encodeBytes/decodeBytes 闭环: {:02x?}", decoded_bytes);
    ensure!(decoded_bytes == expected_bytes);

    // 7. 超 4KB 大值写入，强制触发 MMKV 扩容（munmap -> ftruncate(8192) -> mmap -> AES-CFB 重加密 -> crc32）
    let k_big = emu.new_jstring("large_payload");
    let big_val = "ARM64_MMKV_STRESS_".repeat(300); // 5400 bytes > 1 page (4096)
    let v_big = emu.new_jstring(big_val.clone());
    let ok = emu.call_registered_native(CLS, "encodeString", &[handle, k_big.0, v_big.0])?;
    ensure!(ok != 0, "大值 encodeString 失败");
    let big_decoded_ref = JObjectRef(emu.call_registered_native(
        CLS,
        "decodeString",
        &[handle, k_big.0, fallback.0],
    )?);
    let big_decoded = emu.read_jstring(big_decoded_ref).unwrap_or("").to_string();
    println!(
        "[+] 超 4KB 扩容读写闭环: len={} bytes (match={})",
        big_decoded.len(),
        big_decoded == big_val
    );
    ensure!(big_decoded == big_val);

    // 8. count & actualSize
    let count = emu.call_registered_native(CLS, "count", &[handle, 0])?;
    let actual_size = emu.call_registered_native(CLS, "actualSize", &[handle])?;
    println!("[+] MMKV.count() = {count}, actualSize() = {actual_size} bytes");
    ensure!(count == 4, "预期 count=4，实际 {count}");

    println!("[SUCCESS] 官方 Tencent libmmkv.so (v1.3.9, arm64-v8a) 全链路 AES 加密与扩容闭环验证通过!");
    Ok(())
}
