use anyhow::{ensure, Result};
use runidbg_arm64_emu_tracer::memory::read_guest_cstr;
use runidbg_arm64_emu_tracer::AndroidEmulator;

fn test_zstd() -> Result<()> {
    println!("\n=== [1/4] Zstandard (libzstd-jni-1.5.7-28.so) ===");
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()?;
    let module = emu.load_library("samples/libzstd-jni-1.5.7-28.so")?;

    let ver_ptr = emu.call_symbol(&module, "ZSTD_versionString", &[])?;
    let ver = read_guest_cstr(emu.uc(), ver_ptr, 64);
    println!("[+] ZSTD_versionString() = \"{ver}\"");
    ensure!(ver.starts_with("1.5."), "预期 1.5.x，实际 {ver}");

    let payload: Vec<u8> = b"ARM64_EMU_TRACER_ZSTD_COMPAT_TEST_PAYLOAD_0123456789!@#$"
        .repeat(300); // 16,800 bytes
    let bound = emu.call_symbol(&module, "ZSTD_compressBound", &[payload.len() as u64])?;

    let src_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(payload.len() as u64)?;
    let dst_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(bound)?;
    let out_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(payload.len() as u64)?;
    emu.uc_mut().mem_write(src_addr, &payload)?;

    let comp_sz = emu.call_symbol(
        &module,
        "ZSTD_compress",
        &[dst_addr, bound, src_addr, payload.len() as u64, 3],
    )?;
    println!(
        "[+] ZSTD_compress({}B -> {}B, ratio={:.1}%)",
        payload.len(),
        comp_sz,
        (comp_sz as f64 / payload.len() as f64) * 100.0
    );
    ensure!(comp_sz > 0 && comp_sz < payload.len() as u64);

    let decomp_sz = emu.call_symbol(
        &module,
        "ZSTD_decompress",
        &[out_addr, payload.len() as u64, dst_addr, comp_sz],
    )?;
    ensure!(decomp_sz == payload.len() as u64);

    let mut out_buf = vec![0u8; payload.len()];
    emu.uc().mem_read(out_addr, &mut out_buf)?;
    ensure!(out_buf == payload, "ZSTD 解压字节不匹配");
    println!("[PASS] libzstd-jni 16.8KB 压缩/解压逐字节一致!");
    Ok(())
}

fn test_sqlite() -> Result<()> {
    println!("\n=== [2/4] AndroidX SQLite3 (libsqliteJni.so) ===");
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()?;
    let module = emu.load_library("samples/libsqliteJni.so")?;

    let ver_ptr = emu.call_symbol(&module, "sqlite3_libversion", &[])?;
    let ver = read_guest_cstr(emu.uc(), ver_ptr, 64);
    println!("[+] sqlite3_libversion() = \"{ver}\"");
    ensure!(ver.starts_with("3."), "预期 SQLite 3.x，实际 {ver}");

    let db_path = "/data/user/0/com.example.sdksuite/files/test.db\0";
    let path_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(db_path.len() as u64)?;
    let db_ptr_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(8)?;
    emu.uc_mut().mem_write(path_addr, db_path.as_bytes())?;

    let rc = emu.call_symbol(&module, "sqlite3_open", &[path_addr, db_ptr_addr])? as i32;
    let mut db_bytes = [0u8; 8];
    emu.uc().mem_read(db_ptr_addr, &mut db_bytes)?;
    let db = u64::from_le_bytes(db_bytes);
    println!("[+] sqlite3_open(test.db) rc={rc}, db=0x{db:016x}");
    ensure!(rc == 0 && db != 0, "sqlite3_open 失败: rc={rc}");

    let sql = "CREATE TABLE bench (id INTEGER PRIMARY KEY, sdk TEXT, score INT);\
               INSERT INTO bench VALUES (1,'mmkv',95),(2,'zstd',98),(3,'sqlite',99);\0";
    let sql_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(sql.len() as u64)?;
    emu.uc_mut().mem_write(sql_addr, sql.as_bytes())?;
    let rc = emu.call_symbol(&module, "sqlite3_exec", &[db, sql_addr, 0, 0, 0])? as i32;
    println!("[+] sqlite3_exec(CREATE + INSERT) rc={rc}");
    ensure!(rc == 0, "sqlite3_exec 失败: rc={rc}");

    let query = "SELECT COUNT(*), SUM(score), MAX(sdk) FROM bench;\0";
    let q_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(query.len() as u64)?;
    let stmt_ptr_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(8)?;
    emu.uc_mut().mem_write(q_addr, query.as_bytes())?;
    let rc = emu.call_symbol(
        &module,
        "sqlite3_prepare_v2",
        &[db, q_addr, (-1i32) as u64, stmt_ptr_addr, 0],
    )? as i32;
    ensure!(rc == 0, "sqlite3_prepare_v2 失败: rc={rc}");

    let mut stmt_bytes = [0u8; 8];
    emu.uc().mem_read(stmt_ptr_addr, &mut stmt_bytes)?;
    let stmt = u64::from_le_bytes(stmt_bytes);

    let step_rc = emu.call_symbol(&module, "sqlite3_step", &[stmt])? as i32;
    ensure!(step_rc == 100, "预期 SQLITE_ROW(100)，实际 {step_rc}");

    let count = emu.call_symbol(&module, "sqlite3_column_int", &[stmt, 0])? as i32;
    let total = emu.call_symbol(&module, "sqlite3_column_int", &[stmt, 1])? as i32;
    let max_sdk_ptr = emu.call_symbol(&module, "sqlite3_column_text", &[stmt, 2])?;
    let max_sdk = read_guest_cstr(emu.uc(), max_sdk_ptr, 64);
    println!("[+] SELECT COUNT(*)={count}, SUM(score)={total}, MAX(sdk)=\"{max_sdk}\"");
    ensure!(count == 3 && total == 292 && max_sdk == "zstd");

    emu.call_symbol(&module, "sqlite3_finalize", &[stmt])?;
    emu.call_symbol(&module, "sqlite3_close", &[db])?;
    println!("[PASS] libsqliteJni 文件库建表/写入/聚合查询闭环通过!");
    Ok(())
}

fn test_webp() -> Result<()> {
    println!("\n=== [3/4] Meta/Google WebP (libstatic-webp.so) ===");
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()?;
    let module = emu.load_library("samples/libstatic-webp.so")?;

    let ver = emu.call_symbol(&module, "WebPGetDecoderVersion", &[])? as u32;
    println!("[+] WebPGetDecoderVersion() = 0x{ver:06x}");
    ensure!(ver != 0);

    // 2x2 无损 VP8L WebP: Red(255,0,0,255), Green(0,255,0,255), Blue(0,0,255,255), Yellow(255,255,0,255)
    let webp_data: [u8; 52] = [
        82, 73, 70, 70, 44, 0, 0, 0, 87, 69, 66, 80, 86, 80, 56, 76, 31, 0, 0, 0, 47, 1, 64, 0, 0,
        31, 32, 16, 72, 218, 31, 122, 141, 249, 23, 16, 20, 249, 63, 218, 252, 7, 95, 36, 224, 7,
        8, 17, 253, 15, 1, 0,
    ];
    let data_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(webp_data.len() as u64)?;
    let w_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(4)?;
    let h_addr = emu.uc_mut().get_data_mut().mem.alloc_heap(4)?;
    emu.uc_mut().mem_write(data_addr, &webp_data)?;

    let ok = emu.call_symbol(
        &module,
        "WebPGetInfo",
        &[data_addr, webp_data.len() as u64, w_addr, h_addr],
    )? as i32;
    let mut wb = [0u8; 4];
    let mut hb = [0u8; 4];
    emu.uc().mem_read(w_addr, &mut wb)?;
    emu.uc().mem_read(h_addr, &mut hb)?;
    let w = i32::from_le_bytes(wb);
    let h = i32::from_le_bytes(hb);
    println!("[+] WebPGetInfo() ok={ok}, width={w}, height={h}");
    ensure!(ok == 1 && w == 2 && h == 2);

    let rgba_ptr = emu.call_symbol(
        &module,
        "WebPDecodeRGBA",
        &[data_addr, webp_data.len() as u64, w_addr, h_addr],
    )?;
    ensure!(rgba_ptr != 0, "WebPDecodeRGBA 返回 NULL");
    let mut rgba = [0u8; 16];
    emu.uc().mem_read(rgba_ptr, &mut rgba)?;
    let expected: [u8; 16] = [
        255, 0, 0, 255, // Red
        0, 255, 0, 255, // Green
        0, 0, 255, 255, // Blue
        255, 255, 0, 255, // Yellow
    ];
    println!("[+] WebPDecodeRGBA() = {:?}", rgba);
    ensure!(rgba == expected, "RGBA 像素解码不匹配");
    emu.call_symbol(&module, "WebPFree", &[rgba_ptr])?;
    println!("[PASS] libstatic-webp 2x2 无损 VP8L RGBA 解码逐像素一致!");
    Ok(())
}

fn test_conscrypt() -> Result<()> {
    println!("\n=== [4/4] Google Conscrypt / BoringSSL (libconscrypt_jni.so) ===");
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.sdksuite")
        .build()?;
    let module = emu.load_library("samples/libconscrypt_jni.so")?;
    println!(
        "[+] 加载 libconscrypt_jni.so @ 0x{:016x} (size=0x{:x}, init_array={})",
        module.base_addr,
        module.image_size,
        module.init_array.len()
    );

    let jni_ver = emu.call_jni_onload(&module)?.unwrap_or(0);
    println!(
        "[+] JNI_OnLoad 返回: 0x{jni_ver:08x} (RegisterNatives={})",
        emu.jni().registered_natives.len()
    );
    ensure!(jni_ver == 0x0001_0006);

    const CLS: &str = "org/conscrypt/NativeCrypto";

    // 1. BoringSSL RAND_bytes(byte[16])
    let rand_arr = emu.new_jbyte_array(vec![0u8; 16]);
    emu.call_registered_native(CLS, "RAND_bytes", &[rand_arr.0])?;
    let rand_bytes = match emu.jni().objects.get(rand_arr) {
        Some(runidbg_arm64_emu_tracer::jni::JObject::ByteArray(b)) => b.clone(),
        _ => Vec::new(),
    };
    println!("[+] BoringSSL RAND_bytes(16) = {:02x?}", rand_bytes);
    ensure!(rand_bytes.iter().any(|&b| b != 0), "RAND_bytes 全为 0");

    // 2. BoringSSL EVP SHA-256("hello arm64-emu-tracer")
    let algo = emu.new_jstring("sha256");
    let evp_md = emu.call_registered_native(CLS, "EVP_get_digestbyname", &[algo.0])?;
    ensure!(evp_md != 0, "EVP_get_digestbyname(sha256) 返回 0");

    let md_ctx_ptr = emu.call_registered_native(CLS, "EVP_MD_CTX_create", &[])?;
    ensure!(md_ctx_ptr != 0, "EVP_MD_CTX_create 返回 0");

    let mut fields = std::collections::HashMap::new();
    fields.insert(
        "address".to_string(),
        runidbg_arm64_emu_tracer::jni::JValue::Long(md_ctx_ptr as i64),
    );
    let ctx_ref = emu.jni_mut().objects.add_local(
        runidbg_arm64_emu_tracer::jni::JObject::Custom {
            class_name: "org/conscrypt/NativeRef$EVP_MD_CTX".to_string(),
            fields,
        },
    );

    let init_ok = emu.call_registered_native(CLS, "EVP_DigestInit_ex", &[ctx_ref.0, evp_md])? as i32;
    ensure!(init_ok == 1, "EVP_DigestInit_ex 失败: {init_ok}");

    let msg = b"hello arm64-emu-tracer";
    let msg_arr = emu.new_jbyte_array(msg.to_vec());
    emu.call_registered_native(
        CLS,
        "EVP_DigestUpdate",
        &[ctx_ref.0, msg_arr.0, 0, msg.len() as u64],
    )?;

    let out_arr = emu.new_jbyte_array(vec![0u8; 32]);
    let digest_len =
        emu.call_registered_native(CLS, "EVP_DigestFinal_ex", &[ctx_ref.0, out_arr.0, 0])? as i32;
    ensure!(digest_len == 32, "预期 SHA-256 长度 32，实际 {digest_len}");

    let digest_hex: String = match emu.jni().objects.get(out_arr) {
        Some(runidbg_arm64_emu_tracer::jni::JObject::ByteArray(b)) => {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        _ => String::new(),
    };
    println!("[+] BoringSSL SHA-256 = {digest_hex}");
    ensure!(
        digest_hex == "faa5350e1990f7a9ac3dc87e907de931f10b83c8e203ff053f54f0c62fcf7ac5",
        "SHA-256 不匹配"
    );

    emu.call_registered_native(CLS, "EVP_MD_CTX_destroy", &[md_ctx_ptr])?;
    println!("[PASS] libconscrypt_jni (BoringSSL) RAND_bytes + EVP SHA-256 逐字节一致!");
    Ok(())
}

fn main() -> Result<()> {
    test_zstd()?;
    test_sqlite()?;
    test_webp()?;
    test_conscrypt()?;
    Ok(())
}
