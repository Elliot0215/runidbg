use std::time::Instant;

use anyhow::Result;
use arm64_emu_tracer::jni::{JObject, JObjectRef};
use arm64_emu_tracer::tracer::{BinaryTracer, TraceLevel};
use arm64_emu_tracer::AndroidEmulator;

fn main() -> Result<()> {
    let so_path = "samples/libcrypto_sign.so";
    let pkg_name = "com.demo.android.app";
    let payload = "device_id=8848&ts=1732000000&nonce=xyz";
    let salt = b"s3cr3t_s4lt!";

    // 1. 构建 Android ARM64 模拟器（开启双流 Full Trace 落盘到 /tmp/crypto_sign.{idx,ext}）
    let mut emu = AndroidEmulator::builder()
        .package_name(pkg_name)
        .build()?;

    let module = emu.load_library(so_path)?;
    println!(
        "[+] 加载真实 clang AArch64 ELF: {} @ 0x{:016x} (size=0x{:x}, init_array={})",
        module.name,
        module.base_addr,
        module.image_size,
        module.init_array.len()
    );

    // 2. 引导执行 JNI_OnLoad（动态注册 com/demo/CryptoSigner.sign）
    let jni_ver = emu.call_jni_onload(&module)?.expect("应导出 JNI_OnLoad");
    println!("[+] JNI_OnLoad 返回 0x{jni_ver:08x}");
    for reg in &emu.jni().registered_natives {
        println!(
            "    [RegisterNatives] {}.{}{}=> 0x{:016x}",
            reg.class_name, reg.name, reg.sig, reg.fn_ptr
        );
    }

    // 3. 挂载双流 Full Trace（仅追踪目标 .so 代码段，自动跳过 HLE/JNI 跳板噪声）
    let idx_path = "/tmp/crypto_sign.idx";
    let ext_path = "/tmp/crypto_sign.ext";
    let mut tracer =
        BinaryTracer::new_dual_mmap(idx_path, ext_path, 200_000, 400_000, TraceLevel::Full)?;
    tracer
        .filter_mut()
        .allow_range(module.base_addr, module.base_addr + module.image_size);
    emu.set_tracer(tracer)?;

    // 4. 构造 Android Context / jstring / jbyteArray 参数并调用动态注册的 native_sign
    let ctx_ref = emu.jni_mut().objects.add_local(JObject::Context {
        package_name: pkg_name.to_string(),
    });
    let payload_ref = emu.new_jstring(payload);
    let salt_ref = emu.new_jbyte_array(salt.to_vec());

    let t0 = Instant::now();
    let ret_raw = emu.call_registered_native(
        "com/demo/CryptoSigner",
        "sign",
        &[ctx_ref.0, payload_ref.0, salt_ref.0],
    )?;
    let elapsed = t0.elapsed();
    emu.tracer().flush()?;

    let sig = emu
        .read_jstring(JObjectRef(ret_raw))
        .expect("返回值应为有效 jstring")
        .to_string();
    let stats = emu.tracer().stats;

    println!("\n=== 真实 AArch64 HMAC-SHA256 模拟执行结果 ===");
    println!("签名输出      : {sig}");
    println!("执行指令数    : {} (扩展访存/多寄存器事件: {})", stats.total_insns, stats.recorded_ext);
    println!("Full Trace耗时: {:.3} ms", elapsed.as_secs_f64() * 1000.0);
    println!("双流落盘文件  : {idx_path} & {ext_path}");

    // 5. 关闭 Trace（切换 Fast 模式）测试 Snapshot 100 次高速批量回放吞吐
    let snap = emu.capture_snapshot()?;
    emu.tracer_mut().set_level(TraceLevel::Fast);
    let batch_start = Instant::now();
    for _ in 0..100 {
        emu.restore_snapshot(&snap)?;
        let r = emu.call_registered_native(
            "com/demo/CryptoSigner",
            "sign",
            &[ctx_ref.0, payload_ref.0, salt_ref.0],
        )?;
        assert_eq!(emu.read_jstring(JObjectRef(r)), Some(sig.as_str()));
    }
    let batch_ms = batch_start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "Snapshot 100次批量回放耗时: {:.2} ms (单次 {:.3} ms)",
        batch_ms,
        batch_ms / 100.0
    );

    Ok(())
}
