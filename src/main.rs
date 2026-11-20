use std::env;
use std::time::Instant;

use anyhow::{Context, Result};
use runidbg_arm64_emu_tracer::tracer::{BinaryTracer, TraceLevel};
use runidbg_arm64_emu_tracer::AndroidEmulator;

fn main() -> Result<()> {
    // 命令行用法: runidbg-arm64-emu-tracer <so_path> [symbol_name] [sysroot_lib64_dir]
    let args: Vec<String> = env::args().collect();
    let so_path = args.get(1).map(String::as_str).unwrap_or("libtest.so");
    let symbol_name = args.get(2).map(String::as_str).unwrap_or("target_func");
    let sysroot_dir = args.get(3).map(String::as_str);

    // 1. 通过统一门面构建 Android ARM64 沙箱（自动配置 NEON/TLS、Syscall、HLE 跳板、JNI 虚表与 Trace）
    let mut builder = AndroidEmulator::builder()
        .package_name("com.example.app")
        .with_memory_trace(1_000_000, TraceLevel::RegDelta);
    if let Some(dir) = sysroot_dir {
        builder = builder.add_search_path(dir);
    }
    let mut emu = builder.build().context("初始化 AndroidEmulator 失败")?;

    // 2. 加载目标 .so（递归解析 DT_NEEDED、执行重定位与 .init_array）
    let module = emu
        .load_library(so_path)
        .with_context(|| format!("加载 ELF 模块失败: {so_path}"))?;

    println!(
        "[+] 已加载模块 {} @ 0x{:016x} (size=0x{:x}, 导出符号={}, init_array={})",
        module.name,
        module.base_addr,
        module.image_size,
        module.symbols.len(),
        module.init_array.len()
    );

    // 仅追踪目标业务模块代码区间，自动过滤系统库与 HLE 跳板噪声
    emu.tracer_mut()
        .filter_mut()
        .allow_range(module.base_addr, module.base_addr + module.image_size);

    // 3. 若存在 JNI_OnLoad 则自动引导执行
    if let Some(ver) = emu.call_jni_onload(&module)? {
        println!("[+] JNI_OnLoad 执行完毕，返回版本 0x{ver:08x}");
    }

    // 4. 准备调用参数并执行目标符号
    let arg0_buf = emu.uc_mut().get_data_mut().mem.alloc_heap(64)?;
    emu.uc_mut().mem_write(arg0_buf, b"hello_arm64_emu\0")?;
    let arg1_len: u64 = 15;

    let start_time = Instant::now();
    let ret_x0 = emu
        .call_symbol(&module, symbol_name, &[arg0_buf, arg1_len])
        .with_context(|| format!("调用导出符号 `{symbol_name}` 失败"))?;
    let elapsed = start_time.elapsed();

    emu.tracer().flush()?;

    // 5. 输出执行统计与反汇编预览
    let stats = emu.tracer().stats;
    let heap_used = emu.uc().get_data().mem.heap_used();
    let secs = elapsed.as_secs_f64();
    let mips = if secs > 0.0 {
        (stats.total_insns as f64 / 1_000_000.0) / secs
    } else {
        0.0
    };

    println!("\n=== 模拟执行完成 ===");
    println!("返回值 X0     : 0x{ret_x0:016x} ({ret_x0})");
    println!("总执行指令数  : {}", stats.total_insns);
    println!(
        "已记录 Trace  : {} (丢弃: {})",
        stats.recorded_insns, stats.dropped_insns
    );
    println!("耗时 / 吞吐   : {:.3} ms ({:.2} MIPS)", secs * 1000.0, mips);
    println!("堆内存已使用  : {} bytes", heap_used);

    let records = emu.tracer().records();
    if !records.is_empty() {
        println!(
            "\n=== 前 {} 条指令 Trace 预览 (bad64 离线解码) ===",
            records.len().min(10)
        );
        for rec in records.iter().take(10) {
            println!("  {}", BinaryTracer::decode_record(rec));
        }
    }

    Ok(())
}
