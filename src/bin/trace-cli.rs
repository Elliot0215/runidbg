use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use arm64_emu_tracer::tracer::{BinaryTracer, TraceReader};

fn parse_u64_hex_or_dec(s: &str) -> Result<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).with_context(|| format!("无效的十六进制数: {s}"))
    } else {
        s.parse::<u64>()
            .with_context(|| format!("无效的十进制数: {s}"))
    }
}

fn print_usage() {
    eprintln!(
        "arm64-emu-tracer 离线 Trace 分析工具 (trace-cli)\n\
         用法:\n\
           trace-cli dump <trace.idx> [--ext <trace.ext>] [--skip N] [--limit N]\n\
           trace-cli search <trace.idx> [--ext <trace.ext>] [--val <hex>] [--addr <hex>] [--pc <hex>]\n\
           trace-cli export-ida <trace.idx> --base <hex> [--out <script.py>]\n\
           trace-cli export-bn  <trace.idx> --base <hex> [--out <script.py>]"
    );
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_usage();
        return Ok(());
    }

    let cmd = args[1].as_str();
    let idx_path = PathBuf::from(&args[2]);
    let mut ext_path: Option<PathBuf> = None;
    let mut skip: usize = 0;
    let mut limit: usize = usize::MAX;
    let mut val_filter: Option<u64> = None;
    let mut addr_filter: Option<u64> = None;
    let mut pc_filter: Option<u64> = None;
    let mut base_addr: u64 = 0;
    let mut out_path: Option<PathBuf> = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" if i + 1 < args.len() => {
                ext_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--skip" if i + 1 < args.len() => {
                skip = args[i + 1].parse().context("无效的 --skip 值")?;
                i += 2;
            }
            "--limit" if i + 1 < args.len() => {
                limit = args[i + 1].parse().context("无效的 --limit 值")?;
                i += 2;
            }
            "--val" if i + 1 < args.len() => {
                val_filter = Some(parse_u64_hex_or_dec(&args[i + 1])?);
                i += 2;
            }
            "--addr" if i + 1 < args.len() => {
                addr_filter = Some(parse_u64_hex_or_dec(&args[i + 1])?);
                i += 2;
            }
            "--pc" if i + 1 < args.len() => {
                pc_filter = Some(parse_u64_hex_or_dec(&args[i + 1])?);
                i += 2;
            }
            "--base" if i + 1 < args.len() => {
                base_addr = parse_u64_hex_or_dec(&args[i + 1])?;
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            other => bail!("未知参数: {other}"),
        }
    }

    let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;

    match cmd {
        "dump" => {
            println!(
                "# trace.idx: {} 条指令 | trace.ext: {} 条扩展事件",
                reader.len(),
                reader.ext_len()
            );
            let end = reader.len().min(skip.saturating_add(limit));
            for idx in skip..end {
                if let Some(rec) = reader.get(idx) {
                    let seq = rec.seq_low32;
                    println!("#{idx:06} {}", BinaryTracer::decode_record(&rec));
                    if ext_path.is_some() {
                        for ext in reader.ext_for_seq(seq) {
                            println!("{}", BinaryTracer::format_ext_record(&ext));
                        }
                    }
                }
            }
        }
        "search" => {
            if let Some(target) = val_filter {
                let hits = reader.search_value(target);
                println!("# 命中寄存器值 0x{target:016x}: {} 条", hits.len());
                for (idx, rec) in hits {
                    println!("#{idx:06} {}", BinaryTracer::decode_record(&rec));
                }
            }
            if let Some(target_addr) = addr_filter {
                let hits = reader.search_mem_addr(target_addr);
                println!("# 命中访存地址 0x{target_addr:016x}: {} 条", hits.len());
                for ext in hits {
                    let seq = ext.seq_low32;
                    let pc = ext.pc;
                    println!(
                        "seq={seq} pc=0x{pc:016x} {}",
                        BinaryTracer::format_ext_record(&ext).trim()
                    );
                }
            }
            if let Some(target_pc) = pc_filter {
                let mut count = 0usize;
                for idx in 0..reader.len() {
                    if let Some(rec) = reader.get(idx) {
                        let pc = rec.pc;
                        if pc == target_pc {
                            println!("#{idx:06} {}", BinaryTracer::decode_record(&rec));
                            count += 1;
                        }
                    }
                }
                println!("# 命中 PC 0x{target_pc:016x}: {count} 条");
            }
        }
        "export-ida" => {
            let script = reader.export_ida_python(base_addr);
            if let Some(out) = out_path {
                fs::write(&out, &script)?;
                println!("已导出 IDAPython 覆盖率脚本到 {}", out.display());
            } else {
                print!("{script}");
            }
        }
        "export-bn" => {
            let script = reader.export_binja_python(base_addr);
            if let Some(out) = out_path {
                fs::write(&out, &script)?;
                println!("已导出 Binary Ninja 覆盖率脚本到 {}", out.display());
            } else {
                print!("{script}");
            }
        }
        _ => {
            print_usage();
            bail!("不支持的子命令: {cmd}");
        }
    }

    Ok(())
}
