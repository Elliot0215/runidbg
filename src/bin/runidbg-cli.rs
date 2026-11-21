use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use runidbg_arm64_emu_tracer::tracer::{
    decode_instruction_with_reg, format_ascii_hint, BinaryTracer, TraceReader,
};

fn parse_u64_hex_or_dec(s: &str) -> Result<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).with_context(|| format!("无效的十六进制数: {s}"))
    } else {
        s.parse::<u64>()
            .with_context(|| format!("无效的十进制数: {s}"))
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ':')
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        bail!("无效的十六进制字节串: {s}");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .with_context(|| format!("无效的十六进制字节: {}", &cleaned[i..i + 2]))?;
        out.push(byte);
    }
    Ok(out)
}

fn print_usage() {
    eprintln!(
        "runidbg-arm64-emu-tracer 工具集 (runidbg-cli)\n\
         全局选项 (置于子命令之前):\n\
           [--log-level <trace|debug|info|warn|error>] [--log-format <compact|json>]\n\
         用法:\n\
           runidbg-cli run <script.js> [-- <args...>]                                         运行 QuickJS 仿真脚本\n\
           runidbg-cli serve <script.js> [--listen 127.0.0.1:8080] [--workers 1|auto]         启动异步 HTTP/JSON-RPC 2.0 服务\n\
                     [--max-queue 1024] [--timeout-ms 30000] [--max-insns 0]\n\
                     [--allow-reload] [--allow-eval] [-- <args...>]\n\
           runidbg-cli mcp [--script <init.js>] [--cwd <dir>] [--http 127.0.0.1:8090]         启动 MCP 服务端 (stdio / HTTP)\n\
           runidbg-cli debug <lib.so> <symbol|0xaddr> [--listen 127.0.0.1:1234] [--pkg PKG]   启动 GDB RSP 远程调试服务端\n\
           runidbg-cli init-types [dir]                                                       生成 runidbg.d.ts 类型声明\n\
           runidbg-cli dump <trace.idx> [--ext <trace.ext>] [--base <hex>] [--skip N] [--limit N]\n\
           runidbg-cli search <trace.idx> [--ext <trace.ext>] [--base <hex>] [--val <hex>] [--addr <hex>] [--pc <hex>]\n\
                     [--ascii <text>] [--bytes <hex>] [--limit N]\n\
           runidbg-cli stats <trace.idx> [--base <hex>] [--top N]\n\
           runidbg-cli calltree <trace.idx> [--base <hex>] [--max-depth N] [--min-insns N]\n\
           runidbg-cli crypto-scan <trace.idx> [--ext <trace.ext>] [--base <hex>]\n\
           runidbg-cli ui <trace.idx> [--ext <trace.ext>] [--base <hex>] [--listen 127.0.0.1:8088] [--open]\n\
           runidbg-cli export-ida <trace.idx> --base <hex> [--out <script.py>]\n\
           runidbg-cli export-bn  <trace.idx> --base <hex> [--out <script.py>]"
    );
}

#[cfg(feature = "js")]
fn run_js_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("用法: runidbg-cli run <script.js> [-- <args...>]");
    }
    let script_path = PathBuf::from(&args[0]);
    let script_args: Vec<String> = if args.get(1).map(String::as_str) == Some("--") {
        args[2..].to_vec()
    } else {
        args[1..].to_vec()
    };
    runidbg_arm64_emu_tracer::script::JsRunner::run_file(&script_path, &script_args)?;
    Ok(())
}

#[cfg(not(feature = "js"))]
fn run_js_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 QuickJS 脚本引擎，请使用默认 features 或 `--features js` 重新编译")
}

#[cfg(feature = "rpc")]
fn serve_rpc_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(
            "用法: runidbg-cli serve <script.js> [--listen 127.0.0.1:8080] [--workers 1|auto] [--max-queue 1024] [--timeout-ms 30000] [--max-insns 0] [--allow-reload] [--allow-eval] [-- <args...>]"
        );
    }
    let script_path = PathBuf::from(&args[0]);
    let mut cfg = runidbg_arm64_emu_tracer::script::rpc::RpcServerConfig::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                cfg.listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--workers" if i + 1 < args.len() => {
                let raw = args[i + 1].as_str();
                cfg.workers = if raw.eq_ignore_ascii_case("auto") {
                    std::thread::available_parallelism()
                        .map(std::num::NonZeroUsize::get)
                        .unwrap_or(1)
                } else {
                    raw.parse::<usize>()
                        .with_context(|| format!("无效的 --workers 值: {raw}"))?
                        .max(1)
                };
                i += 2;
            }
            "--max-queue" if i + 1 < args.len() => {
                cfg.max_queue = args[i + 1]
                    .parse::<usize>()
                    .with_context(|| format!("无效的 --max-queue 值: {}", args[i + 1]))?
                    .max(1);
                i += 2;
            }
            "--timeout-ms" if i + 1 < args.len() => {
                cfg.timeout_ms = args[i + 1]
                    .parse::<u64>()
                    .with_context(|| format!("无效的 --timeout-ms 值: {}", args[i + 1]))?;
                i += 2;
            }
            "--max-insns" if i + 1 < args.len() => {
                cfg.max_instructions = args[i + 1]
                    .parse::<usize>()
                    .with_context(|| format!("无效的 --max-insns 值: {}", args[i + 1]))?;
                i += 2;
            }
            "--allow-eval" => {
                cfg.allow_eval = true;
                i += 1;
            }
            "--allow-reload" => {
                cfg.allow_reload = true;
                i += 1;
            }
            "--" => {
                cfg.cli_args = args[i + 1..].to_vec();
                break;
            }
            other => bail!("serve 未知参数: {other}"),
        }
    }
    let handle = runidbg_arm64_emu_tracer::script::rpc::start_rpc_server(
        runidbg_arm64_emu_tracer::script::rpc::RpcSource::File(script_path),
        cfg,
    )?;
    eprintln!(
        "[runidbg-rpc] 已监听 http://{} | workers={} (GET /health, GET /metrics, POST /call/<method>, POST /rpc)",
        handle.local_addr(),
        handle.workers()
    );
    handle.wait();
    Ok(())
}

#[cfg(not(feature = "rpc"))]
fn serve_rpc_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 RPC 服务，请使用默认 features 或 `--features rpc` 重新编译")
}

#[cfg(feature = "mcp")]
fn mcp_command(args: &[String]) -> Result<()> {
    let mut init_script: Option<PathBuf> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut http_addr: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--script" if i + 1 < args.len() => {
                init_script = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--cwd" if i + 1 < args.len() => {
                cwd = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--http" if i + 1 < args.len() => {
                http_addr = Some(args[i + 1].clone());
                i += 2;
            }
            other => bail!("mcp 未知参数: {other}"),
        }
    }
    let base_dir = cwd.unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if let Some(addr) = http_addr {
        #[cfg(feature = "rpc")]
        {
            let handle = runidbg_arm64_emu_tracer::script::mcp::start_mcp_http_server(
                &addr,
                &base_dir,
                init_script.as_deref(),
            )?;
            eprintln!(
                "[runidbg-mcp] Streamable HTTP 已监听 http://{}/mcp",
                handle.local_addr()
            );
            handle.wait();
            return Ok(());
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = addr;
            bail!("HTTP MCP 模式需要同时启用 `rpc` feature");
        }
    }
    let mut server =
        runidbg_arm64_emu_tracer::script::mcp::McpServer::new(&base_dir, init_script.as_deref())?;
    server.run_stdio()
}

#[cfg(not(feature = "mcp"))]
fn mcp_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 MCP 服务，请使用默认 features 或 `--features mcp` 重新编译")
}

#[cfg(feature = "js")]
fn init_types_command(args: &[String]) -> Result<()> {
    let dir = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let out = runidbg_arm64_emu_tracer::script::write_type_definitions(&dir)?;
    println!("已生成 TypeScript 类型声明: {}", out.display());
    Ok(())
}

#[cfg(not(feature = "js"))]
fn init_types_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 QuickJS 脚本引擎，请使用默认 features 或 `--features js` 重新编译")
}

#[cfg(feature = "ui")]
fn ui_command(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("用法: runidbg-cli ui <trace.idx> [--ext <trace.ext>] [--base <hex>] [--listen 127.0.0.1:8088] [--open]");
    }
    let idx_path = PathBuf::from(&args[0]);
    let mut ext_path: Option<PathBuf> = None;
    let mut base_addr: u64 = 0;
    let mut listen_addr = "127.0.0.1:8088".to_string();
    let mut auto_open = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ext" if i + 1 < args.len() => {
                ext_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--base" if i + 1 < args.len() => {
                base_addr = parse_u64_hex_or_dec(&args[i + 1])?;
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--open" => {
                auto_open = true;
                i += 1;
            }
            other => bail!("ui 未知参数: {other}"),
        }
    }

    if ext_path.is_none() {
        let sibling = idx_path.with_extension("ext");
        if sibling != idx_path && sibling.is_file() {
            ext_path = Some(sibling);
        }
    }

    let handle = runidbg_arm64_emu_tracer::ui::start_trace_ui_server(
        &idx_path,
        ext_path.as_deref(),
        base_addr,
        &listen_addr,
    )?;
    let url = format!("http://{}/", handle.local_addr());
    println!("[runidbg-ui] Trace Web UI 已启动: {url}");
    println!("[runidbg-ui] 按 Ctrl+C 退出");
    if auto_open {
        runidbg_arm64_emu_tracer::ui::open_in_browser(&url);
    }
    handle.wait();
    Ok(())
}

#[cfg(not(feature = "ui"))]
fn ui_command(_args: &[String]) -> Result<()> {
    bail!("当前构建未启用 Web UI（默认关闭以保持精简），请使用 `cargo build --release --features ui` 重新编译")
}

fn debug_gdb_command(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!("用法: runidbg-cli debug <lib.so> <symbol|0xaddr> [--listen 127.0.0.1:1234] [--pkg com.example.app]");
    }
    let so_path = PathBuf::from(&args[0]);
    let target = args[1].as_str();
    let mut listen_addr = "127.0.0.1:1234".to_string();
    let mut pkg = "com.example.app".to_string();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--pkg" if i + 1 < args.len() => {
                pkg = args[i + 1].clone();
                i += 2;
            }
            other => bail!("debug 未知参数: {other}"),
        }
    }

    let mut emu = runidbg_arm64_emu_tracer::AndroidEmulator::builder()
        .package_name(pkg)
        .build()?;
    let module = emu.load_library(&so_path)?;
    let start_pc = if target.starts_with("0x") || target.starts_with("0X") {
        parse_u64_hex_or_dec(target)?
    } else {
        module
            .find_symbol(target)
            .with_context(|| format!("未找到导出符号: {target}"))?
    };
    eprintln!(
        "[runidbg-gdb] 已加载 {} (base=0x{:016x}, size=0x{:x})",
        module.name, module.base_addr, module.image_size
    );
    runidbg_arm64_emu_tracer::debug::GdbServer::serve(&mut emu, &listen_addr, start_pc, &[])
}

fn main() -> Result<()> {
    let raw_args: Vec<String> = env::args().collect();
    let mut log_level: Option<String> = None;
    let mut log_format = "compact".to_string();
    let mut args = Vec::with_capacity(raw_args.len());
    if let Some(bin) = raw_args.first() {
        args.push(bin.clone());
    }
    let mut idx = 1;
    while idx < raw_args.len() {
        match raw_args[idx].as_str() {
            "--log-level" if idx + 1 < raw_args.len() => {
                log_level = Some(raw_args[idx + 1].clone());
                idx += 2;
            }
            "--log-format" if idx + 1 < raw_args.len() => {
                log_format = raw_args[idx + 1].clone();
                idx += 2;
            }
            _ => {
                args.extend_from_slice(&raw_args[idx..]);
                break;
            }
        }
    }

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let cmd = args[1].as_str();
    let default_level = match cmd {
        "serve" | "debug" => "info",
        _ => "warn",
    };
    runidbg_arm64_emu_tracer::logging::init_logging(
        log_level.as_deref().unwrap_or(default_level),
        &log_format,
    );

    match cmd {
        "run" => return run_js_command(&args[2..]),
        "serve" => return serve_rpc_command(&args[2..]),
        "mcp" => return mcp_command(&args[2..]),
        "debug" => return debug_gdb_command(&args[2..]),
        "ui" => return ui_command(&args[2..]),
        "init-types" => return init_types_command(&args[2..]),
        "-h" | "--help" | "help" => {
            print_usage();
            return Ok(());
        }
        _ => {}
    }

    if args.len() < 3 {
        print_usage();
        return Ok(());
    }

    let idx_path = PathBuf::from(&args[2]);
    let mut ext_path: Option<PathBuf> = None;
    let mut skip: usize = 0;
    let mut limit: usize = usize::MAX;
    let mut val_filter: Option<u64> = None;
    let mut addr_filter: Option<u64> = None;
    let mut pc_filter: Option<u64> = None;
    let mut ascii_filter: Option<String> = None;
    let mut bytes_filter: Option<Vec<u8>> = None;
    let mut base_addr: u64 = 0;
    let mut top_n: usize = 20;
    let mut max_depth: usize = 4;
    let mut min_insns: usize = 1000;
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
            "--ascii" if i + 1 < args.len() => {
                ascii_filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--bytes" if i + 1 < args.len() => {
                bytes_filter = Some(parse_hex_bytes(&args[i + 1])?);
                i += 2;
            }
            "--base" if i + 1 < args.len() => {
                base_addr = parse_u64_hex_or_dec(&args[i + 1])?;
                i += 2;
            }
            "--top" if i + 1 < args.len() => {
                top_n = args[i + 1].parse().context("无效的 --top 值")?;
                i += 2;
            }
            "--max-depth" if i + 1 < args.len() => {
                max_depth = args[i + 1].parse().context("无效的 --max-depth 值")?;
                i += 2;
            }
            "--min-insns" if i + 1 < args.len() => {
                min_insns = args[i + 1].parse().context("无效的 --min-insns 值")?;
                i += 2;
            }
            "--out" if i + 1 < args.len() => {
                out_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            other => bail!("未知参数: {other}"),
        }
    }

    if ext_path.is_none() {
        let sibling = idx_path.with_extension("ext");
        if sibling != idx_path && sibling.is_file() {
            ext_path = Some(sibling);
        }
    }

    let reader = TraceReader::open(&idx_path, ext_path.as_deref())?;

    let format_rel = |pc: u64| -> String {
        if base_addr != 0 && pc >= base_addr {
            format!(" [+0x{:x}]", pc - base_addr)
        } else {
            String::new()
        }
    };

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
                    let pc = rec.pc;
                    let op = rec.opcode;
                    let deltas = reader.reg_deltas_for(idx);
                    let primary = deltas.first().copied();
                    println!(
                        "#{idx:06}{} {}",
                        format_rel(pc),
                        decode_instruction_with_reg(pc, op, primary)
                    );
                    for &(reg_id, reg_val) in deltas.iter().skip(1) {
                        let name = if reg_id == 31 {
                            "SP".to_string()
                        } else {
                            format!("X{reg_id}")
                        };
                        let hint = format_ascii_hint(reg_val, 8).unwrap_or_default();
                        println!("    [REG] {name} <- 0x{reg_val:016x}{hint}");
                    }
                    if ext_path.is_some() {
                        for ext in reader.mem_events_for(idx) {
                            println!("{}", BinaryTracer::format_ext_record(&ext));
                        }
                    }
                }
            }
        }
        "search" => {
            if let Some(target) = val_filter {
                let reg_hits = reader.search_value_attributed(target);
                println!("# 命中寄存器写入值 0x{target:016x}: {} 条", reg_hits.len());
                for (idx, rec, reg_id) in reg_hits.into_iter().take(limit) {
                    let pc = rec.pc;
                    let op = rec.opcode;
                    println!(
                        "#{idx:06}{} {}",
                        format_rel(pc),
                        decode_instruction_with_reg(pc, op, Some((reg_id, target)))
                    );
                }
                if ext_path.is_some() {
                    let mem_hits = reader.search_mem_value(target);
                    if !mem_hits.is_empty() {
                        println!("# 命中内存读写值 0x{target:016x}: {} 条", mem_hits.len());
                        for ext in mem_hits.into_iter().take(limit) {
                            let seq = ext.seq_low32;
                            let pc = ext.pc;
                            println!(
                                "seq={seq} pc=0x{pc:016x}{} {}",
                                format_rel(pc),
                                BinaryTracer::format_ext_record(&ext).trim()
                            );
                        }
                    }
                }
            }
            if let Some(ref ascii) = ascii_filter {
                let hits = reader.search_mem_bytes(ascii.as_bytes());
                println!("# 命中内存写入 ASCII \"{ascii}\": {} 条", hits.len());
                for hit in hits.into_iter().take(limit) {
                    println!(
                        "seq={} pc=0x{:016x}{} [MEM W] addr=0x{:016x} len={} (\"{ascii}\")",
                        hit.seq_low32,
                        hit.pc,
                        format_rel(hit.pc),
                        hit.addr,
                        hit.matched_len
                    );
                }
            }
            if let Some(ref pat) = bytes_filter {
                let hits = reader.search_mem_bytes(pat);
                let hex_str: String = pat.iter().map(|b| format!("{b:02x}")).collect();
                println!("# 命中内存写入字节序列 {hex_str}: {} 条", hits.len());
                for hit in hits.into_iter().take(limit) {
                    println!(
                        "seq={} pc=0x{:016x}{} [MEM W] addr=0x{:016x} len={} ({hex_str})",
                        hit.seq_low32,
                        hit.pc,
                        format_rel(hit.pc),
                        hit.addr,
                        hit.matched_len
                    );
                }
            }
            if let Some(target_addr) = addr_filter {
                let hits = reader.search_mem_addr(target_addr);
                println!("# 命中访存地址 0x{target_addr:016x}: {} 条", hits.len());
                for ext in hits.into_iter().take(limit) {
                    let seq = ext.seq_low32;
                    let pc = ext.pc;
                    println!(
                        "seq={seq} pc=0x{pc:016x}{} {}",
                        format_rel(pc),
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
                            if count < limit {
                                let op = rec.opcode;
                                let primary = reader.reg_deltas_for(idx).first().copied();
                                println!(
                                    "#{idx:06}{} {}",
                                    format_rel(pc),
                                    decode_instruction_with_reg(pc, op, primary)
                                );
                            }
                            count += 1;
                        }
                    }
                }
                println!("# 命中 PC 0x{target_pc:016x}: {count} 条");
            }
        }
        "calltree" => {
            let total = reader.len().max(1);
            let nodes = reader.build_calltree();
            let filtered: Vec<_> = nodes
                .iter()
                .filter(|n| n.depth <= max_depth && (n.depth == 0 || n.insn_count() >= min_insns))
                .collect();
            println!(
                "# 时间轴调用树: 总指令={} | 总调用节点={} | 显示={} (max_depth={}, min_insns={})",
                reader.len(),
                nodes.len(),
                filtered.len(),
                max_depth,
                min_insns
            );
            for node in filtered {
                let indent = "  ".repeat(node.depth);
                let cnt = node.insn_count();
                let pct = (cnt as f64) * 100.0 / (total as f64);
                let caller_str = if node.caller_pc != 0 {
                    format!(" <- from 0x{:016x}{}", node.caller_pc, format_rel(node.caller_pc))
                } else {
                    String::new()
                };
                println!(
                    "{indent}[#{:07}..#{:07}] {:>8} insns ({:>5.1}%) 0x{:016x}{}{caller_str}",
                    node.start_idx,
                    node.end_idx,
                    cnt,
                    pct,
                    node.target_pc,
                    format_rel(node.target_pc),
                );
            }
        }
        "crypto-scan" => {
            let groups = reader.scan_crypto();
            println!(
                "# 密码学特征扫描: 总指令={} | 命中算法窗口={} 个",
                reader.len(),
                groups.len()
            );
            if groups.is_empty() {
                println!("  (未检出已知标准密码学常量)");
            } else {
                for g in groups {
                    let consts: Vec<String> = g
                        .distinct_constants
                        .iter()
                        .map(|c| format!("0x{c:08x}"))
                        .collect();
                    println!(
                        "  {:<16} [#{:07}..#{:07}] pc=0x{:016x}{} hits={:<4} consts=[{}]",
                        g.algorithm,
                        g.start_idx,
                        g.end_idx,
                        g.first_pc,
                        format_rel(g.first_pc),
                        g.hit_count,
                        consts.join(", ")
                    );
                }
            }
        }
        "stats" => {
            use std::collections::HashMap;
            let mut pc_counts: HashMap<u64, u64> = HashMap::new();
            let mut bl_targets: HashMap<u64, u64> = HashMap::new();
            let total = reader.len();
            for idx in 0..total {
                if let Some(rec) = reader.get(idx) {
                    let pc = rec.pc;
                    let op = rec.opcode;
                    *pc_counts.entry(pc).or_insert(0) += 1;
                    // ARM64 `BL imm26` 编码: top 6 bits == 0b100101 (0x9400_0000..0x97ff_ffff)
                    if (op & 0xFC00_0000) == 0x9400_0000 {
                        let imm26 = ((op & 0x03FF_FFFF) as i32) << 6 >> 6;
                        let target = pc.wrapping_add((imm26 as i64 * 4) as u64);
                        *bl_targets.entry(target).or_insert(0) += 1;
                    }
                }
            }
            println!(
                "# Trace 统计: 总指令={total} | 唯一 PC={} | 扩展事件={} | 唯一 BL 目标={}",
                pc_counts.len(),
                reader.ext_len(),
                bl_targets.len()
            );
            let mut top_bl: Vec<(u64, u64)> = bl_targets.into_iter().collect();
            top_bl.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            println!("\n=== Top {} 热点调用目标 (BL) ===", top_n.min(top_bl.len()));
            for (addr, cnt) in top_bl.into_iter().take(top_n) {
                println!("  0x{addr:016x}{}  x{cnt}", format_rel(addr));
            }
            let mut top_pcs: Vec<(u64, u64)> = pc_counts.into_iter().collect();
            top_pcs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            println!("\n=== Top {} 热点指令地址 (PC) ===", top_n.min(top_pcs.len()));
            for (addr, cnt) in top_pcs.into_iter().take(top_n) {
                println!("  0x{addr:016x}{}  x{cnt}", format_rel(addr));
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
