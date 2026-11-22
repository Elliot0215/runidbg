use std::collections::HashSet;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use unicorn_engine::RegisterARM64;

use crate::cpu::RET_MAGIC_ADDR;
use crate::emulator::AndroidEmulator;

const AARCH64_TARGET_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>aarch64</architecture>
  <feature name="org.gnu.gdb.aarch64.core">
    <reg name="x0" bitsize="64"/>
    <reg name="x1" bitsize="64"/>
    <reg name="x2" bitsize="64"/>
    <reg name="x3" bitsize="64"/>
    <reg name="x4" bitsize="64"/>
    <reg name="x5" bitsize="64"/>
    <reg name="x6" bitsize="64"/>
    <reg name="x7" bitsize="64"/>
    <reg name="x8" bitsize="64"/>
    <reg name="x9" bitsize="64"/>
    <reg name="x10" bitsize="64"/>
    <reg name="x11" bitsize="64"/>
    <reg name="x12" bitsize="64"/>
    <reg name="x13" bitsize="64"/>
    <reg name="x14" bitsize="64"/>
    <reg name="x15" bitsize="64"/>
    <reg name="x16" bitsize="64"/>
    <reg name="x17" bitsize="64"/>
    <reg name="x18" bitsize="64"/>
    <reg name="x19" bitsize="64"/>
    <reg name="x20" bitsize="64"/>
    <reg name="x21" bitsize="64"/>
    <reg name="x22" bitsize="64"/>
    <reg name="x23" bitsize="64"/>
    <reg name="x24" bitsize="64"/>
    <reg name="x25" bitsize="64"/>
    <reg name="x26" bitsize="64"/>
    <reg name="x27" bitsize="64"/>
    <reg name="x28" bitsize="64"/>
    <reg name="x29" bitsize="64"/>
    <reg name="x30" bitsize="64"/>
    <reg name="sp" bitsize="64" type="data_ptr"/>
    <reg name="pc" bitsize="64" type="code_ptr"/>
    <reg name="cpsr" bitsize="32"/>
  </feature>
</target>
"#;

const CORE_REGS: [RegisterARM64; 34] = [
    RegisterARM64::X0,
    RegisterARM64::X1,
    RegisterARM64::X2,
    RegisterARM64::X3,
    RegisterARM64::X4,
    RegisterARM64::X5,
    RegisterARM64::X6,
    RegisterARM64::X7,
    RegisterARM64::X8,
    RegisterARM64::X9,
    RegisterARM64::X10,
    RegisterARM64::X11,
    RegisterARM64::X12,
    RegisterARM64::X13,
    RegisterARM64::X14,
    RegisterARM64::X15,
    RegisterARM64::X16,
    RegisterARM64::X17,
    RegisterARM64::X18,
    RegisterARM64::X19,
    RegisterARM64::X20,
    RegisterARM64::X21,
    RegisterARM64::X22,
    RegisterARM64::X23,
    RegisterARM64::X24,
    RegisterARM64::X25,
    RegisterARM64::X26,
    RegisterARM64::X27,
    RegisterARM64::X28,
    RegisterARM64::X29,
    RegisterARM64::X30,
    RegisterARM64::SP,
    RegisterARM64::PC,
    RegisterARM64::NZCV,
];

/// 轻量级 ARM64 GDB Remote Serial Protocol (RSP) 服务端
///
/// 兼容 IDA Pro、Binary Ninja、`gdb-multiarch`、`pwndbg` 与 `lldb`，支持：
/// - 寄存器读写 (`g`/`G`/`p`/`P`) 与 `target.xml` 自动识别 AArch64 架构
/// - Guest 内存读写 (`m`/`M`)
/// - 软件/硬件断点 (`Z0`/`z0`/`Z1`/`z1`)
/// - 单步执行 (`s`) 与继续执行 (`c`)
pub struct GdbServer;

impl GdbServer {
    /// 绑定指定 TCP 地址，等待首个调试器连入并进入交互调试循环
    pub fn serve(
        emu: &mut AndroidEmulator,
        listen_addr: &str,
        start_pc: u64,
        args: &[u64],
    ) -> Result<()> {
        if !emu.backend_kind().supports_gdb() {
            return Err(crate::error::EmuError::Backend(format!(
                "当前后端 `{}` 仅支持仿真模式，不支持 GDB 调试模式（GDB 仅支持 `unicorn` 后端）",
                emu.backend_kind()
            ))
            .into());
        }
        let listener = TcpListener::bind(listen_addr)
            .with_context(|| format!("绑定 GDB Stub 监听地址失败: {listen_addr}"))?;
        tracing::info!(
            target: "runidbg::gdb",
            addr = %listener.local_addr()?,
            pc = format_args!("0x{start_pc:016x}"),
            "等待 GDB/IDA 调试器连入"
        );
        Self::serve_listener(emu, listener, start_pc, args)
    }

    /// 使用已绑定的 `TcpListener` 启动单次 GDB RSP 调试会话（便于测试使用 `127.0.0.1:0`）
    pub fn serve_listener(
        emu: &mut AndroidEmulator,
        listener: TcpListener,
        start_pc: u64,
        args: &[u64],
    ) -> Result<()> {
        if !emu.backend_kind().supports_gdb() {
            return Err(crate::error::EmuError::Backend(format!(
                "当前后端 `{}` 仅支持仿真模式，不支持 GDB 调试模式（GDB 仅支持 `unicorn` 后端）",
                emu.backend_kind()
            ))
            .into());
        }
        // 准备调用寄存器（X0..X7, LR=RET_MAGIC_ADDR, PC=start_pc）
        for (idx, &val) in args.iter().take(8).enumerate() {
            emu.uc_mut().reg_write(CORE_REGS[idx], val)?;
        }
        emu.uc_mut().reg_write(RegisterARM64::LR, RET_MAGIC_ADDR)?;
        emu.uc_mut().reg_write(RegisterARM64::PC, start_pc)?;

        let (stream, _peer) = listener.accept().context("接收 GDB 客户端连接失败")?;
        Self::handle_client(emu, stream)
    }

    fn handle_client(emu: &mut AndroidEmulator, mut stream: TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut no_ack = false;
        let breakpoints: Arc<Mutex<HashSet<u64>>> = Arc::new(Mutex::new(HashSet::new()));

        while let Some(pkt) = read_rsp_packet(&mut reader)? {
            if !no_ack {
                stream.write_all(b"+")?;
                stream.flush()?;
            }

            let resp = match pkt.as_str() {
                "?" => "S05".to_string(),
                "QStartNoAckMode" => {
                    no_ack = true;
                    "OK".to_string()
                }
                p if p.starts_with("qSupported") => {
                    "PacketSize=4096;QStartNoAckMode+;qXfer:features:read+;swbreak+;hwbreak+"
                        .to_string()
                }
                p if p.starts_with("qXfer:features:read:target.xml:") => {
                    handle_xfer_xml(&p["qXfer:features:read:target.xml:".len()..])
                }
                "qC" => "QC1".to_string(),
                "qfThreadInfo" => "m1".to_string(),
                "qsThreadInfo" => "l".to_string(),
                p if p.starts_with("Hg") || p.starts_with("Hc") => "OK".to_string(),
                "g" => read_all_regs_hex(emu)?,
                p if p.starts_with('G') => {
                    write_all_regs_hex(emu, &p[1..])?;
                    "OK".to_string()
                }
                p if p.starts_with('p') => read_single_reg_hex(emu, &p[1..]),
                p if p.starts_with('P') => write_single_reg_hex(emu, &p[1..]),
                p if p.starts_with('m') => read_mem_hex(emu, &p[1..]),
                p if p.starts_with('M') => write_mem_hex(emu, &p[1..]),
                p if p.starts_with("Z0,") || p.starts_with("Z1,") => {
                    if let Some(addr) = parse_bp_addr(&p[3..]) {
                        if let Ok(mut bps) = breakpoints.lock() {
                            bps.insert(addr);
                        }
                        "OK".to_string()
                    } else {
                        "E01".to_string()
                    }
                }
                p if p.starts_with("z0,") || p.starts_with("z1,") => {
                    if let Some(addr) = parse_bp_addr(&p[3..]) {
                        if let Ok(mut bps) = breakpoints.lock() {
                            bps.remove(&addr);
                        }
                        "OK".to_string()
                    } else {
                        "E01".to_string()
                    }
                }
                "s" => step_once(emu),
                "c" => continue_exec(emu, &breakpoints),
                "D" => {
                    send_rsp_packet(&mut stream, "OK")?;
                    break;
                }
                "k" => break,
                _ => String::new(),
            };

            send_rsp_packet(&mut stream, &resp)?;
        }

        Ok(())
    }
}

fn read_rsp_packet(reader: &mut BufReader<TcpStream>) -> Result<Option<String>> {
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                if byte[0] == b'$' {
                    break;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    let mut payload = Vec::new();
    loop {
        if reader.read(&mut byte)? == 0 {
            return Ok(None);
        }
        if byte[0] == b'#' {
            break;
        }
        payload.push(byte[0]);
    }
    // 读取 2 字节校验和
    let mut csum = [0u8; 2];
    reader.read_exact(&mut csum)?;

    Ok(Some(String::from_utf8_lossy(&payload).into_owned()))
}

fn send_rsp_packet(stream: &mut TcpStream, payload: &str) -> Result<()> {
    let checksum: u8 = payload
        .as_bytes()
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    let frame = format!("${payload}#{checksum:02x}");
    stream.write_all(frame.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn handle_xfer_xml(spec: &str) -> String {
    let mut parts = spec.split(',');
    let offset = parts
        .next()
        .and_then(|s| usize::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let length = parts
        .next()
        .and_then(|s| usize::from_str_radix(s, 16).ok())
        .unwrap_or(1024);
    let bytes = AARCH64_TARGET_XML.as_bytes();
    if offset >= bytes.len() {
        return "l".to_string();
    }
    let end = offset.saturating_add(length).min(bytes.len());
    let prefix = if end >= bytes.len() { 'l' } else { 'm' };
    format!("{prefix}{}", &AARCH64_TARGET_XML[offset..end])
}

fn read_all_regs_hex(emu: &AndroidEmulator) -> Result<String> {
    let mut out = String::with_capacity(33 * 16 + 8);
    for (idx, &reg) in CORE_REGS.iter().enumerate() {
        let val = emu.uc().reg_read(reg)?;
        if idx == 33 {
            // cpsr / nzcv: 32-bit LE
            for b in (val as u32).to_le_bytes() {
                out.push_str(&format!("{b:02x}"));
            }
        } else {
            for b in val.to_le_bytes() {
                out.push_str(&format!("{b:02x}"));
            }
        }
    }
    Ok(out)
}

fn write_all_regs_hex(emu: &mut AndroidEmulator, hex: &str) -> Result<()> {
    let bytes = decode_hex(hex)?;
    let mut off = 0usize;
    for (idx, &reg) in CORE_REGS.iter().enumerate() {
        if idx == 33 {
            if off + 4 <= bytes.len() {
                let v = u32::from_le_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                ]);
                emu.uc_mut().reg_write(reg, u64::from(v))?;
            }
            break;
        }
        if off + 8 > bytes.len() {
            break;
        }
        let v = u64::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        emu.uc_mut().reg_write(reg, v)?;
        off += 8;
    }
    Ok(())
}

fn read_single_reg_hex(emu: &AndroidEmulator, idx_hex: &str) -> String {
    let Ok(idx) = usize::from_str_radix(idx_hex, 16) else {
        return "E01".to_string();
    };
    let Some(&reg) = CORE_REGS.get(idx) else {
        return "0000000000000000".to_string();
    };
    let Ok(val) = emu.uc().reg_read(reg) else {
        return "E02".to_string();
    };
    if idx == 33 {
        encode_hex(&(val as u32).to_le_bytes())
    } else {
        encode_hex(&val.to_le_bytes())
    }
}

fn write_single_reg_hex(emu: &mut AndroidEmulator, body: &str) -> String {
    let Some((idx_hex, val_hex)) = body.split_once('=') else {
        return "E01".to_string();
    };
    let Ok(idx) = usize::from_str_radix(idx_hex, 16) else {
        return "E01".to_string();
    };
    let Some(&reg) = CORE_REGS.get(idx) else {
        return "E01".to_string();
    };
    let Ok(bytes) = decode_hex(val_hex) else {
        return "E01".to_string();
    };
    let val = if bytes.len() >= 8 {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    } else if bytes.len() >= 4 {
        u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    } else {
        return "E01".to_string();
    };
    if emu.uc_mut().reg_write(reg, val).is_ok() {
        "OK".to_string()
    } else {
        "E02".to_string()
    }
}

fn read_mem_hex(emu: &AndroidEmulator, spec: &str) -> String {
    let Some((addr_hex, len_hex)) = spec.split_once(',') else {
        return "E01".to_string();
    };
    let (Ok(addr), Ok(len)) = (
        u64::from_str_radix(addr_hex, 16),
        usize::from_str_radix(len_hex, 16),
    ) else {
        return "E01".to_string();
    };
    let mut buf = vec![0u8; len.min(64 * 1024)];
    match emu.uc().mem_read(addr, &mut buf) {
        Ok(()) => encode_hex(&buf),
        Err(_) => "E0E".to_string(),
    }
}

fn write_mem_hex(emu: &mut AndroidEmulator, spec: &str) -> String {
    let Some((header, data_hex)) = spec.split_once(':') else {
        return "E01".to_string();
    };
    let Some((addr_hex, _len_hex)) = header.split_once(',') else {
        return "E01".to_string();
    };
    let (Ok(addr), Ok(bytes)) = (u64::from_str_radix(addr_hex, 16), decode_hex(data_hex)) else {
        return "E01".to_string();
    };
    if emu.uc_mut().mem_write(addr, &bytes).is_ok() {
        let page_start = addr & !0xfff;
        let page_end = (addr + bytes.len() as u64 + 0xfff) & !0xfff;
        let _ = emu.uc_mut().ctl_remove_cache(page_start, page_end);
        "OK".to_string()
    } else {
        "E0E".to_string()
    }
}

fn parse_bp_addr(spec: &str) -> Option<u64> {
    let addr_hex = spec.split(',').next()?;
    u64::from_str_radix(addr_hex, 16).ok()
}

fn step_once(emu: &mut AndroidEmulator) -> String {
    let Ok(pc) = emu.uc().reg_read(RegisterARM64::PC) else {
        return "S0b".to_string();
    };
    if pc == RET_MAGIC_ADDR {
        return "W00".to_string();
    }
    match emu.uc_mut().emu_start(pc, RET_MAGIC_ADDR, 0, 1) {
        Ok(()) => {
            let next_pc = emu.uc().reg_read(RegisterARM64::PC).unwrap_or(0);
            if next_pc == RET_MAGIC_ADDR {
                "W00".to_string()
            } else {
                "S05".to_string()
            }
        }
        Err(_) => "S0b".to_string(),
    }
}

fn continue_exec(emu: &mut AndroidEmulator, breakpoints: &Arc<Mutex<HashSet<u64>>>) -> String {
    let Ok(start_pc) = emu.uc().reg_read(RegisterARM64::PC) else {
        return "S0b".to_string();
    };
    if start_pc == RET_MAGIC_ADDR {
        return "W00".to_string();
    }

    let bps_snapshot: HashSet<u64> = breakpoints
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();

    // 若当前 PC 恰好停在某个断点上，先单步越过当前指令再继续运行
    let resume_pc = if bps_snapshot.contains(&start_pc) {
        if emu.uc_mut().emu_start(start_pc, RET_MAGIC_ADDR, 0, 1).is_err() {
            return "S0b".to_string();
        }
        let next = emu.uc().reg_read(RegisterARM64::PC).unwrap_or(RET_MAGIC_ADDR);
        if next == RET_MAGIC_ADDR {
            return "W00".to_string();
        }
        if bps_snapshot.contains(&next) {
            return "S05".to_string();
        }
        next
    } else {
        start_pc
    };

    let hook_id = if !bps_snapshot.is_empty() {
        let bps = bps_snapshot;
        // 清除断点所在页的 Unicorn TB 缓存确保命中
        for &bp in &bps {
            let p = bp & !0xfff;
            let _ = emu.uc_mut().ctl_remove_cache(p, p + 0x1000);
        }
        emu.uc_mut()
            .add_code_hook(0, u64::MAX, move |uc, addr, _size| {
                if bps.contains(&addr) {
                    let _ = uc.emu_stop();
                }
            })
            .ok()
    } else {
        None
    };

    let res = emu.uc_mut().emu_start(resume_pc, RET_MAGIC_ADDR, 0, 0);
    if let Some(h) = hook_id {
        let _ = emu.uc_mut().remove_hook(h);
    }

    match res {
        Ok(()) => {
            let end_pc = emu.uc().reg_read(RegisterARM64::PC).unwrap_or(0);
            if end_pc == RET_MAGIC_ADDR {
                "W00".to_string()
            } else {
                "S05".to_string()
            }
        }
        Err(_) => "S0b".to_string(),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!("无效的十六进制长度"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16)?;
        out.push(b);
    }
    Ok(out)
}
