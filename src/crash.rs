use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use unicorn_engine::{RegisterARM64, Unicorn};

use crate::loader::DynamicLinker;
use crate::memory::MemoryManager;

const MAX_BREADCRUMBS: usize = 32;

/// 轻量级环形事件缓冲：记录最近 32 条外部交互（HLE / JNI / Syscall），供崩溃报告回溯前因
#[derive(Debug, Clone, Default)]
pub struct BreadcrumbRing {
    buf: Arc<Mutex<VecDeque<String>>>,
}

impl BreadcrumbRing {
    pub fn new() -> Self {
        Self {
            buf: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_BREADCRUMBS))),
        }
    }

    pub fn push(&self, entry: impl Into<String>) {
        if let Ok(mut g) = self.buf.lock() {
            if g.len() >= MAX_BREADCRUMBS {
                g.pop_front();
            }
            g.push_back(entry.into());
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<String> {
        let Ok(g) = self.buf.lock() else {
            return Vec::new();
        };
        let skip = g.len().saturating_sub(limit);
        g.iter().skip(skip).cloned().collect()
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.buf.lock() {
            g.clear();
        }
    }
}

#[derive(Debug, Clone)]
pub struct DisasmLine {
    pub addr: u64,
    pub word: u32,
    pub asm: String,
    pub is_pc: bool,
}

#[derive(Debug, Clone)]
pub struct BacktraceFrame {
    pub index: usize,
    pub addr: u64,
    pub location: String,
}

/// ARM64 Guest 崩溃现场完整报告（零正常执行开销，仅在异常/超时时采集）
#[derive(Debug, Clone)]
pub struct CrashReport {
    pub reason: String,
    pub pc: u64,
    pub pc_location: String,
    pub lr: u64,
    pub lr_location: String,
    pub sp: u64,
    pub fp: u64,
    pub nzcv: u64,
    pub x: [u64; 31],
    pub disasm: Vec<DisasmLine>,
    pub backtrace: Vec<BacktraceFrame>,
    pub stack_preview: Vec<(u64, u64)>,
    pub breadcrumbs: Vec<String>,
    pub vma_summary: Vec<String>,
}

const X_REGS: [RegisterARM64; 31] = [
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
];

impl CrashReport {
    /// 从当前 Unicorn 现场采集完整崩溃报告
    pub fn capture<D>(
        uc: &Unicorn<'_, D>,
        linker: &DynamicLinker,
        mem: &MemoryManager,
        breadcrumbs: &BreadcrumbRing,
        reason: impl Into<String>,
    ) -> Self {
        let mut x = [0u64; 31];
        for (i, &reg) in X_REGS.iter().enumerate() {
            x[i] = uc.reg_read(reg).unwrap_or(0);
        }
        let pc = uc.reg_read(RegisterARM64::PC).unwrap_or(0);
        let sp = uc.reg_read(RegisterARM64::SP).unwrap_or(0);
        let lr = x[30];
        let fp = x[29];
        let nzcv = uc.reg_read(RegisterARM64::NZCV).unwrap_or(0);

        let pc_location = resolve_location(linker, pc);
        let lr_location = resolve_location(linker, lr);

        // 反汇编 [PC - 16, PC + 16]（最多 9 条 ARM64 指令）
        let mut disasm = Vec::with_capacity(9);
        let start_pc = pc.saturating_sub(16) & !3;
        for i in 0..9u64 {
            let addr = start_pc.saturating_add(i * 4);
            let mut raw = [0u8; 4];
            if uc.mem_read(addr, &mut raw).is_ok() {
                let word = u32::from_le_bytes(raw);
                let asm = match bad64::decode(word, addr) {
                    Ok(inst) => format!("{inst}"),
                    Err(_) => format!(".word 0x{word:08x}"),
                };
                disasm.push(DisasmLine {
                    addr,
                    word,
                    asm,
                    is_pc: addr == (pc & !3),
                });
            }
        }

        // ARM64 FP (x29) 帧指针调用栈回溯（最多 16 帧）
        let mut backtrace = Vec::new();
        backtrace.push(BacktraceFrame {
            index: 0,
            addr: pc,
            location: pc_location.clone(),
        });
        if lr != 0 {
            backtrace.push(BacktraceFrame {
                index: 1,
                addr: lr,
                location: lr_location.clone(),
            });
        }
        let mut cur_fp = fp;
        for frame_idx in 2..16usize {
            if cur_fp == 0 || !cur_fp.is_multiple_of(8) {
                break;
            }
            let mut pair = [0u8; 16];
            if uc.mem_read(cur_fp, &mut pair).is_err() {
                break;
            }
            let next_fp = u64::from_le_bytes([
                pair[0], pair[1], pair[2], pair[3], pair[4], pair[5], pair[6], pair[7],
            ]);
            let saved_lr = u64::from_le_bytes([
                pair[8], pair[9], pair[10], pair[11], pair[12], pair[13], pair[14], pair[15],
            ]);
            if saved_lr == 0 {
                break;
            }
            backtrace.push(BacktraceFrame {
                index: frame_idx,
                addr: saved_lr,
                location: resolve_location(linker, saved_lr),
            });
            if next_fp == 0 || next_fp <= cur_fp || next_fp - cur_fp > 0x10_0000 {
                break;
            }
            cur_fp = next_fp;
        }

        // 栈顶 64 字节预览（8 个 u64）
        let mut stack_preview = Vec::new();
        if sp != 0 {
            let mut buf = [0u8; 64];
            if uc.mem_read(sp, &mut buf).is_ok() {
                for (i, chunk) in buf.as_chunks::<8>().0.iter().enumerate() {
                    stack_preview.push((sp + (i as u64) * 8, u64::from_le_bytes(*chunk)));
                }
            }
        }

        let vma_summary: Vec<String> = mem
            .format_proc_maps()
            .lines()
            .take(32)
            .map(ToString::to_string)
            .collect();

        Self {
            reason: reason.into(),
            pc,
            pc_location,
            lr,
            lr_location,
            sp,
            fp,
            nzcv,
            x,
            disasm,
            backtrace,
            stack_preview,
            breadcrumbs: breadcrumbs.recent(16),
            vma_summary,
        }
    }

    /// 渲染人类可读的多段式崩溃现场报告
    pub fn format_pretty(&self) -> String {
        let mut out = String::new();
        out.push_str("==================== runidbg Guest Crash Report ====================\n");
        out.push_str(&format!("Reason   : {}\n", self.reason));
        out.push_str(&format!(
            "Fault PC : 0x{:016x} ({})\n",
            self.pc, self.pc_location
        ));
        out.push_str(&format!(
            "Return LR: 0x{:016x} ({})\n",
            self.lr, self.lr_location
        ));
        out.push_str(&format!(
            "SP / FP  : SP=0x{:016x}  FP=0x{:016x}  NZCV=0x{:08x}\n",
            self.sp, self.fp, self.nzcv
        ));
        if let Some(null_jni) = self
            .breadcrumbs
            .iter()
            .rev()
            .find(|b| b.contains("-> NULL"))
        {
            out.push_str(&format!("Suspected: 疑似根因 -> {null_jni}\n"));
        }

        if !self.disasm.is_empty() {
            out.push_str("\n--- Disassembly (ARM64) ---\n");
            for line in &self.disasm {
                let marker = if line.is_pc { ">>>" } else { "   " };
                out.push_str(&format!(
                    "{marker} 0x{:016x}: {:08x}  {}\n",
                    line.addr, line.word, line.asm
                ));
            }
        }

        out.push_str("\n--- Registers ---\n");
        for row in 0..8 {
            for col in 0..4 {
                let idx = row * 4 + col;
                if idx < 31 {
                    out.push_str(&format!("x{idx:<2}=0x{:016x}  ", self.x[idx]));
                }
            }
            out.push('\n');
        }

        if !self.backtrace.is_empty() {
            out.push_str("\n--- Backtrace (FP Chain) ---\n");
            for f in &self.backtrace {
                out.push_str(&format!(
                    "  #{:<2} 0x{:016x}  {}\n",
                    f.index, f.addr, f.location
                ));
            }
        }

        if !self.breadcrumbs.is_empty() {
            out.push_str("\n--- Recent Breadcrumbs (HLE / JNI / Syscall) ---\n");
            for (i, b) in self.breadcrumbs.iter().enumerate() {
                out.push_str(&format!("  [{i:02}] {b}\n"));
            }
        }

        if !self.stack_preview.is_empty() {
            out.push_str("\n--- Stack Top ---\n");
            for (addr, val) in &self.stack_preview {
                out.push_str(&format!("  [0x{addr:016x}] = 0x{val:016x}\n"));
            }
        }

        if !self.vma_summary.is_empty() {
            out.push_str("\n--- Memory Maps (VMA) ---\n");
            for line in &self.vma_summary {
                out.push_str(&format!("  {line}\n"));
            }
        }
        out.push_str("====================================================================");
        out
    }
}

impl fmt::Display for CrashReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_pretty())
    }
}

/// 将任意 Guest 地址解析为 `module+0xoffset (nearest_symbol+0xdelta)`
pub fn resolve_location(linker: &DynamicLinker, addr: u64) -> String {
    if addr == crate::cpu::RET_MAGIC_ADDR {
        return "<RET_MAGIC_ADDR>".to_string();
    }
    for name in linker.load_order() {
        if let Some(m) = linker.get_module(name) {
            let end = m.base_addr.saturating_add(m.image_size);
            if addr >= m.base_addr && addr < end {
                let off = addr - m.base_addr;
                // 查找最接近且 <= addr 的导出符号
                let mut best: Option<(&str, u64)> = None;
                for (sym, &sym_addr) in &m.symbols {
                    if sym_addr <= addr {
                        let delta = addr - sym_addr;
                        if best.is_none_or(|(_, d)| delta < d) {
                            best = Some((sym.as_str(), delta));
                        }
                    }
                }
                if let Some((sym, delta)) = best {
                    if delta < 0x10_0000 {
                        return format!("{name}+0x{off:x} ({sym}+0x{delta:x})");
                    }
                }
                return format!("{name}+0x{off:x}");
            }
        }
    }
    "<unknown>".to_string()
}
