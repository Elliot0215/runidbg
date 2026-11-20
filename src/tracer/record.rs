use std::mem::size_of;

/// 分层 Trace 级别：按逆向需求在吞吐速度与信息完整度之间自由切换
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceLevel {
    /// 极速模式：仅记录 PC + Opcode + 指令序号（零寄存器采样，适合覆盖率/控制流追踪）
    Fast,
    /// 增量寄存器模式（默认）：采样 X0..X30 + SP 并计算增量位图，多寄存器变化自动写入扩展流
    RegDelta,
    /// 全量模式：在 RegDelta 基础上配合内存 R/W Hook 记录所有访存地址与数据
    Full,
}

/// 扩展流事件类型（写入 `trace.ext`）
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKind {
    MemRead = 1,
    MemWrite = 2,
    /// 单条指令触发多个寄存器变化时（如 `LDP`/`STP`），除主寄存器外的其余变化
    RegDeltaExtra = 3,
}

impl ExtKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::MemRead),
            2 => Some(Self::MemWrite),
            3 => Some(Self::RegDeltaExtra),
            _ => None,
        }
    }
}

/// 热路径定长二进制主索引记录（`trace.idx`，固定 32 字节，每 64B Cache Line 容纳 2 条）
///
/// 设计要点：
/// - `#[repr(C, packed)]` 消除结构体填充字节，保证跨平台二进制落盘格式紧凑确定
/// - 热路径严禁字符串格式化、严禁 `String`/`Vec` 动态扩容
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct TraceRecord {
    /// 指令地址 (PC)
    pub pc: u64,
    /// ARM64 32-bit 原始机器码（小端）
    pub opcode: u32,
    /// 增量寄存器变化位图：bit 0..=30 对应 X0..=X30，bit 31 对应 SP
    pub reg_diff_mask: u32,
    /// 首个发生变化的寄存器索引 (0..=31)，0xFF 表示无寄存器变化
    pub primary_reg_id: u8,
    /// 预留标志/对齐字节（`_reserved[0]` bit0=1 表示该指令在 `trace.ext` 中存在关联扩展记录）
    pub _reserved: [u8; 3],
    /// `primary_reg_id` 对应寄存器变化后的新值
    pub primary_reg_val: u64,
    /// 指令执行序号（低 32 位，用于与 `trace.ext` 精确关联及回溯定位）
    pub seq_low32: u32,
}

const _: () = assert!(size_of::<TraceRecord>() == 32);

/// 扩展事件定长二进制记录（`trace.ext`，固定 32 字节）
/// 用于记录内存读写事件以及单条指令的多寄存器增量变化，通过 `seq_low32` 与 `trace.idx` 关联
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ExtRecord {
    /// 关联的指令序号（对应 `TraceRecord.seq_low32`）
    pub seq_low32: u32,
    /// 事件类型（见 `ExtKind`）
    pub kind: u8,
    /// 访存字节数（1/2/4/8）或额外变化的寄存器编号（0..=31）
    pub size_or_reg: u8,
    pub _pad: [u8; 2],
    /// 访存虚拟地址（`MemRead`/`MemWrite`）或保留 0
    pub addr: u64,
    /// 访存读写值或寄存器新值
    pub value: u64,
    /// 触发该事件时的指令 PC
    pub pc: u64,
}

const _: () = assert!(size_of::<ExtRecord>() == 32);

/// 指令地址范围过滤器（空列表表示不过滤，全量记录）
#[derive(Debug, Default, Clone)]
pub struct TraceFilter {
    allow_ranges: Vec<(u64, u64)>,
}

impl TraceFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加允许记录的 `[start, end)` 地址区间（例如仅追踪目标 `.so` 代码段，跳过 libc 噪声）
    pub fn allow_range(&mut self, start: u64, end: u64) -> &mut Self {
        self.allow_ranges.push((start, end));
        self
    }

    #[inline(always)]
    pub fn matches(&self, addr: u64) -> bool {
        if self.allow_ranges.is_empty() {
            return true;
        }
        self.allow_ranges
            .iter()
            .any(|&(s, e)| addr >= s && addr < e)
    }
}

/// 执行统计信息
#[derive(Debug, Default, Clone, Copy)]
pub struct TraceStats {
    pub total_insns: u64,
    pub recorded_insns: u64,
    pub dropped_insns: u64,
    pub recorded_ext: u64,
    pub dropped_ext: u64,
}

pub(crate) fn format_reg_name(reg_id: u8) -> String {
    if reg_id == 31 {
        "SP".to_string()
    } else {
        format!("X{reg_id}")
    }
}

/// 若小端字节序列为 4 字节或 8 字节全可打印 ASCII（且非全空格），返回可读旁注（如 ` ("3019")`）
pub fn format_ascii_hint(value: u64, byte_width: u8) -> Option<String> {
    let bytes_all = value.to_le_bytes();
    let slice: &[u8] = match byte_width {
        4 => &bytes_all[..4],
        8 => {
            if value <= u32::MAX as u64 && value != 0 {
                &bytes_all[..4]
            } else {
                &bytes_all[..8]
            }
        }
        _ => return None,
    };
    if slice.iter().all(|&b| (0x20..=0x7E).contains(&b)) && slice.iter().any(|&b| b != b' ') {
        let s = std::str::from_utf8(slice).ok()?;
        Some(format!(" (\"{s}\")"))
    } else {
        None
    }
}

/// 冷路径辅助：解码单条指令并附加已正确归属的执行后主寄存器变更
pub fn decode_instruction_with_reg(pc: u64, opcode: u32, reg_delta: Option<(u8, u64)>) -> String {
    let disasm = match bad64::decode(opcode, pc) {
        Ok(insn) => insn.to_string(),
        Err(_) => format!(".word 0x{opcode:08x}"),
    };

    if let Some((reg_id, reg_val)) = reg_delta {
        let reg_name = format_reg_name(reg_id);
        let hint = format_ascii_hint(reg_val, 8).unwrap_or_default();
        format!("0x{pc:016x}: {disasm:<32} ; {reg_name} <- 0x{reg_val:016x}{hint}")
    } else {
        format!("0x{pc:016x}: {disasm}")
    }
}

/// 冷路径辅助：利用 `bad64` 零堆分配解码器对单条 Trace 记录进行离线反汇编
pub fn decode_trace_record(record: &TraceRecord) -> String {
    let pc = record.pc;
    let opcode = record.opcode;
    let reg_id = record.primary_reg_id;
    let reg_val = record.primary_reg_val;
    let delta = (reg_id != 0xFF).then_some((reg_id, reg_val));
    decode_instruction_with_reg(pc, opcode, delta)
}

/// 冷路径辅助：格式化单条扩展事件记录
pub fn format_ext_record(ext: &ExtRecord) -> String {
    let kind = ExtKind::from_u8(ext.kind);
    let addr = ext.addr;
    let value = ext.value;
    let size_or_reg = ext.size_or_reg;
    match kind {
        Some(ExtKind::MemRead) => {
            let hint = format_ascii_hint(value, size_or_reg).unwrap_or_default();
            format!("    [MEM R{size_or_reg}] [0x{addr:016x}] -> 0x{value:016x}{hint}")
        }
        Some(ExtKind::MemWrite) => {
            let hint = format_ascii_hint(value, size_or_reg).unwrap_or_default();
            format!("    [MEM W{size_or_reg}] [0x{addr:016x}] <- 0x{value:016x}{hint}")
        }
        Some(ExtKind::RegDeltaExtra) => {
            let name = format_reg_name(size_or_reg);
            let hint = format_ascii_hint(value, 8).unwrap_or_default();
            format!("    [REG] {name} <- 0x{value:016x}{hint}")
        }
        None => format!("    [EXT?] kind={} val=0x{value:016x}", ext.kind),
    }
}
