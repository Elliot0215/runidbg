//! `good64` 词法与操作数解析：GPR / FP / NEON 向量与元素 / 扩展与移位 / 完整访存 / 系统寄存器 / 屏障域

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

/// 通用整数寄存器（区分 `SP/WSP` 与 `XZR/WZR`）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reg {
    pub num: u8,
    pub is_64: bool,
    pub is_sp: bool,
}

impl Reg {
    #[inline]
    pub fn is_zr(self) -> bool {
        self.num == 31 && !self.is_sp
    }

    pub fn require_gpr_or_zr(self, ctx: &str) -> Result<u32> {
        if self.is_sp {
            bail!("{ctx}: 此操作数不支持 SP/WSP");
        }
        Ok(u32::from(self.num))
    }

    pub fn require_gpr_or_sp(self, ctx: &str) -> Result<u32> {
        if self.is_zr() {
            bail!("{ctx}: 此操作数不支持 XZR/WZR");
        }
        Ok(u32::from(self.num))
    }

    pub fn require_64(self, ctx: &str) -> Result<Self> {
        if !self.is_64 {
            bail!("{ctx}: 需要 64 位寄存器 (Xn)");
        }
        Ok(self)
    }

    pub fn require_32(self, ctx: &str) -> Result<Self> {
        if self.is_64 {
            bail!("{ctx}: 需要 32 位寄存器 (Wn)");
        }
        Ok(self)
    }
}

/// 标量浮点/SIMD 寄存器：`b0..31` / `h0..31` / `s0..31` / `d0..31` / `q0..31`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FpWidth {
    B = 0, // 8-bit
    H = 1, // 16-bit
    S = 2, // 32-bit
    D = 3, // 64-bit
    Q = 4, // 128-bit
}

impl FpWidth {
    #[inline]
    pub fn byte_size(self) -> i64 {
        1i64 << (self as u32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FpReg {
    pub num: u8,
    pub width: FpWidth,
}

/// NEON 向量排布：`8b` / `16b` / `4h` / `8h` / `2s` / `4s` / `2d`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VecArrange {
    B8,
    B16,
    H4,
    H8,
    S2,
    S4,
    D2,
}

impl VecArrange {
    #[inline]
    pub fn is_128(self) -> bool {
        matches!(self, Self::B16 | Self::H8 | Self::S4 | Self::D2)
    }

    #[inline]
    pub fn q_bit(self) -> u32 {
        u32::from(self.is_128()) << 30
    }

    /// 元素大小编码：b=0, h=1, s=2, d=3
    #[inline]
    pub fn elem_size(self) -> u32 {
        match self {
            Self::B8 | Self::B16 => 0,
            Self::H4 | Self::H8 => 1,
            Self::S2 | Self::S4 => 2,
            Self::D2 => 3,
        }
    }

    #[inline]
    pub fn elem_bits(self) -> u32 {
        8u32 << self.elem_size()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VecReg {
    pub num: u8,
    pub arrange: VecArrange,
}

/// NEON 向量元素：`v0.b[3]` / `v1.h[2]` / `v2.s[1]` / `v3.d[0]`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VecElem {
    pub num: u8,
    /// 元素大小：0=b, 1=h, 2=s, 3=d
    pub elem_size: u8,
    pub index: u8,
}

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Int(i128),
    Sym(String),
    SymOffset(String, i128),
}

impl Expr {
    pub fn eval_addr(&self, labels: &HashMap<String, u64>) -> Result<u64> {
        match self {
            Self::Int(v) => check_int_range(*v, true, "地址/数据表达式"),
            Self::Sym(name) => labels
                .get(name)
                .copied()
                .ok_or_else(|| anyhow!("未定义的标签: '{name}'")),
            Self::SymOffset(name, off) => {
                let base = labels
                    .get(name)
                    .copied()
                    .ok_or_else(|| anyhow!("未定义的标签: '{name}'"))?;
                let delta = i64::try_from(*off)
                    .map_err(|_| anyhow!("标签偏移超出 64 位范围: {off}"))?;
                Ok(base.wrapping_add(delta as u64))
            }
        }
    }
}

pub(crate) fn check_int_range(val: i128, is_64: bool, ctx: &str) -> Result<u64> {
    if is_64 {
        if val < i128::from(i64::MIN) || val > i128::from(u64::MAX) {
            bail!("{ctx}: 立即数 {val} 超出 64 位整数范围");
        }
        Ok(val as u64)
    } else {
        if val < i128::from(i32::MIN) || val > i128::from(u32::MAX) {
            bail!("{ctx}: 立即数 {val} 超出 32 位整数范围");
        }
        Ok((val as u64) & 0xFFFF_FFFF)
    }
}

fn parse_strict_u8(s: &str) -> Option<u8> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

fn parse_strict_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShiftKind {
    Lsl = 0,
    Lsr = 1,
    Asr = 2,
    Ror = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtendKind {
    Uxtb = 0,
    Uxth = 1,
    Uxtw = 2,
    Uxtx = 3,
    Sxtb = 4,
    Sxth = 5,
    Sxtw = 6,
    Sxtx = 7,
}

#[derive(Debug, Clone)]
pub(crate) enum MemAddr {
    /// `[base]` 或 `[base, #imm]`
    Offset { base: Reg, off: i64 },
    /// `[base, #imm]!`
    PreIndex { base: Reg, off: i64 },
    /// `[base], #imm`
    PostIndex { base: Reg, off: i64 },
    /// `[base, Rm{, lsl/uxtw/sxtw/sxtx #s}]`
    RegOffset {
        base: Reg,
        index: Reg,
        /// ARM64 option: uxtw=0b010, lsl=0b011, sxtw=0b110, sxtx=0b111
        option: u32,
        /// 显式移位量（None 表示未写移位修饰，S=0）
        shift: Option<u8>,
    },
}

/// 按逗号分割操作数，保留 `[ ... ]` 与 `{ ... }` 内部逗号
pub(crate) fn split_operands(rest: &str) -> Result<Vec<String>> {
    if rest.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut bracket_depth = 0i32;
    let mut brace_depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in rest.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => {
                bracket_depth -= 1;
                if bracket_depth < 0 {
                    bail!("不匹配的 ']'");
                }
            }
            '{' => brace_depth += 1,
            '}' => {
                brace_depth -= 1;
                if brace_depth < 0 {
                    bail!("不匹配的 '}}'");
                }
            }
            ',' if bracket_depth == 0 && brace_depth == 0 => {
                let tok = rest[start..i].trim();
                if tok.is_empty() {
                    bail!("空操作数");
                }
                out.push(tok.to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if bracket_depth != 0 {
        bail!("未闭合的 '['");
    }
    if brace_depth != 0 {
        bail!("未闭合的 '{{'");
    }
    let tail = rest[start..].trim();
    if tail.is_empty() {
        bail!("末尾存在空操作数");
    }
    out.push(tail.to_string());
    Ok(out)
}

pub(crate) fn parse_reg(tok: &str) -> Option<Reg> {
    let s = tok.trim().to_ascii_lowercase();
    match s.as_str() {
        "sp" => Some(Reg {
            num: 31,
            is_64: true,
            is_sp: true,
        }),
        "wsp" => Some(Reg {
            num: 31,
            is_64: false,
            is_sp: true,
        }),
        "xzr" => Some(Reg {
            num: 31,
            is_64: true,
            is_sp: false,
        }),
        "wzr" => Some(Reg {
            num: 31,
            is_64: false,
            is_sp: false,
        }),
        "fp" => Some(Reg {
            num: 29,
            is_64: true,
            is_sp: false,
        }),
        "lr" => Some(Reg {
            num: 30,
            is_64: true,
            is_sp: false,
        }),
        _ => {
            let (is_64, rest) = if let Some(r) = s.strip_prefix('x') {
                (true, r)
            } else {
                (false, s.strip_prefix('w')?)
            };
            let n = parse_strict_u8(rest)?;
            if n <= 30 {
                Some(Reg {
                    num: n,
                    is_64,
                    is_sp: false,
                })
            } else {
                None
            }
        }
    }
}

pub(crate) fn parse_fp_reg(tok: &str) -> Option<FpReg> {
    let s = tok.trim().to_ascii_lowercase();
    let bytes = s.as_bytes();
    let width = match *bytes.first()? {
        b'b' => FpWidth::B,
        b'h' => FpWidth::H,
        b's' => FpWidth::S,
        b'd' => FpWidth::D,
        b'q' => FpWidth::Q,
        _ => return None,
    };
    let rest = &s[1..];
    let num = parse_strict_u8(rest)?;
    if num <= 31 {
        Some(FpReg { num, width })
    } else {
        None
    }
}

pub(crate) fn parse_vec_reg(tok: &str) -> Option<VecReg> {
    let s = tok.trim().to_ascii_lowercase();
    let (head, arr) = s.split_once('.')?;
    if arr.contains('[') {
        return None;
    }
    let num = parse_strict_u8(head.strip_prefix('v')?)?;
    if num > 31 {
        return None;
    }
    let arrange = match arr {
        "8b" => VecArrange::B8,
        "16b" => VecArrange::B16,
        "4h" => VecArrange::H4,
        "8h" => VecArrange::H8,
        "2s" => VecArrange::S2,
        "4s" => VecArrange::S4,
        "2d" => VecArrange::D2,
        _ => return None,
    };
    Some(VecReg { num, arrange })
}

pub(crate) fn parse_vec_elem(tok: &str) -> Option<VecElem> {
    let s = tok.trim().to_ascii_lowercase();
    let (head, tail) = s.split_once('.')?;
    let num = parse_strict_u8(head.strip_prefix('v')?)?;
    if num > 31 {
        return None;
    }
    let (es_str, idx_br) = tail.split_once('[')?;
    let idx_str = idx_br.strip_suffix(']')?;
    let index = parse_strict_u8(idx_str)?;
    let (elem_size, max_idx) = match es_str {
        "b" => (0u8, 15u8),
        "h" => (1u8, 7u8),
        "s" => (2u8, 3u8),
        "d" => (3u8, 1u8),
        _ => return None,
    };
    if index > max_idx {
        return None;
    }
    Some(VecElem {
        num,
        elem_size,
        index,
    })
}

pub(crate) fn parse_imm(tok: &str) -> Result<i128> {
    let s = tok.trim();
    let s = s.strip_prefix('#').unwrap_or(s).trim();
    parse_int_literal(s)
}

pub(crate) fn parse_int_literal(s: &str) -> Result<i128> {
    let s = s.trim();
    let (neg, body) = if let Some(r) = s.strip_prefix('-') {
        (true, r.trim())
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r.trim())
    } else {
        (false, s)
    };
    if body.is_empty() || body.starts_with('+') || body.starts_with('-') {
        bail!("无效立即数: '{s}'");
    }
    let cleaned: String = body.chars().filter(|&c| c != '_').collect();
    let mag: u128 = if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("无效十六进制立即数: '{s}'");
        }
        u128::from_str_radix(hex, 16).map_err(|_| anyhow!("无效十六进制立即数: '{s}'"))?
    } else if let Some(bin) = cleaned
        .strip_prefix("0b")
        .or_else(|| cleaned.strip_prefix("0B"))
    {
        if bin.is_empty() || !bin.bytes().all(|b| b == b'0' || b == b'1') {
            bail!("无效二进制立即数: '{s}'");
        }
        u128::from_str_radix(bin, 2).map_err(|_| anyhow!("无效二进制立即数: '{s}'"))?
    } else {
        if cleaned.is_empty() || !cleaned.bytes().all(|b| b.is_ascii_digit()) {
            bail!("无效立即数: '{s}'");
        }
        cleaned
            .parse::<u128>()
            .map_err(|_| anyhow!("无效立即数: '{s}'"))?
    };
    if mag > i128::MAX as u128 {
        bail!("立即数溢出: '{s}'");
    }
    if neg {
        Ok(-(mag as i128))
    } else {
        Ok(mag as i128)
    }
}

pub(crate) fn parse_expr(tok: &str) -> Result<Expr> {
    let s = tok.trim();
    let s_no_hash = s.strip_prefix('#').unwrap_or(s).trim();
    if let Ok(v) = parse_int_literal(s_no_hash) {
        return Ok(Expr::Int(v));
    }
    if let Some(pos) = s_no_hash.find(['+', '-']) {
        if pos > 0 {
            let sym = s_no_hash[..pos].trim();
            let off_str = s_no_hash[pos..].trim();
            if let Ok(off) = parse_int_literal(off_str) {
                return Ok(Expr::SymOffset(sym.to_string(), off));
            }
        }
    }
    Ok(Expr::Sym(s_no_hash.to_string()))
}

pub(crate) fn parse_shift(tok: &str) -> Result<(ShiftKind, u8)> {
    let parts: Vec<&str> = tok.split_whitespace().collect();
    if parts.len() != 2 {
        bail!("无效移位修饰符: '{tok}'");
    }
    let kind = match parts[0].to_ascii_lowercase().as_str() {
        "lsl" => ShiftKind::Lsl,
        "lsr" => ShiftKind::Lsr,
        "asr" => ShiftKind::Asr,
        "ror" => ShiftKind::Ror,
        _ => bail!("未知移位类型: '{}'", parts[0]),
    };
    let amt = parse_imm(parts[1])?;
    if !(0..=63).contains(&amt) {
        bail!("移位量超出范围: {amt}");
    }
    Ok((kind, amt as u8))
}

pub(crate) fn try_parse_extend(tok: &str) -> Option<Result<(ExtendKind, u8)>> {
    let parts: Vec<&str> = tok.split_whitespace().collect();
    if parts.is_empty() || parts.len() > 2 {
        return None;
    }
    let kind = match parts[0].to_ascii_lowercase().as_str() {
        "uxtb" => ExtendKind::Uxtb,
        "uxth" => ExtendKind::Uxth,
        "uxtw" => ExtendKind::Uxtw,
        "uxtx" => ExtendKind::Uxtx,
        "sxtb" => ExtendKind::Sxtb,
        "sxth" => ExtendKind::Sxth,
        "sxtw" => ExtendKind::Sxtw,
        "sxtx" => ExtendKind::Sxtx,
        _ => return None,
    };
    let amt = if parts.len() == 2 {
        match parse_imm(parts[1]) {
            Ok(v) if (0..=4).contains(&v) => v as u8,
            Ok(v) => return Some(Err(anyhow!("扩展左移量超出 [0, 4] 范围: {v}"))),
            Err(e) => return Some(Err(e)),
        }
    } else {
        0
    };
    Some(Ok((kind, amt)))
}

pub(crate) fn parse_cond(s: &str) -> Option<u32> {
    match s.to_ascii_lowercase().as_str() {
        "eq" => Some(0x0),
        "ne" => Some(0x1),
        "cs" | "hs" => Some(0x2),
        "cc" | "lo" => Some(0x3),
        "mi" => Some(0x4),
        "pl" => Some(0x5),
        "vs" => Some(0x6),
        "vc" => Some(0x7),
        "hi" => Some(0x8),
        "ls" => Some(0x9),
        "ge" => Some(0xA),
        "lt" => Some(0xB),
        "gt" => Some(0xC),
        "le" => Some(0xD),
        "al" => Some(0xE),
        "nv" => Some(0xF),
        _ => None,
    }
}

/// 解析内存屏障域（`dsb` / `dmb` 选项）
pub(crate) fn parse_barrier_domain(tok: &str) -> Option<u32> {
    match tok.trim().to_ascii_lowercase().as_str() {
        "oshld" => Some(0b0001),
        "oshst" => Some(0b0010),
        "osh" => Some(0b0011),
        "nshld" => Some(0b0101),
        "nshst" => Some(0b0110),
        "nsh" => Some(0b0111),
        "ishld" => Some(0b1001),
        "ishst" => Some(0b1010),
        "ish" => Some(0b1011),
        "ld" => Some(0b1101),
        "st" => Some(0b1110),
        "sy" => Some(0b1111),
        _ => None,
    }
}

/// 解析常用系统寄存器与通用 `S<op0>_<op1>_C<crn>_C<crm>_<op2>` 名称，返回 `(op0, op1, crn, crm, op2)`
pub(crate) fn parse_sysreg(name: &str) -> Option<(u32, u32, u32, u32, u32)> {
    let s = name.trim().to_ascii_lowercase();
    match s.as_str() {
        "nzcv" => Some((3, 3, 4, 2, 0)),
        "daif" => Some((3, 3, 4, 2, 1)),
        "fpcr" => Some((3, 3, 4, 4, 0)),
        "fpsr" => Some((3, 3, 4, 4, 1)),
        "tpidr_el0" => Some((3, 3, 13, 0, 2)),
        "tpidrro_el0" => Some((3, 3, 13, 0, 3)),
        "tpidr_el1" => Some((3, 0, 13, 0, 4)),
        "cntfrq_el0" => Some((3, 3, 14, 0, 0)),
        "cntpct_el0" => Some((3, 3, 14, 0, 1)),
        "cntvct_el0" => Some((3, 3, 14, 0, 2)),
        "ctr_el0" => Some((3, 3, 0, 0, 1)),
        "dczid_el0" => Some((3, 3, 0, 0, 7)),
        "midr_el1" => Some((3, 0, 0, 0, 0)),
        "mpidr_el1" => Some((3, 0, 0, 0, 5)),
        _ => {
            // 通用格式：s<op0>_<op1>_c<crn>_c<crm>_<op2>
            let body = s.strip_prefix('s')?;
            let parts: Vec<&str> = body.split('_').collect();
            if parts.len() != 5 {
                return None;
            }
            let op0 = parse_strict_u32(parts[0])?;
            let op1 = parse_strict_u32(parts[1])?;
            let crn = parse_strict_u32(parts[2].strip_prefix('c')?)?;
            let crm = parse_strict_u32(parts[3].strip_prefix('c')?)?;
            let op2 = parse_strict_u32(parts[4])?;
            if (2..=3).contains(&op0) && op1 < 8 && crn < 16 && crm < 16 && op2 < 8 {
                Some((op0, op1, crn, crm, op2))
            } else {
                None
            }
        }
    }
}

pub(crate) fn parse_mem_addr(ops: &[String]) -> Result<MemAddr> {
    if ops.is_empty() {
        bail!("缺少内存地址操作数");
    }
    let first = ops[0].trim();
    if !first.starts_with('[') {
        bail!("无效内存操作数: '{first}'");
    }

    // 后索引：`[base], #imm`
    if ops.len() == 2 {
        let inner = first
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| anyhow!("无效后索引基址: '{first}'"))?;
        let base = parse_reg(inner)
            .ok_or_else(|| anyhow!("无效基址寄存器: '{inner}'"))?
            .require_64("内存基址")?;
        base.require_gpr_or_sp("内存基址")?;
        let raw_off = parse_imm(&ops[1])?;
        let off = i64::try_from(raw_off)
            .map_err(|_| anyhow!("后索引偏移超出 64 位范围: {raw_off}"))?;
        return Ok(MemAddr::PostIndex { base, off });
    }

    if ops.len() != 1 {
        bail!("内存地址操作数过多");
    }

    let (is_pre, body) = if let Some(b) = first.strip_suffix("]!") {
        (true, b.strip_prefix('[').unwrap())
    } else if let Some(b) = first.strip_suffix(']') {
        (false, b.strip_prefix('[').unwrap())
    } else {
        bail!("内存操作数未闭合: '{first}'");
    };

    let inner_parts: Vec<&str> = body.split(',').map(str::trim).collect();
    let base = parse_reg(inner_parts[0])
        .ok_or_else(|| anyhow!("无效基址寄存器: '{}'", inner_parts[0]))?
        .require_64("内存基址")?;
    base.require_gpr_or_sp("内存基址")?;

    if inner_parts.len() == 1 {
        if is_pre {
            bail!("前索引寻址必须显式提供偏移量: '{first}'");
        }
        return Ok(MemAddr::Offset { base, off: 0 });
    }

    // 寄存器索引寻址：`[base, Rm]` 或 `[base, Rm, lsl/uxtw/sxtw/sxtx #s]`
    if let Some(index) = parse_reg(inner_parts[1]) {
        if is_pre {
            bail!("寄存器偏移寻址不支持前索引 '!'");
        }
        index.require_gpr_or_zr("偏移寄存器")?;
        if inner_parts.len() == 2 {
            if !index.is_64 {
                bail!("32 位偏移寄存器必须指定 uxtw 或 sxtw 扩展: '{first}'");
            }
            return Ok(MemAddr::RegOffset {
                base,
                index,
                option: 0b011, // LSL
                shift: None,
            });
        }
        if inner_parts.len() != 3 {
            bail!("无效寄存器偏移格式: '{first}'");
        }
        let mod_parts: Vec<&str> = inner_parts[2].split_whitespace().collect();
        if mod_parts.is_empty() || mod_parts.len() > 2 {
            bail!("无效偏移修饰符: '{}'", inner_parts[2]);
        }
        let mod_kind = mod_parts[0].to_ascii_lowercase();
        let option = match mod_kind.as_str() {
            "uxtw" => {
                index.require_32("uxtw 偏移")?;
                0b010u32
            }
            "lsl" => {
                index.require_64("lsl 偏移")?;
                if mod_parts.len() != 2 {
                    bail!("lsl 访存偏移修饰必须提供移位量: '{first}'");
                }
                0b011u32
            }
            "sxtw" => {
                index.require_32("sxtw 偏移")?;
                0b110u32
            }
            "sxtx" => {
                index.require_64("sxtx 偏移")?;
                0b111u32
            }
            other => bail!("不支持的访存偏移修饰 '{other}'（支持 lsl/uxtw/sxtw/sxtx）"),
        };
        let shift = if mod_parts.len() == 2 {
            let amt = parse_imm(mod_parts[1])?;
            if !(0..=4).contains(&amt) {
                bail!("访存移位量超出范围: {amt}");
            }
            Some(amt as u8)
        } else {
            None
        };
        return Ok(MemAddr::RegOffset {
            base,
            index,
            option,
            shift,
        });
    }

    if inner_parts.len() != 2 {
        bail!("暂不支持该内存寻址格式: '{first}'");
    }
    let raw_off = parse_imm(inner_parts[1])?;
    let off = i64::try_from(raw_off)
        .map_err(|_| anyhow!("内存偏移超出 64 位范围: {raw_off}"))?;
    if is_pre {
        Ok(MemAddr::PreIndex { base, off })
    } else {
        Ok(MemAddr::Offset { base, off })
    }
}

/// 解析目标分支/PC 相对地址：
/// - `#imm` 按 **PC 相对字节偏移** 处理；
/// - 标签或裸地址按 **绝对地址**（`target - pc`）处理。
pub(crate) fn resolve_pc_delta(
    tok: &str,
    pc: u64,
    labels: &HashMap<String, u64>,
) -> Result<i128> {
    let trimmed = tok.trim();
    if let Some(after_hash) = trimmed.strip_prefix('#') {
        return parse_int_literal(after_hash);
    }
    let expr = parse_expr(trimmed)?;
    let target = expr.eval_addr(labels)?;
    Ok((target as i128) - (pc as i128))
}

pub(crate) fn check_signed_bits(val: i128, bits: u32, ctx: &str) -> Result<u32> {
    let min = -(1i128 << (bits - 1));
    let max = (1i128 << (bits - 1)) - 1;
    if val < min || val > max {
        bail!("{ctx}: 偏移/立即数 {val} 超出 {bits}-bit 有符号范围 [{min}, {max}]");
    }
    let mask = (1u64 << bits) - 1;
    Ok(((val as i64 as u64) & mask) as u32)
}
