//! `good64` — 轻量、零依赖纯 Rust ARM64 (AArch64) 汇编器与 Inline Hook 重定位器
//!
//! 与反汇编器 `bad64` 互补，覆盖 Android ARM64 逆向 Patch、Shellcode 与 Inline Hook 实战中
//! 99% 高频 A64 指令（整数/位域/位反转/进位/长乘/条件选择与比较/扩展寄存器/完整与原子访存/
//! 系统寄存器与 PAC·BTI/标量 FP 与 S·D·Q 访存/高频 128-bit NEON 与 AES），并内置
//! PC 相对指令重定位器（[`relocate_instruction`] / [`relocate_instructions`]）。
//!
//! # 示例
//! ```
//! use runidbg_arm64_emu_tracer::good64::{assemble, encode_branch_trampoline};
//!
//! let code = assemble(
//!     "
//!     stp x29, x30, [sp, #-16]!
//!     mov x0, #0x12345678
//!     cbz x1, done
//!     add x0, x0, x1
//! done:
//!     ldp x29, x30, [sp], #16
//!     ret
//!     ",
//!     0x4000_1000,
//! ).unwrap();
//! assert_eq!(code.len() % 4, 0);
//!
//! let jmp = encode_branch_trampoline(0x4000_0000, 0x4000_1000);
//! assert_eq!(jmp.len(), 4);
//! ```

mod int;
mod parse;
mod reloc;
mod simd;

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

use self::parse::{parse_expr, parse_imm, parse_reg, split_operands, Expr};

pub use self::reloc::{relocate_instruction, relocate_instructions};

// ============================================================================
// 1. 公共便捷 API 与 Inline Hook 跳板辅助
// ============================================================================

/// 将 ARM64 汇编文本汇编为小端字节流（`pc` 为首条指令所在虚拟地址）
pub fn assemble(source: &str, pc: u64) -> Result<Vec<u8>> {
    Assembler::assemble(source, pc)
}

/// 将 ARM64 汇编文本汇编为 32-bit 指令字序列（若含非 4 字节对齐的数据伪指令则报错）
pub fn assemble_words(source: &str, pc: u64) -> Result<Vec<u32>> {
    let bytes = assemble(source, pc)?;
    if !bytes.len().is_multiple_of(4) {
        bail!("汇编输出长度 {} 不是 4 字节对齐", bytes.len());
    }
    Ok(bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect())
}

/// 经典 16 字节绝对跳转跳板：`ldr x16, #8; br x16; .quad target`（使用 IP0 寄存器 `x16`，符合 AAPCS64）
pub fn encode_abs_jump(target: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    // ldr x16, #8 (PC + 8 -> imm19 = 2): 0x5800_0050
    out[0..4].copy_from_slice(&0x5800_0050u32.to_le_bytes());
    // br x16: 0xD61F_0200
    out[4..8].copy_from_slice(&0xD61F_0200u32.to_le_bytes());
    out[8..16].copy_from_slice(&target.to_le_bytes());
    out
}

/// Inline Hook 跳转跳板生成器：
/// - `from_pc` 与 `target_pc` 4 字节对齐且距离在 `±128 MiB` 内 → 生成 **4 字节** `b target`
/// - 否则 → 生成 **16 字节** 绝对跳板 `ldr x16, #8; br x16; .quad target`
pub fn encode_branch_trampoline(from_pc: u64, target_pc: u64) -> Vec<u8> {
    if (from_pc & 3) == 0 && (target_pc & 3) == 0 {
        let delta = (target_pc as i128) - (from_pc as i128);
        if (-0x0800_0000..=0x07FF_FFFC).contains(&delta) {
            let imm26 = ((delta >> 2) as u32) & 0x03FF_FFFF;
            return (0x1400_0000u32 | imm26).to_le_bytes().to_vec();
        }
    }
    encode_abs_jump(target_pc).to_vec()
}

/// Inline Hook 调用跳板生成器：
/// - `from_pc` 与 `target_pc` 4 字节对齐且距离在 `±128 MiB` 内 → 生成 **4 字节** `bl target`
/// - 否则 → 生成 **20 字节** 自包含调用跳板：`ldr x16, #12; blr x16; b #12; .quad target`
pub fn encode_call_trampoline(from_pc: u64, target_pc: u64) -> Vec<u8> {
    if (from_pc & 3) == 0 && (target_pc & 3) == 0 {
        let delta = (target_pc as i128) - (from_pc as i128);
        if (-0x0800_0000..=0x07FF_FFFC).contains(&delta) {
            let imm26 = ((delta >> 2) as u32) & 0x03FF_FFFF;
            return (0x9400_0000u32 | imm26).to_le_bytes().to_vec();
        }
    }
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&0x5800_0070u32.to_le_bytes());
    out.extend_from_slice(&0xD63F_0200u32.to_le_bytes());
    out.extend_from_slice(&0x1400_0003u32.to_le_bytes());
    out.extend_from_slice(&target_pc.to_le_bytes());
    out
}

/// 将任意 64-bit 立即数最优编码为 1–4 条 `MOVZ`/`MOVN`/`ORR`/`MOVK` 指令（用于 `Rd` = 0..=30）
pub fn encode_mov_imm64(rd: u8, imm: u64) -> Vec<u32> {
    encode_mov_imm(rd & 31, true, imm)
}

/// 将任意 32-bit 立即数最优编码为 1–2 条 `MOVZ`/`MOVN`/`ORR`/`MOVK` 指令（用于 `Wd` = 0..=30）
pub fn encode_mov_imm32(rd: u8, imm: u32) -> Vec<u32> {
    encode_mov_imm(rd & 31, false, u64::from(imm))
}

pub(crate) fn encode_mov_imm(rd: u8, is_64: bool, val: u64) -> Vec<u32> {
    let sf = u32::from(is_64) << 31;
    let rd32 = u32::from(rd & 31);
    let masked = if is_64 { val } else { val & 0xFFFF_FFFF };

    let chunks = if is_64 { 4usize } else { 2usize };
    let mut nonzero = Vec::with_capacity(chunks);
    let mut nonffff = Vec::with_capacity(chunks);
    for hw in 0..chunks {
        let part = ((masked >> (hw * 16)) & 0xFFFF) as u32;
        if part != 0 {
            nonzero.push((hw as u32, part));
        }
        if part != 0xFFFF {
            nonffff.push((hw as u32, part));
        }
    }

    if nonzero.is_empty() {
        return vec![sf | 0x5280_0000 | rd32];
    }
    if nonzero.len() == 1 {
        let (hw, part) = nonzero[0];
        return vec![sf | 0x5280_0000 | (hw << 21) | (part << 5) | rd32];
    }
    if nonffff.is_empty() {
        return vec![sf | 0x1280_0000 | rd32];
    }
    if nonffff.len() == 1 {
        let (hw, part) = nonffff[0];
        let inv = (!part) & 0xFFFF;
        return vec![sf | 0x1280_0000 | (hw << 21) | (inv << 5) | rd32];
    }
    // 注意：ORR (immediate) 的 Rd=31 编码为 SP/WSP 而非 XZR/WZR，必须排除 rd32 == 31 以免破坏栈指针！
    if rd32 != 31 {
        if let Some((n, immr, imms)) = encode_logical_imm(masked, is_64) {
            return vec![
                sf | 0x3200_03E0
                    | (u32::from(n) << 22)
                    | (u32::from(immr) << 16)
                    | (u32::from(imms) << 10)
                    | rd32,
            ];
        }
    }

    if nonffff.len() < nonzero.len() {
        let mut out = Vec::with_capacity(nonffff.len());
        let (hw0, part0) = nonffff[0];
        let inv0 = (!part0) & 0xFFFF;
        out.push(sf | 0x1280_0000 | (hw0 << 21) | (inv0 << 5) | rd32);
        for &(hw, part) in &nonffff[1..] {
            out.push(sf | 0x7280_0000 | (hw << 21) | (part << 5) | rd32);
        }
        out
    } else {
        let mut out = Vec::with_capacity(nonzero.len());
        let (hw0, part0) = nonzero[0];
        out.push(sf | 0x5280_0000 | (hw0 << 21) | (part0 << 5) | rd32);
        for &(hw, part) in &nonzero[1..] {
            out.push(sf | 0x7280_0000 | (hw << 21) | (part << 5) | rd32);
        }
        out
    }
}

/// 将 32/64 位整数编码为 ARM64 逻辑立即数 `(N, immr, imms)`（不符合位掩码规则则返回 `None`）
pub fn encode_logical_imm(val: u64, is_64: bool) -> Option<(u8, u8, u8)> {
    let reg_size = if is_64 { 64u32 } else { 32u32 };
    let val = if is_64 { val } else { val & 0xFFFF_FFFF };
    let all_ones = if is_64 { u64::MAX } else { 0xFFFF_FFFF };
    if val == 0 || val == all_ones {
        return None;
    }

    let mut esize = reg_size;
    let mut pattern = val;
    while esize > 2 {
        let half = esize / 2;
        let mask = (1u64 << half) - 1;
        let lo = pattern & mask;
        let hi = (pattern >> half) & mask;
        if lo == hi {
            esize = half;
            pattern = lo;
        } else {
            break;
        }
    }

    let elem_mask = if esize == 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    };
    let p = pattern & elem_mask;
    let ones = p.count_ones();
    if ones == 0 || ones == esize {
        return None;
    }

    let mut rot = 0u32;
    let target = (1u64 << ones) - 1;
    let mut found = false;
    for r in 0..esize {
        let rotated = if r == 0 {
            target
        } else {
            ((target << r) | (target >> (esize - r))) & elem_mask
        };
        if rotated == p {
            rot = if r == 0 { 0 } else { esize - r };
            found = true;
            break;
        }
    }
    if !found {
        return None;
    }

    let n = u8::from(esize == 64);
    let immr = rot as u8;
    let size_prefix = if esize == 64 {
        0u8
    } else {
        ((!(esize * 2 - 1)) & 0x3F) as u8
    };
    let imms = size_prefix | ((ones - 1) as u8);
    Some((n, immr, imms))
}

// ============================================================================
// 2. 编程式流式编码器 Arm64Emitter
// ============================================================================

/// 轻量编程式 ARM64 指令发射器（直接输出小端机器码）
#[derive(Debug, Clone)]
pub struct Arm64Emitter {
    base_pc: u64,
    bytes: Vec<u8>,
}

impl Arm64Emitter {
    pub fn new(base_pc: u64) -> Self {
        Self {
            base_pc,
            bytes: Vec::new(),
        }
    }

    #[inline]
    pub fn pc(&self) -> u64 {
        self.base_pc.wrapping_add(self.bytes.len() as u64)
    }

    #[inline]
    pub fn emit_u32(&mut self, word: u32) -> &mut Self {
        self.bytes.extend_from_slice(&word.to_le_bytes());
        self
    }

    #[inline]
    pub fn emit_u64(&mut self, val: u64) -> &mut Self {
        self.bytes.extend_from_slice(&val.to_le_bytes());
        self
    }

    #[inline]
    pub fn nop(&mut self) -> &mut Self {
        self.emit_u32(0xD503_201F)
    }

    #[inline]
    pub fn ret(&mut self) -> &mut Self {
        self.emit_u32(0xD65F_03C0)
    }

    #[inline]
    pub fn br(&mut self, rn: u8) -> &mut Self {
        self.emit_u32(0xD61F_0000 | (u32::from(rn & 31) << 5))
    }

    #[inline]
    pub fn blr(&mut self, rn: u8) -> &mut Self {
        self.emit_u32(0xD63F_0000 | (u32::from(rn & 31) << 5))
    }

    #[inline]
    pub fn svc(&mut self, imm16: u16) -> &mut Self {
        self.emit_u32(0xD400_0001 | (u32::from(imm16) << 5))
    }

    #[inline]
    pub fn brk(&mut self, imm16: u16) -> &mut Self {
        self.emit_u32(0xD420_0000 | (u32::from(imm16) << 5))
    }

    pub fn mov_imm64(&mut self, rd: u8, imm: u64) -> &mut Self {
        for w in encode_mov_imm64(rd, imm) {
            self.emit_u32(w);
        }
        self
    }

    pub fn branch_to(&mut self, target: u64) -> &mut Self {
        let code = encode_branch_trampoline(self.pc(), target);
        self.bytes.extend_from_slice(&code);
        self
    }

    pub fn call_to(&mut self, target: u64) -> &mut Self {
        let code = encode_call_trampoline(self.pc(), target);
        self.bytes.extend_from_slice(&code);
        self
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ============================================================================
// 3. 两遍汇编驱动
// ============================================================================

#[derive(Debug, Clone)]
enum Statement {
    Insn {
        mnemonic: String,
        operands: Vec<String>,
        line: usize,
    },
    Data {
        elem_size: usize,
        items: Vec<Expr>,
        line: usize,
    },
}

struct Assembler;

impl Assembler {
    fn assemble(source: &str, base_pc: u64) -> Result<Vec<u8>> {
        let mut stmts: Vec<(u64, usize, Statement)> = Vec::new();
        let mut labels: HashMap<String, u64> = HashMap::new();
        let mut cur_pc = base_pc;

        for (line_idx, raw_line) in source.lines().enumerate() {
            let line_no = line_idx + 1;
            let stripped = strip_line_comment(raw_line);
            for raw_stmt in stripped.split(';') {
                let mut part = raw_stmt.trim();
                if part.is_empty() {
                    continue;
                }
                while let Some((lbl, rest)) = split_leading_label(part) {
                    if labels.insert(lbl.to_string(), cur_pc).is_some() {
                        bail!("第 {line_no} 行: 重复定义的标签 '{lbl}'");
                    }
                    part = rest.trim();
                    if part.is_empty() {
                        break;
                    }
                }
                if part.is_empty() {
                    continue;
                }

                let stmt = parse_statement(part, line_no)?;
                let sz = measure_statement(&stmt)
                    .map_err(|e| anyhow!("第 {line_no} 行长度计算失败: {e}"))?;
                stmts.push((cur_pc, sz, stmt));
                cur_pc = cur_pc.wrapping_add(sz as u64);
            }
        }

        let mut out = Vec::with_capacity((cur_pc.wrapping_sub(base_pc)) as usize);
        for (pc, expected_sz, stmt) in &stmts {
            match stmt {
                Statement::Data {
                    elem_size,
                    items,
                    line,
                } => {
                    for expr in items {
                        let val = expr
                            .eval_addr(&labels)
                            .map_err(|e| anyhow!("第 {line} 行数据伪指令错误: {e}"))?;
                        match elem_size {
                            1 => out.push(val as u8),
                            2 => out.extend_from_slice(&(val as u16).to_le_bytes()),
                            4 => out.extend_from_slice(&(val as u32).to_le_bytes()),
                            8 => out.extend_from_slice(&val.to_le_bytes()),
                            _ => unreachable!(),
                        }
                    }
                }
                Statement::Insn {
                    mnemonic,
                    operands,
                    line,
                } => {
                    let words = encode_instruction(mnemonic, operands, *pc, &labels)
                        .map_err(|e| anyhow!("第 {line} 行 `{mnemonic}` 汇编失败: {e}"))?;
                    if words.len() * 4 != *expected_sz {
                        bail!(
                            "内部一致性错误：第 {line} 行 `{mnemonic}` 两遍长度不一致（预测 {}B，实际 {}B）",
                            expected_sz,
                            words.len() * 4
                        );
                    }
                    for w in words {
                        out.extend_from_slice(&w.to_le_bytes());
                    }
                }
            }
        }
        Ok(out)
    }
}

fn strip_line_comment(line: &str) -> &str {
    let s = line.split("//").next().unwrap_or(line);
    let trimmed = s.trim_start();
    if trimmed.starts_with('@') {
        ""
    } else {
        s
    }
}

fn split_leading_label(s: &str) -> Option<(&str, &str)> {
    let colon = s.find(':')?;
    let head = &s[..colon];
    if head.is_empty()
        || head.as_bytes()[0].is_ascii_digit()
        || head.contains(char::is_whitespace)
        || head.contains('[')
    {
        return None;
    }
    if head
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'$')
    {
        Some((head, &s[colon + 1..]))
    } else {
        None
    }
}

fn parse_statement(text: &str, line: usize) -> Result<Statement> {
    let (mnem_raw, rest) = match text.find(char::is_whitespace) {
        Some(idx) => (&text[..idx], text[idx..].trim()),
        None => (text, ""),
    };
    let mnemonic = mnem_raw.to_ascii_lowercase();
    let operands = split_operands(rest)?;

    let elem_size = match mnemonic.as_str() {
        ".byte" | ".1byte" => Some(1),
        ".hword" | ".short" | ".2byte" => Some(2),
        ".word" | ".4byte" | ".long" => Some(4),
        ".quad" | ".8byte" | ".xword" => Some(8),
        _ => None,
    };
    if let Some(elem_size) = elem_size {
        if operands.is_empty() {
            bail!("第 {line} 行: `{mnemonic}` 至少需要一个数据项");
        }
        let mut items = Vec::with_capacity(operands.len());
        for op in &operands {
            items.push(parse_expr(op)?);
        }
        return Ok(Statement::Data {
            elem_size,
            items,
            line,
        });
    }

    Ok(Statement::Insn {
        mnemonic,
        operands,
        line,
    })
}

fn measure_statement(stmt: &Statement) -> Result<usize> {
    match stmt {
        Statement::Data {
            elem_size, items, ..
        } => Ok(elem_size * items.len()),
        Statement::Insn {
            mnemonic, operands, ..
        } => {
            if mnemonic == "mov" && operands.len() == 2 {
                if let Some(rd) = parse_reg(&operands[0]) {
                    if parse_reg(&operands[1]).is_none()
                        && parse::parse_vec_elem(&operands[1]).is_none()
                    {
                        let imm = parse_imm(&operands[1])?;
                        let val = parse::check_int_range(imm, rd.is_64, "mov #imm")?;
                        let words = encode_mov_imm(rd.num, rd.is_64, val);
                        return Ok(words.len() * 4);
                    }
                }
            }
            Ok(4)
        }
    }
}

fn encode_instruction(
    mnemonic: &str,
    ops: &[String],
    pc: u64,
    labels: &HashMap<String, u64>,
) -> Result<Vec<u32>> {
    if let Some(words) = int::encode_int_instruction(mnemonic, ops, pc, labels)? {
        return Ok(words);
    }
    if let Some(words) = simd::encode_simd_instruction(mnemonic, ops)? {
        return Ok(words);
    }
    bail!("good64 暂不支持指令 '{mnemonic}'")
}

// ============================================================================
// 4. 全指令家族双向自检单元测试（good64 -> bad64::decode 机器验证）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn disasm_one(word: u32, pc: u64) -> String {
        bad64::decode(word, pc)
            .unwrap_or_else(|e| panic!("bad64 decode failed for 0x{word:08x}: {e:?}"))
            .to_string()
    }

    #[test]
    fn test_good64_full_route_a_roundtrip_with_bad64() {
        let cases: &[(&str, &str)] = &[
            // 基础系统 / 分支 / 移动 / 算术
            ("nop", "nop"),
            ("ret", "ret"),
            ("ret x16", "ret x16"),
            ("br x16", "br x16"),
            ("blr x8", "blr x8"),
            ("svc #0", "svc #0x0"),
            ("brk #0x123", "brk #0x123"),
            ("dsb ish", "dsb ish"),
            ("dmb ishst", "dmb ishst"),
            ("isb", "isb"),
            ("clrex", "clrex"),
            ("bti c", "bti c"),
            ("bti j", "bti j"),
            ("bti jc", "bti jc"),
            ("paciasp", "paciasp"),
            ("autiasp", "autiasp"),
            ("retaa", "retaa"),
            ("retab", "retab"),
            ("xpaclri", "xpaclri"),
            ("mrs x0, tpidr_el0", "mrs x0, tpidr_el0"),
            ("msr tpidr_el0, x1", "msr tpidr_el0, x1"),
            ("mrs x2, nzcv", "mrs x2, nzcv"),
            ("mrs x3, cntvct_el0", "mrs x3, cntvct_el0"),
            // 扩展与位域
            ("sxtb x0, w1", "sxtb x0, w1"),
            ("sxth x0, w1", "sxth x0, w1"),
            ("sxtw x0, w1", "sxtw x0, w1"),
            ("uxtb w0, w1", "uxtb w0, w1"),
            ("uxth w0, w1", "uxth w0, w1"),
            ("ubfx x0, x1, #4, #8", "ubfx x0, x1, #0x4, #0x8"),
            ("sbfx w0, w1, #3, #5", "sbfx w0, w1, #0x3, #0x5"),
            ("bfi x0, x1, #8, #12", "bfi x0, x1, #0x8, #0xc"),
            ("bfxil w0, w1, #2, #6", "bfxil w0, w1, #0x2, #0x6"),
            ("extr x0, x1, x2, #16", "extr x0, x1, x2, #0x10"),
            // 位操作与字节序
            ("rbit x0, x1", "rbit x0, x1"),
            ("rbit w0, w1", "rbit w0, w1"),
            ("rev x0, x1", "rev x0, x1"),
            ("rev w0, w1", "rev w0, w1"),
            ("rev16 x0, x1", "rev16 x0, x1"),
            ("rev32 x0, x1", "rev32 x0, x1"),
            ("clz x0, x1", "clz x0, x1"),
            ("cls w0, w1", "cls w0, w1"),
            // 进位、长乘、高位乘、条件比较
            ("adc x0, x1, x2", "adc x0, x1, x2"),
            ("adcs x0, x1, x2", "adcs x0, x1, x2"),
            ("sbc w0, w1, w2", "sbc w0, w1, w2"),
            ("ngc x0, x1", "ngc x0, x1"),
            ("mneg x0, x1, x2", "mneg x0, x1, x2"),
            ("smull x0, w1, w2", "smull x0, w1, w2"),
            ("umull x0, w1, w2", "umull x0, w1, w2"),
            ("smaddl x0, w1, w2, x3", "smaddl x0, w1, w2, x3"),
            ("umsubl x0, w1, w2, x3", "umsubl x0, w1, w2, x3"),
            ("smulh x0, x1, x2", "smulh x0, x1, x2"),
            ("umulh x0, x1, x2", "umulh x0, x1, x2"),
            ("csetm x0, eq", "csetm x0, eq"),
            ("cinc x0, x1, ne", "cinc x0, x1, ne"),
            ("cinv w0, w1, lt", "cinv w0, w1, lt"),
            ("cneg x0, x1, ge", "cneg x0, x1, ge"),
            ("ccmp x0, x1, #4, eq", "ccmp x0, x1, #0x4, eq"),
            ("ccmp x0, #5, #0, ne", "ccmp x0, #0x5, #0x0, ne"),
            ("ccmn w0, #1, #2, hi", "ccmn w0, #0x1, #0x2, hi"),
            // 扩展寄存器算术
            ("add x0, x1, w2, uxtw #2", "add x0, x1, w2, uxtw #0x2"),
            ("sub x0, sp, w1, sxtw #3", "sub x0, sp, w1, sxtw #0x3"),
            ("add sp, sp, x0", "add sp, sp, x0"),
            // 寄存器索引访存、有符号加载、成对/非临时与原子访存
            ("ldr x0, [x1, x2, lsl #3]", "ldr x0, [x1, x2, lsl #0x3]"),
            ("ldrb w0, [x1, x2]", "ldrb w0, [x1, x2]"),
            ("ldr w0, [x1, w2, uxtw #2]", "ldr w0, [x1, w2, uxtw #0x2]"),
            ("ldrsb x0, [x1, #4]", "ldrsb x0, [x1, #0x4]"),
            ("ldrsh w0, [x1, #6]", "ldrsh w0, [x1, #0x6]"),
            ("ldnp x0, x1, [x2, #16]", "ldnp x0, x1, [x2, #0x10]"),
            ("stnp x0, x1, [x2, #16]", "stnp x0, x1, [x2, #0x10]"),
            ("ldxr x0, [x1]", "ldxr x0, [x1]"),
            ("ldaxr w0, [x1]", "ldaxr w0, [x1]"),
            ("stxr w2, x0, [x1]", "stxr w2, x0, [x1]"),
            ("stlxr w2, w0, [x1]", "stlxr w2, w0, [x1]"),
            ("ldar x0, [x1]", "ldar x0, [x1]"),
            ("stlr w0, [x1]", "stlr w0, [x1]"),
            ("ldarb w0, [x1]", "ldarb w0, [x1]"),
            ("stlrh w0, [x1]", "stlrh w0, [x1]"),
            ("cas x0, x1, [x2]", "cas x0, x1, [x2]"),
            ("casal w0, w1, [x2]", "casal w0, w1, [x2]"),
            ("swpal x0, x1, [x2]", "swpal x0, x1, [x2]"),
            ("ldaddal x0, x1, [x2]", "ldaddal x0, x1, [x2]"),
            // 标量浮点与 S/D/Q 访存
            ("fmov d0, d1", "fmov d0, d1"),
            ("fmov d0, x0", "fmov d0, x0"),
            ("fmov x1, d0", "fmov x1, d0"),
            ("fmov s0, w0", "fmov s0, w0"),
            ("fadd d0, d1, d2", "fadd d0, d1, d2"),
            ("fsub s0, s1, s2", "fsub s0, s1, s2"),
            ("fmul d0, d1, d2", "fmul d0, d1, d2"),
            ("fdiv s0, s1, s2", "fdiv s0, s1, s2"),
            ("fabs d0, d1", "fabs d0, d1"),
            ("fneg s0, s1", "fneg s0, s1"),
            ("fsqrt d0, d1", "fsqrt d0, d1"),
            ("fcmp d0, d1", "fcmp d0, d1"),
            ("fcmp d0, #0.0", "fcmp d0, #0"),
            ("fcsel d0, d1, d2, gt", "fcsel d0, d1, d2, gt"),
            ("fcvt d0, s1", "fcvt d0, s1"),
            ("fcvt s0, d1", "fcvt s0, d1"),
            ("scvtf d0, x1", "scvtf d0, x1"),
            ("ucvtf s0, w1", "ucvtf s0, w1"),
            ("fcvtzs x0, d1", "fcvtzs x0, d1"),
            ("fcvtzu w0, s1", "fcvtzu w0, s1"),
            ("ldr q0, [x1, #0x10]", "ldr q0, [x1, #0x10]"),
            ("str q1, [x2, x3, lsl #4]", "str q1, [x2, x3, lsl #0x4]"),
            ("stp q0, q1, [sp, #-32]!", "stp q0, q1, [sp, #0xffffffffffffffe0]!"),
            ("ldp q0, q1, [sp], #32", "ldp q0, q1, [sp], #0x20"),
            // NEON 向量 & ARMv8 AES
            ("mov v0.16b, v1.16b", "mov v0.16b, v1.16b"),
            ("eor v0.16b, v1.16b, v2.16b", "eor v0.16b, v1.16b, v2.16b"),
            ("and v0.16b, v1.16b, v2.16b", "and v0.16b, v1.16b, v2.16b"),
            ("bic v0.16b, v1.16b, v2.16b", "bic v0.16b, v1.16b, v2.16b"),
            ("not v0.16b, v1.16b", "mvn v0.16b, v1.16b"),
            ("mvn v0.16b, v1.16b", "mvn v0.16b, v1.16b"),
            ("mov x0, v1.d[1]", "mov x0, v1.d[1]"),
            ("mov v0.s[2], w3", "mov v0.s[2], w3"),
            ("movi v0.16b, #0x5a", "movi v0.16b, #0x5a"),
            ("add v0.4s, v1.4s, v2.4s", "add v0.4s, v1.4s, v2.4s"),
            ("sub v0.2d, v1.2d, v2.2d", "sub v0.2d, v1.2d, v2.2d"),
            ("mul v0.4s, v1.4s, v2.4s", "mul v0.4s, v1.4s, v2.4s"),
            ("shl v0.4s, v1.4s, #3", "shl v0.4s, v1.4s, #0x3"),
            ("ushr v0.4s, v1.4s, #5", "ushr v0.4s, v1.4s, #0x5"),
            ("sshr v0.2d, v1.2d, #8", "sshr v0.2d, v1.2d, #0x8"),
            ("ext v0.16b, v1.16b, v2.16b, #4", "ext v0.16b, v1.16b, v2.16b, #0x4"),
            ("rev32 v0.16b, v1.16b", "rev32 v0.16b, v1.16b"),
            ("rev64 v0.4s, v1.4s", "rev64 v0.4s, v1.4s"),
            ("dup v0.4s, w1", "dup v0.4s, w1"),
            ("umov x0, v1.d[1]", "mov x0, v1.d[1]"),
            ("ins v0.s[2], w3", "mov v0.s[2], w3"),
            ("tbl v0.16b, {v1.16b, v2.16b}, v3.16b", "tbl v0.16b, {v1.16b, v2.16b}, v3.16b"),
            ("aese v0.16b, v1.16b", "aese v0.16b, v1.16b"),
            ("aesd v0.16b, v1.16b", "aesd v0.16b, v1.16b"),
            ("aesmc v0.16b, v1.16b", "aesmc v0.16b, v1.16b"),
            ("aesimc v0.16b, v1.16b", "aesimc v0.16b, v1.16b"),
        ];

        for &(src, expected) in cases {
            let words = assemble_words(src, 0x4000_0000)
                .unwrap_or_else(|e| panic!("assemble failed for `{src}`: {e}"));
            assert_eq!(words.len(), 1, "expected 1 word for `{src}`");
            let dis = disasm_one(words[0], 0x4000_0000);
            assert_eq!(
                dis, expected,
                "roundtrip mismatch for `{src}` (word=0x{:08x})",
                words[0]
            );
        }
    }

    #[test]
    fn test_good64_relocator_near_and_far() {
        let old_pc = 0x4000_1000u64;
        // 1. ADR 在近距（4B）与超远距（>1MB 展开为 movz/movk）的重定位
        let adr_word = assemble_words("adr x5, 0x40001234", old_pc).unwrap()[0];
        let near = relocate_instruction(adr_word, old_pc, 0x4000_2000).unwrap();
        assert_eq!(near.len(), 4);
        assert_eq!(
            disasm_one(u32::from_le_bytes(near.try_into().unwrap()), 0x4000_2000),
            "adr x5, 0x40001234"
        );

        let far = relocate_instruction(adr_word, old_pc, 0x9000_0000).unwrap();
        assert!(far.len() >= 8);
        assert_eq!(
            disasm_one(u32::from_le_bytes(far[0..4].try_into().unwrap()), 0x9000_0000),
            "mov x5, #0x1234"
        );

        // 2. CBZ 超远距重定位为反转 CBNZ + 16B 绝对跳板
        let cbz_word = assemble_words("cbz x0, 0x40001040", old_pc).unwrap()[0];
        let cbz_far = relocate_instruction(cbz_word, old_pc, 0x9000_0000).unwrap();
        assert_eq!(cbz_far.len(), 20);
        assert_eq!(
            disasm_one(u32::from_le_bytes(cbz_far[0..4].try_into().unwrap()), 0x9000_0000),
            "cbnz x0, 0x90000014"
        );
        assert_eq!(
            u64::from_le_bytes(cbz_far[12..20].try_into().unwrap()),
            0x4000_1040
        );

        // 3. P0-1: ADRP XZR 超距不得编出 ORR SP，应降级为 NOP
        let adrp_xzr = 0xB000_001Fu32; // adrp xzr, 0x7ffff000 (from 0x7fffe000)
        let reloc_xzr = relocate_instruction(adrp_xzr, 0x7FFF_E000, 0x4_0000_0000).unwrap();
        assert_eq!(reloc_xzr, 0xD503_201Fu32.to_le_bytes());

        // 4. P1-9: 未分配编码 0xDC00_0000 不得被 LDR literal 误改写
        assert_eq!(
            relocate_instruction(0xDC00_0000, 0x4000_1000, 0x4000_2000).unwrap(),
            0xDC00_0000u32.to_le_bytes()
        );
        assert_eq!(
            relocate_instruction(0xDC00_0000, 0x4000_1000, 0x9000_0000).unwrap(),
            0xDC00_0000u32.to_le_bytes()
        );

        // 5. P1-10: 块内分支跨超距展开 ADR 自动多遍重定向至新偏移
        let block = assemble(
            "cbz x0, done; adr x9, 0x40005555; add x0, x0, #1; done: ret",
            0x4000_1000,
        )
        .unwrap();
        let reloc_block = relocate_instructions(&block, 0x4000_1000, 0x9000_0000).unwrap();
        let first_word = u32::from_le_bytes(reloc_block[0..4].try_into().unwrap());
        let expected_done_pc = 0x9000_0000u64 + (reloc_block.len() as u64 - 4);
        assert_eq!(
            disasm_one(first_word, 0x9000_0000),
            format!("cbz x0, 0x{expected_done_pc:x}")
        );
    }

    #[test]
    fn test_good64_audit_regressions() {
        // P0-1: mov xzr/wzr #bitmask_imm 绝不能编成 orr sp/wsp
        for src in [
            "mov xzr, #0x5555555555555555",
            "mov xzr, #0x7ffff000",
            "mov wzr, #0x00ff00ff",
        ] {
            let words = assemble_words(src, 0).unwrap();
            for w in words {
                let dis = disasm_one(w, 0);
                assert!(
                    !dis.contains("sp"),
                    "`{src}` 误编码为写 SP: {dis} (0x{w:08x})"
                );
            }
        }

        // P0-2: cset/csetm/cinc/cinv/cneg 禁止 al/nv
        for bad in [
            "cset x0, al",
            "csetm x0, nv",
            "cinc x0, x1, al",
            "cinv w0, w1, nv",
            "cneg x0, x1, al",
        ] {
            assert!(assemble(bad, 0).is_err(), "应拒绝 `{bad}`");
        }

        // P0-3 & P1-1..P1-8: 溢出/截断/非法寄存器/非法排布/非法参数全部拒绝
        for bad in [
            "add x0, x1, #-0x80000000000000000000000000000000",
            "add x0, x1, #0xffffffffffffffffffffffffffffffff",
            "add x0, x1, #0x+5",
            "add x0, x1, #-+5",
            "ldr x0, [x1, #0x10000000000000008]",
            "mov w0, #0x100000000",
            "and w0, w1, #0x1000000ff",
            "mvn w0, w1, lsl #32",
            "add w0, w1, x2, uxtx #1",
            "ubfx x0, x1, #0x7fffffffffffffffffffffffffffffff, #1",
            "ldrb x0, [x1]",
            "strh x0, [x1]",
            "uxtb x0, w1",
            "uxth x0, w1",
            "nop x0",
            "retaa x16",
            "paciasp x0",
            "1: nop",
            "mov v0.4s, v1.4s",
            "mov w0, v1.b[0]",
            "add x0, x1, x2,",
            "ldr x0, [x1, x2, lsl]",
            "ldr x0, [x1]!",
        ] {
            assert!(assemble(bad, 0).is_err(), "应拒绝非法输入 `{bad}`");
        }

        // P1-3: 32 位 add w0, w1, w2, uxtx #1 合法且能正确往返
        let w = assemble_words("add w0, w1, w2, uxtx #1", 0).unwrap()[0];
        assert_eq!(disasm_one(w, 0), "add w0, w1, w2, uxtx #0x1");

        // P1-6: clrex #0 与 isb sy 正确编码
        assert_eq!(assemble_words("clrex #0", 0).unwrap()[0], 0xD503_305F);
        assert_eq!(assemble_words("isb sy", 0).unwrap()[0], 0xD503_3FDF);
    }
}
