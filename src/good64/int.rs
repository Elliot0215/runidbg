//! `good64` 整数、位域、位操作、原子、PAC/BTI、系统寄存器与完整整数访存编码器

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

use super::parse::{
    check_signed_bits, parse_barrier_domain, parse_cond, parse_expr, parse_imm, parse_int_literal,
    parse_mem_addr, parse_reg, parse_shift, parse_sysreg, resolve_pc_delta, try_parse_extend,
    ExtendKind, MemAddr, Reg, ShiftKind,
};
use super::{encode_logical_imm, encode_mov_imm};

pub(crate) fn encode_int_instruction(
    mnemonic: &str,
    ops: &[String],
    pc: u64,
    labels: &HashMap<String, u64>,
) -> Result<Option<Vec<u32>>> {
    // 条件分支 `b.<cond>`
    if let Some(cond_str) = mnemonic.strip_prefix("b.") {
        let cond = parse_cond(cond_str).ok_or_else(|| anyhow!("未知条件码: '{cond_str}'"))?;
        if ops.len() != 1 {
            bail!("需要 1 个跳转目标");
        }
        let delta = resolve_pc_delta(&ops[0], pc, labels)?;
        if (delta & 3) != 0 {
            bail!("跳转偏移 {delta} 未 4 字节对齐");
        }
        let imm19 = check_signed_bits(delta >> 2, 19, "b.cond")?;
        return Ok(Some(vec![0x5400_0000 | (imm19 << 5) | cond]));
    }

    let words = match mnemonic {
        // ---- 系统提示 / 屏障 / PAC / BTI ----
        "nop" | "yield" | "wfe" | "wfi" | "sev" | "sevl" | "paciasp" | "autiasp" | "pacibsp"
        | "autibsp" | "xpaclri" | "retaa" | "retab" => {
            if !ops.is_empty() {
                bail!("{mnemonic} 不接受任何操作数");
            }
            let w = match mnemonic {
                "nop" => 0xD503_201Fu32,
                "yield" => 0xD503_203Fu32,
                "wfe" => 0xD503_205Fu32,
                "wfi" => 0xD503_207Fu32,
                "sev" => 0xD503_209Fu32,
                "sevl" => 0xD503_20BFu32,
                "paciasp" => 0xD503_233Fu32,
                "autiasp" => 0xD503_23BFu32,
                "pacibsp" => 0xD503_237Fu32,
                "autibsp" => 0xD503_23FFu32,
                "xpaclri" => 0xD503_20FFu32,
                "retaa" => 0xD65F_0BFFu32,
                "retab" => 0xD65F_0FFFu32,
                _ => unreachable!(),
            };
            vec![w]
        }
        "clrex" => {
            let crm = if ops.is_empty() {
                0xFu32
            } else if ops.len() == 1 {
                let v = parse_imm(&ops[0])?;
                if !(0..=15).contains(&v) {
                    bail!("clrex 立即数必须在 0..=15 之间: {v}");
                }
                v as u32
            } else {
                bail!("clrex 最多接受 1 个立即数参数");
            };
            vec![0xD503_305F | (crm << 8)]
        }
        "isb" => {
            let crm = if ops.is_empty() {
                0xFu32
            } else if ops.len() == 1 {
                let s = ops[0].trim().to_ascii_lowercase();
                if s == "sy" {
                    0xFu32
                } else {
                    let v = parse_imm(&ops[0])?;
                    if !(0..=15).contains(&v) {
                        bail!("isb 参数仅支持 sy 或 0..=15，收到 '{}'", ops[0]);
                    }
                    v as u32
                }
            } else {
                bail!("isb 最多接受 1 个参数");
            };
            vec![0xD503_30DF | (crm << 8)]
        }
        "dsb" | "dmb" => {
            let crm = if ops.is_empty() {
                0xFu32 // 默认 sy
            } else if ops.len() == 1 {
                parse_barrier_domain(&ops[0])
                    .ok_or_else(|| anyhow!("未知屏障域: '{}'", ops[0]))?
            } else {
                bail!("{mnemonic} 最多接受 1 个屏障域参数");
            };
            let base = if mnemonic == "dsb" {
                0xD503_309Fu32
            } else {
                0xD503_30BFu32
            };
            vec![base | (crm << 8)]
        }
        "bti" => {
            let crm_op2 = if ops.is_empty() {
                0x00u32
            } else if ops.len() == 1 {
                match ops[0].trim().to_ascii_lowercase().as_str() {
                    "c" => 0x40u32,
                    "j" => 0x80u32,
                    "jc" => 0xC0u32,
                    other => bail!("bti 仅支持空/c/j/jc，收到 '{other}'"),
                }
            } else {
                bail!("bti 最多接受 1 个参数");
            };
            vec![0xD503_241F | crm_op2]
        }

        // ---- 系统寄存器读写 MRS / MSR ----
        "mrs" => {
            if ops.len() != 2 {
                bail!("mrs 需要 2 个操作数: Xt, sysreg");
            }
            let rt = parse_reg(&ops[0])
                .ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?
                .require_64("mrs")?
                .require_gpr_or_zr("mrs")?;
            let (op0, op1, crn, crm, op2) =
                parse_sysreg(&ops[1]).ok_or_else(|| anyhow!("未知系统寄存器: {}", ops[1]))?;
            vec![
                0xD530_0000
                    | ((op0 - 2) << 19)
                    | (op1 << 16)
                    | (crn << 12)
                    | (crm << 8)
                    | (op2 << 5)
                    | rt,
            ]
        }
        "msr" => {
            if ops.len() != 2 {
                bail!("msr 需要 2 个操作数: sysreg, Xt");
            }
            let (op0, op1, crn, crm, op2) =
                parse_sysreg(&ops[0]).ok_or_else(|| anyhow!("未知系统寄存器: {}", ops[0]))?;
            let rt = parse_reg(&ops[1])
                .ok_or_else(|| anyhow!("无效寄存器: {}", ops[1]))?
                .require_64("msr")?
                .require_gpr_or_zr("msr")?;
            vec![
                0xD510_0000
                    | ((op0 - 2) << 19)
                    | (op1 << 16)
                    | (crn << 12)
                    | (crm << 8)
                    | (op2 << 5)
                    | rt,
            ]
        }

        // ---- 间接分支 / 返回 / 异常 ----
        "ret" => {
            let rn = if ops.is_empty() {
                30u32
            } else if ops.len() == 1 {
                parse_reg(&ops[0])
                    .ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?
                    .require_64("ret")?
                    .require_gpr_or_zr("ret")?
            } else {
                bail!("ret 最多接受 1 个寄存器");
            };
            vec![0xD65F_0000 | (rn << 5)]
        }
        "br" | "blr" => {
            if ops.len() != 1 {
                bail!("{mnemonic} 需要 1 个 64 位寄存器");
            }
            let rn = parse_reg(&ops[0])
                .ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?
                .require_64(mnemonic)?
                .require_gpr_or_zr(mnemonic)?;
            let base = if mnemonic == "br" {
                0xD61F_0000
            } else {
                0xD63F_0000
            };
            vec![base | (rn << 5)]
        }
        "svc" | "hvc" | "brk" | "hlt" => {
            if ops.len() != 1 {
                bail!("{mnemonic} 需要 1 个 16 位立即数");
            }
            let imm = parse_imm(&ops[0])?;
            if !(0..=0xFFFF).contains(&imm) {
                bail!("{mnemonic} 立即数超出 u16 范围: {imm}");
            }
            let base = match mnemonic {
                "svc" => 0xD400_0001u32,
                "hvc" => 0xD400_0002u32,
                "brk" => 0xD420_0000u32,
                "hlt" => 0xD440_0000u32,
                _ => unreachable!(),
            };
            vec![base | ((imm as u32) << 5)]
        }

        // ---- 直接分支 B / BL / CBZ / CBNZ / TBZ / TBNZ ----
        "b" | "bl" => {
            if ops.len() != 1 {
                bail!("{mnemonic} 需要 1 个跳转目标");
            }
            let delta = resolve_pc_delta(&ops[0], pc, labels)?;
            if (delta & 3) != 0 {
                bail!("跳转偏移 {delta} 未 4 字节对齐");
            }
            let imm26 = check_signed_bits(delta >> 2, 26, mnemonic)?;
            let base = if mnemonic == "b" {
                0x1400_0000u32
            } else {
                0x9400_0000u32
            };
            vec![base | imm26]
        }
        "cbz" | "cbnz" => {
            if ops.len() != 2 {
                bail!("{mnemonic} 需要 2 个操作数: Rt, target");
            }
            let rt = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
            let rt_num = rt.require_gpr_or_zr(mnemonic)?;
            let delta = resolve_pc_delta(&ops[1], pc, labels)?;
            if (delta & 3) != 0 {
                bail!("跳转偏移 {delta} 未 4 字节对齐");
            }
            let imm19 = check_signed_bits(delta >> 2, 19, mnemonic)?;
            let sf = u32::from(rt.is_64) << 31;
            let op = if mnemonic == "cbnz" { 1u32 << 24 } else { 0 };
            vec![sf | 0x3400_0000 | op | (imm19 << 5) | rt_num]
        }
        "tbz" | "tbnz" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Rt, #bit, target");
            }
            let rt = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
            let rt_num = rt.require_gpr_or_zr(mnemonic)?;
            let bit = parse_imm(&ops[1])?;
            let max_bit = if rt.is_64 { 63 } else { 31 };
            if !(0..=max_bit).contains(&bit) {
                bail!("{mnemonic} 位索引超出范围: {bit}");
            }
            let delta = resolve_pc_delta(&ops[2], pc, labels)?;
            if (delta & 3) != 0 {
                bail!("跳转偏移 {delta} 未 4 字节对齐");
            }
            let imm14 = check_signed_bits(delta >> 2, 14, mnemonic)?;
            let b5 = ((bit as u32) >> 5) << 31;
            let b40 = ((bit as u32) & 31) << 19;
            let op = if mnemonic == "tbnz" { 1u32 << 24 } else { 0 };
            vec![b5 | 0x3600_0000 | op | b40 | (imm14 << 5) | rt_num]
        }

        // ---- ADR / ADRP ----
        "adr" | "adrp" => {
            if ops.len() != 2 {
                bail!("{mnemonic} 需要 2 个操作数: Xd, target");
            }
            let rd = parse_reg(&ops[0])
                .ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?
                .require_64(mnemonic)?
                .require_gpr_or_zr(mnemonic)?;
            let imm = if mnemonic == "adr" {
                let delta = resolve_pc_delta(&ops[1], pc, labels)?;
                check_signed_bits(delta, 21, "adr")?
            } else {
                let trimmed = ops[1].trim();
                let delta_pages = if let Some(after_hash) = trimmed.strip_prefix('#') {
                    let off = parse_int_literal(after_hash)?;
                    if (off & 0xFFF) != 0 {
                        bail!("adrp 偏移 {off} 未 4KB 对齐");
                    }
                    off >> 12
                } else {
                    let target = parse_expr(trimmed)?.eval_addr(labels)?;
                    (((target & !0xFFF) as i128) - ((pc & !0xFFF) as i128)) >> 12
                };
                check_signed_bits(delta_pages, 21, "adrp")?
            };
            let immlo = imm & 3;
            let immhi = (imm >> 2) & 0x7_FFFF;
            let op = if mnemonic == "adrp" { 1u32 << 31 } else { 0 };
            vec![op | (immlo << 29) | 0x1000_0000 | (immhi << 5) | rd]
        }

        // ---- MOVZ / MOVN / MOVK / MOV / MVN ----
        "movz" | "movn" | "movk" => {
            if ops.len() != 2 && ops.len() != 3 {
                bail!("{mnemonic} 需要 2 或 3 个操作数");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
            let rd_num = rd.require_gpr_or_zr(mnemonic)?;
            let imm = parse_imm(&ops[1])?;
            if !(0..=0xFFFF).contains(&imm) {
                bail!("{mnemonic} 立即数超出 u16 范围: {imm}");
            }
            let hw = if ops.len() == 3 {
                let (sk, amt) = parse_shift(&ops[2])?;
                if !matches!(sk, ShiftKind::Lsl) || !amt.is_multiple_of(16) {
                    bail!("{mnemonic} 移位必须是 lsl #0/#16/#32/#48");
                }
                let max_amt = if rd.is_64 { 48 } else { 16 };
                if amt > max_amt {
                    bail!("{mnemonic} 移位量超出寄存器位宽: {amt}");
                }
                u32::from(amt / 16)
            } else {
                0
            };
            let sf = u32::from(rd.is_64) << 31;
            let opc = match mnemonic {
                "movn" => 0x1280_0000u32,
                "movz" => 0x5280_0000u32,
                "movk" => 0x7280_0000u32,
                _ => unreachable!(),
            };
            vec![sf | opc | (hw << 21) | ((imm as u32) << 5) | rd_num]
        }
        "mov" => {
            if ops.len() != 2 {
                return Ok(None);
            }
            let Some(rd) = parse_reg(&ops[0]) else {
                return Ok(None); // 交由 SIMD 向量 `mov v0.16b, v1.16b` 处理
            };
            if let Some(rm) = parse_reg(&ops[1]) {
                if rd.is_64 != rm.is_64 {
                    bail!("mov 源/目的寄存器位宽不一致");
                }
                let sf = u32::from(rd.is_64) << 31;
                if rd.is_sp || rm.is_sp {
                    let rd_num = rd.require_gpr_or_sp("mov")?;
                    let rn_num = rm.require_gpr_or_sp("mov")?;
                    return Ok(Some(vec![sf | 0x1100_0000 | (rn_num << 5) | rd_num]));
                }
                let rd_num = rd.require_gpr_or_zr("mov")?;
                let rm_num = rm.require_gpr_or_zr("mov")?;
                return Ok(Some(vec![sf | 0x2A00_03E0 | (rm_num << 16) | rd_num]));
            }
            if super::parse::parse_vec_elem(&ops[1]).is_some() {
                return Ok(None); // 交由 SIMD `mov xd, vn.d[idx]` (umov 别名) 处理
            }
            let rd_num = rd.require_gpr_or_zr("mov #imm")?;
            let imm = super::parse::check_int_range(parse_imm(&ops[1])?, rd.is_64, "mov #imm")?;
            encode_mov_imm(rd_num as u8, rd.is_64, imm)
        }
        "mvn" => {
            if ops.len() != 2 && ops.len() != 3 {
                bail!("mvn 需要 2 或 3 个操作数");
            }
            let Some(rd) = parse_reg(&ops[0]) else {
                return Ok(None); // 交由 SIMD `mvn v0.16b, v1.16b` 处理
            };
            let rm = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[1]))?;
            if rd.is_64 != rm.is_64 {
                bail!("mvn 寄存器位宽不一致");
            }
            let (sk, amt) = if ops.len() == 3 {
                let (sk, a) = parse_shift(&ops[2])?;
                if !rd.is_64 && a >= 32 {
                    bail!("32 位 mvn 移位量超出范围: {a}");
                }
                (sk, a)
            } else {
                (ShiftKind::Lsl, 0)
            };
            let sf = u32::from(rd.is_64) << 31;
            vec![
                sf | 0x2A20_03E0
                    | ((sk as u32) << 22)
                    | (rm.require_gpr_or_zr("mvn")? << 16)
                    | (u32::from(amt) << 10)
                    | rd.require_gpr_or_zr("mvn")?,
            ]
        }

        // ---- 符号/零扩展与位域：SXTB/SXTH/SXTW/UXTB/UXTH/SBFM/BFM/UBFM/SBFX/UBFX/BFI/BFXIL/EXTR ----
        "sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" => encode_extend_alias(mnemonic, ops)?,
        "sbfm" | "bfm" | "ubfm" | "sbfx" | "ubfx" | "bfi" | "bfxil" => {
            encode_bitfield(mnemonic, ops)?
        }
        "extr" => {
            if ops.len() != 4 {
                bail!("extr 需要 4 个操作数: Rd, Rn, Rm, #lsb");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rm = parse_reg(&ops[2]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rd.is_64 != rn.is_64 || rd.is_64 != rm.is_64 {
                bail!("extr 寄存器位宽不一致");
            }
            let lsb = parse_imm(&ops[3])?;
            let width = if rd.is_64 { 64 } else { 32 };
            if !(0..width).contains(&lsb) {
                bail!("extr lsb 超出范围: {lsb}");
            }
            let sf = u32::from(rd.is_64) << 31;
            let n = u32::from(rd.is_64) << 22;
            vec![
                sf | 0x1380_0000
                    | n
                    | (rm.require_gpr_or_zr("extr")? << 16)
                    | ((lsb as u32) << 10)
                    | (rn.require_gpr_or_zr("extr")? << 5)
                    | rd.require_gpr_or_zr("extr")?,
            ]
        }

        // ---- 1-source 位操作：RBIT / REV16 / REV32 / REV / CLZ / CLS ----
        "rbit" | "rev16" | "rev32" | "rev" | "clz" | "cls" => {
            if ops.len() != 2 {
                return Ok(None); // `rev32`/`rev64` 可能是向量版本
            }
            let Some(rd) = parse_reg(&ops[0]) else {
                return Ok(None);
            };
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[1]))?;
            if rd.is_64 != rn.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            if mnemonic == "rev32" && !rd.is_64 {
                bail!("rev32 仅支持 64 位寄存器 Xd, Xn");
            }
            let opcode = match mnemonic {
                "rbit" => 0u32,
                "rev16" => 1u32,
                "rev32" => 2u32,
                "rev" => {
                    if rd.is_64 {
                        3u32
                    } else {
                        2u32
                    }
                }
                "clz" => 4u32,
                "cls" => 5u32,
                _ => unreachable!(),
            };
            let sf = u32::from(rd.is_64) << 31;
            vec![
                sf | 0x5AC0_0000
                    | (opcode << 10)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ]
        }

        // ---- ADD / ADDS / SUB / SUBS / CMP / CMN / NEG / NEGS ----
        "add" | "adds" | "sub" | "subs" => {
            if ops.first().and_then(|o| parse_reg(o)).is_none() {
                return Ok(None); // 交由 NEON 向量 add/sub
            }
            let (is_sub, set_flags) = match mnemonic {
                "add" => (false, false),
                "adds" => (false, true),
                "sub" => (true, false),
                "subs" => (true, true),
                _ => unreachable!(),
            };
            encode_add_sub(ops, is_sub, set_flags, None)?
        }
        "cmp" | "cmn" => {
            if ops.len() != 2 && ops.len() != 3 {
                bail!("{mnemonic} 需要 2 或 3 个操作数");
            }
            let rn = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
            let zr = Reg {
                num: 31,
                is_64: rn.is_64,
                is_sp: false,
            };
            encode_add_sub(ops, mnemonic == "cmp", true, Some(zr))?
        }
        "neg" | "negs" => {
            if ops.len() != 2 && ops.len() != 3 {
                bail!("{mnemonic} 需要 2 或 3 个操作数");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
            let zr_name = if rd.is_64 { "xzr" } else { "wzr" }.to_string();
            let mut synth = vec![ops[0].clone(), zr_name, ops[1].clone()];
            if ops.len() == 3 {
                synth.push(ops[2].clone());
            }
            encode_add_sub(&synth, true, mnemonic == "negs", None)?
        }

        // ---- 带进位加减 ADC / ADCS / SBC / SBCS / NGC / NGCS ----
        "adc" | "adcs" | "sbc" | "sbcs" | "ngc" | "ngcs" => encode_adc_sbc(mnemonic, ops)?,

        // ---- 逻辑位运算（含向量分派） ----
        "and" | "ands" | "orr" | "orn" | "eor" | "eon" | "bic" | "bics" => {
            if ops.first().and_then(|o| parse_reg(o)).is_none() {
                return Ok(None); // 交由 NEON 向量逻辑
            }
            encode_logical(mnemonic, ops, None)?
        }
        "tst" => {
            if ops.len() != 2 && ops.len() != 3 {
                bail!("tst 需要 2 或 3 个操作数");
            }
            let rn = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
            let zr = Reg {
                num: 31,
                is_64: rn.is_64,
                is_sp: false,
            };
            encode_logical("ands", ops, Some(zr))?
        }

        // ---- 移位 LSL / LSR / ASR / ROR ----
        "lsl" | "lsr" | "asr" | "ror" => encode_shift_insn(mnemonic, ops)?,

        // ---- 乘除与长乘/高位乘 ----
        "mul" => {
            if ops.first().and_then(|o| parse_reg(o)).is_none() {
                return Ok(None); // 交由 NEON 向量 mul
            }
            encode_mul_family(mnemonic, ops)?
        }
        "mneg" | "madd" | "msub" | "smull" | "umull" | "smaddl" | "umaddl" | "smsubl"
        | "umsubl" | "smulh" | "umulh" | "udiv" | "sdiv" => encode_mul_family(mnemonic, ops)?,

        // ---- 条件选择与条件比较 ----
        "csel" | "csinc" | "csinv" | "csneg" | "cset" | "csetm" | "cinc" | "cinv" | "cneg"
        | "ccmp" | "ccmn" => encode_cond_ops(mnemonic, ops)?,

        // ---- 访存（若首操作数是 FP 寄存器则交由 simd 模块处理） ----
        "ldr" | "str" | "ldrb" | "strb" | "ldrh" | "strh" | "ldrsw" | "ldrsb" | "ldrsh"
        | "ldur" | "stur" | "ldurb" | "sturb" | "ldurh" | "sturh" | "ldursb" | "ldursh" => {
            if ops.first().and_then(|o| parse_reg(o)).is_none() {
                return Ok(None);
            }
            encode_load_store(mnemonic, ops, pc, labels)?
        }
        "ldp" | "stp" | "ldnp" | "stnp" => {
            if ops.first().and_then(|o| parse_reg(o)).is_none() {
                return Ok(None);
            }
            encode_load_store_pair(mnemonic, ops)?
        }

        // ---- 独占与释放/获取 & LSE 原子 ----
        "ldxr" | "ldaxr" | "stxr" | "stlxr" | "ldar" | "stlr" | "ldarb" | "stlrb" | "ldarh"
        | "stlrh" | "cas" | "casa" | "casl" | "casal" | "swp" | "swpa" | "swpl" | "swpal"
        | "ldadd" | "ldadda" | "ldaddl" | "ldaddal" => encode_atomic(mnemonic, ops)?,

        _ => return Ok(None),
    };
    Ok(Some(words))
}

fn encode_extend_alias(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 2 {
        bail!("{mnemonic} 需要 2 个操作数: Rd, Wn");
    }
    let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
    let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[1]))?;
    rn.require_32(mnemonic)?;
    let rd_num = rd.require_gpr_or_zr(mnemonic)?;
    let rn_num = rn.require_gpr_or_zr(mnemonic)?;
    match mnemonic {
        "sxtb" => {
            let sf = u32::from(rd.is_64);
            Ok(vec![
                (sf << 31) | 0x1300_0000 | (sf << 22) | (7 << 10) | (rn_num << 5) | rd_num,
            ])
        }
        "sxth" => {
            let sf = u32::from(rd.is_64);
            Ok(vec![
                (sf << 31) | 0x1300_0000 | (sf << 22) | (15 << 10) | (rn_num << 5) | rd_num,
            ])
        }
        "sxtw" => {
            rd.require_64("sxtw")?;
            Ok(vec![0x9340_7C00 | (rn_num << 5) | rd_num])
        }
        "uxtb" => {
            rd.require_32("uxtb")?;
            Ok(vec![0x5300_1C00 | (rn_num << 5) | rd_num])
        }
        "uxth" => {
            rd.require_32("uxth")?;
            Ok(vec![0x5300_3C00 | (rn_num << 5) | rd_num])
        }
        _ => unreachable!(),
    }
}

fn encode_bitfield(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 4 {
        bail!("{mnemonic} 需要 4 个操作数");
    }
    let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
    let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[1]))?;
    if rd.is_64 != rn.is_64 {
        bail!("{mnemonic} 寄存器位宽不一致");
    }
    let width_bits = if rd.is_64 { 64i128 } else { 32i128 };
    let a = parse_imm(&ops[2])?;
    let b = parse_imm(&ops[3])?;

    let (opc, immr, imms) = match mnemonic {
        "sbfm" | "bfm" | "ubfm" => {
            if !(0..width_bits).contains(&a) || !(0..width_bits).contains(&b) {
                bail!("{mnemonic} immr/imms 超出范围");
            }
            let opc = match mnemonic {
                "sbfm" => 0x1300_0000u32,
                "bfm" => 0x3300_0000u32,
                "ubfm" => 0x5300_0000u32,
                _ => unreachable!(),
            };
            (opc, a as u32, b as u32)
        }
        "sbfx" | "ubfx" | "bfxil" => {
            let lsb = a;
            let w = b;
            if !(0..width_bits).contains(&lsb) || !(1..=(width_bits - lsb)).contains(&w) {
                bail!("{mnemonic} lsb={lsb}, width={w} 超出位宽 {width_bits}");
            }
            let opc = match mnemonic {
                "sbfx" => 0x1300_0000u32,
                "bfxil" => 0x3300_0000u32,
                "ubfx" => 0x5300_0000u32,
                _ => unreachable!(),
            };
            (opc, lsb as u32, (lsb + w - 1) as u32)
        }
        "bfi" => {
            let lsb = a;
            let w = b;
            if !(0..width_bits).contains(&lsb) || !(1..=(width_bits - lsb)).contains(&w) {
                bail!("bfi lsb={lsb}, width={w} 超出位宽 {width_bits}");
            }
            let immr = ((width_bits - lsb) % width_bits) as u32;
            (0x3300_0000u32, immr, (w - 1) as u32)
        }
        _ => unreachable!(),
    };
    let sf = u32::from(rd.is_64);
    Ok(vec![
        (sf << 31)
            | opc
            | (sf << 22)
            | (immr << 16)
            | (imms << 10)
            | (rn.require_gpr_or_zr(mnemonic)? << 5)
            | rd.require_gpr_or_zr(mnemonic)?,
    ])
}

fn encode_add_sub(
    ops: &[String],
    is_sub: bool,
    set_flags: bool,
    implicit_rd: Option<Reg>,
) -> Result<Vec<u32>> {
    let (rd, rn_tok, op2_tok, mod_tok) = if let Some(rd) = implicit_rd {
        if ops.len() != 2 && ops.len() != 3 {
            bail!("需要 2 或 3 个操作数");
        }
        (rd, &ops[0], &ops[1], ops.get(2))
    } else {
        if ops.len() != 3 && ops.len() != 4 {
            bail!("需要 3 或 4 个操作数");
        }
        let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效目的寄存器: {}", ops[0]))?;
        (rd, &ops[1], &ops[2], ops.get(3))
    };

    let rn = parse_reg(rn_tok).ok_or_else(|| anyhow!("无效源寄存器: {rn_tok}"))?;
    if rd.is_64 != rn.is_64 {
        bail!("寄存器位宽不一致");
    }
    let sf = u32::from(rd.is_64) << 31;
    let op = u32::from(is_sub) << 30;
    let s = u32::from(set_flags) << 29;

    // 寄存器操作数（支持移位寄存器 与 扩展寄存器 uxtw/sxtw/sp）
    if let Some(rm) = parse_reg(op2_tok) {
        // 扩展寄存器形式：`uxtb`/`uxth`/`uxtw`/`uxtx`/`sxtb`/`sxth`/`sxtw`/`sxtx` 或涉及 SP
        let ext_opt = mod_tok.and_then(|t| try_parse_extend(t));
        if let Some(ext_res) = ext_opt {
            let (ek, amt) = ext_res?;
            let needs_64_rm = rd.is_64 && matches!(ek, ExtendKind::Uxtx | ExtendKind::Sxtx);
            if needs_64_rm && !rm.is_64 {
                bail!("64 位 uxtx/sxtx 需要 64 位源寄存器 Xm");
            }
            if !needs_64_rm && rm.is_64 {
                bail!("该扩展选项需要 32 位源寄存器 Wm");
            }
            let rd_num = if set_flags {
                rd.require_gpr_or_zr("adds/subs ext")?
            } else {
                rd.require_gpr_or_sp("add/sub ext")?
            };
            let rn_num = rn.require_gpr_or_sp("add/sub ext")?;
            let rm_num = rm.require_gpr_or_zr("add/sub ext")?;
            return Ok(vec![
                sf | op
                    | s
                    | 0x0B20_0000
                    | (rm_num << 16)
                    | ((ek as u32) << 13)
                    | (u32::from(amt) << 10)
                    | (rn_num << 5)
                    | rd_num,
            ]);
        }
        if rd.is_sp || rn.is_sp {
            // `add sp, sp, x0[, lsl #0..4]` 或 `cmp sp, x0` -> 自动编码为扩展寄存器 uxtx/uxtw
            if rm.is_64 != rd.is_64 {
                bail!("SP 寄存器运算操作数位宽不一致");
            }
            let amt = if let Some(st) = mod_tok {
                let (k, a) = parse_shift(st)?;
                if !matches!(k, ShiftKind::Lsl) || a > 4 {
                    bail!("SP 扩展寄存器运算仅支持 lsl #0..4");
                }
                a
            } else {
                0
            };
            let opt = if rd.is_64 { 0b011u32 } else { 0b010u32 };
            let rd_num = if set_flags {
                rd.require_gpr_or_zr("cmp sp")?
            } else {
                rd.require_gpr_or_sp("add/sub sp")?
            };
            let rn_num = rn.require_gpr_or_sp("add/sub sp")?;
            let rm_num = rm.require_gpr_or_zr("add/sub sp")?;
            return Ok(vec![
                sf | op
                    | s
                    | 0x0B20_0000
                    | (rm_num << 16)
                    | (opt << 13)
                    | (u32::from(amt) << 10)
                    | (rn_num << 5)
                    | rd_num,
            ]);
        }

        if rm.is_64 != rd.is_64 {
            bail!("源寄存器位宽不一致");
        }
        let (sk, amt) = if let Some(st) = mod_tok {
            let (k, a) = parse_shift(st)?;
            if matches!(k, ShiftKind::Ror) {
                bail!("add/sub 移位寄存器不支持 ror");
            }
            if !rd.is_64 && a >= 32 {
                bail!("32 位指令移位量超出范围: {a}");
            }
            (k, a)
        } else {
            (ShiftKind::Lsl, 0)
        };
        let rd_num = rd.require_gpr_or_zr("add/sub reg")?;
        let rn_num = rn.require_gpr_or_zr("add/sub reg")?;
        let rm_num = rm.require_gpr_or_zr("add/sub reg")?;
        return Ok(vec![
            sf | op
                | s
                | 0x0B00_0000
                | ((sk as u32) << 22)
                | (rm_num << 16)
                | (u32::from(amt) << 10)
                | (rn_num << 5)
                | rd_num,
        ]);
    }

    // 立即数操作数
    let mut imm = parse_imm(op2_tok)?;
    let mut actual_sub = is_sub;
    if imm < 0 {
        imm = -imm;
        actual_sub = !actual_sub;
    }
    let mut sh = 0u32;
    if let Some(st) = mod_tok {
        let (k, a) = parse_shift(st)?;
        if !matches!(k, ShiftKind::Lsl) || (a != 0 && a != 12) {
            bail!("add/sub 立即数仅支持 lsl #0 或 lsl #12");
        }
        if a == 12 {
            sh = 1;
        }
    } else if imm > 0xFFF && (imm & 0xFFF) == 0 && (imm >> 12) <= 0xFFF {
        imm >>= 12;
        sh = 1;
    }
    if !(0..=0xFFF).contains(&imm) {
        bail!("add/sub 立即数 {imm} 超出 12-bit 范围");
    }
    let rd_num = if set_flags {
        rd.require_gpr_or_zr("adds/subs imm")?
    } else {
        rd.require_gpr_or_sp("add/sub imm")?
    };
    let rn_num = rn.require_gpr_or_sp("add/sub imm")?;
    let op_final = u32::from(actual_sub) << 30;
    Ok(vec![
        sf | op_final | s | 0x1100_0000 | (sh << 22) | ((imm as u32) << 10) | (rn_num << 5) | rd_num,
    ])
}

fn encode_adc_sbc(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    let (is_sub, set_flags, rd, rn, rm) = match mnemonic {
        "ngc" | "ngcs" => {
            if ops.len() != 2 {
                bail!("{mnemonic} 需要 2 个操作数: Rd, Rm");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rm = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let zr = Reg {
                num: 31,
                is_64: rd.is_64,
                is_sp: false,
            };
            (true, mnemonic == "ngcs", rd, zr, rm)
        }
        _ => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Rd, Rn, Rm");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rm = parse_reg(&ops[2]).ok_or_else(|| anyhow!("无效寄存器"))?;
            (
                mnemonic.starts_with("sbc"),
                mnemonic.ends_with('s'),
                rd,
                rn,
                rm,
            )
        }
    };
    if rd.is_64 != rn.is_64 || rd.is_64 != rm.is_64 {
        bail!("{mnemonic} 寄存器位宽不一致");
    }
    let sf = u32::from(rd.is_64) << 31;
    let op = u32::from(is_sub) << 30;
    let s = u32::from(set_flags) << 29;
    Ok(vec![
        sf | op
            | s
            | 0x1A00_0000
            | (rm.require_gpr_or_zr(mnemonic)? << 16)
            | (rn.require_gpr_or_zr(mnemonic)? << 5)
            | rd.require_gpr_or_zr(mnemonic)?,
    ])
}

fn encode_logical(
    mnemonic: &str,
    ops: &[String],
    implicit_rd: Option<Reg>,
) -> Result<Vec<u32>> {
    let (rd, rn_tok, op2_tok, shift_tok) = if let Some(rd) = implicit_rd {
        if ops.len() != 2 && ops.len() != 3 {
            bail!("需要 2 或 3 个操作数");
        }
        (rd, &ops[0], &ops[1], ops.get(2))
    } else {
        if ops.len() != 3 && ops.len() != 4 {
            bail!("需要 3 或 4 个操作数");
        }
        let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效目的寄存器: {}", ops[0]))?;
        (rd, &ops[1], &ops[2], ops.get(3))
    };

    let rn = parse_reg(rn_tok).ok_or_else(|| anyhow!("无效源寄存器: {rn_tok}"))?;
    if rd.is_64 != rn.is_64 {
        bail!("寄存器位宽不一致");
    }
    let sf = u32::from(rd.is_64) << 31;

    if let Some(rm) = parse_reg(op2_tok) {
        if rm.is_64 != rd.is_64 {
            bail!("寄存器位宽不一致");
        }
        let (sk, amt) = if let Some(st) = shift_tok {
            let (k, a) = parse_shift(st)?;
            if !rd.is_64 && a >= 32 {
                bail!("32 位逻辑指令移位量超出范围: {a}");
            }
            (k, a)
        } else {
            (ShiftKind::Lsl, 0)
        };
        let (opc, n_bit) = match mnemonic {
            "and" => (0u32, 0u32),
            "bic" => (0u32, 1u32),
            "orr" => (1u32, 0u32),
            "orn" => (1u32, 1u32),
            "eor" => (2u32, 0u32),
            "eon" => (2u32, 1u32),
            "ands" => (3u32, 0u32),
            "bics" => (3u32, 1u32),
            _ => unreachable!(),
        };
        return Ok(vec![
            sf | (opc << 29)
                | 0x0A00_0000
                | ((sk as u32) << 22)
                | (n_bit << 21)
                | (rm.require_gpr_or_zr(mnemonic)? << 16)
                | (u32::from(amt) << 10)
                | (rn.require_gpr_or_zr(mnemonic)? << 5)
                | rd.require_gpr_or_zr(mnemonic)?,
        ]);
    }

    if shift_tok.is_some() {
        bail!("{mnemonic} 立即数形式不支持额外移位参数");
    }
    let opc = match mnemonic {
        "and" => 0u32,
        "orr" => 1u32,
        "eor" => 2u32,
        "ands" => 3u32,
        _ => bail!("{mnemonic} 不支持立即数操作数"),
    };
    let imm = super::parse::check_int_range(parse_imm(op2_tok)?, rd.is_64, mnemonic)?;
    let (n, immr, imms) = encode_logical_imm(imm, rd.is_64)
        .ok_or_else(|| anyhow!("0x{imm:x} 不是合法的 ARM64 位掩码逻辑立即数"))?;
    let rd_num = if mnemonic == "ands" {
        rd.require_gpr_or_zr(mnemonic)?
    } else {
        rd.require_gpr_or_sp(mnemonic)?
    };
    let rn_num = rn.require_gpr_or_zr(mnemonic)?;
    Ok(vec![
        sf | (opc << 29)
            | 0x1200_0000
            | (u32::from(n) << 22)
            | (u32::from(immr) << 16)
            | (u32::from(imms) << 10)
            | (rn_num << 5)
            | rd_num,
    ])
}

fn encode_shift_insn(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 3 {
        bail!("{mnemonic} 需要 3 个操作数: Rd, Rn, Rm/#imm");
    }
    let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
    let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[1]))?;
    if rd.is_64 != rn.is_64 {
        bail!("{mnemonic} 寄存器位宽不一致");
    }
    let sf = u32::from(rd.is_64) << 31;
    let rd_num = rd.require_gpr_or_zr(mnemonic)?;
    let rn_num = rn.require_gpr_or_zr(mnemonic)?;

    if let Some(rm) = parse_reg(&ops[2]) {
        if rm.is_64 != rd.is_64 {
            bail!("{mnemonic} 移位寄存器位宽不一致");
        }
        let op2 = match mnemonic {
            "lsl" => 0x0u32,
            "lsr" => 0x1u32,
            "asr" => 0x2u32,
            "ror" => 0x3u32,
            _ => unreachable!(),
        };
        return Ok(vec![
            sf | 0x1AC0_2000
                | (rm.require_gpr_or_zr(mnemonic)? << 16)
                | (op2 << 10)
                | (rn_num << 5)
                | rd_num,
        ]);
    }

    let width = if rd.is_64 { 64i128 } else { 32i128 };
    let amt = parse_imm(&ops[2])?;
    if !(0..width).contains(&amt) {
        bail!("{mnemonic} 移位量 {amt} 超出 [0, {})", width);
    }
    let n_bit = u32::from(rd.is_64) << 22;
    let shift = amt as u32;
    let w_u32 = width as u32;
    match mnemonic {
        "lsl" => {
            let immr = (w_u32 - shift) % w_u32;
            let imms = w_u32 - 1 - shift;
            Ok(vec![
                sf | 0x5300_0000 | n_bit | (immr << 16) | (imms << 10) | (rn_num << 5) | rd_num,
            ])
        }
        "lsr" => {
            let imms = w_u32 - 1;
            Ok(vec![
                sf | 0x5300_0000 | n_bit | (shift << 16) | (imms << 10) | (rn_num << 5) | rd_num,
            ])
        }
        "asr" => {
            let imms = w_u32 - 1;
            Ok(vec![
                sf | 0x1300_0000 | n_bit | (shift << 16) | (imms << 10) | (rn_num << 5) | rd_num,
            ])
        }
        "ror" => Ok(vec![
            sf | 0x1380_0000 | n_bit | (rn_num << 16) | (shift << 10) | (rn_num << 5) | rd_num,
        ]),
        _ => unreachable!(),
    }
}

fn encode_mul_family(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    match mnemonic {
        "mul" | "mneg" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个寄存器操作数");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rm = parse_reg(&ops[2]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rd.is_64 != rn.is_64 || rd.is_64 != rm.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            let sf = u32::from(rd.is_64) << 31;
            let o0 = if mnemonic == "mneg" { 1u32 << 15 } else { 0 };
            Ok(vec![
                sf | 0x1B00_7C00
                    | o0
                    | (rm.require_gpr_or_zr(mnemonic)? << 16)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "madd" | "msub" => {
            if ops.len() != 4 {
                bail!("{mnemonic} 需要 4 个寄存器操作数");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rm = parse_reg(&ops[2]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let ra = parse_reg(&ops[3]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rd.is_64 != rn.is_64 || rd.is_64 != rm.is_64 || rd.is_64 != ra.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            let sf = u32::from(rd.is_64) << 31;
            let o0 = if mnemonic == "msub" { 1u32 << 15 } else { 0 };
            Ok(vec![
                sf | 0x1B00_0000
                    | (rm.require_gpr_or_zr(mnemonic)? << 16)
                    | o0
                    | (ra.require_gpr_or_zr(mnemonic)? << 10)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "smull" | "umull" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Xd, Wn, Wm");
            }
            let rd = parse_reg(&ops[0])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_64(mnemonic)?;
            let rn = parse_reg(&ops[1])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_32(mnemonic)?;
            let rm = parse_reg(&ops[2])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_32(mnemonic)?;
            let base = if mnemonic == "smull" {
                0x9B20_7C00u32
            } else {
                0x9BA0_7C00u32
            };
            Ok(vec![
                base | (rm.require_gpr_or_zr(mnemonic)? << 16)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "smaddl" | "smsubl" | "umaddl" | "umsubl" => {
            if ops.len() != 4 {
                bail!("{mnemonic} 需要 4 个操作数: Xd, Wn, Wm, Xa");
            }
            let rd = parse_reg(&ops[0])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_64(mnemonic)?;
            let rn = parse_reg(&ops[1])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_32(mnemonic)?;
            let rm = parse_reg(&ops[2])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_32(mnemonic)?;
            let ra = parse_reg(&ops[3])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_64(mnemonic)?;
            let base = if mnemonic.starts_with('s') {
                0x9B20_0000u32
            } else {
                0x9BA0_0000u32
            };
            let o0 = if mnemonic.contains("sub") {
                1u32 << 15
            } else {
                0
            };
            Ok(vec![
                base | (rm.require_gpr_or_zr(mnemonic)? << 16)
                    | o0
                    | (ra.require_gpr_or_zr(mnemonic)? << 10)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "smulh" | "umulh" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Xd, Xn, Xm");
            }
            let rd = parse_reg(&ops[0])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_64(mnemonic)?;
            let rn = parse_reg(&ops[1])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_64(mnemonic)?;
            let rm = parse_reg(&ops[2])
                .ok_or_else(|| anyhow!("无效寄存器"))?
                .require_64(mnemonic)?;
            let base = if mnemonic == "smulh" {
                0x9B40_7C00u32
            } else {
                0x9BC0_7C00u32
            };
            Ok(vec![
                base | (rm.require_gpr_or_zr(mnemonic)? << 16)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "udiv" | "sdiv" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个寄存器操作数");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rm = parse_reg(&ops[2]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rd.is_64 != rn.is_64 || rd.is_64 != rm.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            let sf = u32::from(rd.is_64) << 31;
            let op = if mnemonic == "sdiv" {
                0x1AC0_0C00u32
            } else {
                0x1AC0_0800u32
            };
            Ok(vec![
                sf | op
                    | (rm.require_gpr_or_zr(mnemonic)? << 16)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        _ => unreachable!(),
    }
}

fn encode_cond_ops(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    match mnemonic {
        "csel" | "csinc" | "csinv" | "csneg" => {
            if ops.len() != 4 {
                bail!("{mnemonic} 需要 4 个操作数: Rd, Rn, Rm, cond");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rm = parse_reg(&ops[2]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rd.is_64 != rn.is_64 || rd.is_64 != rm.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            let cond = parse_cond(&ops[3]).ok_or_else(|| anyhow!("未知条件码: {}", ops[3]))?;
            let sf = u32::from(rd.is_64) << 31;
            let (op, o2) = match mnemonic {
                "csel" => (0u32, 0u32),
                "csinc" => (0u32, 1u32),
                "csinv" => (1u32, 0u32),
                "csneg" => (1u32, 1u32),
                _ => unreachable!(),
            };
            Ok(vec![
                sf | (op << 30)
                    | 0x1A80_0000
                    | (rm.require_gpr_or_zr(mnemonic)? << 16)
                    | (cond << 12)
                    | (o2 << 10)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "cset" | "csetm" => {
            if ops.len() != 2 {
                bail!("{mnemonic} 需要 2 个操作数: Rd, cond");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let cond = parse_cond(&ops[1]).ok_or_else(|| anyhow!("未知条件码: {}", ops[1]))?;
            if cond >= 0xE {
                bail!("{mnemonic} 不支持条件码 al/nv");
            }
            let inv_cond = cond ^ 1;
            let sf = u32::from(rd.is_64) << 31;
            let base = if mnemonic == "cset" {
                0x1A9F_07E0u32 // CSINC Rd, ZR, ZR, invert(cond)
            } else {
                0x5A9F_03E0u32 // CSINV Rd, ZR, ZR, invert(cond)
            };
            Ok(vec![
                sf | base | (inv_cond << 12) | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "cinc" | "cinv" | "cneg" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Rd, Rn, cond");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rd.is_64 != rn.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            let cond = parse_cond(&ops[2]).ok_or_else(|| anyhow!("未知条件码: {}", ops[2]))?;
            if cond >= 0xE {
                bail!("{mnemonic} 不支持条件码 al/nv");
            }
            let inv_cond = cond ^ 1;
            let sf = u32::from(rd.is_64) << 31;
            let (op, o2) = match mnemonic {
                "cinc" => (0u32, 1u32),
                "cinv" => (1u32, 0u32),
                "cneg" => (1u32, 1u32),
                _ => unreachable!(),
            };
            let rn_num = rn.require_gpr_or_zr(mnemonic)?;
            Ok(vec![
                sf | (op << 30)
                    | 0x1A80_0000
                    | (rn_num << 16)
                    | (inv_cond << 12)
                    | (o2 << 10)
                    | (rn_num << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "ccmp" | "ccmn" => {
            if ops.len() != 4 {
                bail!("{mnemonic} 需要 4 个操作数: Rn, Rm/#imm5, #nzcv, cond");
            }
            let rn = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let nzcv = parse_imm(&ops[2])?;
            if !(0..=15).contains(&nzcv) {
                bail!("{mnemonic} nzcv 必须在 0..=15 之间: {nzcv}");
            }
            let cond = parse_cond(&ops[3]).ok_or_else(|| anyhow!("未知条件码: {}", ops[3]))?;
            let sf = u32::from(rn.is_64) << 31;
            let op = if mnemonic == "ccmp" { 1u32 << 30 } else { 0 };
            let rn_num = rn.require_gpr_or_zr(mnemonic)?;
            if let Some(rm) = parse_reg(&ops[1]) {
                if rm.is_64 != rn.is_64 {
                    bail!("{mnemonic} 寄存器位宽不一致");
                }
                Ok(vec![
                    sf | op
                        | 0x3A40_0000
                        | (rm.require_gpr_or_zr(mnemonic)? << 16)
                        | (cond << 12)
                        | (rn_num << 5)
                        | (nzcv as u32),
                ])
            } else {
                let imm5 = parse_imm(&ops[1])?;
                if !(0..=31).contains(&imm5) {
                    bail!("{mnemonic} 立即数必须在 0..=31 之间: {imm5}");
                }
                Ok(vec![
                    sf | op
                        | 0x3A40_0800
                        | ((imm5 as u32) << 16)
                        | (cond << 12)
                        | (rn_num << 5)
                        | (nzcv as u32),
                ])
            }
        }
        _ => unreachable!(),
    }
}

fn encode_load_store(
    mnemonic: &str,
    ops: &[String],
    pc: u64,
    labels: &HashMap<String, u64>,
) -> Result<Vec<u32>> {
    if ops.len() < 2 {
        bail!("{mnemonic} 至少需要 2 个操作数");
    }
    let rt = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
    let rt_num = rt.require_gpr_or_zr(mnemonic)?;

    // PC 相对字面量加载 `ldr Xt/Wt, label/#imm`
    if mnemonic == "ldr" && ops.len() == 2 && !ops[1].trim().starts_with('[') {
        let delta = resolve_pc_delta(&ops[1], pc, labels)?;
        if (delta & 3) != 0 {
            bail!("ldr 字面量偏移 {delta} 未 4 字节对齐");
        }
        let imm19 = check_signed_bits(delta >> 2, 19, "ldr literal")?;
        let opc = if rt.is_64 { 0x5800_0000u32 } else { 0x1800_0000u32 };
        return Ok(vec![opc | (imm19 << 5) | rt_num]);
    }

    let addr = parse_mem_addr(&ops[1..])?;
    let (size_bits, opc_bits, scale, is_unscaled_mnem) = match mnemonic {
        "strb" | "sturb" => {
            rt.require_32(mnemonic)?;
            (0u32, 0u32, 1i64, mnemonic == "sturb")
        }
        "ldrb" | "ldurb" => {
            rt.require_32(mnemonic)?;
            (0u32, 1u32, 1i64, mnemonic == "ldurb")
        }
        "ldrsb" | "ldursb" => (
            0u32,
            if rt.is_64 { 2u32 } else { 3u32 },
            1i64,
            mnemonic == "ldursb",
        ),
        "strh" | "sturh" => {
            rt.require_32(mnemonic)?;
            (1u32, 0u32, 2i64, mnemonic == "sturh")
        }
        "ldrh" | "ldurh" => {
            rt.require_32(mnemonic)?;
            (1u32, 1u32, 2i64, mnemonic == "ldurh")
        }
        "ldrsh" | "ldursh" => (
            1u32,
            if rt.is_64 { 2u32 } else { 3u32 },
            2i64,
            mnemonic == "ldursh",
        ),
        "ldrsw" => {
            rt.require_64("ldrsw")?;
            (2u32, 2u32, 4i64, false)
        }
        "str" | "stur" => {
            if rt.is_64 {
                (3u32, 0u32, 8i64, mnemonic == "stur")
            } else {
                (2u32, 0u32, 4i64, mnemonic == "stur")
            }
        }
        "ldr" | "ldur" => {
            if rt.is_64 {
                (3u32, 1u32, 8i64, mnemonic == "ldur")
            } else {
                (2u32, 1u32, 4i64, mnemonic == "ldur")
            }
        }
        _ => unreachable!(),
    };

    let base_bits = (size_bits << 30) | 0x3800_0000 | (opc_bits << 22);
    match addr {
        MemAddr::Offset { base, off } => {
            let rn = base.require_gpr_or_sp(mnemonic)?;
            if !is_unscaled_mnem && off >= 0 && (off % scale) == 0 && (off / scale) <= 0xFFF {
                let imm12 = (off / scale) as u32;
                return Ok(vec![
                    base_bits | 0x0100_0000 | (imm12 << 10) | (rn << 5) | rt_num,
                ]);
            }
            let imm9 = check_signed_bits(i128::from(off), 9, mnemonic)?;
            Ok(vec![base_bits | (imm9 << 12) | (rn << 5) | rt_num])
        }
        MemAddr::PreIndex { base, off } => {
            if is_unscaled_mnem {
                bail!("{mnemonic} 不支持前索引 '!'");
            }
            let rn = base.require_gpr_or_sp(mnemonic)?;
            let imm9 = check_signed_bits(i128::from(off), 9, mnemonic)?;
            Ok(vec![
                base_bits | (imm9 << 12) | 0x0000_0C00 | (rn << 5) | rt_num,
            ])
        }
        MemAddr::PostIndex { base, off } => {
            if is_unscaled_mnem {
                bail!("{mnemonic} 不支持后索引");
            }
            let rn = base.require_gpr_or_sp(mnemonic)?;
            let imm9 = check_signed_bits(i128::from(off), 9, mnemonic)?;
            Ok(vec![
                base_bits | (imm9 << 12) | 0x0000_0400 | (rn << 5) | rt_num,
            ])
        }
        MemAddr::RegOffset {
            base,
            index,
            option,
            shift,
        } => {
            if is_unscaled_mnem {
                bail!("{mnemonic} 不支持寄存器偏移寻址");
            }
            let expected_shift = scale.trailing_zeros() as u8;
            let s_bit = match shift {
                None => 0u32,
                Some(0) => {
                    if scale == 1 {
                        1u32
                    } else {
                        0u32
                    }
                }
                Some(sh) if sh == expected_shift => 1u32,
                Some(sh) => bail!(
                    "{mnemonic} 寄存器偏移仅支持移位 #0 或 #{expected_shift}，收到 #{sh}"
                ),
            };
            let rn = base.require_gpr_or_sp(mnemonic)?;
            let rm = index.require_gpr_or_zr(mnemonic)?;
            Ok(vec![
                base_bits
                    | 0x0020_0800
                    | (rm << 16)
                    | (option << 13)
                    | (s_bit << 12)
                    | (rn << 5)
                    | rt_num,
            ])
        }
    }
}

fn encode_load_store_pair(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() < 3 {
        bail!("{mnemonic} 需要至少 3 个操作数: Rt1, Rt2, [Xn, #off]");
    }
    let rt1 = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[0]))?;
    let rt2 = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器: {}", ops[1]))?;
    if rt1.is_64 != rt2.is_64 {
        bail!("{mnemonic} 两个寄存器位宽必须一致");
    }
    let rt1_num = rt1.require_gpr_or_zr(mnemonic)?;
    let rt2_num = rt2.require_gpr_or_zr(mnemonic)?;
    let scale = if rt1.is_64 { 8i64 } else { 4i64 };
    let opc = if rt1.is_64 { 2u32 << 30 } else { 0u32 };
    let l_bit = if mnemonic == "ldp" || mnemonic == "ldnp" {
        1u32 << 22
    } else {
        0
    };
    let is_np = mnemonic == "ldnp" || mnemonic == "stnp";

    let addr = parse_mem_addr(&ops[2..])?;
    let (mode_bits, base, off) = match addr {
        MemAddr::Offset { base, off } => (
            if is_np { 0x2800_0000u32 } else { 0x2900_0000u32 },
            base,
            off,
        ),
        MemAddr::PreIndex { base, off } if !is_np => (0x2980_0000u32, base, off),
        MemAddr::PostIndex { base, off } if !is_np => (0x2880_0000u32, base, off),
        _ => bail!("{mnemonic} 不支持该寻址模式"),
    };
    if (off % scale) != 0 {
        bail!("{mnemonic} 偏移 {off} 必须为 {scale} 字节对齐");
    }
    let imm7 = check_signed_bits(i128::from(off / scale), 7, mnemonic)?;
    let rn = base.require_gpr_or_sp(mnemonic)?;
    Ok(vec![
        opc | mode_bits | l_bit | (imm7 << 15) | (rt2_num << 10) | (rn << 5) | rt1_num,
    ])
}

fn encode_atomic(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    // 辅助解析 `[Xn|sp]`（零偏移）
    let parse_zero_base = |tok: &str| -> Result<u32> {
        let addr = parse_mem_addr(&[tok.to_string()])?;
        match addr {
            MemAddr::Offset { base, off: 0 } => base.require_gpr_or_sp(mnemonic),
            _ => bail!("{mnemonic} 仅支持零偏移基址 [Xn|sp]"),
        }
    };

    match mnemonic {
        "ldxr" | "ldaxr" | "ldar" | "stlr" | "ldarb" | "stlrb" | "ldarh" | "stlrh" => {
            if ops.len() != 2 {
                bail!("{mnemonic} 需要 2 个操作数: Rt, [Xn|sp]");
            }
            let rt = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rt_num = rt.require_gpr_or_zr(mnemonic)?;
            let rn = parse_zero_base(&ops[1])?;
            let (size, base) = match mnemonic {
                "ldxr" => (if rt.is_64 { 3u32 } else { 2u32 }, 0x085F_7C00u32),
                "ldaxr" => (if rt.is_64 { 3u32 } else { 2u32 }, 0x085F_FC00u32),
                "ldar" => (if rt.is_64 { 3u32 } else { 2u32 }, 0x08DF_FC00u32),
                "stlr" => (if rt.is_64 { 3u32 } else { 2u32 }, 0x089F_FC00u32),
                "ldarb" => {
                    rt.require_32("ldarb")?;
                    (0u32, 0x08DF_FC00u32)
                }
                "stlrb" => {
                    rt.require_32("stlrb")?;
                    (0u32, 0x089F_FC00u32)
                }
                "ldarh" => {
                    rt.require_32("ldarh")?;
                    (1u32, 0x08DF_FC00u32)
                }
                "stlrh" => {
                    rt.require_32("stlrh")?;
                    (1u32, 0x089F_FC00u32)
                }
                _ => unreachable!(),
            };
            Ok(vec![(size << 30) | base | (rn << 5) | rt_num])
        }
        "stxr" | "stlxr" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Ws, Rt, [Xn|sp]");
            }
            let ws = parse_reg(&ops[0])
                .ok_or_else(|| anyhow!("无效状态寄存器"))?
                .require_32(mnemonic)?;
            let rt = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rn = parse_zero_base(&ops[2])?;
            let size = if rt.is_64 { 3u32 } else { 2u32 };
            let base = if mnemonic == "stlxr" {
                0x0800_FC00u32
            } else {
                0x0800_7C00u32
            };
            Ok(vec![
                (size << 30)
                    | base
                    | (ws.require_gpr_or_zr(mnemonic)? << 16)
                    | (rn << 5)
                    | rt.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "cas" | "casa" | "casl" | "casal" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Rs, Rt, [Xn|sp]");
            }
            let rs = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rt = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rs.is_64 != rt.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            let rn = parse_zero_base(&ops[2])?;
            let size = if rs.is_64 { 3u32 } else { 2u32 };
            let l_bit = u32::from(mnemonic == "casa" || mnemonic == "casal") << 22;
            let o0_bit = u32::from(mnemonic == "casl" || mnemonic == "casal") << 15;
            Ok(vec![
                (size << 30)
                    | 0x08A0_7C00
                    | l_bit
                    | (rs.require_gpr_or_zr(mnemonic)? << 16)
                    | o0_bit
                    | (rn << 5)
                    | rt.require_gpr_or_zr(mnemonic)?,
            ])
        }
        "swp" | "swpa" | "swpl" | "swpal" | "ldadd" | "ldadda" | "ldaddl" | "ldaddal" => {
            if ops.len() != 3 {
                bail!("{mnemonic} 需要 3 个操作数: Rs, Rt, [Xn|sp]");
            }
            let rs = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效寄存器"))?;
            let rt = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效寄存器"))?;
            if rs.is_64 != rt.is_64 {
                bail!("{mnemonic} 寄存器位宽不一致");
            }
            let rn = parse_zero_base(&ops[2])?;
            let size = if rs.is_64 { 3u32 } else { 2u32 };
            let is_swp = mnemonic.starts_with("swp");
            let suffix = if is_swp { &mnemonic[3..] } else { &mnemonic[5..] };
            let a_bit = u32::from(suffix == "a" || suffix == "al") << 23;
            let r_bit = u32::from(suffix == "l" || suffix == "al") << 22;
            let base = if is_swp {
                0x3820_8000u32
            } else {
                0x3820_0000u32
            };
            Ok(vec![
                (size << 30)
                    | base
                    | a_bit
                    | r_bit
                    | (rs.require_gpr_or_zr(mnemonic)? << 16)
                    | (rn << 5)
                    | rt.require_gpr_or_zr(mnemonic)?,
            ])
        }
        _ => unreachable!(),
    }
}
