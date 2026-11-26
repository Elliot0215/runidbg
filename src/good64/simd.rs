//! `good64` 标量浮点（S/D）、浮点/NEON 访存（B/H/S/D/Q）、高频 128-bit NEON 与 ARMv8 AES 编码器

use anyhow::{anyhow, bail, Result};

use super::parse::{
    check_signed_bits, parse_cond, parse_fp_reg, parse_imm, parse_mem_addr, parse_reg,
    parse_vec_elem, parse_vec_reg, FpReg, FpWidth, MemAddr, VecArrange,
};

pub(crate) fn encode_simd_instruction(mnemonic: &str, ops: &[String]) -> Result<Option<Vec<u32>>> {
    let words = match mnemonic {
        // ---- 标量浮点算术 / 比较 / 转换 / 移动 ----
        "fmov" => encode_fmov(ops)?,
        "fadd" | "fsub" | "fmul" | "fdiv" => encode_fp_binop(mnemonic, ops)?,
        "fabs" | "fneg" | "fsqrt" => encode_fp_unop(mnemonic, ops)?,
        "fcmp" => encode_fcmp(ops)?,
        "fcsel" => encode_fcsel(ops)?,
        "fcvt" => encode_fcvt(ops)?,
        "scvtf" | "ucvtf" | "fcvtzs" | "fcvtzu" => encode_fp_int_conv(mnemonic, ops)?,

        // ---- 浮点/SIMD 访存（b/h/s/d/q） ----
        "ldr" | "str" | "ldur" | "stur" => {
            let Some(ft) = ops.first().and_then(|o| parse_fp_reg(o)) else {
                return Ok(None);
            };
            encode_fp_load_store(mnemonic, ft, &ops[1..])?
        }
        "ldp" | "stp" | "ldnp" | "stnp" => {
            let Some(ft1) = ops.first().and_then(|o| parse_fp_reg(o)) else {
                return Ok(None);
            };
            let ft2 = ops
                .get(1)
                .and_then(|o| parse_fp_reg(o))
                .ok_or_else(|| anyhow!("{mnemonic} 需要两个同宽浮点/SIMD 寄存器"))?;
            encode_fp_load_store_pair(mnemonic, ft1, ft2, &ops[2..])?
        }

        // ---- NEON 向量逻辑 / 算术 / 移位 / 重排 / AES ----
        "mov" => {
            if ops.len() != 2 {
                return Ok(None);
            }
            // mov vd.16b, vn.16b -> orr vd.16b, vn.16b, vn.16b
            if let (Some(vd), Some(vn)) = (parse_vec_reg(&ops[0]), parse_vec_reg(&ops[1])) {
                if vd.arrange != vn.arrange {
                    bail!("向量 mov 排布不一致");
                }
                if !matches!(vd.arrange, VecArrange::B8 | VecArrange::B16) {
                    bail!("向量 mov 仅支持 .8b / .16b 排布");
                }
                let rn = u32::from(vn.num);
                vec![vd.arrange.q_bit() | 0x0EA0_1C00 | (rn << 16) | (rn << 5) | u32::from(vd.num)]
            } else if let (Some(rd), Some(elem)) = (parse_reg(&ops[0]), parse_vec_elem(&ops[1])) {
                // mov xd, vn.d[idx] / mov wd, vn.s[idx] -> umov 别名（ARMv8 仅 .s/.d 允许 mov 别名）
                match elem.elem_size {
                    2 => {
                        rd.require_32("mov .s[idx]")?;
                    }
                    3 => {
                        rd.require_64("mov .d[idx]")?;
                    }
                    _ => bail!("mov 仅支持 .s[idx] / .d[idx] 别名，.b/.h 请显式使用 umov"),
                }
                let q = u32::from(elem.elem_size == 3) << 30;
                let imm5 = ((u32::from(elem.index) << 1) | 1) << elem.elem_size;
                vec![
                    q | 0x0E00_3C00
                        | (imm5 << 16)
                        | (u32::from(elem.num) << 5)
                        | rd.require_gpr_or_zr("mov")?,
                ]
            } else if let (Some(elem), Some(rn)) = (parse_vec_elem(&ops[0]), parse_reg(&ops[1])) {
                // mov vd.T[idx], rn -> ins 别名
                if elem.elem_size == 3 {
                    rn.require_64("mov .d[idx]")?;
                } else {
                    rn.require_32("mov .b/.h/.s[idx]")?;
                }
                let imm5 = ((u32::from(elem.index) << 1) | 1) << elem.elem_size;
                vec![
                    0x4E00_1C00
                        | (imm5 << 16)
                        | (rn.require_gpr_or_zr("mov")? << 5)
                        | u32::from(elem.num),
                ]
            } else {
                return Ok(None);
            }
        }
        "and" | "bic" | "orr" | "orn" | "eor" => {
            if ops.len() != 3 {
                return Ok(None);
            }
            let (Some(vd), Some(vn), Some(vm)) = (
                parse_vec_reg(&ops[0]),
                parse_vec_reg(&ops[1]),
                parse_vec_reg(&ops[2]),
            ) else {
                return Ok(None);
            };
            if vd.arrange != vn.arrange || vd.arrange != vm.arrange {
                bail!("向量 {mnemonic} 排布不一致");
            }
            if !matches!(vd.arrange, VecArrange::B8 | VecArrange::B16) {
                bail!("向量 {mnemonic} 仅支持 .8b / .16b 排布");
            }
            let base = match mnemonic {
                "and" => 0x0E20_1C00u32,
                "bic" => 0x0E60_1C00u32,
                "orr" => 0x0EA0_1C00u32,
                "orn" => 0x0EE0_1C00u32,
                "eor" => 0x2E20_1C00u32,
                _ => unreachable!(),
            };
            vec![
                vd.arrange.q_bit()
                    | base
                    | (u32::from(vm.num) << 16)
                    | (u32::from(vn.num) << 5)
                    | u32::from(vd.num),
            ]
        }
        "not" | "mvn" => {
            if ops.len() != 2 {
                return Ok(None);
            }
            let (Some(vd), Some(vn)) = (parse_vec_reg(&ops[0]), parse_vec_reg(&ops[1])) else {
                return Ok(None);
            };
            if vd.arrange != vn.arrange || !matches!(vd.arrange, VecArrange::B8 | VecArrange::B16) {
                bail!("{mnemonic} 向量形式仅支持 .8b / .16b 排布");
            }
            vec![vd.arrange.q_bit() | 0x2E20_5800 | (u32::from(vn.num) << 5) | u32::from(vd.num)]
        }
        "movi" => {
            if ops.len() != 2 {
                bail!("movi 需要 2 个操作数: Vd.8b/16b, #imm8");
            }
            let vd = parse_vec_reg(&ops[0]).ok_or_else(|| anyhow!("无效向量寄存器: {}", ops[0]))?;
            if !matches!(vd.arrange, VecArrange::B8 | VecArrange::B16) {
                bail!("movi 当前支持 .8b / .16b 排布");
            }
            let imm = parse_imm(&ops[1])?;
            if !(0..=0xFF).contains(&imm) {
                bail!("movi 立即数超出 u8 范围: {imm}");
            }
            let abc = ((imm as u32) >> 5) & 7;
            let defgh = (imm as u32) & 0x1F;
            vec![
                vd.arrange.q_bit() | 0x0F00_E400 | (abc << 16) | (defgh << 5) | u32::from(vd.num),
            ]
        }
        "add" | "sub" | "mul" => {
            if ops.len() != 3 {
                return Ok(None);
            }
            let (Some(vd), Some(vn), Some(vm)) = (
                parse_vec_reg(&ops[0]),
                parse_vec_reg(&ops[1]),
                parse_vec_reg(&ops[2]),
            ) else {
                return Ok(None);
            };
            if vd.arrange != vn.arrange || vd.arrange != vm.arrange {
                bail!("向量 {mnemonic} 排布不一致");
            }
            if mnemonic == "mul" && vd.arrange == VecArrange::D2 {
                bail!("向量 mul 不支持 .2d 排布");
            }
            let base = match mnemonic {
                "add" => 0x0E20_8400u32,
                "sub" => 0x2E20_8400u32,
                "mul" => 0x0E20_9C00u32,
                _ => unreachable!(),
            };
            vec![
                vd.arrange.q_bit()
                    | base
                    | (vd.arrange.elem_size() << 22)
                    | (u32::from(vm.num) << 16)
                    | (u32::from(vn.num) << 5)
                    | u32::from(vd.num),
            ]
        }
        "shl" | "ushr" | "sshr" => encode_vec_shift(mnemonic, ops)?,
        "ext" => {
            if ops.len() != 4 {
                bail!("ext 需要 4 个操作数: Vd.T, Vn.T, Vm.T, #index");
            }
            let vd = parse_vec_reg(&ops[0]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
            let vn = parse_vec_reg(&ops[1]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
            let vm = parse_vec_reg(&ops[2]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
            if vd.arrange != vn.arrange
                || vd.arrange != vm.arrange
                || !matches!(vd.arrange, VecArrange::B8 | VecArrange::B16)
            {
                bail!("ext 仅支持 .8b / .16b");
            }
            let max_idx = if vd.arrange.is_128() { 15 } else { 7 };
            let idx = parse_imm(&ops[3])?;
            if !(0..=max_idx).contains(&idx) {
                bail!("ext index 超出范围: {idx}");
            }
            vec![
                vd.arrange.q_bit()
                    | 0x2E00_0000
                    | (u32::from(vm.num) << 16)
                    | ((idx as u32) << 11)
                    | (u32::from(vn.num) << 5)
                    | u32::from(vd.num),
            ]
        }
        "rev32" | "rev64" => {
            if ops.len() != 2 {
                return Ok(None);
            }
            let (Some(vd), Some(vn)) = (parse_vec_reg(&ops[0]), parse_vec_reg(&ops[1])) else {
                return Ok(None);
            };
            if vd.arrange != vn.arrange {
                bail!("{mnemonic} 向量排布不一致");
            }
            let es = vd.arrange.elem_size();
            if mnemonic == "rev32" && es > 1 {
                bail!("向量 rev32 仅支持 .8b/.16b/.4h/.8h");
            }
            if mnemonic == "rev64" && es > 2 {
                bail!("向量 rev64 不支持 .2d");
            }
            let base = if mnemonic == "rev32" {
                0x2E20_0800u32
            } else {
                0x0E20_0800u32
            };
            vec![
                vd.arrange.q_bit()
                    | base
                    | (es << 22)
                    | (u32::from(vn.num) << 5)
                    | u32::from(vd.num),
            ]
        }
        "dup" => {
            if ops.len() != 2 {
                bail!("dup 需要 2 个操作数: Vd.T, Rn");
            }
            let vd = parse_vec_reg(&ops[0]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("dup 源操作数需为通用寄存器"))?;
            let es = vd.arrange.elem_size();
            if es == 3 {
                rn.require_64("dup .2d")?;
            } else {
                rn.require_32("dup .b/.h/.s")?;
            }
            let imm5 = 1u32 << es;
            vec![
                vd.arrange.q_bit()
                    | 0x0E00_0C00
                    | (imm5 << 16)
                    | (rn.require_gpr_or_zr("dup")? << 5)
                    | u32::from(vd.num),
            ]
        }
        "umov" => {
            if ops.len() != 2 {
                bail!("umov 需要 2 个操作数: Rd, Vn.T[idx]");
            }
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效目的寄存器"))?;
            let elem = parse_vec_elem(&ops[1]).ok_or_else(|| anyhow!("无效向量元素: {}", ops[1]))?;
            if elem.elem_size == 3 {
                rd.require_64("umov .d[idx]")?;
            } else {
                rd.require_32("umov .b/.h/.s[idx]")?;
            }
            let q = u32::from(elem.elem_size == 3) << 30;
            let imm5 = ((u32::from(elem.index) << 1) | 1) << elem.elem_size;
            vec![
                q | 0x0E00_3C00
                    | (imm5 << 16)
                    | (u32::from(elem.num) << 5)
                    | rd.require_gpr_or_zr("umov")?,
            ]
        }
        "ins" => {
            if ops.len() != 2 {
                bail!("ins 需要 2 个操作数: Vd.T[idx], Rn");
            }
            let elem = parse_vec_elem(&ops[0]).ok_or_else(|| anyhow!("无效向量元素: {}", ops[0]))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("ins 源操作数需为通用寄存器"))?;
            if elem.elem_size == 3 {
                rn.require_64("ins .d[idx]")?;
            } else {
                rn.require_32("ins .b/.h/.s[idx]")?;
            }
            let imm5 = ((u32::from(elem.index) << 1) | 1) << elem.elem_size;
            vec![
                0x4E00_1C00
                    | (imm5 << 16)
                    | (rn.require_gpr_or_zr("ins")? << 5)
                    | u32::from(elem.num),
            ]
        }
        "tbl" => encode_tbl(ops)?,

        // ---- ARMv8 AES Crypto 扩展 ----
        "aese" | "aesd" | "aesmc" | "aesimc" => {
            if ops.len() != 2 {
                bail!("{mnemonic} 需要 2 个操作数: Vd.16b, Vn.16b");
            }
            let vd = parse_vec_reg(&ops[0]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
            let vn = parse_vec_reg(&ops[1]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
            if vd.arrange != VecArrange::B16 || vn.arrange != VecArrange::B16 {
                bail!("{mnemonic} 仅支持 .16b 排布");
            }
            let base = match mnemonic {
                "aese" => 0x4E28_4800u32,
                "aesd" => 0x4E28_5800u32,
                "aesmc" => 0x4E28_6800u32,
                "aesimc" => 0x4E28_7800u32,
                _ => unreachable!(),
            };
            vec![base | (u32::from(vn.num) << 5) | u32::from(vd.num)]
        }

        _ => return Ok(None),
    };
    Ok(Some(words))
}

fn fp_ftype(w: FpWidth, ctx: &str) -> Result<u32> {
    match w {
        FpWidth::S => Ok(0),
        FpWidth::D => Ok(1),
        _ => bail!("{ctx}: 标量浮点指令仅支持 S/D 寄存器"),
    }
}

fn encode_fmov(ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 2 {
        bail!("fmov 需要 2 个操作数");
    }
    match (
        parse_fp_reg(&ops[0]),
        parse_fp_reg(&ops[1]),
        parse_reg(&ops[0]),
        parse_reg(&ops[1]),
    ) {
        (Some(fd), Some(fn_reg), _, _) => {
            if fd.width != fn_reg.width {
                bail!("fmov 浮点寄存器位宽不一致");
            }
            let ftype = fp_ftype(fd.width, "fmov")?;
            Ok(vec![
                0x1E20_4000 | (ftype << 22) | (u32::from(fn_reg.num) << 5) | u32::from(fd.num),
            ])
        }
        (Some(fd), None, _, Some(rn)) => {
            let rn_num = rn.require_gpr_or_zr("fmov")?;
            match (fd.width, rn.is_64) {
                (FpWidth::S, false) => Ok(vec![0x1E27_0000 | (rn_num << 5) | u32::from(fd.num)]),
                (FpWidth::D, true) => Ok(vec![0x9E67_0000 | (rn_num << 5) | u32::from(fd.num)]),
                _ => bail!("fmov GPR->FP 仅支持 (Sd, Wn) 或 (Dd, Xn)"),
            }
        }
        (None, Some(fn_reg), Some(rd), _) => {
            let rd_num = rd.require_gpr_or_zr("fmov")?;
            match (rd.is_64, fn_reg.width) {
                (false, FpWidth::S) => Ok(vec![0x1E26_0000 | (u32::from(fn_reg.num) << 5) | rd_num]),
                (true, FpWidth::D) => Ok(vec![0x9E66_0000 | (u32::from(fn_reg.num) << 5) | rd_num]),
                _ => bail!("fmov FP->GPR 仅支持 (Wd, Sn) 或 (Xd, Dn)"),
            }
        }
        _ => bail!("不支持的 fmov 操作数组合: {}, {}", ops[0], ops[1]),
    }
}

fn encode_fp_binop(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 3 {
        bail!("{mnemonic} 需要 3 个浮点寄存器: Fd, Fn, Fm");
    }
    let fd = parse_fp_reg(&ops[0]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    let fn_r = parse_fp_reg(&ops[1]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    let fm = parse_fp_reg(&ops[2]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    if fd.width != fn_r.width || fd.width != fm.width {
        bail!("{mnemonic} 浮点寄存器位宽不一致");
    }
    let ftype = fp_ftype(fd.width, mnemonic)?;
    let base = match mnemonic {
        "fmul" => 0x1E20_0800u32,
        "fdiv" => 0x1E20_1800u32,
        "fadd" => 0x1E20_2800u32,
        "fsub" => 0x1E20_3800u32,
        _ => unreachable!(),
    };
    Ok(vec![
        base | (ftype << 22)
            | (u32::from(fm.num) << 16)
            | (u32::from(fn_r.num) << 5)
            | u32::from(fd.num),
    ])
}

fn encode_fp_unop(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 2 {
        bail!("{mnemonic} 需要 2 个浮点寄存器: Fd, Fn");
    }
    let fd = parse_fp_reg(&ops[0]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    let fn_r = parse_fp_reg(&ops[1]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    if fd.width != fn_r.width {
        bail!("{mnemonic} 浮点寄存器位宽不一致");
    }
    let ftype = fp_ftype(fd.width, mnemonic)?;
    let base = match mnemonic {
        "fabs" => 0x1E20_C000u32,
        "fneg" => 0x1E21_4000u32,
        "fsqrt" => 0x1E21_C000u32,
        _ => unreachable!(),
    };
    Ok(vec![
        base | (ftype << 22) | (u32::from(fn_r.num) << 5) | u32::from(fd.num),
    ])
}

fn encode_fcmp(ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 2 {
        bail!("fcmp 需要 2 个操作数: Fn, Fm/#0.0");
    }
    let fn_r = parse_fp_reg(&ops[0]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    let ftype = fp_ftype(fn_r.width, "fcmp")?;
    if let Some(fm) = parse_fp_reg(&ops[1]) {
        if fm.width != fn_r.width {
            bail!("fcmp 浮点寄存器位宽不一致");
        }
        return Ok(vec![
            0x1E20_2000 | (ftype << 22) | (u32::from(fm.num) << 16) | (u32::from(fn_r.num) << 5),
        ]);
    }
    let trimmed = ops[1].trim();
    let s = trimmed.strip_prefix('#').unwrap_or(trimmed).trim();
    if s == "0" || s == "0.0" {
        return Ok(vec![0x1E20_2008 | (ftype << 22) | (u32::from(fn_r.num) << 5)]);
    }
    bail!("fcmp 立即数仅支持 #0.0");
}

fn encode_fcsel(ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 4 {
        bail!("fcsel 需要 4 个操作数: Fd, Fn, Fm, cond");
    }
    let fd = parse_fp_reg(&ops[0]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    let fn_r = parse_fp_reg(&ops[1]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    let fm = parse_fp_reg(&ops[2]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    if fd.width != fn_r.width || fd.width != fm.width {
        bail!("fcsel 浮点寄存器位宽不一致");
    }
    let ftype = fp_ftype(fd.width, "fcsel")?;
    let cond = parse_cond(&ops[3]).ok_or_else(|| anyhow!("未知条件码: {}", ops[3]))?;
    Ok(vec![
        0x1E20_0C00
            | (ftype << 22)
            | (u32::from(fm.num) << 16)
            | (cond << 12)
            | (u32::from(fn_r.num) << 5)
            | u32::from(fd.num),
    ])
}

fn encode_fcvt(ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 2 {
        bail!("fcvt 需要 2 个浮点寄存器: Fd, Fn");
    }
    let fd = parse_fp_reg(&ops[0]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    let fn_r = parse_fp_reg(&ops[1]).ok_or_else(|| anyhow!("无效浮点寄存器"))?;
    match (fd.width, fn_r.width) {
        (FpWidth::D, FpWidth::S) => Ok(vec![
            0x1E22_C000 | (u32::from(fn_r.num) << 5) | u32::from(fd.num),
        ]),
        (FpWidth::S, FpWidth::D) => Ok(vec![
            0x1E62_4000 | (u32::from(fn_r.num) << 5) | u32::from(fd.num),
        ]),
        _ => bail!("fcvt 当前支持 (Dd, Sn) 与 (Sd, Dn)"),
    }
}

fn encode_fp_int_conv(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 2 {
        bail!("{mnemonic} 需要 2 个操作数");
    }
    match mnemonic {
        "scvtf" | "ucvtf" => {
            let fd = parse_fp_reg(&ops[0]).ok_or_else(|| anyhow!("无效目的浮点寄存器"))?;
            let rn = parse_reg(&ops[1]).ok_or_else(|| anyhow!("无效源整数寄存器"))?;
            let ftype = fp_ftype(fd.width, mnemonic)?;
            let sf = u32::from(rn.is_64) << 31;
            let base = if mnemonic == "scvtf" {
                0x1E22_0000u32
            } else {
                0x1E23_0000u32
            };
            Ok(vec![
                sf | base
                    | (ftype << 22)
                    | (rn.require_gpr_or_zr(mnemonic)? << 5)
                    | u32::from(fd.num),
            ])
        }
        "fcvtzs" | "fcvtzu" => {
            let rd = parse_reg(&ops[0]).ok_or_else(|| anyhow!("无效目的整数寄存器"))?;
            let fn_r = parse_fp_reg(&ops[1]).ok_or_else(|| anyhow!("无效源浮点寄存器"))?;
            let ftype = fp_ftype(fn_r.width, mnemonic)?;
            let sf = u32::from(rd.is_64) << 31;
            let base = if mnemonic == "fcvtzs" {
                0x1E38_0000u32
            } else {
                0x1E39_0000u32
            };
            Ok(vec![
                sf | base
                    | (ftype << 22)
                    | (u32::from(fn_r.num) << 5)
                    | rd.require_gpr_or_zr(mnemonic)?,
            ])
        }
        _ => unreachable!(),
    }
}

fn encode_fp_load_store(mnemonic: &str, ft: FpReg, addr_ops: &[String]) -> Result<Vec<u32>> {
    let addr = parse_mem_addr(addr_ops)?;
    let is_load = mnemonic == "ldr" || mnemonic == "ldur";
    let is_unscaled = mnemonic == "ldur" || mnemonic == "stur";
    let scale = ft.width.byte_size();
    let (size_bits, opc_bits) = match ft.width {
        FpWidth::B => (0u32, u32::from(is_load)),
        FpWidth::H => (1u32, u32::from(is_load)),
        FpWidth::S => (2u32, u32::from(is_load)),
        FpWidth::D => (3u32, u32::from(is_load)),
        FpWidth::Q => (0u32, if is_load { 3u32 } else { 2u32 }),
    };
    // V=1 (bit 26) -> 0x3C00_0000
    let base_bits = (size_bits << 30) | 0x3C00_0000 | (opc_bits << 22);
    let rt_num = u32::from(ft.num);
    match addr {
        MemAddr::Offset { base, off } => {
            let rn = base.require_gpr_or_sp(mnemonic)?;
            if !is_unscaled && off >= 0 && (off % scale) == 0 && (off / scale) <= 0xFFF {
                let imm12 = (off / scale) as u32;
                return Ok(vec![
                    base_bits | 0x0100_0000 | (imm12 << 10) | (rn << 5) | rt_num,
                ]);
            }
            let imm9 = check_signed_bits(i128::from(off), 9, mnemonic)?;
            Ok(vec![base_bits | (imm9 << 12) | (rn << 5) | rt_num])
        }
        MemAddr::PreIndex { base, off } => {
            if is_unscaled {
                bail!("{mnemonic} 不支持前索引");
            }
            let rn = base.require_gpr_or_sp(mnemonic)?;
            let imm9 = check_signed_bits(i128::from(off), 9, mnemonic)?;
            Ok(vec![
                base_bits | (imm9 << 12) | 0x0000_0C00 | (rn << 5) | rt_num,
            ])
        }
        MemAddr::PostIndex { base, off } => {
            if is_unscaled {
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
            if is_unscaled {
                bail!("{mnemonic} 不支持寄存器偏移");
            }
            let expected_shift = scale.trailing_zeros() as u8;
            let s_bit = match shift {
                None => 0u32,
                Some(0) => u32::from(scale == 1),
                Some(sh) if sh == expected_shift => 1u32,
                Some(sh) if expected_shift == 0 => {
                    bail!("{mnemonic} 移位量仅支持 #0，收到 #{sh}")
                }
                Some(sh) => bail!("{mnemonic} 移位量仅支持 #0 或 #{expected_shift}，收到 #{sh}"),
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

fn encode_fp_load_store_pair(
    mnemonic: &str,
    ft1: FpReg,
    ft2: FpReg,
    addr_ops: &[String],
) -> Result<Vec<u32>> {
    if ft1.width != ft2.width {
        bail!("{mnemonic} 两个浮点寄存器位宽必须一致");
    }
    let (opc, scale) = match ft1.width {
        FpWidth::S => (0u32 << 30, 4i64),
        FpWidth::D => (1u32 << 30, 8i64),
        FpWidth::Q => (2u32 << 30, 16i64),
        _ => bail!("{mnemonic} 浮点成对访存仅支持 S/D/Q 寄存器"),
    };
    let l_bit = if mnemonic == "ldp" || mnemonic == "ldnp" {
        1u32 << 22
    } else {
        0
    };
    let is_np = mnemonic == "ldnp" || mnemonic == "stnp";
    let addr = parse_mem_addr(addr_ops)?;
    let (mode_bits, base, off) = match addr {
        MemAddr::Offset { base, off } => (
            if is_np { 0x2C00_0000u32 } else { 0x2D00_0000u32 },
            base,
            off,
        ),
        MemAddr::PreIndex { base, off } if !is_np => (0x2D80_0000u32, base, off),
        MemAddr::PostIndex { base, off } if !is_np => (0x2C80_0000u32, base, off),
        _ => bail!("{mnemonic} 不支持该寻址模式"),
    };
    if (off % scale) != 0 {
        bail!("{mnemonic} 偏移 {off} 必须为 {scale} 字节对齐");
    }
    let imm7 = check_signed_bits(i128::from(off / scale), 7, mnemonic)?;
    let rn = base.require_gpr_or_sp(mnemonic)?;
    Ok(vec![
        opc | mode_bits
            | l_bit
            | (imm7 << 15)
            | (u32::from(ft2.num) << 10)
            | (rn << 5)
            | u32::from(ft1.num),
    ])
}

fn encode_vec_shift(mnemonic: &str, ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 3 {
        bail!("{mnemonic} 需要 3 个操作数: Vd.T, Vn.T, #shift");
    }
    let vd = parse_vec_reg(&ops[0]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
    let vn = parse_vec_reg(&ops[1]).ok_or_else(|| anyhow!("无效向量寄存器"))?;
    if vd.arrange != vn.arrange {
        bail!("{mnemonic} 向量排布不一致");
    }
    let elem_bits = vd.arrange.elem_bits() as i128;
    let shift = parse_imm(&ops[2])?;
    let (base, immh_immb) = if mnemonic == "shl" {
        if !(0..elem_bits).contains(&shift) {
            bail!("shl 移位量超出 [0, {})", elem_bits);
        }
        (0x0F00_5400u32, (elem_bits + shift) as u32)
    } else {
        if !(1..=elem_bits).contains(&shift) {
            bail!("{mnemonic} 移位量超出 [1, {}]", elem_bits);
        }
        let base = if mnemonic == "ushr" {
            0x2F00_0400u32
        } else {
            0x0F00_0400u32
        };
        (base, (elem_bits * 2 - shift) as u32)
    };
    Ok(vec![
        vd.arrange.q_bit()
            | base
            | (immh_immb << 16)
            | (u32::from(vn.num) << 5)
            | u32::from(vd.num),
    ])
}

fn encode_tbl(ops: &[String]) -> Result<Vec<u32>> {
    if ops.len() != 3 {
        bail!("tbl 需要 3 个操作数: Vd.8b/16b, {{Vn.16b, ...}}, Vm.8b/16b");
    }
    let vd = parse_vec_reg(&ops[0]).ok_or_else(|| anyhow!("无效目的向量寄存器"))?;
    let vm = parse_vec_reg(&ops[2]).ok_or_else(|| anyhow!("无效索引向量寄存器"))?;
    if vd.arrange != vm.arrange || !matches!(vd.arrange, VecArrange::B8 | VecArrange::B16) {
        bail!("tbl 仅支持 .8b / .16b");
    }
    let list_inner = ops[1]
        .trim()
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| anyhow!("tbl 表寄存器必须用 {{...}} 包裹"))?;
    let regs: Vec<super::parse::VecReg> = list_inner
        .split(',')
        .map(|t| {
            parse_vec_reg(t.trim())
                .ok_or_else(|| anyhow!("tbl 无效表寄存器: '{}'", t.trim()))
        })
        .collect::<Result<Vec<_>>>()?;
    if regs.is_empty() || regs.len() > 4 {
        bail!("tbl 表寄存器数量必须在 1..=4 之间");
    }
    for (i, r) in regs.iter().enumerate() {
        if r.arrange != VecArrange::B16 {
            bail!("tbl 表寄存器必须为 .16b 排布");
        }
        if i > 0 && r.num != ((regs[0].num + i as u8) & 31) {
            bail!("tbl 表寄存器必须连续递增");
        }
    }
    let len_code = (regs.len() as u32 - 1) << 13;
    Ok(vec![
        vd.arrange.q_bit()
            | 0x0E00_0000
            | (u32::from(vm.num) << 16)
            | len_code
            | (u32::from(regs[0].num) << 5)
            | u32::from(vd.num),
    ])
}
