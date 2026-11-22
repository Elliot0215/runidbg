//! 平台无关的 ARM64 硬件虚拟化公共原语（供 Linux KVM 与 macOS Hypervisor.framework 共用）
//!
//! 本模块无任何 OS 专属依赖，可在 x86_64 / aarch64 / Linux / macOS 上直接编译与单测。

/// EL1 异常向量表基址（位于低地址保留区，16KB 对齐，同时兼容 Apple Silicon 16KB 页与 4KB 逻辑页）
pub const VBAR_EL1_ADDR: u64 = 0x0000_8000;

/// 恒等映射一级页表地址（16KB 对齐，满足 Hypervisor.framework IPA 16KB 对齐约束）
pub const TTBR0_PAGE_ADDR: u64 = 0x0000_4000;

/// KVM 使用的 EL1 向量入口陷阱指令：`BRK #0x1337`（触发 `KVM_EXIT_DEBUG`）
pub const KVM_BRK_TRAP_INSN: u32 = 0xD422_66E0;

/// Hypervisor.framework 使用的 EL1 向量入口陷阱指令：`HVC #0`（触发 `HV_EXIT_REASON_EXCEPTION`）
pub const HVF_HVC_TRAP_INSN: u32 = 0xD400_0002;

/// `CPACR_EL1`: FPEN[21:20] = 0b11，允许 EL0/EL1 执行 FP/NEON/SIMD 指令
pub const CPACR_EL1_FPEN_ALL: u64 = 0x3 << 20;

/// `MAIR_EL1`: Attr0 = Normal Write-Back Read/Write Allocate (`0xFF`), Attr1 = Device-nGnRnE (`0x00`)
pub const MAIR_EL1_DEFAULT: u64 = 0x0000_0000_0000_00FF;

/// `TCR_EL1`: T0SZ=16 (48-bit VA), TG0=0b00 (4KB granule), SH0=Inner Shareable, ORGN0/IRGN0=WBWA, IPS=40-bit
pub const TCR_EL1_4KB_48BIT: u64 =
    16u64 | (0b01 << 8) | (0b01 << 10) | (0b11 << 12) | (0b010 << 32);

/// `SCTLR_EL1`: 开启 MMU (M=1)、数据缓存 (C=1)、指令缓存 (I=1)，关闭对齐强制陷阱 (A=0, SA=0)
pub const SCTLR_EL1_MMU_ON: u64 = (1 << 0) | (1 << 2) | (1 << 12);

/// `SCTLR_EL1`（无 MMU / 恒等 IPA 直通模式）：允许未对齐访存，M=0
pub const SCTLR_EL1_FLAT: u64 = 0x00C5_0838;

/// `CPSR` / `PSTATE`: EL0t（用户态，AArch64）
pub const PSTATE_EL0T: u64 = 0x0000_0000;

/// `CPSR` / `PSTATE`: EL1h（内核态，使用 SP_EL1，屏蔽 DAIF）
pub const PSTATE_EL1H: u64 = 0x0000_03C5;

/// ARM64 EL1 异常向量表共 16 个入口，每个入口占 128 字节（总计 2KB）
pub const EL1_VECTOR_TABLE_SIZE: usize = 2048;

/// 构造 2KB ARM64 EL1 异常向量表：在全部 16 个向量槽位首指令写入指定陷阱指令（`BRK` 或 `HVC`）
pub fn build_el1_vector_table(trap_insn: u32) -> [u8; EL1_VECTOR_TABLE_SIZE] {
    let mut table = [0u8; EL1_VECTOR_TABLE_SIZE];
    let bytes = trap_insn.to_le_bytes();
    for slot in 0..16 {
        let off = slot * 128;
        table[off..off + 4].copy_from_slice(&bytes);
    }
    table
}

/// 解码后的 `ESR_EL1` 异常原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EsrException {
    /// AArch64 `SVC #imm16`（EC = 0x15）
    Svc64 { imm16: u16 },
    /// AArch64 `HVC #imm16`（EC = 0x16）
    Hvc64 { imm16: u16 },
    /// AArch64 `BRK #imm16`（EC = 0x3C）
    Brk64 { imm16: u16 },
    /// 取指中止（EC = 0x20 低特权级 / 0x21 同特权级）
    InsnAbort { from_lower_el: bool, fsc: u8 },
    /// 数据访问中止（EC = 0x24 低特权级 / 0x25 同特权级）
    DataAbort {
        from_lower_el: bool,
        is_write: bool,
        fsc: u8,
    },
    /// 未分类或未实现指令异常（含 EC = 0x00 Unknown）
    Unknown { ec: u8, iss: u32 },
}

/// 解码 ARM64 `ESR_EL1`（Exception Syndrome Register）
pub fn decode_esr_el1(esr: u64) -> EsrException {
    let ec = ((esr >> 26) & 0x3F) as u8;
    let iss = (esr & 0x01FF_FFFF) as u32;
    match ec {
        0x15 => EsrException::Svc64 {
            imm16: (iss & 0xFFFF) as u16,
        },
        0x16 => EsrException::Hvc64 {
            imm16: (iss & 0xFFFF) as u16,
        },
        0x3C => EsrException::Brk64 {
            imm16: (iss & 0xFFFF) as u16,
        },
        0x20 | 0x21 => EsrException::InsnAbort {
            from_lower_el: ec == 0x20,
            fsc: (iss & 0x3F) as u8,
        },
        0x24 | 0x25 => EsrException::DataAbort {
            from_lower_el: ec == 0x24,
            is_write: ((iss >> 6) & 1) != 0,
            fsc: (iss & 0x3F) as u8,
        },
        _ => EsrException::Unknown { ec, iss },
    }
}

/// 编码 ARMv8 4KB 粒度页表目录项（Table Descriptor，用于 L0/L1/L2）
#[inline]
pub const fn pte_table_desc(next_table_pa: u64) -> u64 {
    (next_table_pa & 0x0000_FFFF_FFFF_F000) | 0b11
}

/// 编码 ARMv8 4KB 粒度 L1 1GB 恒等块映射项（Block Descriptor，Normal RWX，EL0/EL1 可访）
#[inline]
pub const fn pte_block_1gb_desc(pa_1gb_aligned: u64) -> u64 {
    // Valid=1, Type=0(Block) -> 0b01; AF=bit 10; SH=Inner(0b11)<<8; AP=EL0/EL1 RW(0b01)<<6; AttrIdx=0
    (pa_1gb_aligned & 0x0000_FFFF_C000_0000) | (1 << 10) | (0b11 << 8) | (0b01 << 6) | 0b01
}

/// 编码 ARMv8 4KB 粒度 L3 页映射项（Page Descriptor，按权限控制 AP/UXN/PXN）
#[inline]
pub const fn pte_page_4kb_desc(pa_4kb_aligned: u64, writable: bool, executable: bool) -> u64 {
    // AP[7:6]: 0b01 = EL0/EL1 RW, 0b11 = EL0/EL1 RO
    let ap = if writable { 0b01u64 << 6 } else { 0b11u64 << 6 };
    // UXN=bit 54, PXN=bit 53
    let xn = if executable {
        0u64
    } else {
        (1u64 << 54) | (1u64 << 53)
    };
    (pa_4kb_aligned & 0x0000_FFFF_FFFF_F000) | xn | (1 << 10) | (0b11 << 8) | ap | 0b11
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el1_vector_table_fills_all_16_entries() {
        let kvm_tbl = build_el1_vector_table(KVM_BRK_TRAP_INSN);
        assert_eq!(kvm_tbl.len(), 2048);
        for slot in 0..16 {
            let off = slot * 128;
            let insn = u32::from_le_bytes(kvm_tbl[off..off + 4].try_into().unwrap());
            assert_eq!(insn, KVM_BRK_TRAP_INSN);
        }

        let hvf_tbl = build_el1_vector_table(HVF_HVC_TRAP_INSN);
        for slot in 0..16 {
            let off = slot * 128;
            let insn = u32::from_le_bytes(hvf_tbl[off..off + 4].try_into().unwrap());
            assert_eq!(insn, HVF_HVC_TRAP_INSN);
        }
    }

    #[test]
    fn decode_esr_covers_svc_hvc_brk_and_aborts() {
        assert_eq!(
            decode_esr_el1((0x15u64 << 26) | 0x1001),
            EsrException::Svc64 { imm16: 0x1001 }
        );
        assert_eq!(
            decode_esr_el1(0x16u64 << 26),
            EsrException::Hvc64 { imm16: 0 }
        );
        assert_eq!(
            decode_esr_el1((0x3Cu64 << 26) | 0x1337),
            EsrException::Brk64 { imm16: 0x1337 }
        );
        assert_eq!(
            decode_esr_el1((0x24u64 << 26) | (1 << 6) | 0x07),
            EsrException::DataAbort {
                from_lower_el: true,
                is_write: true,
                fsc: 0x07,
            }
        );
        assert_eq!(
            decode_esr_el1((0x20u64 << 26) | 0x04),
            EsrException::InsnAbort {
                from_lower_el: true,
                fsc: 0x04,
            }
        );
    }

    #[test]
    fn page_table_descriptors_and_16k_alignment() {
        assert_eq!(TTBR0_PAGE_ADDR % 0x4000, 0);
        assert_eq!(VBAR_EL1_ADDR % 0x800, 0);
        let l0 = pte_table_desc(0x8000);
        assert_eq!(l0 & 0b11, 0b11);
        assert_eq!(l0 & !0xFFF, 0x8000);

        let blk = pte_block_1gb_desc(0x4000_0000);
        assert_eq!(blk & 0b11, 0b01);
        assert_eq!(blk & 0x0000_FFFF_C000_0000, 0x4000_0000);

        let rx = pte_page_4kb_desc(0x2000_1000, false, true);
        assert_eq!(rx & (1 << 54), 0); // executable
        assert_eq!((rx >> 6) & 0b11, 0b11); // RO

        let rw = pte_page_4kb_desc(0x5000_0000, true, false);
        assert_ne!(rw & (1 << 54), 0); // UXN set
        assert_eq!((rw >> 6) & 0b11, 0b01); // RW
    }
}
