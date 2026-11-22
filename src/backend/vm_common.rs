//! 平台无关的 ARM64 硬件虚拟化公共原语（供 Linux KVM 与 macOS Hypervisor.framework 共用）
//!
//! 本模块无任何 OS 专属依赖，可在 x86_64 / aarch64 / Linux / macOS 上直接编译与单测。

/// EL1 异常向量表基址（位于低地址保留区，16KB 对齐，同时兼容 Apple Silicon 16KB 页与 4KB 逻辑页）
pub const VBAR_EL1_ADDR: u64 = 0x0000_8000;

/// 恒等映射一级页表地址（16KB 对齐，满足 Hypervisor.framework IPA 16KB 对齐约束）
pub const TTBR0_PAGE_ADDR: u64 = 0x0000_4000;

/// 恒等映射二级页表地址（紧跟 L1 之后，用于细化 `0..1GB` 区域权限，与 L1 共占同一 16KB 宿主页）
pub const TTBR0_L2_PAGE_ADDR: u64 = 0x0000_5000;

/// 恒等映射页表总字节数（4KB L1 + 4KB L2）
pub const TTBR0_TABLES_SIZE: usize = 8192;

/// KVM 使用的 EL1 向量入口陷阱指令：`BRK #0x1337`（触发 `KVM_EXIT_DEBUG`）
pub const KVM_BRK_TRAP_INSN: u32 = 0xD422_66E0;

/// Hypervisor.framework 使用的 EL1 向量入口陷阱指令：`HVC #0`（触发 `HV_EXIT_REASON_EXCEPTION`）
pub const HVF_HVC_TRAP_INSN: u32 = 0xD400_0002;

/// `CPACR_EL1`: FPEN[21:20] = 0b11，允许 EL0/EL1 执行 FP/NEON/SIMD 指令
pub const CPACR_EL1_FPEN_ALL: u64 = 0x3 << 20;

/// `MAIR_EL1`: Attr0 = Normal Write-Back Read/Write Allocate (`0xFF`), Attr1 = Device-nGnRnE (`0x00`)
pub const MAIR_EL1_DEFAULT: u64 = 0x0000_0000_0000_00FF;

/// `TCR_EL1`: T0SZ=25 (39-bit VA，从 L1 直接起查，单张 4KB 页即可恒等映射 512GB),
/// TG0=4KB, SH0=Inner Shareable, ORGN0/IRGN0=WBWA, EPD1=1 (禁用 TTBR1), IPS=40-bit
pub const TCR_EL1_4KB_39BIT: u64 =
    25u64 | (0b01 << 8) | (0b01 << 10) | (0b11 << 12) | (1 << 23) | (0b010 << 32);

/// `TCR_EL1`: T0SZ=16 (48-bit VA), TG0=0b00 (4KB granule), SH0=Inner Shareable, ORGN0/IRGN0=WBWA, IPS=40-bit
pub const TCR_EL1_4KB_48BIT: u64 =
    16u64 | (0b01 << 8) | (0b01 << 10) | (0b11 << 12) | (0b010 << 32);

/// `SCTLR_EL1`: 开启 MMU (M=1)、数据缓存 (C=1)、指令缓存 (I=1)，关闭对齐强制陷阱 (A=0, SA=0, SA0=0)，
/// 保留 RES1 位以符合 ARMv8-A 规范
pub const SCTLR_EL1_MMU_ON: u64 = 0x00C5_0838 | (1 << 0) | (1 << 2) | (1 << 12);

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

/// 构造 8KB（4KB L1 + 4KB L2）恒等映射页表，映射 512GB Normal WBWA 可缓存内存：
/// - `L1[0]` 指向 `TTBR0_L2_PAGE_ADDR`（512 × 2MB Block 细化 `0..1GB`）：
///   - `L2[0]` (`0x0000_0000..0x0020_0000`，含 `TTBR0=0x4000` 与 `VBAR_EL1=0x8000`) 使用 `AP=0b11`（EL0/EL1 只读可执行），
///     满足 ARMv8 铁律「EL0 可写页隐含 PXN=1，不可在 EL1 执行」，保证 EL1 异常向量表正常取指；
///   - `L2[1..512]` (`0x0020_0000..0x4000_0000`，覆盖 `0x1000_0000` 跳板与 `0x2000_0000` 系统共享库如 `libc++_shared.so`) 使用 `AP=0b01`（EL0 RWX）；
/// - `L1[1..512]` (`0x4000_0000..512GB`，覆盖用户 `.so`/Heap/TLS/Stack/RET_MAGIC) 使用 `AP=0b01`（EL0 RWX），
///   启用硬件 L1/L2/L3 缓存并允许任意未对齐访存（如 `STP Q0, Q0`）。
pub fn build_identity_page_tables() -> [u8; TTBR0_TABLES_SIZE] {
    let mut tables = [0u8; TTBR0_TABLES_SIZE];
    // L1[0] -> L2 Table at TTBR0_L2_PAGE_ADDR
    let l1_0 = pte_table_desc(TTBR0_L2_PAGE_ADDR);
    tables[0..8].copy_from_slice(&l1_0.to_le_bytes());
    // L1[1..512] -> 1GB RWX Normal WBWA blocks (1GB..512GB)
    for i in 1..512u64 {
        let desc = pte_block_1gb_desc(i << 30);
        let off = (i as usize) * 8;
        tables[off..off + 8].copy_from_slice(&desc.to_le_bytes());
    }

    // L2[0]: 0..2MB, Normal WBWA, AP=0b11 (EL0/EL1 RO+RX, PXN=0, UXN=0)
    let l2_base = 4096usize;
    let l2_0 = (1u64 << 10) | (0b11 << 8) | (0b11 << 6) | 0b01;
    tables[l2_base..l2_base + 8].copy_from_slice(&l2_0.to_le_bytes());
    // L2[1..512]: 2MB..1GB, Normal WBWA, AP=0b01 (EL0 RWX)
    for i in 1..512u64 {
        let desc = pte_block_2mb_desc(i << 21);
        let off = l2_base + (i as usize) * 8;
        tables[off..off + 8].copy_from_slice(&desc.to_le_bytes());
    }
    tables
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

/// 编码 ARMv8 4KB 粒度 L2 2MB 恒等块映射项（Block Descriptor，Normal RWX，EL0/EL1 可访）
#[inline]
pub const fn pte_block_2mb_desc(pa_2mb_aligned: u64) -> u64 {
    // Valid=1, Type=0(Block) -> 0b01; AF=bit 10; SH=Inner(0b11)<<8; AP=EL0/EL1 RW(0b01)<<6; AttrIdx=0
    (pa_2mb_aligned & 0x0000_FFFF_FFE0_0000) | (1 << 10) | (0b11 << 8) | (0b01 << 6) | 0b01
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

        let tables = build_identity_page_tables();
        assert_eq!(tables.len(), TTBR0_TABLES_SIZE);
        // L1[0] points to L2 table at TTBR0_L2_PAGE_ADDR
        let l1_0 = u64::from_le_bytes(tables[0..8].try_into().unwrap());
        assert_eq!(l1_0, pte_table_desc(TTBR0_L2_PAGE_ADDR));
        // L1[1] maps 1GB..2GB as EL0 RWX (AP=0b01)
        let l1_1 = u64::from_le_bytes(tables[8..16].try_into().unwrap());
        assert_eq!(l1_1 & 0b11, 0b01);
        assert_eq!((l1_1 >> 6) & 0b11, 0b01);
        // L2[0] maps 0..2MB as EL0/EL1 RO+RX (AP=0b11) so VBAR_EL1=0x8000 is executable in EL1
        let l2_0 = u64::from_le_bytes(tables[4096..4104].try_into().unwrap());
        assert_eq!(l2_0 & 0b11, 0b01);
        assert_eq!((l2_0 >> 6) & 0b11, 0b11);
        // L2[256] maps 0x2000_0000..0x2020_0000 as EL0 RWX (AP=0b01) for shared libs
        let off = 4096 + 256 * 8;
        let l2_256 = u64::from_le_bytes(tables[off..off + 8].try_into().unwrap());
        assert_eq!(l2_256 & 0x0000_FFFF_FFE0_0000, 0x2000_0000);
        assert_eq!((l2_256 >> 6) & 0b11, 0b01);
    }
}
