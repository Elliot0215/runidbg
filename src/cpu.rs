use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::RegisterARM64;

use crate::backend::{CpuBackend, CpuContextBlob, ARM64_SVC_RET_INSN};
use crate::error::EmuResult;
use crate::memory::{MemoryManager, PAGE_SIZE};

/// 默认栈空间配置（8MB，处于低 4GB 虚拟地址空间，兼容 Unicorn 2.1.x 默认软 MMU）
pub const STACK_BASE: u64 = 0x7000_0000;
pub const STACK_SIZE: u64 = 0x0080_0000;

/// 主线程 TLS 空间配置（64KB，兼容 Android 10–12 Bionic `TPIDR_EL0` 槽位布局）
pub const TLS_BASE: u64 = 0x6000_0000;
pub const TLS_SIZE: u64 = 0x0001_0000;

/// Android Bionic AArch64 TLS 关键槽位偏移（每个槽位 8 字节）
/// 参考 AOSP `bionic/libc/platform/bionic/tls_defines.h`
pub const TLS_SLOT_SELF: u64 = 0; // offset 0x00: 指向 TLS 基址自身
pub const TLS_SLOT_THREAD_ID: u64 = 1; // offset 0x08: 指向 pthread_internal_t
pub const TLS_SLOT_ERRNO: u64 = 2; // offset 0x10: 指向线程专属 errno 地址
pub const TLS_SLOT_STACK_GUARD: u64 = 5; // offset 0x28: Stack Canary (__stack_chk_guard)

/// 默认确定性 Stack Canary 值
pub const DEFAULT_STACK_GUARD: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// 函数返回停止魔数地址（LR 初始值，emu_start 的 until 地址）
pub const RET_MAGIC_ADDR: u64 = 0xDEAD_0000;

/// 临时初始化代码页地址（用于执行开启 NEON/FP 与配置 TPIDR_EL0 的系统寄存器指令）
const CPU_INIT_STUB_ADDR: u64 = 0xDEAD_1000;

/// CPU 寄存器上下文快照包装器（用于 Snapshot/Restore 与协作调度切换）
pub struct CpuSnapshot {
    inner: CpuContextBlob,
}

impl CpuSnapshot {
    /// 捕获当前完整 CPU 寄存器上下文快照
    pub fn capture<B: CpuBackend + ?Sized>(uc: &B) -> EmuResult<Self> {
        let inner = uc.capture_context()?;
        Ok(Self { inner })
    }

    /// 恢复先前保存的 CPU 寄存器上下文快照
    pub fn restore<B: CpuBackend + ?Sized>(&self, uc: &mut B) -> EmuResult<()> {
        uc.restore_context(&self.inner)?;
        Ok(())
    }
}

/// ARM64 CPU 上下文配置
#[derive(Debug, Clone, Copy)]
pub struct CpuContext {
    pub stack_base: u64,
    pub stack_size: u64,
    pub stack_top: u64,
    pub tls_base: u64,
    pub errno_addr: u64,
}

impl CpuContext {
    /// 初始化 ARM64 CPU 执行环境：
    /// 1. 映射栈空间并设置 16 字节对齐的 SP
    /// 2. 映射返回停止魔数页 (0xDEAD0000) 并设置 LR
    /// 3. 写入并执行开启 NEON/FP 浮点运算的机器码（配置 CPACR_EL1）
    /// 4. 映射并初始化 Android Bionic TLS 块并写入 `TPIDR_EL0`
    pub fn init<B: CpuBackend + ?Sized>(uc: &mut B, mem: &mut MemoryManager) -> EmuResult<Self> {
        // 1. 映射栈空间 (RW)，预留 0x100 字节保护缓冲区，严格保持 16 字节对齐 (AAPCS64 规范)
        mem.map_labeled(
            uc,
            STACK_BASE,
            STACK_SIZE,
            Prot::READ | Prot::WRITE,
            "[stack]",
            0,
        )?;
        let stack_top = (STACK_BASE + STACK_SIZE - 0x100) & !0xF;

        // 2. 映射 RET_MAGIC_ADDR 所在页 (RX)，非 Unicorn 后端写入 SVC #0x1003 返回哨兵
        mem.map_labeled(
            uc,
            RET_MAGIC_ADDR,
            PAGE_SIZE,
            Prot::READ | Prot::EXEC,
            "[emu:ret_magic]",
            0,
        )?;
        if uc.uses_svc_trampolines() {
            mem.write_u32(uc, RET_MAGIC_ADDR, ARM64_SVC_RET_INSN)?;
        }

        // 3. 开启 ARM64 NEON / FP 浮点与 SIMD 单元（非 Unicorn 后端原生开启）
        if !uc.uses_svc_trampolines() {
            Self::enable_neon_fp(uc, mem)?;
        }

        // 4. 初始化 Bionic TLS 空间并设置 TPIDR_EL0
        let errno_addr = Self::init_tls(uc, mem, TLS_BASE, 1000)?;

        // 5. 设置初始栈指针与返回地址，清零被 Stub 借用的 X0
        uc.reg_write(RegisterARM64::SP, stack_top)?;
        uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR)?;
        uc.reg_write(RegisterARM64::X0, 0)?;

        Ok(Self {
            stack_base: STACK_BASE,
            stack_size: STACK_SIZE,
            stack_top,
            tls_base: TLS_BASE,
            errno_addr,
        })
    }

    /// 写入并执行 ARM64 开启 NEON/FP 浮点运算的初始化指令序列
    fn enable_neon_fp<B: CpuBackend + ?Sized>(
        uc: &mut B,
        mem: &mut MemoryManager,
    ) -> EmuResult<()> {
        // 4 条 ARM64 机器码（32-bit 定长，小端序）：
        //   0xD538_1040: mrs x0, cpacr_el1       ; 读取 CPACR_EL1 (op0=3, op1=0, CRn=1, CRm=0, op2=2) 到 X0
        //   0xB26C_0400: orr x0, x0, #0x300000   ; 置位 FPEN[21:20] = 0b11 (sf=1, N=1, immr=44, imms=1)
        //   0xD518_1040: msr cpacr_el1, x0       ; 写回 CPACR_EL1
        //   0xD503_3FDF: isb                     ; 指令同步屏障，确保系统寄存器生效
        const ENABLE_NEON_INSNS: [u32; 4] = [0xD538_1040, 0xB26C_0400, 0xD518_1040, 0xD503_3FDF];

        let mut code = [0u8; 16];
        for (i, insn) in ENABLE_NEON_INSNS.iter().enumerate() {
            code[i * 4..(i + 1) * 4].copy_from_slice(&insn.to_le_bytes());
        }

        mem.map_labeled(
            uc,
            CPU_INIT_STUB_ADDR,
            PAGE_SIZE,
            Prot::READ | Prot::EXEC,
            "[emu:cpu_init]",
            0,
        )?;
        mem.write(uc, CPU_INIT_STUB_ADDR, &code)?;

        // 执行上述 4 条指令（不挂载任何 Trace Hook，零污染）
        uc.run_simple(
            CPU_INIT_STUB_ADDR,
            CPU_INIT_STUB_ADDR + code.len() as u64,
            0,
            ENABLE_NEON_INSNS.len(),
        )?;

        Ok(())
    }

    /// 映射并填充 Android 10–12 Bionic TLS 块，并写入 `TPIDR_EL0` 系统寄存器
    pub fn init_tls<B: CpuBackend + ?Sized>(
        uc: &mut B,
        mem: &mut MemoryManager,
        tls_base: u64,
        tid: u32,
    ) -> EmuResult<u64> {
        mem.map_labeled(
            uc,
            tls_base,
            TLS_SIZE,
            Prot::READ | Prot::WRITE,
            "[tls]",
            0,
        )?;

        let pthread_struct_addr = tls_base + 0x1000;
        let errno_addr = tls_base + 0x2000;

        // 填充 Bionic 关键 TLS 槽位
        mem.write_u64(uc, tls_base + TLS_SLOT_SELF * 8, tls_base)?;
        mem.write_u64(uc, tls_base + TLS_SLOT_THREAD_ID * 8, pthread_struct_addr)?;
        mem.write_u64(uc, tls_base + TLS_SLOT_ERRNO * 8, errno_addr)?;
        mem.write_u64(uc, tls_base + TLS_SLOT_STACK_GUARD * 8, DEFAULT_STACK_GUARD)?;

        // 写入模拟 pthread_internal_t 中的 tid 与初始 errno=0
        mem.write_u32(uc, pthread_struct_addr + 0x10, tid)?;
        mem.write_u32(uc, errno_addr, 0)?;

        if uc.uses_svc_trampolines() {
            // 非 Unicorn 后端直接写 TPIDR_EL0 寄存器，无需跑初始化小代码
            uc.reg_write(RegisterARM64::TPIDR_EL0, tls_base)?;
        } else {
            // 执行 `msr tpidr_el0, x0; isb` 将 tls_base 写入 TPIDR_EL0
            const SET_TPIDR_INSNS: [u32; 2] = [0xD51B_D040, 0xD503_3FDF];
            let mut code = [0u8; 8];
            for (i, insn) in SET_TPIDR_INSNS.iter().enumerate() {
                code[i * 4..(i + 1) * 4].copy_from_slice(&insn.to_le_bytes());
            }

            let stub_addr = CPU_INIT_STUB_ADDR + 0x40;
            mem.write(uc, stub_addr, &code)?;
            uc.reg_write(RegisterARM64::X0, tls_base)?;
            uc.run_simple(
                stub_addr,
                stub_addr + code.len() as u64,
                0,
                SET_TPIDR_INSNS.len(),
            )?;
        }

        Ok(errno_addr)
    }

    /// 重置函数调用帧并按 AAPCS64 调用约定写入前 8 个整型/指针参数 (X0..X7)
    pub fn prepare_call<B: CpuBackend + ?Sized>(&self, uc: &mut B, args: &[u64]) -> EmuResult<()> {
        const ARG_REGS: [RegisterARM64; 8] = [
            RegisterARM64::X0,
            RegisterARM64::X1,
            RegisterARM64::X2,
            RegisterARM64::X3,
            RegisterARM64::X4,
            RegisterARM64::X5,
            RegisterARM64::X6,
            RegisterARM64::X7,
        ];

        uc.reg_write(RegisterARM64::SP, self.stack_top)?;
        uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR)?;

        for (reg, &val) in ARG_REGS.iter().zip(args.iter()) {
            uc.reg_write(*reg, val)?;
        }

        Ok(())
    }

    /// 保存当前完整 CPU 寄存器上下文快照
    pub fn save_snapshot<B: CpuBackend + ?Sized>(&self, uc: &B) -> EmuResult<CpuSnapshot> {
        CpuSnapshot::capture(uc)
    }

    /// 恢复先前保存的 CPU 寄存器上下文快照
    pub fn restore_snapshot<B: CpuBackend + ?Sized>(
        &self,
        uc: &mut B,
        snapshot: &CpuSnapshot,
    ) -> EmuResult<()> {
        snapshot.restore(uc)
    }
}
