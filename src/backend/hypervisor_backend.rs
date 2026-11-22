//! macOS Apple Silicon `Hypervisor.framework` 硬件虚拟化后端（零外部 crate 依赖）
//!
//! 关键细节：
//! - Apple Silicon IPA 映射严格要求 16KB 对齐，内部以 16KB 宿主物理页为映射粒度并维护 4KB 逻辑页视图，
//!   避免 Android 4KB 相邻段（如 `.text`/`.rodata`、`RET_MAGIC_ADDR`）在 `hv_vm_map` 时冲突。
//! - Guest 运行在 EL0t，EL1 异常向量表（`VBAR_EL1_ADDR = 0x8000`）填充 `HVC #0` 指令，
//!   捕获 `HV_EXIT_REASON_EXCEPTION` 后读取 `ESR_EL1` / `ELR_EL1` / `FAR_EL1` 分发给统一外部陷阱循环。

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use unicorn_engine::unicorn_const::Prot;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use unicorn_engine::RegisterARM64;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use crate::backend::{BackendKind, CpuBackend, CpuContextBlob, RunStopReason};
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
use crate::error::{EmuError, EmuResult};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{c_int, c_void};
    use std::ptr;

    use unicorn_engine::unicorn_const::Prot;
    use unicorn_engine::RegisterARM64;

    use crate::backend::vm_common::{
        build_el1_vector_table, build_identity_page_tables, decode_esr_el1, EsrException,
        CPACR_EL1_FPEN_ALL, HVF_HVC_TRAP_INSN, MAIR_EL1_DEFAULT, PSTATE_EL0T, SCTLR_EL1_MMU_ON,
        TCR_EL1_4KB_39BIT, TTBR0_PAGE_ADDR, TTBR0_TABLES_SIZE, VBAR_EL1_ADDR,
    };
    use crate::backend::{
        BackendKind, CpuBackend, CpuContextBlob, GenericCpuContext, RunStopReason,
        SVC_IMM_RET_MAGIC,
    };
    use crate::error::{EmuError, EmuResult};
    use crate::memory::{align_down, align_up, PAGE_SIZE};

    const HV_PAGE_SIZE: u64 = 0x4000; // Apple Silicon 16KB 硬件页
    const HV_SUCCESS: i32 = 0;
    const HV_DENIED: i32 = 0xFAE9_4007u32 as i32;

    const HV_MEMORY_READ: u64 = 1 << 0;
    const HV_MEMORY_WRITE: u64 = 1 << 1;
    const HV_MEMORY_EXEC: u64 = 1 << 2;

    const HV_EXIT_REASON_CANCELED: u32 = 0;
    const HV_EXIT_REASON_EXCEPTION: u32 = 1;
    const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;

    const HV_REG_PC: u32 = 31;
    const HV_REG_FPCR: u32 = 32;
    const HV_REG_FPSR: u32 = 33;
    const HV_REG_CPSR: u32 = 34;

    const HV_SYS_REG_SCTLR_EL1: u16 = 0xC080;
    const HV_SYS_REG_CPACR_EL1: u16 = 0xC082;
    const HV_SYS_REG_TTBR0_EL1: u16 = 0xC100;
    const HV_SYS_REG_TCR_EL1: u16 = 0xC102;
    const HV_SYS_REG_SPSR_EL1: u16 = 0xC200;
    const HV_SYS_REG_ELR_EL1: u16 = 0xC201;
    const HV_SYS_REG_SP_EL0: u16 = 0xC208;
    const HV_SYS_REG_ESR_EL1: u16 = 0xC290;
    const HV_SYS_REG_FAR_EL1: u16 = 0xC300;
    const HV_SYS_REG_MAIR_EL1: u16 = 0xC510;
    const HV_SYS_REG_VBAR_EL1: u16 = 0xC600;
    const HV_SYS_REG_TPIDR_EL0: u16 = 0xDE82;
    const HV_SYS_REG_SP_EL1: u16 = 0xE208;

    const PROT_READ: c_int = 0x1;
    const PROT_WRITE: c_int = 0x2;
    const MAP_PRIVATE: c_int = 0x0002;
    const MAP_ANON: c_int = 0x1000;
    const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

    #[repr(C)]
    struct HvVcpuExitException {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    }

    #[repr(C)]
    struct HvVcpuExit {
        reason: u32,
        _pad: u32,
        exception: HvVcpuExitException,
    }

    #[link(name = "Hypervisor", kind = "framework")]
    unsafe extern "C" {
        fn hv_vm_create(config: *mut c_void) -> i32;
        fn hv_vm_destroy() -> i32;
        fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> i32;
        fn hv_vm_unmap(ipa: u64, size: usize) -> i32;
        fn hv_vcpu_create(
            vcpu: *mut u64,
            exit: *mut *mut HvVcpuExit,
            config: *mut c_void,
        ) -> i32;
        fn hv_vcpu_destroy(vcpu: u64) -> i32;
        fn hv_vcpu_run(vcpu: u64) -> i32;
        fn hv_vcpu_get_reg(vcpu: u64, reg: u32, value: *mut u64) -> i32;
        fn hv_vcpu_set_reg(vcpu: u64, reg: u32, value: u64) -> i32;
        fn hv_vcpu_get_simd_fp_reg(vcpu: u64, reg: u32, value: *mut u128) -> i32;
        fn hv_vcpu_set_simd_fp_reg(vcpu: u64, reg: u32, value: u128) -> i32;
        fn hv_vcpu_get_sys_reg(vcpu: u64, reg: u16, value: *mut u64) -> i32;
        fn hv_vcpu_set_sys_reg(vcpu: u64, reg: u16, value: u64) -> i32;
    }

    unsafe extern "C" {
        fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(addr: *mut c_void, length: usize) -> c_int;
        fn sys_icache_invalidate(start: *mut c_void, len: usize);
    }

    fn hv_check(rc: i32, op: &str) -> EmuResult<()> {
        if rc == HV_SUCCESS {
            return Ok(());
        }
        if rc == HV_DENIED {
            return Err(EmuError::Backend(format!(
                "Hypervisor.framework {op} 返回 HV_DENIED (0x{:08x})：当前可执行文件缺少 `com.apple.security.hypervisor` entitlement，请使用 `codesign --entitlements <plist> --force -s - <binary>` 签名后重试",
                rc as u32
            )));
        }
        Err(EmuError::Backend(format!(
            "Hypervisor.framework {op} 失败: hv_return_t=0x{:08x}",
            rc as u32
        )))
    }

    pub struct HypervisorCpu {
        vcpu: u64,
        exit: *mut HvVcpuExit,
        /// 16KB 对齐宿主 IPA 页 -> mmap 宿主虚拟地址
        host_pages_16k: BTreeMap<u64, *mut u8>,
        /// Android 4KB 逻辑已映射页集合
        logical_pages_4k: BTreeSet<u64>,
        stop_requested: bool,
    }

    impl HypervisorCpu {
        pub fn new() -> EmuResult<Self> {
            hv_check(unsafe { hv_vm_create(ptr::null_mut()) }, "hv_vm_create")?;

            let mut vcpu: u64 = 0;
            let mut exit: *mut HvVcpuExit = ptr::null_mut();
            let rc = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, ptr::null_mut()) };
            if rc != HV_SUCCESS {
                unsafe {
                    hv_vm_destroy();
                }
                hv_check(rc, "hv_vcpu_create")?;
            }

            let mut cpu = Self {
                vcpu,
                exit,
                host_pages_16k: BTreeMap::new(),
                logical_pages_4k: BTreeSet::new(),
                stop_requested: false,
            };

            // 1. 映射 16KB 对齐的 Stage-1 L1+L2 恒等页表（512GB Normal Cacheable WBWA，仅前 2MB 只读保 VBAR_EL1）
            cpu.mem_map(TTBR0_PAGE_ADDR, TTBR0_TABLES_SIZE as u64, Prot::READ | Prot::WRITE)?;
            let page_tables = build_identity_page_tables();
            cpu.mem_write(TTBR0_PAGE_ADDR, &page_tables)?;

            // 2. 映射 EL1 异常向量表（填充 HVC #0 触发 HV_EXIT_REASON_EXCEPTION）
            cpu.mem_map(VBAR_EL1_ADDR, PAGE_SIZE, Prot::READ | Prot::EXEC)?;
            let vec_table = build_el1_vector_table(HVF_HVC_TRAP_INSN);
            cpu.mem_write(VBAR_EL1_ADDR, &vec_table)?;

            cpu.set_sys_reg(HV_SYS_REG_VBAR_EL1, VBAR_EL1_ADDR)?;
            cpu.set_sys_reg(HV_SYS_REG_CPACR_EL1, CPACR_EL1_FPEN_ALL)?;
            cpu.set_sys_reg(HV_SYS_REG_MAIR_EL1, MAIR_EL1_DEFAULT)?;
            cpu.set_sys_reg(HV_SYS_REG_TCR_EL1, TCR_EL1_4KB_39BIT)?;
            cpu.set_sys_reg(HV_SYS_REG_TTBR0_EL1, TTBR0_PAGE_ADDR)?;
            cpu.set_sys_reg(HV_SYS_REG_SCTLR_EL1, SCTLR_EL1_MMU_ON)?;
            cpu.set_sys_reg(HV_SYS_REG_SP_EL1, VBAR_EL1_ADDR + PAGE_SIZE)?;
            cpu.set_reg(HV_REG_CPSR, PSTATE_EL0T)?;

            Ok(cpu)
        }

        fn get_reg(&self, reg: u32) -> EmuResult<u64> {
            let mut val = 0u64;
            hv_check(
                unsafe { hv_vcpu_get_reg(self.vcpu, reg, &mut val) },
                "hv_vcpu_get_reg",
            )?;
            Ok(val)
        }

        fn set_reg(&mut self, reg: u32, val: u64) -> EmuResult<()> {
            hv_check(
                unsafe { hv_vcpu_set_reg(self.vcpu, reg, val) },
                "hv_vcpu_set_reg",
            )
        }

        fn get_sys_reg(&self, reg: u16) -> EmuResult<u64> {
            let mut val = 0u64;
            hv_check(
                unsafe { hv_vcpu_get_sys_reg(self.vcpu, reg, &mut val) },
                "hv_vcpu_get_sys_reg",
            )?;
            Ok(val)
        }

        fn set_sys_reg(&mut self, reg: u16, val: u64) -> EmuResult<()> {
            hv_check(
                unsafe { hv_vcpu_set_sys_reg(self.vcpu, reg, val) },
                "hv_vcpu_set_sys_reg",
            )
        }

        fn ensure_16k_page(&mut self, ipa_16k: u64) -> EmuResult<*mut u8> {
            if let Some(&ptr) = self.host_pages_16k.get(&ipa_16k) {
                return Ok(ptr);
            }
            let host_ptr = unsafe {
                mmap(
                    ptr::null_mut(),
                    HV_PAGE_SIZE as usize,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON,
                    -1,
                    0,
                )
            };
            if host_ptr == MAP_FAILED || host_ptr.is_null() {
                return Err(EmuError::Backend(
                    "Hypervisor 16KB 物理页分配失败".to_string(),
                ));
            }
            let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
            let rc = unsafe { hv_vm_map(host_ptr, ipa_16k, HV_PAGE_SIZE as usize, flags) };
            if rc != HV_SUCCESS {
                unsafe {
                    munmap(host_ptr, HV_PAGE_SIZE as usize);
                }
                hv_check(rc, "hv_vm_map")?;
            }
            let ptr = host_ptr as *mut u8;
            self.host_pages_16k.insert(ipa_16k, ptr);
            Ok(ptr)
        }

        pub fn run_until_trap(
            &mut self,
            start_pc: u64,
            _timeout_us: u64,
            _max_instructions: usize,
        ) -> RunStopReason {
            self.stop_requested = false;
            if let Err(e) = self.set_reg(HV_REG_PC, start_pc) {
                return RunStopReason::IllegalInstruction {
                    pc: start_pc,
                    detail: e.to_string(),
                };
            }
            if let Err(e) = self.set_reg(HV_REG_CPSR, PSTATE_EL0T) {
                return RunStopReason::IllegalInstruction {
                    pc: start_pc,
                    detail: e.to_string(),
                };
            }

            if let Err(e) = hv_check(unsafe { hv_vcpu_run(self.vcpu) }, "hv_vcpu_run") {
                return RunStopReason::IllegalInstruction {
                    pc: start_pc,
                    detail: e.to_string(),
                };
            }

            let exit = unsafe { &*self.exit };
            match exit.reason {
                HV_EXIT_REASON_EXCEPTION => {
                    let el2_esr = exit.exception.syndrome;
                    match decode_esr_el1(el2_esr) {
                        // 由 EL1 向量表中的 HVC #0 陷入 EL2 -> 读取 EL1 保存的真实 ESR/ELR/FAR
                        EsrException::Hvc64 { .. } => {
                            let esr_el1 = self.get_sys_reg(HV_SYS_REG_ESR_EL1).unwrap_or(0);
                            let elr_el1 =
                                self.get_sys_reg(HV_SYS_REG_ELR_EL1).unwrap_or(start_pc);
                            let far_el1 = self.get_sys_reg(HV_SYS_REG_FAR_EL1).unwrap_or(0);
                            let spsr_el1 =
                                self.get_sys_reg(HV_SYS_REG_SPSR_EL1).unwrap_or(PSTATE_EL0T);
                            let _ = self.set_reg(HV_REG_CPSR, spsr_el1);
                            let _ = self.set_reg(HV_REG_PC, elr_el1);
                            match decode_esr_el1(esr_el1) {
                                EsrException::Svc64 { imm16 } => RunStopReason::Svc {
                                    imm: imm16,
                                    next_pc: elr_el1,
                                },
                                EsrException::DataAbort { is_write, fsc, .. } => {
                                    RunStopReason::MemoryFault {
                                        pc: elr_el1,
                                        addr: far_el1,
                                        is_write,
                                        detail: format!(
                                            "Hypervisor DataAbort(fsc=0x{fsc:x}, write={is_write}, far=0x{far_el1:016x})"
                                        ),
                                    }
                                }
                                EsrException::InsnAbort { fsc, .. } => RunStopReason::MemoryFault {
                                    pc: elr_el1,
                                    addr: far_el1,
                                    is_write: false,
                                    detail: format!(
                                        "Hypervisor InsnAbort(fsc=0x{fsc:x}, far=0x{far_el1:016x})"
                                    ),
                                },
                                other => RunStopReason::IllegalInstruction {
                                    pc: elr_el1,
                                    detail: format!(
                                        "Hypervisor EL1 Exception({other:?}, esr=0x{esr_el1:x})"
                                    ),
                                },
                            }
                        }
                        EsrException::DataAbort { is_write, fsc, .. } => {
                            let pc = self.get_reg(HV_REG_PC).unwrap_or(start_pc);
                            let addr = exit.exception.physical_address;
                            RunStopReason::MemoryFault {
                                pc,
                                addr,
                                is_write,
                                detail: format!(
                                    "Hypervisor Stage-2 DataAbort(fsc=0x{fsc:x}, ipa=0x{addr:016x})"
                                ),
                            }
                        }
                        EsrException::InsnAbort { fsc, .. } => {
                            let pc = self.get_reg(HV_REG_PC).unwrap_or(start_pc);
                            let addr = exit.exception.physical_address;
                            RunStopReason::MemoryFault {
                                pc,
                                addr,
                                is_write: false,
                                detail: format!(
                                    "Hypervisor Stage-2 InsnAbort(fsc=0x{fsc:x}, ipa=0x{addr:016x})"
                                ),
                            }
                        }
                        other => {
                            let pc = self.get_reg(HV_REG_PC).unwrap_or(start_pc);
                            RunStopReason::IllegalInstruction {
                                pc,
                                detail: format!(
                                    "Hypervisor EL2 Exception({other:?}, esr=0x{el2_esr:x})"
                                ),
                            }
                        }
                    }
                }
                HV_EXIT_REASON_CANCELED | HV_EXIT_REASON_VTIMER_ACTIVATED => RunStopReason::Stopped,
                other => RunStopReason::IllegalInstruction {
                    pc: self.get_reg(HV_REG_PC).unwrap_or(start_pc),
                    detail: format!("Hypervisor 未预期退出码: reason={other}"),
                },
            }
        }
    }

    impl Drop for HypervisorCpu {
        fn drop(&mut self) {
            unsafe {
                let _ = hv_vcpu_destroy(self.vcpu);
            }
            for (&ipa_16k, &host_ptr) in &self.host_pages_16k {
                unsafe {
                    let _ = hv_vm_unmap(ipa_16k, HV_PAGE_SIZE as usize);
                    munmap(host_ptr.cast(), HV_PAGE_SIZE as usize);
                }
            }
            unsafe {
                let _ = hv_vm_destroy();
            }
        }
    }

    fn gpr_idx(reg: RegisterARM64) -> Option<u32> {
        match reg {
            RegisterARM64::X0 => Some(0),
            RegisterARM64::X1 => Some(1),
            RegisterARM64::X2 => Some(2),
            RegisterARM64::X3 => Some(3),
            RegisterARM64::X4 => Some(4),
            RegisterARM64::X5 => Some(5),
            RegisterARM64::X6 => Some(6),
            RegisterARM64::X7 => Some(7),
            RegisterARM64::X8 => Some(8),
            RegisterARM64::X9 => Some(9),
            RegisterARM64::X10 => Some(10),
            RegisterARM64::X11 => Some(11),
            RegisterARM64::X12 => Some(12),
            RegisterARM64::X13 => Some(13),
            RegisterARM64::X14 => Some(14),
            RegisterARM64::X15 => Some(15),
            RegisterARM64::X16 => Some(16),
            RegisterARM64::X17 => Some(17),
            RegisterARM64::X18 => Some(18),
            RegisterARM64::X19 => Some(19),
            RegisterARM64::X20 => Some(20),
            RegisterARM64::X21 => Some(21),
            RegisterARM64::X22 => Some(22),
            RegisterARM64::X23 => Some(23),
            RegisterARM64::X24 => Some(24),
            RegisterARM64::X25 => Some(25),
            RegisterARM64::X26 => Some(26),
            RegisterARM64::X27 => Some(27),
            RegisterARM64::X28 => Some(28),
            RegisterARM64::X29 => Some(29),
            RegisterARM64::X30 => Some(30),
            _ => None,
        }
    }

    fn d_idx(reg: RegisterARM64) -> Option<u8> {
        match reg {
            RegisterARM64::D0 => Some(0),
            RegisterARM64::D1 => Some(1),
            RegisterARM64::D2 => Some(2),
            RegisterARM64::D3 => Some(3),
            RegisterARM64::D4 => Some(4),
            RegisterARM64::D5 => Some(5),
            RegisterARM64::D6 => Some(6),
            RegisterARM64::D7 => Some(7),
            RegisterARM64::D8 => Some(8),
            RegisterARM64::D9 => Some(9),
            RegisterARM64::D10 => Some(10),
            RegisterARM64::D11 => Some(11),
            RegisterARM64::D12 => Some(12),
            RegisterARM64::D13 => Some(13),
            RegisterARM64::D14 => Some(14),
            RegisterARM64::D15 => Some(15),
            RegisterARM64::D16 => Some(16),
            RegisterARM64::D17 => Some(17),
            RegisterARM64::D18 => Some(18),
            RegisterARM64::D19 => Some(19),
            RegisterARM64::D20 => Some(20),
            RegisterARM64::D21 => Some(21),
            RegisterARM64::D22 => Some(22),
            RegisterARM64::D23 => Some(23),
            RegisterARM64::D24 => Some(24),
            RegisterARM64::D25 => Some(25),
            RegisterARM64::D26 => Some(26),
            RegisterARM64::D27 => Some(27),
            RegisterARM64::D28 => Some(28),
            RegisterARM64::D29 => Some(29),
            RegisterARM64::D30 => Some(30),
            RegisterARM64::D31 => Some(31),
            _ => None,
        }
    }

    impl CpuBackend for HypervisorCpu {
        fn kind(&self) -> BackendKind {
            BackendKind::Hypervisor
        }

        fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64> {
            if let Some(i) = gpr_idx(reg) {
                return self.get_reg(i);
            }
            if let Some(d) = d_idx(reg) {
                return Ok(self.reg_read_q(d)? as u64);
            }
            match reg {
                RegisterARM64::SP => self.get_sys_reg(HV_SYS_REG_SP_EL0),
                RegisterARM64::PC => self.get_reg(HV_REG_PC),
                RegisterARM64::NZCV | RegisterARM64::PSTATE => self.get_reg(HV_REG_CPSR),
                RegisterARM64::TPIDR_EL0 => self.get_sys_reg(HV_SYS_REG_TPIDR_EL0),
                RegisterARM64::FPCR => self.get_reg(HV_REG_FPCR),
                RegisterARM64::FPSR => self.get_reg(HV_REG_FPSR),
                _ => Ok(0),
            }
        }

        fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()> {
            if let Some(i) = gpr_idx(reg) {
                return self.set_reg(i, val);
            }
            if let Some(d) = d_idx(reg) {
                let cur = self.reg_read_q(d)?;
                let next = (cur & !0xFFFF_FFFF_FFFF_FFFFu128) | u128::from(val);
                return self.reg_write_q(d, next);
            }
            match reg {
                RegisterARM64::SP => self.set_sys_reg(HV_SYS_REG_SP_EL0, val),
                RegisterARM64::PC => self.set_reg(HV_REG_PC, val),
                RegisterARM64::NZCV | RegisterARM64::PSTATE => self.set_reg(HV_REG_CPSR, val),
                RegisterARM64::TPIDR_EL0 => self.set_sys_reg(HV_SYS_REG_TPIDR_EL0, val),
                RegisterARM64::FPCR => self.set_reg(HV_REG_FPCR, val),
                RegisterARM64::FPSR => self.set_reg(HV_REG_FPSR, val),
                _ => Ok(()),
            }
        }

        fn reg_read_q(&self, idx: u8) -> EmuResult<u128> {
            let mut val = 0u128;
            hv_check(
                unsafe { hv_vcpu_get_simd_fp_reg(self.vcpu, u32::from(idx & 31), &mut val) },
                "hv_vcpu_get_simd_fp_reg",
            )?;
            Ok(val)
        }

        fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()> {
            hv_check(
                unsafe { hv_vcpu_set_simd_fp_reg(self.vcpu, u32::from(idx & 31), val) },
                "hv_vcpu_set_simd_fp_reg",
            )
        }

        fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
            let mut off = 0usize;
            while off < buf.len() {
                let cur = addr + off as u64;
                let page_4k = align_down(cur, PAGE_SIZE);
                if !self.logical_pages_4k.contains(&page_4k) {
                    return Err(EmuError::UnmappedMemory {
                        addr: cur,
                        size: buf.len() - off,
                    });
                }
                let ipa_16k = align_down(cur, HV_PAGE_SIZE);
                let host_ptr = *self.host_pages_16k.get(&ipa_16k).ok_or(
                    EmuError::UnmappedMemory {
                        addr: cur,
                        size: buf.len() - off,
                    },
                )?;
                let in_page = (cur - ipa_16k) as usize;
                let chunk = (PAGE_SIZE as usize - ((cur - page_4k) as usize)).min(buf.len() - off);
                unsafe {
                    ptr::copy_nonoverlapping(
                        host_ptr.add(in_page),
                        buf.as_mut_ptr().add(off),
                        chunk,
                    );
                }
                off += chunk;
            }
            Ok(())
        }

        fn mem_write(&mut self, addr: u64, data: &[u8]) -> EmuResult<()> {
            let mut off = 0usize;
            while off < data.len() {
                let cur = addr + off as u64;
                let page_4k = align_down(cur, PAGE_SIZE);
                if !self.logical_pages_4k.contains(&page_4k) {
                    return Err(EmuError::UnmappedMemory {
                        addr: cur,
                        size: data.len() - off,
                    });
                }
                let ipa_16k = align_down(cur, HV_PAGE_SIZE);
                let host_ptr = *self.host_pages_16k.get(&ipa_16k).ok_or(
                    EmuError::UnmappedMemory {
                        addr: cur,
                        size: data.len() - off,
                    },
                )?;
                let in_page = (cur - ipa_16k) as usize;
                let chunk = (PAGE_SIZE as usize - ((cur - page_4k) as usize)).min(data.len() - off);
                unsafe {
                    ptr::copy_nonoverlapping(
                        data.as_ptr().add(off),
                        host_ptr.add(in_page),
                        chunk,
                    );
                }
                off += chunk;
            }
            Ok(())
        }

        fn mem_map(&mut self, addr: u64, size: u64, _prot: Prot) -> EmuResult<()> {
            let start = align_down(addr, PAGE_SIZE);
            let end = align_up(addr.saturating_add(size), PAGE_SIZE);
            let mut cur = start;
            while cur < end {
                let ipa_16k = align_down(cur, HV_PAGE_SIZE);
                self.ensure_16k_page(ipa_16k)?;
                self.logical_pages_4k.insert(cur);
                cur += PAGE_SIZE;
            }
            Ok(())
        }

        fn mem_unmap(&mut self, addr: u64, size: u64) -> EmuResult<()> {
            let start = align_down(addr, PAGE_SIZE);
            let end = align_up(addr.saturating_add(size), PAGE_SIZE);
            let mut touched_16k = BTreeSet::new();
            let mut cur = start;
            while cur < end {
                if self.logical_pages_4k.remove(&cur) {
                    let ipa_16k = align_down(cur, HV_PAGE_SIZE);
                    if let Some(&host_ptr) = self.host_pages_16k.get(&ipa_16k) {
                        let sub_off = (cur - ipa_16k) as usize;
                        unsafe {
                            ptr::write_bytes(host_ptr.add(sub_off), 0, PAGE_SIZE as usize);
                        }
                    }
                    touched_16k.insert(ipa_16k);
                }
                cur += PAGE_SIZE;
            }
            for ipa_16k in touched_16k {
                let any_live = (0..4).any(|i| self.logical_pages_4k.contains(&(ipa_16k + i * PAGE_SIZE)));
                if !any_live {
                    if let Some(host_ptr) = self.host_pages_16k.remove(&ipa_16k) {
                        unsafe {
                            let _ = hv_vm_unmap(ipa_16k, HV_PAGE_SIZE as usize);
                            munmap(host_ptr.cast(), HV_PAGE_SIZE as usize);
                        }
                    }
                }
            }
            Ok(())
        }

        fn mem_protect(&mut self, _addr: u64, _size: u64, _prot: Prot) -> EmuResult<()> {
            Ok(())
        }

        fn flush_cache(&mut self, begin: u64, end: u64) -> EmuResult<()> {
            if end > begin {
                for (&ipa_16k, &host_ptr) in &self.host_pages_16k {
                    let p_end = ipa_16k + HV_PAGE_SIZE;
                    if p_end <= begin || ipa_16k >= end {
                        continue;
                    }
                    let f_start = begin.max(ipa_16k);
                    let f_end = end.min(p_end);
                    let off = (f_start - ipa_16k) as usize;
                    let len = (f_end - f_start) as usize;
                    unsafe {
                        sys_icache_invalidate(host_ptr.add(off).cast(), len);
                    }
                }
            } else {
                for &host_ptr in self.host_pages_16k.values() {
                    unsafe {
                        sys_icache_invalidate(host_ptr.cast(), HV_PAGE_SIZE as usize);
                    }
                }
            }
            Ok(())
        }

        fn run_simple(
            &mut self,
            begin: u64,
            until: u64,
            timeout_us: u64,
            count: usize,
        ) -> EmuResult<()> {
            match self.run_until_trap(begin, timeout_us, count) {
                RunStopReason::Svc {
                    imm: SVC_IMM_RET_MAGIC,
                    ..
                }
                | RunStopReason::Stopped => Ok(()),
                RunStopReason::Svc { imm, next_pc } => {
                    if next_pc == until || next_pc.wrapping_sub(4) == until {
                        Ok(())
                    } else {
                        Err(EmuError::Backend(format!(
                            "Hypervisor run_simple 遇到未处理 SVC #0x{imm:x} @ 0x{next_pc:x}"
                        )))
                    }
                }
                RunStopReason::MemoryFault { pc, detail, .. }
                | RunStopReason::IllegalInstruction { pc, detail } => Err(EmuError::Backend(
                    format!("Hypervisor run_simple 异常 @ 0x{pc:x}: {detail}"),
                )),
                RunStopReason::Timeout { pc } => Err(EmuError::Backend(format!(
                    "Hypervisor run_simple 超时 @ 0x{pc:x}"
                ))),
            }
        }

        fn stop(&mut self) -> EmuResult<()> {
            self.stop_requested = true;
            Ok(())
        }

        fn is_stop_requested(&self) -> bool {
            self.stop_requested
        }

        fn capture_context(&self) -> EmuResult<CpuContextBlob> {
            let mut x = [0u64; 31];
            for (i, slot) in x.iter_mut().enumerate() {
                *slot = self.get_reg(i as u32)?;
            }
            let mut q = [0u128; 32];
            for (i, slot) in q.iter_mut().enumerate() {
                *slot = self.reg_read_q(i as u8)?;
            }
            Ok(CpuContextBlob::Generic(Box::new(GenericCpuContext {
                x,
                sp: self.get_sys_reg(HV_SYS_REG_SP_EL0)?,
                pc: self.get_reg(HV_REG_PC)?,
                pstate: self.get_reg(HV_REG_CPSR)?,
                tpidr_el0: self.get_sys_reg(HV_SYS_REG_TPIDR_EL0)?,
                q,
                fpcr: self.get_reg(HV_REG_FPCR).unwrap_or(0) as u32,
                fpsr: self.get_reg(HV_REG_FPSR).unwrap_or(0) as u32,
            })))
        }

        fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()> {
            match ctx {
                CpuContextBlob::Generic(g) => {
                    for (i, &val) in g.x.iter().enumerate() {
                        self.set_reg(i as u32, val)?;
                    }
                    for (i, &val) in g.q.iter().enumerate() {
                        self.reg_write_q(i as u8, val)?;
                    }
                    self.set_sys_reg(HV_SYS_REG_SP_EL0, g.sp)?;
                    self.set_reg(HV_REG_PC, g.pc)?;
                    self.set_reg(HV_REG_CPSR, g.pstate)?;
                    self.set_sys_reg(HV_SYS_REG_TPIDR_EL0, g.tpidr_el0)?;
                    let _ = self.set_reg(HV_REG_FPCR, u64::from(g.fpcr));
                    let _ = self.set_reg(HV_REG_FPSR, u64::from(g.fpsr));
                    Ok(())
                }
                CpuContextBlob::Unicorn(_) => Err(EmuError::Backend(
                    "不能将 Unicorn 快照恢复到 Hypervisor 后端".to_string(),
                )),
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use imp::HypervisorCpu;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub struct HypervisorCpu;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl HypervisorCpu {
    pub fn new() -> EmuResult<Self> {
        Err(EmuError::Backend(
            "Hypervisor.framework 后端仅支持 macOS Apple Silicon (aarch64) 宿主机（当前平台请使用 unicorn / dynarmic / kvm）"
                .to_string(),
        ))
    }

    pub fn run_until_trap(
        &mut self,
        start_pc: u64,
        _timeout_us: u64,
        _max_instructions: usize,
    ) -> RunStopReason {
        RunStopReason::IllegalInstruction {
            pc: start_pc,
            detail: "Hypervisor.framework 后端在当前宿主机不可用".to_string(),
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl CpuBackend for HypervisorCpu {
    fn kind(&self) -> BackendKind {
        BackendKind::Hypervisor
    }
    fn reg_read(&self, _reg: RegisterARM64) -> EmuResult<u64> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn reg_write(&mut self, _reg: RegisterARM64, _val: u64) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn reg_read_q(&self, _idx: u8) -> EmuResult<u128> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn reg_write_q(&mut self, _idx: u8, _val: u128) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn mem_read(&self, _addr: u64, _buf: &mut [u8]) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn mem_write(&mut self, _addr: u64, _data: &[u8]) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn mem_map(&mut self, _addr: u64, _size: u64, _prot: Prot) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn mem_unmap(&mut self, _addr: u64, _size: u64) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn mem_protect(&mut self, _addr: u64, _size: u64, _prot: Prot) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn flush_cache(&mut self, _begin: u64, _end: u64) -> EmuResult<()> {
        Ok(())
    }
    fn run_simple(&mut self, _: u64, _: u64, _: u64, _: usize) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn stop(&mut self) -> EmuResult<()> {
        Ok(())
    }
    fn capture_context(&self) -> EmuResult<CpuContextBlob> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
    fn restore_context(&mut self, _ctx: &CpuContextBlob) -> EmuResult<()> {
        Err(EmuError::Backend("Hypervisor 不可用".to_string()))
    }
}
