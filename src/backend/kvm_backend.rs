//! Linux AArch64 KVM 硬件虚拟化后端（零外部 crate 依赖，直调 `/dev/kvm` ioctl）

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
use unicorn_engine::unicorn_const::Prot;
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
use unicorn_engine::RegisterARM64;

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
use crate::backend::{BackendKind, CpuBackend, CpuContextBlob, RunStopReason};
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
use crate::error::{EmuError, EmuResult};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod imp {
    use std::collections::BTreeMap;
    use std::ffi::{c_int, c_ulong, c_void};
    use std::fs::OpenOptions;
    use std::os::fd::IntoRawFd;
    use std::ptr;

    use unicorn_engine::unicorn_const::Prot;
    use unicorn_engine::RegisterARM64;

    use crate::backend::vm_common::{
        build_el1_vector_table, build_identity_page_tables, decode_esr_el1, EsrException,
        CPACR_EL1_FPEN_ALL, KVM_BRK_TRAP_INSN, MAIR_EL1_DEFAULT, PSTATE_EL0T, SCTLR_EL1_MMU_ON,
        TCR_EL1_4KB_39BIT, TTBR0_PAGE_ADDR, TTBR0_TABLES_SIZE, VBAR_EL1_ADDR,
    };
    use crate::backend::{
        BackendKind, CpuBackend, CpuContextBlob, GenericCpuContext, RunStopReason,
    };
    use crate::error::{EmuError, EmuResult};
    use crate::memory::{align_down, align_up, PAGE_SIZE};

    const PROT_READ: c_int = 0x1;
    const PROT_WRITE: c_int = 0x2;
    const MAP_SHARED: c_int = 0x01;
    const MAP_PRIVATE: c_int = 0x02;
    const MAP_ANONYMOUS: c_int = 0x20;
    const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

    const KVM_CREATE_VM: c_ulong = 0xAE01;
    const KVM_GET_VCPU_MMAP_SIZE: c_ulong = 0xAE04;
    const KVM_CREATE_VCPU: c_ulong = 0xAE41;
    const KVM_SET_USER_MEMORY_REGION: c_ulong = 0x4020_AE46;
    const KVM_RUN: c_ulong = 0xAE80;
    const KVM_SET_GUEST_DEBUG: c_ulong = 0x4208_AE9B;
    const KVM_GET_ONE_REG: c_ulong = 0x4010_AEAB;
    const KVM_SET_ONE_REG: c_ulong = 0x4010_AEAC;
    const KVM_ARM_VCPU_INIT: c_ulong = 0x4020_AEAE;
    const KVM_ARM_PREFERRED_TARGET: c_ulong = 0x8020_AEAF;

    const KVM_EXIT_DEBUG: u32 = 4;
    const KVM_EXIT_HLT: u32 = 5;
    const KVM_EXIT_MMIO: u32 = 6;
    const KVM_EXIT_FAIL_ENTRY: u32 = 9;
    const KVM_EXIT_INTERNAL_ERROR: u32 = 17;

    const KVM_GUESTDBG_ENABLE: u32 = 0x0000_0001;
    const KVM_GUESTDBG_USE_SW_BP: u32 = 0x0001_0000;

    // ARM64 KVM_GET_ONE_REG / KVM_SET_ONE_REG ID 编码
    const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
    const KVM_REG_SIZE_U32: u64 = 0x0020_0000_0000_0000;
    const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
    const KVM_REG_SIZE_U128: u64 = 0x0040_0000_0000_0000;
    const KVM_REG_ARM_CORE: u64 = 0x0010_0000;
    const KVM_REG_ARM64_SYSREG: u64 = 0x0013_0000;

    const fn core_reg_u64(u32_off: u64) -> u64 {
        KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | u32_off
    }
    const fn core_reg_u128(u32_off: u64) -> u64 {
        KVM_REG_ARM64 | KVM_REG_SIZE_U128 | KVM_REG_ARM_CORE | u32_off
    }
    const fn core_reg_u32(u32_off: u64) -> u64 {
        KVM_REG_ARM64 | KVM_REG_SIZE_U32 | KVM_REG_ARM_CORE | u32_off
    }
    const fn sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
        KVM_REG_ARM64
            | KVM_REG_SIZE_U64
            | KVM_REG_ARM64_SYSREG
            | (op0 << 14)
            | (op1 << 11)
            | (crn << 7)
            | (crm << 3)
            | op2
    }

    const REG_SP_EL0: u64 = core_reg_u64(0x3E);
    const REG_PC: u64 = core_reg_u64(0x40);
    const REG_PSTATE: u64 = core_reg_u64(0x42);
    const REG_SP_EL1: u64 = core_reg_u64(0x44);
    const REG_ELR_EL1: u64 = core_reg_u64(0x46);
    const REG_SPSR_EL1: u64 = core_reg_u64(0x48);
    const REG_FPSR: u64 = core_reg_u32(0xD4);
    const REG_FPCR: u64 = core_reg_u32(0xD5);

    const SYS_SCTLR_EL1: u64 = sys_reg(3, 0, 1, 0, 0);
    const SYS_CPACR_EL1: u64 = sys_reg(3, 0, 1, 0, 2);
    const SYS_TTBR0_EL1: u64 = sys_reg(3, 0, 2, 0, 0);
    const SYS_TCR_EL1: u64 = sys_reg(3, 0, 2, 0, 2);
    const SYS_ESR_EL1: u64 = sys_reg(3, 0, 5, 2, 0);
    const SYS_FAR_EL1: u64 = sys_reg(3, 0, 6, 0, 0);
    const SYS_MAIR_EL1: u64 = sys_reg(3, 0, 10, 2, 0);
    const SYS_VBAR_EL1: u64 = sys_reg(3, 0, 12, 0, 0);
    const SYS_TPIDR_EL0: u64 = sys_reg(3, 3, 13, 0, 2);

    #[repr(C)]
    struct KvmVcpuInit {
        target: u32,
        features: [u32; 7],
    }

    #[repr(C)]
    struct KvmUserspaceMemoryRegion {
        slot: u32,
        flags: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    }

    #[repr(C)]
    struct KvmOneReg {
        id: u64,
        addr: u64,
    }

    #[repr(C)]
    struct KvmGuestDebug {
        control: u32,
        pad: u32,
        // ARM64 kvm_guest_debug_arch = dbg_bcr[16] + dbg_bvr[16] + dbg_wcr[16] + dbg_wvr[16] = 64 * u64 (512B)
        arch_pad: [u64; 64],
    }

    unsafe extern "C" {
        fn close(fd: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(addr: *mut c_void, length: usize) -> c_int;
    }

    struct KvmSlot {
        slot_id: u32,
        guest_addr: u64,
        size: u64,
        host_ptr: *mut u8,
    }

    pub struct KvmCpu {
        kvm_fd: c_int,
        vm_fd: c_int,
        vcpu_fd: c_int,
        run_ptr: *mut u8,
        run_size: usize,
        slots: BTreeMap<u64, KvmSlot>,
        next_slot: u32,
        stop_requested: bool,
    }

    impl KvmCpu {
        pub fn new() -> EmuResult<Self> {
            let kvm_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .map_err(|e| {
                    EmuError::Backend(format!(
                        "无法打开 /dev/kvm（请确认内核启用 KVM 且当前用户具备 /dev/kvm 权限）: {e}"
                    ))
                })?;
            let kvm_fd: c_int = kvm_file.into_raw_fd();
            let vm_fd = unsafe { ioctl(kvm_fd, KVM_CREATE_VM, 0 as c_ulong) };
            if vm_fd < 0 {
                unsafe { close(kvm_fd) };
                return Err(EmuError::Backend("KVM_CREATE_VM 失败".to_string()));
            }
            let vcpu_fd = unsafe { ioctl(vm_fd, KVM_CREATE_VCPU, 0 as c_ulong) };
            if vcpu_fd < 0 {
                unsafe {
                    close(vm_fd);
                    close(kvm_fd);
                }
                return Err(EmuError::Backend("KVM_CREATE_VCPU 失败".to_string()));
            }

            let mut init = KvmVcpuInit {
                target: 0,
                features: [0; 7],
            };
            if unsafe { ioctl(vm_fd, KVM_ARM_PREFERRED_TARGET, &mut init) } < 0 {
                unsafe {
                    close(vcpu_fd);
                    close(vm_fd);
                    close(kvm_fd);
                }
                return Err(EmuError::Backend(
                    "KVM_ARM_PREFERRED_TARGET 失败".to_string(),
                ));
            }
            if unsafe { ioctl(vcpu_fd, KVM_ARM_VCPU_INIT, &init) } < 0 {
                unsafe {
                    close(vcpu_fd);
                    close(vm_fd);
                    close(kvm_fd);
                }
                return Err(EmuError::Backend("KVM_ARM_VCPU_INIT 失败".to_string()));
            }

            let mmap_size = unsafe { ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0 as c_ulong) };
            if mmap_size <= 0 {
                unsafe {
                    close(vcpu_fd);
                    close(vm_fd);
                    close(kvm_fd);
                }
                return Err(EmuError::Backend(
                    "KVM_GET_VCPU_MMAP_SIZE 失败".to_string(),
                ));
            }
            let run_size = mmap_size as usize;
            let run_ptr = unsafe {
                mmap(
                    ptr::null_mut(),
                    run_size,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    vcpu_fd,
                    0,
                )
            };
            if run_ptr == MAP_FAILED || run_ptr.is_null() {
                unsafe {
                    close(vcpu_fd);
                    close(vm_fd);
                    close(kvm_fd);
                }
                return Err(EmuError::Backend("mmap kvm_run 共享页失败".to_string()));
            }

            let dbg = KvmGuestDebug {
                control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
                pad: 0,
                arch_pad: [0; 64],
            };
            if unsafe { ioctl(vcpu_fd, KVM_SET_GUEST_DEBUG, &dbg) } < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    munmap(run_ptr, run_size);
                    close(vcpu_fd);
                    close(vm_fd);
                    close(kvm_fd);
                }
                return Err(EmuError::Backend(format!(
                    "KVM_SET_GUEST_DEBUG 失败: {err}"
                )));
            }

            let mut cpu = Self {
                kvm_fd,
                vm_fd,
                vcpu_fd,
                run_ptr: run_ptr as *mut u8,
                run_size,
                slots: BTreeMap::new(),
                next_slot: 0,
                stop_requested: false,
            };

            // 1. 映射 Stage-1 L1+L2 恒等页表（512GB Normal Cacheable WBWA，仅前 2MB 只读保 VBAR_EL1）
            cpu.mem_map(TTBR0_PAGE_ADDR, TTBR0_TABLES_SIZE as u64, Prot::READ | Prot::WRITE)?;
            let page_tables = build_identity_page_tables();
            cpu.mem_write(TTBR0_PAGE_ADDR, &page_tables)?;

            // 2. 映射 EL1 异常向量表（填充 BRK #0x1337，使 EL0 SVC/Abort 经 EL1 向量表退回宿主）
            cpu.mem_map(VBAR_EL1_ADDR, PAGE_SIZE, Prot::READ | Prot::EXEC)?;
            let vec_table = build_el1_vector_table(KVM_BRK_TRAP_INSN);
            cpu.mem_write(VBAR_EL1_ADDR, &vec_table)?;

            cpu.set_one_reg_u64(SYS_VBAR_EL1, VBAR_EL1_ADDR)?;
            cpu.set_one_reg_u64(SYS_CPACR_EL1, CPACR_EL1_FPEN_ALL)?;
            cpu.set_one_reg_u64(SYS_MAIR_EL1, MAIR_EL1_DEFAULT)?;
            cpu.set_one_reg_u64(SYS_TCR_EL1, TCR_EL1_4KB_39BIT)?;
            cpu.set_one_reg_u64(SYS_TTBR0_EL1, TTBR0_PAGE_ADDR)?;
            cpu.set_one_reg_u64(SYS_SCTLR_EL1, SCTLR_EL1_MMU_ON)?;
            cpu.set_one_reg_u64(REG_SP_EL1, VBAR_EL1_ADDR + PAGE_SIZE)?;
            cpu.set_one_reg_u64(REG_PSTATE, PSTATE_EL0T)?;

            Ok(cpu)
        }

        fn get_one_reg_u64(&self, id: u64) -> EmuResult<u64> {
            let mut val = 0u64;
            let reg = KvmOneReg {
                id,
                addr: (&mut val as *mut u64) as u64,
            };
            if unsafe { ioctl(self.vcpu_fd, KVM_GET_ONE_REG, &reg) } < 0 {
                return Err(EmuError::Backend(format!(
                    "KVM_GET_ONE_REG(0x{id:x}) 失败"
                )));
            }
            Ok(val)
        }

        fn set_one_reg_u64(&self, id: u64, val: u64) -> EmuResult<()> {
            let reg = KvmOneReg {
                id,
                addr: (&val as *const u64) as u64,
            };
            if unsafe { ioctl(self.vcpu_fd, KVM_SET_ONE_REG, &reg) } < 0 {
                return Err(EmuError::Backend(format!(
                    "KVM_SET_ONE_REG(0x{id:x}) 失败"
                )));
            }
            Ok(())
        }

        fn get_one_reg_u128(&self, id: u64) -> EmuResult<u128> {
            let mut val = 0u128;
            let reg = KvmOneReg {
                id,
                addr: (&mut val as *mut u128) as u64,
            };
            if unsafe { ioctl(self.vcpu_fd, KVM_GET_ONE_REG, &reg) } < 0 {
                return Err(EmuError::Backend(format!(
                    "KVM_GET_ONE_REG(u128 0x{id:x}) 失败"
                )));
            }
            Ok(val)
        }

        fn set_one_reg_u128(&self, id: u64, val: u128) -> EmuResult<()> {
            let reg = KvmOneReg {
                id,
                addr: (&val as *const u128) as u64,
            };
            if unsafe { ioctl(self.vcpu_fd, KVM_SET_ONE_REG, &reg) } < 0 {
                return Err(EmuError::Backend(format!(
                    "KVM_SET_ONE_REG(u128 0x{id:x}) 失败"
                )));
            }
            Ok(())
        }

        fn find_slot(&self, addr: u64) -> Option<&KvmSlot> {
            self.slots
                .range(..=addr)
                .next_back()
                .map(|(_, s)| s)
                .filter(|s| addr >= s.guest_addr && addr < s.guest_addr + s.size)
        }

        pub fn run_until_trap(
            &mut self,
            start_pc: u64,
            _timeout_us: u64,
            _max_instructions: usize,
        ) -> RunStopReason {
            self.stop_requested = false;
            if let Err(e) = self.set_one_reg_u64(REG_PC, start_pc) {
                return RunStopReason::IllegalInstruction {
                    pc: start_pc,
                    detail: e.to_string(),
                };
            }
            if let Err(e) = self.set_one_reg_u64(REG_PSTATE, PSTATE_EL0T) {
                return RunStopReason::IllegalInstruction {
                    pc: start_pc,
                    detail: e.to_string(),
                };
            }

            loop {
                if unsafe { ioctl(self.vcpu_fd, KVM_RUN, 0 as c_ulong) } < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(4) {
                        continue; // EINTR
                    }
                    return RunStopReason::IllegalInstruction {
                        pc: start_pc,
                        detail: format!("KVM_RUN ioctl 返回错误: {err}"),
                    };
                }
                break;
            }

            // struct kvm_run.exit_reason 位于偏移 +8 (u32)
            let exit_reason = unsafe { ptr::read_volatile(self.run_ptr.add(8).cast::<u32>()) };
            match exit_reason {
                KVM_EXIT_DEBUG => {
                    let esr = self.get_one_reg_u64(SYS_ESR_EL1).unwrap_or(0);
                    let elr = self.get_one_reg_u64(REG_ELR_EL1).unwrap_or(start_pc);
                    let far = self.get_one_reg_u64(SYS_FAR_EL1).unwrap_or(0);
                    let spsr = self.get_one_reg_u64(REG_SPSR_EL1).unwrap_or(PSTATE_EL0T);
                    let _ = self.set_one_reg_u64(REG_PSTATE, spsr);
                    let _ = self.set_one_reg_u64(REG_PC, elr);
                    match decode_esr_el1(esr) {
                        EsrException::Svc64 { imm16 } => RunStopReason::Svc {
                            imm: imm16,
                            next_pc: elr,
                        },
                        EsrException::DataAbort { is_write, fsc, .. } => {
                            RunStopReason::MemoryFault {
                                pc: elr,
                                addr: far,
                                is_write,
                                detail: format!(
                                    "KVM DataAbort(fsc=0x{fsc:x}, write={is_write}, far=0x{far:016x})"
                                ),
                            }
                        }
                        EsrException::InsnAbort { fsc, .. } => RunStopReason::MemoryFault {
                            pc: elr,
                            addr: far,
                            is_write: false,
                            detail: format!("KVM InsnAbort(fsc=0x{fsc:x}, far=0x{far:016x})"),
                        },
                        other => RunStopReason::IllegalInstruction {
                            pc: elr,
                            detail: format!("KVM Exception({other:?}, esr=0x{esr:x})"),
                        },
                    }
                }
                KVM_EXIT_MMIO => {
                    let pc = self.get_one_reg_u64(REG_PC).unwrap_or(start_pc);
                    let addr = unsafe { ptr::read_volatile(self.run_ptr.add(32).cast::<u64>()) };
                    let is_write =
                        unsafe { ptr::read_volatile(self.run_ptr.add(52).cast::<u8>()) } != 0;
                    RunStopReason::MemoryFault {
                        pc,
                        addr,
                        is_write,
                        detail: format!("KVM MMIO 未映射访存: addr=0x{addr:016x}"),
                    }
                }
                KVM_EXIT_HLT => RunStopReason::Stopped,
                KVM_EXIT_FAIL_ENTRY | KVM_EXIT_INTERNAL_ERROR => RunStopReason::IllegalInstruction {
                    pc: self.get_one_reg_u64(REG_PC).unwrap_or(start_pc),
                    detail: format!("KVM exit_reason={exit_reason}"),
                },
                other => RunStopReason::IllegalInstruction {
                    pc: self.get_one_reg_u64(REG_PC).unwrap_or(start_pc),
                    detail: format!("KVM 未预期退出码: exit_reason={other}"),
                },
            }
        }
    }

    impl Drop for KvmCpu {
        fn drop(&mut self) {
            for slot in self.slots.values() {
                unsafe {
                    munmap(slot.host_ptr.cast(), slot.size as usize);
                }
            }
            unsafe {
                munmap(self.run_ptr.cast(), self.run_size);
                close(self.vcpu_fd);
                close(self.vm_fd);
                close(self.kvm_fd);
            }
        }
    }

    fn reg_to_kvm_id(reg: RegisterARM64) -> Option<u64> {
        let gpr = match reg {
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
        };
        if let Some(i) = gpr {
            return Some(core_reg_u64(i * 2));
        }
        match reg {
            RegisterARM64::SP => Some(REG_SP_EL0),
            RegisterARM64::PC => Some(REG_PC),
            RegisterARM64::NZCV | RegisterARM64::PSTATE => Some(REG_PSTATE),
            RegisterARM64::TPIDR_EL0 => Some(SYS_TPIDR_EL0),
            _ => None,
        }
    }

    impl CpuBackend for KvmCpu {
        fn kind(&self) -> BackendKind {
            BackendKind::Kvm
        }

        fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64> {
            if let Some(id) = reg_to_kvm_id(reg) {
                return self.get_one_reg_u64(id);
            }
            if let Some(d) = d_reg_index(reg) {
                return Ok(self.reg_read_q(d)? as u64);
            }
            Ok(0)
        }

        fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()> {
            if let Some(id) = reg_to_kvm_id(reg) {
                return self.set_one_reg_u64(id, val);
            }
            if let Some(d) = d_reg_index(reg) {
                let cur = self.reg_read_q(d)?;
                let next = (cur & !0xFFFF_FFFF_FFFF_FFFFu128) | u128::from(val);
                return self.reg_write_q(d, next);
            }
            Ok(())
        }

        fn reg_read_q(&self, idx: u8) -> EmuResult<u128> {
            self.get_one_reg_u128(core_reg_u128(0x54 + u64::from(idx & 31) * 4))
        }

        fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()> {
            self.set_one_reg_u128(core_reg_u128(0x54 + u64::from(idx & 31) * 4), val)
        }

        fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
            let mut off = 0usize;
            while off < buf.len() {
                let cur = addr + off as u64;
                let slot = self.find_slot(cur).ok_or(EmuError::UnmappedMemory {
                    addr: cur,
                    size: buf.len() - off,
                })?;
                let slot_off = (cur - slot.guest_addr) as usize;
                let chunk = (slot.size as usize - slot_off).min(buf.len() - off);
                unsafe {
                    ptr::copy_nonoverlapping(
                        slot.host_ptr.add(slot_off),
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
                let slot = self.find_slot(cur).ok_or(EmuError::UnmappedMemory {
                    addr: cur,
                    size: data.len() - off,
                })?;
                let slot_off = (cur - slot.guest_addr) as usize;
                let chunk = (slot.size as usize - slot_off).min(data.len() - off);
                unsafe {
                    ptr::copy_nonoverlapping(
                        data.as_ptr().add(off),
                        slot.host_ptr.add(slot_off),
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
            let len = end.saturating_sub(start);
            if len == 0 {
                return Ok(());
            }
            let host_ptr = unsafe {
                mmap(
                    ptr::null_mut(),
                    len as usize,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if host_ptr == MAP_FAILED || host_ptr.is_null() {
                return Err(EmuError::Backend("KVM 宿主内存分配失败".to_string()));
            }
            let slot_id = self.next_slot;
            self.next_slot += 1;
            let region = KvmUserspaceMemoryRegion {
                slot: slot_id,
                flags: 0,
                guest_phys_addr: start,
                memory_size: len,
                userspace_addr: host_ptr as u64,
            };
            if unsafe { ioctl(self.vm_fd, KVM_SET_USER_MEMORY_REGION, &region) } < 0 {
                unsafe { munmap(host_ptr, len as usize) };
                return Err(EmuError::Backend(format!(
                    "KVM_SET_USER_MEMORY_REGION 失败: addr=0x{start:x}, size=0x{len:x}"
                )));
            }
            self.slots.insert(
                start,
                KvmSlot {
                    slot_id,
                    guest_addr: start,
                    size: len,
                    host_ptr: host_ptr as *mut u8,
                },
            );
            Ok(())
        }

        fn mem_unmap(&mut self, addr: u64, _size: u64) -> EmuResult<()> {
            let start = align_down(addr, PAGE_SIZE);
            if let Some(slot) = self.slots.remove(&start) {
                let region = KvmUserspaceMemoryRegion {
                    slot: slot.slot_id,
                    flags: 0,
                    guest_phys_addr: slot.guest_addr,
                    memory_size: 0,
                    userspace_addr: slot.host_ptr as u64,
                };
                let _ = unsafe { ioctl(self.vm_fd, KVM_SET_USER_MEMORY_REGION, &region) };
                unsafe { munmap(slot.host_ptr.cast(), slot.size as usize) };
            }
            Ok(())
        }

        fn mem_protect(&mut self, _addr: u64, _size: u64, _prot: Prot) -> EmuResult<()> {
            Ok(())
        }

        fn flush_cache(&mut self, _begin: u64, _end: u64) -> EmuResult<()> {
            Ok(())
        }

        fn run_simple(
            &mut self,
            _begin: u64,
            _until: u64,
            _timeout_us: u64,
            _count: usize,
        ) -> EmuResult<()> {
            Ok(())
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
                *slot = self.get_one_reg_u64(core_reg_u64(i as u64 * 2))?;
            }
            let mut q = [0u128; 32];
            for (i, slot) in q.iter_mut().enumerate() {
                *slot = self.reg_read_q(i as u8)?;
            }
            Ok(CpuContextBlob::Generic(Box::new(GenericCpuContext {
                x,
                sp: self.get_one_reg_u64(REG_SP_EL0)?,
                pc: self.get_one_reg_u64(REG_PC)?,
                pstate: self.get_one_reg_u64(REG_PSTATE)?,
                tpidr_el0: self.get_one_reg_u64(SYS_TPIDR_EL0)?,
                q,
                fpcr: self.get_one_reg_u64(REG_FPCR).unwrap_or(0) as u32,
                fpsr: self.get_one_reg_u64(REG_FPSR).unwrap_or(0) as u32,
            })))
        }

        fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()> {
            match ctx {
                CpuContextBlob::Generic(g) => {
                    for (i, &val) in g.x.iter().enumerate() {
                        self.set_one_reg_u64(core_reg_u64(i as u64 * 2), val)?;
                    }
                    for (i, &val) in g.q.iter().enumerate() {
                        self.reg_write_q(i as u8, val)?;
                    }
                    self.set_one_reg_u64(REG_SP_EL0, g.sp)?;
                    self.set_one_reg_u64(REG_PC, g.pc)?;
                    self.set_one_reg_u64(REG_PSTATE, g.pstate)?;
                    self.set_one_reg_u64(SYS_TPIDR_EL0, g.tpidr_el0)?;
                    let _ = self.set_one_reg_u64(REG_FPCR, u64::from(g.fpcr));
                    let _ = self.set_one_reg_u64(REG_FPSR, u64::from(g.fpsr));
                    Ok(())
                }
                CpuContextBlob::Unicorn(_) => Err(EmuError::Backend(
                    "不能将 Unicorn 快照恢复到 KVM 后端".to_string(),
                )),
            }
        }
    }

    fn d_reg_index(reg: RegisterARM64) -> Option<u8> {
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
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use imp::KvmCpu;

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
pub struct KvmCpu;

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
impl KvmCpu {
    pub fn new() -> EmuResult<Self> {
        Err(EmuError::Backend(
            "KVM 后端仅支持 Linux aarch64 宿主机（当前平台请使用 unicorn / dynarmic / hypervisor）"
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
            detail: "KVM 后端在当前宿主机不可用".to_string(),
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
impl CpuBackend for KvmCpu {
    fn kind(&self) -> BackendKind {
        BackendKind::Kvm
    }
    fn reg_read(&self, _reg: RegisterARM64) -> EmuResult<u64> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn reg_write(&mut self, _reg: RegisterARM64, _val: u64) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn reg_read_q(&self, _idx: u8) -> EmuResult<u128> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn reg_write_q(&mut self, _idx: u8, _val: u128) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn mem_read(&self, _addr: u64, _buf: &mut [u8]) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn mem_write(&mut self, _addr: u64, _data: &[u8]) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn mem_map(&mut self, _addr: u64, _size: u64, _prot: Prot) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn mem_unmap(&mut self, _addr: u64, _size: u64) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn mem_protect(&mut self, _addr: u64, _size: u64, _prot: Prot) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn flush_cache(&mut self, _begin: u64, _end: u64) -> EmuResult<()> {
        Ok(())
    }
    fn run_simple(&mut self, _: u64, _: u64, _: u64, _: usize) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn stop(&mut self) -> EmuResult<()> {
        Ok(())
    }
    fn capture_context(&self) -> EmuResult<CpuContextBlob> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
    fn restore_context(&mut self, _ctx: &CpuContextBlob) -> EmuResult<()> {
        Err(EmuError::Backend("KVM 不可用".to_string()))
    }
}
