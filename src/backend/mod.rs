//! 多执行后端统一抽象层：Unicorn（默认，支持全量 Trace / GDB / 原生 Hook）、Dynarmic（JIT 加速）、
//! KVM（Linux aarch64 硬件虚拟化）与 Hypervisor.framework（macOS Apple Silicon 硬件虚拟化）。

#[cfg(feature = "dynarmic")]
pub mod dynarmic_backend;
#[cfg(all(feature = "hypervisor", target_os = "macos"))]
pub mod hypervisor_backend;
#[cfg(all(feature = "kvm", target_os = "linux"))]
pub mod kvm_backend;
#[cfg(any(
    all(feature = "kvm", target_os = "linux"),
    all(feature = "hypervisor", target_os = "macos"),
    test
))]
pub mod vm_common;

use std::fmt;
use std::str::FromStr;

use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{Context, RegisterARM64, Unicorn};

use crate::error::{EmuError, EmuResult};

/// 统一 `SVC #imm16` 陷阱编码（供 Dynarmic / KVM / Hypervisor 共用外部调度循环）
pub const SVC_IMM_SYSCALL: u16 = 0x0000;
pub const SVC_IMM_HLE_TRAMPOLINE: u16 = 0x1001;
pub const SVC_IMM_JNI_TRAMPOLINE: u16 = 0x1002;
pub const SVC_IMM_RET_MAGIC: u16 = 0x1003;

/// 编码 ARM64 `SVC #imm16` 指令机器码（`0xD400_0001 | (imm16 << 5)`）
#[inline]
pub const fn encode_arm64_svc(imm16: u16) -> u32 {
    0xD400_0001 | ((imm16 as u32) << 5)
}

pub const ARM64_SVC_HLE_INSN: u32 = encode_arm64_svc(SVC_IMM_HLE_TRAMPOLINE);
pub const ARM64_SVC_JNI_INSN: u32 = encode_arm64_svc(SVC_IMM_JNI_TRAMPOLINE);
pub const ARM64_SVC_RET_INSN: u32 = encode_arm64_svc(SVC_IMM_RET_MAGIC);

/// 支持的 CPU 执行后端类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendKind {
    #[default]
    Unicorn,
    Dynarmic,
    Kvm,
    Hypervisor,
}

impl BackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unicorn => "unicorn",
            Self::Dynarmic => "dynarmic",
            Self::Kvm => "kvm",
            Self::Hypervisor => "hypervisor",
        }
    }

    /// 是否支持逐指令 / 内存读写 Trace Hook（仅 Unicorn 支持；其他后端仅限仿真模式）
    pub const fn supports_trace(self) -> bool {
        matches!(self, Self::Unicorn)
    }

    /// 是否支持 GDB Stub 远程单步调试（仅 Unicorn 支持；其他后端仅限仿真模式）
    pub const fn supports_gdb(self) -> bool {
        matches!(self, Self::Unicorn)
    }

    /// 是否支持原生指令/内存/Syscall Hook（仅 Unicorn 支持；其他后端仅限仿真模式）
    pub const fn supports_native_hooks(self) -> bool {
        matches!(self, Self::Unicorn)
    }

    /// 是否使用 `SVC #imm16` 跳板与统一外部陷阱循环（非 Unicorn 后端均为 true）
    pub const fn uses_svc_trampolines(self) -> bool {
        !matches!(self, Self::Unicorn)
    }

    /// 当前构建与目标平台实际编译启用的执行后端列表：
    /// - Linux 默认编译：`[Unicorn, Dynarmic, Kvm]`
    /// - macOS 默认编译：`[Unicorn, Dynarmic, Hypervisor]`
    pub const fn compiled_backends() -> &'static [Self] {
        &[
            Self::Unicorn,
            #[cfg(feature = "dynarmic")]
            Self::Dynarmic,
            #[cfg(all(feature = "kvm", target_os = "linux"))]
            Self::Kvm,
            #[cfg(all(feature = "hypervisor", target_os = "macos"))]
            Self::Hypervisor,
        ]
    }

    /// 当前构建与目标平台是否已编译该后端
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::Unicorn => true,
            Self::Dynarmic => cfg!(feature = "dynarmic"),
            Self::Kvm => cfg!(all(feature = "kvm", target_os = "linux")),
            Self::Hypervisor => cfg!(all(feature = "hypervisor", target_os = "macos")),
        }
    }

    /// 返回当前已编译后端的逗号分隔名称列表
    pub fn compiled_names() -> String {
        Self::compiled_backends()
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BackendKind {
    type Err = EmuError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "unicorn" | "uc" => Ok(Self::Unicorn),
            "dynarmic" | "jit" => Ok(Self::Dynarmic),
            "kvm" => Ok(Self::Kvm),
            "hypervisor" | "hyper" | "hvf" => Ok(Self::Hypervisor),
            other => Err(EmuError::Backend(format!(
                "未知的执行后端 `{other}`（当前平台已编译: {}）",
                Self::compiled_names()
            ))),
        }
    }
}

/// 非 Unicorn 后端单次 `run_until_trap` 退出原因
#[derive(Debug, Clone)]
pub enum RunStopReason {
    /// 命中 `SVC #imm16`（`next_pc` 为 SVC 之后下一条指令地址，`slot_addr = next_pc - 4`）
    Svc { imm: u16, next_pc: u64 },
    /// 访问未映射或无权限内存
    MemoryFault {
        pc: u64,
        addr: u64,
        is_write: bool,
        detail: String,
    },
    /// 非法指令或未处理 CPU 异常
    IllegalInstruction { pc: u64, detail: String },
    /// 执行超时或耗尽指令预算
    Timeout { pc: u64 },
    /// 主动调用 `stop()` 中止执行
    Stopped,
}

/// 跨后端通用的 ARM64 寄存器完整快照（供 Dynarmic / KVM / Hypervisor 与 `.rtape` 跨后端磁带使用）
#[derive(Debug, Clone)]
pub struct GenericCpuContext {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub tpidr_el0: u64,
    pub q: [u128; 32],
    pub fpcr: u32,
    pub fpsr: u32,
}

const GPR_REGS: [RegisterARM64; 31] = [
    RegisterARM64::X0,
    RegisterARM64::X1,
    RegisterARM64::X2,
    RegisterARM64::X3,
    RegisterARM64::X4,
    RegisterARM64::X5,
    RegisterARM64::X6,
    RegisterARM64::X7,
    RegisterARM64::X8,
    RegisterARM64::X9,
    RegisterARM64::X10,
    RegisterARM64::X11,
    RegisterARM64::X12,
    RegisterARM64::X13,
    RegisterARM64::X14,
    RegisterARM64::X15,
    RegisterARM64::X16,
    RegisterARM64::X17,
    RegisterARM64::X18,
    RegisterARM64::X19,
    RegisterARM64::X20,
    RegisterARM64::X21,
    RegisterARM64::X22,
    RegisterARM64::X23,
    RegisterARM64::X24,
    RegisterARM64::X25,
    RegisterARM64::X26,
    RegisterARM64::X27,
    RegisterARM64::X28,
    RegisterARM64::X29,
    RegisterARM64::X30,
];

/// 从任意后端（含 Unicorn）提取平台与后端无关的完整 ARM64 通用寄存器状态
pub fn capture_generic_context<B: CpuBackend + ?Sized>(cpu: &B) -> EmuResult<GenericCpuContext> {
    let mut x = [0u64; 31];
    for (slot, &reg) in x.iter_mut().zip(GPR_REGS.iter()) {
        *slot = cpu.reg_read(reg)?;
    }
    let mut q = [0u128; 32];
    for (i, slot) in q.iter_mut().enumerate() {
        *slot = cpu.reg_read_q(i as u8)?;
    }
    // 仅持久化 EL0 条件标志位 NZCV (bits 31:28)，确保跨后端可移植且不会带入特权模式/保留位
    let nzcv = cpu.reg_read(RegisterARM64::NZCV)? & 0xF000_0000;
    Ok(GenericCpuContext {
        x,
        sp: cpu.reg_read(RegisterARM64::SP)?,
        pc: cpu.reg_read(RegisterARM64::PC)?,
        pstate: nzcv,
        tpidr_el0: cpu.reg_read(RegisterARM64::TPIDR_EL0)?,
        q,
        fpcr: cpu.reg_read(RegisterARM64::FPCR)? as u32,
        fpsr: cpu.reg_read(RegisterARM64::FPSR)? as u32,
    })
}

/// 将跨后端通用寄存器状态写入任意后端（全后端统一直接写入所有寄存器含 `TPIDR_EL0` / `NZCV` / `FPCR` / `FPSR`）
pub fn restore_generic_context<B: CpuBackend + ?Sized>(
    cpu: &mut B,
    ctx: &GenericCpuContext,
) -> EmuResult<()> {
    for (&reg, &val) in GPR_REGS.iter().zip(ctx.x.iter()) {
        cpu.reg_write(reg, val)?;
    }
    for (i, &val) in ctx.q.iter().enumerate() {
        cpu.reg_write_q(i as u8, val)?;
    }
    cpu.reg_write(RegisterARM64::SP, ctx.sp)?;
    cpu.reg_write(RegisterARM64::PC, ctx.pc)?;
    cpu.reg_write(RegisterARM64::NZCV, ctx.pstate & 0xF000_0000)?;
    cpu.reg_write(RegisterARM64::FPCR, u64::from(ctx.fpcr))?;
    cpu.reg_write(RegisterARM64::FPSR, u64::from(ctx.fpsr))?;
    cpu.reg_write(RegisterARM64::TPIDR_EL0, ctx.tpidr_el0)?;
    Ok(())
}

/// CPU 上下文快照载体（Unicorn 走零拷贝原生 `Context`，其他后端走通用结构体）
pub enum CpuContextBlob {
    Unicorn(Context),
    Generic(Box<GenericCpuContext>),
}

/// 底层 ARM64 CPU 执行后端统一抽象 Trait
pub trait CpuBackend {
    fn kind(&self) -> BackendKind;

    #[inline]
    fn uses_svc_trampolines(&self) -> bool {
        self.kind().uses_svc_trampolines()
    }

    fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64>;
    fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()>;

    fn reg_read_q(&self, idx: u8) -> EmuResult<u128>;
    fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()>;

    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()>;

    fn mem_read_as_vec(&self, addr: u64, size: usize) -> EmuResult<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.mem_read(addr, &mut buf)?;
        Ok(buf)
    }

    fn mem_write(&mut self, addr: u64, data: &[u8]) -> EmuResult<()>;
    fn mem_map(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()>;
    fn mem_unmap(&mut self, addr: u64, size: u64) -> EmuResult<()>;
    fn mem_protect(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()>;
    fn flush_cache(&mut self, begin: u64, end: u64) -> EmuResult<()>;
    fn run_simple(&mut self, begin: u64, until: u64, timeout_us: u64, count: usize) -> EmuResult<()>;
    fn stop(&mut self) -> EmuResult<()>;

    fn is_stop_requested(&self) -> bool {
        false
    }

    fn capture_context(&self) -> EmuResult<CpuContextBlob>;
    fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()>;
}

/// 携带宿主机运行时状态 `D`（即 `EmuState`）的 CPU 后端 Trait
pub trait BackendWithData<D>: CpuBackend {
    fn get_data(&self) -> &D;
    fn get_data_mut(&mut self) -> &mut D;
}

fn q_reg_from_index(idx: u8) -> RegisterARM64 {
    match idx & 31 {
        0 => RegisterARM64::Q0,
        1 => RegisterARM64::Q1,
        2 => RegisterARM64::Q2,
        3 => RegisterARM64::Q3,
        4 => RegisterARM64::Q4,
        5 => RegisterARM64::Q5,
        6 => RegisterARM64::Q6,
        7 => RegisterARM64::Q7,
        8 => RegisterARM64::Q8,
        9 => RegisterARM64::Q9,
        10 => RegisterARM64::Q10,
        11 => RegisterARM64::Q11,
        12 => RegisterARM64::Q12,
        13 => RegisterARM64::Q13,
        14 => RegisterARM64::Q14,
        15 => RegisterARM64::Q15,
        16 => RegisterARM64::Q16,
        17 => RegisterARM64::Q17,
        18 => RegisterARM64::Q18,
        19 => RegisterARM64::Q19,
        20 => RegisterARM64::Q20,
        21 => RegisterARM64::Q21,
        22 => RegisterARM64::Q22,
        23 => RegisterARM64::Q23,
        24 => RegisterARM64::Q24,
        25 => RegisterARM64::Q25,
        26 => RegisterARM64::Q26,
        27 => RegisterARM64::Q27,
        28 => RegisterARM64::Q28,
        29 => RegisterARM64::Q29,
        30 => RegisterARM64::Q30,
        _ => RegisterARM64::Q31,
    }
}

impl<D> CpuBackend for Unicorn<'_, D> {
    fn kind(&self) -> BackendKind {
        BackendKind::Unicorn
    }

    fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64> {
        Ok(Unicorn::reg_read(self, reg)?)
    }

    fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()> {
        Ok(Unicorn::reg_write(self, reg, val)?)
    }

    fn reg_read_q(&self, idx: u8) -> EmuResult<u128> {
        let mut raw = [0u8; 16];
        let bytes = Unicorn::reg_read_long(self, q_reg_from_index(idx))?;
        let n = bytes.len().min(16);
        raw[..n].copy_from_slice(&bytes[..n]);
        Ok(u128::from_le_bytes(raw))
    }

    fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()> {
        let raw = val.to_le_bytes();
        Ok(Unicorn::reg_write_long(self, q_reg_from_index(idx), &raw)?)
    }

    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        Ok(Unicorn::mem_read(self, addr, buf)?)
    }

    fn mem_write(&mut self, addr: u64, data: &[u8]) -> EmuResult<()> {
        Ok(Unicorn::mem_write(self, addr, data)?)
    }

    fn mem_map(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        Ok(Unicorn::mem_map(self, addr, size, prot)?)
    }

    fn mem_unmap(&mut self, addr: u64, size: u64) -> EmuResult<()> {
        Ok(Unicorn::mem_unmap(self, addr, size)?)
    }

    fn mem_protect(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        Ok(Unicorn::mem_protect(self, addr, size, prot)?)
    }

    fn flush_cache(&mut self, begin: u64, end: u64) -> EmuResult<()> {
        if end > begin {
            let _ = Unicorn::ctl_remove_cache(self, begin, end);
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
        Ok(Unicorn::emu_start(self, begin, until, timeout_us, count)?)
    }

    fn stop(&mut self) -> EmuResult<()> {
        Ok(Unicorn::emu_stop(self)?)
    }

    fn capture_context(&self) -> EmuResult<CpuContextBlob> {
        Ok(CpuContextBlob::Unicorn(Unicorn::context_init(self)?))
    }

    fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()> {
        match ctx {
            CpuContextBlob::Unicorn(inner) => Ok(Unicorn::context_restore(self, inner)?),
            CpuContextBlob::Generic(_) => Err(EmuError::Backend(
                "不能将非 Unicorn 快照恢复到 Unicorn 后端".to_string(),
            )),
        }
    }
}

impl<D> BackendWithData<D> for Unicorn<'_, D> {
    fn get_data(&self) -> &D {
        Unicorn::get_data(self)
    }

    fn get_data_mut(&mut self) -> &mut D {
        Unicorn::get_data_mut(self)
    }
}

impl<B: CpuBackend + ?Sized> CpuBackend for &mut B {
    fn kind(&self) -> BackendKind {
        (**self).kind()
    }
    fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64> {
        (**self).reg_read(reg)
    }
    fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()> {
        (**self).reg_write(reg, val)
    }
    fn reg_read_q(&self, idx: u8) -> EmuResult<u128> {
        (**self).reg_read_q(idx)
    }
    fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()> {
        (**self).reg_write_q(idx, val)
    }
    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        (**self).mem_read(addr, buf)
    }
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> EmuResult<()> {
        (**self).mem_write(addr, data)
    }
    fn mem_map(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        (**self).mem_map(addr, size, prot)
    }
    fn mem_unmap(&mut self, addr: u64, size: u64) -> EmuResult<()> {
        (**self).mem_unmap(addr, size)
    }
    fn mem_protect(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        (**self).mem_protect(addr, size, prot)
    }
    fn flush_cache(&mut self, begin: u64, end: u64) -> EmuResult<()> {
        (**self).flush_cache(begin, end)
    }
    fn run_simple(&mut self, begin: u64, until: u64, timeout_us: u64, count: usize) -> EmuResult<()> {
        (**self).run_simple(begin, until, timeout_us, count)
    }
    fn stop(&mut self) -> EmuResult<()> {
        (**self).stop()
    }
    fn is_stop_requested(&self) -> bool {
        (**self).is_stop_requested()
    }
    fn capture_context(&self) -> EmuResult<CpuContextBlob> {
        (**self).capture_context()
    }
    fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()> {
        (**self).restore_context(ctx)
    }
}

impl<D, B: BackendWithData<D> + ?Sized> BackendWithData<D> for &mut B {
    fn get_data(&self) -> &D {
        (**self).get_data()
    }
    fn get_data_mut(&mut self) -> &mut D {
        (**self).get_data_mut()
    }
}

/// 将外部 CPU 后端（Dynarmic / KVM / Hypervisor）与宿主机状态 `D` 绑定，实现 `BackendWithData<D>`
pub struct ExternalBackend<C, D> {
    pub cpu: C,
    pub data: Box<D>,
}

impl<C: CpuBackend, D> ExternalBackend<C, D> {
    pub fn new(cpu: C, data: D) -> Self {
        Self {
            cpu,
            data: Box::new(data),
        }
    }
}

impl<C: CpuBackend, D> CpuBackend for ExternalBackend<C, D> {
    fn kind(&self) -> BackendKind {
        self.cpu.kind()
    }
    fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64> {
        self.cpu.reg_read(reg)
    }
    fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()> {
        self.cpu.reg_write(reg, val)
    }
    fn reg_read_q(&self, idx: u8) -> EmuResult<u128> {
        self.cpu.reg_read_q(idx)
    }
    fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()> {
        self.cpu.reg_write_q(idx, val)
    }
    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        self.cpu.mem_read(addr, buf)
    }
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> EmuResult<()> {
        self.cpu.mem_write(addr, data)
    }
    fn mem_map(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        self.cpu.mem_map(addr, size, prot)
    }
    fn mem_unmap(&mut self, addr: u64, size: u64) -> EmuResult<()> {
        self.cpu.mem_unmap(addr, size)
    }
    fn mem_protect(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        self.cpu.mem_protect(addr, size, prot)
    }
    fn flush_cache(&mut self, begin: u64, end: u64) -> EmuResult<()> {
        self.cpu.flush_cache(begin, end)
    }
    fn run_simple(&mut self, begin: u64, until: u64, timeout_us: u64, count: usize) -> EmuResult<()> {
        self.cpu.run_simple(begin, until, timeout_us, count)
    }
    fn stop(&mut self) -> EmuResult<()> {
        self.cpu.stop()
    }
    fn is_stop_requested(&self) -> bool {
        self.cpu.is_stop_requested()
    }
    fn capture_context(&self) -> EmuResult<CpuContextBlob> {
        self.cpu.capture_context()
    }
    fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()> {
        self.cpu.restore_context(ctx)
    }
}

impl<C: CpuBackend, D> BackendWithData<D> for ExternalBackend<C, D> {
    fn get_data(&self) -> &D {
        &self.data
    }
    fn get_data_mut(&mut self) -> &mut D {
        &mut self.data
    }
}

/// 统一多后端枚举容器（供 `AndroidEmulator` 持有，同时支持 Unicorn 与外部 SVC 陷阱后端）
pub enum CpuEngine<D: 'static> {
    Unicorn(Unicorn<'static, D>),
    #[cfg(feature = "dynarmic")]
    Dynarmic(Box<ExternalBackend<dynarmic_backend::DynarmicCpu, D>>),
    #[cfg(all(feature = "kvm", target_os = "linux"))]
    Kvm(Box<ExternalBackend<kvm_backend::KvmCpu, D>>),
    #[cfg(all(feature = "hypervisor", target_os = "macos"))]
    Hypervisor(Box<ExternalBackend<hypervisor_backend::HypervisorCpu, D>>),
}

macro_rules! dispatch_engine {
    ($self:expr, $cpu:ident => $body:expr) => {
        match $self {
            CpuEngine::Unicorn($cpu) => $body,
            #[cfg(feature = "dynarmic")]
            CpuEngine::Dynarmic($cpu) => {
                let $cpu = $cpu.as_ref();
                $body
            }
            #[cfg(all(feature = "kvm", target_os = "linux"))]
            CpuEngine::Kvm($cpu) => {
                let $cpu = $cpu.as_ref();
                $body
            }
            #[cfg(all(feature = "hypervisor", target_os = "macos"))]
            CpuEngine::Hypervisor($cpu) => {
                let $cpu = $cpu.as_ref();
                $body
            }
        }
    };
}

macro_rules! dispatch_engine_mut {
    ($self:expr, $cpu:ident => $body:expr) => {
        match $self {
            CpuEngine::Unicorn($cpu) => $body,
            #[cfg(feature = "dynarmic")]
            CpuEngine::Dynarmic($cpu) => {
                let $cpu = $cpu.as_mut();
                $body
            }
            #[cfg(all(feature = "kvm", target_os = "linux"))]
            CpuEngine::Kvm($cpu) => {
                let $cpu = $cpu.as_mut();
                $body
            }
            #[cfg(all(feature = "hypervisor", target_os = "macos"))]
            CpuEngine::Hypervisor($cpu) => {
                let $cpu = $cpu.as_mut();
                $body
            }
        }
    };
}

impl<D: 'static> CpuEngine<D> {
    #[allow(irrefutable_let_patterns)]
    pub fn as_unicorn(&self) -> Option<&Unicorn<'static, D>> {
        if let CpuEngine::Unicorn(uc) = self {
            Some(uc)
        } else {
            None
        }
    }

    #[allow(irrefutable_let_patterns)]
    pub fn as_unicorn_mut(&mut self) -> Option<&mut Unicorn<'static, D>> {
        if let CpuEngine::Unicorn(uc) = self {
            Some(uc)
        } else {
            None
        }
    }

    /// 供非 Unicorn 后端执行单步陷阱循环
    #[allow(unreachable_patterns, unused_variables)]
    pub fn run_external_step(
        &mut self,
        start_pc: u64,
        timeout_us: u64,
        max_instructions: usize,
    ) -> EmuResult<RunStopReason> {
        match self {
            CpuEngine::Unicorn(_) => Err(EmuError::Backend(
                "Unicorn 后端不通过 run_external_step 调度".to_string(),
            )),
            #[cfg(feature = "dynarmic")]
            CpuEngine::Dynarmic(ext) => {
                Ok(ext.cpu.run_until_trap(start_pc, timeout_us, max_instructions))
            }
            #[cfg(all(feature = "kvm", target_os = "linux"))]
            CpuEngine::Kvm(ext) => {
                Ok(ext.cpu.run_until_trap(start_pc, timeout_us, max_instructions))
            }
            #[cfg(all(feature = "hypervisor", target_os = "macos"))]
            CpuEngine::Hypervisor(ext) => {
                Ok(ext.cpu.run_until_trap(start_pc, timeout_us, max_instructions))
            }
        }
    }
}

impl<D: 'static> CpuBackend for CpuEngine<D> {
    fn kind(&self) -> BackendKind {
        dispatch_engine!(self, cpu => CpuBackend::kind(cpu))
    }
    fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64> {
        dispatch_engine!(self, cpu => CpuBackend::reg_read(cpu, reg))
    }
    fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::reg_write(cpu, reg, val))
    }
    fn reg_read_q(&self, idx: u8) -> EmuResult<u128> {
        dispatch_engine!(self, cpu => CpuBackend::reg_read_q(cpu, idx))
    }
    fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::reg_write_q(cpu, idx, val))
    }
    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        dispatch_engine!(self, cpu => CpuBackend::mem_read(cpu, addr, buf))
    }
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::mem_write(cpu, addr, data))
    }
    fn mem_map(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::mem_map(cpu, addr, size, prot))
    }
    fn mem_unmap(&mut self, addr: u64, size: u64) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::mem_unmap(cpu, addr, size))
    }
    fn mem_protect(&mut self, addr: u64, size: u64, prot: Prot) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::mem_protect(cpu, addr, size, prot))
    }
    fn flush_cache(&mut self, begin: u64, end: u64) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::flush_cache(cpu, begin, end))
    }
    fn run_simple(&mut self, begin: u64, until: u64, timeout_us: u64, count: usize) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::run_simple(cpu, begin, until, timeout_us, count))
    }
    fn stop(&mut self) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::stop(cpu))
    }
    fn is_stop_requested(&self) -> bool {
        dispatch_engine!(self, cpu => CpuBackend::is_stop_requested(cpu))
    }
    fn capture_context(&self) -> EmuResult<CpuContextBlob> {
        dispatch_engine!(self, cpu => CpuBackend::capture_context(cpu))
    }
    fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()> {
        dispatch_engine_mut!(self, cpu => CpuBackend::restore_context(cpu, ctx))
    }
}

impl<D: 'static> BackendWithData<D> for CpuEngine<D> {
    fn get_data(&self) -> &D {
        dispatch_engine!(self, cpu => BackendWithData::get_data(cpu))
    }
    fn get_data_mut(&mut self) -> &mut D {
        dispatch_engine_mut!(self, cpu => BackendWithData::get_data_mut(cpu))
    }
}
