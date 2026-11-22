use thiserror::Error;
use unicorn_engine::unicorn_const::uc_error;

/// 模拟器统一错误类型
#[derive(Debug, Error)]
pub enum EmuError {
    /// Unicorn 底层引擎错误
    #[error("Unicorn 引擎错误: {0:?}")]
    Unicorn(uc_error),

    /// 执行后端错误（Dynarmic / KVM / Hypervisor 或当前后端不支持的能力）
    #[error("执行后端错误: {0}")]
    Backend(String),

    /// 访问未映射内存
    #[error("访问未映射内存: addr=0x{addr:016x}, size=0x{size:x}")]
    UnmappedMemory { addr: u64, size: usize },

    /// 遇到尚未实现的 Linux/Android Syscall
    #[error("未实现的 Syscall: nr={num} at pc=0x{pc:016x}")]
    UnimplementedSyscall { num: u64, pc: u64 },

    /// 执行到非法指令
    #[error("非法指令: opcode=0x{opcode:08x} at pc=0x{pc:016x}")]
    IllegalInstruction { pc: u64, opcode: u32 },

    /// ELF 解析失败 (goblin)
    #[error("ELF 解析失败: {0}")]
    ElfParse(#[from] goblin::error::Error),

    /// ELF 格式不符合 Android ARM64 要求
    #[error("无效的 ARM64 ELF 文件: {0}")]
    InvalidElf(String),

    /// 未在导出符号表中找到目标符号
    #[error("未找到导出符号: {0}")]
    SymbolNotFound(String),

    /// 模拟堆空间耗尽
    #[error("模拟堆内存不足: requested=0x{requested:x}, available=0x{available:x}")]
    OutOfMemory { requested: u64, available: u64 },

    /// 执行超时或超出指令数预算
    #[error("执行超时或超出指令预算: pc=0x{pc:016x}, timeout_us={timeout_us}, max_instructions={max_instructions}")]
    ExecutionTimeout {
        pc: u64,
        timeout_us: u64,
        max_instructions: usize,
    },

    /// Guest 执行崩溃（附带完整 ARM64 寄存器、反汇编、调用栈与前因轨迹报告）
    #[error("{0}")]
    GuestCrash(Box<crate::crash::CrashReport>),

    /// 文件 I/O 或 mmap 落盘错误
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
}

// unicorn_engine::unicorn_const::uc_error 未必实现 std::error::Error，手动实现 From
impl From<uc_error> for EmuError {
    fn from(err: uc_error) -> Self {
        Self::Unicorn(err)
    }
}

pub type EmuResult<T> = Result<T, EmuError>;
