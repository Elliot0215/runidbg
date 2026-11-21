use std::collections::HashMap;

use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::error::EmuResult;
use crate::memory::{
    align_down, align_up, read_guest_cstr, read_guest_cstr_bytes, MemoryManager, PAGE_SIZE,
};
use crate::os::vfs::VirtualFs;

/// HLE 跳板区基址与大小（1MB，每槽 4 字节，最多容纳 262,144 个跳板入口）
pub const TRAMPOLINE_BASE: u64 = 0x1000_0000;
pub const TRAMPOLINE_SIZE: u64 = 0x0010_0000;

/// ARM64 `RET` 指令机器码（所有跳板槽位均填充此指令，Hook 执行完原生逻辑后直接返回调用方）
const ARM64_RET_INSN: u32 = 0xD65F_03C0;

/// 文件型 `mmap` 映射元数据，用于 `msync` / `munmap` 将脏页写回 `VirtualFs`
#[derive(Debug, Clone)]
struct MmapFileBacking {
    path: String,
    offset: usize,
    len: usize,
}

/// 内置高频 libc / Bionic / pthread / zlib HLE 劫持动作
#[derive(Debug, Clone)]
pub enum HleBuiltin {
    // 堆分配
    Malloc,
    Calloc,
    Realloc,
    PosixMemalign,
    Free,
    // 内存操作
    Memcpy,
    Memmove,
    Memset,
    Memcmp,
    Memchr,
    Bzero,
    // 字符串操作
    Strlen,
    Strnlen,
    Strcmp,
    Strncmp,
    Strcasecmp,
    Strncasecmp,
    Strcpy,
    Strncpy,
    Strcat,
    Strchr,
    Strrchr,
    Strstr,
    Strspn,
    Strcspn,
    Strdup,
    Strerror,
    // 格式化与转换
    Snprintf,
    SnprintfChk,
    Sprintf,
    SprintfChk,
    Asprintf,
    Vasprintf,
    Sscanf,
    Vsnprintf,
    VsnprintfChk,
    Atoi,
    Atol,
    Strtol,
    // POSIX 文件与内存映射（由 VirtualFs 支撑）
    Open,
    Close,
    Read,
    Write,
    Pread,
    Pwrite,
    Lseek,
    Fstat,
    Stat,
    Ftruncate,
    Access,
    Mkdir,
    Unlink,
    Rename,
    Mmap,
    Munmap,
    Msync,
    // Android / 系统 / zlib 杂项
    SystemPropertyGet,
    AndroidLogPrint,
    Errno,
    Getauxval,
    Getpagesize,
    Sysconf,
    Crc32,
    Arc4Random,
    Arc4RandomBuf,
    Rand,
    Getpid,
    Gettid,
    Getuid,
    Time,
    ClockGettime,
    Gettimeofday,
    LocaltimeR,
    Sleep,
    Usleep,
    Syscall,
    CxaAtexit,
    NoopZero,
    StackChkFail,
    Abort,
    Exit,
    Memalign,
    Printf,
    Fprintf,
    Ctype(&'static str),
    MathUnaryF64(&'static str),
    MathBinaryF64(&'static str),
    // Pthread 单线程安全实现
    PthreadSelf,
    PthreadOnce,
    PthreadKeyCreate,
    PthreadSetSpecific,
    PthreadGetSpecific,
    // 未实现的外部符号占位桩（触发时打印告警并返回 0，避免直接跳空指针崩溃）
    UnimplementedStub(String),
}

impl HleBuiltin {
    /// 按标准 C / Bionic 符号名匹配内置 HLE 实现
    pub fn from_symbol(name: &str) -> Option<Self> {
        match name {
            "malloc" => Some(Self::Malloc),
            "calloc" => Some(Self::Calloc),
            "realloc" => Some(Self::Realloc),
            "posix_memalign" => Some(Self::PosixMemalign),
            "free" => Some(Self::Free),
            "memcpy" | "__memcpy_chk" => Some(Self::Memcpy),
            "memmove" | "__memmove_chk" => Some(Self::Memmove),
            "memset" | "__memset_chk" => Some(Self::Memset),
            "memcmp" => Some(Self::Memcmp),
            "memchr" => Some(Self::Memchr),
            "bzero" => Some(Self::Bzero),
            "strlen" | "__strlen_chk" => Some(Self::Strlen),
            "strnlen" => Some(Self::Strnlen),
            "strcmp" => Some(Self::Strcmp),
            "strncmp" => Some(Self::Strncmp),
            "strcasecmp" => Some(Self::Strcasecmp),
            "strncasecmp" => Some(Self::Strncasecmp),
            "strcpy" | "__strcpy_chk" => Some(Self::Strcpy),
            "strncpy" | "__strncpy_chk" => Some(Self::Strncpy),
            "strcat" | "__strcat_chk" => Some(Self::Strcat),
            "strchr" | "__strchr_chk" => Some(Self::Strchr),
            "strrchr" | "__strrchr_chk" => Some(Self::Strrchr),
            "strstr" => Some(Self::Strstr),
            "strspn" => Some(Self::Strspn),
            "strcspn" => Some(Self::Strcspn),
            "strdup" => Some(Self::Strdup),
            "strerror" => Some(Self::Strerror),
            "snprintf" => Some(Self::Snprintf),
            "__snprintf_chk" => Some(Self::SnprintfChk),
            "sprintf" => Some(Self::Sprintf),
            "__sprintf_chk" => Some(Self::SprintfChk),
            "asprintf" => Some(Self::Asprintf),
            "vasprintf" => Some(Self::Vasprintf),
            "sscanf" => Some(Self::Sscanf),
            "vsnprintf" => Some(Self::Vsnprintf),
            "__vsnprintf_chk" => Some(Self::VsnprintfChk),
            "atoi" => Some(Self::Atoi),
            "atol" | "atoll" => Some(Self::Atol),
            "strtol" | "strtoul" | "strtoll" | "strtoull" => Some(Self::Strtol),
            "open" | "__open_2" => Some(Self::Open),
            "close" => Some(Self::Close),
            "read" | "__read_chk" => Some(Self::Read),
            "write" => Some(Self::Write),
            "pread" | "pread64" | "__pread_chk" | "__pread64_chk" => Some(Self::Pread),
            "pwrite" | "pwrite64" => Some(Self::Pwrite),
            "lseek" | "lseek64" => Some(Self::Lseek),
            "fstat" | "fstat64" => Some(Self::Fstat),
            "stat" | "stat64" | "lstat" | "lstat64" => Some(Self::Stat),
            "ftruncate" | "ftruncate64" => Some(Self::Ftruncate),
            "access" => Some(Self::Access),
            "mkdir" => Some(Self::Mkdir),
            "unlink" => Some(Self::Unlink),
            "rename" => Some(Self::Rename),
            "mmap" | "mmap64" => Some(Self::Mmap),
            "munmap" => Some(Self::Munmap),
            "msync" => Some(Self::Msync),
            "__system_property_get" => Some(Self::SystemPropertyGet),
            "__android_log_print" | "__android_log_write" => Some(Self::AndroidLogPrint),
            "__errno" => Some(Self::Errno),
            "getauxval" => Some(Self::Getauxval),
            "getpagesize" => Some(Self::Getpagesize),
            "sysconf" => Some(Self::Sysconf),
            "crc32" => Some(Self::Crc32),
            "arc4random" => Some(Self::Arc4Random),
            "arc4random_buf" => Some(Self::Arc4RandomBuf),
            "rand" | "random" => Some(Self::Rand),
            "getpid" => Some(Self::Getpid),
            "gettid" => Some(Self::Gettid),
            "getuid" | "geteuid" | "getgid" | "getegid" => Some(Self::Getuid),
            "time" => Some(Self::Time),
            "clock_gettime" => Some(Self::ClockGettime),
            "gettimeofday" => Some(Self::Gettimeofday),
            "localtime_r" | "gmtime_r" => Some(Self::LocaltimeR),
            "sleep" => Some(Self::Sleep),
            "usleep" => Some(Self::Usleep),
            "syscall" => Some(Self::Syscall),
            "__cxa_atexit" | "__cxa_finalize" | "atexit" => Some(Self::CxaAtexit),
            "__stack_chk_fail" => Some(Self::StackChkFail),
            "abort" => Some(Self::Abort),
            "exit" | "_exit" | "_Exit" => Some(Self::Exit),
            "memalign" | "aligned_alloc" => Some(Self::Memalign),
            "printf" => Some(Self::Printf),
            "fprintf" => Some(Self::Fprintf),
            "isalpha" => Some(Self::Ctype("isalpha")),
            "isdigit" => Some(Self::Ctype("isdigit")),
            "isalnum" => Some(Self::Ctype("isalnum")),
            "isspace" => Some(Self::Ctype("isspace")),
            "isupper" => Some(Self::Ctype("isupper")),
            "islower" => Some(Self::Ctype("islower")),
            "isxdigit" => Some(Self::Ctype("isxdigit")),
            "isprint" => Some(Self::Ctype("isprint")),
            "toupper" => Some(Self::Ctype("toupper")),
            "tolower" => Some(Self::Ctype("tolower")),
            "sin" => Some(Self::MathUnaryF64("sin")),
            "cos" => Some(Self::MathUnaryF64("cos")),
            "tan" => Some(Self::MathUnaryF64("tan")),
            "asin" => Some(Self::MathUnaryF64("asin")),
            "acos" => Some(Self::MathUnaryF64("acos")),
            "atan" => Some(Self::MathUnaryF64("atan")),
            "sinh" => Some(Self::MathUnaryF64("sinh")),
            "cosh" => Some(Self::MathUnaryF64("cosh")),
            "tanh" => Some(Self::MathUnaryF64("tanh")),
            "exp" => Some(Self::MathUnaryF64("exp")),
            "exp2" => Some(Self::MathUnaryF64("exp2")),
            "log" => Some(Self::MathUnaryF64("log")),
            "log2" => Some(Self::MathUnaryF64("log2")),
            "log10" => Some(Self::MathUnaryF64("log10")),
            "sqrt" => Some(Self::MathUnaryF64("sqrt")),
            "floor" => Some(Self::MathUnaryF64("floor")),
            "ceil" => Some(Self::MathUnaryF64("ceil")),
            "round" => Some(Self::MathUnaryF64("round")),
            "fabs" => Some(Self::MathUnaryF64("fabs")),
            "pow" => Some(Self::MathBinaryF64("pow")),
            "fmod" => Some(Self::MathBinaryF64("fmod")),
            "atan2" => Some(Self::MathBinaryF64("atan2")),
            "hypot" => Some(Self::MathBinaryF64("hypot")),
            "pthread_self" => Some(Self::PthreadSelf),
            "pthread_once" => Some(Self::PthreadOnce),
            "pthread_key_create" => Some(Self::PthreadKeyCreate),
            "pthread_setspecific" => Some(Self::PthreadSetSpecific),
            "pthread_getspecific" => Some(Self::PthreadGetSpecific),
            "flock"
            | "fcntl"
            | "ioctl"
            | "madvise"
            | "newlocale"
            | "uselocale"
            | "freelocale"
            | "mbtowc"
            | "fchown"
            | "chown"
            | "chmod"
            | "fchmod"
            | "fsync"
            | "fdatasync"
            | "getenv"
            | "srand"
            | "sigaction"
            | "sigfillset"
            | "sigemptyset"
            | "sigaddset"
            | "sigdelset"
            | "sigprocmask"
            | "signal"
            | "alarm"
            | "prctl"
            | "__system_property_find"
            | "eglGetProcAddress"
            | "android_set_abort_message"
            | "dlopen"
            | "dlsym"
            | "openlog"
            | "closelog"
            | "syslog"
            | "fflush"
            | "pthread_create"
            | "pthread_detach"
            | "pthread_join"
            | "pthread_attr_init"
            | "pthread_attr_destroy"
            | "pthread_attr_setdetachstate"
            | "pthread_attr_setstacksize"
            | "pthread_mutex_init"
            | "pthread_mutex_lock"
            | "pthread_mutex_trylock"
            | "pthread_mutex_unlock"
            | "pthread_mutex_destroy"
            | "pthread_mutexattr_init"
            | "pthread_mutexattr_settype"
            | "pthread_mutexattr_destroy"
            | "pthread_rwlock_init"
            | "pthread_rwlock_rdlock"
            | "pthread_rwlock_wrlock"
            | "pthread_rwlock_unlock"
            | "pthread_rwlock_destroy"
            | "pthread_cond_init"
            | "pthread_cond_wait"
            | "pthread_cond_timedwait"
            | "pthread_cond_signal"
            | "pthread_cond_broadcast"
            | "pthread_cond_destroy"
            | "pthread_condattr_init"
            | "pthread_condattr_setclock"
            | "pthread_condattr_getclock"
            | "pthread_condattr_destroy"
            | "pthread_key_delete" => Some(Self::NoopZero),
            _ => None,
        }
    }
}

/// HLE 跳板表：将外部符号或热点函数映射到 `TRAMPOLINE_BASE + slot * 4`
pub struct TrampolineTable {
    slots: Vec<HleBuiltin>,
    name_to_addr: HashMap<String, u64>,
    pthread_keys: HashMap<u32, u64>,
    next_pthread_key: u32,
    mmap_backings: HashMap<u64, MmapFileBacking>,
    pub errno_addr: u64,
    initialized: bool,
}

impl Default for TrampolineTable {
    fn default() -> Self {
        Self::new()
    }
}

/// `pthread_once` 回调执行跳板地址（位于 64KB 跳板区末尾，不占用符号槽位）
/// 指令序列：
/// ```asm
/// STP X29, X30, [SP, #-16]!   ; 0xA9BF7BFD
/// BLR X1                      ; 0xD63F0020 (调用 init_routine)
/// MOV X0, #0                  ; 0xD2800000 (返回 0)
/// LDP X29, X30, [SP], #16     ; 0xA8C17BFD
/// RET                         ; 0xD65F03C0
/// ```
const PTHREAD_ONCE_STUB_ADDR: u64 = TRAMPOLINE_BASE + PAGE_SIZE * 16 - 0x100;

impl TrampolineTable {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            name_to_addr: HashMap::new(),
            pthread_keys: HashMap::new(),
            next_pthread_key: 1,
            mmap_backings: HashMap::new(),
            errno_addr: crate::cpu::TLS_BASE + 0x100,
            initialized: false,
        }
    }

    /// 映射跳板区内存（初始映射 64KB，按需使用）
    pub fn init<D>(&mut self, uc: &mut Unicorn<'_, D>, mem: &mut MemoryManager) -> EmuResult<()> {
        if self.initialized {
            return Ok(());
        }
        mem.map_labeled(
            uc,
            TRAMPOLINE_BASE,
            PAGE_SIZE * 16,
            Prot::READ | Prot::EXEC,
            "[emu:hle_trampoline]",
            0,
        )?;
        let stub_insns: [u32; 5] = [
            0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
            0xD63F_0020, // blr x1
            0xD280_0000, // mov x0, #0
            0xA8C1_7BFD, // ldp x29, x30, [sp], #16
            ARM64_RET_INSN,
        ];
        for (i, insn) in stub_insns.iter().enumerate() {
            mem.write_u32(uc, PTHREAD_ONCE_STUB_ADDR + (i as u64) * 4, *insn)?;
        }
        self.initialized = true;
        Ok(())
    }

    /// 注册一个符号到跳板槽位，并向对应地址写入 ARM64 `RET` 指令
    pub fn register<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
        mem: &mut MemoryManager,
        name: &str,
        action: HleBuiltin,
    ) -> EmuResult<u64> {
        if !self.initialized {
            self.init(uc, mem)?;
        }
        if let Some(&addr) = self.name_to_addr.get(name) {
            return Ok(addr);
        }

        let slot_idx = self.slots.len() as u64;
        let addr = TRAMPOLINE_BASE + slot_idx * 4;
        mem.write_u32(uc, addr, ARM64_RET_INSN)?;
        self.slots.push(action);
        self.name_to_addr.insert(name.to_string(), addr);
        Ok(addr)
    }

    /// O(1) 按 PC 地址查找跳板动作
    #[inline]
    pub fn lookup(&self, pc: u64) -> Option<HleBuiltin> {
        if pc < TRAMPOLINE_BASE || !(pc - TRAMPOLINE_BASE).is_multiple_of(4) {
            return None;
        }
        let idx = ((pc - TRAMPOLINE_BASE) / 4) as usize;
        self.slots.get(idx).cloned()
    }

    pub fn get_addr(&self, name: &str) -> Option<u64> {
        self.name_to_addr.get(name).copied()
    }
}

/// 解析 C 风格十进制有符号整数前缀（兼容 `atoi` / `atol` / `atoll`）
fn parse_c_i64(s: &str) -> i64 {
    let bytes = s.trim_start().as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let (neg, start) = match bytes[0] {
        b'-' => (true, 1),
        b'+' => (false, 1),
        _ => (false, 0),
    };
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == start {
        return 0;
    }
    let digits = &s.trim_start()[start..end];
    let val = digits.parse::<i64>().unwrap_or(0);
    if neg {
        val.wrapping_neg()
    } else {
        val
    }
}

/// 精简版 AAPCS64 `sscanf(input, fmt, ...)`（支持 `%d/%i/%u/%ld/%lu/%lld/%llu/%x/%X/%s/%c`）
fn run_guest_sscanf<D>(uc: &mut Unicorn<'_, D>, input: &str, fmt: &str) -> i32 {
    let mut in_pos = 0usize;
    let in_bytes = input.as_bytes();
    let fmt_bytes = fmt.as_bytes();
    let mut fi = 0usize;
    let mut arg_idx = 2usize; // x2..x7, 然后栈参
    let mut matched = 0i32;

    let read_arg_ptr = |uc: &Unicorn<'_, D>, idx: usize| -> u64 {
        const REGS: [RegisterARM64; 8] = [
            RegisterARM64::X0,
            RegisterARM64::X1,
            RegisterARM64::X2,
            RegisterARM64::X3,
            RegisterARM64::X4,
            RegisterARM64::X5,
            RegisterARM64::X6,
            RegisterARM64::X7,
        ];
        if idx < 8 {
            uc.reg_read(REGS[idx]).unwrap_or(0)
        } else {
            let sp = uc.reg_read(RegisterARM64::SP).unwrap_or(0);
            let mut b = [0u8; 8];
            let _ = uc.mem_read(sp + ((idx - 8) as u64) * 8, &mut b);
            u64::from_le_bytes(b)
        }
    };

    while fi < fmt_bytes.len() {
        if fmt_bytes[fi].is_ascii_whitespace() {
            while fi < fmt_bytes.len() && fmt_bytes[fi].is_ascii_whitespace() {
                fi += 1;
            }
            while in_pos < in_bytes.len() && in_bytes[in_pos].is_ascii_whitespace() {
                in_pos += 1;
            }
            continue;
        }
        if fmt_bytes[fi] != b'%' {
            if in_pos < in_bytes.len() && in_bytes[in_pos] == fmt_bytes[fi] {
                in_pos += 1;
                fi += 1;
                continue;
            }
            break;
        }
        fi += 1;
        if fi < fmt_bytes.len() && fmt_bytes[fi] == b'%' {
            if in_pos < in_bytes.len() && in_bytes[in_pos] == b'%' {
                in_pos += 1;
                fi += 1;
                continue;
            }
            break;
        }
        let suppress = if fi < fmt_bytes.len() && fmt_bytes[fi] == b'*' {
            fi += 1;
            true
        } else {
            false
        };
        let mut width: Option<usize> = None;
        while fi < fmt_bytes.len() && fmt_bytes[fi].is_ascii_digit() {
            width = Some(width.unwrap_or(0) * 10 + (fmt_bytes[fi] - b'0') as usize);
            fi += 1;
        }
        let mut is_long = false;
        while fi < fmt_bytes.len() && matches!(fmt_bytes[fi], b'l' | b'h' | b'z') {
            if fmt_bytes[fi] == b'l' || fmt_bytes[fi] == b'z' {
                is_long = true;
            }
            fi += 1;
        }
        if fi >= fmt_bytes.len() {
            break;
        }
        let spec = fmt_bytes[fi];
        fi += 1;

        match spec {
            b'd' | b'i' | b'u' | b'x' | b'X' => {
                while in_pos < in_bytes.len() && in_bytes[in_pos].is_ascii_whitespace() {
                    in_pos += 1;
                }
                let max_end = width
                    .map(|w| in_pos.saturating_add(w).min(in_bytes.len()))
                    .unwrap_or(in_bytes.len());
                let mut neg = false;
                if in_pos < max_end && matches!(in_bytes[in_pos], b'-' | b'+') {
                    neg = in_bytes[in_pos] == b'-';
                    in_pos += 1;
                }
                let mut radix = if matches!(spec, b'x' | b'X') { 16u32 } else { 10u32 };
                if matches!(spec, b'i' | b'x' | b'X')
                    && in_pos + 1 < max_end
                    && in_bytes[in_pos] == b'0'
                    && matches!(in_bytes[in_pos + 1], b'x' | b'X')
                {
                    radix = 16;
                    in_pos += 2;
                }
                let dstart = in_pos;
                while in_pos < max_end && (in_bytes[in_pos] as char).is_digit(radix) {
                    in_pos += 1;
                }
                if in_pos == dstart {
                    break;
                }
                let raw = &input[dstart..in_pos];
                let uval = u64::from_str_radix(raw, radix).unwrap_or(0);
                let val = if neg {
                    (uval as i64).wrapping_neg() as u64
                } else {
                    uval
                };
                if !suppress {
                    let dst = read_arg_ptr(uc, arg_idx);
                    arg_idx += 1;
                    if dst != 0 {
                        if is_long {
                            let _ = uc.mem_write(dst, &val.to_le_bytes());
                        } else {
                            let _ = uc.mem_write(dst, &(val as u32).to_le_bytes());
                        }
                    }
                    matched += 1;
                }
            }
            b's' => {
                while in_pos < in_bytes.len() && in_bytes[in_pos].is_ascii_whitespace() {
                    in_pos += 1;
                }
                let max_end = width
                    .map(|w| in_pos.saturating_add(w).min(in_bytes.len()))
                    .unwrap_or(in_bytes.len());
                let start = in_pos;
                while in_pos < max_end && !in_bytes[in_pos].is_ascii_whitespace() {
                    in_pos += 1;
                }
                if in_pos == start {
                    break;
                }
                if !suppress {
                    let dst = read_arg_ptr(uc, arg_idx);
                    arg_idx += 1;
                    if dst != 0 {
                        let mut out = in_bytes[start..in_pos].to_vec();
                        out.push(0);
                        let _ = uc.mem_write(dst, &out);
                    }
                    matched += 1;
                }
            }
            b'c' => {
                let count = width.unwrap_or(1);
                if in_pos + count > in_bytes.len() {
                    break;
                }
                if !suppress {
                    let dst = read_arg_ptr(uc, arg_idx);
                    arg_idx += 1;
                    if dst != 0 {
                        let _ = uc.mem_write(dst, &in_bytes[in_pos..in_pos + count]);
                    }
                    matched += 1;
                }
                in_pos += count;
            }
            _ => break,
        }
    }
    matched
}

/// 按 AAPCS64 规则解析 `snprintf`/`sprintf` 变参格式化字符串
/// 支持 `%s`、`%d`/`%i`/`%u`、`%x`/`%X`、`%p`、`%c`、`%%` 以及宽度/零填充（如 `%02x`、`%08X`）
fn format_guest_printf<D>(uc: &Unicorn<'_, D>, fmt: &str, first_gpr_idx: usize) -> String {
    const GPRS: [RegisterARM64; 8] = [
        RegisterARM64::X0,
        RegisterARM64::X1,
        RegisterARM64::X2,
        RegisterARM64::X3,
        RegisterARM64::X4,
        RegisterARM64::X5,
        RegisterARM64::X6,
        RegisterARM64::X7,
    ];
    let sp = uc.reg_read(RegisterARM64::SP).unwrap_or(0);
    let mut gpr = first_gpr_idx;
    let mut stack_off = 0u64;

    format_guest_printf_with_reader(uc, fmt, || {
        if gpr < GPRS.len() {
            let v = uc.reg_read(GPRS[gpr]).unwrap_or(0);
            gpr += 1;
            v
        } else {
            let mut buf = [0u8; 8];
            let v = if uc.mem_read(sp + stack_off, &mut buf).is_ok() {
                u64::from_le_bytes(buf)
            } else {
                0
            };
            stack_off += 8;
            v
        }
    })
}

/// 按 AAPCS64 `va_list` 结构解析 `vsnprintf`/`__vsnprintf_chk`/`vasprintf`
/// AAPCS64 `va_list` (32B): `{ __stack: u64, __gr_top: u64, __vr_top: u64, __gr_offs: i32, __vr_offs: i32 }`
fn format_guest_vprintf<D>(uc: &Unicorn<'_, D>, fmt: &str, va_list_ptr: u64) -> String {
    if va_list_ptr == 0 {
        return fmt.to_string();
    }
    let mut raw = [0u8; 32];
    if uc.mem_read(va_list_ptr, &mut raw).is_err() {
        return fmt.to_string();
    }
    let mut stack_ptr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let gr_top = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let mut gr_offs = i32::from_le_bytes(raw[24..28].try_into().unwrap());

    format_guest_printf_with_reader(uc, fmt, || {
        let addr = if gr_offs < 0 {
            let a = (gr_top as i64).wrapping_add(gr_offs as i64) as u64;
            gr_offs = gr_offs.saturating_add(8);
            a
        } else {
            let a = stack_ptr;
            stack_ptr = stack_ptr.wrapping_add(8);
            a
        };
        let mut buf = [0u8; 8];
        if uc.mem_read(addr, &mut buf).is_ok() {
            u64::from_le_bytes(buf)
        } else {
            0
        }
    })
}

fn format_guest_printf_with_reader<D, F>(
    uc: &Unicorn<'_, D>,
    fmt: &str,
    mut next_arg: F,
) -> String
where
    F: FnMut() -> u64,
{

    let bytes = fmt.as_bytes();
    let mut out = String::with_capacity(fmt.len() + 32);
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'%' {
            out.push('%');
            i += 1;
            continue;
        }

        let mut zero_pad = false;
        let mut width: usize = 0;
        if bytes[i] == b'0' {
            zero_pad = true;
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            width = width * 10 + (bytes[i] - b'0') as usize;
            i += 1;
        }
        // 跳过精度段（如 %.4s）
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        let mut is_long = false;
        while i < bytes.len() && matches!(bytes[i], b'l' | b'h' | b'z') {
            if bytes[i] == b'l' || bytes[i] == b'z' {
                is_long = true;
            }
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let spec = bytes[i] as char;
        i += 1;
        let val = next_arg();
        let formatted = match spec {
            's' => {
                if val == 0 {
                    "(null)".to_string()
                } else {
                    read_guest_cstr(uc, val, 4096)
                }
            }
            'd' | 'i' => {
                if is_long {
                    format!("{}", val as i64)
                } else {
                    format!("{}", val as i32)
                }
            }
            'u' => {
                if is_long {
                    format!("{val}")
                } else {
                    format!("{}", val as u32)
                }
            }
            'x' => {
                if is_long {
                    format!("{val:x}")
                } else {
                    format!("{:x}", val as u32)
                }
            }
            'X' => {
                if is_long {
                    format!("{val:X}")
                } else {
                    format!("{:X}", val as u32)
                }
            }
            'p' => format!("0x{val:x}"),
            'c' => format!("{}", (val as u8) as char),
            _ => format!("%{spec}"),
        };

        if width > formatted.len() {
            let pad_ch = if zero_pad { '0' } else { ' ' };
            for _ in 0..(width - formatted.len()) {
                out.push(pad_ch);
            }
        }
        out.push_str(&formatted);
    }

    out
}

/// 挂载 HLE 跳板区 Code Hook
///
/// 当 Guest 执行 `BLR` / `BR` 跳转到 `TRAMPOLINE_BASE..TRAMPOLINE_BASE + TRAMPOLINE_SIZE` 时，
/// 在执行该槽位的 `RET` 指令前拦截并运行对应的原生 Rust 实现，将结果写入 `X0`。
pub fn attach_trampoline_hook<'a, D, F>(
    uc: &mut Unicorn<'a, D>,
    mut get_state: F,
) -> EmuResult<UcHookId>
where
    F: FnMut(&mut D) -> (&mut TrampolineTable, &mut MemoryManager, &mut VirtualFs) + 'a,
{
    let hook_id = uc.add_code_hook(
        TRAMPOLINE_BASE,
        TRAMPOLINE_BASE + TRAMPOLINE_SIZE,
        move |uc, addr, _size| {
            let action = {
                let (table, _, _) = get_state(uc.get_data_mut());
                table.lookup(addr)
            };
            let Some(builtin) = action else {
                return;
            };
            execute_hle_builtin(uc, builtin, &mut get_state);
        },
    )?;

    Ok(hook_id)
}

/// 将标准 Linux 负错误码转换为 C 库约定（设置 `*__errno() = -res` 并返回 `-1`）
#[inline]
fn c_errno_ret<D>(uc: &mut Unicorn<'_, D>, errno_addr: u64, res: i64) -> u64 {
    if res < 0 {
        let err = (-res) as i32;
        let _ = uc.mem_write(errno_addr, &err.to_le_bytes());
        u64::MAX
    } else {
        res as u64
    }
}

/// 按 Linux AArch64 ABI 填充 128 字节 `struct stat`
#[inline]
fn write_aarch64_stat<D>(uc: &mut Unicorn<'_, D>, stat_buf: u64, mode: u32, size: u64) -> bool {
    let mut st = [0u8; 128];
    st[16..20].copy_from_slice(&mode.to_le_bytes());
    st[48..56].copy_from_slice(&size.to_le_bytes());
    st[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
    st[64..72].copy_from_slice(&(size.div_ceil(512) as i64).to_le_bytes()); // st_blocks
    uc.mem_write(stat_buf, &st).is_ok()
}

/// 标准 IEEE 802.3 zlib `crc32` 计算（多项式 `0xEDB88320`）
fn zlib_crc32(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            let mask = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !c
}

/// 将 Linux `PROT_READ/WRITE/EXEC` 转换为 Unicorn `Prot`
#[inline]
fn linux_prot_to_uc(prot: u64) -> Prot {
    let mut p = Prot::NONE;
    if prot & 0x1 != 0 {
        p |= Prot::READ;
    }
    if prot & 0x2 != 0 {
        p |= Prot::WRITE;
    }
    if prot & 0x4 != 0 {
        p |= Prot::EXEC;
    }
    if p == Prot::NONE {
        Prot::READ | Prot::WRITE
    } else {
        p
    }
}

/// 执行具体的原生 Rust HLE 逻辑，并按 AAPCS64 将返回值写入 X0
fn execute_hle_builtin<D, F>(uc: &mut Unicorn<'_, D>, builtin: HleBuiltin, get_state: &mut F)
where
    F: FnMut(&mut D) -> (&mut TrampolineTable, &mut MemoryManager, &mut VirtualFs),
{
    let x0 = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
    let x1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
    let x2 = uc.reg_read(RegisterARM64::X2).unwrap_or(0);

    let ret: u64 = match builtin {
        HleBuiltin::Malloc => {
            let alloc_sz = x0.max(1);
            let raw = {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.alloc_heap(16 + alloc_sz).unwrap_or(0)
            };
            if raw != 0 {
                let _ = uc.mem_write(raw, &0x4845_4150_424C_4B31u64.to_le_bytes());
                let _ = uc.mem_write(raw + 8, &alloc_sz.to_le_bytes());
                raw + 16
            } else {
                0
            }
        }
        HleBuiltin::Calloc => {
            let total = x0.saturating_mul(x1).max(1);
            let raw = {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.alloc_heap(16 + total).unwrap_or(0)
            };
            if raw != 0 {
                let _ = uc.mem_write(raw, &0x4845_4150_424C_4B31u64.to_le_bytes());
                let _ = uc.mem_write(raw + 8, &total.to_le_bytes());
                let zeros = vec![0u8; total as usize];
                let _ = uc.mem_write(raw + 16, &zeros);
                raw + 16
            } else {
                0
            }
        }
        HleBuiltin::Realloc => {
            let old_ptr = x0;
            let new_size = x1.max(1);
            let raw = {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.alloc_heap(16 + new_size).unwrap_or(0)
            };
            if raw != 0 {
                let _ = uc.mem_write(raw, &0x4845_4150_424C_4B31u64.to_le_bytes());
                let _ = uc.mem_write(raw + 8, &new_size.to_le_bytes());
                let new_ptr = raw + 16;
                if old_ptr >= 16 {
                    let mut hdr = [0u8; 16];
                    if uc.mem_read(old_ptr - 16, &mut hdr).is_ok() {
                        let magic = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
                        let old_sz = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
                        if magic == 0x4845_4150_424C_4B31 {
                            let copy_len = old_sz.min(new_size) as usize;
                            let mut data = vec![0u8; copy_len];
                            if uc.mem_read(old_ptr, &mut data).is_ok() {
                                let _ = uc.mem_write(new_ptr, &data);
                            }
                        }
                    }
                }
                new_ptr
            } else {
                0
            }
        }
        HleBuiltin::PosixMemalign => {
            // int posix_memalign(void **memptr, size_t alignment, size_t size)
            let alignment = x1.max(16);
            let alloc_sz = x2.max(1);
            let raw = {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.alloc_heap(alignment + 16 + alloc_sz).unwrap_or(0)
            };
            if raw != 0 && x0 != 0 {
                let aligned = align_up(raw + 16, alignment);
                let _ = uc.mem_write(aligned - 16, &0x4845_4150_424C_4B31u64.to_le_bytes());
                let _ = uc.mem_write(aligned - 8, &alloc_sz.to_le_bytes());
                let _ = uc.mem_write(x0, &aligned.to_le_bytes());
                0
            } else {
                12 // ENOMEM
            }
        }
        HleBuiltin::Free => {
            if x0 != 0 {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.hle_free(x0);
            }
            0
        }
        HleBuiltin::CxaAtexit | HleBuiltin::NoopZero => 0,
        HleBuiltin::Memcpy | HleBuiltin::Memmove => {
            let len = x2 as usize;
            if len > 0 {
                let mut buf = vec![0u8; len];
                if uc.mem_read(x1, &mut buf).is_ok() {
                    let _ = uc.mem_write(x0, &buf);
                }
            }
            x0
        }
        HleBuiltin::Memset => {
            let len = x2 as usize;
            if len > 0 {
                let buf = vec![(x1 & 0xFF) as u8; len];
                let _ = uc.mem_write(x0, &buf);
            }
            x0
        }
        HleBuiltin::Bzero => {
            let len = x1 as usize;
            if len > 0 {
                let buf = vec![0u8; len];
                let _ = uc.mem_write(x0, &buf);
            }
            0
        }
        HleBuiltin::Memcmp => {
            let len = x2 as usize;
            let mut a = vec![0u8; len];
            let mut b = vec![0u8; len];
            if len > 0 && uc.mem_read(x0, &mut a).is_ok() && uc.mem_read(x1, &mut b).is_ok() {
                match a.cmp(&b) {
                    std::cmp::Ordering::Less => (-1i64) as u64,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                }
            } else {
                0
            }
        }
        HleBuiltin::Memchr => {
            let needle = (x1 & 0xFF) as u8;
            let len = (x2 as usize).min(4 * 1024 * 1024);
            let mut buf = vec![0u8; len];
            if len > 0 && uc.mem_read(x0, &mut buf).is_ok() {
                buf.iter()
                    .position(|&b| b == needle)
                    .map(|p| x0 + p as u64)
                    .unwrap_or(0)
            } else {
                0
            }
        }
        HleBuiltin::Strlen => read_guest_cstr_bytes(uc, x0, 1024 * 1024).len() as u64,
        HleBuiltin::Strnlen => {
            let max_len = (x1 as usize).min(1024 * 1024);
            read_guest_cstr_bytes(uc, x0, max_len).len() as u64
        }
        HleBuiltin::Strcmp => {
            let a = read_guest_cstr_bytes(uc, x0, 1024 * 1024);
            let b = read_guest_cstr_bytes(uc, x1, 1024 * 1024);
            match a.cmp(&b) {
                std::cmp::Ordering::Less => (-1i64) as u64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }
        }
        HleBuiltin::Strncmp => {
            let n = (x2 as usize).min(1024 * 1024);
            let a = read_guest_cstr_bytes(uc, x0, n);
            let b = read_guest_cstr_bytes(uc, x1, n);
            match a.cmp(&b) {
                std::cmp::Ordering::Less => (-1i64) as u64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }
        }
        HleBuiltin::Strcasecmp => {
            let a: Vec<u8> = read_guest_cstr_bytes(uc, x0, 1024 * 1024)
                .into_iter()
                .map(|c| c.to_ascii_lowercase())
                .collect();
            let b: Vec<u8> = read_guest_cstr_bytes(uc, x1, 1024 * 1024)
                .into_iter()
                .map(|c| c.to_ascii_lowercase())
                .collect();
            match a.cmp(&b) {
                std::cmp::Ordering::Less => (-1i64) as u64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }
        }
        HleBuiltin::Strncasecmp => {
            let n = (x2 as usize).min(1024 * 1024);
            let a: Vec<u8> = read_guest_cstr_bytes(uc, x0, n)
                .into_iter()
                .map(|c| c.to_ascii_lowercase())
                .collect();
            let b: Vec<u8> = read_guest_cstr_bytes(uc, x1, n)
                .into_iter()
                .map(|c| c.to_ascii_lowercase())
                .collect();
            match a.cmp(&b) {
                std::cmp::Ordering::Less => (-1i64) as u64,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }
        }
        HleBuiltin::Strcpy => {
            let mut src = read_guest_cstr_bytes(uc, x1, 1024 * 1024);
            src.push(0);
            let _ = uc.mem_write(x0, &src);
            x0
        }
        HleBuiltin::Strncpy => {
            let n = (x2 as usize).min(1024 * 1024);
            let src = read_guest_cstr_bytes(uc, x1, n);
            let mut dst = vec![0u8; n];
            let copy_len = src.len().min(n);
            dst[..copy_len].copy_from_slice(&src[..copy_len]);
            let _ = uc.mem_write(x0, &dst);
            x0
        }
        HleBuiltin::Strcat => {
            let dst_len = read_guest_cstr_bytes(uc, x0, 1024 * 1024).len();
            let mut src = read_guest_cstr_bytes(uc, x1, 1024 * 1024);
            src.push(0);
            let _ = uc.mem_write(x0 + dst_len as u64, &src);
            x0
        }
        HleBuiltin::Strchr => {
            let needle = (x1 & 0xFF) as u8;
            let bytes = read_guest_cstr_bytes(uc, x0, 1024 * 1024);
            if needle == 0 {
                x0 + bytes.len() as u64
            } else {
                bytes
                    .iter()
                    .position(|&b| b == needle)
                    .map(|p| x0 + p as u64)
                    .unwrap_or(0)
            }
        }
        HleBuiltin::Strrchr => {
            let needle = (x1 & 0xFF) as u8;
            let bytes = read_guest_cstr_bytes(uc, x0, 1024 * 1024);
            if needle == 0 {
                x0 + bytes.len() as u64
            } else {
                bytes
                    .iter()
                    .rposition(|&b| b == needle)
                    .map(|p| x0 + p as u64)
                    .unwrap_or(0)
            }
        }
        HleBuiltin::Strstr => {
            let hay = read_guest_cstr(uc, x0, 1024 * 1024);
            let needle = read_guest_cstr(uc, x1, 1024 * 1024);
            if needle.is_empty() {
                x0
            } else {
                hay.find(&needle).map(|p| x0 + p as u64).unwrap_or(0)
            }
        }
        HleBuiltin::Strspn => {
            let s = read_guest_cstr_bytes(uc, x0, 1024 * 1024);
            let accept = read_guest_cstr_bytes(uc, x1, 1024);
            s.iter().take_while(|b| accept.contains(b)).count() as u64
        }
        HleBuiltin::Strcspn => {
            let s = read_guest_cstr_bytes(uc, x0, 1024 * 1024);
            let reject = read_guest_cstr_bytes(uc, x1, 1024);
            s.iter().take_while(|b| !reject.contains(b)).count() as u64
        }
        HleBuiltin::Strdup => {
            let mut bytes = read_guest_cstr_bytes(uc, x0, 1024 * 1024);
            bytes.push(0);
            let raw = {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.alloc_heap(16 + bytes.len() as u64).unwrap_or(0)
            };
            if raw != 0 {
                let _ = uc.mem_write(raw, &0x4845_4150_424C_4B31u64.to_le_bytes());
                let _ = uc.mem_write(raw + 8, &(bytes.len() as u64).to_le_bytes());
                let _ = uc.mem_write(raw + 16, &bytes);
                raw + 16
            } else {
                0
            }
        }
        HleBuiltin::Snprintf => {
            // int snprintf(char *str, size_t size, const char *format, ...)
            let max_sz = x1 as usize;
            let fmt = read_guest_cstr(uc, x2, 4096);
            let formatted = format_guest_printf(uc, &fmt, 3);
            if max_sz > 0 && x0 != 0 {
                let bytes = formatted.as_bytes();
                let copy_len = bytes.len().min(max_sz - 1);
                let mut out = Vec::with_capacity(copy_len + 1);
                out.extend_from_slice(&bytes[..copy_len]);
                out.push(0);
                let _ = uc.mem_write(x0, &out);
            }
            formatted.len() as u64
        }
        HleBuiltin::SnprintfChk => {
            // int __snprintf_chk(char *dst, size_t size, int flags, size_t destlen, const char *fmt, ...)
            let max_sz = x1 as usize;
            let fmt_ptr = uc.reg_read(RegisterARM64::X4).unwrap_or(0);
            let fmt = read_guest_cstr(uc, fmt_ptr, 4096);
            let formatted = format_guest_printf(uc, &fmt, 5);
            if max_sz > 0 && x0 != 0 {
                let bytes = formatted.as_bytes();
                let copy_len = bytes.len().min(max_sz - 1);
                let mut out = Vec::with_capacity(copy_len + 1);
                out.extend_from_slice(&bytes[..copy_len]);
                out.push(0);
                let _ = uc.mem_write(x0, &out);
            }
            formatted.len() as u64
        }
        HleBuiltin::Sprintf => {
            // int sprintf(char *str, const char *format, ...)
            let fmt = read_guest_cstr(uc, x1, 4096);
            let formatted = format_guest_printf(uc, &fmt, 2);
            if x0 != 0 {
                let mut out = formatted.as_bytes().to_vec();
                out.push(0);
                let _ = uc.mem_write(x0, &out);
            }
            formatted.len() as u64
        }
        HleBuiltin::SprintfChk => {
            // int __sprintf_chk(char *dst, int flags, size_t destlen, const char *fmt, ...)
            let fmt_ptr = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
            let fmt = read_guest_cstr(uc, fmt_ptr, 4096);
            let formatted = format_guest_printf(uc, &fmt, 4);
            if x0 != 0 {
                let mut out = formatted.as_bytes().to_vec();
                out.push(0);
                let _ = uc.mem_write(x0, &out);
            }
            formatted.len() as u64
        }
        HleBuiltin::Asprintf => {
            // int asprintf(char **strp, const char *format, ...)
            let fmt = read_guest_cstr(uc, x1, 4096);
            let formatted = format_guest_printf(uc, &fmt, 2);
            let mut out = formatted.as_bytes().to_vec();
            out.push(0);
            let ptr = {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.alloc_heap(out.len() as u64).unwrap_or(0)
            };
            if ptr != 0 {
                let _ = uc.mem_write(ptr, &out);
                if x0 != 0 {
                    let _ = uc.mem_write(x0, &ptr.to_le_bytes());
                }
                formatted.len() as u64
            } else {
                (-1i64) as u64
            }
        }
        HleBuiltin::Vasprintf => {
            // int vasprintf(char **strp, const char *format, va_list ap)
            let fmt = read_guest_cstr(uc, x1, 4096);
            let formatted = format_guest_vprintf(uc, &fmt, x2);
            let mut out = formatted.as_bytes().to_vec();
            out.push(0);
            let ptr = {
                let (_, mem, _) = get_state(uc.get_data_mut());
                mem.alloc_heap(out.len() as u64).unwrap_or(0)
            };
            if ptr != 0 {
                let _ = uc.mem_write(ptr, &out);
                if x0 != 0 {
                    let _ = uc.mem_write(x0, &ptr.to_le_bytes());
                }
                formatted.len() as u64
            } else {
                (-1i64) as u64
            }
        }
        HleBuiltin::Vsnprintf => {
            // int vsnprintf(char *str, size_t size, const char *fmt, va_list ap)
            let max_sz = x1 as usize;
            let fmt = read_guest_cstr(uc, x2, 4096);
            let ap_ptr = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
            let formatted = format_guest_vprintf(uc, &fmt, ap_ptr);
            if max_sz > 0 && x0 != 0 {
                let bytes = formatted.as_bytes();
                let copy_len = bytes.len().min(max_sz - 1);
                let mut out = Vec::with_capacity(copy_len + 1);
                out.extend_from_slice(&bytes[..copy_len]);
                out.push(0);
                let _ = uc.mem_write(x0, &out);
            }
            formatted.len() as u64
        }
        HleBuiltin::VsnprintfChk => {
            // int __vsnprintf_chk(char *dst, size_t size, int flags, size_t destlen, const char *fmt, va_list ap)
            let max_sz = x1 as usize;
            let fmt_ptr = uc.reg_read(RegisterARM64::X4).unwrap_or(0);
            let ap_ptr = uc.reg_read(RegisterARM64::X5).unwrap_or(0);
            let fmt = read_guest_cstr(uc, fmt_ptr, 4096);
            let formatted = format_guest_vprintf(uc, &fmt, ap_ptr);
            if max_sz > 0 && x0 != 0 {
                let bytes = formatted.as_bytes();
                let copy_len = bytes.len().min(max_sz - 1);
                let mut out = Vec::with_capacity(copy_len + 1);
                out.extend_from_slice(&bytes[..copy_len]);
                out.push(0);
                let _ = uc.mem_write(x0, &out);
            }
            formatted.len() as u64
        }
        HleBuiltin::Strerror => {
            let msg_addr = {
                let (table, _, _) = get_state(uc.get_data_mut());
                table.errno_addr + 8
            };
            let msg = format!("errno {}\0", x0 as i32);
            let _ = uc.mem_write(msg_addr, msg.as_bytes());
            msg_addr
        }
        HleBuiltin::Open => {
            // int open(const char *path, int flags, mode_t mode) / __open_2(path, flags)
            let path = read_guest_cstr(uc, x0, 512);
            let (errno_addr, res) = {
                let (table, mem, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.open_with_flags(&path, x1 as u32, mem))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Close => {
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.close(x0 as i32))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Read => {
            // ssize_t read(int fd, void *buf, size_t count)
            let count = (x2 as usize).min(16 * 1024 * 1024);
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.read(x0 as i32, count))
            };
            match res {
                Ok(data) => {
                    if !data.is_empty() && x1 != 0 {
                        let _ = uc.mem_write(x1, &data);
                    }
                    data.len() as u64
                }
                Err(e) => c_errno_ret(uc, errno_addr, e),
            }
        }
        HleBuiltin::Write => {
            // ssize_t write(int fd, const void *buf, size_t count)
            let count = (x2 as usize).min(16 * 1024 * 1024);
            let mut buf = vec![0u8; count];
            if count > 0 && x1 != 0 {
                let _ = uc.mem_read(x1, &mut buf);
            }
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.write(x0 as i32, &buf))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Pread => {
            // ssize_t pread(int fd, void *buf, size_t count, off_t offset)
            let count = (x2 as usize).min(16 * 1024 * 1024);
            let offset = uc.reg_read(RegisterARM64::X3).unwrap_or(0) as usize;
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.read_at(x0 as i32, offset, count))
            };
            match res {
                Some(data) => {
                    if !data.is_empty() && x1 != 0 {
                        let _ = uc.mem_write(x1, &data);
                    }
                    data.len() as u64
                }
                None => c_errno_ret(uc, errno_addr, crate::os::vfs::EBADF),
            }
        }
        HleBuiltin::Pwrite => {
            // ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
            let count = (x2 as usize).min(16 * 1024 * 1024);
            let offset = uc.reg_read(RegisterARM64::X3).unwrap_or(0) as usize;
            let mut buf = vec![0u8; count];
            if count > 0 && x1 != 0 {
                let _ = uc.mem_read(x1, &mut buf);
            }
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.write_at(x0 as i32, offset, &buf))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Lseek => {
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.lseek(x0 as i32, x1 as i64, x2 as i32))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Fstat => {
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.fstat_fd(x0 as i32))
            };
            match res {
                Ok((mode, size)) => {
                    if x1 != 0 && write_aarch64_stat(uc, x1, mode, size) {
                        0
                    } else {
                        c_errno_ret(uc, errno_addr, crate::os::vfs::EINVAL)
                    }
                }
                Err(e) => c_errno_ret(uc, errno_addr, e),
            }
        }
        HleBuiltin::Stat => {
            let path = read_guest_cstr(uc, x0, 512);
            let (errno_addr, res) = {
                let (table, mem, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.stat_path(&path, mem))
            };
            match res {
                Ok((mode, size)) => {
                    if x1 != 0 && write_aarch64_stat(uc, x1, mode, size) {
                        0
                    } else {
                        c_errno_ret(uc, errno_addr, crate::os::vfs::EINVAL)
                    }
                }
                Err(e) => c_errno_ret(uc, errno_addr, e),
            }
        }
        HleBuiltin::Ftruncate => {
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.ftruncate(x0 as i32, x1))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Access => {
            let path = read_guest_cstr(uc, x0, 512);
            let (errno_addr, res) = {
                let (table, mem, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.access(&path, mem))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Mkdir => {
            let path = read_guest_cstr(uc, x0, 512);
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.mkdir(&path))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Unlink => {
            let path = read_guest_cstr(uc, x0, 512);
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.unlink(&path))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Rename => {
            let old_path = read_guest_cstr(uc, x0, 512);
            let new_path = read_guest_cstr(uc, x1, 512);
            let (errno_addr, res) = {
                let (table, _, vfs) = get_state(uc.get_data_mut());
                (table.errno_addr, vfs.rename(&old_path, &new_path))
            };
            c_errno_ret(uc, errno_addr, res)
        }
        HleBuiltin::Mmap => {
            // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
            let hint = x0;
            let len = x1;
            let perms = linux_prot_to_uc(x2);
            let fd = uc.reg_read(RegisterARM64::X4).unwrap_or(u64::MAX) as i32;
            let offset = uc.reg_read(RegisterARM64::X5).unwrap_or(0) as usize;

            let aligned_len = align_up(len.max(PAGE_SIZE), PAGE_SIZE);
            let file_path = if fd >= 0 {
                let (_, _, vfs) = get_state(uc.get_data_mut());
                vfs.fd_path(fd).map(str::to_string)
            } else {
                None
            };

            // MAP_SHARED 一致性：若该文件已有活跃 mmap 映射，先将其脏页刷回 VFS 再读取
            if let Some(ref target_path) = file_path {
                let existing: Vec<(u64, MmapFileBacking)> = {
                    let (table, _, _) = get_state(uc.get_data_mut());
                    table
                        .mmap_backings
                        .iter()
                        .filter(|(_, b)| b.path == *target_path)
                        .map(|(&a, b)| (a, b.clone()))
                        .collect()
                };
                for (old_addr, b) in existing {
                    let mut buf = vec![0u8; b.len];
                    if b.len > 0 && uc.mem_read(old_addr, &mut buf).is_ok() {
                        let (_, _, vfs) = get_state(uc.get_data_mut());
                        vfs.write_at_path(&b.path, b.offset, &buf);
                    }
                }
            }

            let file_bytes = if fd >= 0 {
                let (_, _, vfs) = get_state(uc.get_data_mut());
                vfs.read_at(fd, offset, len as usize)
            } else {
                None
            };

            let flags = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
            let map_fixed = (flags & 0x10) != 0;
            let req_hint = if map_fixed && hint != 0 { hint } else { 0 };

            let label = file_path
                .as_deref()
                .map(|p| format!("[mmap:{p}]"))
                .unwrap_or_else(|| "[anon:hle_mmap]".to_string());

            let mapped_addr = {
                let mut tmp_mem =
                    std::mem::replace(get_state(uc.get_data_mut()).1, MemoryManager::new(0, 0));
                let res = tmp_mem.mmap(uc, req_hint, aligned_len, perms, label, offset as u64);
                *get_state(uc.get_data_mut()).1 = tmp_mem;
                res.ok()
            };

            if let Some(addr) = mapped_addr {
                if let Some(bytes) = file_bytes {
                    if !bytes.is_empty() {
                        let _ = uc.mem_write(addr, &bytes);
                    }
                }
                if let Some(path) = file_path {
                    let (table, _, _) = get_state(uc.get_data_mut());
                    table.mmap_backings.insert(
                        addr,
                        MmapFileBacking {
                            path,
                            offset,
                            len: len as usize,
                        },
                    );
                }
                addr
            } else {
                u64::MAX // MAP_FAILED
            }
        }
        HleBuiltin::Msync => {
            // int msync(void *addr, size_t length, int flags)
            let backing = {
                let (table, _, _) = get_state(uc.get_data_mut());
                table.mmap_backings.get(&x0).cloned()
            };
            if let Some(b) = backing {
                let sync_len = (x1 as usize).min(b.len);
                let mut buf = vec![0u8; sync_len];
                if sync_len > 0 && uc.mem_read(x0, &mut buf).is_ok() {
                    let (_, _, vfs) = get_state(uc.get_data_mut());
                    vfs.write_at_path(&b.path, b.offset, &buf);
                }
            }
            0
        }
        HleBuiltin::Munmap => {
            // int munmap(void *addr, size_t length)
            let backing = {
                let (table, _, _) = get_state(uc.get_data_mut());
                table.mmap_backings.remove(&x0)
            };
            if let Some(b) = backing {
                let mut buf = vec![0u8; b.len];
                if b.len > 0 && uc.mem_read(x0, &mut buf).is_ok() {
                    let (_, _, vfs) = get_state(uc.get_data_mut());
                    vfs.write_at_path(&b.path, b.offset, &buf);
                }
            }
            let aligned_len = align_up(x1.max(PAGE_SIZE), PAGE_SIZE);
            let mut tmp_mem =
                std::mem::replace(get_state(uc.get_data_mut()).1, MemoryManager::new(0, 0));
            let _ = tmp_mem.munmap(uc, align_down(x0, PAGE_SIZE), aligned_len);
            *get_state(uc.get_data_mut()).1 = tmp_mem;
            0
        }
        HleBuiltin::Atoi => {
            let s = read_guest_cstr(uc, x0, 64);
            parse_c_i64(&s) as i32 as i64 as u64
        }
        HleBuiltin::Atol => {
            let s = read_guest_cstr(uc, x0, 128);
            parse_c_i64(&s) as u64
        }
        HleBuiltin::Sscanf => {
            // int sscanf(const char *str, const char *format, ...)
            let input = read_guest_cstr(uc, x0, 4096);
            let fmt = read_guest_cstr(uc, x1, 1024);
            run_guest_sscanf(uc, &input, &fmt) as u64
        }
        HleBuiltin::Strtol => {
            let s = read_guest_cstr(uc, x0, 128);
            let base = (x2 as u32).clamp(0, 36);
            let trimmed = s.trim();
            let parsed = if base == 0 {
                if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))
                {
                    i64::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    trimmed.parse::<i64>().unwrap_or(0)
                }
            } else {
                i64::from_str_radix(trimmed.trim_start_matches("0x"), base).unwrap_or(0)
            };
            if x1 != 0 {
                let end_ptr = x0 + s.len() as u64;
                let _ = uc.mem_write(x1, &end_ptr.to_le_bytes());
            }
            parsed as u64
        }
        HleBuiltin::SystemPropertyGet => {
            let key = read_guest_cstr(uc, x0, 256);
            let val = {
                let (_, _, vfs) = get_state(uc.get_data_mut());
                vfs.get_property(&key).unwrap_or("").to_string()
            };
            let mut bytes = val.as_bytes().to_vec();
            bytes.push(0);
            let _ = uc.mem_write(x1, &bytes);
            val.len() as u64
        }
        HleBuiltin::AndroidLogPrint => {
            let tag = read_guest_cstr(uc, x1, 128);
            let fmt = read_guest_cstr(uc, x2, 512);
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.breadcrumbs()
                .push(format!("[android_log/{tag}] {fmt}"));
            tracing::info!(target: "runidbg::hle", tag = %tag, "{fmt}");
            fmt.len() as u64
        }
        HleBuiltin::Errno => {
            let (table, _, _) = get_state(uc.get_data_mut());
            table.errno_addr
        }
        HleBuiltin::Getauxval => match x0 {
            6 => PAGE_SIZE, // AT_PAGESZ
            16 | 26 => 0,   // AT_HWCAP / AT_HWCAP2（关闭可选硬件扩展以走纯兼容路径）
            _ => 0,
        },
        HleBuiltin::Getpagesize => PAGE_SIZE,
        HleBuiltin::Sysconf => match x0 as i32 {
            39 | 40 => PAGE_SIZE, // Bionic _SC_PAGESIZE / _SC_PAGE_SIZE
            96 | 97 => 4,         // Bionic _SC_NPROCESSORS_CONF / _SC_NPROCESSORS_ONLN
            _ => 0,
        },
        HleBuiltin::Crc32 => {
            // uLong crc32(uLong crc, const Bytef *buf, uInt len)
            if x1 == 0 {
                0
            } else {
                let len = (x2 as usize).min(16 * 1024 * 1024);
                let mut buf = vec![0u8; len];
                if len > 0 && uc.mem_read(x1, &mut buf).is_ok() {
                    zlib_crc32(x0 as u32, &buf) as u64
                } else {
                    x0 as u32 as u64
                }
            }
        }
        HleBuiltin::Arc4Random => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            let mut b = [0u8; 4];
            vfs.fill_random(&mut b);
            u32::from_le_bytes(b) as u64
        }
        HleBuiltin::Rand => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            let mut b = [0u8; 4];
            vfs.fill_random(&mut b);
            (u32::from_le_bytes(b) & 0x7FFF_FFFF) as u64
        }
        HleBuiltin::Arc4RandomBuf => {
            let len = (x1 as usize).min(1024 * 1024);
            let mut buf = vec![0u8; len];
            {
                let (_, _, vfs) = get_state(uc.get_data_mut());
                vfs.fill_random(&mut buf);
            }
            if x0 != 0 && !buf.is_empty() {
                let _ = uc.mem_write(x0, &buf);
            }
            0
        }
        HleBuiltin::Getpid => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.pid as u64
        }
        HleBuiltin::Gettid | HleBuiltin::PthreadSelf => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.tid as u64
        }
        HleBuiltin::Getuid => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.uid as u64
        }
        HleBuiltin::Time => {
            let sec = {
                let (_, _, vfs) = get_state(uc.get_data_mut());
                vfs.current_clock_ns() / 1_000_000_000
            };
            if x0 != 0 {
                let _ = uc.mem_write(x0, &(sec as i64).to_le_bytes());
            }
            sec
        }
        HleBuiltin::ClockGettime => {
            // int clock_gettime(clockid_t clk_id, struct timespec *tp)
            let ns = {
                let (_, _, vfs) = get_state(uc.get_data_mut());
                vfs.current_clock_ns()
            };
            if x1 != 0 {
                let sec = (ns / 1_000_000_000) as i64;
                let nsec = (ns % 1_000_000_000) as i64;
                let mut buf = [0u8; 16];
                buf[0..8].copy_from_slice(&sec.to_le_bytes());
                buf[8..16].copy_from_slice(&nsec.to_le_bytes());
                let _ = uc.mem_write(x1, &buf);
            }
            0
        }
        HleBuiltin::Gettimeofday => {
            // int gettimeofday(struct timeval *tv, struct timezone *tz)
            let ns = {
                let (_, _, vfs) = get_state(uc.get_data_mut());
                vfs.current_clock_ns()
            };
            if x0 != 0 {
                let sec = (ns / 1_000_000_000) as i64;
                let usec = ((ns % 1_000_000_000) / 1_000) as i64;
                let mut buf = [0u8; 16];
                buf[0..8].copy_from_slice(&sec.to_le_bytes());
                buf[8..16].copy_from_slice(&usec.to_le_bytes());
                let _ = uc.mem_write(x0, &buf);
            }
            if x1 != 0 {
                let _ = uc.mem_write(x1, &[0u8; 8]);
            }
            0
        }
        HleBuiltin::LocaltimeR => {
            // struct tm *localtime_r(const time_t *timep, struct tm *result)
            // Linux AArch64 struct tm (56 bytes): 9 x i32 + 4B pad + i64 tm_gmtoff + u64 tm_zone
            if x1 != 0 {
                let mut t_bytes = [0u8; 8];
                let ts = if x0 != 0 && uc.mem_read(x0, &mut t_bytes).is_ok() {
                    i64::from_le_bytes(t_bytes).max(0)
                } else {
                    1_700_000_000
                };
                let sec = (ts % 60) as i32;
                let min = ((ts / 60) % 60) as i32;
                let hour = ((ts / 3600) % 24) as i32;
                let days = (ts / 86400) as i32;
                let year = 70 + (days / 365);
                let yday = days % 365;
                let mon = (yday / 30).min(11);
                let mday = (yday % 30) + 1;
                let wday = (days + 4) % 7;
                let mut tm = [0u8; 56];
                tm[0..4].copy_from_slice(&sec.to_le_bytes());
                tm[4..8].copy_from_slice(&min.to_le_bytes());
                tm[8..12].copy_from_slice(&hour.to_le_bytes());
                tm[12..16].copy_from_slice(&mday.to_le_bytes());
                tm[16..20].copy_from_slice(&mon.to_le_bytes());
                tm[20..24].copy_from_slice(&year.to_le_bytes());
                tm[24..28].copy_from_slice(&wday.to_le_bytes());
                tm[28..32].copy_from_slice(&yday.to_le_bytes());
                let _ = uc.mem_write(x1, &tm);
            }
            x1
        }
        HleBuiltin::Sleep => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.mono_clock_ns = vfs
                .mono_clock_ns
                .saturating_add(x0.saturating_mul(1_000_000_000));
            0
        }
        HleBuiltin::Usleep => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.mono_clock_ns = vfs.mono_clock_ns.saturating_add(x0.saturating_mul(1_000));
            0
        }
        HleBuiltin::Syscall => {
            // long syscall(long number, ...)
            match x0 {
                172 => {
                    let (_, _, vfs) = get_state(uc.get_data_mut());
                    vfs.pid as u64
                }
                178 => {
                    let (_, _, vfs) = get_state(uc.get_data_mut());
                    vfs.tid as u64
                }
                278 => {
                    // SYS_getrandom(buf, buflen, flags)
                    let len = (x2 as usize).min(1024 * 1024);
                    let mut buf = vec![0u8; len];
                    {
                        let (_, _, vfs) = get_state(uc.get_data_mut());
                        vfs.fill_random(&mut buf);
                    }
                    if x1 != 0 && !buf.is_empty() {
                        let _ = uc.mem_write(x1, &buf);
                    }
                    len as u64
                }
                _ => 0,
            }
        }
        HleBuiltin::StackChkFail => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.breadcrumbs().push("[HLE WARN] __stack_chk_fail");
            tracing::warn!(target: "runidbg::hle", "触发 __stack_chk_fail (已拦截并安全返回)");
            0
        }
        HleBuiltin::Abort => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.breadcrumbs().push("[HLE FATAL] abort()");
            tracing::error!(target: "runidbg::hle", "Guest 调用 abort()，终止仿真");
            let _ = uc.emu_stop();
            0
        }
        HleBuiltin::Exit => {
            let _ = uc.emu_stop();
            x0
        }
        HleBuiltin::Memalign => {
            // void *memalign(size_t alignment, size_t size)
            let align = x0.max(16);
            let size = x1.max(1);
            let (_, mem, _) = get_state(uc.get_data_mut());
            let raw = mem.alloc_heap(size + align).unwrap_or(0);
            if raw == 0 {
                0
            } else {
                align_up(raw, align)
            }
        }
        HleBuiltin::Printf => {
            let fmt = read_guest_cstr(uc, x0, 512);
            fmt.len() as u64
        }
        HleBuiltin::Fprintf => {
            let fmt = read_guest_cstr(uc, x1, 512);
            fmt.len() as u64
        }
        HleBuiltin::Ctype(op) => {
            let c = (x0 & 0xFF) as u8;
            match op {
                "isalpha" => u64::from(c.is_ascii_alphabetic()),
                "isdigit" => u64::from(c.is_ascii_digit()),
                "isalnum" => u64::from(c.is_ascii_alphanumeric()),
                "isspace" => u64::from(c.is_ascii_whitespace()),
                "isupper" => u64::from(c.is_ascii_uppercase()),
                "islower" => u64::from(c.is_ascii_lowercase()),
                "isxdigit" => u64::from(c.is_ascii_hexdigit()),
                "isprint" => u64::from(c.is_ascii_graphic() || c == b' '),
                "toupper" => c.to_ascii_uppercase() as u64,
                "tolower" => c.to_ascii_lowercase() as u64,
                _ => 0,
            }
        }
        HleBuiltin::MathUnaryF64(op) => {
            let v = f64::from_bits(uc.reg_read(RegisterARM64::D0).unwrap_or(0));
            let res = match op {
                "sin" => v.sin(),
                "cos" => v.cos(),
                "tan" => v.tan(),
                "asin" => v.asin(),
                "acos" => v.acos(),
                "atan" => v.atan(),
                "sinh" => v.sinh(),
                "cosh" => v.cosh(),
                "tanh" => v.tanh(),
                "exp" => v.exp(),
                "exp2" => v.exp2(),
                "log" => v.ln(),
                "log2" => v.log2(),
                "log10" => v.log10(),
                "sqrt" => v.sqrt(),
                "floor" => v.floor(),
                "ceil" => v.ceil(),
                "round" => v.round(),
                "fabs" => v.abs(),
                _ => 0.0,
            };
            let _ = uc.reg_write(RegisterARM64::D0, res.to_bits());
            0
        }
        HleBuiltin::MathBinaryF64(op) => {
            let a = f64::from_bits(uc.reg_read(RegisterARM64::D0).unwrap_or(0));
            let b = f64::from_bits(uc.reg_read(RegisterARM64::D1).unwrap_or(0));
            let res = match op {
                "pow" => a.powf(b),
                "fmod" => a % b,
                "atan2" => a.atan2(b),
                "hypot" => a.hypot(b),
                _ => 0.0,
            };
            let _ = uc.reg_write(RegisterARM64::D0, res.to_bits());
            0
        }
        HleBuiltin::PthreadOnce => {
            // int pthread_once(pthread_once_t *once_control, void (*init_routine)(void))
            let mut cur = [0u8; 4];
            if x0 != 0
                && x1 != 0
                && uc.mem_read(x0, &mut cur).is_ok()
                && u32::from_le_bytes(cur) == 0
            {
                let _ = uc.mem_write(x0, &1u32.to_le_bytes());
                let _ = uc.reg_write(RegisterARM64::PC, PTHREAD_ONCE_STUB_ADDR);
                return;
            }
            0
        }
        HleBuiltin::PthreadKeyCreate => {
            let key = {
                let (table, _, _) = get_state(uc.get_data_mut());
                let k = table.next_pthread_key;
                table.next_pthread_key += 1;
                table.pthread_keys.insert(k, 0);
                k
            };
            if x0 != 0 {
                let _ = uc.mem_write(x0, &key.to_le_bytes());
            }
            0
        }
        HleBuiltin::PthreadSetSpecific => {
            let (table, _, _) = get_state(uc.get_data_mut());
            table.pthread_keys.insert(x0 as u32, x1);
            0
        }
        HleBuiltin::PthreadGetSpecific => {
            let (table, _, _) = get_state(uc.get_data_mut());
            table.pthread_keys.get(&(x0 as u32)).copied().unwrap_or(0)
        }
        HleBuiltin::UnimplementedStub(sym) => {
            let (_, _, vfs) = get_state(uc.get_data_mut());
            vfs.breadcrumbs()
                .push(format!("[HLE UNIMPL] {sym}(x0=0x{x0:x}, x1=0x{x1:x}) -> 0"));
            tracing::warn!(
                target: "runidbg::hle",
                symbol = %sym,
                x0 = format_args!("0x{x0:x}"),
                x1 = format_args!("0x{x1:x}"),
                "调用未实现的外部符号"
            );
            0
        }
    };

    let _ = uc.reg_write(RegisterARM64::X0, ret);
}
