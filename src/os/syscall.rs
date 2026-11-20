use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::error::EmuResult;
use crate::memory::{read_guest_cstr as read_guest_c_string, MemoryManager};
use crate::os::vfs::{VirtualFs, EBADF, EINVAL, ENOSYS};

/// ARM64 Unicorn SVC #0 中断号 (`EXCP_SWI`)
pub const ARM64_EXCP_SWI: u32 = 2;

/// Linux AArch64 常用系统调用号 (asm-generic/unistd.h)
pub const SYS_IOCTL: u64 = 29;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_LSEEK: u64 = 62;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_READLINKAT: u64 = 78;
pub const SYS_NEWFSTATAT: u64 = 79;
pub const SYS_FSTAT: u64 = 80;
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const SYS_SET_TID_ADDRESS: u64 = 96;
pub const SYS_FUTEX: u64 = 98;
pub const SYS_NANOSLEEP: u64 = 101;
pub const SYS_CLOCK_GETTIME: u64 = 113;
pub const SYS_PTRACE: u64 = 117;
pub const SYS_SCHED_YIELD: u64 = 124;
pub const SYS_TKILL: u64 = 130;
pub const SYS_TGKILL: u64 = 131;
pub const SYS_RT_SIGACTION: u64 = 134;
pub const SYS_RT_SIGPROCMASK: u64 = 135;
pub const SYS_UNAME: u64 = 160;
pub const SYS_PRCTL: u64 = 167;
pub const SYS_GETTIMEOFDAY: u64 = 169;
pub const SYS_GETPID: u64 = 172;
pub const SYS_GETPPID: u64 = 173;
pub const SYS_GETUID: u64 = 174;
pub const SYS_GETEUID: u64 = 175;
pub const SYS_GETGID: u64 = 176;
pub const SYS_GETEGID: u64 = 177;
pub const SYS_GETTID: u64 = 178;
pub const SYS_BRK: u64 = 214;
pub const SYS_MUNMAP: u64 = 215;
pub const SYS_MMAP: u64 = 222;
pub const SYS_MPROTECT: u64 = 226;
pub const SYS_MADVISE: u64 = 233;
pub const SYS_PRLIMIT64: u64 = 261;
pub const SYS_GETRANDOM: u64 = 278;

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
    p
}

/// 挂载 ARM64 `SVC #0` 系统调用拦截 Hook
///
/// 通过泛型闭包 `get_state` 从 Unicorn UserData (`D`) 中取出 `(&mut MemoryManager, &mut VirtualFs)`，
/// 实现与宿主状态的完全解耦。
pub fn attach_syscall_hook<'a, D, F>(
    uc: &mut Unicorn<'a, D>,
    get_state: F,
) -> EmuResult<UcHookId>
where
    F: FnMut(&mut D) -> (&mut MemoryManager, &mut VirtualFs) + 'a,
{
    attach_syscall_hook_with_interceptor(uc, get_state, |_, _, _| None)
}

/// 挂载带前置拦截器的 ARM64 `SVC #0` 系统调用 Hook
///
/// 每次触发 `SVC #0` 时先调用 `interceptor(uc, nr, &args)`：
/// - 返回 `Some(ret)`：跳过内置分发，直接将 `ret` 写入 `X0`；
/// - 返回 `None`：放行给内置 SVC 分发器处理。
pub fn attach_syscall_hook_with_interceptor<'a, D, F, I>(
    uc: &mut Unicorn<'a, D>,
    mut get_state: F,
    mut interceptor: I,
) -> EmuResult<UcHookId>
where
    F: FnMut(&mut D) -> (&mut MemoryManager, &mut VirtualFs) + 'a,
    I: FnMut(&mut Unicorn<'_, D>, u64, &[u64; 6]) -> Option<u64> + 'a,
{
    let hook_id = uc.add_intr_hook(move |uc, intno| {
        if intno != ARM64_EXCP_SWI {
            return;
        }

        // AArch64 Linux ABI: X8 = syscall 号, X0..X5 = 6 个参数, 返回值写回 X0
        let nr = uc.reg_read(RegisterARM64::X8).unwrap_or(0);
        let a0 = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
        let a1 = uc.reg_read(RegisterARM64::X1).unwrap_or(0);
        let a2 = uc.reg_read(RegisterARM64::X2).unwrap_or(0);
        let a3 = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
        let a4 = uc.reg_read(RegisterARM64::X4).unwrap_or(0);
        let a5 = uc.reg_read(RegisterARM64::X5).unwrap_or(0);
        let args = [a0, a1, a2, a3, a4, a5];

        if let Some(custom_ret) = interceptor(uc, nr, &args) {
            let _ = uc.reg_write(RegisterARM64::X0, custom_ret);
            return;
        }

        let ret = dispatch_syscall(uc, nr, args, &mut get_state);
        let _ = uc.reg_write(RegisterARM64::X0, ret as u64);
    })?;

    Ok(hook_id)
}

/// 核心 Syscall 分发逻辑
fn dispatch_syscall<D, F>(
    uc: &mut Unicorn<'_, D>,
    nr: u64,
    args: [u64; 6],
    get_state: &mut F,
) -> i64
where
    F: FnMut(&mut D) -> (&mut MemoryManager, &mut VirtualFs),
{
    match nr {
        SYS_OPENAT => {
            // openat(dirfd, pathname, flags, mode)
            let path = read_guest_c_string(uc, args[1], 512);
            let (mem, vfs) = get_state(uc.get_data_mut());
            vfs.open_with_flags(&path, args[2] as u32, mem)
        }
        SYS_CLOSE => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.close(args[0] as i32)
        }
        SYS_LSEEK => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.lseek(args[0] as i32, args[1] as i64, args[2] as i32)
        }
        SYS_READ => {
            let fd = args[0] as i32;
            let buf_addr = args[1];
            let count = (args[2] as usize).min(16 * 1024 * 1024);
            let data = {
                let (_, vfs) = get_state(uc.get_data_mut());
                match vfs.read(fd, count) {
                    Ok(d) => d,
                    Err(errno) => return errno,
                }
            };
            if !data.is_empty() && uc.mem_write(buf_addr, &data).is_err() {
                return EINVAL;
            }
            data.len() as i64
        }
        SYS_WRITE => {
            let fd = args[0] as i32;
            let buf_addr = args[1];
            let count = (args[2] as usize).min(16 * 1024 * 1024);
            let mut buf = vec![0u8; count];
            if count > 0 && uc.mem_read(buf_addr, &mut buf).is_err() {
                return EINVAL;
            }
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.write(fd, &buf)
        }
        SYS_READLINKAT => {
            let path = read_guest_c_string(uc, args[1], 512);
            let target = {
                let (_, vfs) = get_state(uc.get_data_mut());
                match vfs.readlink(&path) {
                    Ok(t) => t,
                    Err(e) => return e,
                }
            };
            let max_len = args[3] as usize;
            let copy_len = target.len().min(max_len);
            if uc
                .mem_write(args[2], &target.as_bytes()[..copy_len])
                .is_err()
            {
                return EINVAL;
            }
            copy_len as i64
        }
        SYS_FSTAT => {
            let fd = args[0] as i32;
            let stat_buf = args[1];
            let (mode, size) = {
                let (_, vfs) = get_state(uc.get_data_mut());
                match vfs.fstat_fd(fd) {
                    Ok(s) => s,
                    Err(e) => return e,
                }
            };
            // AArch64 `struct stat` 为 128 字节：st_mode @ +16, st_size @ +48
            let mut st = [0u8; 128];
            st[16..20].copy_from_slice(&mode.to_le_bytes());
            st[48..56].copy_from_slice(&size.to_le_bytes());
            if uc.mem_write(stat_buf, &st).is_err() {
                return EBADF;
            }
            0
        }
        SYS_NEWFSTATAT => {
            let path = read_guest_c_string(uc, args[1], 512);
            let stat_buf = args[2];
            let (mode, size) = {
                let (mem, vfs) = get_state(uc.get_data_mut());
                match vfs.stat_path(&path, mem) {
                    Ok(s) => s,
                    Err(e) => return e,
                }
            };
            let mut st = [0u8; 128];
            st[16..20].copy_from_slice(&mode.to_le_bytes());
            st[48..56].copy_from_slice(&size.to_le_bytes());
            if uc.mem_write(stat_buf, &st).is_err() {
                return EINVAL;
            }
            0
        }
        SYS_BRK => {
            let (mem, _) = get_state(uc.get_data_mut());
            mem.brk(args[0]) as i64
        }
        SYS_MMAP => {
            // mmap(addr, length, prot, flags, fd, offset)
            let hint = args[0];
            let len = args[1];
            let perms = linux_prot_to_uc(args[2]);
            let fd = args[4] as i32;
            let offset = args[5];

            let file_bytes = if fd >= 0 {
                let (_, vfs) = get_state(uc.get_data_mut());
                vfs.lseek(fd, offset as i64, 0);
                vfs.read(fd, len as usize).ok()
            } else {
                None
            };

            let aligned_len = crate::memory::align_up(
                len.max(crate::memory::PAGE_SIZE),
                crate::memory::PAGE_SIZE,
            );
            let addr = if hint == 0 {
                let (mem, _) = get_state(uc.get_data_mut());
                let mut candidate = crate::memory::MMAP_BASE;
                for r in mem.regions() {
                    if candidate + aligned_len <= r.start {
                        break;
                    }
                    if candidate < r.end {
                        candidate = crate::memory::align_up(r.end, crate::memory::PAGE_SIZE);
                    }
                }
                candidate
            } else {
                crate::memory::align_down(hint, crate::memory::PAGE_SIZE)
            };

            if uc.mem_map(addr, aligned_len, perms).is_err() {
                return EINVAL;
            }
            if let Some(bytes) = file_bytes {
                let _ = uc.mem_write(addr, &bytes);
            }
            addr as i64
        }
        SYS_MUNMAP => {
            let aligned_addr = crate::memory::align_down(args[0], crate::memory::PAGE_SIZE);
            let aligned_len = crate::memory::align_up(args[1], crate::memory::PAGE_SIZE);
            if aligned_len > 0 && uc.mem_unmap(aligned_addr, aligned_len).is_err() {
                return EINVAL;
            }
            0
        }
        SYS_MPROTECT => {
            let aligned_addr = crate::memory::align_down(args[0], crate::memory::PAGE_SIZE);
            let aligned_len = crate::memory::align_up(args[1], crate::memory::PAGE_SIZE);
            let perms = linux_prot_to_uc(args[2]);
            if aligned_len > 0 && uc.mem_protect(aligned_addr, aligned_len, perms).is_err() {
                return EINVAL;
            }
            0
        }
        SYS_MADVISE
        | SYS_RT_SIGACTION
        | SYS_RT_SIGPROCMASK
        | SYS_PRCTL
        | SYS_IOCTL
        | SYS_SCHED_YIELD
        | SYS_PRLIMIT64 => 0,
        // 反调试对抗：`ptrace(PTRACE_TRACEME, ...)` 伪装未被任何调试器附加，直接返回 0
        SYS_PTRACE => 0,
        // 反调试对抗：屏蔽进程自杀信号（`tkill`/`tgkill`），防止反调试检测到异常后自毁
        SYS_TKILL | SYS_TGKILL => 0,
        // 虚拟时钟加速：`nanosleep(req, rem)` 不做真实宿主睡眠，直接将虚拟单调时钟快进对应纳秒
        SYS_NANOSLEEP => {
            let req_addr = args[0];
            let mut ts = [0u8; 16];
            if req_addr != 0 && uc.mem_read(req_addr, &mut ts).is_ok() {
                let sec = i64::from_le_bytes(ts[0..8].try_into().unwrap_or([0; 8])).max(0) as u64;
                let nsec = i64::from_le_bytes(ts[8..16].try_into().unwrap_or([0; 8])).max(0) as u64;
                let delta_ns = sec.saturating_mul(1_000_000_000).saturating_add(nsec);
                let (_, vfs) = get_state(uc.get_data_mut());
                vfs.mono_clock_ns = vfs.mono_clock_ns.saturating_add(delta_ns);
            }
            0
        }
        // 单线程/协作式 futex：防止 Bionic pthread_mutex / pthread_once 在模拟环境中死锁
        SYS_FUTEX => {
            // futex(uaddr, op, val, ...)
            let uaddr = args[0];
            let op = (args[1] as u32) & 0x7F; // 去除 FUTEX_PRIVATE_FLAG (128)
            let val = args[2] as u32;
            match op {
                // FUTEX_WAIT (0) / FUTEX_WAIT_BITSET (9)
                0 | 9 => {
                    let mut cur = [0u8; 4];
                    if uaddr != 0
                        && uc.mem_read(uaddr, &mut cur).is_ok()
                        && u32::from_le_bytes(cur) != val
                    {
                        return -11; // -EAGAIN
                    }
                    0
                }
                // FUTEX_WAKE (1) / FUTEX_WAKE_BITSET (10)
                1 | 10 => 1,
                _ => 0,
            }
        }
        SYS_SET_TID_ADDRESS => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.tid as i64
        }
        SYS_GETPID => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.pid as i64
        }
        SYS_GETPPID => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.ppid as i64
        }
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.uid as i64
        }
        SYS_GETTID => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.tid as i64
        }
        SYS_CLOCK_GETTIME => {
            // clock_gettime(clk_id, struct timespec *tp) -> { tv_sec: i64, tv_nsec: i64 }
            let tp_addr = args[1];
            let ns = {
                let (_, vfs) = get_state(uc.get_data_mut());
                vfs.mono_clock_ns += 1_000_000; // 每次递增 1ms，确定性推进
                vfs.mono_clock_ns
            };
            let sec = (ns / 1_000_000_000) as i64;
            let nsec = (ns % 1_000_000_000) as i64;
            let mut buf = [0u8; 16];
            buf[0..8].copy_from_slice(&sec.to_le_bytes());
            buf[8..16].copy_from_slice(&nsec.to_le_bytes());
            if uc.mem_write(tp_addr, &buf).is_err() {
                return EINVAL;
            }
            0
        }
        SYS_GETTIMEOFDAY => {
            let tv_addr = args[0];
            let ns = {
                let (_, vfs) = get_state(uc.get_data_mut());
                vfs.mono_clock_ns += 1_000_000;
                vfs.mono_clock_ns
            };
            let sec = (ns / 1_000_000_000) as i64;
            let usec = ((ns % 1_000_000_000) / 1_000) as i64;
            let mut buf = [0u8; 16];
            buf[0..8].copy_from_slice(&sec.to_le_bytes());
            buf[8..16].copy_from_slice(&usec.to_le_bytes());
            if tv_addr != 0 && uc.mem_write(tv_addr, &buf).is_err() {
                return EINVAL;
            }
            0
        }
        SYS_GETRANDOM => {
            let buf_addr = args[0];
            let count = (args[1] as usize).min(4096);
            let mut out = vec![0u8; count];
            {
                let (_, vfs) = get_state(uc.get_data_mut());
                vfs.fill_random(&mut out);
            }
            if uc.mem_write(buf_addr, &out).is_err() {
                return EINVAL;
            }
            count as i64
        }
        SYS_UNAME => {
            // struct utsname: 6 个 65 字节字段 (sysname, nodename, release, version, machine, domainname)
            let buf_addr = args[0];
            let mut uts = [0u8; 65 * 6];
            let fields = [
                "Linux",
                "localhost",
                "5.4.147-android12-9",
                "#1 SMP PREEMPT",
                "aarch64",
                "(none)",
            ];
            for (i, f) in fields.iter().enumerate() {
                let off = i * 65;
                uts[off..off + f.len()].copy_from_slice(f.as_bytes());
            }
            if uc.mem_write(buf_addr, &uts).is_err() {
                return EINVAL;
            }
            0
        }
        SYS_EXIT | SYS_EXIT_GROUP => {
            let _ = uc.emu_stop();
            0
        }
        _ => {
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.diag().record_missing_syscall(nr);
            vfs.breadcrumbs()
                .push(format!("[SVC ENOSYS] nr={nr} (x0=0x{:x})", args[0]));
            tracing::warn!(target: "runidbg::syscall", nr, x0 = format_args!("0x{:x}", args[0]), "未实现的 ARM64 Syscall");
            ENOSYS
        }
    }
}
