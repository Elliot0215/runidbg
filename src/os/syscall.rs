use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::backend::{BackendWithData, CpuBackend};

use crate::error::EmuResult;
use crate::memory::{read_guest_cstr as read_guest_c_string, MemoryManager};
use crate::os::net::{
    parse_sockaddr, serialize_sockaddr, AF_INET, FIONBIO, O_NONBLOCK, SIOCGIFADDR, SIOCGIFCONF,
    SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFNETMASK,
};
use crate::os::vfs::{VirtualFs, EBADF, EINVAL, ENOSYS};

/// ARM64 Unicorn SVC #0 中断号 (`EXCP_SWI`)
pub const ARM64_EXCP_SWI: u32 = 2;

/// Linux AArch64 常用系统调用号 (asm-generic/unistd.h)
pub const SYS_EVENTFD2: u64 = 19;
pub const SYS_EPOLL_CREATE1: u64 = 20;
pub const SYS_EPOLL_CTL: u64 = 21;
pub const SYS_EPOLL_PWAIT: u64 = 22;
pub const SYS_FCNTL: u64 = 25;
pub const SYS_IOCTL: u64 = 29;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_PIPE2: u64 = 59;
pub const SYS_LSEEK: u64 = 62;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_PPOLL: u64 = 73;
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
pub const SYS_SOCKET: u64 = 198;
pub const SYS_SOCKETPAIR: u64 = 199;
pub const SYS_BIND: u64 = 200;
pub const SYS_LISTEN: u64 = 201;
pub const SYS_ACCEPT: u64 = 202;
pub const SYS_CONNECT: u64 = 203;
pub const SYS_GETSOCKNAME: u64 = 204;
pub const SYS_GETPEERNAME: u64 = 205;
pub const SYS_SENDTO: u64 = 206;
pub const SYS_RECVFROM: u64 = 207;
pub const SYS_SETSOCKOPT: u64 = 208;
pub const SYS_GETSOCKOPT: u64 = 209;
pub const SYS_SHUTDOWN: u64 = 210;
pub const SYS_BRK: u64 = 214;
pub const SYS_MUNMAP: u64 = 215;
pub const SYS_MMAP: u64 = 222;
pub const SYS_MPROTECT: u64 = 226;
pub const SYS_MADVISE: u64 = 233;
pub const SYS_ACCEPT4: u64 = 242;
pub const SYS_PRLIMIT64: u64 = 261;
pub const SYS_GETRANDOM: u64 = 278;
pub const SYS_MKDIRAT: u64 = 34;
pub const SYS_UNLINKAT: u64 = 35;
pub const SYS_STATFS: u64 = 43;
pub const SYS_FSTATFS: u64 = 44;
pub const SYS_FTRUNCATE: u64 = 46;
pub const SYS_GETDENTS64: u64 = 61;
pub const SYS_PREAD64: u64 = 67;
pub const SYS_PWRITE64: u64 = 68;

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

/// 核心 Syscall 分发逻辑（供 Unicorn `SVC #0` Hook 与非 Unicorn 外部陷阱循环共用）
pub fn dispatch_syscall<B, D, F>(
    uc: &mut B,
    nr: u64,
    args: [u64; 6],
    get_state: &mut F,
) -> i64
where
    B: BackendWithData<D> + ?Sized,
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
        SYS_GETDENTS64 => {
            let fd = args[0] as i32;
            let dirp = args[1];
            let count = (args[2] as usize).min(1024 * 1024);
            let bytes = {
                let (_, vfs) = get_state(uc.get_data_mut());
                match vfs.read_getdents64(fd, count) {
                    Ok(b) => b,
                    Err(e) => return e,
                }
            };
            if !bytes.is_empty() && uc.mem_write(dirp, &bytes).is_err() {
                return EBADF;
            }
            bytes.len() as i64
        }
        SYS_PREAD64 => {
            let fd = args[0] as i32;
            let buf = args[1];
            let count = (args[2] as usize).min(16 * 1024 * 1024);
            let offset = args[3] as usize;
            let data = {
                let (_, vfs) = get_state(uc.get_data_mut());
                match vfs.pread(fd, offset, count) {
                    Ok(d) => d,
                    Err(e) => return e,
                }
            };
            if !data.is_empty() && uc.mem_write(buf, &data).is_err() {
                return EBADF;
            }
            data.len() as i64
        }
        SYS_PWRITE64 => {
            let fd = args[0] as i32;
            let buf = args[1];
            let count = (args[2] as usize).min(16 * 1024 * 1024);
            let offset = args[3] as usize;
            let mut data = vec![0u8; count];
            if count > 0 && uc.mem_read(buf, &mut data).is_err() {
                return EBADF;
            }
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.write_at(fd, offset, &data)
        }
        SYS_FTRUNCATE => {
            let fd = args[0] as i32;
            let len = args[1];
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.ftruncate(fd, len)
        }
        SYS_MKDIRAT => {
            let path = read_guest_c_string(uc, args[1], 512);
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.mkdir(&path)
        }
        SYS_UNLINKAT => {
            let path = read_guest_c_string(uc, args[1], 512);
            let (_, vfs) = get_state(uc.get_data_mut());
            vfs.unlink(&path)
        }
        SYS_STATFS | SYS_FSTATFS => {
            let buf = args[1];
            // AArch64 `struct statfs` = 120 字节：f_type=EXT4_SUPER_MAGIC(0xEF53), f_bsize=4096, f_blocks/bfree/bavail
            let mut st = [0u8; 120];
            st[0..8].copy_from_slice(&0xEF53u64.to_le_bytes());
            st[8..16].copy_from_slice(&4096u64.to_le_bytes());
            st[16..24].copy_from_slice(&16_777_216u64.to_le_bytes()); // 64 GB total
            st[24..32].copy_from_slice(&8_388_608u64.to_le_bytes()); // 32 GB free
            st[32..40].copy_from_slice(&8_388_608u64.to_le_bytes()); // 32 GB avail
            st[64..72].copy_from_slice(&255u64.to_le_bytes()); // f_namelen
            if buf != 0 && uc.mem_write(buf, &st).is_err() {
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
        | SYS_SCHED_YIELD
        | SYS_PRLIMIT64 => 0,
        SYS_IOCTL => {
            let fd = args[0] as i32;
            let req = args[1];
            let argp = args[2];
            match req {
                FIONBIO => {
                    let mut val_buf = [0u8; 4];
                    if argp != 0 && uc.mem_read(argp, &mut val_buf).is_ok() {
                        let nb = u32::from_le_bytes(val_buf) != 0;
                        let (_, vfs) = get_state(uc.get_data_mut());
                        let _ = vfs.net.set_nonblocking(fd, nb);
                    }
                    0
                }
                SIOCGIFFLAGS => {
                    // IFF_UP (0x1) | IFF_BROADCAST (0x2) | IFF_RUNNING (0x40) | IFF_MULTICAST (0x1000)
                    if argp != 0 {
                        let flags: u16 = 0x1043;
                        let _ = uc.mem_write(argp + 16, &flags.to_le_bytes());
                    }
                    0
                }
                SIOCGIFADDR => {
                    if argp != 0 {
                        let ipv4 = get_state(uc.get_data_mut()).1.net.config.nic.ipv4;
                        let mut sa = [0u8; 16];
                        sa[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
                        sa[4..8].copy_from_slice(&ipv4);
                        let _ = uc.mem_write(argp + 16, &sa);
                    }
                    0
                }
                SIOCGIFNETMASK => {
                    if argp != 0 {
                        let mask = get_state(uc.get_data_mut()).1.net.config.nic.netmask;
                        let mut sa = [0u8; 16];
                        sa[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
                        sa[4..8].copy_from_slice(&mask);
                        let _ = uc.mem_write(argp + 16, &sa);
                    }
                    0
                }
                SIOCGIFHWADDR => {
                    if argp != 0 {
                        let mac = get_state(uc.get_data_mut()).1.net.config.nic.mac;
                        let mut sa = [0u8; 16];
                        sa[0..2].copy_from_slice(&1u16.to_le_bytes()); // ARPHRD_ETHER
                        sa[2..8].copy_from_slice(&mac);
                        let _ = uc.mem_write(argp + 16, &sa);
                    }
                    0
                }
                SIOCGIFCONF => {
                    // struct ifconf { int ifc_len; pad(4); void *ifc_buf; } (AArch64 = 16 bytes)
                    if argp != 0 {
                        let mut hdr = [0u8; 16];
                        if uc.mem_read(argp, &mut hdr).is_ok() {
                            let cap = i32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]).max(0) as usize;
                            let buf_ptr = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
                            let nic = get_state(uc.get_data_mut()).1.net.config.nic.clone();
                            // struct ifreq on AArch64 = 40 bytes (16B name + 24B union)
                            if buf_ptr != 0 && cap >= 40 {
                                let mut ifreq = [0u8; 40];
                                let nbytes = nic.name.as_bytes();
                                let nlen = nbytes.len().min(15);
                                ifreq[..nlen].copy_from_slice(&nbytes[..nlen]);
                                ifreq[16..18].copy_from_slice(&(AF_INET as u16).to_le_bytes());
                                ifreq[20..24].copy_from_slice(&nic.ipv4);
                                let _ = uc.mem_write(buf_ptr, &ifreq);
                                let _ = uc.mem_write(argp, &40i32.to_le_bytes());
                            } else {
                                let _ = uc.mem_write(argp, &40i32.to_le_bytes());
                            }
                        }
                    }
                    0
                }
                _ => 0,
            }
        }
        SYS_FCNTL => {
            let fd = args[0] as i32;
            let cmd = args[1] as i32;
            let arg = args[2] as u32;
            let (_, vfs) = get_state(uc.get_data_mut());
            match cmd {
                3 => {
                    // F_GETFL
                    if vfs.net.is_nonblocking(fd) {
                        O_NONBLOCK as i64
                    } else {
                        0
                    }
                }
                4 => {
                    // F_SETFL
                    if vfs.net.contains_fd(fd) {
                        vfs.net.set_nonblocking(fd, (arg & O_NONBLOCK) != 0);
                    }
                    0
                }
                _ => 0,
            }
        }
        SYS_EVENTFD2 => {
            let initval = args[0];
            let flags = args[1] as u32;
            let (_, vfs) = get_state(uc.get_data_mut());
            let fd = vfs.alloc_raw_fd();
            vfs.net.create_eventfd(fd, initval, flags)
        }
        SYS_EPOLL_CREATE1 => {
            let (_, vfs) = get_state(uc.get_data_mut());
            let fd = vfs.alloc_raw_fd();
            vfs.net.create_epoll(fd)
        }
        SYS_EPOLL_CTL => {
            let epfd = args[0] as i32;
            let op = args[1] as i32;
            let fd = args[2] as i32;
            let ev_ptr = args[3];
            let (events, data) = if ev_ptr != 0 {
                // struct epoll_event on AArch64: u32 events (0..4) + u32 pad (4..8) + u64 data (8..16)
                let mut buf = [0u8; 16];
                if uc.mem_read(ev_ptr, &mut buf).is_ok() {
                    let ev = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                    let dt = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                    (ev, dt)
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };
            get_state(uc.get_data_mut())
                .1
                .net
                .epoll_ctl(epfd, op, fd, events, data)
        }
        SYS_EPOLL_PWAIT => {
            let epfd = args[0] as i32;
            let ev_ptr = args[1];
            let max_events = (args[2] as i32).max(0) as usize;
            let timeout_ms = args[3] as i32;
            let res = get_state(uc.get_data_mut())
                .1
                .net
                .epoll_wait(epfd, max_events, timeout_ms);
            match res {
                Ok(ready) => {
                    for (i, (ev, dt)) in ready.iter().enumerate() {
                        let mut buf = [0u8; 16];
                        buf[0..4].copy_from_slice(&ev.to_le_bytes());
                        buf[8..16].copy_from_slice(&dt.to_le_bytes());
                        let _ = uc.mem_write(ev_ptr + (i as u64) * 16, &buf);
                    }
                    ready.len() as i64
                }
                Err(e) => e,
            }
        }
        SYS_PIPE2 => {
            let fds_ptr = args[0];
            let flags = args[1] as u32;
            let (rfd, wfd, ret) = {
                let (_, vfs) = get_state(uc.get_data_mut());
                let rfd = vfs.alloc_raw_fd();
                let wfd = vfs.alloc_raw_fd();
                let ret = vfs.net.create_pipe(rfd, wfd, flags);
                (rfd, wfd, ret)
            };
            if ret == 0 && fds_ptr != 0 {
                let mut pair = [0u8; 8];
                pair[0..4].copy_from_slice(&rfd.to_le_bytes());
                pair[4..8].copy_from_slice(&wfd.to_le_bytes());
                if uc.mem_write(fds_ptr, &pair).is_err() {
                    return EINVAL;
                }
            }
            ret
        }
        SYS_PPOLL => {
            // ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, ...)
            let fds_ptr = args[0];
            let nfds = (args[1] as usize).min(1024);
            let tmo_ptr = args[2];
            let timeout_ms = if tmo_ptr != 0 {
                let mut ts = [0u8; 16];
                if uc.mem_read(tmo_ptr, &mut ts).is_ok() {
                    let secs = i64::from_le_bytes(ts[0..8].try_into().unwrap()).max(0);
                    let nsecs = i64::from_le_bytes(ts[8..16].try_into().unwrap()).max(0);
                    (secs.saturating_mul(1000) + nsecs / 1_000_000).min(i32::MAX as i64) as i32
                } else {
                    0
                }
            } else {
                -1
            };
            let mut items = Vec::with_capacity(nfds);
            for i in 0..nfds {
                let mut pfd = [0u8; 8];
                if uc.mem_read(fds_ptr + (i as u64) * 8, &mut pfd).is_ok() {
                    let fd = i32::from_le_bytes(pfd[0..4].try_into().unwrap());
                    let ev = u16::from_le_bytes(pfd[4..6].try_into().unwrap());
                    items.push((fd, ev));
                }
            }
            let revents = get_state(uc.get_data_mut())
                .1
                .net
                .poll_fds(&items, timeout_ms);
            let mut count = 0i64;
            for (i, &rev) in revents.iter().enumerate() {
                if rev != 0 {
                    count += 1;
                }
                let _ = uc.mem_write(fds_ptr + (i as u64) * 8 + 6, &rev.to_le_bytes());
            }
            count
        }
        SYS_SOCKET => {
            let domain = args[0] as i32;
            let sock_type = args[1] as i32;
            let protocol = args[2] as i32;
            let (_, vfs) = get_state(uc.get_data_mut());
            let fd = vfs.alloc_raw_fd();
            vfs.net.create_socket(fd, domain, sock_type, protocol)
        }
        SYS_SOCKETPAIR => {
            let sv_ptr = args[3];
            let (fd0, fd1, ret) = {
                let (_, vfs) = get_state(uc.get_data_mut());
                let fd0 = vfs.alloc_raw_fd();
                let fd1 = vfs.alloc_raw_fd();
                let ret = vfs.net.create_pipe(fd0, fd1, 0);
                (fd0, fd1, ret)
            };
            if ret == 0 && sv_ptr != 0 {
                let mut pair = [0u8; 8];
                pair[0..4].copy_from_slice(&fd0.to_le_bytes());
                pair[4..8].copy_from_slice(&fd1.to_le_bytes());
                let _ = uc.mem_write(sv_ptr, &pair);
            }
            ret
        }
        SYS_BIND => {
            let fd = args[0] as i32;
            let addr_ptr = args[1];
            let addr_len = (args[2] as usize).min(128);
            let mut sa = vec![0u8; addr_len];
            if uc.mem_read(addr_ptr, &mut sa).is_err() {
                return EINVAL;
            }
            let Some(sock_addr) = parse_sockaddr(&sa) else {
                return EINVAL;
            };
            get_state(uc.get_data_mut()).1.net.bind(fd, sock_addr)
        }
        SYS_LISTEN => {
            let fd = args[0] as i32;
            get_state(uc.get_data_mut()).1.net.listen(fd)
        }
        SYS_ACCEPT | SYS_ACCEPT4 => {
            let fd = args[0] as i32;
            let addr_ptr = args[1];
            let addrlen_ptr = args[2];
            let flags = if nr == SYS_ACCEPT4 { args[3] as i32 } else { 0 };
            let (new_fd, res) = {
                let (_, vfs) = get_state(uc.get_data_mut());
                let new_fd = vfs.alloc_raw_fd();
                let res = vfs.net.accept(fd, new_fd, flags);
                (new_fd, res)
            };
            match res {
                Ok(peer) => {
                    if addr_ptr != 0 {
                        let bytes = serialize_sockaddr(peer);
                        let _ = uc.mem_write(addr_ptr, &bytes);
                        if addrlen_ptr != 0 {
                            let _ = uc.mem_write(addrlen_ptr, &(bytes.len() as u32).to_le_bytes());
                        }
                    }
                    new_fd as i64
                }
                Err(e) => e,
            }
        }
        SYS_CONNECT => {
            let fd = args[0] as i32;
            let addr_ptr = args[1];
            let addr_len = (args[2] as usize).min(128);
            let mut sa = vec![0u8; addr_len];
            if uc.mem_read(addr_ptr, &mut sa).is_err() {
                return EINVAL;
            }
            let Some(sock_addr) = parse_sockaddr(&sa) else {
                return EINVAL;
            };
            get_state(uc.get_data_mut()).1.net.connect(fd, sock_addr)
        }
        SYS_GETSOCKNAME | SYS_GETPEERNAME => {
            let fd = args[0] as i32;
            let addr_ptr = args[1];
            let addrlen_ptr = args[2];
            let addr_opt = {
                let (_, vfs) = get_state(uc.get_data_mut());
                if nr == SYS_GETSOCKNAME {
                    vfs.net.local_addr(fd)
                } else {
                    vfs.net.peer_addr(fd)
                }
            };
            let Some(addr) = addr_opt else {
                return EINVAL;
            };
            let bytes = serialize_sockaddr(addr);
            if addr_ptr != 0 {
                let _ = uc.mem_write(addr_ptr, &bytes);
            }
            if addrlen_ptr != 0 {
                let _ = uc.mem_write(addrlen_ptr, &(bytes.len() as u32).to_le_bytes());
            }
            0
        }
        SYS_SENDTO => {
            let fd = args[0] as i32;
            let buf_ptr = args[1];
            let len = (args[2] as usize).min(1024 * 1024);
            let dest_ptr = args[4];
            let dest_len = (args[5] as usize).min(128);
            let mut data = vec![0u8; len];
            if len > 0 && uc.mem_read(buf_ptr, &mut data).is_err() {
                return EINVAL;
            }
            let dest = if dest_ptr != 0 && dest_len >= 8 {
                let mut sa = vec![0u8; dest_len];
                if uc.mem_read(dest_ptr, &mut sa).is_ok() {
                    parse_sockaddr(&sa)
                } else {
                    None
                }
            } else {
                None
            };
            get_state(uc.get_data_mut()).1.net.send(fd, &data, dest)
        }
        SYS_RECVFROM => {
            let fd = args[0] as i32;
            let buf_ptr = args[1];
            let len = (args[2] as usize).min(1024 * 1024);
            let src_ptr = args[4];
            let srclen_ptr = args[5];
            match get_state(uc.get_data_mut()).1.net.recv(fd, len) {
                Ok((data, peer)) => {
                    if !data.is_empty() && uc.mem_write(buf_ptr, &data).is_err() {
                        return EINVAL;
                    }
                    if let Some(peer_addr) = peer {
                        if src_ptr != 0 {
                            let bytes = serialize_sockaddr(peer_addr);
                            let _ = uc.mem_write(src_ptr, &bytes);
                            if srclen_ptr != 0 {
                                let _ =
                                    uc.mem_write(srclen_ptr, &(bytes.len() as u32).to_le_bytes());
                            }
                        }
                    }
                    data.len() as i64
                }
                Err(e) => e,
            }
        }
        SYS_SETSOCKOPT => 0,
        SYS_GETSOCKOPT => {
            // SO_ERROR 等默认返回 0（无错误）
            let optval_ptr = args[3];
            let optlen_ptr = args[4];
            if optval_ptr != 0 {
                let _ = uc.mem_write(optval_ptr, &0i32.to_le_bytes());
            }
            if optlen_ptr != 0 {
                let _ = uc.mem_write(optlen_ptr, &4u32.to_le_bytes());
            }
            0
        }
        SYS_SHUTDOWN => {
            let fd = args[0] as i32;
            let how = args[1] as i32;
            get_state(uc.get_data_mut()).1.net.shutdown(fd, how)
        }
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
                vfs.current_clock_ns()
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
                vfs.current_clock_ns()
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
            let (release, version) = {
                let (_, vfs) = get_state(uc.get_data_mut());
                let dp = vfs.device_profile();
                (dp.kernel_release.clone(), dp.kernel_version.clone())
            };
            let mut uts = [0u8; 65 * 6];
            let fields = [
                "Linux",
                "localhost",
                release.as_str(),
                version.as_str(),
                "aarch64",
                "(none)",
            ];
            for (i, f) in fields.iter().enumerate() {
                let off = i * 65;
                let copy_len = f.len().min(64);
                uts[off..off + copy_len].copy_from_slice(&f.as_bytes()[..copy_len]);
            }
            if uc.mem_write(buf_addr, &uts).is_err() {
                return EINVAL;
            }
            0
        }
        SYS_EXIT | SYS_EXIT_GROUP => {
            let _ = CpuBackend::stop(uc);
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
