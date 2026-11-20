use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crash::BreadcrumbRing;
use crate::diag::EnvDiag;
use crate::memory::MemoryManager;

/// 标准 Linux 负错误码
pub const ENOENT: i64 = -2;
pub const EBADF: i64 = -9;
pub const EEXIST: i64 = -17;
pub const EINVAL: i64 = -22;
pub const ENOSYS: i64 = -38;

/// Linux AArch64 `open`/`openat` 常用标志位
pub const O_CREAT: u32 = 0o100;
pub const O_TRUNC: u32 = 0o1000;

/// 打开的文件描述符状态
#[derive(Debug, Clone)]
enum OpenFileKind {
    /// 内存缓冲（合成文件或只读宿主机文件快照）
    Buffer { data: Vec<u8>, cursor: usize },
    /// 直接关联到 `overlay_files` 的可读写虚拟文件
    Overlay { cursor: usize },
    /// `/dev/urandom` / `/dev/random` 伪随机设备流
    Urandom,
    /// 标准输出 / 标准错误
    StdStream { is_stderr: bool },
}

#[derive(Debug, Clone)]
struct OpenFile {
    path: String,
    kind: OpenFileKind,
}

/// Overlay 虚拟文件系统与进程/设备属性上下文
///
/// 设计要点：
/// 1. 自动动态合成 `/proc/self/maps`（实时读取 `MemoryManager`）、`/proc/self/status`（默认 `TracerPid: 0`）、`/proc/self/cmdline`。
/// 2. 支持只读挂载宿主机 Sysroot 目录（如 Android `/system/lib64`），任何写操作仅落入内存 Overlay，不污染宿主机。
/// 3. 支持可读写内存 Overlay 文件与虚拟目录（供 MMKV / SQLite 等 NDK SDK 执行 `open(O_CREAT)`/`ftruncate`/`mmap`/`msync`）。
/// 4. 内置确定性 XorShift64 PRNG，便于加密算法与反调试逻辑的确定性复现。
pub struct VirtualFs {
    pub package_name: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub tid: u32,
    /// Android 系统属性表（供 `__system_property_get` 与反调试查询）
    pub properties: HashMap<String, String>,
    /// 只读宿主机目录挂载点：(虚拟前缀, 宿主机路径)
    sysroot_mounts: Vec<(String, PathBuf)>,
    /// 内存 Overlay 文件表：虚拟绝对路径 -> 字节内容
    overlay_files: HashMap<String, Vec<u8>>,
    /// 虚拟目录集合
    overlay_dirs: HashSet<String>,
    /// 进程 FD 表
    fds: BTreeMap<i32, OpenFile>,
    next_fd: i32,
    /// 确定性伪随机数状态
    rng_state: u64,
    /// 虚拟单调时钟（纳秒），每次调用递增 1ms，防止时间差反调试
    pub mono_clock_ns: u64,
    /// 为 true 时直接读取宿主机真实时间（适用于需要当前 Unix 时间戳的实签场景）
    pub use_real_clock: bool,
    /// 缺环境自动诊断器（关闭时零开销）
    diag: EnvDiag,
    /// 最近外部事件环形缓冲（供崩溃现场报告使用）
    breadcrumbs: BreadcrumbRing,
}

impl Default for VirtualFs {
    fn default() -> Self {
        Self::new("com.example.app")
    }
}

impl VirtualFs {
    pub fn new(package_name: impl Into<String>) -> Self {
        let pkg = package_name.into();
        let mut properties = HashMap::new();
        // 默认 Android 11 (API 30) 设备属性模板
        properties.insert("ro.build.version.sdk".into(), "30".into());
        properties.insert("ro.build.version.release".into(), "11".into());
        properties.insert("ro.product.cpu.abi".into(), "arm64-v8a".into());
        properties.insert("ro.debuggable".into(), "0".into());
        properties.insert("ro.secure".into(), "1".into());
        properties.insert(
            "ro.build.fingerprint".into(),
            "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys".into(),
        );

        let mut overlay_dirs = HashSet::new();
        for dir in [
            "/",
            "/data",
            "/data/user",
            "/data/user/0",
            "/data/data",
            "/tmp",
            "/proc",
            "/proc/self",
            "/dev",
            "/system",
        ] {
            overlay_dirs.insert(dir.to_string());
        }
        overlay_dirs.insert(format!("/data/user/0/{pkg}"));
        overlay_dirs.insert(format!("/data/user/0/{pkg}/files"));
        overlay_dirs.insert(format!("/data/user/0/{pkg}/cache"));
        overlay_dirs.insert(format!("/data/data/{pkg}"));
        overlay_dirs.insert(format!("/data/data/{pkg}/files"));

        let mut fds = BTreeMap::new();
        fds.insert(
            0,
            OpenFile {
                path: "/dev/null".into(),
                kind: OpenFileKind::Buffer {
                    data: Vec::new(),
                    cursor: 0,
                },
            },
        );
        fds.insert(
            1,
            OpenFile {
                path: "/dev/stdout".into(),
                kind: OpenFileKind::StdStream { is_stderr: false },
            },
        );
        fds.insert(
            2,
            OpenFile {
                path: "/dev/stderr".into(),
                kind: OpenFileKind::StdStream { is_stderr: true },
            },
        );

        Self {
            package_name: pkg,
            pid: 10420,
            ppid: 1000,
            uid: 10123,
            tid: 10420,
            properties,
            sysroot_mounts: Vec::new(),
            overlay_files: HashMap::new(),
            overlay_dirs,
            fds,
            next_fd: 3,
            rng_state: 0x2026_1119_CAFE_BABE,
            mono_clock_ns: 1_700_000_000_000_000_000,
            use_real_clock: false,
            diag: EnvDiag::new(),
            breadcrumbs: BreadcrumbRing::new(),
        }
    }

    pub fn set_diag(&mut self, diag: EnvDiag) {
        self.diag = diag;
    }

    pub fn diag(&self) -> &EnvDiag {
        &self.diag
    }

    pub fn breadcrumbs(&self) -> &BreadcrumbRing {
        &self.breadcrumbs
    }

    /// 切换是否使用宿主机真实时间戳（默认关闭，使用确定性虚拟时钟）
    pub fn set_use_real_clock(&mut self, enabled: bool) {
        self.use_real_clock = enabled;
    }

    /// 手动设置虚拟时钟基准（Unix 秒），同时切回确定性虚拟时钟模式
    pub fn set_clock_secs(&mut self, unix_secs: u64) {
        self.use_real_clock = false;
        self.mono_clock_ns = unix_secs.saturating_mul(1_000_000_000);
    }

    /// 获取当前仿真时钟（纳秒）：开启 `use_real_clock` 时返回宿主机实时时间，否则确定性递增 1ms
    pub fn current_clock_ns(&mut self) -> u64 {
        if self.use_real_clock {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(self.mono_clock_ns);
            self.mono_clock_ns = now;
            now
        } else {
            self.mono_clock_ns = self.mono_clock_ns.saturating_add(1_000_000);
            self.mono_clock_ns
        }
    }

    /// 挂载宿主机只读目录到虚拟路径（例如 `/system` -> `./sysroot/system`）
    pub fn mount_readonly(&mut self, guest_prefix: impl Into<String>, host_dir: impl AsRef<Path>) {
        self.sysroot_mounts
            .push((guest_prefix.into(), host_dir.as_ref().to_path_buf()));
    }

    /// 记录路径的所有父目录到虚拟目录集合
    fn ensure_parent_dirs(&mut self, path: &str) {
        let mut cur = path;
        while let Some(pos) = cur.rfind('/') {
            if pos == 0 {
                self.overlay_dirs.insert("/".to_string());
                break;
            }
            cur = &cur[..pos];
            self.overlay_dirs.insert(cur.to_string());
        }
    }

    /// 写入内存 Overlay 文件（优先级高于宿主机只读挂载）
    pub fn add_overlay_file(&mut self, guest_path: impl Into<String>, data: Vec<u8>) {
        let path = Self::clean_path(&guest_path.into());
        self.ensure_parent_dirs(&path);
        self.overlay_files.insert(path, data);
    }

    /// 读取内存 Overlay 文件
    pub fn get_overlay_file(&self, guest_path: &str) -> Option<&[u8]> {
        let path = Self::clean_path(guest_path);
        self.overlay_files.get(&path).map(Vec::as_slice)
    }

    /// 设置 Android 系统属性
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// 读取 Android 系统属性（未命中时自动记入缺环境诊断器）
    pub fn get_property(&self, key: &str) -> Option<&str> {
        let res = self.properties.get(key).map(String::as_str);
        if res.is_none() {
            self.diag.record_missing_property(key);
        }
        res
    }

    /// 生成确定性随机字节（供 `/dev/urandom` 与 `getrandom` Syscall 使用）
    pub fn fill_random(&mut self, dst: &mut [u8]) {
        for byte in dst.iter_mut() {
            let mut x = self.rng_state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.rng_state = x;
            *byte = (x & 0xFF) as u8;
        }
    }

    /// 折叠重复斜杠并去除非根路径的末尾斜杠
    fn clean_path(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut prev_slash = false;
        for ch in raw.chars() {
            if ch == '/' {
                if !prev_slash {
                    out.push('/');
                }
                prev_slash = true;
            } else {
                out.push(ch);
                prev_slash = false;
            }
        }
        if out.len() > 1 && out.ends_with('/') {
            out.pop();
        }
        out
    }

    /// 规范化 `/proc/<pid>/...` 为 `/proc/self/...` 并清理斜杠
    fn normalize_path(&self, raw: &str) -> String {
        let cleaned = Self::clean_path(raw);
        let pid_prefix = format!("/proc/{}/", self.pid);
        if let Some(rest) = cleaned.strip_prefix(&pid_prefix) {
            return format!("/proc/self/{rest}");
        }
        cleaned
    }

    /// 打开虚拟文件并返回 FD（只读模式便捷封装）
    pub fn open(&mut self, raw_path: &str, mem: &MemoryManager) -> i64 {
        self.open_with_flags(raw_path, 0, mem)
    }

    /// 按 Linux `flags` 打开或创建虚拟文件并返回 FD（失败返回负 Linux errno）
    pub fn open_with_flags(&mut self, raw_path: &str, flags: u32, mem: &MemoryManager) -> i64 {
        let path = self.normalize_path(raw_path);

        // 1. 设备文件
        if path == "/dev/urandom" || path == "/dev/random" {
            return self.alloc_fd(path, OpenFileKind::Urandom);
        }
        if path == "/dev/null" {
            return self.alloc_fd(
                path,
                OpenFileKind::Buffer {
                    data: Vec::new(),
                    cursor: 0,
                },
            );
        }

        // 2. 动态合成 `/proc/self/*`
        if path == "/proc/self/maps" {
            let maps = mem.format_proc_maps().into_bytes();
            return self.alloc_fd(path, OpenFileKind::Buffer { data: maps, cursor: 0 });
        }
        if path == "/proc/self/status" {
            let status = format!(
                "Name:\t{}\nUmask:\t0077\nState:\tR (running)\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nTracerPid:\t0\nUid:\t{}\t{}\t{}\t{}\n",
                self.package_name,
                self.pid,
                self.pid,
                self.ppid,
                self.uid,
                self.uid,
                self.uid,
                self.uid
            )
            .into_bytes();
            return self.alloc_fd(
                path,
                OpenFileKind::Buffer {
                    data: status,
                    cursor: 0,
                },
            );
        }
        if path == "/proc/self/cmdline" {
            let mut cmdline = self.package_name.as_bytes().to_vec();
            cmdline.push(0);
            return self.alloc_fd(
                path,
                OpenFileKind::Buffer {
                    data: cmdline,
                    cursor: 0,
                },
            );
        }

        // 3. 内存 Overlay 文件（支持 O_TRUNC 与直接读写共享）
        if let Some(buf) = self.overlay_files.get_mut(&path) {
            if flags & O_TRUNC != 0 {
                buf.clear();
            }
            return self.alloc_fd(path, OpenFileKind::Overlay { cursor: 0 });
        }

        // 4. 只读 Sysroot 宿主机映射
        for (prefix, host_root) in &self.sysroot_mounts {
            if let Some(rel) = path.strip_prefix(prefix) {
                let rel_trimmed = rel.trim_start_matches('/');
                let host_path = host_root.join(rel_trimmed);
                if let Ok(data) = fs::read(&host_path) {
                    return self.alloc_fd(path, OpenFileKind::Buffer { data, cursor: 0 });
                }
            }
        }

        // 5. 若带 O_CREAT，则在内存 Overlay 中创建新文件
        if flags & O_CREAT != 0 {
            self.ensure_parent_dirs(&path);
            self.overlay_files.insert(path.clone(), Vec::new());
            return self.alloc_fd(path, OpenFileKind::Overlay { cursor: 0 });
        }

        self.diag.record_missing_file(&path);
        self.breadcrumbs.push(format!("[VFS ENOENT] open({path})"));
        tracing::debug!(target: "runidbg::syscall", path = %path, "open 返回 ENOENT");
        ENOENT
    }

    fn alloc_fd(&mut self, path: String, kind: OpenFileKind) -> i64 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, OpenFile { path, kind });
        fd as i64
    }

    /// 从 FD 读取最多 `count` 字节
    pub fn read(&mut self, fd: i32, count: usize) -> Result<Vec<u8>, i64> {
        let is_urandom = matches!(
            self.fds.get(&fd).map(|f| &f.kind),
            Some(OpenFileKind::Urandom)
        );
        if is_urandom {
            let mut out = vec![0u8; count];
            self.fill_random(&mut out);
            return Ok(out);
        }

        let overlay_info = match self.fds.get(&fd) {
            Some(OpenFile {
                path,
                kind: OpenFileKind::Overlay { cursor },
            }) => Some((path.clone(), *cursor)),
            _ => None,
        };
        if let Some((path, cursor)) = overlay_info {
            let data = self.overlay_files.get(&path).ok_or(EBADF)?;
            if cursor >= data.len() {
                return Ok(Vec::new());
            }
            let avail = (data.len() - cursor).min(count);
            let slice = data[cursor..cursor + avail].to_vec();
            if let Some(OpenFile {
                kind: OpenFileKind::Overlay { cursor: c },
                ..
            }) = self.fds.get_mut(&fd)
            {
                *c += avail;
            }
            return Ok(slice);
        }

        let file = self.fds.get_mut(&fd).ok_or(EBADF)?;
        match &mut file.kind {
            OpenFileKind::Buffer { data, cursor } => {
                if *cursor >= data.len() {
                    return Ok(Vec::new());
                }
                let avail = (data.len() - *cursor).min(count);
                let slice = data[*cursor..*cursor + avail].to_vec();
                *cursor += avail;
                Ok(slice)
            }
            OpenFileKind::Overlay { .. } | OpenFileKind::Urandom => unreachable!(),
            OpenFileKind::StdStream { .. } => Ok(Vec::new()),
        }
    }

    /// 向 FD 写入字节（标准输出直接打印，Overlay 文件持久化到 `overlay_files`）
    pub fn write(&mut self, fd: i32, bytes: &[u8]) -> i64 {
        let overlay_info = match self.fds.get(&fd) {
            Some(OpenFile {
                path,
                kind: OpenFileKind::Overlay { cursor },
            }) => Some((path.clone(), *cursor)),
            _ => None,
        };
        if let Some((path, cursor)) = overlay_info {
            let data = self.overlay_files.entry(path).or_default();
            let end = cursor + bytes.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[cursor..end].copy_from_slice(bytes);
            if let Some(OpenFile {
                kind: OpenFileKind::Overlay { cursor: c },
                ..
            }) = self.fds.get_mut(&fd)
            {
                *c = end;
            }
            return bytes.len() as i64;
        }

        let Some(file) = self.fds.get_mut(&fd) else {
            return EBADF;
        };
        match &mut file.kind {
            OpenFileKind::StdStream { is_stderr } => {
                let text = String::from_utf8_lossy(bytes);
                if *is_stderr {
                    eprint!("[guest stderr] {text}");
                } else {
                    print!("[guest stdout] {text}");
                }
                bytes.len() as i64
            }
            OpenFileKind::Buffer { data, cursor } => {
                let end = *cursor + bytes.len();
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[*cursor..end].copy_from_slice(bytes);
                *cursor = end;
                bytes.len() as i64
            }
            OpenFileKind::Overlay { .. } => unreachable!(),
            OpenFileKind::Urandom => bytes.len() as i64,
        }
    }

    /// 移动文件游标 (`SEEK_SET=0`, `SEEK_CUR=1`, `SEEK_END=2`)
    pub fn lseek(&mut self, fd: i32, offset: i64, whence: i32) -> i64 {
        let overlay_len = match self.fds.get(&fd) {
            Some(OpenFile {
                path,
                kind: OpenFileKind::Overlay { .. },
            }) => Some(self.overlay_files.get(path).map_or(0, Vec::len)),
            _ => None,
        };

        let Some(file) = self.fds.get_mut(&fd) else {
            return EBADF;
        };
        match &mut file.kind {
            OpenFileKind::Buffer { data, cursor } => {
                let base = match whence {
                    0 => 0i64,
                    1 => *cursor as i64,
                    2 => data.len() as i64,
                    _ => return EINVAL,
                };
                let new_pos = base.saturating_add(offset);
                if new_pos < 0 {
                    return EINVAL;
                }
                *cursor = new_pos as usize;
                new_pos
            }
            OpenFileKind::Overlay { cursor } => {
                let file_len = overlay_len.unwrap_or(0);
                let base = match whence {
                    0 => 0i64,
                    1 => *cursor as i64,
                    2 => file_len as i64,
                    _ => return EINVAL,
                };
                let new_pos = base.saturating_add(offset);
                if new_pos < 0 {
                    return EINVAL;
                }
                *cursor = new_pos as usize;
                new_pos
            }
            _ => 0,
        }
    }

    /// 调整打开文件的大小（供 `ftruncate` 使用，MMKV 扩容核心依赖）
    pub fn ftruncate(&mut self, fd: i32, length: u64) -> i64 {
        let overlay_path = match self.fds.get(&fd) {
            Some(OpenFile {
                path,
                kind: OpenFileKind::Overlay { .. },
            }) => Some(path.clone()),
            _ => None,
        };
        if let Some(path) = overlay_path {
            let data = self.overlay_files.entry(path).or_default();
            data.resize(length as usize, 0);
            return 0;
        }
        let Some(file) = self.fds.get_mut(&fd) else {
            return EBADF;
        };
        if let OpenFileKind::Buffer { data, .. } = &mut file.kind {
            data.resize(length as usize, 0);
            return 0;
        }
        0
    }

    /// 获取已打开 FD 的文件长度（供 `fstat` 填充 `st_size`）
    pub fn file_size(&self, fd: i32) -> Result<u64, i64> {
        let file = self.fds.get(&fd).ok_or(EBADF)?;
        match &file.kind {
            OpenFileKind::Buffer { data, .. } => Ok(data.len() as u64),
            OpenFileKind::Overlay { .. } => Ok(self
                .overlay_files
                .get(&file.path)
                .map_or(0, |v| v.len() as u64)),
            _ => Ok(0),
        }
    }

    /// 查询 FD 的 `(st_mode, st_size)`
    pub fn fstat_fd(&self, fd: i32) -> Result<(u32, u64), i64> {
        let size = self.file_size(fd)?;
        Ok((0o100644, size))
    }

    /// 查询路径的 `(st_mode, st_size)`（区分目录 `S_IFDIR|0755` 与普通文件 `S_IFREG|0644`）
    pub fn stat_path(&self, raw_path: &str, mem: &MemoryManager) -> Result<(u32, u64), i64> {
        let path = self.normalize_path(raw_path);
        if self.overlay_dirs.contains(&path) {
            return Ok((0o040755, 4096));
        }
        if let Some(data) = self.overlay_files.get(&path) {
            return Ok((0o100644, data.len() as u64));
        }
        if path == "/proc/self/maps" {
            return Ok((0o100444, mem.format_proc_maps().len() as u64));
        }
        if matches!(
            path.as_str(),
            "/proc/self/status" | "/proc/self/cmdline" | "/dev/urandom" | "/dev/random" | "/dev/null"
        ) {
            return Ok((0o100444, 0));
        }
        for (prefix, host_root) in &self.sysroot_mounts {
            if let Some(rel) = path.strip_prefix(prefix) {
                let host_path = host_root.join(rel.trim_start_matches('/'));
                if let Ok(meta) = fs::metadata(&host_path) {
                    let mode = if meta.is_dir() { 0o040755 } else { 0o100644 };
                    return Ok((mode, meta.len()));
                }
            }
        }
        Err(ENOENT)
    }

    /// 创建虚拟目录
    pub fn mkdir(&mut self, raw_path: &str) -> i64 {
        let path = self.normalize_path(raw_path);
        if self.overlay_dirs.contains(&path) {
            return EEXIST;
        }
        self.ensure_parent_dirs(&path);
        self.overlay_dirs.insert(path);
        0
    }

    /// 检查文件或目录是否存在
    pub fn access(&self, raw_path: &str, mem: &MemoryManager) -> i64 {
        if self.stat_path(raw_path, mem).is_ok() {
            0
        } else {
            ENOENT
        }
    }

    /// 删除虚拟 Overlay 文件
    pub fn unlink(&mut self, raw_path: &str) -> i64 {
        let path = self.normalize_path(raw_path);
        if self.overlay_files.remove(&path).is_some() {
            0
        } else {
            ENOENT
        }
    }

    /// 重命名虚拟 Overlay 文件
    pub fn rename(&mut self, old_raw: &str, new_raw: &str) -> i64 {
        let old_path = self.normalize_path(old_raw);
        let new_path = self.normalize_path(new_raw);
        if let Some(data) = self.overlay_files.remove(&old_path) {
            self.ensure_parent_dirs(&new_path);
            self.overlay_files.insert(new_path, data);
            0
        } else {
            ENOENT
        }
    }

    /// 按偏移读取 FD 内容（供 `mmap` / `pread` 使用，不改变当前文件游标）
    pub fn read_at(&self, fd: i32, offset: usize, len: usize) -> Option<Vec<u8>> {
        let file = self.fds.get(&fd)?;
        let src: &[u8] = match &file.kind {
            OpenFileKind::Buffer { data, .. } => data.as_slice(),
            OpenFileKind::Overlay { .. } => self.overlay_files.get(&file.path)?.as_slice(),
            _ => return None,
        };
        if offset >= src.len() {
            return Some(Vec::new());
        }
        let end = (offset + len).min(src.len());
        Some(src[offset..end].to_vec())
    }

    /// 按偏移写入 FD 内容（供 `pwrite` 使用，不改变当前文件游标）
    pub fn write_at(&mut self, fd: i32, offset: usize, bytes: &[u8]) -> i64 {
        let overlay_path = match self.fds.get(&fd) {
            Some(OpenFile {
                path,
                kind: OpenFileKind::Overlay { .. },
            }) => Some(path.clone()),
            _ => None,
        };
        if let Some(path) = overlay_path {
            let data = self.overlay_files.entry(path).or_default();
            let end = offset + bytes.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[offset..end].copy_from_slice(bytes);
            return bytes.len() as i64;
        }
        let Some(file) = self.fds.get_mut(&fd) else {
            return EBADF;
        };
        if let OpenFileKind::Buffer { data, .. } = &mut file.kind {
            let end = offset + bytes.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[offset..end].copy_from_slice(bytes);
            return bytes.len() as i64;
        }
        EBADF
    }

    /// 将 `mmap` 脏页写回 Overlay 文件（即使原 FD 已关闭也能按路径写回）
    pub fn write_at_path(&mut self, raw_path: &str, offset: usize, bytes: &[u8]) {
        let path = self.normalize_path(raw_path);
        if let Some(data) = self.overlay_files.get_mut(&path) {
            let end = offset + bytes.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[offset..end].copy_from_slice(bytes);
        }
    }

    /// 读取符号链接（如 `/proc/self/exe`）
    pub fn readlink(&self, raw_path: &str) -> Result<String, i64> {
        let path = self.normalize_path(raw_path);
        if path == "/proc/self/exe" {
            return Ok("/system/bin/app_process64".to_string());
        }
        Err(ENOENT)
    }

    /// 关闭 FD
    pub fn close(&mut self, fd: i32) -> i64 {
        if fd <= 2 {
            return 0;
        }
        if self.fds.remove(&fd).is_some() {
            0
        } else {
            EBADF
        }
    }

    /// 查询 FD 关联路径（调试日志与 `mmap` 写回用）
    pub fn fd_path(&self, fd: i32) -> Option<&str> {
        self.fds.get(&fd).map(|f| f.path.as_str())
    }
}
