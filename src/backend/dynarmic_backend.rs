//! Dynarmic ARM64 JIT 执行后端（`dynarmic = "0.1.3"`）
//!
//! 集成要点与已规避的上游深坑：
//! 1. 导出 `#[no_mangle] JitA64_HaltExecution` 垫片转发到 C++ 实际的 `JitA64_haltexecution`。
//! 2. Unix 下采用单块 4GB `mmap(PROT_NONE)` 连续虚拟保留区 + 128KB 位图作为 `page_table` 后端，
//!    彻底避免 `detect_misaligned_access_via_page_table` 漏掉 128-bit 导致的跨页 NEON 静默损坏。
//! 3. 构造 `Box<ExclusiveMonitor>` 并通过哨兵校验注入 `DynarmicConfig::global_monitor`（绕开 `dczid_el0` 笔误）。
//! 4. 仅设置 `cfg.tpidr_el0(...)`，避免调用存在笔误的 `cfg.tpidrro_el0(...)`。
//! 5. 访存故障回调触发瞬间立刻捕获 `jit.get_pc()`，退出 `jit.run()` 后还原 PC，防止漂移到 `RET_MAGIC_ADDR`。
//! 6. 严格保证 `DynarmicCpu` 字段声明顺序 `jit` 在最前，避免析构期悬垂引用。

use std::cell::UnsafeCell;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::ptr;
use std::time::{Duration, Instant};

use dynarmic::a64::{Callbacks, Config, Dynarmic, Exception, VAddr};
use dynarmic::{CallbackImpl, ExclusiveMonitor, GuestInt, HaltReason, OptimizationFlag};
use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::RegisterARM64;

use crate::backend::{BackendKind, CpuBackend, CpuContextBlob, GenericCpuContext, RunStopReason};
use crate::error::{EmuError, EmuResult};
use crate::memory::{align_down, align_up, PAGE_SIZE};

/// 坑 1 修复：dynarmic 0.1.3 C++ 导出小写 `JitA64_haltexecution`，Rust 声明大驼峰 `JitA64_HaltExecution`
///
/// # Safety
/// 仅供 `dynarmic` Rust 绑定内部经由 C ABI 调用，`this` 必须是指向有效 `A64::Jit` 实例的非空指针。
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C-unwind" fn JitA64_HaltExecution(this: *mut c_void, hr: HaltReason) {
    unsafe extern "C-unwind" {
        fn JitA64_haltexecution(this: *mut c_void, hr: HaltReason);
    }
    unsafe { JitA64_haltexecution(this, hr) };
}

/// 宿主机 OS 硬件页大小（Apple Silicon macOS 为 16KB，其余平台为 4KB；`mprotect`/`mmap(MAP_FIXED)` 必须按此对齐）
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const HOST_PAGE_SIZE: u64 = 0x4000;
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
const HOST_PAGE_SIZE: u64 = PAGE_SIZE;

/// 4GB 连续地址空间（2^32 = 1,048,576 个 4KB 页）
const ARENA_BITS: usize = 32;
const ARENA_SIZE: usize = 1usize << ARENA_BITS;
const ARENA_PAGES: usize = ARENA_SIZE / (PAGE_SIZE as usize);
const BITMAP_WORDS: usize = ARENA_PAGES / 64;

#[cfg(unix)]
mod unix_mmap {
    use std::ffi::{c_int, c_void};

    pub const PROT_NONE: c_int = 0x0;
    pub const PROT_READ: c_int = 0x1;
    pub const PROT_WRITE: c_int = 0x2;

    #[cfg(target_os = "macos")]
    pub const MAP_PRIVATE: c_int = 0x0002;
    #[cfg(target_os = "macos")]
    pub const MAP_FIXED: c_int = 0x0010;
    #[cfg(target_os = "macos")]
    pub const MAP_ANON_FLAGS: c_int = 0x1000; // MAP_ANON (macOS PROT_NONE 懒提交，无需 NORESERVE)

    #[cfg(target_os = "linux")]
    pub const MAP_PRIVATE: c_int = 0x02;
    #[cfg(target_os = "linux")]
    pub const MAP_FIXED: c_int = 0x10;
    #[cfg(target_os = "linux")]
    pub const MAP_ANON_FLAGS: c_int = 0x20 | 0x4000; // MAP_ANONYMOUS | MAP_NORESERVE

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub const MAP_PRIVATE: c_int = 0x02;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub const MAP_FIXED: c_int = 0x10;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub const MAP_ANON_FLAGS: c_int = 0x1000;

    pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

    unsafe extern "C" {
        pub fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;
        pub fn munmap(addr: *mut c_void, length: usize) -> c_int;
        pub fn mprotect(addr: *mut c_void, length: usize, prot: c_int) -> c_int;
    }
}

/// 连续 4GB 虚拟保留区 + 128KB 位图 + >4GB 溢出页表
struct MemoryArena {
    #[cfg(unix)]
    base: *mut u8,
    bitmap: Vec<u64>,
    high_pages: BTreeMap<u64, Box<[u8; 4096]>>,
    #[cfg(not(unix))]
    low_pages: BTreeMap<u64, Box<[u8; 4096]>>,
}

impl MemoryArena {
    fn new() -> EmuResult<Self> {
        #[cfg(unix)]
        let base = unsafe {
            let ptr = unix_mmap::mmap(
                ptr::null_mut(),
                ARENA_SIZE,
                unix_mmap::PROT_NONE,
                unix_mmap::MAP_PRIVATE | unix_mmap::MAP_ANON_FLAGS,
                -1,
                0,
            );
            if ptr == unix_mmap::MAP_FAILED || ptr.is_null() {
                return Err(EmuError::Backend(
                    "Dynarmic 4GB 虚拟地址保留区 mmap(PROT_NONE) 失败".to_string(),
                ));
            }
            ptr as *mut u8
        };

        Ok(Self {
            #[cfg(unix)]
            base,
            bitmap: vec![0u64; BITMAP_WORDS],
            high_pages: BTreeMap::new(),
            #[cfg(not(unix))]
            low_pages: BTreeMap::new(),
        })
    }

    #[inline]
    fn is_low_page_mapped(&self, page_idx: usize) -> bool {
        if page_idx >= ARENA_PAGES {
            return false;
        }
        (self.bitmap[page_idx >> 6] & (1u64 << (page_idx & 63))) != 0
    }

    #[inline]
    fn set_low_page_mapped(&mut self, page_idx: usize, mapped: bool) {
        let word = &mut self.bitmap[page_idx >> 6];
        let mask = 1u64 << (page_idx & 63);
        if mapped {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }

    fn map_range(
        &mut self,
        page_table: &mut [*mut c_void],
        addr: u64,
        size: u64,
    ) -> EmuResult<()> {
        let start = align_down(addr, PAGE_SIZE);
        let end = align_up(addr.saturating_add(size), PAGE_SIZE);
        if end <= start {
            return Ok(());
        }

        #[cfg(unix)]
        {
            let low_end = end.min(ARENA_SIZE as u64);
            if start < low_end {
                let host_start = align_down(start, HOST_PAGE_SIZE);
                let host_end = align_up(low_end, HOST_PAGE_SIZE).min(ARENA_SIZE as u64);
                let len = (host_end - host_start) as usize;
                let rc = unsafe {
                    unix_mmap::mprotect(
                        self.base.add(host_start as usize).cast(),
                        len,
                        unix_mmap::PROT_READ | unix_mmap::PROT_WRITE,
                    )
                };
                if rc != 0 {
                    return Err(EmuError::Backend(format!(
                        "Dynarmic mprotect(RW) 失败: addr=0x{host_start:x}, size=0x{len:x}"
                    )));
                }
                let mut cur = start;
                while cur < low_end {
                    let idx = (cur / PAGE_SIZE) as usize;
                    if !self.is_low_page_mapped(idx) {
                        // 若该 4KB 逻辑页位于已提交的 16KB 宿主页内，确保新映射页内容全零
                        unsafe {
                            ptr::write_bytes(self.base.add(cur as usize), 0, PAGE_SIZE as usize);
                        }
                    }
                    self.set_low_page_mapped(idx, true);
                    page_table[idx] = unsafe { self.base.add(cur as usize).cast() };
                    cur += PAGE_SIZE;
                }
            }
            let mut cur = start.max(ARENA_SIZE as u64);
            while cur < end {
                self.high_pages.entry(cur).or_insert_with(|| Box::new([0u8; 4096]));
                cur += PAGE_SIZE;
            }
        }

        #[cfg(not(unix))]
        {
            let mut cur = start;
            while cur < end {
                if cur < ARENA_SIZE as u64 {
                    let idx = (cur / PAGE_SIZE) as usize;
                    let ptr = self
                        .low_pages
                        .entry(cur)
                        .or_insert_with(|| Box::new([0u8; 4096]))
                        .as_mut_ptr()
                        .cast();
                    self.set_low_page_mapped(idx, true);
                    page_table[idx] = ptr;
                } else {
                    self.high_pages
                        .entry(cur)
                        .or_insert_with(|| Box::new([0u8; 4096]));
                }
                cur += PAGE_SIZE;
            }
        }

        Ok(())
    }

    fn unmap_range(
        &mut self,
        page_table: &mut [*mut c_void],
        addr: u64,
        size: u64,
    ) -> EmuResult<()> {
        let start = align_down(addr, PAGE_SIZE);
        let end = align_up(addr.saturating_add(size), PAGE_SIZE);
        if end <= start {
            return Ok(());
        }

        #[cfg(unix)]
        {
            let low_end = end.min(ARENA_SIZE as u64);
            if start < low_end {
                let mut cur = start;
                while cur < low_end {
                    let idx = (cur / PAGE_SIZE) as usize;
                    if self.is_low_page_mapped(idx) {
                        unsafe {
                            ptr::write_bytes(self.base.add(cur as usize), 0, PAGE_SIZE as usize);
                        }
                    }
                    self.set_low_page_mapped(idx, false);
                    page_table[idx] = ptr::null_mut();
                    cur += PAGE_SIZE;
                }
                let host_start = align_down(start, HOST_PAGE_SIZE);
                let host_end = align_up(low_end, HOST_PAGE_SIZE).min(ARENA_SIZE as u64);
                let sub_pages = (HOST_PAGE_SIZE / PAGE_SIZE) as usize;
                let mut h = host_start;
                while h < host_end {
                    let base_idx = (h / PAGE_SIZE) as usize;
                    let any_live = (0..sub_pages).any(|k| self.is_low_page_mapped(base_idx + k));
                    if !any_live {
                        let res = unsafe {
                            unix_mmap::mmap(
                                self.base.add(h as usize).cast(),
                                HOST_PAGE_SIZE as usize,
                                unix_mmap::PROT_NONE,
                                unix_mmap::MAP_PRIVATE
                                    | unix_mmap::MAP_FIXED
                                    | unix_mmap::MAP_ANON_FLAGS,
                                -1,
                                0,
                            )
                        };
                        if res == unix_mmap::MAP_FAILED {
                            return Err(EmuError::Backend(format!(
                                "Dynarmic unmap 归还物理页失败: addr=0x{h:x}, size=0x{HOST_PAGE_SIZE:x}"
                            )));
                        }
                    }
                    h += HOST_PAGE_SIZE;
                }
            }
            let mut cur = start.max(ARENA_SIZE as u64);
            while cur < end {
                self.high_pages.remove(&cur);
                cur += PAGE_SIZE;
            }
        }

        #[cfg(not(unix))]
        {
            let mut cur = start;
            while cur < end {
                if cur < ARENA_SIZE as u64 {
                    let idx = (cur / PAGE_SIZE) as usize;
                    self.set_low_page_mapped(idx, false);
                    page_table[idx] = ptr::null_mut();
                    self.low_pages.remove(&cur);
                } else {
                    self.high_pages.remove(&cur);
                }
                cur += PAGE_SIZE;
            }
        }

        Ok(())
    }

    fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let mut offset = 0usize;
        while offset < buf.len() {
            let cur = addr
                .checked_add(offset as u64)
                .ok_or(EmuError::UnmappedMemory {
                    addr,
                    size: buf.len(),
                })?;
            let page_base = align_down(cur, PAGE_SIZE);
            let page_off = (cur - page_base) as usize;
            let chunk = (PAGE_SIZE as usize - page_off).min(buf.len() - offset);

            if page_base < ARENA_SIZE as u64 {
                let idx = (page_base / PAGE_SIZE) as usize;
                if !self.is_low_page_mapped(idx) {
                    return Err(EmuError::UnmappedMemory {
                        addr: cur,
                        size: chunk,
                    });
                }
                #[cfg(unix)]
                unsafe {
                    ptr::copy_nonoverlapping(
                        self.base.add(cur as usize),
                        buf.as_mut_ptr().add(offset),
                        chunk,
                    );
                }
                #[cfg(not(unix))]
                {
                    let page = self
                        .low_pages
                        .get(&page_base)
                        .ok_or(EmuError::UnmappedMemory {
                            addr: cur,
                            size: chunk,
                        })?;
                    buf[offset..offset + chunk].copy_from_slice(&page[page_off..page_off + chunk]);
                }
            } else {
                let page = self
                    .high_pages
                    .get(&page_base)
                    .ok_or(EmuError::UnmappedMemory {
                        addr: cur,
                        size: chunk,
                    })?;
                buf[offset..offset + chunk].copy_from_slice(&page[page_off..page_off + chunk]);
            }
            offset += chunk;
        }
        Ok(())
    }

    fn write_bytes(&mut self, addr: u64, data: &[u8]) -> EmuResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut offset = 0usize;
        while offset < data.len() {
            let cur = addr
                .checked_add(offset as u64)
                .ok_or(EmuError::UnmappedMemory {
                    addr,
                    size: data.len(),
                })?;
            let page_base = align_down(cur, PAGE_SIZE);
            let page_off = (cur - page_base) as usize;
            let chunk = (PAGE_SIZE as usize - page_off).min(data.len() - offset);

            if page_base < ARENA_SIZE as u64 {
                let idx = (page_base / PAGE_SIZE) as usize;
                if !self.is_low_page_mapped(idx) {
                    return Err(EmuError::UnmappedMemory {
                        addr: cur,
                        size: chunk,
                    });
                }
                #[cfg(unix)]
                unsafe {
                    ptr::copy_nonoverlapping(
                        data.as_ptr().add(offset),
                        self.base.add(cur as usize),
                        chunk,
                    );
                }
                #[cfg(not(unix))]
                {
                    let page = self
                        .low_pages
                        .get_mut(&page_base)
                        .ok_or(EmuError::UnmappedMemory {
                            addr: cur,
                            size: chunk,
                        })?;
                    page[page_off..page_off + chunk]
                        .copy_from_slice(&data[offset..offset + chunk]);
                }
            } else {
                let page = self
                    .high_pages
                    .get_mut(&page_base)
                    .ok_or(EmuError::UnmappedMemory {
                        addr: cur,
                        size: chunk,
                    })?;
                page[page_off..page_off + chunk].copy_from_slice(&data[offset..offset + chunk]);
            }
            offset += chunk;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for MemoryArena {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                unix_mmap::munmap(self.base.cast(), ARENA_SIZE);
            }
        }
    }
}

struct PendingFault {
    pc: u64,
    addr: u64,
    is_write: bool,
    detail: String,
}

struct SharedState {
    arena_ptr: *mut MemoryArena,
    jit_ptr: *mut Dynarmic<'static, DynarmicCb>,
    pending_svc: Option<(u16, u64)>,
    pending_fault: Option<PendingFault>,
    pending_exception: Option<(u64, String)>,
    ticks_remaining: u64,
    deadline: Option<Instant>,
    timed_out: bool,
    stop_requested: bool,
    cntpct_base: Instant,
}

struct DynarmicCb {
    shared: *const UnsafeCell<SharedState>,
}

impl DynarmicCb {
    #[inline]
    #[allow(clippy::mut_from_ref)]
    unsafe fn state(&self) -> &mut SharedState {
        unsafe { &mut *(*self.shared).get() }
    }

    #[inline]
    unsafe fn halt_with(&self, hr: HaltReason) {
        let st = unsafe { self.state() };
        if !st.jit_ptr.is_null() {
            unsafe { (*st.jit_ptr).halt(hr) };
        }
    }

    #[inline]
    unsafe fn current_pc(&self) -> u64 {
        let st = unsafe { self.state() };
        if !st.jit_ptr.is_null() {
            unsafe { (*st.jit_ptr).get_pc() }
        } else {
            0
        }
    }
}

impl Callbacks for DynarmicCb {
    fn memory_read_code(cb: &CallbackImpl<Self>, addr: VAddr) -> Option<u32> {
        let st = unsafe { cb.state() };
        let arena = unsafe { &*st.arena_ptr };
        let mut raw = [0u8; 4];
        if arena.read_bytes(addr, &mut raw).is_ok() {
            Some(u32::from_le_bytes(raw))
        } else {
            if st.pending_fault.is_none() {
                st.pending_fault = Some(PendingFault {
                    pc: addr,
                    addr,
                    is_write: false,
                    detail: format!("Dynarmic 取指未映射内存: addr=0x{addr:016x}"),
                });
            }
            unsafe { cb.halt_with(HaltReason::MemoryAbort) };
            None
        }
    }

    extern "C" fn memory_read<T: GuestInt>(cb: &CallbackImpl<Self>, addr: VAddr) -> T {
        let st = unsafe { cb.state() };
        let arena = unsafe { &*st.arena_ptr };
        let size = std::mem::size_of::<T>();
        let mut raw = [0u8; 16];
        if arena.read_bytes(addr, &mut raw[..size]).is_ok() {
            return unsafe { ptr::read_unaligned(raw.as_ptr().cast::<T>()) };
        }
        // 坑 5 修复：回调现场立即记录真实故障 PC，避免后续同块内 ret 把 PC 改写成 RET_MAGIC_ADDR
        if st.pending_fault.is_none() {
            let pc = unsafe { cb.current_pc() };
            st.pending_fault = Some(PendingFault {
                pc,
                addr,
                is_write: false,
                detail: format!("Dynarmic 读未映射内存: addr=0x{addr:016x}, size={size}"),
            });
        }
        unsafe { cb.halt_with(HaltReason::MemoryAbort) };
        T::zero()
    }

    extern "C" fn memory_write<T: GuestInt>(cb: &mut CallbackImpl<Self>, addr: VAddr, val: T) {
        let st = unsafe { cb.state() };
        let arena = unsafe { &mut *st.arena_ptr };
        let size = std::mem::size_of::<T>();
        let mut raw = [0u8; 16];
        unsafe {
            ptr::write_unaligned(raw.as_mut_ptr().cast::<T>(), val);
        }
        if arena.write_bytes(addr, &raw[..size]).is_ok() {
            return;
        }
        if st.pending_fault.is_none() {
            let pc = unsafe { cb.current_pc() };
            st.pending_fault = Some(PendingFault {
                pc,
                addr,
                is_write: true,
                detail: format!("Dynarmic 写未映射内存: addr=0x{addr:016x}, size={size}"),
            });
        }
        unsafe { cb.halt_with(HaltReason::MemoryAbort) };
    }

    extern "C" fn memory_write_exclusive<T: GuestInt>(
        cb: &mut CallbackImpl<Self>,
        addr: VAddr,
        val: T,
        expected: T,
    ) -> bool {
        let st = unsafe { cb.state() };
        let arena = unsafe { &mut *st.arena_ptr };
        let size = std::mem::size_of::<T>();
        let mut cur_raw = [0u8; 16];
        if arena.read_bytes(addr, &mut cur_raw[..size]).is_err() {
            if st.pending_fault.is_none() {
                let pc = unsafe { cb.current_pc() };
                st.pending_fault = Some(PendingFault {
                    pc,
                    addr,
                    is_write: true,
                    detail: format!("Dynarmic 原子写未映射内存: addr=0x{addr:016x}, size={size}"),
                });
            }
            unsafe { cb.halt_with(HaltReason::MemoryAbort) };
            return false;
        }
        let cur = unsafe { ptr::read_unaligned(cur_raw.as_ptr().cast::<T>()) };
        if cur != expected {
            return false;
        }
        let mut new_raw = [0u8; 16];
        unsafe {
            ptr::write_unaligned(new_raw.as_mut_ptr().cast::<T>(), val);
        }
        arena.write_bytes(addr, &new_raw[..size]).is_ok()
    }

    extern "C" fn call_svc(cb: &mut CallbackImpl<Self>, swi: u32) {
        let st = unsafe { cb.state() };
        let next_pc = unsafe { cb.current_pc() };
        st.pending_svc = Some(((swi & 0xFFFF) as u16, next_pc));
        unsafe { cb.halt_with(HaltReason::UserDefined1) };
    }

    extern "C" fn raised_exception(cb: &mut CallbackImpl<Self>, addr: VAddr, exc: Exception) {
        match exc {
            Exception::Yield
            | Exception::WaitForEvent
            | Exception::WaitForInterrupt
            | Exception::SendEvent
            | Exception::SendEventLocal => {}
            _ => {
                let st = unsafe { cb.state() };
                if st.pending_exception.is_none() {
                    st.pending_exception = Some((addr, format!("Dynarmic({exc:?})")));
                }
                unsafe { cb.halt_with(HaltReason::UserDefined2) };
            }
        }
    }

    extern "C" fn interpreter_fallback(cb: &mut CallbackImpl<Self>, pc: VAddr, _num: usize) {
        let st = unsafe { cb.state() };
        if st.pending_exception.is_none() {
            st.pending_exception = Some((pc, format!("Dynarmic(InterpreterFallback @ 0x{pc:x})")));
        }
        unsafe { cb.halt_with(HaltReason::UserDefined2) };
    }

    extern "C" fn add_ticks(cb: &mut CallbackImpl<Self>, ticks: u64) {
        let st = unsafe { cb.state() };
        if st.ticks_remaining != u64::MAX {
            st.ticks_remaining = st.ticks_remaining.saturating_sub(ticks);
            if st.ticks_remaining == 0 {
                st.timed_out = true;
                unsafe { cb.halt_with(HaltReason::UserDefined3) };
                return;
            }
        }
        if let Some(deadline) = st.deadline {
            if Instant::now() >= deadline {
                st.timed_out = true;
                unsafe { cb.halt_with(HaltReason::UserDefined3) };
            }
        }
    }

    extern "C" fn get_ticks_remaining(cb: &CallbackImpl<Self>) -> u64 {
        let st = unsafe { cb.state() };
        if st.stop_requested || st.timed_out {
            0
        } else if st.ticks_remaining == u64::MAX {
            1_000_000
        } else {
            st.ticks_remaining
        }
    }

    extern "C" fn get_cntpct(cb: &CallbackImpl<Self>) -> u64 {
        let st = unsafe { cb.state() };
        st.cntpct_base.elapsed().as_nanos() as u64 / 16
    }
}

/// 坑 3 修复：通过 `cntfrq_el0` + `ctr_el0` 哨兵定位 `DynarmicConfig::global_monitor` 并注入 `ExclusiveMonitor`
///
/// 绝不调用上游存在笔误的 `cfg.dczid_el0(...)`，仅验证默认 `dczid_el0 == 4` 且 `processor_id == 0 && global_monitor == null`。
fn inject_global_monitor<T: Callbacks>(
    cfg: &mut Config<'_, T>,
    monitor_ptr: *mut ExclusiveMonitor,
) -> EmuResult<()> {
    const SENTINEL_CNTFRQ: u32 = 0x5A17_C0DE;
    const SENTINEL_CTR: u32 = 0xA538_1234;
    const DEFAULT_CNTFRQ: u32 = 600_000_000;
    const DEFAULT_CTR: u32 = 0x8444_C004;
    const DEFAULT_DCZID: u32 = 4;

    cfg.cntfrq_el0(SENTINEL_CNTFRQ).ctr_el0(SENTINEL_CTR);

    let cfg_ptr = (cfg as *mut Config<'_, T>).cast::<u8>();
    let cfg_len = std::mem::size_of::<Config<'_, T>>();
    let mut injected = false;

    unsafe {
        let bytes = std::slice::from_raw_parts_mut(cfg_ptr, cfg_len);
        // DynarmicConfig #[repr(C)] 布局（64-bit）：
        // +0x00 callbacks (*mut)
        // +0x08 processor_id (usize)
        // +0x10 global_monitor (*mut ExclusiveMonitor)
        // +0x18 optimizations (u32) + 4 bools
        // +0x20 cntfrq_el0 (u32), +0x24 ctr_el0 (u32), +0x28 dczid_el0 (u32)
        let mut off = 0x20usize;
        while off + 12 <= cfg_len {
            let w0 = u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
            let w1 = u32::from_ne_bytes(bytes[off + 4..off + 8].try_into().unwrap());
            let w2 = u32::from_ne_bytes(bytes[off + 8..off + 12].try_into().unwrap());
            if w0 == SENTINEL_CNTFRQ && w1 == SENTINEL_CTR && w2 == DEFAULT_DCZID {
                let proc_off = off - 0x18;
                let gm_off = off - 0x10;
                let proc_id = ptr::read_unaligned(cfg_ptr.add(proc_off).cast::<usize>());
                let cur_gm =
                    ptr::read_unaligned(cfg_ptr.add(gm_off).cast::<*mut ExclusiveMonitor>());
                if proc_id == 0 && cur_gm.is_null() {
                    ptr::write_unaligned(
                        cfg_ptr.add(gm_off).cast::<*mut ExclusiveMonitor>(),
                        monitor_ptr,
                    );
                    injected = true;
                    break;
                }
            }
            off += 4;
        }
    }

    cfg.cntfrq_el0(DEFAULT_CNTFRQ).ctr_el0(DEFAULT_CTR);

    if !injected {
        return Err(EmuError::Backend(
            "无法定位 DynarmicConfig::global_monitor 槽位（请确认 dynarmic 版本为 0.1.3）"
                .to_string(),
        ));
    }
    Ok(())
}

/// Dynarmic ARM64 JIT CPU 实例
///
/// **Drop 顺序铁律**：`jit` 必须位于第一个字段，确保先销毁 C++ JIT 再释放 page_table / arena / monitor / tpidr / shared。
pub struct DynarmicCpu {
    jit: Box<Dynarmic<'static, DynarmicCb>>,
    page_table: Box<[*mut c_void]>,
    arena: Box<MemoryArena>,
    _exclusive_monitor: Box<ExclusiveMonitor>,
    tpidr_el0: Box<u64>,
    shared: Box<UnsafeCell<SharedState>>,
}

impl DynarmicCpu {
    pub fn new() -> EmuResult<Self> {
        let mut arena = Box::new(MemoryArena::new()?);
        let mut page_table = vec![ptr::null_mut::<c_void>(); ARENA_PAGES].into_boxed_slice();
        let mut exclusive_monitor = Box::new(ExclusiveMonitor::new(1));
        let mut tpidr_el0 = Box::new(0u64);
        let shared = Box::new(UnsafeCell::new(SharedState {
            arena_ptr: arena.as_mut() as *mut MemoryArena,
            jit_ptr: ptr::null_mut(),
            pending_svc: None,
            pending_fault: None,
            pending_exception: None,
            ticks_remaining: u64::MAX,
            deadline: None,
            timed_out: false,
            stop_requested: false,
            cntpct_base: Instant::now(),
        }));

        let mut cfg = Dynarmic::<DynarmicCb>::new_config();
        cfg.optimizations(OptimizationFlag::ALL)
            .unsafe_optimization(false)
            .cycle_counting(true)
            .code_cache_size(64 * 1024 * 1024);

        // 坑 3 修复：注入 ExclusiveMonitor
        inject_global_monitor(&mut cfg, exclusive_monitor.as_mut() as *mut ExclusiveMonitor)?;

        // 坑 4 修复：只设 tpidr_el0，绝不调用存在上游笔误的 tpidrro_el0
        unsafe {
            let tpidr_static: &'static mut u64 = &mut *(tpidr_el0.as_mut() as *mut u64);
            cfg.tpidr_el0(tpidr_static);
            cfg.page_table(page_table.as_mut_ptr(), ARENA_BITS, false);
        }

        let cb = DynarmicCb {
            shared: shared.as_ref() as *const UnsafeCell<SharedState>,
        };
        let mut jit = Box::new(cfg.init(cb));
        unsafe {
            (*shared.get()).jit_ptr = jit.as_mut() as *mut Dynarmic<'static, DynarmicCb>;
        }

        Ok(Self {
            jit,
            page_table,
            arena,
            _exclusive_monitor: exclusive_monitor,
            tpidr_el0,
            shared,
        })
    }

    /// 运行一段 Guest 代码直到触发 SVC / 异常 / 故障 / 超时
    pub fn run_until_trap(
        &mut self,
        start_pc: u64,
        timeout_us: u64,
        max_instructions: usize,
    ) -> RunStopReason {
        {
            let st = unsafe { &mut *self.shared.get() };
            st.pending_svc = None;
            st.pending_fault = None;
            st.pending_exception = None;
            st.timed_out = false;
            st.stop_requested = false;
            st.ticks_remaining = if max_instructions > 0 {
                max_instructions as u64
            } else {
                u64::MAX
            };
            st.deadline = if timeout_us > 0 {
                Some(Instant::now() + Duration::from_micros(timeout_us))
            } else {
                None
            };
        }

        self.jit.set_pc(start_pc);

        loop {
            self.jit.clear_halt(HaltReason::MemoryAbort);
            self.jit.clear_halt(HaltReason::UserDefined1);
            self.jit.clear_halt(HaltReason::UserDefined2);
            self.jit.clear_halt(HaltReason::UserDefined3);

            let _hr = unsafe { self.jit.run() };

            let st = unsafe { &mut *self.shared.get() };
            if let Some(fault) = st.pending_fault.take() {
                // 坑 5 修复：还原真实故障 PC（而非同块后续 ret 产生的 RET_MAGIC_ADDR）
                self.jit.set_pc(fault.pc);
                return RunStopReason::MemoryFault {
                    pc: fault.pc,
                    addr: fault.addr,
                    is_write: fault.is_write,
                    detail: fault.detail,
                };
            }
            if let Some((imm, next_pc)) = st.pending_svc.take() {
                return RunStopReason::Svc { imm, next_pc };
            }
            if let Some((exc_pc, detail)) = st.pending_exception.take() {
                self.jit.set_pc(exc_pc);
                return RunStopReason::IllegalInstruction { pc: exc_pc, detail };
            }
            if st.stop_requested {
                return RunStopReason::Stopped;
            }
            if st.timed_out {
                return RunStopReason::Timeout {
                    pc: self.jit.get_pc(),
                };
            }
            if let Some(deadline) = st.deadline {
                if Instant::now() >= deadline {
                    return RunStopReason::Timeout {
                        pc: self.jit.get_pc(),
                    };
                }
            }
            // 普通时间片耗尽（1M ticks），继续从当前 PC 跑下一个时间片
        }
    }
}

fn reg_to_gpr_index(reg: RegisterARM64) -> Option<usize> {
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

fn reg_to_d_index(reg: RegisterARM64) -> Option<usize> {
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

impl CpuBackend for DynarmicCpu {
    fn kind(&self) -> BackendKind {
        BackendKind::Dynarmic
    }

    fn reg_read(&self, reg: RegisterARM64) -> EmuResult<u64> {
        if let Some(i) = reg_to_gpr_index(reg) {
            return Ok(self.jit.get_reg(i));
        }
        if let Some(i) = reg_to_d_index(reg) {
            return Ok(self.jit.get_vector(i) as u64);
        }
        match reg {
            RegisterARM64::SP => Ok(self.jit.get_sp()),
            RegisterARM64::PC => Ok(self.jit.get_pc()),
            RegisterARM64::NZCV | RegisterARM64::PSTATE => Ok(u64::from(self.jit.get_pstate())),
            RegisterARM64::TPIDR_EL0 => Ok(*self.tpidr_el0),
            RegisterARM64::FPCR => Ok(u64::from(self.jit.get_fpcr())),
            RegisterARM64::FPSR => Ok(u64::from(self.jit.get_fpsr())),
            _ => Ok(0),
        }
    }

    fn reg_write(&mut self, reg: RegisterARM64, val: u64) -> EmuResult<()> {
        if let Some(i) = reg_to_gpr_index(reg) {
            self.jit.set_reg(i, val);
            return Ok(());
        }
        if let Some(i) = reg_to_d_index(reg) {
            let cur = self.jit.get_vector(i);
            let next = (cur & !0xFFFF_FFFF_FFFF_FFFFu128) | u128::from(val);
            self.jit.set_vector(i, next);
            return Ok(());
        }
        match reg {
            RegisterARM64::SP => self.jit.set_sp(val),
            RegisterARM64::PC => self.jit.set_pc(val),
            RegisterARM64::NZCV | RegisterARM64::PSTATE => self.jit.set_pstate(val as u32),
            RegisterARM64::TPIDR_EL0 => *self.tpidr_el0 = val,
            RegisterARM64::FPCR => self.jit.set_fpcr(val as u32),
            RegisterARM64::FPSR => self.jit.set_fpsr(val as u32),
            _ => {}
        }
        Ok(())
    }

    fn reg_read_q(&self, idx: u8) -> EmuResult<u128> {
        Ok(self.jit.get_vector(usize::from(idx & 31)))
    }

    fn reg_write_q(&mut self, idx: u8, val: u128) -> EmuResult<()> {
        self.jit.set_vector(usize::from(idx & 31), val);
        Ok(())
    }

    fn mem_read(&self, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        self.arena.read_bytes(addr, buf)
    }

    fn mem_write(&mut self, addr: u64, data: &[u8]) -> EmuResult<()> {
        self.arena.write_bytes(addr, data)
    }

    fn mem_map(&mut self, addr: u64, size: u64, _prot: Prot) -> EmuResult<()> {
        self.arena.map_range(&mut self.page_table, addr, size)
    }

    fn mem_unmap(&mut self, addr: u64, size: u64) -> EmuResult<()> {
        self.arena.unmap_range(&mut self.page_table, addr, size)?;
        self.jit.invalidate_cache_range(addr, size as usize);
        Ok(())
    }

    fn mem_protect(&mut self, _addr: u64, _size: u64, _prot: Prot) -> EmuResult<()> {
        Ok(())
    }

    fn flush_cache(&mut self, begin: u64, end: u64) -> EmuResult<()> {
        if end > begin {
            self.jit
                .invalidate_cache_range(begin, (end - begin) as usize);
        } else {
            self.jit.clear_cache();
            self.jit.clear_exclusive_state();
        }
        Ok(())
    }

    fn run_simple(&mut self, begin: u64, until: u64, timeout_us: u64, count: usize) -> EmuResult<()> {
        let mut pc = begin;
        let max_steps = if count > 0 { count } else { usize::MAX };
        for _ in 0..max_steps {
            if pc == until {
                return Ok(());
            }
            self.jit.set_pc(pc);
            let _ = self.jit.step();
            pc = self.jit.get_pc();
            if timeout_us > 0 {
                // run_simple 仅用于短初始化片段
                break;
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> EmuResult<()> {
        unsafe {
            (*self.shared.get()).stop_requested = true;
        }
        self.jit.halt(HaltReason::UserDefined3);
        Ok(())
    }

    fn is_stop_requested(&self) -> bool {
        unsafe { (*self.shared.get()).stop_requested }
    }

    fn capture_context(&self) -> EmuResult<CpuContextBlob> {
        Ok(CpuContextBlob::Generic(Box::new(GenericCpuContext {
            x: self.jit.get_regs(),
            sp: self.jit.get_sp(),
            pc: self.jit.get_pc(),
            pstate: u64::from(self.jit.get_pstate()),
            tpidr_el0: *self.tpidr_el0,
            q: self.jit.get_vectors(),
            fpcr: self.jit.get_fpcr(),
            fpsr: self.jit.get_fpsr(),
        })))
    }

    fn restore_context(&mut self, ctx: &CpuContextBlob) -> EmuResult<()> {
        match ctx {
            CpuContextBlob::Generic(g) => {
                self.jit.set_regs(&g.x);
                self.jit.set_sp(g.sp);
                self.jit.set_pc(g.pc);
                self.jit.set_pstate(g.pstate as u32);
                *self.tpidr_el0 = g.tpidr_el0;
                self.jit.set_vectors(&g.q);
                self.jit.set_fpcr(g.fpcr);
                self.jit.set_fpsr(g.fpsr);
                self.jit.clear_exclusive_state();
                Ok(())
            }
            CpuContextBlob::Unicorn(_) => Err(EmuError::Backend(
                "不能将 Unicorn 快照恢复到 Dynarmic 后端".to_string(),
            )),
        }
    }
}
