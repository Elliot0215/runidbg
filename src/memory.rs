use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use unicorn_engine::unicorn_const::Prot;
use crate::backend::CpuBackend;

use crate::error::{EmuError, EmuResult};

/// ARM64 标准页大小（4KB）
pub const PAGE_SIZE: u64 = 0x1000;

/// 匿名 mmap 默认分配区间（与 HEAP_BASE 错开，位于 0x5800_0000..0x6000_0000）
pub const MMAP_BASE: u64 = 0x5800_0000;
pub const MMAP_LIMIT: u64 = 0x6000_0000;
/// 宿主脚本/探测缓冲隔离区（64MB，位于 0x6400_0000..0x6800_0000，惰性映射，开启 `freezeLayout` 或调用 `allocScratch` 时使用，零干扰 guest `[heap]`）
pub const HOST_SCRATCH_BASE: u64 = 0x6400_0000;
pub const HOST_SCRATCH_SIZE: u64 = 0x0400_0000;
const MAX_HEAP_ALLOC_LOG: usize = 65_536;

/// Guest 堆分配历史条目（供 `emu.mem.heapLayout()` 诊断跨跑堆布局漂移）
#[derive(Debug, Clone)]
pub struct HeapAllocRecord {
    pub seq: u64,
    pub ptr: u64,
    pub size: u64,
    pub caller_pc: u64,
    pub op: &'static str,
    pub freed: bool,
}

/// 堆块头部魔数与大小（16 字节对齐，供 HLE malloc/realloc/free 记录块元数据）
const HEAP_BLOCK_MAGIC: u64 = 0x4845_4150_424C_4B31; // "HEAPBLK1"
const HEAP_HEADER_SIZE: u64 = 16;

/// 向下对齐到指定 2 的幂次边界
/// 原理：利用位掩码 `!(align - 1)` 清除低位偏移，例如 align=0x1000 时清零低 12 位
#[inline]
pub const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

/// 向上对齐到指定 2 的幂次边界
/// 原理：先加 `align - 1` 触发进位，再用 `!(align - 1)` 截断低位，避免分支判断
#[inline]
pub const fn align_up(size: u64, align: u64) -> u64 {
    (size + align - 1) & !(align - 1)
}

/// 虚拟内存映射区间元数据（用于 MMU 管理与合成 `/proc/self/maps`）
#[derive(Debug, Clone)]
pub struct VmaRegion {
    pub start: u64,
    pub end: u64,
    pub perms: Prot,
    pub label: String,
    pub file_offset: u64,
}

impl VmaRegion {
    /// 格式化为标准 Linux `/proc/self/maps` 权限字段（如 `r-xp`、`rw-p`）
    fn perms_str(&self) -> String {
        let r = if (self.perms.0 & Prot::READ.0) != 0 { 'r' } else { '-' };
        let w = if (self.perms.0 & Prot::WRITE.0) != 0 { 'w' } else { '-' };
        let x = if (self.perms.0 & Prot::EXEC.0) != 0 { 'x' } else { '-' };
        format!("{r}{w}{x}p")
    }
}

/// 带空闲块合并（Coalescing Free-List）的模拟堆分配器
/// 保留 `BumpAllocator` 类型名以兼容已有导出 API；支持 `free()` 真实回收复用与前后空闲块合并，
/// 防止 `serve` 常驻多轮调用时堆游标单向耗尽。
#[derive(Debug, Clone)]
pub struct BumpAllocator {
    base: u64,
    size: u64,
    cursor: u64,
    /// 按地址有序的空闲块表：`start -> size`（始终保持相邻块已合并）
    free_blocks: BTreeMap<u64, u64>,
    /// 当前存活的已分配块表：`start -> size`（防重复 free 与越界 free）
    allocated: BTreeMap<u64, u64>,
    /// 当前实际存活的已分配字节数
    in_use: u64,
}

impl BumpAllocator {
    pub const fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            cursor: base,
            free_blocks: BTreeMap::new(),
            allocated: BTreeMap::new(),
            in_use: 0,
        }
    }

    /// 按指定对齐要求分配内存（优先复用空闲链表中合适块，不足时再推进游标）
    pub fn alloc(&mut self, size: u64, align: u64) -> EmuResult<u64> {
        let align = align.max(1).next_power_of_two();
        let alloc_size = align_up(size.max(1), 16);

        // 1. 优先从 free_blocks 查找满足对齐与大小的空闲块（Best-Fit 降低碎片）
        let mut best: Option<(u64, u64, u64)> = None; // (block_start, block_size, aligned_start)
        for (&b_start, &b_size) in &self.free_blocks {
            let aligned = align_up(b_start, align);
            let b_end = b_start.saturating_add(b_size);
            let req_end = aligned.saturating_add(alloc_size);
            if req_end <= b_end {
                let waste = b_size - alloc_size;
                if best.is_none_or(|(_, prev_sz, _)| b_size < prev_sz) {
                    best = Some((b_start, b_size, aligned));
                    if waste == 0 {
                        break;
                    }
                }
            }
        }

        if let Some((b_start, b_size, aligned)) = best {
            self.free_blocks.remove(&b_start);
            let b_end = b_start + b_size;
            let req_end = aligned + alloc_size;
            // 前置对齐空隙放回空闲表
            if aligned > b_start {
                self.free_blocks.insert(b_start, aligned - b_start);
            }
            // 后置剩余块 >= 16 字节则切分放回空闲表，否则并入本次分配避免极小碎片
            let actual_size = if b_end - req_end >= 16 {
                self.free_blocks.insert(req_end, b_end - req_end);
                alloc_size
            } else {
                b_end - aligned
            };
            self.allocated.insert(aligned, actual_size);
            self.in_use = self.in_use.saturating_add(actual_size);
            return Ok(aligned);
        }

        // 2. 空闲链表无可用块时，从线性前沿 cursor 分配
        let aligned = align_up(self.cursor, align);
        let end = aligned.saturating_add(alloc_size);
        let limit = self.base + self.size;

        if end > limit {
            return Err(EmuError::OutOfMemory {
                requested: size,
                available: limit.saturating_sub(self.cursor),
            });
        }

        // 若因高对齐跳过了前段空隙，顺手纳入空闲表供小块复用
        if aligned > self.cursor && aligned - self.cursor >= 16 {
            self.insert_and_coalesce(self.cursor, aligned - self.cursor);
        }

        self.cursor = end;
        self.allocated.insert(aligned, alloc_size);
        self.in_use = self.in_use.saturating_add(alloc_size);
        Ok(aligned)
    }

    /// 回收先前分配的块并与前后相邻空闲块自动合并；若触达堆顶则同步回缩 `cursor`
    pub fn free(&mut self, ptr: u64) -> bool {
        let Some(block_size) = self.allocated.remove(&ptr) else {
            return false;
        };
        self.in_use = self.in_use.saturating_sub(block_size);
        self.insert_and_coalesce(ptr, block_size);
        true
    }

    fn insert_and_coalesce(&mut self, mut start: u64, mut size: u64) {
        // 向前合并
        if let Some((&prev_start, &prev_size)) = self.free_blocks.range(..start).next_back() {
            if prev_start.saturating_add(prev_size) == start {
                self.free_blocks.remove(&prev_start);
                start = prev_start;
                size = size.saturating_add(prev_size);
            }
        }
        // 向后合并
        let end = start.saturating_add(size);
        if let Some(&next_size) = self.free_blocks.get(&end) {
            self.free_blocks.remove(&end);
            size = size.saturating_add(next_size);
        }
        // 若合并后的空闲块紧贴 cursor，直接回缩前沿
        if start.saturating_add(size) == self.cursor {
            self.cursor = start;
        } else {
            self.free_blocks.insert(start, size);
        }
    }

    pub const fn base(&self) -> u64 {
        self.base
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    /// 当前实际存活字节数（已扣除 `free()` 回收部分）
    pub const fn used(&self) -> u64 {
        self.in_use
    }

    /// 堆游标水位（距堆基址的高水位偏移）
    pub const fn high_water_mark(&self) -> u64 {
        self.cursor - self.base
    }

    pub(crate) fn export_raw(&self) -> BumpAllocatorRaw {
        BumpAllocatorRaw {
            base: self.base,
            size: self.size,
            cursor: self.cursor,
            free_blocks: self.free_blocks.iter().map(|(&k, &v)| (k, v)).collect(),
            allocated: self.allocated.iter().map(|(&k, &v)| (k, v)).collect(),
            in_use: self.in_use,
        }
    }

    pub(crate) fn from_raw(raw: BumpAllocatorRaw) -> Self {
        Self {
            base: raw.base,
            size: raw.size,
            cursor: raw.cursor,
            free_blocks: raw.free_blocks.into_iter().collect(),
            allocated: raw.allocated.into_iter().collect(),
            in_use: raw.in_use,
        }
    }
}

/// 堆分配器原始字段快照（供 `.rtape` 编解码使用）
#[derive(Debug, Clone)]
pub(crate) struct BumpAllocatorRaw {
    pub base: u64,
    pub size: u64,
    pub cursor: u64,
    pub free_blocks: Vec<(u64, u64)>,
    pub allocated: Vec<(u64, u64)>,
    pub in_use: u64,
}

/// 模拟堆元数据快照（供 `EmuSnapshot` 完整保存与恢复堆状态，含 `[host-scratch]` 隔离区）
#[derive(Debug, Clone)]
pub struct HeapSnapshot {
    pub heap: BumpAllocator,
    pub brk_cursor: u64,
    pub mmap_cursor: u64,
    pub host_scratch: BumpAllocator,
    pub host_scratch_mapped_end: u64,
    pub freeze_layout: bool,
    pub heap_alloc_log: VecDeque<HeapAllocRecord>,
    pub next_alloc_seq: u64,
}

/// 模拟器 MMU 内存管理器
/// 负责 4KB 页对齐映射、区间表维护、mmap/munmap/mprotect/brk、安全读写以及模拟堆管理
pub struct MemoryManager {
    /// 已映射的 4KB 页基址集合（防止相邻 ELF Segment 共享页边界时重复 map 触发 UC_ERR_MAP）
    mapped_pages: BTreeSet<u64>,
    /// 有序虚拟内存区间表（key = 区间起始页地址），用于 `/proc/self/maps` 合成与权限追踪
    regions: BTreeMap<u64, VmaRegion>,
    /// 内置 Bump Allocator（托管 `[heap]` 空间）
    heap: BumpAllocator,
    /// `brk` 当前堆顶指针
    brk_cursor: u64,
    /// 匿名 `mmap` 下一个分配游标
    mmap_cursor: u64,
    /// 宿主侧探测/临时缓冲隔离分配器（`HOST_SCRATCH_BASE`，不扰动 guest `[heap]`）
    host_scratch: BumpAllocator,
    host_scratch_mapped_end: u64,
    /// 是否冻结 guest 堆布局（为 true 时，宿主 `emu.mem.alloc` 自动路由至 `host_scratch`）
    freeze_layout: bool,
    /// Guest HLE 堆分配/释放记录（O(1) 环形淘汰，供 `heapLayout()` 指纹排查）
    heap_alloc_log: VecDeque<HeapAllocRecord>,
    /// 活跃分配地址到 `heap_alloc_log` 首条 seq 偏移索引（`ptr -> seq`，用于 O(1) `record_heap_free`）
    active_heap_allocs: HashMap<u64, u64>,
    next_alloc_seq: u64,
    /// 虚拟内存布局变更代际（每次 map/mmap/munmap/mprotect/restore_from_tape 递增，供微快照校验）
    layout_epoch: u64,
}

impl MemoryManager {
    pub fn new(heap_base: u64, heap_size: u64) -> Self {
        let aligned_base = align_down(heap_base, PAGE_SIZE);
        let aligned_size = align_up(heap_size, PAGE_SIZE);
        Self {
            mapped_pages: BTreeSet::new(),
            regions: BTreeMap::new(),
            heap: BumpAllocator::new(aligned_base, aligned_size),
            brk_cursor: aligned_base,
            mmap_cursor: MMAP_BASE,
            host_scratch: BumpAllocator::new(HOST_SCRATCH_BASE, HOST_SCRATCH_SIZE),
            host_scratch_mapped_end: HOST_SCRATCH_BASE,
            freeze_layout: false,
            heap_alloc_log: VecDeque::new(),
            active_heap_allocs: HashMap::new(),
            next_alloc_seq: 1,
            layout_epoch: 0,
        }
    }

    /// 初始化并向 Unicorn 映射模拟堆区域（RW 权限）
    pub fn init_heap<B: CpuBackend + ?Sized>(&mut self, uc: &mut B) -> EmuResult<()> {
        self.map_labeled(
            uc,
            self.heap.base(),
            self.heap.size(),
            Prot::READ | Prot::WRITE,
            "[heap]",
            0,
        )?;
        self.brk_cursor = self.heap.base();
        Ok(())
    }

    /// 4KB 页对齐映射内存（默认匿名标签 `[anon]`）
    pub fn map_aligned<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        addr: u64,
        size: u64,
        perms: Prot,
    ) -> EmuResult<(u64, u64)> {
        self.map_labeled(uc, addr, size, perms, "[anon]", 0)
    }

    /// 4KB 页对齐映射内存并记录 VMA 元数据（用于 `/proc/self/maps` 合成）
    pub fn map_labeled<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        addr: u64,
        size: u64,
        perms: Prot,
        label: impl Into<String>,
        file_offset: u64,
    ) -> EmuResult<(u64, u64)> {
        if size == 0 {
            return Ok((align_down(addr, PAGE_SIZE), 0));
        }

        let start = align_down(addr, PAGE_SIZE);
        let end = align_up(addr + size, PAGE_SIZE);
        let label_str = label.into();

        // 按连续未映射区间合并调用 mem_map，减少 FFI 调用次数
        let mut widened_pages = Vec::new();
        let mut cur = start;
        while cur < end {
            if self.mapped_pages.contains(&cur) {
                // 该页已被前一个 Segment 映射，放宽权限确保可写可执行（同步在 VMA 表中保留共享页 RWX 权限，避免磁带恢复降级）
                uc.mem_protect(cur, PAGE_SIZE, Prot::ALL)?;
                widened_pages.push(cur);
                cur += PAGE_SIZE;
                continue;
            }

            let run_start = cur;
            while cur < end && !self.mapped_pages.contains(&cur) {
                self.mapped_pages.insert(cur);
                cur += PAGE_SIZE;
            }
            let run_size = cur - run_start;
            uc.mem_map(run_start, run_size, perms)?;
        }

        self.record_vma(VmaRegion {
            start,
            end,
            perms,
            label: label_str,
            file_offset: align_down(file_offset, PAGE_SIZE),
        });
        for wp in widened_pages {
            self.widen_vma_page_perms(wp, Prot::ALL);
        }
        self.layout_epoch = self.layout_epoch.wrapping_add(1);

        Ok((start, end - start))
    }

    /// 模拟 Linux `mmap`：当 `hint_addr == 0` 时从匿名映射池自动分配空闲区间
    pub fn mmap<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        hint_addr: u64,
        size: u64,
        perms: Prot,
        label: impl Into<String>,
        file_offset: u64,
    ) -> EmuResult<u64> {
        let aligned_size = align_up(size.max(PAGE_SIZE), PAGE_SIZE);
        let target_addr = if hint_addr == 0 {
            let addr = align_up(self.mmap_cursor, PAGE_SIZE);
            let next = addr.saturating_add(aligned_size);
            if next > MMAP_LIMIT {
                return Err(EmuError::OutOfMemory {
                    requested: aligned_size,
                    available: MMAP_LIMIT.saturating_sub(addr),
                });
            }
            self.mmap_cursor = next;
            addr
        } else {
            align_down(hint_addr, PAGE_SIZE)
        };

        self.map_labeled(uc, target_addr, aligned_size, perms, label, file_offset)?;
        Ok(target_addr)
    }

    /// 模拟 Linux `munmap`：解除指定页范围映射并清理 VMA 元数据
    pub fn munmap<B: CpuBackend + ?Sized>(&mut self, uc: &mut B, addr: u64, size: u64) -> EmuResult<()> {
        if size == 0 {
            return Ok(());
        }
        let start = align_down(addr, PAGE_SIZE);
        let end = align_up(addr + size, PAGE_SIZE);

        let mut cur = start;
        while cur < end {
            if self.mapped_pages.remove(&cur) {
                let run_start = cur;
                cur += PAGE_SIZE;
                while cur < end && self.mapped_pages.remove(&cur) {
                    cur += PAGE_SIZE;
                }
                uc.mem_unmap(run_start, cur - run_start)?;
            } else {
                cur += PAGE_SIZE;
            }
        }

        self.remove_vma_range(start, end);
        self.layout_epoch = self.layout_epoch.wrapping_add(1);
        Ok(())
    }

    /// 模拟 Linux `mprotect`：修改已映射页的读写执行权限并同步更新 VMA 区间
    pub fn mprotect<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        addr: u64,
        size: u64,
        perms: Prot,
    ) -> EmuResult<()> {
        if size == 0 {
            return Ok(());
        }
        let start = align_down(addr, PAGE_SIZE);
        let end = align_up(addr + size, PAGE_SIZE);

        uc.mem_protect(start, end - start, perms)?;

        // 更新受影响区间的权限（支持区间分裂）
        let overlapping: Vec<VmaRegion> = self
            .regions
            .values()
            .filter(|r| r.start < end && r.end > start)
            .cloned()
            .collect();

        for r in overlapping {
            self.regions.remove(&r.start);
            if r.start < start {
                self.regions.insert(
                    r.start,
                    VmaRegion {
                        end: start,
                        ..r.clone()
                    },
                );
            }
            let mid_start = r.start.max(start);
            let mid_end = r.end.min(end);
            self.regions.insert(
                mid_start,
                VmaRegion {
                    start: mid_start,
                    end: mid_end,
                    perms,
                    label: r.label.clone(),
                    file_offset: r.file_offset + (mid_start - r.start),
                },
            );
            if r.end > end {
                self.regions.insert(
                    end,
                    VmaRegion {
                        start: end,
                        file_offset: r.file_offset + (end - r.start),
                        ..r
                    },
                );
            }
        }
        self.layout_epoch = self.layout_epoch.wrapping_add(1);

        Ok(())
    }

    /// 模拟 Linux `brk` 系统调用：查询或扩展堆边界
    pub fn brk(&mut self, new_brk: u64) -> u64 {
        let heap_start = self.heap.base();
        let heap_end = self.heap.base() + self.heap.size();
        if new_brk == 0 || new_brk < heap_start || new_brk > heap_end {
            return self.brk_cursor;
        }
        self.brk_cursor = new_brk;
        self.brk_cursor
    }

    /// 合成标准 Linux `/proc/self/maps` 内容（供反调试与 VFS 动态返回）
    pub fn format_proc_maps(&self) -> String {
        let mut out = String::new();
        for r in self.regions.values() {
            out.push_str(&format!(
                "{:08x}-{:08x} {} {:08x} 00:00 0          {}\n",
                r.start,
                r.end,
                r.perms_str(),
                r.file_offset,
                r.label
            ));
        }
        out
    }

    /// 查询所有已记录的 VMA 区间
    pub fn regions(&self) -> impl Iterator<Item = &VmaRegion> {
        self.regions.values()
    }

    fn record_vma(&mut self, new_vma: VmaRegion) {
        self.remove_vma_range(new_vma.start, new_vma.end);
        self.regions.insert(new_vma.start, new_vma);
    }

    /// 将单个共享 4KB 页在 VMA 表中拆分并合并权限（确保相邻 ELF PT_LOAD 共享页权限在快照/磁带中不降级）
    fn widen_vma_page_perms(&mut self, page_start: u64, extra_perms: Prot) {
        let page_end = page_start + PAGE_SIZE;
        let overlapping: Vec<VmaRegion> = self
            .regions
            .values()
            .filter(|r| r.start < page_end && r.end > page_start)
            .cloned()
            .collect();
        for r in overlapping {
            let merged = Prot(r.perms.0 | extra_perms.0);
            if merged == r.perms {
                continue;
            }
            self.regions.remove(&r.start);
            if r.start < page_start {
                self.regions.insert(
                    r.start,
                    VmaRegion {
                        end: page_start,
                        ..r.clone()
                    },
                );
            }
            let mid_start = r.start.max(page_start);
            let mid_end = r.end.min(page_end);
            self.regions.insert(
                mid_start,
                VmaRegion {
                    start: mid_start,
                    end: mid_end,
                    perms: merged,
                    label: r.label.clone(),
                    file_offset: r.file_offset + (mid_start - r.start),
                },
            );
            if r.end > page_end {
                self.regions.insert(
                    page_end,
                    VmaRegion {
                        start: page_end,
                        file_offset: r.file_offset + (page_end - r.start),
                        ..r
                    },
                );
            }
        }
    }

    fn remove_vma_range(&mut self, start: u64, end: u64) {
        let overlapping: Vec<VmaRegion> = self
            .regions
            .values()
            .filter(|r| r.start < end && r.end > start)
            .cloned()
            .collect();
        for r in overlapping {
            self.regions.remove(&r.start);
            if r.start < start {
                self.regions.insert(
                    r.start,
                    VmaRegion {
                        end: start,
                        ..r.clone()
                    },
                );
            }
            if r.end > end {
                self.regions.insert(
                    end,
                    VmaRegion {
                        start: end,
                        file_offset: r.file_offset + (end - r.start),
                        ..r
                    },
                );
            }
        }
        self.layout_epoch = self.layout_epoch.wrapping_add(1);
    }

    /// 从模拟堆中分配一块内存（默认 16 字节对齐）
    pub fn alloc_heap(&mut self, size: u64) -> EmuResult<u64> {
        self.heap.alloc(size, 16)
    }

    /// 从模拟堆中按自定义对齐分配内存
    pub fn alloc_heap_aligned(&mut self, size: u64, align: u64) -> EmuResult<u64> {
        self.heap.alloc(size, align)
    }

    /// 释放由 `alloc_heap` / `alloc_heap_aligned` 或 `alloc_host_scratch` 分配的原始堆块
    pub fn free_heap(&mut self, ptr: u64) -> bool {
        if ptr == 0 {
            return false;
        }
        if (HOST_SCRATCH_BASE..HOST_SCRATCH_BASE + HOST_SCRATCH_SIZE).contains(&ptr) {
            return self.host_scratch.free(ptr);
        }
        self.heap.free(ptr)
    }

    /// 开关「冻结 Guest 堆布局」模式（开启后宿主 `emu.mem.alloc` 自动分配到独立 `[host-scratch]` 区，绝不偏移 guest `malloc` 地址）
    pub fn set_freeze_layout(&mut self, enabled: bool) {
        self.freeze_layout = enabled;
    }

    #[inline]
    pub const fn is_layout_frozen(&self) -> bool {
        self.freeze_layout
    }

    /// 从独立 `[host-scratch]` 隔离区分配宿主/探测脚本专用缓冲（惰性按 64KB 步进映射，完全不干扰 guest `[heap]`）
    pub fn alloc_host_scratch<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        size: u64,
    ) -> EmuResult<u64> {
        let ptr = self.host_scratch.alloc(size.max(1), 16)?;
        let needed_end = align_up(ptr.saturating_add(size.max(1)), PAGE_SIZE * 16)
            .min(HOST_SCRATCH_BASE + HOST_SCRATCH_SIZE);
        if needed_end > self.host_scratch_mapped_end {
            let map_start = self.host_scratch_mapped_end;
            let map_len = needed_end - map_start;
            self.map_labeled(
                uc,
                map_start,
                map_len,
                Prot::READ | Prot::WRITE,
                "[host-scratch]",
                0,
            )?;
            self.host_scratch_mapped_end = needed_end;
        }
        Ok(ptr)
    }

    /// 记录一次 guest HLE 堆分配（O(1) 环形队列，供 `heapLayout()` 诊断跨跑地址漂移）
    pub fn record_heap_alloc(&mut self, ptr: u64, size: u64, caller_pc: u64, op: &'static str) {
        let seq = self.next_alloc_seq;
        self.next_alloc_seq = self.next_alloc_seq.wrapping_add(1);
        if self.heap_alloc_log.len() >= MAX_HEAP_ALLOC_LOG {
            if let Some(evicted) = self.heap_alloc_log.pop_front() {
                if self.active_heap_allocs.get(&evicted.ptr) == Some(&evicted.seq) {
                    self.active_heap_allocs.remove(&evicted.ptr);
                }
            }
        }
        self.heap_alloc_log.push_back(HeapAllocRecord {
            seq,
            ptr,
            size,
            caller_pc,
            op,
            freed: false,
        });
        self.active_heap_allocs.insert(ptr, seq);
    }

    /// O(1) 标记对应堆块已释放
    pub fn record_heap_free(&mut self, ptr: u64, _caller_pc: u64) {
        if let Some(seq) = self.active_heap_allocs.remove(&ptr) {
            if let Some(first) = self.heap_alloc_log.front() {
                let offset = seq.wrapping_sub(first.seq) as usize;
                if let Some(rec) = self.heap_alloc_log.get_mut(offset) {
                    if rec.seq == seq && rec.ptr == ptr {
                        rec.freed = true;
                    }
                }
            }
        }
    }

    pub fn heap_alloc_log(&self) -> &VecDeque<HeapAllocRecord> {
        &self.heap_alloc_log
    }

    /// 检查 `[begin, end]` 区间内是否存在至少 1 个已映射 4KB 页（供 `hook.mem` 未映射告警使用）
    pub fn has_any_mapped_page_in(&self, begin: u64, end: u64) -> bool {
        let start_page = align_down(begin, PAGE_SIZE);
        let end_page = align_down(end.max(begin), PAGE_SIZE);
        self.mapped_pages
            .range(start_page..=end_page)
            .next()
            .is_some()
    }

    /// 带块头元数据的 HLE `malloc`（支持 `realloc` 读取原块大小，并可被 `hle_free` 回收复用）
    pub fn hle_malloc<B: CpuBackend + ?Sized>(&mut self, uc: &mut B, size: u64) -> EmuResult<u64> {
        let alloc_sz = size.max(1);
        let raw_addr = self.heap.alloc(HEAP_HEADER_SIZE + alloc_sz, 16)?;
        self.write_u64(uc, raw_addr, HEAP_BLOCK_MAGIC)?;
        self.write_u64(uc, raw_addr + 8, alloc_sz)?;
        Ok(raw_addr + HEAP_HEADER_SIZE)
    }

    /// 释放由 `hle_malloc` / `hle_calloc` / `hle_realloc` / `alloc_host_scratch`（或原始 `alloc_heap`）分配的块
    pub fn hle_free(&mut self, ptr: u64) -> bool {
        if ptr == 0 {
            return false;
        }
        if (HOST_SCRATCH_BASE..HOST_SCRATCH_BASE + HOST_SCRATCH_SIZE).contains(&ptr) {
            return self.host_scratch.free(ptr);
        }
        if ptr >= self.heap.base() + HEAP_HEADER_SIZE
            && self.heap.free(ptr - HEAP_HEADER_SIZE)
        {
            return true;
        }
        self.heap.free(ptr)
    }

    /// 带零初始化的 HLE `calloc`
    pub fn hle_calloc<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        nmemb: u64,
        size: u64,
    ) -> EmuResult<u64> {
        let total = nmemb.saturating_mul(size).max(1);
        let ptr = self.hle_malloc(uc, total)?;
        let zeros = vec![0u8; total as usize];
        self.write(uc, ptr, &zeros)?;
        Ok(ptr)
    }

    /// HLE `realloc`（读取 16 字节块头原大小并拷贝数据到新块，同时回收旧块）
    pub fn hle_realloc<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        old_ptr: u64,
        new_size: u64,
    ) -> EmuResult<u64> {
        if old_ptr == 0 {
            return self.hle_malloc(uc, new_size);
        }
        if new_size == 0 {
            self.hle_free(old_ptr);
            return Ok(0);
        }
        let new_ptr = self.hle_malloc(uc, new_size)?;
        if old_ptr >= self.heap.base() + HEAP_HEADER_SIZE {
            let magic = self.read_u64(uc, old_ptr - HEAP_HEADER_SIZE).unwrap_or(0);
            if magic == HEAP_BLOCK_MAGIC {
                let old_size = self.read_u64(uc, old_ptr - 8).unwrap_or(0);
                let copy_len = old_size.min(new_size) as usize;
                if copy_len > 0 {
                    let data = self.read(uc, old_ptr, copy_len)?;
                    self.write(uc, new_ptr, &data)?;
                }
            }
        }
        self.hle_free(old_ptr);
        Ok(new_ptr)
    }

    /// 捕获模拟堆元数据快照（含空闲链表、已分配块表、`[host-scratch]` 与分配日志）
    pub fn heap_snapshot(&self) -> HeapSnapshot {
        HeapSnapshot {
            heap: self.heap.clone(),
            brk_cursor: self.brk_cursor,
            mmap_cursor: self.mmap_cursor,
            host_scratch: self.host_scratch.clone(),
            host_scratch_mapped_end: self.host_scratch_mapped_end,
            freeze_layout: self.freeze_layout,
            heap_alloc_log: self.heap_alloc_log.clone(),
            next_alloc_seq: self.next_alloc_seq,
        }
    }

    /// 恢复模拟堆元数据快照（保留后端已映射上界防止重复 `map_labeled` 提权 RWX）
    pub fn restore_heap_snapshot(&mut self, snap: &HeapSnapshot) {
        self.heap = snap.heap.clone();
        self.brk_cursor = snap.brk_cursor;
        self.mmap_cursor = snap.mmap_cursor;
        self.host_scratch = snap.host_scratch.clone();
        // EmuSnapshot::restore 不会 munmap 快照后新增映射页，保留较大上界避免后续重复映射提权
        self.host_scratch_mapped_end = self
            .host_scratch_mapped_end
            .max(snap.host_scratch_mapped_end);
        self.freeze_layout = snap.freeze_layout;
        self.heap_alloc_log = snap.heap_alloc_log.clone();
        self.next_alloc_seq = snap.next_alloc_seq;
        self.active_heap_allocs.clear();
        for rec in &self.heap_alloc_log {
            if !rec.freed {
                self.active_heap_allocs.insert(rec.ptr, rec.seq);
            }
        }
    }

    pub(crate) fn host_scratch_ref(&self) -> &BumpAllocator {
        &self.host_scratch
    }

    #[inline]
    pub(crate) fn layout_epoch(&self) -> u64 {
        self.layout_epoch
    }

    #[inline]
    pub fn is_page_mapped(&self, addr: u64) -> bool {
        self.mapped_pages.contains(&align_down(addr, PAGE_SIZE))
    }

    pub(crate) fn mapped_pages(&self) -> &BTreeSet<u64> {
        &self.mapped_pages
    }

    pub(crate) fn mmap_cursor(&self) -> u64 {
        self.mmap_cursor
    }

    pub(crate) fn brk_cursor(&self) -> u64 {
        self.brk_cursor
    }

    pub(crate) fn heap_ref(&self) -> &BumpAllocator {
        &self.heap
    }

    /// 按 `.rtape` 磁带目标状态同步全部 VMA 映射、4KB 内存页与堆分配器元数据
    ///
    /// 支持首次恢复与运行中任意检查点快进/倒带（仅卸载多余页、映射新增页、写回差异/非零页并清零空页）。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_from_tape<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        target_vmas: &[VmaRegion],
        target_pages: &BTreeMap<u64, [u8; 4096]>,
        target_heap: BumpAllocator,
        brk_cursor: u64,
        mmap_cursor: u64,
        target_host_scratch: Option<BumpAllocator>,
        target_freeze_layout: Option<bool>,
    ) -> EmuResult<()> {
        const MIN_GUEST_VA: u64 = 0x1_0000;
        const MAX_GUEST_VA: u64 = 0x0001_0000_0000_0000;
        const MAX_TOTAL_PAGES: usize = 1_048_576; // 上限 4 GiB

        let mut desired_pages: BTreeSet<u64> = BTreeSet::new();
        let mut page_perms: BTreeMap<u64, Prot> = BTreeMap::new();
        for vma in target_vmas {
            if vma.start >= vma.end
                || (vma.start & (PAGE_SIZE - 1)) != 0
                || (vma.end & (PAGE_SIZE - 1)) != 0
                || vma.start < MIN_GUEST_VA
                || vma.end > MAX_GUEST_VA
            {
                return Err(EmuError::Backend(format!(
                    "磁带包含非法 VMA 区间: [0x{:x}, 0x{:x})",
                    vma.start, vma.end
                )));
            }
            let page_count = ((vma.end - vma.start) / PAGE_SIZE) as usize;
            if desired_pages.len().saturating_add(page_count) > MAX_TOTAL_PAGES {
                return Err(EmuError::Backend("磁带总映射页数超过安全上限".to_string()));
            }
            let mut p = vma.start;
            while p < vma.end {
                desired_pages.insert(p);
                page_perms
                    .entry(p)
                    .and_modify(|cur| *cur = Prot(cur.0 | vma.perms.0))
                    .or_insert(vma.perms);
                p = p
                    .checked_add(PAGE_SIZE)
                    .ok_or_else(|| EmuError::Backend("VMA 页枚举地址溢出".to_string()))?;
            }
        }
        for &p in target_pages.keys() {
            if (p & (PAGE_SIZE - 1)) != 0 || !(MIN_GUEST_VA..MAX_GUEST_VA).contains(&p) {
                return Err(EmuError::Backend(format!(
                    "磁带包含非法页地址: 0x{p:x}"
                )));
            }
            desired_pages.insert(p);
            page_perms.entry(p).or_insert(Prot::ALL);
        }

        // 1. 卸载当前存在但目标状态不存在的连续页段（逐段更新 mapped_pages 并刷清 Unicorn TB）
        let to_unmap: Vec<u64> = self
            .mapped_pages
            .difference(&desired_pages)
            .copied()
            .collect();
        let mut idx = 0;
        while idx < to_unmap.len() {
            let run_start = to_unmap[idx];
            let mut run_end = run_start
                .checked_add(PAGE_SIZE)
                .ok_or_else(|| EmuError::Backend("卸载页段地址溢出".to_string()))?;
            while idx + 1 < to_unmap.len() && to_unmap[idx + 1] == run_end {
                idx += 1;
                run_end = run_end
                    .checked_add(PAGE_SIZE)
                    .ok_or_else(|| EmuError::Backend("卸载页段地址溢出".to_string()))?;
            }
            let _ = uc.flush_cache(run_start, run_end);
            uc.mem_unmap(run_start, run_end - run_start)?;
            let mut p = run_start;
            while p < run_end {
                self.mapped_pages.remove(&p);
                p += PAGE_SIZE;
            }
            idx += 1;
        }

        // 2. 映射目标存在但当前未映射的连续页段（逐段立即记入 mapped_pages 避免半失败脱同步）
        let to_map: Vec<u64> = desired_pages
            .difference(&self.mapped_pages)
            .copied()
            .collect();
        let mut idx = 0;
        while idx < to_map.len() {
            let run_start = to_map[idx];
            let mut run_end = run_start
                .checked_add(PAGE_SIZE)
                .ok_or_else(|| EmuError::Backend("映射页段地址溢出".to_string()))?;
            while idx + 1 < to_map.len() && to_map[idx + 1] == run_end {
                idx += 1;
                run_end = run_end
                    .checked_add(PAGE_SIZE)
                    .ok_or_else(|| EmuError::Backend("映射页段地址溢出".to_string()))?;
            }
            uc.mem_map(run_start, run_end - run_start, Prot::ALL)?;
            let mut p = run_start;
            while p < run_end {
                self.mapped_pages.insert(p);
                p += PAGE_SIZE;
            }
            idx += 1;
        }

        // 3. 写入全部目标页镜像（未出现在 target_pages 中的已映射页清零，确保无残留脏数据）
        const ZERO_PAGE: [u8; 4096] = [0u8; 4096];
        for &page in &desired_pages {
            if let Some(bytes) = target_pages.get(&page) {
                uc.mem_write(page, bytes)?;
            } else {
                uc.mem_write(page, &ZERO_PAGE)?;
            }
        }

        // 4. 按每页合并权限批量调用 mem_protect，并重建规范化 VMA 表
        let perm_entries: Vec<(u64, Prot)> = page_perms.into_iter().collect();
        let mut pidx = 0;
        while pidx < perm_entries.len() {
            let (run_start, prot) = perm_entries[pidx];
            let mut run_end = run_start + PAGE_SIZE;
            while pidx + 1 < perm_entries.len()
                && perm_entries[pidx + 1].0 == run_end
                && perm_entries[pidx + 1].1 == prot
            {
                pidx += 1;
                run_end += PAGE_SIZE;
            }
            uc.mem_protect(run_start, run_end - run_start, prot)?;
            pidx += 1;
        }

        self.regions.clear();
        for vma in target_vmas {
            self.record_vma(vma.clone());
        }

        self.heap = target_heap;
        self.brk_cursor = brk_cursor;
        self.mmap_cursor = mmap_cursor;

        // 依据目标已映射页重新精确计算 `[host-scratch]` 的连续映射上界（防倒带后跳映射崩溃或提权 RWX）
        let mut scratch_mapped_end = HOST_SCRATCH_BASE;
        let scratch_limit = HOST_SCRATCH_BASE + HOST_SCRATCH_SIZE;
        while scratch_mapped_end < scratch_limit && self.mapped_pages.contains(&scratch_mapped_end)
        {
            scratch_mapped_end += PAGE_SIZE;
        }
        self.host_scratch_mapped_end = scratch_mapped_end;
        if let Some(hs) = target_host_scratch {
            self.host_scratch = hs;
        } else {
            // 兼容旧版未含 SCRT 尾部块的磁带：若已存在 [host-scratch] 页，将游标推进到映射上界以防 UAF 覆写
            let mut hs = BumpAllocator::new(HOST_SCRATCH_BASE, HOST_SCRATCH_SIZE);
            if scratch_mapped_end > HOST_SCRATCH_BASE {
                let _ = hs.alloc(scratch_mapped_end - HOST_SCRATCH_BASE, 16);
            }
            self.host_scratch = hs;
        }
        if let Some(fl) = target_freeze_layout {
            self.freeze_layout = fl;
        }
        self.heap_alloc_log.clear();
        self.active_heap_allocs.clear();
        self.next_alloc_seq = 1;
        self.layout_epoch = self.layout_epoch.wrapping_add(1);
        Ok(())
    }

    /// 读取指定地址内存到新 Vec
    pub fn read<B: CpuBackend + ?Sized>(&self, uc: &B, addr: u64, size: usize) -> EmuResult<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.read_into(uc, addr, &mut buf)?;
        Ok(buf)
    }

    /// 零分配读取指定地址内存到已有切片
    pub fn read_into<B: CpuBackend + ?Sized>(&self, uc: &B, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        uc.mem_read(addr, buf)
            .map_err(|_| EmuError::UnmappedMemory {
                addr,
                size: buf.len(),
            })
    }

    /// 向模拟内存写入字节切片
    pub fn write<B: CpuBackend + ?Sized>(&self, uc: &mut B, addr: u64, data: &[u8]) -> EmuResult<()> {
        uc.mem_write(addr, data)
            .map_err(|_| EmuError::UnmappedMemory {
                addr,
                size: data.len(),
            })
    }

    /// 读取小端 64 位整数
    pub fn read_u64<B: CpuBackend + ?Sized>(&self, uc: &B, addr: u64) -> EmuResult<u64> {
        let mut buf = [0u8; 8];
        self.read_into(uc, addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// 写入小端 64 位整数
    pub fn write_u64<B: CpuBackend + ?Sized>(&self, uc: &mut B, addr: u64, val: u64) -> EmuResult<()> {
        self.write(uc, addr, &val.to_le_bytes())
    }

    /// 写入小端 32 位整数
    pub fn write_u32<B: CpuBackend + ?Sized>(&self, uc: &mut B, addr: u64, val: u32) -> EmuResult<()> {
        self.write(uc, addr, &val.to_le_bytes())
    }

    /// 从模拟内存读取以 `\0` 结尾的 C 字符串（最大读取 `max_len` 字节防止无限扫描）
    pub fn read_c_string<B: CpuBackend + ?Sized>(
        &self,
        uc: &B,
        addr: u64,
        max_len: usize,
    ) -> EmuResult<String> {
        let mut bytes = Vec::with_capacity(64);
        let mut chunk = [0u8; 64];
        let mut cur = addr;

        while bytes.len() < max_len {
            let remain = (max_len - bytes.len()).min(chunk.len());
            if uc.mem_read(cur, &mut chunk[..remain]).is_err() {
                // 若越过页边界，逐字节读取剩余安全部分
                for i in 0..remain {
                    let mut b = [0u8; 1];
                    if uc.mem_read(cur + i as u64, &mut b).is_err() {
                        break;
                    }
                    if b[0] == 0 {
                        return Ok(String::from_utf8_lossy(&bytes).into_owned());
                    }
                    bytes.push(b[0]);
                }
                break;
            }
            if let Some(pos) = chunk[..remain].iter().position(|&b| b == 0) {
                bytes.extend_from_slice(&chunk[..pos]);
                break;
            }
            bytes.extend_from_slice(&chunk[..remain]);
            cur += remain as u64;
        }

        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// 向模拟内存写入以 `\0` 结尾的 C 字符串
    pub fn write_c_string<B: CpuBackend + ?Sized>(&self, uc: &mut B, addr: u64, s: &str) -> EmuResult<()> {
        let mut buf = Vec::with_capacity(s.len() + 1);
        buf.extend_from_slice(s.as_bytes());
        buf.push(0);
        self.write(uc, addr, &buf)
    }

    pub fn heap_used(&self) -> u64 {
        self.heap.used()
    }
}

/// 仅借用 `&Unicorn` 读取 Guest C 字符串原始字节（不含 `\0`），供 Hook 回调内安全调用，避免借用冲突
pub fn read_guest_cstr_bytes<B: CpuBackend + ?Sized>(uc: &B, addr: u64, max_len: usize) -> Vec<u8> {
    if addr == 0 || max_len == 0 {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(64);
    let mut chunk = [0u8; 64];
    let mut cur = addr;

    while bytes.len() < max_len {
        let remain = (max_len - bytes.len()).min(chunk.len());
        if uc.mem_read(cur, &mut chunk[..remain]).is_err() {
            for i in 0..remain {
                let mut b = [0u8; 1];
                if uc.mem_read(cur + i as u64, &mut b).is_err() || b[0] == 0 {
                    return bytes;
                }
                bytes.push(b[0]);
            }
            break;
        }
        if let Some(pos) = chunk[..remain].iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..pos]);
            break;
        }
        bytes.extend_from_slice(&chunk[..remain]);
        cur += remain as u64;
    }

    bytes
}

/// 仅借用 `&Unicorn` 读取 Guest C 字符串并按 UTF-8 容错解码
pub fn read_guest_cstr<B: CpuBackend + ?Sized>(uc: &B, addr: u64, max_len: usize) -> String {
    let bytes = read_guest_cstr_bytes(uc, addr, max_len);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 仅借用 `&Unicorn` 读取小端 `u64`（越界返回 0）
#[inline]
pub fn read_guest_u64<B: CpuBackend + ?Sized>(uc: &B, addr: u64) -> u64 {
    let mut buf = [0u8; 8];
    if addr != 0 && uc.mem_read(addr, &mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        0
    }
}

/// 仅借用 `&Unicorn` 读取小端 `i32`（越界返回 0）
#[inline]
pub fn read_guest_i32<B: CpuBackend + ?Sized>(uc: &B, addr: u64) -> i32 {
    let mut buf = [0u8; 4];
    if addr != 0 && uc.mem_read(addr, &mut buf).is_ok() {
        i32::from_le_bytes(buf)
    } else {
        0
    }
}
