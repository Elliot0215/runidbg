use std::collections::{BTreeMap, BTreeSet};
use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::Unicorn;

use crate::error::{EmuError, EmuResult};

/// ARM64 标准页大小（4KB）
pub const PAGE_SIZE: u64 = 0x1000;

/// 匿名 mmap 默认分配区间（与 HEAP_BASE 错开，位于 0x5800_0000..0x6000_0000）
pub const MMAP_BASE: u64 = 0x5800_0000;
pub const MMAP_LIMIT: u64 = 0x6000_0000;

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
}

/// 模拟堆元数据快照（供 `EmuSnapshot` 完整保存与恢复堆状态）
#[derive(Debug, Clone)]
pub struct HeapSnapshot {
    pub heap: BumpAllocator,
    pub brk_cursor: u64,
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
        }
    }

    /// 初始化并向 Unicorn 映射模拟堆区域（RW 权限）
    pub fn init_heap<D>(&mut self, uc: &mut Unicorn<'_, D>) -> EmuResult<()> {
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
    pub fn map_aligned<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
        addr: u64,
        size: u64,
        perms: Prot,
    ) -> EmuResult<(u64, u64)> {
        self.map_labeled(uc, addr, size, perms, "[anon]", 0)
    }

    /// 4KB 页对齐映射内存并记录 VMA 元数据（用于 `/proc/self/maps` 合成）
    pub fn map_labeled<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
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
        let mut cur = start;
        while cur < end {
            if self.mapped_pages.contains(&cur) {
                // 该页已被前一个 Segment 映射，放宽权限确保可写可执行
                uc.mem_protect(cur, PAGE_SIZE, Prot::ALL)?;
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

        Ok((start, end - start))
    }

    /// 模拟 Linux `mmap`：当 `hint_addr == 0` 时从匿名映射池自动分配空闲区间
    pub fn mmap<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
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
    pub fn munmap<D>(&mut self, uc: &mut Unicorn<'_, D>, addr: u64, size: u64) -> EmuResult<()> {
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
        Ok(())
    }

    /// 模拟 Linux `mprotect`：修改已映射页的读写执行权限并同步更新 VMA 区间
    pub fn mprotect<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
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
    }

    /// 从模拟堆中分配一块内存（默认 16 字节对齐）
    pub fn alloc_heap(&mut self, size: u64) -> EmuResult<u64> {
        self.heap.alloc(size, 16)
    }

    /// 从模拟堆中按自定义对齐分配内存
    pub fn alloc_heap_aligned(&mut self, size: u64, align: u64) -> EmuResult<u64> {
        self.heap.alloc(size, align)
    }

    /// 释放由 `alloc_heap` / `alloc_heap_aligned` 分配的原始堆块
    pub fn free_heap(&mut self, ptr: u64) -> bool {
        if ptr == 0 {
            return false;
        }
        self.heap.free(ptr)
    }

    /// 带块头元数据的 HLE `malloc`（支持 `realloc` 读取原块大小，并可被 `hle_free` 回收复用）
    pub fn hle_malloc<D>(&mut self, uc: &mut Unicorn<'_, D>, size: u64) -> EmuResult<u64> {
        let alloc_sz = size.max(1);
        let raw_addr = self.heap.alloc(HEAP_HEADER_SIZE + alloc_sz, 16)?;
        self.write_u64(uc, raw_addr, HEAP_BLOCK_MAGIC)?;
        self.write_u64(uc, raw_addr + 8, alloc_sz)?;
        Ok(raw_addr + HEAP_HEADER_SIZE)
    }

    /// 释放由 `hle_malloc` / `hle_calloc` / `hle_realloc`（或原始 `alloc_heap`）分配的块
    pub fn hle_free(&mut self, ptr: u64) -> bool {
        if ptr == 0 {
            return false;
        }
        if ptr >= self.heap.base() + HEAP_HEADER_SIZE
            && self.heap.free(ptr - HEAP_HEADER_SIZE)
        {
            return true;
        }
        self.heap.free(ptr)
    }

    /// 带零初始化的 HLE `calloc`
    pub fn hle_calloc<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
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
    pub fn hle_realloc<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
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

    /// 捕获模拟堆元数据快照（含空闲链表与已分配块表）
    pub fn heap_snapshot(&self) -> HeapSnapshot {
        HeapSnapshot {
            heap: self.heap.clone(),
            brk_cursor: self.brk_cursor,
        }
    }

    /// 恢复模拟堆元数据快照
    pub fn restore_heap_snapshot(&mut self, snap: &HeapSnapshot) {
        self.heap = snap.heap.clone();
        self.brk_cursor = snap.brk_cursor;
    }

    /// 读取指定地址内存到新 Vec
    pub fn read<D>(&self, uc: &Unicorn<'_, D>, addr: u64, size: usize) -> EmuResult<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.read_into(uc, addr, &mut buf)?;
        Ok(buf)
    }

    /// 零分配读取指定地址内存到已有切片
    pub fn read_into<D>(&self, uc: &Unicorn<'_, D>, addr: u64, buf: &mut [u8]) -> EmuResult<()> {
        uc.mem_read(addr, buf)
            .map_err(|_| EmuError::UnmappedMemory {
                addr,
                size: buf.len(),
            })
    }

    /// 向模拟内存写入字节切片
    pub fn write<D>(&self, uc: &mut Unicorn<'_, D>, addr: u64, data: &[u8]) -> EmuResult<()> {
        uc.mem_write(addr, data)
            .map_err(|_| EmuError::UnmappedMemory {
                addr,
                size: data.len(),
            })
    }

    /// 读取小端 64 位整数
    pub fn read_u64<D>(&self, uc: &Unicorn<'_, D>, addr: u64) -> EmuResult<u64> {
        let mut buf = [0u8; 8];
        self.read_into(uc, addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// 写入小端 64 位整数
    pub fn write_u64<D>(&self, uc: &mut Unicorn<'_, D>, addr: u64, val: u64) -> EmuResult<()> {
        self.write(uc, addr, &val.to_le_bytes())
    }

    /// 写入小端 32 位整数
    pub fn write_u32<D>(&self, uc: &mut Unicorn<'_, D>, addr: u64, val: u32) -> EmuResult<()> {
        self.write(uc, addr, &val.to_le_bytes())
    }

    /// 从模拟内存读取以 `\0` 结尾的 C 字符串（最大读取 `max_len` 字节防止无限扫描）
    pub fn read_c_string<D>(
        &self,
        uc: &Unicorn<'_, D>,
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
    pub fn write_c_string<D>(&self, uc: &mut Unicorn<'_, D>, addr: u64, s: &str) -> EmuResult<()> {
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
pub fn read_guest_cstr_bytes<D>(uc: &Unicorn<'_, D>, addr: u64, max_len: usize) -> Vec<u8> {
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
pub fn read_guest_cstr<D>(uc: &Unicorn<'_, D>, addr: u64, max_len: usize) -> String {
    let bytes = read_guest_cstr_bytes(uc, addr, max_len);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 仅借用 `&Unicorn` 读取小端 `u64`（越界返回 0）
#[inline]
pub fn read_guest_u64<D>(uc: &Unicorn<'_, D>, addr: u64) -> u64 {
    let mut buf = [0u8; 8];
    if addr != 0 && uc.mem_read(addr, &mut buf).is_ok() {
        u64::from_le_bytes(buf)
    } else {
        0
    }
}

/// 仅借用 `&Unicorn` 读取小端 `i32`（越界返回 0）
#[inline]
pub fn read_guest_i32<D>(uc: &Unicorn<'_, D>, addr: u64) -> i32 {
    let mut buf = [0u8; 4];
    if addr != 0 && uc.mem_read(addr, &mut buf).is_ok() {
        i32::from_le_bytes(buf)
    } else {
        0
    }
}
