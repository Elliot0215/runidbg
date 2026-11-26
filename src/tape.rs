//! `.rtape` 统一磁带快照格式（v1：多检查点增量存档磁带 + 跨后端接力，预留二期时间旅行扩展槽）
//!
//! 设计要点：
//! - **零额外依赖**：纯 Rust 紧凑二进制帧 + `flate2` Zlib 压缩（兼容 `--no-default-features` 最小核心）。
//! - **稀疏基线 + 4KB 脏页增量 diff**：
//!   - 首个检查点 (`BaseCheckpoint`) 自动跳过全零 4KB 页，大幅压缩空堆/空栈体积；
//!   - 后续检查点 (`DeltaCheckpoint`) 仅存相对前一检查点发生变化的 4KB 脏页、被清零页与已卸载页。
//! - **跨进程 / 跨后端无缝接力**：保存后端无关的 `GenericCpuContext` 与完整子系统状态（VMA/堆/ELF 模块/HLE/JNI/VFS），
//!   恢复到任意目标后端（`Unicorn` ↔ `Dynarmic` ↔ `Kvm` ↔ `Hypervisor`）时自动重写 HLE/JNI/RET 跳板指令页。
//! - **前向兼容二期时间旅行**：Chunk 流保留 `TAG_EVENT_LOG = 3` 与文件头 `reserved` 偏移字段。

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use unicorn_engine::unicorn_const::Prot;

use crate::backend::GenericCpuContext;
use crate::cpu::CpuContext;
use crate::error::{EmuError, EmuResult};
use crate::jni::env::JniTapeState;
use crate::jni::types::{
    FieldDesc, JObject, JObjectRef, JValue, MethodDesc, ObjectTableDelta, ObjectTableRaw,
    RegisteredNative,
};
use crate::loader::dex::{DexClassInfo, DexFieldInfo, DexMethodInfo, DexValue};
use crate::loader::elf::LoadedModule;
use crate::loader::linker::LinkerTapeState;
use crate::loader::trampoline::{
    AssetDirStream, AssetStream, DirStream, DlModuleEntry, MmapFileBacking, PropInfoEntry,
    StdioStream, TrampolineTapeState, TRAMPOLINE_SIZE,
};
use crate::memory::{BumpAllocator, VmaRegion, PAGE_SIZE};
use crate::os::device::DeviceProfile;
use crate::os::net::{NetConfig, NetTapeState, NetVirtualFdTape, PipeChannelTape, VirtualNic};
use crate::os::vfs::{OpenFile, OpenFileKind, VfsTapeState};

/// 磁带文件魔数与版本号
pub const TAPE_MAGIC: &[u8; 8] = b"RTAPE001";
pub const TAPE_VERSION: u32 = 1;
const TAPE_FLAG_ZLIB: u32 = 1 << 0;

const CHUNK_BASE_CHECKPOINT: u32 = 1;
const CHUNK_DELTA_CHECKPOINT: u32 = 2;
/// 二期时间旅行确定性事件流 Chunk Tag（完全向后兼容 v1 读取器）
const CHUNK_EVENT_LOG: u32 = 3;
const EVENT_LOG_VERSION: u32 = 1;

/// 解码安全边界常量（防御畸形/恶意 .rtape 触发 OOM、Zip Bomb 或整数溢出）
const MAX_TAPE_FILE_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB 磁盘单文件上限
const MAX_CHUNK_UNCOMPRESSED: usize = 512 * 1024 * 1024; // 512 MiB 单块上限
const MAX_TOTAL_UNCOMPRESSED: usize = 2 * 1024 * 1024 * 1024; // 2 GiB 跨块累计解压上限
const MAX_CHUNKS: usize = 65_536;
const MAX_EVENTS: usize = 4_000_000;
const EVENT_RECORD_FLAGS_MASK: u32 = 0x7; // CLOCK(1) | JNI(2) | HOST_FS(4)
const MAX_TOTAL_MAPPED_PAGES: usize = 1_048_576; // 4 GiB
const MIN_GUEST_VA: u64 = 0x1_0000;
const MAX_GUEST_VA: u64 = 0x0001_0000_0000_0000;
const MAX_DEX_VALUE_DEPTH: usize = 32;

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// 磁带检查点选择器（支持按最新、序号或书签名定位）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapeSelector {
    Latest,
    Index(usize),
    Label(String),
}

impl TapeSelector {
    /// 解析字符串选择器：`""` / `"latest"` -> `Latest`，`label:<name>` -> `Label`，`idx:<n>` 或非负整数 -> `Index`，其余 -> `Label`
    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("latest") {
            Self::Latest
        } else if let Some(rest) = trimmed.strip_prefix("label:") {
            Self::Label(rest.to_string())
        } else if let Some(rest) = trimmed.strip_prefix("idx:") {
            if let Ok(idx) = rest.parse::<usize>() {
                Self::Index(idx)
            } else {
                Self::Label(trimmed.to_string())
            }
        } else if let Ok(idx) = trimmed.parse::<usize>() {
            Self::Index(idx)
        } else {
            Self::Label(trimmed.to_string())
        }
    }
}

/// 单个检查点的公开摘要元数据（供 CLI `tape info` / JS `Emu.inspectTape` / MCP 使用）
#[derive(Debug, Clone)]
pub struct TapeCheckpointInfo {
    pub index: u32,
    pub label: String,
    pub timestamp_ms: u64,
    pub source_backend: String,
    pub insn_count: u64,
    pub is_delta: bool,
    pub stored_pages: usize,
    pub zeroed_pages: usize,
    pub removed_pages: usize,
    pub compressed_bytes: usize,
    pub uncompressed_bytes: usize,
    pub modules: Vec<String>,
}

/// 二期时间旅行确定性回放事件（按 `(insn, seq)` 单调有序）
#[derive(Debug, Clone)]
pub enum ReplayEvent {
    /// 宿主机实时时钟读取（`use_real_clock == true`）
    ClockRead { insn: u64, seq: u64, ns: u64 },
    /// 外部 JNI Handler 回调结果与 `ObjectTable` 紧凑增量（离线回放无需原 JS/Rust Handler）
    JniCallback {
        insn: u64,
        seq: u64,
        ret: JValue,
        delta: ObjectTableDelta,
    },
    /// 外部 Hook / Syscall 产生的 Guest 内存写副作用
    ExternalMemWrite {
        insn: u64,
        seq: u64,
        pc: u64,
        writes: Vec<(u64, Vec<u8>)>,
    },
}

/// 二期时间旅行确定性事件日志段（持久化在 `CHUNK_EVENT_LOG = 3`）
#[derive(Debug, Clone, Default)]
pub struct TapeEventLog {
    pub timeline_version: u32,
    pub start_insn: u64,
    pub end_insn: u64,
    pub keyframe_interval: u64,
    pub record_flags: u32,
    /// 时间轴命名书签：`(insn_count, label)`
    pub bookmarks: Vec<(u64, String)>,
    /// 每个关键帧捕获时刻对应的精确事件游标：`(keyframe_insn, event_index)`
    pub keyframe_event_offsets: Vec<(u64, u32)>,
    /// 录制期间从只读宿主机 `sysroot_mounts` 命中的文件缓存（保证脱离宿主机可完全离线重放）
    pub host_files: Vec<(String, Vec<u8>)>,
    /// 非确定性边界事件序列
    pub events: Vec<ReplayEvent>,
}

impl TapeEventLog {
    pub fn to_timeline_info(&self) -> TapeTimelineInfo {
        let mut clock_events = 0usize;
        let mut jni_events = 0usize;
        let mut hook_events = 0usize;
        for ev in &self.events {
            match ev {
                ReplayEvent::ClockRead { .. } => clock_events += 1,
                ReplayEvent::JniCallback { .. } => jni_events += 1,
                ReplayEvent::ExternalMemWrite { .. } => hook_events += 1,
            }
        }
        TapeTimelineInfo {
            start_insn: self.start_insn,
            end_insn: self.end_insn,
            keyframe_interval: self.keyframe_interval,
            event_count: self.events.len(),
            clock_events,
            jni_events,
            hook_events,
            host_file_count: self.host_files.len(),
            bookmarks: self.bookmarks.clone(),
        }
    }
}

/// 时间旅行时间轴公开摘要（供 CLI `tape info` / JS / MCP 展示）
#[derive(Debug, Clone)]
pub struct TapeTimelineInfo {
    pub start_insn: u64,
    pub end_insn: u64,
    pub keyframe_interval: u64,
    pub event_count: usize,
    pub clock_events: usize,
    pub jni_events: usize,
    pub hook_events: usize,
    pub host_file_count: usize,
    pub bookmarks: Vec<(u64, String)>,
}

/// 整卷 `.rtape` 磁带文件摘要
#[derive(Debug, Clone)]
pub struct TapeSummary {
    pub version: u32,
    pub file_size: u64,
    pub checkpoints: Vec<TapeCheckpointInfo>,
    pub timeline: Option<TapeTimelineInfo>,
}

/// 检查点元数据记录（内部存储）
#[derive(Debug, Clone)]
pub(crate) struct TapeMeta {
    pub index: u32,
    pub label: String,
    pub timestamp_ms: u64,
    pub source_backend: String,
    pub insn_count: u64,
}

impl TapeMeta {
    pub fn new(index: u32, label: impl Into<String>, source_backend: &str) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            index,
            label: label.into(),
            timestamp_ms: ts,
            source_backend: source_backend.to_string(),
            insn_count: 0,
        }
    }
}

/// 单个时间点物化后的完整模拟器状态（非零 4KB 页集合 + 全部运行时子系统状态）
#[derive(Debug, Clone)]
pub(crate) struct TapeFullState {
    pub regs: GenericCpuContext,
    pub cpu_layout: CpuContext,
    pub vmas: Vec<VmaRegion>,
    pub heap: BumpAllocator,
    pub brk_cursor: u64,
    pub mmap_cursor: u64,
    pub host_scratch: Option<BumpAllocator>,
    pub freeze_layout: Option<bool>,
    /// 仅存非零 4KB 页（空页稀疏省略）
    pub nonzero_pages: BTreeMap<u64, [u8; 4096]>,
    pub linker: LinkerTapeState,
    pub trampolines: TrampolineTapeState,
    pub jni: JniTapeState,
    pub vfs: VfsTapeState,
}

/// 磁带内单个已编码检查点块
#[derive(Debug, Clone)]
struct TapeCheckpointChunk {
    meta: TapeMeta,
    is_delta: bool,
    /// Base: 全量非零页；Delta: 新增或内容变更的非零 4KB 脏页
    pages: Vec<(u64, [u8; 4096])>,
    /// Delta 专用：之前非零但现在全零的 4KB 页
    zeroed_pages: Vec<u64>,
    /// Delta 专用：已被卸载的 4KB 页
    removed_pages: Vec<u64>,
    regs: GenericCpuContext,
    cpu_layout: CpuContext,
    vmas: Vec<VmaRegion>,
    heap: BumpAllocator,
    brk_cursor: u64,
    mmap_cursor: u64,
    host_scratch: Option<BumpAllocator>,
    freeze_layout: Option<bool>,
    linker: LinkerTapeState,
    trampolines: TrampolineTapeState,
    jni: JniTapeState,
    vfs: VfsTapeState,
    compressed_bytes: usize,
    uncompressed_bytes: usize,
}

impl TapeCheckpointChunk {
    fn to_info(&self) -> TapeCheckpointInfo {
        TapeCheckpointInfo {
            index: self.meta.index,
            label: self.meta.label.clone(),
            timestamp_ms: self.meta.timestamp_ms,
            source_backend: self.meta.source_backend.clone(),
            insn_count: self.meta.insn_count,
            is_delta: self.is_delta,
            stored_pages: self.pages.len(),
            zeroed_pages: self.zeroed_pages.len(),
            removed_pages: self.removed_pages.len(),
            compressed_bytes: self.compressed_bytes,
            uncompressed_bytes: self.uncompressed_bytes,
            modules: self.linker.load_order.clone(),
        }
    }
}

/// 内存中的多检查点磁带容器（支持顺序追加书签、持久化落盘、任意检查点物化、倒带/快进与二期时间旅行事件流）
#[derive(Debug, Clone)]
pub struct Tape {
    chunks: Vec<TapeCheckpointChunk>,
    event_log: Option<Arc<TapeEventLog>>,
}

impl Tape {
    /// 以首个全量基线检查点创建新磁带
    pub(crate) fn from_base(meta: TapeMeta, state: TapeFullState) -> Self {
        let pages: Vec<(u64, [u8; 4096])> = state.nonzero_pages.into_iter().collect();
        let chunk = TapeCheckpointChunk {
            meta,
            is_delta: false,
            pages,
            zeroed_pages: Vec::new(),
            removed_pages: Vec::new(),
            regs: state.regs,
            cpu_layout: state.cpu_layout,
            vmas: state.vmas,
            heap: state.heap,
            brk_cursor: state.brk_cursor,
            mmap_cursor: state.mmap_cursor,
            host_scratch: state.host_scratch,
            freeze_layout: state.freeze_layout,
            linker: state.linker,
            trampolines: state.trampolines,
            jni: state.jni,
            vfs: state.vfs,
            compressed_bytes: 0,
            uncompressed_bytes: 0,
        };
        Self {
            chunks: vec![chunk],
            event_log: None,
        }
    }

    pub fn event_log(&self) -> Option<&TapeEventLog> {
        self.event_log.as_deref()
    }

    pub(crate) fn event_log_arc(&self) -> Option<Arc<TapeEventLog>> {
        self.event_log.as_ref().map(Arc::clone)
    }

    pub fn set_event_log(&mut self, log: Option<TapeEventLog>) {
        self.event_log = log.map(Arc::new);
    }

    pub fn has_time_travel(&self) -> bool {
        self.event_log.is_some()
    }

    pub fn timeline_info(&self) -> Option<TapeTimelineInfo> {
        self.event_log.as_deref().map(TapeEventLog::to_timeline_info)
    }

    /// 查找 `meta.insn_count <= target_insn` 的最近关键帧索引（二分定位，供二期时间旅行快速 seek）
    pub(crate) fn nearest_keyframe_index(&self, target_insn: u64) -> usize {
        let pos = self
            .chunks
            .partition_point(|c| c.meta.insn_count <= target_insn);
        pos.saturating_sub(1)
    }

    /// 查找恰好位于 `target_insn` 且保存的 `PC != RET_MAGIC_ADDR` 的多调用边界关键帧（用于无缝跨越连续 `call_address`）
    pub(crate) fn call_boundary_keyframe_at(&self, target_insn: u64) -> Option<usize> {
        let end = self
            .chunks
            .partition_point(|c| c.meta.insn_count <= target_insn);
        let mut idx = end;
        while idx > 0 {
            idx -= 1;
            let c = &self.chunks[idx];
            if c.meta.insn_count != target_insn {
                break;
            }
            if c.regs.pc != crate::cpu::RET_MAGIC_ADDR {
                return Some(idx);
            }
        }
        None
    }

    /// 直接按索引物化检查点状态
    pub(crate) fn materialize_index(
        &self,
        idx: usize,
    ) -> EmuResult<(TapeCheckpointInfo, TapeFullState)> {
        self.materialize(&TapeSelector::Index(idx))
    }

    /// 获取指定索引关键帧的指令计数
    pub(crate) fn keyframe_insn(&self, idx: usize) -> Option<u64> {
        self.chunks.get(idx).map(|c| c.meta.insn_count)
    }

    /// 获取指定索引关键帧的标签
    pub(crate) fn keyframe_label(&self, idx: usize) -> Option<&str> {
        self.chunks.get(idx).map(|c| c.meta.label.as_str())
    }

    /// 检查点总数
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// 列出磁带内全部检查点摘要
    pub fn checkpoints(&self) -> Vec<TapeCheckpointInfo> {
        self.chunks.iter().map(TapeCheckpointChunk::to_info).collect()
    }

    /// 计算与最新检查点之间的 4KB 脏页 diff，并追加一个新的增量 `DeltaCheckpoint`
    pub(crate) fn push_delta(&mut self, mut meta: TapeMeta, next: TapeFullState) -> EmuResult<TapeCheckpointInfo> {
        if self.chunks.is_empty() {
            meta.index = 0;
            let base = Self::from_base(meta, next);
            *self = base;
            return Ok(self.chunks[0].to_info());
        }

        if self.chunks.iter().any(|c| c.meta.label == meta.label) {
            return Err(EmuError::Backend(format!(
                "磁带中已存在同名检查点书签 `{}`，请使用不同的书签名",
                meta.label
            )));
        }

        let (_, prev) = self.materialize(&TapeSelector::Latest)?;
        meta.index = u32::try_from(self.chunks.len())
            .map_err(|_| EmuError::Backend("磁带检查点数量超出 u32 上限".to_string()))?;

        // 计算已映射页集合变化
        let prev_mapped = collect_mapped_pages(&prev.vmas, &prev.nonzero_pages)?;
        let next_mapped = collect_mapped_pages(&next.vmas, &next.nonzero_pages)?;

        let mut removed_pages = Vec::new();
        for &p in &prev_mapped {
            if !next_mapped.contains(&p) {
                removed_pages.push(p);
            }
        }

        let mut changed_pages = Vec::new();
        let mut zeroed_pages = Vec::new();
        for (&p, bytes) in &next.nonzero_pages {
            match prev.nonzero_pages.get(&p) {
                Some(old) if old == bytes => {}
                _ => changed_pages.push((p, *bytes)),
            }
        }
        for &p in prev.nonzero_pages.keys() {
            if next_mapped.contains(&p) && !next.nonzero_pages.contains_key(&p) {
                zeroed_pages.push(p);
            }
        }

        let chunk = TapeCheckpointChunk {
            meta,
            is_delta: true,
            pages: changed_pages,
            zeroed_pages,
            removed_pages,
            regs: next.regs,
            cpu_layout: next.cpu_layout,
            vmas: next.vmas,
            heap: next.heap,
            brk_cursor: next.brk_cursor,
            mmap_cursor: next.mmap_cursor,
            host_scratch: next.host_scratch,
            freeze_layout: next.freeze_layout,
            linker: next.linker,
            trampolines: next.trampolines,
            jni: next.jni,
            vfs: next.vfs,
            compressed_bytes: 0,
            uncompressed_bytes: 0,
        };
        let info = chunk.to_info();
        self.chunks.push(chunk);
        Ok(info)
    }

    /// 定位目标检查点索引
    pub fn resolve_index(&self, selector: &TapeSelector) -> EmuResult<usize> {
        if self.chunks.is_empty() {
            return Err(EmuError::Backend("磁带文件不包含任何检查点".to_string()));
        }
        match selector {
            TapeSelector::Latest => Ok(self.chunks.len() - 1),
            TapeSelector::Index(i) => {
                if *i < self.chunks.len() {
                    Ok(*i)
                } else {
                    Err(EmuError::Backend(format!(
                        "磁带检查点索引越界: {i}（共 {} 个）",
                        self.chunks.len()
                    )))
                }
            }
            TapeSelector::Label(name) => self
                .chunks
                .iter()
                .rposition(|c| c.meta.label == *name)
                .ok_or_else(|| {
                    let labels: Vec<&str> = self
                        .chunks
                        .iter()
                        .map(|c| c.meta.label.as_str())
                        .collect();
                    EmuError::Backend(format!(
                        "磁带中未找到名为 `{name}` 的检查点（已有: {}）",
                        labels.join(", ")
                    ))
                }),
        }
    }

    /// 物化指定检查点的完整内存页与运行时状态（按 Base + Delta[1..=target] 顺序重放）
    pub(crate) fn materialize(
        &self,
        selector: &TapeSelector,
    ) -> EmuResult<(TapeCheckpointInfo, TapeFullState)> {
        let target_idx = self.resolve_index(selector)?;
        let mut nonzero_pages: BTreeMap<u64, [u8; 4096]> = BTreeMap::new();

        for chunk in &self.chunks[..=target_idx] {
            if !chunk.is_delta {
                nonzero_pages.clear();
            }
            for &p in &chunk.removed_pages {
                nonzero_pages.remove(&p);
            }
            for &p in &chunk.zeroed_pages {
                nonzero_pages.remove(&p);
            }
            for &(p, bytes) in &chunk.pages {
                nonzero_pages.insert(p, bytes);
            }
        }

        let target = &self.chunks[target_idx];
        let state = TapeFullState {
            regs: target.regs.clone(),
            cpu_layout: target.cpu_layout,
            vmas: target.vmas.clone(),
            heap: target.heap.clone(),
            brk_cursor: target.brk_cursor,
            mmap_cursor: target.mmap_cursor,
            host_scratch: target.host_scratch.clone(),
            freeze_layout: target.freeze_layout,
            nonzero_pages,
            linker: target.linker.clone(),
            trampolines: target.trampolines.clone(),
            jni: target.jni.clone(),
            vfs: target.vfs.clone(),
        };
        Ok((target.to_info(), state))
    }

    /// 将完整磁带写入磁盘文件（唯一同目录临时文件 + fsync + 原子 rename，防止并发冲突与半截损坏）
    pub fn save_file(&mut self, path: impl AsRef<Path>) -> EmuResult<TapeSummary> {
        let path = path.as_ref();
        let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            EmuError::Backend(format!("无效的 .rtape 目标路径（缺少文件名）: {}", path.display()))
        })?;
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
        let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".{file_name}.{}.{seq}.rtape.tmp", std::process::id());
        let tmp_path = if parent.as_os_str().is_empty() {
            Path::new(&tmp_name).to_path_buf()
        } else {
            parent.join(&tmp_name)
        };

        let write_result = (|| -> EmuResult<()> {
            let mut file = File::create(&tmp_path)?;

            let chunk_count_u32 = u32::try_from(self.chunks.len())
                .map_err(|_| EmuError::Backend("磁带检查点数量超出 u32 上限".to_string()))?;
            // 32-byte File Header
            let mut hdr = Vec::with_capacity(32);
            hdr.extend_from_slice(TAPE_MAGIC);
            hdr.extend_from_slice(&TAPE_VERSION.to_le_bytes());
            hdr.extend_from_slice(&TAPE_FLAG_ZLIB.to_le_bytes());
            hdr.extend_from_slice(&0u32.to_le_bytes()); // header_crc / reserved
            hdr.extend_from_slice(&chunk_count_u32.to_le_bytes());
            hdr.extend_from_slice(&0u64.to_le_bytes()); // reserved (Phase 2 EventLog index offset)
            file.write_all(&hdr)?;

            for chunk in &mut self.chunks {
                let mut raw = Vec::new();
                encode_chunk_payload(&mut raw, chunk)?;
                let raw_len_u32 = u32::try_from(raw.len()).map_err(|_| {
                    EmuError::Backend("单个 .rtape 检查点原始大小超出 4 GiB 上限".to_string())
                })?;
                let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
                enc.write_all(&raw)?;
                let compressed = enc.finish()?;
                let comp_len_u32 = u32::try_from(compressed.len()).map_err(|_| {
                    EmuError::Backend("单个 .rtape 检查点压缩大小超出 4 GiB 上限".to_string())
                })?;
                chunk.uncompressed_bytes = raw.len();
                chunk.compressed_bytes = compressed.len();

                let tag = if chunk.is_delta {
                    CHUNK_DELTA_CHECKPOINT
                } else {
                    CHUNK_BASE_CHECKPOINT
                };
                file.write_all(&tag.to_le_bytes())?;
                file.write_all(&raw_len_u32.to_le_bytes())?;
                file.write_all(&comp_len_u32.to_le_bytes())?;
                file.write_all(&compressed)?;
            }

            if let Some(ev_log) = &self.event_log {
                let ev_offset = file.stream_position()?;
                let mut raw = Vec::new();
                encode_event_log(&mut raw, ev_log)?;
                let raw_len_u32 = u32::try_from(raw.len()).map_err(|_| {
                    EmuError::Backend("时间旅行事件日志原始大小超出 4 GiB 上限".to_string())
                })?;
                let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
                enc.write_all(&raw)?;
                let compressed = enc.finish()?;
                let comp_len_u32 = u32::try_from(compressed.len()).map_err(|_| {
                    EmuError::Backend("时间旅行事件日志压缩大小超出 4 GiB 上限".to_string())
                })?;
                file.write_all(&CHUNK_EVENT_LOG.to_le_bytes())?;
                file.write_all(&raw_len_u32.to_le_bytes())?;
                file.write_all(&comp_len_u32.to_le_bytes())?;
                file.write_all(&compressed)?;
                // 回填 Header [24..32] event_log_offset
                file.seek(SeekFrom::Start(24))?;
                file.write_all(&ev_offset.to_le_bytes())?;
            }

            file.sync_all()?;
            drop(file);
            fs::rename(&tmp_path, path)?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        write_result?;

        let file_size = fs::metadata(path)?.len();
        Ok(TapeSummary {
            version: TAPE_VERSION,
            file_size,
            checkpoints: self.checkpoints(),
            timeline: self.timeline_info(),
        })
    }

    /// 从磁盘加载完整 `.rtape` 磁带文件（严格校验头字段、压缩上限、累计解压上限、offset、尾部残留与单调性约束）
    pub fn load_file(path: impl AsRef<Path>) -> EmuResult<Self> {
        let path = path.as_ref();
        let file_len = fs::metadata(path)?.len();
        if file_len > MAX_TAPE_FILE_BYTES {
            return Err(EmuError::Backend(format!(
                ".rtape 文件大小超出安全上限 ({file_len} > {MAX_TAPE_FILE_BYTES}): {}",
                path.display()
            )));
        }
        let data = fs::read(path)?;
        if data.len() < 32 {
            return Err(EmuError::Backend(format!(
                "无效的 .rtape 文件（过短: {} bytes）: {}",
                data.len(),
                path.display()
            )));
        }
        if &data[0..8] != TAPE_MAGIC {
            return Err(EmuError::Backend(format!(
                "无效的 .rtape 魔数（期望 RTAPE001）: {}",
                path.display()
            )));
        }
        let version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if version != TAPE_VERSION {
            return Err(EmuError::Backend(format!(
                "不支持的 .rtape 版本 v{version}（当前支持 v{TAPE_VERSION}）"
            )));
        }
        let flags = u32::from_le_bytes(data[12..16].try_into().unwrap());
        if (flags & !TAPE_FLAG_ZLIB) != 0 {
            return Err(EmuError::Backend(format!(
                "不支持的 .rtape 标志位: 0x{flags:08x}"
            )));
        }
        let compressed_flag = (flags & TAPE_FLAG_ZLIB) != 0;
        let expected_chunks = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
        if expected_chunks == 0 || expected_chunks > MAX_CHUNKS {
            return Err(EmuError::Backend(format!(
                "非法的 .rtape 检查点声明数量: {expected_chunks}"
            )));
        }
        let event_log_offset = u64::from_le_bytes(data[24..32].try_into().unwrap());

        let mut pos = 32usize;
        let mut chunks = Vec::new();
        let mut event_log: Option<Arc<TapeEventLog>> = None;
        let mut total_uncompressed: usize = 0;
        while pos < data.len() {
            let chunk_start = pos as u64;
            let hdr_end = pos
                .checked_add(12)
                .ok_or_else(|| EmuError::Backend(".rtape Chunk 偏移溢出".to_string()))?;
            if hdr_end > data.len() {
                return Err(EmuError::Backend("截断的 .rtape Chunk 头".to_string()));
            }
            let tag = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            let uncomp_len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let comp_len = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap()) as usize;
            pos = hdr_end;
            let payload_end = pos
                .checked_add(comp_len)
                .ok_or_else(|| EmuError::Backend(".rtape Chunk 长度溢出".to_string()))?;
            if payload_end > data.len() {
                return Err(EmuError::Backend("截断的 .rtape Chunk 载荷".to_string()));
            }
            let slice = &data[pos..payload_end];
            pos = payload_end;

            if tag == CHUNK_EVENT_LOG {
                if event_log_offset == 0 {
                    // 无 header event_log_offset 声明的未知未来扩展段：安全前向跳过
                    continue;
                }
                if event_log.is_some() {
                    return Err(EmuError::Backend(
                        "损坏的 .rtape 文件：包含重复的 CHUNK_EVENT_LOG 段".to_string(),
                    ));
                }
                if chunk_start != event_log_offset {
                    return Err(EmuError::Backend(format!(
                        "损坏的 .rtape 文件：EventLog 偏移不匹配 header={event_log_offset} actual={chunk_start}"
                    )));
                }
                if uncomp_len > MAX_CHUNK_UNCOMPRESSED {
                    return Err(EmuError::Backend(format!(
                        ".rtape EventLog 解压声明长度超出安全上限: {uncomp_len} bytes"
                    )));
                }
                total_uncompressed = total_uncompressed.saturating_add(uncomp_len);
                if total_uncompressed > MAX_TOTAL_UNCOMPRESSED {
                    return Err(EmuError::Backend(
                        ".rtape 累计解压大小超出安全上限（疑似跨块压缩炸弹）".to_string(),
                    ));
                }
                let raw = decompress_chunk_slice(slice, uncomp_len, compressed_flag)?;
                let mut reader = BinReader::new(&raw);
                let parsed = decode_event_log(&mut reader)?;
                if reader.remaining() != 0 {
                    return Err(EmuError::Backend(format!(
                        ".rtape EventLog 尾部存在 {} 字节未解析残留数据",
                        reader.remaining()
                    )));
                }
                event_log = Some(Arc::new(parsed));
                continue;
            }
            if tag != CHUNK_BASE_CHECKPOINT && tag != CHUNK_DELTA_CHECKPOINT {
                return Err(EmuError::Backend(format!("未知的 .rtape Chunk Tag: {tag}")));
            }
            if chunks.len() >= MAX_CHUNKS {
                return Err(EmuError::Backend(format!(
                    ".rtape 检查点数量超出安全上限: {MAX_CHUNKS}"
                )));
            }
            if uncomp_len > MAX_CHUNK_UNCOMPRESSED {
                return Err(EmuError::Backend(format!(
                    ".rtape Chunk 解压声明长度超出安全上限: {uncomp_len} bytes"
                )));
            }
            total_uncompressed = total_uncompressed.saturating_add(uncomp_len);
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED {
                return Err(EmuError::Backend(
                    ".rtape 累计解压大小超出安全上限（疑似跨块压缩炸弹）".to_string(),
                ));
            }

            let raw = decompress_chunk_slice(slice, uncomp_len, compressed_flag)?;

            let mut reader = BinReader::new(&raw);
            let mut chunk = decode_chunk_payload(&mut reader, tag == CHUNK_DELTA_CHECKPOINT)?;
            if reader.remaining() != 0 {
                return Err(EmuError::Backend(format!(
                    ".rtape Chunk 尾部存在 {} 字节未解析残留数据",
                    reader.remaining()
                )));
            }
            chunk.compressed_bytes = comp_len;
            chunk.uncompressed_bytes = raw.len();
            chunks.push(chunk);
        }

        if chunks.is_empty() {
            return Err(EmuError::Backend("空的 .rtape 文件（无检查点）".to_string()));
        }
        if chunks[0].is_delta {
            return Err(EmuError::Backend(
                "损坏的 .rtape 文件：首个检查点必须为 BASE 帧而非 DELTA 帧".to_string(),
            ));
        }
        if chunks.len() != expected_chunks {
            return Err(EmuError::Backend(format!(
                "损坏或截断的 .rtape 文件：文件头声明 {expected_chunks} 个检查点，实际读取到 {} 个",
                chunks.len()
            )));
        }
        if event_log_offset != 0 && event_log.is_none() {
            return Err(EmuError::Backend(format!(
                "损坏或截断的 .rtape 文件：文件头声明 EventLog 偏移 {event_log_offset} 但未读取到 CHUNK_EVENT_LOG"
            )));
        }
        if let Some(ref log) = event_log {
            if chunks[0].meta.insn_count != log.start_insn {
                return Err(EmuError::Backend(format!(
                    "损坏的 .rtape 时间轴：首帧 insn={} 与 EventLog start_insn={} 不一致",
                    chunks[0].meta.insn_count, log.start_insn
                )));
            }
            let mut prev_insn = chunks[0].meta.insn_count;
            for (idx, c) in chunks.iter().enumerate() {
                if c.meta.insn_count < prev_insn || c.meta.insn_count > log.end_insn {
                    return Err(EmuError::Backend(format!(
                        "损坏的 .rtape 时间轴：检查点 #{idx} insn={} 违反单调/范围约束 [{prev_insn}, {}]",
                        c.meta.insn_count, log.end_insn
                    )));
                }
                prev_insn = c.meta.insn_count;
            }
        }
        Ok(Self { chunks, event_log })
    }

    /// 读取磁盘 `.rtape` 摘要信息（列出全部检查点、页数、体积、模块与可选时间旅行时间轴）
    pub fn inspect_file(path: impl AsRef<Path>) -> EmuResult<TapeSummary> {
        let path = path.as_ref();
        let file_size = fs::metadata(path)?.len();
        let tape = Self::load_file(path)?;
        Ok(TapeSummary {
            version: TAPE_VERSION,
            file_size,
            checkpoints: tape.checkpoints(),
            timeline: tape.timeline_info(),
        })
    }
}

fn decompress_chunk_slice(
    slice: &[u8],
    uncomp_len: usize,
    compressed_flag: bool,
) -> EmuResult<Vec<u8>> {
    if compressed_flag {
        let dec = ZlibDecoder::new(slice);
        let mut out = Vec::with_capacity(uncomp_len.min(64 * 1024));
        dec.take((MAX_CHUNK_UNCOMPRESSED as u64) + 1)
            .read_to_end(&mut out)
            .map_err(|e| EmuError::Backend(format!(".rtape Zlib 解压失败: {e}")))?;
        if out.len() > MAX_CHUNK_UNCOMPRESSED {
            return Err(EmuError::Backend(
                ".rtape Zlib 解压结果超出安全上限（疑似压缩炸弹）".to_string(),
            ));
        }
        if out.len() != uncomp_len {
            return Err(EmuError::Backend(format!(
                ".rtape Chunk 解压长度不匹配: expected={uncomp_len}, actual={}",
                out.len()
            )));
        }
        Ok(out)
    } else {
        if slice.len() != uncomp_len {
            return Err(EmuError::Backend(format!(
                ".rtape 非压缩 Chunk 长度不匹配: expected={uncomp_len}, actual={}",
                slice.len()
            )));
        }
        Ok(slice.to_vec())
    }
}

/// 检查 4KB 页是否全零（用于稀疏存储优化）
#[inline]
pub(crate) fn is_zero_page(page: &[u8; 4096]) -> bool {
    let (prefix, aligned, suffix) = unsafe { page.align_to::<u64>() };
    prefix.iter().all(|&b| b == 0)
        && aligned.iter().all(|&w| w == 0)
        && suffix.iter().all(|&b| b == 0)
}

fn collect_mapped_pages(
    vmas: &[VmaRegion],
    nonzero_pages: &BTreeMap<u64, [u8; 4096]>,
) -> EmuResult<std::collections::BTreeSet<u64>> {
    let mut set = std::collections::BTreeSet::new();
    for v in vmas {
        if v.start >= v.end
            || (v.start & (PAGE_SIZE - 1)) != 0
            || (v.end & (PAGE_SIZE - 1)) != 0
            || v.end > MAX_GUEST_VA
        {
            return Err(EmuError::Backend(format!(
                "VMA 区间越界或未对齐: [0x{:x}, 0x{:x})",
                v.start, v.end
            )));
        }
        let page_count = ((v.end - v.start) / PAGE_SIZE) as usize;
        if set.len().saturating_add(page_count) > MAX_TOTAL_MAPPED_PAGES {
            return Err(EmuError::Backend("VMA 总映射页数超出安全上限".to_string()));
        }
        let mut p = v.start;
        while p < v.end {
            set.insert(p);
            p = p
                .checked_add(PAGE_SIZE)
                .ok_or_else(|| EmuError::Backend("VMA 页枚举溢出".to_string()))?;
        }
    }
    for &p in nonzero_pages.keys() {
        set.insert(p);
    }
    Ok(set)
}

// ============================================================================
// 紧凑零依赖二进制编解码器
// ============================================================================

struct BinWriter<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> BinWriter<'a> {
    fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }
    fn i8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn i16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn f32(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn f64(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) -> EmuResult<()> {
        let len = u32::try_from(b.len())
            .map_err(|_| EmuError::Backend("字节序列长度超出 u32 上限".to_string()))?;
        self.u32(len);
        self.buf.extend_from_slice(b);
        Ok(())
    }
    fn str(&mut self, s: &str) -> EmuResult<()> {
        self.bytes(s.as_bytes())
    }
    fn len_u32(&mut self, len: usize) -> EmuResult<()> {
        let n = u32::try_from(len)
            .map_err(|_| EmuError::Backend("集合长度超出 u32 上限".to_string()))?;
        self.u32(n);
        Ok(())
    }
    fn raw_fixed(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
}

struct BinReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BinReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    fn read_count(&mut self, min_elem_bytes: usize) -> EmuResult<(usize, usize)> {
        let count = self.u32()? as usize;
        let max_possible = self.remaining() / min_elem_bytes.max(1);
        if count > max_possible {
            return Err(EmuError::Backend(format!(
                ".rtape 集合长度超出剩余载荷上限: count={count}, remaining={}",
                self.remaining()
            )));
        }
        Ok((count, count.min(65_536)))
    }
    fn usize_from_u64(&mut self) -> EmuResult<usize> {
        let v = self.u64()?;
        usize::try_from(v).map_err(|_| EmuError::Backend(".rtape usize 字段溢出".to_string()))
    }
    fn take(&mut self, n: usize) -> EmuResult<&'a [u8]> {
        if self.pos.saturating_add(n) > self.data.len() {
            return Err(EmuError::Backend(format!(
                ".rtape 解码越界: need {n} at offset {}/{}",
                self.pos,
                self.data.len()
            )));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> EmuResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> EmuResult<bool> {
        Ok(self.u8()? != 0)
    }
    fn i8(&mut self) -> EmuResult<i8> {
        Ok(self.u8()? as i8)
    }
    fn u16(&mut self) -> EmuResult<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn i16(&mut self) -> EmuResult<i16> {
        Ok(i16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> EmuResult<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i32(&mut self) -> EmuResult<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> EmuResult<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> EmuResult<i64> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> EmuResult<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn f32(&mut self) -> EmuResult<f32> {
        Ok(f32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn f64(&mut self) -> EmuResult<f64> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> EmuResult<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
    fn str(&mut self) -> EmuResult<String> {
        let b = self.bytes()?;
        String::from_utf8(b)
            .map_err(|e| EmuError::Backend(format!(".rtape 字符串 UTF-8 损坏: {e}")))
    }
}

fn encode_chunk_payload(out: &mut Vec<u8>, c: &TapeCheckpointChunk) -> EmuResult<()> {
    let mut w = BinWriter::new(out);

    // 1. Meta
    w.u32(c.meta.index);
    w.str(&c.meta.label)?;
    w.u64(c.meta.timestamp_ms);
    w.str(&c.meta.source_backend)?;
    w.u64(c.meta.insn_count);

    // 2. CPU Registers & Layout
    for &x in &c.regs.x {
        w.u64(x);
    }
    w.u64(c.regs.sp);
    w.u64(c.regs.pc);
    w.u64(c.regs.pstate);
    w.u64(c.regs.tpidr_el0);
    for &q in &c.regs.q {
        w.u128(q);
    }
    w.u32(c.regs.fpcr);
    w.u32(c.regs.fpsr);

    w.u64(c.cpu_layout.stack_base);
    w.u64(c.cpu_layout.stack_size);
    w.u64(c.cpu_layout.stack_top);
    w.u64(c.cpu_layout.tls_base);
    w.u64(c.cpu_layout.errno_addr);

    // 3. VMAs & Heap
    w.len_u32(c.vmas.len())?;
    for v in &c.vmas {
        w.u64(v.start);
        w.u64(v.end);
        #[allow(clippy::unnecessary_cast)]
        let perms_u32 = v.perms.0 as u32;
        w.u32(perms_u32);
        w.str(&v.label)?;
        w.u64(v.file_offset);
    }
    let h = c.heap.export_raw();
    w.u64(h.base);
    w.u64(h.size);
    w.u64(h.cursor);
    w.u64(h.in_use);
    w.len_u32(h.free_blocks.len())?;
    for (k, v) in h.free_blocks {
        w.u64(k);
        w.u64(v);
    }
    w.len_u32(h.allocated.len())?;
    for (k, v) in h.allocated {
        w.u64(k);
        w.u64(v);
    }
    w.u64(c.brk_cursor);
    w.u64(c.mmap_cursor);

    // 4. Pages (Base or Delta)
    w.len_u32(c.removed_pages.len())?;
    for &p in &c.removed_pages {
        w.u64(p);
    }
    w.len_u32(c.zeroed_pages.len())?;
    for &p in &c.zeroed_pages {
        w.u64(p);
    }
    w.len_u32(c.pages.len())?;
    for (p, data) in &c.pages {
        w.u64(*p);
        w.raw_fixed(data);
    }

    // 5. Linker
    w.len_u32(c.linker.modules.len())?;
    for m in &c.linker.modules {
        w.str(&m.name)?;
        w.u64(m.base_addr);
        w.u64(m.image_size);
        w.len_u32(m.symbols.len())?;
        for (sym, &addr) in &m.symbols {
            w.str(sym)?;
            w.u64(addr);
        }
        w.len_u32(m.needed.len())?;
        for n in &m.needed {
            w.str(n)?;
        }
        w.len_u32(m.init_array.len())?;
        for &a in &m.init_array {
            w.u64(a);
        }
    }
    w.len_u32(c.linker.load_order.len())?;
    for s in &c.linker.load_order {
        w.str(s)?;
    }
    w.u64(c.linker.next_sys_base);
    w.u64(c.linker.next_app_base);
    w.len_u32(c.linker.hle_overrides.len())?;
    for s in &c.linker.hle_overrides {
        w.str(s)?;
    }
    w.u64(c.linker.next_tls_offset);
    w.len_u32(c.linker.search_paths.len())?;
    for sp in &c.linker.search_paths {
        w.str(sp)?;
    }
    w.len_u32(c.linker.memory_libs.len())?;
    for (name, bytes) in &c.linker.memory_libs {
        w.str(name)?;
        w.bytes(bytes)?;
    }

    // 6. Trampolines
    w.len_u32(c.trampolines.slot_names.len())?;
    for s in &c.trampolines.slot_names {
        w.str(s)?;
    }
    w.len_u32(c.trampolines.pthread_keys.len())?;
    for &(k, v) in &c.trampolines.pthread_keys {
        w.u32(k);
        w.u64(v);
    }
    w.u32(c.trampolines.next_pthread_key);
    w.u64(c.trampolines.next_pthread_tid);
    w.len_u32(c.trampolines.pending_threads.len())?;
    for &(tid, f, a) in &c.trampolines.pending_threads {
        w.u64(tid);
        w.u64(f);
        w.u64(a);
    }
    w.len_u32(c.trampolines.pthread_exit_stack.len())?;
    for &(a, b) in &c.trampolines.pthread_exit_stack {
        w.u64(a);
        w.u64(b);
    }
    w.len_u32(c.trampolines.sigactions.len())?;
    for &(sig, ref act) in &c.trampolines.sigactions {
        w.i32(sig);
        w.raw_fixed(act);
    }
    w.u64(c.trampolines.sigmask);
    w.len_u32(c.trampolines.mmap_backings.len())?;
    for (addr, mb) in &c.trampolines.mmap_backings {
        w.u64(*addr);
        w.str(&mb.path)?;
        w.u64(mb.offset as u64);
        w.u64(mb.len as u64);
    }
    w.len_u32(c.trampolines.stdio_streams.len())?;
    for (ptr, st) in &c.trampolines.stdio_streams {
        w.u64(*ptr);
        w.i32(st.fd);
        w.bool(st.eof);
        w.bool(st.err);
        w.bool(st.ungetc_buf.is_some());
        if let Some(b) = st.ungetc_buf {
            w.u8(b);
        }
    }
    w.len_u32(c.trampolines.dir_streams.len())?;
    for (ptr, ds) in &c.trampolines.dir_streams {
        w.u64(*ptr);
        w.len_u32(ds.entries.len())?;
        for (name, dtype) in &ds.entries {
            w.str(name)?;
            w.u8(*dtype);
        }
        w.u64(ds.cursor as u64);
        w.u64(ds.dirent_buf);
    }
    w.len_u32(c.trampolines.asset_streams.len())?;
    for (ptr, a) in &c.trampolines.asset_streams {
        w.u64(*ptr);
        w.bytes(&a.data)?;
        w.u64(a.pos as u64);
        w.bool(a.guest_buf.is_some());
        if let Some(gb) = a.guest_buf {
            w.u64(gb);
        }
    }
    w.len_u32(c.trampolines.asset_dirs.len())?;
    for (ptr, ad) in &c.trampolines.asset_dirs {
        w.u64(*ptr);
        w.len_u32(ad.files.len())?;
        for f in &ad.files {
            w.str(f)?;
        }
        w.u64(ad.cursor as u64);
        w.u64(ad.name_buf);
    }
    w.len_u32(c.trampolines.prop_infos.len())?;
    for (ptr, pi) in &c.trampolines.prop_infos {
        w.u64(*ptr);
        w.str(&pi.name)?;
        w.str(&pi.value)?;
        w.u64(pi.name_ptr);
        w.u64(pi.value_ptr);
    }
    w.bool(c.trampolines.last_dlerror.is_some());
    if let Some(err) = &c.trampolines.last_dlerror {
        w.str(err)?;
    }
    w.len_u32(c.trampolines.loaded_modules.len())?;
    for m in &c.trampolines.loaded_modules {
        w.str(&m.name)?;
        w.u64(m.base_addr);
        w.u64(m.image_size);
        w.len_u32(m.symbols.len())?;
        for (sym, &addr) in &m.symbols {
            w.str(sym)?;
            w.u64(addr);
        }
    }
    w.u64(c.trampolines.lcg48_state);
    w.u64(c.trampolines.errno_addr);

    // 7. JNI
    w.str(&c.jni.package_name)?;
    encode_device_profile(&mut w, &c.jni.device_profile)?;
    encode_object_table(&mut w, &c.jni.objects)?;
    w.len_u32(c.jni.registered_natives.len())?;
    for rn in &c.jni.registered_natives {
        w.str(&rn.class_name)?;
        w.str(&rn.name)?;
        w.str(&rn.sig)?;
        w.u64(rn.fn_ptr);
    }
    w.len_u32(c.jni.methods.len())?;
    for (id, m) in &c.jni.methods {
        w.u64(*id);
        w.str(&m.class_name)?;
        w.str(&m.name)?;
        w.str(&m.sig)?;
        w.bool(m.is_static);
    }
    w.u64(c.jni.next_method_id);
    w.len_u32(c.jni.fields.len())?;
    for (id, f) in &c.jni.fields {
        w.u64(*id);
        w.str(&f.class_name)?;
        w.str(&f.name)?;
        w.str(&f.sig)?;
        w.bool(f.is_static);
    }
    w.u64(c.jni.next_field_id);
    w.len_u32(c.jni.static_fields.len())?;
    for (cls, field, val) in &c.jni.static_fields {
        w.str(cls)?;
        w.str(field)?;
        encode_jvalue(&mut w, *val);
    }
    w.u64(c.jni.dex_count as u64);
    w.len_u32(c.jni.dex_classes.len())?;
    for cls in &c.jni.dex_classes {
        encode_dex_class(&mut w, cls)?;
    }
    w.bool(c.jni.strict_find_class);
    w.u64(c.jni.pending_exception.0);
    w.len_u32(c.jni.utf_buffers.len())?;
    for &(addr, r) in &c.jni.utf_buffers {
        w.u64(addr);
        w.u64(r.0);
    }
    w.len_u32(c.jni.array_buffers.len())?;
    for &(addr, r, len) in &c.jni.array_buffers {
        w.u64(addr);
        w.u64(r.0);
        w.u64(len as u64);
    }

    // 8. VFS & Net
    w.str(&c.vfs.package_name)?;
    w.u32(c.vfs.pid);
    w.u32(c.vfs.ppid);
    w.u32(c.vfs.uid);
    w.u32(c.vfs.tid);
    w.len_u32(c.vfs.properties.len())?;
    for (k, v) in &c.vfs.properties {
        w.str(k)?;
        w.str(v)?;
    }
    encode_device_profile(&mut w, &c.vfs.device)?;
    w.len_u32(c.vfs.sysroot_mounts.len())?;
    for (prefix, host) in &c.vfs.sysroot_mounts {
        w.str(prefix)?;
        w.str(host)?;
    }
    w.len_u32(c.vfs.overlay_files.len())?;
    for (k, v) in &c.vfs.overlay_files {
        w.str(k)?;
        w.bytes(v)?;
    }
    w.len_u32(c.vfs.overlay_dirs.len())?;
    for d in &c.vfs.overlay_dirs {
        w.str(d)?;
    }
    w.len_u32(c.vfs.fds.len())?;
    for (fd, of) in &c.vfs.fds {
        w.i32(*fd);
        encode_open_file(&mut w, of)?;
    }
    w.i32(c.vfs.next_fd);
    w.u64(c.vfs.rng_state);
    w.u64(c.vfs.mono_clock_ns);
    w.bool(c.vfs.use_real_clock);
    encode_net_state(&mut w, &c.vfs.net)?;

    // 9. 可选尾部扩展块（魔数 "SCRT" = 0x5343_5254，完全向后兼容旧版 .rtape）：
    //    持久化 [host-scratch] 隔离分配器元数据与 freeze_layout 标志，防止倒带/恢复后 UAF 或 UnmappedMemory
    if let Some(ref hs) = c.host_scratch {
        w.u32(0x5343_5254);
        w.bool(c.freeze_layout.unwrap_or(false));
        let raw = hs.export_raw();
        w.u64(raw.base);
        w.u64(raw.size);
        w.u64(raw.cursor);
        w.u64(raw.in_use);
        w.len_u32(raw.free_blocks.len())?;
        for (k, v) in raw.free_blocks {
            w.u64(k);
            w.u64(v);
        }
        w.len_u32(raw.allocated.len())?;
        for (k, v) in raw.allocated {
            w.u64(k);
            w.u64(v);
        }
    }
    // 10. 可选尾部扩展块（魔数 "RNG2" = 0x524E_4732，完全向后兼容旧版 .rtape）：
    //     持久化独立 libc `rand()`/`srand()` PRNG 状态，与 OS 熵源 `rng_state` 严格分离
    w.u32(0x524E_4732);
    w.u64(c.vfs.libc_rand_state);
    Ok(())
}

fn validate_page_addr(addr: u64, label: &str) -> EmuResult<()> {
    if (addr & (PAGE_SIZE - 1)) != 0 || !(MIN_GUEST_VA..MAX_GUEST_VA).contains(&addr) {
        return Err(EmuError::Backend(format!(
            ".rtape {label} 页地址未对齐或越界: 0x{addr:x}"
        )));
    }
    Ok(())
}

fn decode_chunk_payload(r: &mut BinReader<'_>, is_delta: bool) -> EmuResult<TapeCheckpointChunk> {
    // 1. Meta
    let meta = TapeMeta {
        index: r.u32()?,
        label: r.str()?,
        timestamp_ms: r.u64()?,
        source_backend: r.str()?,
        insn_count: r.u64()?,
    };

    // 2. CPU Registers & Layout
    let mut x = [0u64; 31];
    for slot in &mut x {
        *slot = r.u64()?;
    }
    let sp = r.u64()?;
    let pc = r.u64()?;
    let pstate = r.u64()? & 0xF000_0000;
    let tpidr_el0 = r.u64()?;
    let mut q = [0u128; 32];
    for slot in &mut q {
        *slot = r.u128()?;
    }
    let fpcr = r.u32()?;
    let fpsr = r.u32()?;
    let regs = GenericCpuContext {
        x,
        sp,
        pc,
        pstate,
        tpidr_el0,
        q,
        fpcr,
        fpsr,
    };

    let cpu_layout = CpuContext {
        stack_base: r.u64()?,
        stack_size: r.u64()?,
        stack_top: r.u64()?,
        tls_base: r.u64()?,
        errno_addr: r.u64()?,
    };

    // 3. VMAs & Heap
    let (vma_count, vma_cap) = r.read_count(32)?;
    let mut vmas = Vec::with_capacity(vma_cap);
    let mut total_vma_pages: usize = 0;
    for _ in 0..vma_count {
        let start = r.u64()?;
        let end = r.u64()?;
        let perms_raw = r.u32()?;
        let label = r.str()?;
        let file_offset = r.u64()?;
        if start >= end
            || (start & (PAGE_SIZE - 1)) != 0
            || (end & (PAGE_SIZE - 1)) != 0
            || start < MIN_GUEST_VA
            || end > MAX_GUEST_VA
        {
            return Err(EmuError::Backend(format!(
                ".rtape VMA 区间非法: [0x{start:x}, 0x{end:x})"
            )));
        }
        #[allow(clippy::unnecessary_cast)]
        let all_perms_u32 = Prot::ALL.0 as u32;
        if (perms_raw & !all_perms_u32) != 0 {
            return Err(EmuError::Backend(format!(
                ".rtape VMA 权限位非法: 0x{perms_raw:x}"
            )));
        }
        let pages_in_vma = ((end - start) / PAGE_SIZE) as usize;
        total_vma_pages = total_vma_pages.saturating_add(pages_in_vma);
        if total_vma_pages > MAX_TOTAL_MAPPED_PAGES {
            return Err(EmuError::Backend(
                ".rtape VMA 总映射页数超过安全上限".to_string(),
            ));
        }
        #[allow(clippy::unnecessary_cast)]
        let perms = Prot(perms_raw as _);
        vmas.push(VmaRegion {
            start,
            end,
            perms,
            label,
            file_offset,
        });
    }
    let h_base = r.u64()?;
    let h_size = r.u64()?;
    let h_cursor = r.u64()?;
    let h_in_use = r.u64()?;
    let (h_free_len, h_free_cap) = r.read_count(16)?;
    let mut h_free = Vec::with_capacity(h_free_cap);
    for _ in 0..h_free_len {
        h_free.push((r.u64()?, r.u64()?));
    }
    let (h_alloc_len, h_alloc_cap) = r.read_count(16)?;
    let mut h_alloc = Vec::with_capacity(h_alloc_cap);
    for _ in 0..h_alloc_len {
        h_alloc.push((r.u64()?, r.u64()?));
    }
    let heap = BumpAllocator::from_raw(crate::memory::BumpAllocatorRaw {
        base: h_base,
        size: h_size,
        cursor: h_cursor,
        free_blocks: h_free,
        allocated: h_alloc,
        in_use: h_in_use,
    });
    let brk_cursor = r.u64()?;
    let mmap_cursor = r.u64()?;

    // 4. Pages
    let (removed_len, removed_cap) = r.read_count(8)?;
    let mut removed_pages = Vec::with_capacity(removed_cap);
    for _ in 0..removed_len {
        let p = r.u64()?;
        validate_page_addr(p, "removed_page")?;
        removed_pages.push(p);
    }
    let (zeroed_len, zeroed_cap) = r.read_count(8)?;
    let mut zeroed_pages = Vec::with_capacity(zeroed_cap);
    for _ in 0..zeroed_len {
        let p = r.u64()?;
        validate_page_addr(p, "zeroed_page")?;
        zeroed_pages.push(p);
    }
    let (page_len, page_cap) = r.read_count(4104)?;
    let mut pages = Vec::with_capacity(page_cap);
    for _ in 0..page_len {
        let addr = r.u64()?;
        validate_page_addr(addr, "page")?;
        let slice = r.take(4096)?;
        let mut buf = [0u8; 4096];
        buf.copy_from_slice(slice);
        pages.push((addr, buf));
    }

    // 5. Linker
    let (mod_len, mod_cap) = r.read_count(32)?;
    let mut modules = Vec::with_capacity(mod_cap);
    for _ in 0..mod_len {
        let name = r.str()?;
        let base_addr = r.u64()?;
        let image_size = r.u64()?;
        let (sym_len, sym_cap) = r.read_count(12)?;
        let mut symbols = HashMap::with_capacity(sym_cap);
        for _ in 0..sym_len {
            symbols.insert(r.str()?, r.u64()?);
        }
        let (needed_len, needed_cap) = r.read_count(4)?;
        let mut needed = Vec::with_capacity(needed_cap);
        for _ in 0..needed_len {
            needed.push(r.str()?);
        }
        let (init_len, init_cap) = r.read_count(8)?;
        let mut init_array = Vec::with_capacity(init_cap);
        for _ in 0..init_len {
            init_array.push(r.u64()?);
        }
        modules.push(LoadedModule {
            name,
            base_addr,
            image_size,
            symbols,
            needed,
            init_array,
        });
    }
    let (lo_len, lo_cap) = r.read_count(4)?;
    let mut load_order = Vec::with_capacity(lo_cap);
    for _ in 0..lo_len {
        load_order.push(r.str()?);
    }
    let next_sys_base = r.u64()?;
    let next_app_base = r.u64()?;
    let (hle_len, hle_cap) = r.read_count(4)?;
    let mut hle_overrides = Vec::with_capacity(hle_cap);
    for _ in 0..hle_len {
        hle_overrides.push(r.str()?);
    }
    let next_tls_offset = r.u64()?;
    let (sp_len, sp_cap) = r.read_count(4)?;
    let mut search_paths = Vec::with_capacity(sp_cap);
    for _ in 0..sp_len {
        search_paths.push(r.str()?);
    }
    let (ml_len, ml_cap) = r.read_count(8)?;
    let mut memory_libs = Vec::with_capacity(ml_cap);
    for _ in 0..ml_len {
        memory_libs.push((r.str()?, r.bytes()?));
    }
    let linker = LinkerTapeState {
        modules,
        load_order,
        next_sys_base,
        next_app_base,
        hle_overrides,
        next_tls_offset,
        search_paths,
        memory_libs,
    };

    // 6. Trampolines
    let (slot_len, slot_cap) = r.read_count(4)?;
    if (slot_len as u64).saturating_mul(4) > TRAMPOLINE_SIZE {
        return Err(EmuError::Backend(format!(
            ".rtape HLE 跳板槽位数超界: {slot_len}"
        )));
    }
    let mut slot_names = Vec::with_capacity(slot_cap);
    for _ in 0..slot_len {
        slot_names.push(r.str()?);
    }
    let (pk_len, pk_cap) = r.read_count(12)?;
    let mut pthread_keys = Vec::with_capacity(pk_cap);
    for _ in 0..pk_len {
        pthread_keys.push((r.u32()?, r.u64()?));
    }
    let next_pthread_key = r.u32()?;
    let next_pthread_tid = r.u64()?;
    let (pt_len, pt_cap) = r.read_count(24)?;
    let mut pending_threads = Vec::with_capacity(pt_cap);
    for _ in 0..pt_len {
        pending_threads.push((r.u64()?, r.u64()?, r.u64()?));
    }
    let (pe_len, pe_cap) = r.read_count(16)?;
    let mut pthread_exit_stack = Vec::with_capacity(pe_cap);
    for _ in 0..pe_len {
        pthread_exit_stack.push((r.u64()?, r.u64()?));
    }
    let (sig_len, sig_cap) = r.read_count(36)?;
    let mut sigactions = Vec::with_capacity(sig_cap);
    for _ in 0..sig_len {
        let sig = r.i32()?;
        let mut act = [0u8; 32];
        act.copy_from_slice(r.take(32)?);
        sigactions.push((sig, act));
    }
    let sigmask = r.u64()?;
    let (mb_len, mb_cap) = r.read_count(28)?;
    let mut mmap_backings = Vec::with_capacity(mb_cap);
    for _ in 0..mb_len {
        mmap_backings.push((
            r.u64()?,
            MmapFileBacking {
                path: r.str()?,
                offset: r.usize_from_u64()?,
                len: r.usize_from_u64()?,
            },
        ));
    }
    let (st_len, st_cap) = r.read_count(15)?;
    let mut stdio_streams = Vec::with_capacity(st_cap);
    for _ in 0..st_len {
        let ptr = r.u64()?;
        let fd = r.i32()?;
        let eof = r.bool()?;
        let err = r.bool()?;
        let ungetc_buf = if r.bool()? { Some(r.u8()?) } else { None };
        stdio_streams.push((
            ptr,
            StdioStream {
                fd,
                eof,
                err,
                ungetc_buf,
            },
        ));
    }
    let (ds_len, ds_cap) = r.read_count(28)?;
    let mut dir_streams = Vec::with_capacity(ds_cap);
    for _ in 0..ds_len {
        let ptr = r.u64()?;
        let (en_len, en_cap) = r.read_count(5)?;
        let mut entries = Vec::with_capacity(en_cap);
        for _ in 0..en_len {
            entries.push((r.str()?, r.u8()?));
        }
        let cursor = r.usize_from_u64()?;
        let dirent_buf = r.u64()?;
        dir_streams.push((
            ptr,
            DirStream {
                entries,
                cursor,
                dirent_buf,
            },
        ));
    }
    let (as_len, as_cap) = r.read_count(21)?;
    let mut asset_streams = Vec::with_capacity(as_cap);
    for _ in 0..as_len {
        let ptr = r.u64()?;
        let data = r.bytes()?;
        let pos = r.usize_from_u64()?;
        let guest_buf = if r.bool()? { Some(r.u64()?) } else { None };
        asset_streams.push((
            ptr,
            AssetStream {
                data,
                pos,
                guest_buf,
            },
        ));
    }
    let (ad_len, ad_cap) = r.read_count(28)?;
    let mut asset_dirs = Vec::with_capacity(ad_cap);
    for _ in 0..ad_len {
        let ptr = r.u64()?;
        let (fl_len, fl_cap) = r.read_count(4)?;
        let mut files = Vec::with_capacity(fl_cap);
        for _ in 0..fl_len {
            files.push(r.str()?);
        }
        let cursor = r.usize_from_u64()?;
        let name_buf = r.u64()?;
        asset_dirs.push((
            ptr,
            AssetDirStream {
                files,
                cursor,
                name_buf,
            },
        ));
    }
    let (pi_len, pi_cap) = r.read_count(32)?;
    let mut prop_infos = Vec::with_capacity(pi_cap);
    for _ in 0..pi_len {
        prop_infos.push((
            r.u64()?,
            PropInfoEntry {
                name: r.str()?,
                value: r.str()?,
                name_ptr: r.u64()?,
                value_ptr: r.u64()?,
            },
        ));
    }
    let last_dlerror = if r.bool()? { Some(r.str()?) } else { None };
    let (dl_len, dl_cap) = r.read_count(24)?;
    let mut loaded_modules = Vec::with_capacity(dl_cap);
    for _ in 0..dl_len {
        let name = r.str()?;
        let base_addr = r.u64()?;
        let image_size = r.u64()?;
        let (sym_len, sym_cap) = r.read_count(12)?;
        let mut symbols = HashMap::with_capacity(sym_cap);
        for _ in 0..sym_len {
            symbols.insert(r.str()?, r.u64()?);
        }
        loaded_modules.push(DlModuleEntry {
            name,
            base_addr,
            image_size,
            symbols,
        });
    }
    let lcg48_state = r.u64()?;
    let errno_addr = r.u64()?;
    let trampolines = TrampolineTapeState {
        slot_names,
        pthread_keys,
        next_pthread_key,
        next_pthread_tid,
        pending_threads,
        pthread_exit_stack,
        sigactions,
        sigmask,
        mmap_backings,
        stdio_streams,
        dir_streams,
        asset_streams,
        asset_dirs,
        prop_infos,
        last_dlerror,
        loaded_modules,
        lcg48_state,
        errno_addr,
    };

    // 7. JNI
    let jni_pkg = r.str()?;
    let jni_device = decode_device_profile(r)?;
    let objects = decode_object_table(r)?;
    let (rn_len, rn_cap) = r.read_count(20)?;
    let mut registered_natives = Vec::with_capacity(rn_cap);
    for _ in 0..rn_len {
        registered_natives.push(RegisteredNative {
            class_name: r.str()?,
            name: r.str()?,
            sig: r.str()?,
            fn_ptr: r.u64()?,
        });
    }
    let (meth_len, meth_cap) = r.read_count(21)?;
    let mut methods = Vec::with_capacity(meth_cap);
    for _ in 0..meth_len {
        methods.push((
            r.u64()?,
            MethodDesc {
                class_name: r.str()?,
                name: r.str()?,
                sig: r.str()?,
                is_static: r.bool()?,
            },
        ));
    }
    let next_method_id = r.u64()?;
    let (fld_len, fld_cap) = r.read_count(21)?;
    let mut fields = Vec::with_capacity(fld_cap);
    for _ in 0..fld_len {
        fields.push((
            r.u64()?,
            FieldDesc {
                class_name: r.str()?,
                name: r.str()?,
                sig: r.str()?,
                is_static: r.bool()?,
            },
        ));
    }
    let next_field_id = r.u64()?;
    let (sf_len, sf_cap) = r.read_count(9)?;
    let mut static_fields = Vec::with_capacity(sf_cap);
    for _ in 0..sf_len {
        static_fields.push((r.str()?, r.str()?, decode_jvalue(r)?));
    }
    let dex_count = r.usize_from_u64()?;
    let (dc_len, dc_cap) = r.read_count(25)?;
    let mut dex_classes = Vec::with_capacity(dc_cap);
    for _ in 0..dc_len {
        dex_classes.push(decode_dex_class(r)?);
    }
    let strict_find_class = r.bool()?;
    let pending_exception = JObjectRef(r.u64()?);
    let (utf_len, utf_cap) = r.read_count(16)?;
    let mut utf_buffers = Vec::with_capacity(utf_cap);
    for _ in 0..utf_len {
        utf_buffers.push((r.u64()?, JObjectRef(r.u64()?)));
    }
    let (arr_len, arr_cap) = r.read_count(24)?;
    let mut array_buffers = Vec::with_capacity(arr_cap);
    for _ in 0..arr_len {
        array_buffers.push((r.u64()?, JObjectRef(r.u64()?), r.usize_from_u64()?));
    }
    let jni = JniTapeState {
        package_name: jni_pkg,
        device_profile: jni_device,
        objects,
        registered_natives,
        methods,
        next_method_id,
        fields,
        next_field_id,
        static_fields,
        dex_count,
        dex_classes,
        strict_find_class,
        pending_exception,
        utf_buffers,
        array_buffers,
    };

    // 8. VFS & Net
    let vfs_pkg = r.str()?;
    let pid = r.u32()?;
    let ppid = r.u32()?;
    let uid = r.u32()?;
    let tid = r.u32()?;
    let (prop_len, prop_cap) = r.read_count(8)?;
    let mut properties = Vec::with_capacity(prop_cap);
    for _ in 0..prop_len {
        properties.push((r.str()?, r.str()?));
    }
    let vfs_device = decode_device_profile(r)?;
    let (sm_len, sm_cap) = r.read_count(8)?;
    let mut sysroot_mounts = Vec::with_capacity(sm_cap);
    for _ in 0..sm_len {
        sysroot_mounts.push((r.str()?, r.str()?));
    }
    let (ov_len, ov_cap) = r.read_count(8)?;
    let mut overlay_files = Vec::with_capacity(ov_cap);
    for _ in 0..ov_len {
        overlay_files.push((r.str()?, r.bytes()?));
    }
    let (od_len, od_cap) = r.read_count(4)?;
    let mut overlay_dirs = Vec::with_capacity(od_cap);
    for _ in 0..od_len {
        overlay_dirs.push(r.str()?);
    }
    let (fd_len, fd_cap) = r.read_count(9)?;
    let mut fds = Vec::with_capacity(fd_cap);
    for _ in 0..fd_len {
        fds.push((r.i32()?, decode_open_file(r)?));
    }
    let next_fd = r.i32()?;
    let rng_state = r.u64()?;
    let mono_clock_ns = r.u64()?;
    let use_real_clock = r.bool()?;
    let net = decode_net_state(r)?;
    let mut vfs = VfsTapeState {
        package_name: vfs_pkg,
        pid,
        ppid,
        uid,
        tid,
        properties,
        device: vfs_device,
        sysroot_mounts,
        overlay_files,
        overlay_dirs,
        fds,
        next_fd,
        rng_state,
        libc_rand_state: 1,
        mono_clock_ns,
        use_real_clock,
        net,
    };

    let mut host_scratch = None;
    let mut freeze_layout = None;
    let mut seen_scrt = false;
    let mut seen_rng2 = false;
    while r.remaining() > 0 {
        let tag = r.u32()?;
        match tag {
            0x5343_5254 if !seen_scrt => {
                seen_scrt = true;
                let fl = r.bool()?;
                let s_base = r.u64()?;
                let s_size = r.u64()?;
                let s_cursor = r.u64()?;
                let s_in_use = r.u64()?;
                let s_end = s_base.checked_add(s_size).ok_or_else(|| {
                    EmuError::Backend("SCRT 尾部块 host_scratch base+size 溢出".into())
                })?;
                if s_base != crate::memory::HOST_SCRATCH_BASE
                    || s_size != crate::memory::HOST_SCRATCH_SIZE
                    || s_cursor < s_base
                    || s_cursor > s_end
                {
                    return Err(EmuError::Backend(format!(
                        "SCRT 尾部块 host_scratch 元数据越界: base=0x{s_base:x}, size=0x{s_size:x}, cursor=0x{s_cursor:x}"
                    )));
                }
                let (sf_len, sf_cap) = r.read_count(16)?;
                let mut s_free = Vec::with_capacity(sf_cap);
                for _ in 0..sf_len {
                    s_free.push((r.u64()?, r.u64()?));
                }
                let (sa_len, sa_cap) = r.read_count(16)?;
                let mut s_alloc = Vec::with_capacity(sa_cap);
                for _ in 0..sa_len {
                    s_alloc.push((r.u64()?, r.u64()?));
                }
                host_scratch = Some(BumpAllocator::from_raw(crate::memory::BumpAllocatorRaw {
                    base: s_base,
                    size: s_size,
                    cursor: s_cursor,
                    free_blocks: s_free,
                    allocated: s_alloc,
                    in_use: s_in_use,
                }));
                freeze_layout = Some(fl);
            }
            0x524E_4732 if !seen_rng2 => {
                seen_rng2 = true;
                let lr = r.u64()?;
                vfs.libc_rand_state = if lr == 0 { 1 } else { lr };
            }
            other => {
                return Err(EmuError::Backend(format!(
                    "无效或重复的 checkpoint 尾部扩展块魔数: 0x{other:08x}"
                )));
            }
        }
    }

    Ok(TapeCheckpointChunk {
        meta,
        is_delta,
        pages,
        zeroed_pages,
        removed_pages,
        regs,
        cpu_layout,
        vmas,
        heap,
        brk_cursor,
        mmap_cursor,
        host_scratch,
        freeze_layout,
        linker,
        trampolines,
        jni,
        vfs,
        compressed_bytes: 0,
        uncompressed_bytes: 0,
    })
}

fn encode_device_profile(w: &mut BinWriter<'_>, d: &DeviceProfile) -> EmuResult<()> {
    w.str(&d.brand)?;
    w.str(&d.manufacturer)?;
    w.str(&d.model)?;
    w.str(&d.device)?;
    w.str(&d.product)?;
    w.str(&d.board)?;
    w.str(&d.hardware)?;
    w.str(&d.soc_platform)?;
    w.str(&d.fingerprint)?;
    w.str(&d.build_id)?;
    w.str(&d.build_display)?;
    w.str(&d.incremental)?;
    w.str(&d.security_patch)?;
    w.str(&d.android_release)?;
    w.u32(d.sdk_int);
    w.str(&d.abi)?;
    w.str(&d.abi_list)?;
    w.u32(d.cpu_cores);
    w.str(&d.cpu_implementer)?;
    w.str(&d.cpu_part)?;
    w.u64(d.ram_total_kb);
    w.str(&d.kernel_release)?;
    w.str(&d.kernel_version)?;
    w.u32(d.screen_width);
    w.u32(d.screen_height);
    w.u32(d.screen_dpi);
    w.str(&d.locale)?;
    w.str(&d.timezone)?;
    w.str(&d.carrier_name)?;
    w.str(&d.carrier_mcc_mnc)?;
    w.str(&d.serial_no)?;
    w.str(&d.android_id)?;
    Ok(())
}

fn decode_device_profile(r: &mut BinReader<'_>) -> EmuResult<DeviceProfile> {
    Ok(DeviceProfile {
        brand: r.str()?,
        manufacturer: r.str()?,
        model: r.str()?,
        device: r.str()?,
        product: r.str()?,
        board: r.str()?,
        hardware: r.str()?,
        soc_platform: r.str()?,
        fingerprint: r.str()?,
        build_id: r.str()?,
        build_display: r.str()?,
        incremental: r.str()?,
        security_patch: r.str()?,
        android_release: r.str()?,
        sdk_int: r.u32()?,
        abi: r.str()?,
        abi_list: r.str()?,
        cpu_cores: r.u32()?,
        cpu_implementer: r.str()?,
        cpu_part: r.str()?,
        ram_total_kb: r.u64()?,
        kernel_release: r.str()?,
        kernel_version: r.str()?,
        screen_width: r.u32()?,
        screen_height: r.u32()?,
        screen_dpi: r.u32()?,
        locale: r.str()?,
        timezone: r.str()?,
        carrier_name: r.str()?,
        carrier_mcc_mnc: r.str()?,
        serial_no: r.str()?,
        android_id: r.str()?,
    })
}

fn encode_jvalue(w: &mut BinWriter<'_>, v: JValue) {
    match v {
        JValue::Void => w.u8(0),
        JValue::Boolean(b) => {
            w.u8(1);
            w.bool(b);
        }
        JValue::Byte(b) => {
            w.u8(2);
            w.i8(b);
        }
        JValue::Char(c) => {
            w.u8(3);
            w.u16(c);
        }
        JValue::Short(s) => {
            w.u8(4);
            w.i16(s);
        }
        JValue::Int(i) => {
            w.u8(5);
            w.i32(i);
        }
        JValue::Long(l) => {
            w.u8(6);
            w.i64(l);
        }
        JValue::Float(f) => {
            w.u8(7);
            w.f32(f);
        }
        JValue::Double(d) => {
            w.u8(8);
            w.f64(d);
        }
        JValue::Object(r) => {
            w.u8(9);
            w.u64(r.0);
        }
    }
}

fn decode_jvalue(r: &mut BinReader<'_>) -> EmuResult<JValue> {
    match r.u8()? {
        0 => Ok(JValue::Void),
        1 => Ok(JValue::Boolean(r.bool()?)),
        2 => Ok(JValue::Byte(r.i8()?)),
        3 => Ok(JValue::Char(r.u16()?)),
        4 => Ok(JValue::Short(r.i16()?)),
        5 => Ok(JValue::Int(r.i32()?)),
        6 => Ok(JValue::Long(r.i64()?)),
        7 => Ok(JValue::Float(r.f32()?)),
        8 => Ok(JValue::Double(r.f64()?)),
        9 => Ok(JValue::Object(JObjectRef(r.u64()?))),
        other => Err(EmuError::Backend(format!("未知的 JValue tag: {other}"))),
    }
}

fn encode_jobject(w: &mut BinWriter<'_>, obj: &JObject) -> EmuResult<()> {
    match obj {
        JObject::String(s) => {
            w.u8(0);
            w.str(s)?;
        }
        JObject::BooleanArray(v) => {
            w.u8(1);
            w.bytes(v)?;
        }
        JObject::ByteArray(v) => {
            w.u8(2);
            w.bytes(v)?;
        }
        JObject::CharArray(v) => {
            w.u8(3);
            w.len_u32(v.len())?;
            for &x in v {
                w.u16(x);
            }
        }
        JObject::ShortArray(v) => {
            w.u8(4);
            w.len_u32(v.len())?;
            for &x in v {
                w.i16(x);
            }
        }
        JObject::IntArray(v) => {
            w.u8(5);
            w.len_u32(v.len())?;
            for &x in v {
                w.i32(x);
            }
        }
        JObject::LongArray(v) => {
            w.u8(6);
            w.len_u32(v.len())?;
            for &x in v {
                w.i64(x);
            }
        }
        JObject::FloatArray(v) => {
            w.u8(7);
            w.len_u32(v.len())?;
            for &x in v {
                w.f32(x);
            }
        }
        JObject::DoubleArray(v) => {
            w.u8(8);
            w.len_u32(v.len())?;
            for &x in v {
                w.f64(x);
            }
        }
        JObject::DirectBuffer { addr, capacity } => {
            w.u8(9);
            w.u64(*addr);
            w.u64(*capacity as u64);
        }
        JObject::ReflectedMethod { method_id } => {
            w.u8(10);
            w.u64(*method_id);
        }
        JObject::ReflectedField { field_id } => {
            w.u8(11);
            w.u64(*field_id);
        }
        JObject::Class { name } => {
            w.u8(12);
            w.str(name)?;
        }
        JObject::Context { package_name } => {
            w.u8(13);
            w.str(package_name)?;
        }
        JObject::PackageManager => w.u8(14),
        JObject::PackageInfo {
            package_name,
            version_name,
            version_code,
        } => {
            w.u8(15);
            w.str(package_name)?;
            w.str(version_name)?;
            w.i32(*version_code);
        }
        JObject::Signature(b) => {
            w.u8(16);
            w.bytes(b)?;
        }
        JObject::ObjectArray(items) => {
            w.u8(17);
            w.len_u32(items.len())?;
            for item in items {
                w.u64(item.0);
            }
        }
        JObject::StringBuilder(s) => {
            w.u8(18);
            w.str(s)?;
        }
        JObject::List { class_name, items } => {
            w.u8(19);
            w.str(class_name)?;
            w.len_u32(items.len())?;
            for item in items {
                w.u64(item.0);
            }
        }
        JObject::Map {
            class_name,
            entries,
        } => {
            w.u8(20);
            w.str(class_name)?;
            w.len_u32(entries.len())?;
            for (k, v) in entries {
                w.u64(k.0);
                w.u64(v.0);
            }
        }
        JObject::Iterator { items, pos } => {
            w.u8(21);
            w.len_u32(items.len())?;
            for item in items {
                w.u64(item.0);
            }
            w.u64(*pos as u64);
        }
        JObject::Custom { class_name, fields } => {
            w.u8(22);
            w.str(class_name)?;
            w.len_u32(fields.len())?;
            for (k, &v) in fields {
                w.str(k)?;
                encode_jvalue(w, v);
            }
        }
    }
    Ok(())
}

fn decode_jobject(r: &mut BinReader<'_>) -> EmuResult<JObject> {
    match r.u8()? {
        0 => Ok(JObject::String(r.str()?)),
        1 => Ok(JObject::BooleanArray(r.bytes()?)),
        2 => Ok(JObject::ByteArray(r.bytes()?)),
        3 => {
            let (n, cap) = r.read_count(2)?;
            let mut v = Vec::with_capacity(cap);
            for _ in 0..n {
                v.push(r.u16()?);
            }
            Ok(JObject::CharArray(v))
        }
        4 => {
            let (n, cap) = r.read_count(2)?;
            let mut v = Vec::with_capacity(cap);
            for _ in 0..n {
                v.push(r.i16()?);
            }
            Ok(JObject::ShortArray(v))
        }
        5 => {
            let (n, cap) = r.read_count(4)?;
            let mut v = Vec::with_capacity(cap);
            for _ in 0..n {
                v.push(r.i32()?);
            }
            Ok(JObject::IntArray(v))
        }
        6 => {
            let (n, cap) = r.read_count(8)?;
            let mut v = Vec::with_capacity(cap);
            for _ in 0..n {
                v.push(r.i64()?);
            }
            Ok(JObject::LongArray(v))
        }
        7 => {
            let (n, cap) = r.read_count(4)?;
            let mut v = Vec::with_capacity(cap);
            for _ in 0..n {
                v.push(r.f32()?);
            }
            Ok(JObject::FloatArray(v))
        }
        8 => {
            let (n, cap) = r.read_count(8)?;
            let mut v = Vec::with_capacity(cap);
            for _ in 0..n {
                v.push(r.f64()?);
            }
            Ok(JObject::DoubleArray(v))
        }
        9 => Ok(JObject::DirectBuffer {
            addr: r.u64()?,
            capacity: r.usize_from_u64()?,
        }),
        10 => Ok(JObject::ReflectedMethod { method_id: r.u64()? }),
        11 => Ok(JObject::ReflectedField { field_id: r.u64()? }),
        12 => Ok(JObject::Class { name: r.str()? }),
        13 => Ok(JObject::Context {
            package_name: r.str()?,
        }),
        14 => Ok(JObject::PackageManager),
        15 => Ok(JObject::PackageInfo {
            package_name: r.str()?,
            version_name: r.str()?,
            version_code: r.i32()?,
        }),
        16 => Ok(JObject::Signature(r.bytes()?)),
        17 => {
            let (n, cap) = r.read_count(8)?;
            let mut items = Vec::with_capacity(cap);
            for _ in 0..n {
                items.push(JObjectRef(r.u64()?));
            }
            Ok(JObject::ObjectArray(items))
        }
        18 => Ok(JObject::StringBuilder(r.str()?)),
        19 => {
            let class_name = r.str()?;
            let (n, cap) = r.read_count(8)?;
            let mut items = Vec::with_capacity(cap);
            for _ in 0..n {
                items.push(JObjectRef(r.u64()?));
            }
            Ok(JObject::List { class_name, items })
        }
        20 => {
            let class_name = r.str()?;
            let (n, cap) = r.read_count(16)?;
            let mut entries = Vec::with_capacity(cap);
            for _ in 0..n {
                entries.push((JObjectRef(r.u64()?), JObjectRef(r.u64()?)));
            }
            Ok(JObject::Map {
                class_name,
                entries,
            })
        }
        21 => {
            let (n, cap) = r.read_count(8)?;
            let mut items = Vec::with_capacity(cap);
            for _ in 0..n {
                items.push(JObjectRef(r.u64()?));
            }
            let pos = r.usize_from_u64()?;
            if pos > items.len() {
                return Err(EmuError::Backend(format!(
                    ".rtape JObject::Iterator 游标越界: pos={pos}, len={}",
                    items.len()
                )));
            }
            Ok(JObject::Iterator { items, pos })
        }
        22 => {
            let class_name = r.str()?;
            let (n, cap) = r.read_count(5)?;
            let mut fields = HashMap::with_capacity(cap);
            for _ in 0..n {
                fields.insert(r.str()?, decode_jvalue(r)?);
            }
            Ok(JObject::Custom { class_name, fields })
        }
        other => Err(EmuError::Backend(format!("未知的 JObject tag: {other}"))),
    }
}

fn encode_object_table(w: &mut BinWriter<'_>, t: &ObjectTableRaw) -> EmuResult<()> {
    w.u64(t.next_handle);
    w.len_u32(t.objects.len())?;
    for (id, obj) in &t.objects {
        w.u64(*id);
        encode_jobject(w, obj)?;
    }
    w.len_u32(t.local_refs.len())?;
    for &id in &t.local_refs {
        w.u64(id);
    }
    w.len_u32(t.global_refs.len())?;
    for &(id, cnt) in &t.global_refs {
        w.u64(id);
        w.len_u32(cnt)?;
    }
    w.len_u32(t.class_cache.len())?;
    for (name, r) in &t.class_cache {
        w.str(name)?;
        w.u64(r.0);
    }
    w.len_u32(t.local_frames.len())?;
    for &wm in &t.local_frames {
        w.u64(wm);
    }
    Ok(())
}

fn decode_object_table(r: &mut BinReader<'_>) -> EmuResult<ObjectTableRaw> {
    let next_handle = r.u64()?;
    let (obj_len, obj_cap) = r.read_count(9)?;
    let mut objects = Vec::with_capacity(obj_cap);
    for _ in 0..obj_len {
        objects.push((r.u64()?, decode_jobject(r)?));
    }
    let (lr_len, lr_cap) = r.read_count(8)?;
    let mut local_refs = Vec::with_capacity(lr_cap);
    for _ in 0..lr_len {
        local_refs.push(r.u64()?);
    }
    let (gr_len, gr_cap) = r.read_count(12)?;
    let mut global_refs = Vec::with_capacity(gr_cap);
    for _ in 0..gr_len {
        global_refs.push((r.u64()?, r.u32()? as usize));
    }
    let (cc_len, cc_cap) = r.read_count(12)?;
    let mut class_cache = Vec::with_capacity(cc_cap);
    for _ in 0..cc_len {
        class_cache.push((r.str()?, JObjectRef(r.u64()?)));
    }
    let (lf_len, lf_cap) = r.read_count(8)?;
    let mut local_frames = Vec::with_capacity(lf_cap);
    for _ in 0..lf_len {
        local_frames.push(r.u64()?);
    }
    Ok(ObjectTableRaw {
        next_handle,
        objects,
        local_refs,
        global_refs,
        class_cache,
        local_frames,
    })
}

fn encode_dex_value(w: &mut BinWriter<'_>, v: &DexValue) -> EmuResult<()> {
    match v {
        DexValue::Null => w.u8(0),
        DexValue::Boolean(b) => {
            w.u8(1);
            w.bool(*b);
        }
        DexValue::Byte(b) => {
            w.u8(2);
            w.i8(*b);
        }
        DexValue::Short(s) => {
            w.u8(3);
            w.i16(*s);
        }
        DexValue::Char(c) => {
            w.u8(4);
            w.u16(*c);
        }
        DexValue::Int(i) => {
            w.u8(5);
            w.i32(*i);
        }
        DexValue::Long(l) => {
            w.u8(6);
            w.i64(*l);
        }
        DexValue::Float(f) => {
            w.u8(7);
            w.f32(*f);
        }
        DexValue::Double(d) => {
            w.u8(8);
            w.f64(*d);
        }
        DexValue::String(s) => {
            w.u8(9);
            w.str(s)?;
        }
        DexValue::Type(t) => {
            w.u8(10);
            w.str(t)?;
        }
        DexValue::Array(items) => {
            w.u8(11);
            w.len_u32(items.len())?;
            for item in items {
                encode_dex_value(w, item)?;
            }
        }
    }
    Ok(())
}

fn decode_dex_value(r: &mut BinReader<'_>, depth: usize) -> EmuResult<DexValue> {
    if depth > MAX_DEX_VALUE_DEPTH {
        return Err(EmuError::Backend(".rtape DexValue 嵌套层级超限".to_string()));
    }
    match r.u8()? {
        0 => Ok(DexValue::Null),
        1 => Ok(DexValue::Boolean(r.bool()?)),
        2 => Ok(DexValue::Byte(r.i8()?)),
        3 => Ok(DexValue::Short(r.i16()?)),
        4 => Ok(DexValue::Char(r.u16()?)),
        5 => Ok(DexValue::Int(r.i32()?)),
        6 => Ok(DexValue::Long(r.i64()?)),
        7 => Ok(DexValue::Float(r.f32()?)),
        8 => Ok(DexValue::Double(r.f64()?)),
        9 => Ok(DexValue::String(r.str()?)),
        10 => Ok(DexValue::Type(r.str()?)),
        11 => {
            let (n, cap) = r.read_count(1)?;
            let mut items = Vec::with_capacity(cap);
            for _ in 0..n {
                items.push(decode_dex_value(r, depth + 1)?);
            }
            Ok(DexValue::Array(items))
        }
        other => Err(EmuError::Backend(format!("未知的 DexValue tag: {other}"))),
    }
}

fn encode_dex_class(w: &mut BinWriter<'_>, cls: &DexClassInfo) -> EmuResult<()> {
    w.str(&cls.name)?;
    w.bool(cls.super_class.is_some());
    if let Some(sc) = &cls.super_class {
        w.str(sc)?;
    }
    w.len_u32(cls.interfaces.len())?;
    for itf in &cls.interfaces {
        w.str(itf)?;
    }
    w.u32(cls.access_flags);
    w.len_u32(cls.fields.len())?;
    for f in &cls.fields {
        w.str(&f.name)?;
        w.str(&f.sig)?;
        w.u32(f.access_flags);
        w.bool(f.is_static);
    }
    w.len_u32(cls.methods.len())?;
    for m in &cls.methods {
        w.str(&m.name)?;
        w.str(&m.sig)?;
        w.u32(m.access_flags);
        w.bool(m.is_direct);
    }
    w.len_u32(cls.static_values.len())?;
    for (k, v) in &cls.static_values {
        w.str(k)?;
        encode_dex_value(w, v)?;
    }
    Ok(())
}

fn decode_dex_class(r: &mut BinReader<'_>) -> EmuResult<DexClassInfo> {
    let name = r.str()?;
    let super_class = if r.bool()? { Some(r.str()?) } else { None };
    let (itf_len, itf_cap) = r.read_count(4)?;
    let mut interfaces = Vec::with_capacity(itf_cap);
    for _ in 0..itf_len {
        interfaces.push(r.str()?);
    }
    let access_flags = r.u32()?;
    let (fld_len, fld_cap) = r.read_count(13)?;
    let mut fields = Vec::with_capacity(fld_cap);
    for _ in 0..fld_len {
        fields.push(DexFieldInfo {
            name: r.str()?,
            sig: r.str()?,
            access_flags: r.u32()?,
            is_static: r.bool()?,
        });
    }
    let (mth_len, mth_cap) = r.read_count(13)?;
    let mut methods = Vec::with_capacity(mth_cap);
    for _ in 0..mth_len {
        methods.push(DexMethodInfo {
            name: r.str()?,
            sig: r.str()?,
            access_flags: r.u32()?,
            is_direct: r.bool()?,
        });
    }
    let (sv_len, sv_cap) = r.read_count(5)?;
    let mut static_values = HashMap::with_capacity(sv_cap);
    for _ in 0..sv_len {
        static_values.insert(r.str()?, decode_dex_value(r, 0)?);
    }
    Ok(DexClassInfo {
        name,
        super_class,
        interfaces,
        access_flags,
        fields,
        methods,
        static_values,
    })
}

fn encode_open_file(w: &mut BinWriter<'_>, f: &OpenFile) -> EmuResult<()> {
    w.str(&f.path)?;
    match &f.kind {
        OpenFileKind::Buffer { data, cursor } => {
            w.u8(0);
            w.bytes(data)?;
            w.u64(*cursor as u64);
        }
        OpenFileKind::Overlay { cursor } => {
            w.u8(1);
            w.u64(*cursor as u64);
        }
        OpenFileKind::Urandom => w.u8(2),
        OpenFileKind::StdStream { is_stderr } => {
            w.u8(3);
            w.bool(*is_stderr);
        }
        OpenFileKind::Directory { entries, cursor } => {
            w.u8(4);
            w.len_u32(entries.len())?;
            for (name, dtype) in entries {
                w.str(name)?;
                w.u8(*dtype);
            }
            w.u64(*cursor as u64);
        }
    }
    Ok(())
}

fn decode_open_file(r: &mut BinReader<'_>) -> EmuResult<OpenFile> {
    let path = r.str()?;
    let kind = match r.u8()? {
        0 => OpenFileKind::Buffer {
            data: r.bytes()?,
            cursor: r.usize_from_u64()?,
        },
        1 => OpenFileKind::Overlay {
            cursor: r.usize_from_u64()?,
        },
        2 => OpenFileKind::Urandom,
        3 => OpenFileKind::StdStream {
            is_stderr: r.bool()?,
        },
        4 => {
            let (n, cap) = r.read_count(5)?;
            let mut entries = Vec::with_capacity(cap);
            for _ in 0..n {
                entries.push((r.str()?, r.u8()?));
            }
            let cursor = r.usize_from_u64()?;
            OpenFileKind::Directory { entries, cursor }
        }
        other => return Err(EmuError::Backend(format!("未知的 OpenFileKind tag: {other}"))),
    };
    Ok(OpenFile { path, kind })
}

fn encode_net_state(w: &mut BinWriter<'_>, n: &NetTapeState) -> EmuResult<()> {
    w.bool(n.config.enabled);
    w.len_u32(n.config.allow_hosts.len())?;
    for h in &n.config.allow_hosts {
        w.str(h)?;
    }
    w.bool(n.config.capture_packets);
    w.str(&n.config.nic.name)?;
    w.raw_fixed(&n.config.nic.ipv4);
    w.raw_fixed(&n.config.nic.netmask);
    w.raw_fixed(&n.config.nic.gateway);
    w.raw_fixed(&n.config.nic.mac);
    w.str(&n.config.nic.ipv6)?;

    w.len_u32(n.virtual_fds.len())?;
    for (fd, vfd) in &n.virtual_fds {
        w.i32(*fd);
        match vfd {
            NetVirtualFdTape::Epoll { interests } => {
                w.u8(0);
                w.len_u32(interests.len())?;
                for &(wfd, ev, ud) in interests {
                    w.i32(wfd);
                    w.u32(ev);
                    w.u64(ud);
                }
            }
            NetVirtualFdTape::EventFd {
                counter,
                nonblocking,
            } => {
                w.u8(1);
                w.u64(*counter);
                w.bool(*nonblocking);
            }
            NetVirtualFdTape::Pipe {
                pipe_id,
                is_read_end,
                nonblocking,
            } => {
                w.u8(2);
                w.u64(*pipe_id as u64);
                w.bool(*is_read_end);
                w.bool(*nonblocking);
            }
        }
    }
    w.len_u32(n.pipes.len())?;
    for (id, ch) in &n.pipes {
        w.u64(*id as u64);
        w.bytes(&ch.buf)?;
        w.bool(ch.write_closed);
        w.bool(ch.read_closed);
    }
    w.u64(n.next_pipe_id as u64);
    Ok(())
}

fn decode_net_state(r: &mut BinReader<'_>) -> EmuResult<NetTapeState> {
    let enabled = r.bool()?;
    let (ah_len, ah_cap) = r.read_count(4)?;
    let mut allow_hosts = Vec::with_capacity(ah_cap);
    for _ in 0..ah_len {
        allow_hosts.push(r.str()?);
    }
    let capture_packets = r.bool()?;
    let nic_name = r.str()?;
    let ipv4: [u8; 4] = r.take(4)?.try_into().unwrap();
    let netmask: [u8; 4] = r.take(4)?.try_into().unwrap();
    let gateway: [u8; 4] = r.take(4)?.try_into().unwrap();
    let mac: [u8; 6] = r.take(6)?.try_into().unwrap();
    let ipv6 = r.str()?;

    let (vfd_len, vfd_cap) = r.read_count(5)?;
    let mut virtual_fds = Vec::with_capacity(vfd_cap);
    for _ in 0..vfd_len {
        let fd = r.i32()?;
        let vfd = match r.u8()? {
            0 => {
                let (in_len, in_cap) = r.read_count(16)?;
                let mut interests = Vec::with_capacity(in_cap);
                for _ in 0..in_len {
                    interests.push((r.i32()?, r.u32()?, r.u64()?));
                }
                NetVirtualFdTape::Epoll { interests }
            }
            1 => NetVirtualFdTape::EventFd {
                counter: r.u64()?,
                nonblocking: r.bool()?,
            },
            2 => NetVirtualFdTape::Pipe {
                pipe_id: r.usize_from_u64()?,
                is_read_end: r.bool()?,
                nonblocking: r.bool()?,
            },
            other => {
                return Err(EmuError::Backend(format!(
                    "未知的 NetVirtualFdTape tag: {other}"
                )))
            }
        };
        virtual_fds.push((fd, vfd));
    }
    let (p_len, p_cap) = r.read_count(14)?;
    let mut pipes = Vec::with_capacity(p_cap);
    for _ in 0..p_len {
        pipes.push((
            r.usize_from_u64()?,
            PipeChannelTape {
                buf: r.bytes()?,
                write_closed: r.bool()?,
                read_closed: r.bool()?,
            },
        ));
    }
    let next_pipe_id = r.usize_from_u64()?;
    Ok(NetTapeState {
        config: NetConfig {
            enabled,
            allow_hosts,
            capture_packets,
            nic: VirtualNic {
                name: nic_name,
                ipv4,
                netmask,
                gateway,
                mac,
                ipv6,
            },
        },
        virtual_fds,
        pipes,
        next_pipe_id,
    })
}

fn encode_event_log(out: &mut Vec<u8>, log: &TapeEventLog) -> EmuResult<()> {
    let mut w = BinWriter::new(out);
    w.u32(if log.timeline_version == 0 {
        EVENT_LOG_VERSION
    } else {
        log.timeline_version
    });
    w.u64(log.start_insn);
    w.u64(log.end_insn);
    w.u64(log.keyframe_interval);
    w.u32(log.record_flags);

    w.len_u32(log.bookmarks.len())?;
    for (insn, label) in &log.bookmarks {
        w.u64(*insn);
        w.str(label)?;
    }

    w.len_u32(log.keyframe_event_offsets.len())?;
    for &(kf_insn, ev_idx) in &log.keyframe_event_offsets {
        w.u64(kf_insn);
        w.u32(ev_idx);
    }

    w.len_u32(log.host_files.len())?;
    for (path, data) in &log.host_files {
        w.str(path)?;
        w.bytes(data)?;
    }

    w.len_u32(log.events.len())?;
    for ev in &log.events {
        match ev {
            ReplayEvent::ClockRead { insn, seq, ns } => {
                w.u8(1);
                w.u64(*insn);
                w.u64(*seq);
                w.u64(*ns);
            }
            ReplayEvent::JniCallback {
                insn,
                seq,
                ret,
                delta,
            } => {
                w.u8(2);
                w.u64(*insn);
                w.u64(*seq);
                encode_jvalue(&mut w, *ret);
                w.u64(delta.next_handle);
                w.len_u32(delta.upserted_objects.len())?;
                for (id, obj) in &delta.upserted_objects {
                    w.u64(*id);
                    encode_jobject(&mut w, obj)?;
                }
                w.len_u32(delta.removed_objects.len())?;
                for &id in &delta.removed_objects {
                    w.u64(id);
                }
                w.len_u32(delta.added_local_refs.len())?;
                for &id in &delta.added_local_refs {
                    w.u64(id);
                }
                w.len_u32(delta.removed_local_refs.len())?;
                for &id in &delta.removed_local_refs {
                    w.u64(id);
                }
                w.len_u32(delta.updated_global_refs.len())?;
                for &(id, cnt) in &delta.updated_global_refs {
                    w.u64(id);
                    w.len_u32(cnt)?;
                }
                w.len_u32(delta.added_class_cache.len())?;
                for (name, r) in &delta.added_class_cache {
                    w.str(name)?;
                    w.u64(r.0);
                }
                match &delta.local_frames {
                    Some(frames) => {
                        w.u8(1);
                        w.len_u32(frames.len())?;
                        for &f in frames {
                            w.u64(f);
                        }
                    }
                    None => w.u8(0),
                }
            }
            ReplayEvent::ExternalMemWrite { .. } => {
                return Err(EmuError::Backend(
                    "暂不支持编码 ExternalMemWrite 事件 (tag=3)".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn decode_event_log(r: &mut BinReader<'_>) -> EmuResult<TapeEventLog> {
    let timeline_version = r.u32()?;
    if timeline_version != EVENT_LOG_VERSION {
        return Err(EmuError::Backend(format!(
            "不支持的 .rtape EventLog 版本 v{timeline_version}（当前支持 v{EVENT_LOG_VERSION}）"
        )));
    }
    let start_insn = r.u64()?;
    let end_insn = r.u64()?;
    if end_insn < start_insn {
        return Err(EmuError::Backend(format!(
            "非法的 .rtape EventLog 指令区间: [{start_insn}, {end_insn}]"
        )));
    }
    let keyframe_interval = r.u64()?;
    let record_flags = r.u32()?;
    if (record_flags & !EVENT_RECORD_FLAGS_MASK) != 0 {
        return Err(EmuError::Backend(format!(
            "不支持的 .rtape EventLog record_flags: 0x{record_flags:08x}"
        )));
    }

    let (bm_len, bm_cap) = r.read_count(12)?;
    let mut bookmarks = Vec::with_capacity(bm_cap);
    for _ in 0..bm_len {
        bookmarks.push((r.u64()?, r.str()?));
    }

    let (kf_len, kf_cap) = r.read_count(12)?;
    let mut keyframe_event_offsets = Vec::with_capacity(kf_cap);
    for _ in 0..kf_len {
        keyframe_event_offsets.push((r.u64()?, r.u32()?));
    }

    let (hf_len, hf_cap) = r.read_count(8)?;
    let mut host_files = Vec::with_capacity(hf_cap);
    for _ in 0..hf_len {
        host_files.push((r.str()?, r.bytes()?));
    }

    let (ev_len, ev_cap) = r.read_count(17)?;
    if ev_len > MAX_EVENTS {
        return Err(EmuError::Backend(format!(
            ".rtape EventLog 事件数量超出安全上限: {ev_len} > {MAX_EVENTS}"
        )));
    }
    let mut events = Vec::with_capacity(ev_cap);
    let mut prev_ev_key: Option<(u64, u64)> = None;
    for _ in 0..ev_len {
        let ev = match r.u8()? {
            1 => ReplayEvent::ClockRead {
                insn: r.u64()?,
                seq: r.u64()?,
                ns: r.u64()?,
            },
            2 => {
                let insn = r.u64()?;
                let seq = r.u64()?;
                let ret = decode_jvalue(r)?;
                let next_handle = r.u64()?;
                let (up_len, up_cap) = r.read_count(9)?;
                let mut upserted_objects = Vec::with_capacity(up_cap);
                for _ in 0..up_len {
                    upserted_objects.push((r.u64()?, decode_jobject(r)?));
                }
                let (rm_len, rm_cap) = r.read_count(8)?;
                let mut removed_objects = Vec::with_capacity(rm_cap);
                for _ in 0..rm_len {
                    removed_objects.push(r.u64()?);
                }
                let (al_len, al_cap) = r.read_count(8)?;
                let mut added_local_refs = Vec::with_capacity(al_cap);
                for _ in 0..al_len {
                    added_local_refs.push(r.u64()?);
                }
                let (rl_len, rl_cap) = r.read_count(8)?;
                let mut removed_local_refs = Vec::with_capacity(rl_cap);
                for _ in 0..rl_len {
                    removed_local_refs.push(r.u64()?);
                }
                let (ug_len, ug_cap) = r.read_count(12)?;
                let mut updated_global_refs = Vec::with_capacity(ug_cap);
                for _ in 0..ug_len {
                    updated_global_refs.push((r.u64()?, r.u32()? as usize));
                }
                let (cc_len, cc_cap) = r.read_count(12)?;
                let mut added_class_cache = Vec::with_capacity(cc_cap);
                for _ in 0..cc_len {
                    added_class_cache.push((r.str()?, JObjectRef(r.u64()?)));
                }
                let local_frames = match r.u8()? {
                    0 => None,
                    1 => {
                        let (lf_len, lf_cap) = r.read_count(8)?;
                        let mut frames = Vec::with_capacity(lf_cap);
                        for _ in 0..lf_len {
                            frames.push(r.u64()?);
                        }
                        Some(frames)
                    }
                    other => {
                        return Err(EmuError::Backend(format!(
                            "非法的 ObjectTableDelta local_frames 标记: {other}"
                        )))
                    }
                };
                ReplayEvent::JniCallback {
                    insn,
                    seq,
                    ret,
                    delta: ObjectTableDelta {
                        next_handle,
                        upserted_objects,
                        removed_objects,
                        added_local_refs,
                        removed_local_refs,
                        updated_global_refs,
                        added_class_cache,
                        local_frames,
                    },
                }
            }
            3 => {
                return Err(EmuError::Backend(
                    "暂不支持回放 ExternalMemWrite 事件 (tag=3)".to_string(),
                ));
            }
            other => {
                return Err(EmuError::Backend(format!(
                    "未知的 .rtape ReplayEvent tag: {other}"
                )))
            }
        };
        let (ev_insn, ev_seq) = match &ev {
            ReplayEvent::ClockRead { insn, seq, .. }
            | ReplayEvent::JniCallback { insn, seq, .. }
            | ReplayEvent::ExternalMemWrite { insn, seq, .. } => (*insn, *seq),
        };
        if ev_insn < start_insn || ev_insn > end_insn {
            return Err(EmuError::Backend(format!(
                "非法的 .rtape EventLog 事件指令号 {ev_insn}（超出 [{start_insn}, {end_insn}]）"
            )));
        }
        if let Some((prev_i, prev_s)) = prev_ev_key {
            if ev_insn < prev_i || ev_seq < prev_s {
                return Err(EmuError::Backend(format!(
                    "非法的 .rtape EventLog 事件非单调: ({ev_insn}, {ev_seq}) < ({prev_i}, {prev_s})"
                )));
            }
        }
        prev_ev_key = Some((ev_insn, ev_seq));
        events.push(ev);
    }

    let mut prev_kf: Option<(u64, u32)> = None;
    for &(kf_insn, ev_idx) in &keyframe_event_offsets {
        if kf_insn < start_insn || kf_insn > end_insn {
            return Err(EmuError::Backend(format!(
                "非法的 .rtape keyframe_event_offsets insn={kf_insn}（超出 [{start_insn}, {end_insn}]）"
            )));
        }
        if (ev_idx as usize) > events.len() {
            return Err(EmuError::Backend(format!(
                "非法的 .rtape keyframe_event_offsets ev_idx={ev_idx} > events.len()={}",
                events.len()
            )));
        }
        if let Some((pk, pe)) = prev_kf {
            if kf_insn < pk || ev_idx < pe {
                return Err(EmuError::Backend(format!(
                    "非法的 .rtape keyframe_event_offsets 非单调: ({kf_insn}, {ev_idx}) < ({pk}, {pe})"
                )));
            }
        }
        prev_kf = Some((kf_insn, ev_idx));
    }

    Ok(TapeEventLog {
        timeline_version,
        start_insn,
        end_insn,
        keyframe_interval,
        record_flags,
        bookmarks,
        keyframe_event_offsets,
        host_files,
        events,
    })
}
