//! `.rtape` 二期时间旅行引擎（Time-Travel Debugging）
//!
//! 架构组成：
//! - `EventLogBus`：轻量共享总线，原子维护 `cur_insn`，在录制/回放期间零侵入拦截
//!   `VirtualFs::current_clock_ns`、宿主机 `sysroot_mounts` 读取以及 `JniHandler` 外部回调；
//! - `RecordJniHandler` / `ReplayJniHandler`：自动包装任意业务 `JniHandler`（含 `JsJniHandler`），
//!   录制紧凑 `ObjectTableDelta` + `JValue`，回放时 **无需原 JS 运行时** 即可 bit-exact 还原所有对象句柄；
//! - `TimeTravelRecorder`：挂在 Unicorn `code_hook` 上，首条指令自动捕获 `BASE` 关键帧（完整保留
//!   `prepare_call` 后的 `PC`/`SP`/`LR`/`X0..X7`），每隔 `keyframe_interval` 指令自动打增量 4KB 脏页关键帧并
//!   记录精确 `keyframe_event_offsets`；
//! - `TimeTravelPlayer`：加载含 `EVENT_LOG` 的 `.rtape` 文件，内置 **LRU 关键帧缓存 + 微快照环（Micro-Snapshot Ring）**
//!   支持毫秒级 `seek_insn`、亚毫秒级连续 `step_backward(1)`、以及基于关键帧窗口倒序扫描的 `continue_backward` 与
//!   反向内存观察点（`WatchKind::Write / Read / Access`）。

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use unicorn_engine::unicorn_const::{MemType, Prot};
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::backend::{capture_generic_context, BackendKind, BackendWithData, CpuBackend, CpuEngine};
use crate::cpu::{CpuContext, RET_MAGIC_ADDR};
use crate::emulator::{AndroidEmulator, EmuState};
use crate::error::{EmuError, EmuResult};
use crate::jni::handler::{DefaultJniHandler, JniContext, JniHandler};
use crate::jni::types::{FieldDesc, JObjectRef, JValue, MethodDesc, ObjectTableDelta};
use crate::loader::linker::{DynamicLinker, LinkerTapeState};
use crate::loader::trampoline::TrampolineTapeState;
use crate::os::vfs::VfsTapeState;
use crate::snapshot::EmuSnapshot;
use crate::tape::{is_zero_page, ReplayEvent, Tape, TapeEventLog, TapeFullState, TapeMeta, TapeSummary};

/// 录制标志位
pub const TT_FLAG_CAPTURE_CLOCK: u32 = 1 << 0;
pub const TT_FLAG_CAPTURE_JNI: u32 = 1 << 1;
pub const TT_FLAG_CAPTURE_HOST_FS: u32 = 1 << 2;

/// 时间旅行录制配置
#[derive(Debug, Clone)]
pub struct RecordConfig {
    /// 自动插入增量关键帧的指令间隔（默认 100,000 条指令；0 表示仅存首尾两帧）
    pub keyframe_interval: u64,
    /// 最大允许录制指令数（0 表示不限）
    pub max_insns: u64,
    /// 是否捕获外部 `JniHandler` 回调（默认 true，实现离线脱离 JS 回放）
    pub capture_jni: bool,
}

impl Default for RecordConfig {
    fn default() -> Self {
        Self {
            keyframe_interval: 100_000,
            max_insns: 0,
            capture_jni: true,
        }
    }
}

/// 内存观察点类型（与 GDB RSP `Z2`/`Z3`/`Z4` 一一对应）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchKind {
    /// 写观察点（GDB `Z2`）
    Write,
    /// 读观察点（GDB `Z3`）
    Read,
    /// 读写访问观察点（GDB `Z4`）
    Access,
}

/// 内存观察点定义
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchpoint {
    pub addr: u64,
    pub len: u64,
    pub kind: WatchKind,
}

impl Watchpoint {
    #[inline]
    pub fn matches(&self, access_addr: u64, access_size: usize, is_write: bool) -> bool {
        let kind_ok = match self.kind {
            WatchKind::Write => is_write,
            WatchKind::Read => !is_write,
            WatchKind::Access => true,
        };
        if !kind_ok {
            return false;
        }
        let wp_end = self.addr.saturating_add(self.len.max(1));
        let acc_end = access_addr.saturating_add((access_size.max(1)) as u64);
        access_addr < wp_end && acc_end > self.addr
    }
}

/// 时间旅行单步/继续/反向搜索停止原因
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeTravelStop {
    /// 到达目标指令计数（单步 / seek 完成）
    Step { insn: u64, pc: u64 },
    /// 命中执行断点
    Breakpoint { insn: u64, pc: u64 },
    /// 命中内存观察点（附带观察点命中地址、真实访存地址、类型与值）
    Watchpoint {
        insn: u64,
        pc: u64,
        /// 保证落在被触发观察点 `[wp.addr, wp.addr + wp.len)` 内的上报地址（供 GDB RSP 使用）
        addr: u64,
        /// 指令实际访问的起始地址
        access_addr: u64,
        size: usize,
        /// 被触发观察点的类型（`Write`/`Read`/`Access`，供 GDB 上报 `watch`/`rwatch`/`awatch`）
        kind: WatchKind,
        /// 该次访存的实际方向（`true` 为写，`false` 为读）
        is_write: bool,
        value: i64,
    },
    /// 到达录制历史起点（GDB 对应 `T05replaylog:begin;`）
    LogBegin { insn: u64, pc: u64 },
    /// 到达录制历史终点（GDB 对应 `T05replaylog:end;`）
    LogEnd { insn: u64, pc: u64 },
}

/// 内存观察点命中详情（供 JS / MCP / CLI / Web UI 结构化返回）
#[derive(Debug, Clone)]
pub struct WatchHit {
    pub insn: u64,
    pub pc: u64,
    pub addr: u64,
    pub size: usize,
    pub kind: WatchKind,
    pub is_write: bool,
    pub value: i64,
}

// ============================================================================
// 共享确定性事件总线（Record / Replay 双模式）
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusMode {
    Record,
    Replay,
    /// Live Fork：脱离录制历史继续自由运行
    LiveFork,
}

struct EventBusInner {
    mode: BusMode,
    seq: u64,
    /// 录制模式使用的可变事件数组
    events: Vec<ReplayEvent>,
    /// 回放模式共享的只读事件日志（零拷贝共享，避免 3x RAM 放大）
    replay_log: Option<Arc<TapeEventLog>>,
    /// 重放期间指向事件数组的下一个待消费游标
    replay_cursor: usize,
    /// 录制期间缓存的只读宿主机文件（按虚拟路径去重）
    host_files: BTreeMap<String, Vec<u8>>,
    /// 录制期间记录的关键帧事件游标 `(kf_insn, events.len())`
    keyframe_event_offsets: Vec<(u64, u32)>,
    /// 录制期间命名的书签 `(insn, label)`
    bookmarks: Vec<(u64, String)>,
}

impl EventBusInner {
    #[inline]
    fn replay_events(&self) -> &[ReplayEvent] {
        if let Some(ref log) = self.replay_log {
            &log.events
        } else {
            &self.events
        }
    }

    #[inline]
    fn replay_kf_offsets(&self) -> &[(u64, u32)] {
        if let Some(ref log) = self.replay_log {
            &log.keyframe_event_offsets
        } else {
            &self.keyframe_event_offsets
        }
    }
}

/// 线程安全的时间旅行事件总线（每指令仅原子读/加 1 次 `cur_insn`，极低频事件才加锁）
pub(crate) struct EventLogBus {
    cur_insn: AtomicU64,
    inner: Mutex<EventBusInner>,
}

impl EventLogBus {
    pub fn new_record() -> Self {
        Self {
            cur_insn: AtomicU64::new(0),
            inner: Mutex::new(EventBusInner {
                mode: BusMode::Record,
                seq: 0,
                events: Vec::new(),
                replay_log: None,
                replay_cursor: 0,
                host_files: BTreeMap::new(),
                keyframe_event_offsets: Vec::new(),
                bookmarks: Vec::new(),
            }),
        }
    }

    pub fn new_replay(log: Arc<TapeEventLog>) -> Self {
        let start_insn = log.start_insn;
        Self {
            cur_insn: AtomicU64::new(start_insn),
            inner: Mutex::new(EventBusInner {
                mode: BusMode::Replay,
                seq: 0,
                events: Vec::new(),
                replay_log: Some(log),
                replay_cursor: 0,
                host_files: BTreeMap::new(),
                keyframe_event_offsets: Vec::new(),
                bookmarks: Vec::new(),
            }),
        }
    }

    #[inline]
    pub fn is_replaying(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.mode == BusMode::Replay)
            .unwrap_or(false)
    }

    #[inline]
    pub fn cur_insn(&self) -> u64 {
        self.cur_insn.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn set_cur_insn(&self, insn: u64) {
        self.cur_insn.store(insn, Ordering::Relaxed);
    }

    #[inline]
    pub fn fetch_add_insn(&self) -> u64 {
        self.cur_insn.fetch_add(1, Ordering::Relaxed)
    }

    #[inline]
    pub fn dec_insn_on_crash(&self) {
        let cur = self.cur_insn.load(Ordering::Relaxed);
        self.cur_insn.store(cur.saturating_sub(1), Ordering::Relaxed);
    }

    pub fn set_live_fork(&self, live: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.mode = if live { BusMode::LiveFork } else { BusMode::Replay };
        }
    }

    /// 录制模式下记录一次实时时钟读取
    pub fn record_clock_read(&self, ns: u64) {
        if let Ok(mut g) = self.inner.lock() {
            if g.mode != BusMode::Record {
                return;
            }
            let seq = g.seq;
            g.seq += 1;
            let insn = self.cur_insn();
            g.events.push(ReplayEvent::ClockRead { insn, seq, ns });
        }
    }

    /// 回放模式下严格按 `replay_cursor` 消费下一条 `ClockRead` 事件（绝不越界跳过其他类型事件）
    pub fn replay_clock_read(&self) -> Option<u64> {
        let mut g = self.inner.lock().ok()?;
        if g.mode != BusMode::Replay {
            return None;
        }
        let idx = g.replay_cursor;
        if let Some(ReplayEvent::ClockRead { ns, .. }) = g.replay_events().get(idx) {
            let val = *ns;
            g.replay_cursor = idx + 1;
            return Some(val);
        }
        None
    }

    /// 录制模式下缓存命中只读宿主机 `sysroot_mounts` 的文件内容
    pub fn record_host_file(&self, guest_path: &str, data: &[u8]) {
        if let Ok(mut g) = self.inner.lock() {
            if g.mode != BusMode::Record {
                return;
            }
            g.host_files
                .entry(guest_path.to_string())
                .or_insert_with(|| data.to_vec());
        }
    }

    /// 录制模式下记录一次 JNI 回调返回值与 `ObjectTableDelta`
    pub fn record_jni_callback(&self, ret: JValue, delta: ObjectTableDelta) {
        if let Ok(mut g) = self.inner.lock() {
            if g.mode != BusMode::Record {
                return;
            }
            let seq = g.seq;
            g.seq += 1;
            let insn = self.cur_insn();
            g.events.push(ReplayEvent::JniCallback {
                insn,
                seq,
                ret,
                delta,
            });
        }
    }

    /// 回放模式下严格按 `replay_cursor` 消费下一条 `JniCallback` 事件（绝不跳过其他类型事件）
    pub fn replay_jni_callback(&self) -> Option<(JValue, ObjectTableDelta)> {
        let mut g = self.inner.lock().ok()?;
        if g.mode != BusMode::Replay {
            return None;
        }
        let idx = g.replay_cursor;
        if let Some(ReplayEvent::JniCallback { ret, delta, .. }) = g.replay_events().get(idx) {
            let out = (*ret, delta.clone());
            g.replay_cursor = idx + 1;
            return Some(out);
        }
        None
    }

    /// 关键帧捕获时记录精确的 `(kf_insn, events.len())` 锚点
    pub fn mark_keyframe_event_offset(&self, kf_insn: u64) {
        if let Ok(mut g) = self.inner.lock() {
            let ev_idx = u32::try_from(g.events.len()).unwrap_or(u32::MAX);
            g.keyframe_event_offsets.push((kf_insn, ev_idx));
        }
    }

    /// 录制模式下记录时间轴书签
    pub fn add_bookmark(&self, label: String) -> u64 {
        let insn = self.cur_insn();
        if let Ok(mut g) = self.inner.lock() {
            g.bookmarks.push((insn, label));
        }
        insn
    }

    /// 获取当前重放事件游标（供微快照环保存）
    pub fn replay_cursor(&self) -> usize {
        self.inner.lock().map(|g| g.replay_cursor).unwrap_or(0)
    }

    /// 设置重放事件游标（从关键帧或微快照恢复时调用）
    pub fn set_replay_cursor(&self, cursor: usize) {
        if let Ok(mut g) = self.inner.lock() {
            let max_len = g.replay_events().len();
            g.replay_cursor = cursor.min(max_len);
        }
    }

    /// 按关键帧 `kf_insn` 查找该帧对应的精确起始事件游标
    pub fn event_cursor_for_keyframe(&self, kf_insn: u64) -> usize {
        let Ok(g) = self.inner.lock() else {
            return 0;
        };
        let events = g.replay_events();
        if let Some(&(_, ev_idx)) = g
            .replay_kf_offsets()
            .iter()
            .rev()
            .find(|&&(ins, _)| ins == kf_insn)
        {
            return (ev_idx as usize).min(events.len());
        }
        // 回退：查找第一条 insn > kf_insn 的事件
        events.partition_point(|ev| {
            let ins = match ev {
                ReplayEvent::ClockRead { insn, .. }
                | ReplayEvent::JniCallback { insn, .. }
                | ReplayEvent::ExternalMemWrite { insn, .. } => *insn,
            };
            ins <= kf_insn
        })
    }

    /// 导出完整 `TapeEventLog`（录制结束时调用）
    pub fn export_event_log(&self, config: &RecordConfig) -> TapeEventLog {
        let g = self.inner.lock().expect("EventLogBus lock poisoned");
        let mut flags = TT_FLAG_CAPTURE_CLOCK | TT_FLAG_CAPTURE_HOST_FS;
        if config.capture_jni {
            flags |= TT_FLAG_CAPTURE_JNI;
        }
        TapeEventLog {
            timeline_version: 1,
            start_insn: 0,
            end_insn: self.cur_insn(),
            keyframe_interval: config.keyframe_interval,
            record_flags: flags,
            bookmarks: g.bookmarks.clone(),
            keyframe_event_offsets: g.keyframe_event_offsets.clone(),
            host_files: g
                .host_files
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            events: g.events.clone(),
        }
    }
}

// ============================================================================
// JNI 录制 / 离线确定性回放包装器
// ============================================================================

pub(crate) type SharedJniHandlerSlot = Rc<RefCell<Option<Box<dyn JniHandler>>>>;

/// 录制模式 `JniHandler` 包装器：透传调用原业务 Handler，同时把返回值与 `ObjectTableDelta` 写入事件总线
pub(crate) struct RecordJniHandler {
    inner: SharedJniHandlerSlot,
    bus: Arc<EventLogBus>,
}

impl RecordJniHandler {
    pub fn new(inner: SharedJniHandlerSlot, bus: Arc<EventLogBus>) -> Self {
        Self { inner, bus }
    }

    fn record_call<R>(
        &mut self,
        ctx: &mut JniContext<'_>,
        to_jval: impl FnOnce(&R) -> JValue,
        default_val: R,
        f: impl FnOnce(&mut dyn JniHandler, &mut JniContext<'_>) -> R,
    ) -> R {
        let before = ctx.objects.clone();
        let ret = {
            let mut slot = self.inner.borrow_mut();
            if let Some(h) = slot.as_deref_mut() {
                f(h, ctx)
            } else {
                default_val
            }
        };
        let delta = ctx.objects.diff_since(&before);
        self.bus.record_jni_callback(to_jval(&ret), delta);
        ret
    }
}

impl JniHandler for RecordJniHandler {
    fn find_class(&mut self, ctx: &mut JniContext<'_>, name: &str) -> JObjectRef {
        self.record_call(ctx, |&r| JValue::Object(r), JObjectRef::NULL, |h, c| {
            h.find_class(c, name)
        })
    }
    fn call_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        self.record_call(ctx, |&r| JValue::Object(r), JObjectRef::NULL, |h, c| {
            h.call_object_method(c, obj, method, args)
        })
    }
    fn call_static_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        self.record_call(ctx, |&r| JValue::Object(r), JObjectRef::NULL, |h, c| {
            h.call_static_object_method(c, class_name, method, args)
        })
    }
    fn call_int_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i32 {
        self.record_call(ctx, |&v| JValue::Int(v), 0, |h, c| {
            h.call_int_method(c, obj, method, args)
        })
    }
    fn call_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        self.record_call(ctx, |&v| JValue::Long(v), 0, |h, c| {
            h.call_long_method(c, obj, method, args)
        })
    }
    fn call_boolean_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> bool {
        self.record_call(ctx, |&v| JValue::Boolean(v), false, |h, c| {
            h.call_boolean_method(c, obj, method, args)
        })
    }
    fn call_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        self.record_call(ctx, |_| JValue::Void, (), |h, c| {
            h.call_void_method(c, obj, method, args)
        })
    }
    fn get_object_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> JObjectRef {
        self.record_call(ctx, |&r| JValue::Object(r), JObjectRef::NULL, |h, c| {
            h.get_object_field(c, obj, field)
        })
    }
    fn get_static_object_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> JObjectRef {
        self.record_call(ctx, |&r| JValue::Object(r), JObjectRef::NULL, |h, c| {
            h.get_static_object_field(c, class_name, field)
        })
    }
    fn new_object(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        self.record_call(ctx, |&r| JValue::Object(r), JObjectRef::NULL, |h, c| {
            h.new_object(c, class_name, method, args)
        })
    }
    fn call_static_boolean_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> bool {
        self.record_call(ctx, |&v| JValue::Boolean(v), false, |h, c| {
            h.call_static_boolean_method(c, class_name, method, args)
        })
    }
    fn call_static_int_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i32 {
        self.record_call(ctx, |&v| JValue::Int(v), 0, |h, c| {
            h.call_static_int_method(c, class_name, method, args)
        })
    }
    fn call_static_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        self.record_call(ctx, |&v| JValue::Long(v), 0, |h, c| {
            h.call_static_long_method(c, class_name, method, args)
        })
    }
    fn call_static_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        self.record_call(ctx, |_| JValue::Void, (), |h, c| {
            h.call_static_void_method(c, class_name, method, args)
        })
    }
    fn get_boolean_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> bool {
        self.record_call(ctx, |&v| JValue::Boolean(v), false, |h, c| {
            h.get_boolean_field(c, obj, field)
        })
    }
    fn get_int_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i32 {
        self.record_call(ctx, |&v| JValue::Int(v), 0, |h, c| {
            h.get_int_field(c, obj, field)
        })
    }
    fn get_long_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i64 {
        self.record_call(ctx, |&v| JValue::Long(v), 0, |h, c| {
            h.get_long_field(c, obj, field)
        })
    }
    fn get_static_boolean_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> bool {
        self.record_call(ctx, |&v| JValue::Boolean(v), false, |h, c| {
            h.get_static_boolean_field(c, class_name, field)
        })
    }
    fn get_static_int_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i32 {
        self.record_call(ctx, |&v| JValue::Int(v), 0, |h, c| {
            h.get_static_int_field(c, class_name, field)
        })
    }
    fn get_static_long_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i64 {
        self.record_call(ctx, |&v| JValue::Long(v), 0, |h, c| {
            h.get_static_long_field(c, class_name, field)
        })
    }
    fn call_byte_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i8 {
        self.record_call(ctx, |&v| JValue::Byte(v), 0, |h, c| {
            h.call_byte_method(c, obj, method, args)
        })
    }
    fn call_char_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> u16 {
        self.record_call(ctx, |&v| JValue::Char(v), 0, |h, c| {
            h.call_char_method(c, obj, method, args)
        })
    }
    fn call_short_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i16 {
        self.record_call(ctx, |&v| JValue::Short(v), 0, |h, c| {
            h.call_short_method(c, obj, method, args)
        })
    }
    fn call_float_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f32 {
        self.record_call(ctx, |&v| JValue::Float(v), 0.0, |h, c| {
            h.call_float_method(c, obj, method, args)
        })
    }
    fn call_double_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f64 {
        self.record_call(ctx, |&v| JValue::Double(v), 0.0, |h, c| {
            h.call_double_method(c, obj, method, args)
        })
    }
    fn call_static_byte_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i8 {
        self.record_call(ctx, |&v| JValue::Byte(v), 0, |h, c| {
            h.call_static_byte_method(c, class_name, method, args)
        })
    }
    fn call_static_char_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> u16 {
        self.record_call(ctx, |&v| JValue::Char(v), 0, |h, c| {
            h.call_static_char_method(c, class_name, method, args)
        })
    }
    fn call_static_short_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i16 {
        self.record_call(ctx, |&v| JValue::Short(v), 0, |h, c| {
            h.call_static_short_method(c, class_name, method, args)
        })
    }
    fn call_static_float_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f32 {
        self.record_call(ctx, |&v| JValue::Float(v), 0.0, |h, c| {
            h.call_static_float_method(c, class_name, method, args)
        })
    }
    fn call_static_double_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f64 {
        self.record_call(ctx, |&v| JValue::Double(v), 0.0, |h, c| {
            h.call_static_double_method(c, class_name, method, args)
        })
    }
    fn get_byte_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i8 {
        self.record_call(ctx, |&v| JValue::Byte(v), 0, |h, c| {
            h.get_byte_field(c, obj, field)
        })
    }
    fn get_char_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> u16 {
        self.record_call(ctx, |&v| JValue::Char(v), 0, |h, c| {
            h.get_char_field(c, obj, field)
        })
    }
    fn get_short_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i16 {
        self.record_call(ctx, |&v| JValue::Short(v), 0, |h, c| {
            h.get_short_field(c, obj, field)
        })
    }
    fn get_float_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f32 {
        self.record_call(ctx, |&v| JValue::Float(v), 0.0, |h, c| {
            h.get_float_field(c, obj, field)
        })
    }
    fn get_double_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f64 {
        self.record_call(ctx, |&v| JValue::Double(v), 0.0, |h, c| {
            h.get_double_field(c, obj, field)
        })
    }
    fn set_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
        value: JValue,
    ) {
        self.record_call(ctx, |_| JValue::Void, (), |h, c| {
            h.set_field(c, obj, field, value)
        })
    }
    fn get_static_byte_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i8 {
        self.record_call(ctx, |&v| JValue::Byte(v), 0, |h, c| {
            h.get_static_byte_field(c, class_name, field)
        })
    }
    fn get_static_char_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> u16 {
        self.record_call(ctx, |&v| JValue::Char(v), 0, |h, c| {
            h.get_static_char_field(c, class_name, field)
        })
    }
    fn get_static_short_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i16 {
        self.record_call(ctx, |&v| JValue::Short(v), 0, |h, c| {
            h.get_static_short_field(c, class_name, field)
        })
    }
    fn get_static_float_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> f32 {
        self.record_call(ctx, |&v| JValue::Float(v), 0.0, |h, c| {
            h.get_static_float_field(c, class_name, field)
        })
    }
    fn get_static_double_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> f64 {
        self.record_call(ctx, |&v| JValue::Double(v), 0.0, |h, c| {
            h.get_static_double_field(c, class_name, field)
        })
    }
    fn set_static_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
        value: JValue,
    ) {
        self.record_call(ctx, |_| JValue::Void, (), |h, c| {
            h.set_static_field(c, class_name, field, value)
        })
    }
}

/// 离线回放模式 `JniHandler`：从 `EventLogBus` 按序弹出录制到的 `ObjectTableDelta` 与返回值；
/// 当切换到 Live Fork 模式时自动回退至 `DefaultJniHandler`。
struct ReplayJniHandler {
    bus: Arc<EventLogBus>,
    fallback: DefaultJniHandler,
}

impl ReplayJniHandler {
    fn new(bus: Arc<EventLogBus>) -> Self {
        Self {
            bus,
            fallback: DefaultJniHandler,
        }
    }

    fn replay_or<R>(
        &mut self,
        ctx: &mut JniContext<'_>,
        extract: impl FnOnce(JValue) -> R,
        fallback_fn: impl FnOnce(&mut DefaultJniHandler, &mut JniContext<'_>) -> R,
    ) -> R {
        if let Some((ret, delta)) = self.bus.replay_jni_callback() {
            ctx.objects.apply_delta(&delta);
            extract(ret)
        } else {
            fallback_fn(&mut self.fallback, ctx)
        }
    }
}

impl JniHandler for ReplayJniHandler {
    fn find_class(&mut self, ctx: &mut JniContext<'_>, name: &str) -> JObjectRef {
        self.replay_or(
            ctx,
            |v| v.as_object().unwrap_or(JObjectRef::NULL),
            |f, c| f.find_class(c, name),
        )
    }
    fn call_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        self.replay_or(
            ctx,
            |v| v.as_object().unwrap_or(JObjectRef::NULL),
            |f, c| f.call_object_method(c, obj, method, args),
        )
    }
    fn call_static_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        self.replay_or(
            ctx,
            |v| v.as_object().unwrap_or(JObjectRef::NULL),
            |f, c| f.call_static_object_method(c, class_name, method, args),
        )
    }
    fn call_int_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i32 {
        self.replay_or(ctx, |v| v.as_int().unwrap_or(0), |f, c| {
            f.call_int_method(c, obj, method, args)
        })
    }
    fn call_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        self.replay_or(ctx, |v| v.as_long().unwrap_or(0), |f, c| {
            f.call_long_method(c, obj, method, args)
        })
    }
    fn call_boolean_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> bool {
        self.replay_or(
            ctx,
            |v| matches!(v, JValue::Boolean(true)),
            |f, c| f.call_boolean_method(c, obj, method, args),
        )
    }
    fn call_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        self.replay_or(ctx, |_| (), |f, c| {
            f.call_void_method(c, obj, method, args)
        })
    }
    fn get_object_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> JObjectRef {
        self.replay_or(
            ctx,
            |v| v.as_object().unwrap_or(JObjectRef::NULL),
            |f, c| f.get_object_field(c, obj, field),
        )
    }
    fn get_static_object_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> JObjectRef {
        self.replay_or(
            ctx,
            |v| v.as_object().unwrap_or(JObjectRef::NULL),
            |f, c| f.get_static_object_field(c, class_name, field),
        )
    }
    fn new_object(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        self.replay_or(
            ctx,
            |v| v.as_object().unwrap_or(JObjectRef::NULL),
            |f, c| f.new_object(c, class_name, method, args),
        )
    }
    fn call_static_boolean_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> bool {
        self.replay_or(
            ctx,
            |v| matches!(v, JValue::Boolean(true)),
            |f, c| f.call_static_boolean_method(c, class_name, method, args),
        )
    }
    fn call_static_int_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i32 {
        self.replay_or(ctx, |v| v.as_int().unwrap_or(0), |f, c| {
            f.call_static_int_method(c, class_name, method, args)
        })
    }
    fn call_static_long_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i64 {
        self.replay_or(ctx, |v| v.as_long().unwrap_or(0), |f, c| {
            f.call_static_long_method(c, class_name, method, args)
        })
    }
    fn call_static_void_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) {
        self.replay_or(ctx, |_| (), |f, c| {
            f.call_static_void_method(c, class_name, method, args)
        })
    }
    fn get_boolean_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> bool {
        self.replay_or(
            ctx,
            |v| matches!(v, JValue::Boolean(true)),
            |f, c| f.get_boolean_field(c, obj, field),
        )
    }
    fn get_int_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i32 {
        self.replay_or(ctx, |v| v.as_int().unwrap_or(0), |f, c| {
            f.get_int_field(c, obj, field)
        })
    }
    fn get_long_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i64 {
        self.replay_or(ctx, |v| v.as_long().unwrap_or(0), |f, c| {
            f.get_long_field(c, obj, field)
        })
    }
    fn get_static_boolean_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> bool {
        self.replay_or(
            ctx,
            |v| matches!(v, JValue::Boolean(true)),
            |f, c| f.get_static_boolean_field(c, class_name, field),
        )
    }
    fn get_static_int_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i32 {
        self.replay_or(ctx, |v| v.as_int().unwrap_or(0), |f, c| {
            f.get_static_int_field(c, class_name, field)
        })
    }
    fn get_static_long_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i64 {
        self.replay_or(ctx, |v| v.as_long().unwrap_or(0), |f, c| {
            f.get_static_long_field(c, class_name, field)
        })
    }
    fn call_byte_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i8 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Byte(b) => b,
                _ => 0,
            },
            |f, c| f.call_byte_method(c, obj, method, args),
        )
    }
    fn call_char_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> u16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Char(ch) => ch,
                _ => 0,
            },
            |f, c| f.call_char_method(c, obj, method, args),
        )
    }
    fn call_short_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Short(s) => s,
                _ => 0,
            },
            |f, c| f.call_short_method(c, obj, method, args),
        )
    }
    fn call_float_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f32 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Float(fv) => fv,
                _ => 0.0,
            },
            |f, c| f.call_float_method(c, obj, method, args),
        )
    }
    fn call_double_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f64 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Double(dv) => dv,
                _ => 0.0,
            },
            |f, c| f.call_double_method(c, obj, method, args),
        )
    }
    fn call_static_byte_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i8 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Byte(b) => b,
                _ => 0,
            },
            |f, c| f.call_static_byte_method(c, class_name, method, args),
        )
    }
    fn call_static_char_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> u16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Char(ch) => ch,
                _ => 0,
            },
            |f, c| f.call_static_char_method(c, class_name, method, args),
        )
    }
    fn call_static_short_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> i16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Short(s) => s,
                _ => 0,
            },
            |f, c| f.call_static_short_method(c, class_name, method, args),
        )
    }
    fn call_static_float_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f32 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Float(fv) => fv,
                _ => 0.0,
            },
            |f, c| f.call_static_float_method(c, class_name, method, args),
        )
    }
    fn call_static_double_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        method: &MethodDesc,
        args: &[JValue],
    ) -> f64 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Double(dv) => dv,
                _ => 0.0,
            },
            |f, c| f.call_static_double_method(c, class_name, method, args),
        )
    }
    fn get_byte_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i8 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Byte(b) => b,
                _ => 0,
            },
            |f, c| f.get_byte_field(c, obj, field),
        )
    }
    fn get_char_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> u16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Char(ch) => ch,
                _ => 0,
            },
            |f, c| f.get_char_field(c, obj, field),
        )
    }
    fn get_short_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> i16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Short(s) => s,
                _ => 0,
            },
            |f, c| f.get_short_field(c, obj, field),
        )
    }
    fn get_float_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f32 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Float(fv) => fv,
                _ => 0.0,
            },
            |f, c| f.get_float_field(c, obj, field),
        )
    }
    fn get_double_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
    ) -> f64 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Double(dv) => dv,
                _ => 0.0,
            },
            |f, c| f.get_double_field(c, obj, field),
        )
    }
    fn set_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        field: &FieldDesc,
        value: JValue,
    ) {
        self.replay_or(ctx, |_| (), |f, c| f.set_field(c, obj, field, value))
    }
    fn get_static_byte_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i8 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Byte(b) => b,
                _ => 0,
            },
            |f, c| f.get_static_byte_field(c, class_name, field),
        )
    }
    fn get_static_char_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> u16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Char(ch) => ch,
                _ => 0,
            },
            |f, c| f.get_static_char_field(c, class_name, field),
        )
    }
    fn get_static_short_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> i16 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Short(s) => s,
                _ => 0,
            },
            |f, c| f.get_static_short_field(c, class_name, field),
        )
    }
    fn get_static_float_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> f32 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Float(fv) => fv,
                _ => 0.0,
            },
            |f, c| f.get_static_float_field(c, class_name, field),
        )
    }
    fn get_static_double_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
    ) -> f64 {
        self.replay_or(
            ctx,
            |v| match v {
                JValue::Double(dv) => dv,
                _ => 0.0,
            },
            |f, c| f.get_static_double_field(c, class_name, field),
        )
    }
    fn set_static_field(
        &mut self,
        ctx: &mut JniContext<'_>,
        class_name: &str,
        field: &FieldDesc,
        value: JValue,
    ) {
        self.replay_or(ctx, |_| (), |f, c| {
            f.set_static_field(c, class_name, field, value)
        })
    }
}

// ============================================================================
// 活跃录制会话（挂载在 AndroidEmulator 上）
// ============================================================================

/// 在 Unicorn `code_hook` 内直接捕获 `TapeFullState`（避免外层借用冲突）
fn capture_state_from_uc(
    uc: &Unicorn<'_, EmuState>,
    linker: &LinkerTapeState,
    cpu_layout: CpuContext,
) -> EmuResult<TapeFullState> {
    let regs = capture_generic_context(uc)?;
    let data = uc.get_data();
    let vmas = data.mem.regions().cloned().collect();
    let mut nonzero_pages = BTreeMap::new();
    let mut page_buf = [0u8; 4096];
    for &page_addr in data.mem.mapped_pages() {
        uc.mem_read(page_addr, &mut page_buf)?;
        if !is_zero_page(&page_buf) {
            nonzero_pages.insert(page_addr, page_buf);
        }
    }
    Ok(TapeFullState {
        regs,
        cpu_layout,
        vmas,
        heap: data.mem.heap_ref().clone(),
        brk_cursor: data.mem.brk_cursor(),
        mmap_cursor: data.mem.mmap_cursor(),
        host_scratch: Some(data.mem.host_scratch_ref().clone()),
        freeze_layout: Some(data.mem.is_layout_frozen()),
        nonzero_pages,
        linker: linker.clone(),
        trampolines: data.trampolines.export_tape_state(),
        jni: data.jni.export_tape_state(),
        vfs: data.vfs.export_tape_state(),
    })
}

pub(crate) struct ActiveTimeTravelRecorder {
    pub config: RecordConfig,
    pub bus: Arc<EventLogBus>,
    pub tape: Arc<Mutex<Option<Tape>>>,
    pub linker_snapshot: Arc<Mutex<LinkerTapeState>>,
    pub last_kf_insn: Arc<AtomicU64>,
    pub code_hook: UcHookId,
    pub wrapped_jni_slot: Option<SharedJniHandlerSlot>,
}

impl ActiveTimeTravelRecorder {
    pub fn start(emu: &mut AndroidEmulator, config: RecordConfig) -> EmuResult<Self> {
        if emu.backend_kind() != BackendKind::Unicorn {
            return Err(EmuError::Backend(format!(
                "时间旅行录制仅支持 `unicorn` 后端（当前为 `{}`；可先用当前后端保存一期 .rtape，再通过 from_tape 切入 unicorn 开启时间旅行精录）",
                emu.backend_kind()
            )));
        }

        let bus = Arc::new(EventLogBus::new_record());
        let tape: Arc<Mutex<Option<Tape>>> = Arc::new(Mutex::new(None));
        let base_captured = Arc::new(AtomicBool::new(false));
        let linker_snapshot = Arc::new(Mutex::new(emu.linker().export_tape_state()));
        let cpu_layout = *emu.cpu_layout();

        // 1. 挂载 VFS 确定性事件总线（实时时钟 & 只读宿主机文件捕获）
        emu.vfs_mut().set_tt_bus(Some(Arc::clone(&bus)));

        // 2. 包装 JNI Handler（默认开启，实现离线脱离 JS 回放）
        let wrapped_jni_slot = if config.capture_jni {
            let slot: SharedJniHandlerSlot = Rc::new(RefCell::new(None));
            let prev = emu
                .jni_mut()
                .swap_handler(Box::new(RecordJniHandler::new(
                    Rc::clone(&slot),
                    Arc::clone(&bus),
                )));
            *slot.borrow_mut() = Some(prev);
            Some(slot)
        } else {
            None
        };

        // 3. 挂载全局 Unicorn 指令级录制 Hook
        let bus_h = Arc::clone(&bus);
        let tape_h = Arc::clone(&tape);
        let base_h = Arc::clone(&base_captured);
        let linker_h = Arc::clone(&linker_snapshot);
        let kf_interval = config.keyframe_interval;
        let max_insns = config.max_insns;
        let last_kf_insn = Arc::new(AtomicU64::new(u64::MAX));
        let last_kf_h = Arc::clone(&last_kf_insn);

        let hook_res = {
            let uc = emu.try_uc_mut().expect("Unicorn backend verified");
            uc.add_code_hook(0, u64::MAX, move |uc, addr, _size| {
                if addr == RET_MAGIC_ADDR {
                    return;
                }
                let cur = bus_h.cur_insn();
                if max_insns > 0 && cur >= max_insns {
                    let st = uc.get_data_mut();
                    st.manual_stop = true;
                    st.tt_stopped_at_pc = true;
                    let _ = uc.emu_stop();
                    return;
                }
                if !base_h.load(Ordering::Relaxed) {
                    if let Ok(lk) = linker_h.lock() {
                        if let Ok(state) = capture_state_from_uc(uc, &lk, cpu_layout) {
                            let mut meta = TapeMeta::new(0, "tt_base", "unicorn");
                            meta.insn_count = 0;
                            let t = Tape::from_base(meta, state);
                            if let Ok(mut tg) = tape_h.lock() {
                                *tg = Some(t);
                            }
                            bus_h.mark_keyframe_event_offset(0);
                            last_kf_h.store(0, Ordering::Relaxed);
                            base_h.store(true, Ordering::Relaxed);
                        }
                    }
                } else if kf_interval > 0
                    && cur > 0
                    && cur.is_multiple_of(kf_interval)
                    && last_kf_h.load(Ordering::Relaxed) != cur
                {
                    if let Ok(lk) = linker_h.lock() {
                        if let Ok(state) = capture_state_from_uc(uc, &lk, cpu_layout) {
                            if let Ok(mut tg) = tape_h.lock() {
                                if let Some(t) = tg.as_mut() {
                                    let idx = t.len() as u32;
                                    let mut meta =
                                        TapeMeta::new(idx, format!("kf_{cur}"), "unicorn");
                                    meta.insn_count = cur;
                                    if t.push_delta(meta, state).is_ok() {
                                        bus_h.mark_keyframe_event_offset(cur);
                                        last_kf_h.store(cur, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                }
                bus_h.fetch_add_insn();
            })
            .map_err(|e| EmuError::Backend(format!("挂载时间旅行录制 Hook 失败: {e:?}")))
        };

        let code_hook = match hook_res {
            Ok(id) => id,
            Err(err) => {
                // 失败回滚：避免把模拟器永久留在 Record 总线/包装器状态
                emu.vfs_mut().set_tt_bus(None);
                if let Some(slot) = wrapped_jni_slot {
                    if let Some(orig) = slot.borrow_mut().take() {
                        emu.jni_mut().swap_handler(orig);
                    }
                }
                return Err(err);
            }
        };

        // 确保录制 code_hook 严格位于 HLE/JNI 跳板 Hook 之前执行（避免跳板提前变异状态与事件计数偏移）
        if let Err(err) = emu.move_builtin_code_hooks_to_tail() {
            if let Some(uc) = emu.try_uc_mut() {
                let _ = uc.remove_hook(code_hook);
            }
            emu.vfs_mut().set_tt_bus(None);
            if let Some(slot) = wrapped_jni_slot {
                if let Some(orig) = slot.borrow_mut().take() {
                    emu.jni_mut().swap_handler(orig);
                }
            }
            return Err(err);
        }

        // 刷清全部可执行 VMA（含手动映射/JIT 页）的 TB 缓存，确保新挂载的 code_hook 立即生效
        let exec_ranges: Vec<(u64, u64)> = emu
            .cpu()
            .get_data()
            .mem
            .regions()
            .filter(|r| (r.perms.0 & Prot::EXEC.0) != 0)
            .map(|r| (r.start, r.end))
            .collect();
        for (start, end) in exec_ranges {
            let _ = emu.cpu_mut().flush_cache(start, end);
        }

        Ok(Self {
            config,
            bus,
            tape,
            linker_snapshot,
            last_kf_insn,
            code_hook,
            wrapped_jni_slot,
        })
    }

    pub fn refresh_linker(&self, linker: &LinkerTapeState) {
        if let Ok(mut lk) = self.linker_snapshot.lock() {
            *lk = linker.clone();
        }
    }

    /// 连续多次 `call_address` 间自动捕获调用边界关键帧（保留新的 `PC`/`SP`/`LR`/`X0..X7` 与宿主侧写入）
    pub fn record_call_boundary(
        &self,
        engine: &CpuEngine<EmuState>,
        cpu_layout: &CpuContext,
        linker: &DynamicLinker,
    ) -> EmuResult<()> {
        let cur = self.bus.cur_insn();
        let lk = linker.export_tape_state();
        self.refresh_linker(&lk);
        let regs = capture_generic_context(engine)?;
        let data = engine.get_data();
        let vmas = data.mem.regions().cloned().collect();
        let mut nonzero_pages = BTreeMap::new();
        let mut page_buf = [0u8; 4096];
        for &page_addr in data.mem.mapped_pages() {
            engine.mem_read(page_addr, &mut page_buf)?;
            if !is_zero_page(&page_buf) {
                nonzero_pages.insert(page_addr, page_buf);
            }
        }
        let state = TapeFullState {
            regs,
            cpu_layout: *cpu_layout,
            vmas,
            heap: data.mem.heap_ref().clone(),
            brk_cursor: data.mem.brk_cursor(),
            mmap_cursor: data.mem.mmap_cursor(),
            host_scratch: Some(data.mem.host_scratch_ref().clone()),
            freeze_layout: Some(data.mem.is_layout_frozen()),
            nonzero_pages,
            linker: lk,
            trampolines: data.trampolines.export_tape_state(),
            jni: data.jni.export_tape_state(),
            vfs: data.vfs.export_tape_state(),
        };
        let mut tg = self
            .tape
            .lock()
            .map_err(|_| EmuError::Backend("时间旅行录制磁带锁损坏".to_string()))?;
        if let Some(t) = tg.as_mut() {
            let idx = t.len() as u32;
            let mut meta = TapeMeta::new(idx, format!("call_boundary_{cur}"), "unicorn");
            meta.insn_count = cur;
            t.push_delta(meta, state)?;
            self.bus.mark_keyframe_event_offset(cur);
            self.last_kf_insn.store(cur, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Guest 指令执行过程中发生异常（崩溃）时回退 `code_hook` 预递增的指令计数，消除幽灵 `end_insn`
    pub fn on_guest_crash(&self) {
        self.bus.dec_insn_on_crash();
    }

    pub fn bookmark(&self, label: impl Into<String>) -> u64 {
        self.bus.add_bookmark(label.into())
    }

    pub fn recorded_insns(&self) -> u64 {
        self.bus.cur_insn()
    }

    /// 结束录制、卸载 Hook、还原原 `JniHandler` 并写入完整 `.rtape` 时间旅行磁带文件
    pub fn finish(self, emu: &mut AndroidEmulator, path: impl AsRef<Path>) -> EmuResult<TapeSummary> {
        // 1. 卸载录制 Hook 与 VFS 总线，仅当 RecordJniHandler 仍挂载时还原原 JniHandler
        if let Some(uc) = emu.try_uc_mut() {
            let _ = uc.remove_hook(self.code_hook);
        }
        emu.vfs_mut().set_tt_bus(None);
        if let Some(slot) = self.wrapped_jni_slot {
            if Rc::strong_count(&slot) > 1 {
                if let Some(orig) = slot.borrow_mut().take() {
                    emu.jni_mut().swap_handler(orig);
                }
            }
        }

        // 2. 取出内存磁带（若期间未执行任何指令，直接以当前态作为 0 指令 BASE）
        let end_insn = self.bus.cur_insn();
        let maybe_tape = self
            .tape
            .lock()
            .map_err(|_| EmuError::Backend("时间旅行录制磁带锁损坏".to_string()))?
            .take();
        let mut tape = match maybe_tape {
            Some(t) => t,
            None => {
                let state = emu.capture_tape_state()?;
                let mut meta = TapeMeta::new(0, "tt_base", "unicorn");
                meta.insn_count = 0;
                self.bus.mark_keyframe_event_offset(0);
                Tape::from_base(meta, state)
            }
        };

        // 3. 若终点指令数大于最后一帧关键帧，追加终点增量关键帧（加速跳到末尾与反向追踪！）
        let last_kf = tape
            .keyframe_insn(tape.len().saturating_sub(1))
            .unwrap_or(0);
        if end_insn > last_kf {
            let end_state = emu.capture_tape_state()?;
            let idx = tape.len() as u32;
            let mut meta = TapeMeta::new(idx, format!("tt_end_{end_insn}"), "unicorn");
            meta.insn_count = end_insn;
            tape.push_delta(meta, end_state)?;
            self.bus.mark_keyframe_event_offset(end_insn);
        }

        // 4. 写入 CHUNK_EVENT_LOG (Tag=3) 并原子落盘
        let ev_log = self.bus.export_event_log(&self.config);
        tape.set_event_log(Some(ev_log));
        tape.save_file(path)
    }
}

// ============================================================================
// 时间旅行离线回放与反向调试引擎（TimeTravelPlayer）
// ============================================================================

struct MicroSnapshot {
    insn: u64,
    event_cursor: usize,
    layout_epoch: u64,
    emu_snap: EmuSnapshot,
    vfs: VfsTapeState,
    trampolines: TrampolineTapeState,
}

const MAX_KEYFRAME_CACHE: usize = 8;
const MAX_MICRO_SNAPSHOTS: usize = 32;

/// `.rtape` 二期时间旅行播放器（支持精确 `seek_insn`、单步前进/回退、`continue_backward` 与反向观察点）
pub struct TimeTravelPlayer {
    tape: Tape,
    event_log: Arc<TapeEventLog>,
    bus: Arc<EventLogBus>,
    emu: AndroidEmulator,
    cur_insn: u64,
    /// LRU 物化关键帧缓存：`(keyframe_idx, TapeFullState)`
    kf_cache: VecDeque<(usize, TapeFullState)>,
    /// 轻量微快照环：让连续 `step_backward(1)` / GDB `rs` 降至 <0.1ms
    micro_ring: VecDeque<MicroSnapshot>,
    /// 是否已切出录制轨道进入实时分叉执行
    live_forked: bool,
}

impl TimeTravelPlayer {
    /// 从磁盘 `.rtape` 文件打开时间旅行会话（自动恢复至 `insn = start_insn`）
    pub fn open(path: impl AsRef<Path>) -> EmuResult<Self> {
        let tape = Tape::load_file(path)?;
        Self::from_tape(tape)
    }

    /// 从已加载的 `Tape` 构建时间旅行会话
    pub fn from_tape(tape: Tape) -> EmuResult<Self> {
        let event_log = tape.event_log_arc().ok_or_else(|| {
            EmuError::Backend(
                "该 .rtape 文件不包含二期时间旅行事件日志（CHUNK_EVENT_LOG），请先使用 start_time_travel_record / emu.record.start 录制"
                    .to_string(),
            )
        })?;
        let bus = Arc::new(EventLogBus::new_replay(Arc::clone(&event_log)));
        let mut emu = AndroidEmulator::builder()
            .backend(BackendKind::Unicorn)
            .jni_handler(Box::new(ReplayJniHandler::new(Arc::clone(&bus))))
            .build()?;
        emu.vfs_mut().set_tt_bus(Some(Arc::clone(&bus)));
        // 离线只读宿主机文件映射直接挂载到专用只读区（不污染 overlay_files / overlay_dirs）
        emu.vfs_mut()
            .set_replay_host_files(event_log.host_files.iter().cloned().collect());

        let start_insn = event_log.start_insn;
        let mut player = Self {
            tape,
            event_log,
            bus,
            emu,
            cur_insn: start_insn,
            kf_cache: VecDeque::with_capacity(MAX_KEYFRAME_CACHE),
            micro_ring: VecDeque::with_capacity(MAX_MICRO_SNAPSHOTS),
            live_forked: false,
        };
        player.restore_keyframe(0)?;
        Ok(player)
    }

    pub fn tape(&self) -> &Tape {
        &self.tape
    }

    pub fn event_log(&self) -> &TapeEventLog {
        &self.event_log
    }

    pub fn emu(&self) -> &AndroidEmulator {
        &self.emu
    }

    pub fn emu_mut(&mut self) -> &mut AndroidEmulator {
        &mut self.emu
    }

    pub fn current_insn(&self) -> u64 {
        self.cur_insn
    }

    pub fn start_insn(&self) -> u64 {
        self.event_log.start_insn
    }

    pub fn total_insns(&self) -> u64 {
        self.event_log.end_insn
    }

    pub fn bookmarks(&self) -> &[(u64, String)] {
        &self.event_log.bookmarks
    }

    pub fn is_live_forked(&self) -> bool {
        self.live_forked
    }

    /// 显式切换为实时分叉模式（允许修改寄存器/内存并脱离录制历史继续探索）
    pub fn enter_live_fork(&mut self) {
        self.live_forked = true;
        self.bus.set_live_fork(true);
        self.micro_ring.clear();
    }

    /// 从 LRU 缓存获取或物化指定关键帧 `kf_idx`
    fn get_keyframe_state(&mut self, kf_idx: usize) -> EmuResult<TapeFullState> {
        if let Some(pos) = self.kf_cache.iter().position(|(i, _)| *i == kf_idx) {
            let entry = self.kf_cache.remove(pos).unwrap();
            let cloned = entry.1.clone();
            self.kf_cache.push_back(entry);
            return Ok(cloned);
        }
        let (_, state) = self.tape.materialize_index(kf_idx)?;
        if self.kf_cache.len() >= MAX_KEYFRAME_CACHE {
            self.kf_cache.pop_front();
        }
        self.kf_cache.push_back((kf_idx, state.clone()));
        Ok(state)
    }

    /// 恢复至关键帧 `kf_idx`，并同步精确事件游标（自动清空旧窗口微快照环）
    fn restore_keyframe(&mut self, kf_idx: usize) -> EmuResult<()> {
        let kf_insn = self.tape.keyframe_insn(kf_idx).unwrap_or(0);
        let state = self.get_keyframe_state(kf_idx)?;
        self.emu.apply_tape_state(state)?;
        let ev_cursor = self.bus.event_cursor_for_keyframe(kf_insn);
        self.bus.set_cur_insn(kf_insn);
        self.bus.set_replay_cursor(ev_cursor);
        self.bus.set_live_fork(false);
        self.live_forked = false;
        self.cur_insn = kf_insn;
        self.micro_ring.clear();
        Ok(())
    }

    /// 尝试从微快照环恢复最接近且 `<= target_insn` 的内存微快照（严格校验 `layout_epoch`，失败安全回退关键帧）
    fn try_restore_micro_snapshot(&mut self, target_insn: u64, min_insn: u64) -> EmuResult<bool> {
        let best_pos = self
            .micro_ring
            .iter()
            .enumerate()
            .filter(|(_, m)| m.insn >= min_insn && m.insn <= target_insn)
            .max_by_key(|(_, m)| m.insn)
            .map(|(i, _)| i);
        let Some(idx) = best_pos else {
            return Ok(false);
        };
        let cur_epoch = self.emu.cpu().get_data().mem.layout_epoch();
        if self.micro_ring[idx].layout_epoch != cur_epoch {
            return Ok(false);
        }
        let vfs_state = self.micro_ring[idx].vfs.clone();
        let tramp_state = self.micro_ring[idx].trampolines.clone();
        let insn = self.micro_ring[idx].insn;
        let ev_cursor = self.micro_ring[idx].event_cursor;

        if self.emu.restore_snapshot(&self.micro_ring[idx].emu_snap).is_err() {
            return Ok(false);
        }
        {
            let d = self.emu.cpu_mut().get_data_mut();
            d.vfs.restore_tape_state(vfs_state);
            d.manual_stop = false;
            d.tt_stopped_at_pc = false;
        }
        {
            let mem = std::mem::replace(
                &mut self.emu.cpu_mut().get_data_mut().mem,
                crate::memory::MemoryManager::new(0, 0),
            );
            let mut tramps = std::mem::take(&mut self.emu.cpu_mut().get_data_mut().trampolines);
            let res = tramps.restore_tape_state_and_rewrite(self.emu.cpu_mut(), &mem, tramp_state);
            let d = self.emu.cpu_mut().get_data_mut();
            d.mem = mem;
            d.trampolines = tramps;
            if res.is_err() {
                return Ok(false);
            }
        }
        self.bus.set_cur_insn(insn);
        self.bus.set_replay_cursor(ev_cursor);
        self.bus.set_live_fork(false);
        self.live_forked = false;
        self.cur_insn = insn;
        Ok(true)
    }

    fn capture_micro_snapshot(&mut self) {
        if let Ok(emu_snap) = self.emu.capture_snapshot() {
            let d = self.emu.cpu().get_data();
            let ms = MicroSnapshot {
                insn: self.cur_insn,
                event_cursor: self.bus.replay_cursor(),
                layout_epoch: d.mem.layout_epoch(),
                emu_snap,
                vfs: d.vfs.export_tape_state(),
                trampolines: d.trampolines.export_tape_state(),
            };
            // 按 insn 去重，防止重复 seek 用同指令快照挤占微快照环
            if let Some(pos) = self.micro_ring.iter().position(|m| m.insn == self.cur_insn) {
                self.micro_ring[pos] = ms;
                return;
            }
            if self.micro_ring.len() >= MAX_MICRO_SNAPSHOTS {
                self.micro_ring.pop_front();
            }
            self.micro_ring.push_back(ms);
        }
    }

    /// 精确前向确定性重放到 `target_insn`（要求 `target_insn >= self.cur_insn`）
    fn replay_forward_to(
        &mut self,
        target_insn: u64,
        capture_micro_at: &[u64],
    ) -> EmuResult<()> {
        if target_insn <= self.cur_insn {
            return Ok(());
        }
        // 分段在指定的微快照锚点处停下留档，加速后续连续 rs 单步回退
        let mut stops: Vec<u64> = capture_micro_at
            .iter()
            .copied()
            .filter(|&s| s > self.cur_insn && s < target_insn)
            .collect();
        stops.sort_unstable();
        stops.dedup();
        stops.push(target_insn);

        for stop_at in stops {
            self.run_replay_until(stop_at)?;
            if stop_at < target_insn {
                self.capture_micro_snapshot();
            }
        }
        Ok(())
    }

    /// 底层 Unicorn 确定性重放循环：从当前 `cur_insn` 精准执行到 `stop_insn`（自动跨越多次调用边界）
    fn run_replay_until(&mut self, stop_insn: u64) -> EmuResult<()> {
        while self.cur_insn < stop_insn {
            let mut pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            if pc == RET_MAGIC_ADDR {
                if let Some(cb_idx) = self.tape.call_boundary_keyframe_at(self.cur_insn) {
                    self.restore_keyframe(cb_idx)?;
                    pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
                    if pc == RET_MAGIC_ADDR {
                        return Err(EmuError::Backend(format!(
                            "时间旅行调用边界关键帧 #{cb_idx} (insn={}) 仍位于 RET_MAGIC_ADDR",
                            self.cur_insn
                        )));
                    }
                } else {
                    return Err(EmuError::Backend(format!(
                        "时间旅行重放提前返回到 RET_MAGIC_ADDR @ insn={} (target={stop_insn})",
                        self.cur_insn
                    )));
                }
            }

            let bus_h = Arc::clone(&self.bus);
            let stopped_by_hook = Arc::new(AtomicBool::new(false));
            let stopped_h = Arc::clone(&stopped_by_hook);
            let hook_id = {
                let uc = self.emu.try_uc_mut().ok_or_else(|| {
                    EmuError::Backend("时间旅行回放仅支持 Unicorn 后端".to_string())
                })?;
                uc.get_data_mut().tt_stopped_at_pc = false;
                uc.add_code_hook(0, u64::MAX, move |uc, addr, _size| {
                    if addr == RET_MAGIC_ADDR {
                        return;
                    }
                    let cur = bus_h.cur_insn();
                    if cur >= stop_insn {
                        stopped_h.store(true, Ordering::Relaxed);
                        uc.get_data_mut().tt_stopped_at_pc = true;
                        let _ = uc.emu_stop();
                        return;
                    }
                    bus_h.fetch_add_insn();
                })
                .map_err(|e| EmuError::Backend(format!("挂载时间旅行回放 Hook 失败: {e:?}")))?
            };

            // 保证回放 code_hook 严格先于 HLE/JNI 跳板 Hook 执行，防止在跳板边界停驻时双重执行
            if let Err(err) = self.emu.move_builtin_code_hooks_to_tail() {
                if let Some(uc) = self.emu.try_uc_mut() {
                    let _ = uc.remove_hook(hook_id);
                }
                return Err(err);
            }

            let res = {
                let uc = self.emu.try_uc_mut().expect("Unicorn backend");
                let r = uc.emu_start(pc, RET_MAGIC_ADDR, 0, 0);
                let _ = uc.remove_hook(hook_id);
                uc.get_data_mut().tt_stopped_at_pc = false;
                r
            };
            self.cur_insn = self.bus.cur_insn();
            if let Err(err) = res {
                if !stopped_by_hook.load(Ordering::Relaxed) {
                    return Err(EmuError::Backend(format!(
                        "时间旅行重放异常 @ insn={} (target={stop_insn}): {err:?}",
                        self.cur_insn
                    )));
                }
            }
            if stopped_by_hook.load(Ordering::Relaxed) || self.cur_insn >= stop_insn {
                break;
            }
        }
        Ok(())
    }

    /// 瞬间定位到任意目标指令 `target_insn`（自动选取最佳关键帧/微快照/增量前向路径）
    pub fn seek_insn(&mut self, target_insn: u64) -> EmuResult<TimeTravelStop> {
        let clamped = target_insn.clamp(self.event_log.start_insn, self.event_log.end_insn);
        if !self.live_forked && clamped == self.cur_insn {
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::Step {
                insn: self.cur_insn,
                pc,
            });
        }

        let kf_idx = self.tape.nearest_keyframe_index(clamped);
        let kf_insn = self.tape.keyframe_insn(kf_idx).unwrap_or(0);

        // 判断是否可以直接从当前状态小幅前向重放
        let can_continue_from_cur = !self.live_forked && clamped > self.cur_insn && self.cur_insn >= kf_insn;

        if !can_continue_from_cur {
            // 若在微快照环中找到比关键帧更近的状态，优先用微快照 (<0.1ms!)
            let used_micro = if !self.live_forked && clamped > kf_insn {
                self.try_restore_micro_snapshot(clamped, kf_insn)?
            } else {
                false
            };
            if !used_micro {
                self.restore_keyframe(kf_idx)?;
            }
        }

        // 若目标距离当前大于 8 条指令，在末尾留下密集微快照锚点，让接下来的连续 `rs` 几乎零延迟
        let anchors: Vec<u64> = if clamped.saturating_sub(self.cur_insn) > 8 {
            [64u64, 32, 16, 8, 4, 2]
                .iter()
                .filter_map(|&off| clamped.checked_sub(off))
                .filter(|&a| a > self.cur_insn)
                .collect()
        } else {
            Vec::new()
        };
        self.replay_forward_to(clamped, &anchors)?;

        let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
        Ok(TimeTravelStop::Step {
            insn: self.cur_insn,
            pc,
        })
    }

    /// 跳转到命名书签
    pub fn seek_bookmark(&mut self, label: &str) -> EmuResult<TimeTravelStop> {
        let target = self
            .event_log
            .bookmarks
            .iter()
            .rev()
            .find(|(_, l)| l == label)
            .map(|(ins, _)| *ins)
            .ok_or_else(|| {
                EmuError::Backend(format!("时间轴中未找到书签 `{label}`"))
            })?;
        self.seek_insn(target)
    }

    /// 单步前向执行 `steps` 条指令（`steps == 0` 返回当前位置，不移动）
    pub fn step_forward(&mut self, steps: u64) -> EmuResult<TimeTravelStop> {
        if steps == 0 {
            return self.seek_insn(self.cur_insn);
        }
        if self.cur_insn >= self.event_log.end_insn {
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::LogEnd {
                insn: self.cur_insn,
                pc,
            });
        }
        let target = self.cur_insn.saturating_add(steps);
        if target >= self.event_log.end_insn {
            self.seek_insn(self.event_log.end_insn)?;
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::Step {
                insn: self.cur_insn,
                pc,
            });
        }
        self.seek_insn(target)
    }

    /// 单步回退 `steps` 条指令（对应 GDB `bs` / `rsi`；`steps == 0` 返回当前位置）
    pub fn step_backward(&mut self, steps: u64) -> EmuResult<TimeTravelStop> {
        if steps == 0 {
            return self.seek_insn(self.cur_insn);
        }
        if self.cur_insn <= self.event_log.start_insn {
            if self.live_forked {
                self.seek_insn(self.event_log.start_insn)?;
            }
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::LogBegin {
                insn: self.cur_insn,
                pc,
            });
        }
        let target = self
            .cur_insn
            .saturating_sub(steps)
            .max(self.event_log.start_insn);
        self.seek_insn(target)
    }

    /// 前向继续执行直到命中下一个断点、内存观察点或录制历史终点
    ///
    /// 符合 GDB RSP 正向语义：
    /// - 断点停在命中指令执行前（`insn`）；
    /// - 观察点停在命中指令执行后（`insn + 1`），此时新值已写入内存便于 GDB 对比 Old/New value。
    pub fn continue_forward(
        &mut self,
        breakpoints: &HashSet<u64>,
        watchpoints: &[Watchpoint],
    ) -> EmuResult<TimeTravelStop> {
        if self.live_forked {
            return Err(EmuError::Backend(
                "当前处于 Live Fork 模式，请先 seek/step_backward 回到录制轨道或使用实时继续"
                    .to_string(),
            ));
        }
        if self.cur_insn >= self.event_log.end_insn {
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::LogEnd {
                insn: self.cur_insn,
                pc,
            });
        }
        if breakpoints.is_empty() && watchpoints.is_empty() {
            self.seek_insn(self.event_log.end_insn)?;
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::LogEnd {
                insn: self.cur_insn,
                pc,
            });
        }
        let start_insn = self.cur_insn;
        let end_insn = self.event_log.end_insn;
        let hit = self.scan_window(start_insn, end_insn, breakpoints, watchpoints, true)?;
        match hit {
            Some(stop) => {
                match stop {
                    TimeTravelStop::Breakpoint { insn, .. } => {
                        self.seek_insn(insn)?;
                    }
                    TimeTravelStop::Watchpoint { insn, .. } => {
                        // 正向观察点停在执行完该访存指令后的边界（insn + 1），使 GDB 读内存立即看到新值
                        let post_insn = insn.saturating_add(1).min(end_insn);
                        self.seek_insn(post_insn)?;
                    }
                    _ => {}
                }
                Ok(stop)
            }
            None => {
                self.seek_insn(end_insn)?;
                let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
                Ok(TimeTravelStop::LogEnd {
                    insn: self.cur_insn,
                    pc,
                })
            }
        }
    }

    /// 反向继续执行（对应 GDB `bc` / `rc`）：按关键帧窗口倒序扫描，精准停在 `< cur_insn` 的最后一次断点或观察点命中处
    pub fn continue_backward(
        &mut self,
        breakpoints: &HashSet<u64>,
        watchpoints: &[Watchpoint],
    ) -> EmuResult<TimeTravelStop> {
        if self.cur_insn <= self.event_log.start_insn {
            if self.live_forked {
                self.seek_insn(self.event_log.start_insn)?;
            }
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::LogBegin {
                insn: self.cur_insn,
                pc,
            });
        }
        if breakpoints.is_empty() && watchpoints.is_empty() {
            self.seek_insn(self.event_log.start_insn)?;
            let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            return Ok(TimeTravelStop::LogBegin {
                insn: self.cur_insn,
                pc,
            });
        }

        let mut window_end = self.cur_insn; // 搜索区间 [kf_insn, window_end)
        let mut kf_idx = self.tape.nearest_keyframe_index(window_end.saturating_sub(1));

        loop {
            let kf_insn = self.tape.keyframe_insn(kf_idx).unwrap_or(0);
            self.restore_keyframe(kf_idx)?;
            let last_hit = self.scan_window(kf_insn, window_end, breakpoints, watchpoints, false)?;
            if let Some(stop) = last_hit {
                let target_insn = match stop {
                    TimeTravelStop::Breakpoint { insn, .. }
                    | TimeTravelStop::Watchpoint { insn, .. } => insn,
                    _ => kf_insn,
                };
                self.seek_insn(target_insn)?;
                return Ok(stop);
            }
            if kf_idx == 0 || kf_insn <= self.event_log.start_insn {
                self.seek_insn(self.event_log.start_insn)?;
                let pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
                return Ok(TimeTravelStop::LogBegin {
                    insn: self.cur_insn,
                    pc,
                });
            }
            window_end = kf_insn;
            kf_idx -= 1;
        }
    }

    /// 在当前状态（要求 `self.cur_insn == win_start`）上扫描 `[win_start, win_end)` 区间内的断点/观察点命中。
    /// - `stop_at_first = true`（前向 `continue`）：跳过 `win_start` 自身断点（不跳过观察点），命中观察点后待该指令执行完在下一条指令边界停下；
    /// - `stop_at_first = false`（反向 `continue`）：扫完整段区间并保留最后一次命中（`insn < win_end`）。
    fn scan_window(
        &mut self,
        win_start: u64,
        win_end: u64,
        breakpoints: &HashSet<u64>,
        watchpoints: &[Watchpoint],
        stop_at_first: bool,
    ) -> EmuResult<Option<TimeTravelStop>> {
        if win_end <= win_start {
            return Ok(None);
        }
        let hit_slot: Arc<Mutex<Option<TimeTravelStop>>> = Arc::new(Mutex::new(None));
        let hit_found = Arc::new(AtomicBool::new(false));
        let stop_before_next_insn = Arc::new(AtomicBool::new(false));

        while self.cur_insn < win_end {
            if stop_at_first && hit_found.load(Ordering::Relaxed) {
                break;
            }
            let mut pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
            if pc == RET_MAGIC_ADDR {
                if let Some(cb_idx) = self.tape.call_boundary_keyframe_at(self.cur_insn) {
                    self.restore_keyframe(cb_idx)?;
                    pc = self.emu.cpu().reg_read(RegisterARM64::PC)?;
                    if pc == RET_MAGIC_ADDR {
                        break;
                    }
                } else {
                    break;
                }
            }

            let bus_h = Arc::clone(&self.bus);
            let bps = breakpoints.clone();
            let wps = watchpoints.to_vec();
            let hit_code = Arc::clone(&hit_slot);
            let hit_mem = Arc::clone(&hit_slot);
            let found_code = Arc::clone(&hit_found);
            let found_mem = Arc::clone(&hit_found);
            let stop_next_code = Arc::clone(&stop_before_next_insn);
            let stop_next_mem = Arc::clone(&stop_before_next_insn);
            let stopped_by_hook = Arc::new(AtomicBool::new(false));
            let stopped_code = Arc::clone(&stopped_by_hook);
            let cur_pc_slot = Arc::new(AtomicU64::new(0));
            let cur_pc_code = Arc::clone(&cur_pc_slot);
            let cur_pc_mem = Arc::clone(&cur_pc_slot);

            let (code_hook, mem_hook) = {
                let uc = self.emu.try_uc_mut().ok_or_else(|| {
                    EmuError::Backend("时间旅行扫描仅支持 Unicorn 后端".to_string())
                })?;
                uc.get_data_mut().tt_stopped_at_pc = false;

                let code_hook = uc
                    .add_code_hook(0, u64::MAX, move |uc, addr, _size| {
                        if addr == RET_MAGIC_ADDR {
                            return;
                        }
                        if stop_at_first && stop_next_code.load(Ordering::Relaxed) {
                            stopped_code.store(true, Ordering::Relaxed);
                            uc.get_data_mut().tt_stopped_at_pc = true;
                            let _ = uc.emu_stop();
                            return;
                        }
                        let cur = bus_h.cur_insn();
                        if cur >= win_end {
                            stopped_code.store(true, Ordering::Relaxed);
                            uc.get_data_mut().tt_stopped_at_pc = true;
                            let _ = uc.emu_stop();
                            return;
                        }
                        cur_pc_code.store(addr, Ordering::Relaxed);
                        let skip_start_bp = stop_at_first && cur == win_start;
                        if !skip_start_bp && bps.contains(&addr) {
                            if !stop_at_first || !found_code.swap(true, Ordering::Relaxed) {
                                if let Ok(mut g) = hit_code.lock() {
                                    *g = Some(TimeTravelStop::Breakpoint { insn: cur, pc: addr });
                                }
                            }
                            if stop_at_first {
                                stopped_code.store(true, Ordering::Relaxed);
                                uc.get_data_mut().tt_stopped_at_pc = true;
                                let _ = uc.emu_stop();
                                return;
                            }
                        }
                        bus_h.fetch_add_insn();
                    })
                    .map_err(|e| EmuError::Backend(format!("挂载窗口扫描 code_hook 失败: {e:?}")))?;

                let mem_hook = if !wps.is_empty() {
                    let bus_m = Arc::clone(&self.bus);
                    match uc.add_mem_hook(
                        unicorn_engine::unicorn_const::HookType::MEM_READ
                            | unicorn_engine::unicorn_const::HookType::MEM_WRITE,
                        0,
                        u64::MAX,
                        move |_uc, mem_type, access_addr, size, value| {
                            let is_write = matches!(mem_type, MemType::WRITE);
                            // cur_insn 已在 code_hook 中 +1，因此当前正在执行的指令索引是 cur_insn - 1
                            let insn = bus_m.cur_insn().saturating_sub(1);
                            if insn >= win_end {
                                return true;
                            }
                            for wp in &wps {
                                if wp.matches(access_addr, size, is_write) {
                                    if stop_at_first && found_mem.swap(true, Ordering::Relaxed) {
                                        return true;
                                    }
                                    let pc = cur_pc_mem.load(Ordering::Relaxed);
                                    // 上报给 GDB 的地址必须落在 [wp.addr, wp.addr + wp.len) 内
                                    let reported_addr = access_addr.max(wp.addr);
                                    if let Ok(mut g) = hit_mem.lock() {
                                        *g = Some(TimeTravelStop::Watchpoint {
                                            insn,
                                            pc,
                                            addr: reported_addr,
                                            access_addr,
                                            size,
                                            kind: wp.kind,
                                            is_write,
                                            value,
                                        });
                                    }
                                    if stop_at_first {
                                        // 不在 mem_hook 中途强停（避免撕裂 stp/ldp/post-index），在下一条指令边界停下
                                        stop_next_mem.store(true, Ordering::Relaxed);
                                    }
                                    break;
                                }
                            }
                            true
                        },
                    ) {
                        Ok(h) => Some(h),
                        Err(e) => {
                            let _ = uc.remove_hook(code_hook);
                            return Err(EmuError::Backend(format!(
                                "挂载观察点 mem_hook 失败: {e:?}"
                            )));
                        }
                    }
                } else {
                    None
                };
                (code_hook, mem_hook)
            };

            // 保证扫描 code_hook 严格先于 HLE/JNI 跳板 Hook 执行
            if let Err(err) = self.emu.move_builtin_code_hooks_to_tail() {
                if let Some(uc) = self.emu.try_uc_mut() {
                    let _ = uc.remove_hook(code_hook);
                    if let Some(mh) = mem_hook {
                        let _ = uc.remove_hook(mh);
                    }
                }
                return Err(err);
            }

            let res = {
                let uc = self.emu.try_uc_mut().expect("Unicorn backend");
                let r = uc.emu_start(pc, RET_MAGIC_ADDR, 0, 0);
                let _ = uc.remove_hook(code_hook);
                if let Some(mh) = mem_hook {
                    let _ = uc.remove_hook(mh);
                }
                uc.get_data_mut().tt_stopped_at_pc = false;
                r
            };
            self.cur_insn = self.bus.cur_insn();
            if let Err(err) = res {
                if !stopped_by_hook.load(Ordering::Relaxed) {
                    return Err(EmuError::Backend(format!(
                        "时间旅行窗口扫描异常 @ insn={} ([{win_start}, {win_end})): {err:?}",
                        self.cur_insn
                    )));
                }
            }
            if stopped_by_hook.load(Ordering::Relaxed)
                || (stop_at_first && hit_found.load(Ordering::Relaxed))
                || self.cur_insn >= win_end
            {
                break;
            }
        }
        let res = hit_slot.lock().ok().and_then(|g| g.clone());
        Ok(res)
    }

    /// 便捷反向污点溯源：从当前指令向回查找最近一次写/读 `[addr, addr+len)` 的指令并自动跳转过去；
    /// 若未命中则保持原 `cur_insn` 不变（不静默跳回 0）。
    pub fn find_prev_mem_access(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> EmuResult<Option<WatchHit>> {
        let orig_insn = self.cur_insn;
        let wp = [Watchpoint { addr, len, kind }];
        let empty = HashSet::new();
        match self.continue_backward(&empty, &wp)? {
            TimeTravelStop::Watchpoint {
                insn,
                pc,
                access_addr,
                size,
                kind,
                is_write,
                value,
                ..
            } => Ok(Some(WatchHit {
                insn,
                pc,
                addr: access_addr,
                size,
                kind,
                is_write,
                value,
            })),
            _ => {
                self.seek_insn(orig_insn)?;
                Ok(None)
            }
        }
    }

    /// 便捷前向查找下一次写/读 `[addr, addr+len)` 的指令并自动跳转至该指令执行前（与 `find_prev_mem_access` 对称）；
    /// 若未命中则保持原 `cur_insn` 不变。
    pub fn find_next_mem_access(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> EmuResult<Option<WatchHit>> {
        let orig_insn = self.cur_insn;
        let end_insn = self.event_log.end_insn;
        if orig_insn >= end_insn {
            return Ok(None);
        }
        let scan_start = orig_insn.saturating_add(1);
        if scan_start >= end_insn {
            return Ok(None);
        }
        self.seek_insn(scan_start)?;
        let wp = [Watchpoint { addr, len, kind }];
        let empty = HashSet::new();
        // scan_window 在 stop_at_first=true 时不会跳过 win_start 的观察点，故严格覆盖 [orig_insn+1, end_insn)
        let hit = self.scan_window(scan_start, end_insn, &empty, &wp, true)?;
        match hit {
            Some(TimeTravelStop::Watchpoint {
                insn,
                pc,
                access_addr,
                size,
                kind,
                is_write,
                value,
                ..
            }) => {
                self.seek_insn(insn)?;
                Ok(Some(WatchHit {
                    insn,
                    pc,
                    addr: access_addr,
                    size,
                    kind,
                    is_write,
                    value,
                }))
            }
            _ => {
                self.seek_insn(orig_insn)?;
                Ok(None)
            }
        }
    }

    /// 确定性逐位自检：从关键帧 `0` 全程前向重放经过每个关键帧 `K_i`，逐寄存器（含 NEON `Q0..Q31`/`FPCR`/`FPSR`）校验与录制快照 100% bit-exact 一致
    pub fn verify_determinism(&mut self) -> EmuResult<usize> {
        let kf_count = self.tape.len();
        if kf_count <= 1 {
            return Ok(kf_count);
        }
        self.restore_keyframe(0)?;
        for kf_idx in 1..kf_count {
            let expected_state = self.get_keyframe_state(kf_idx)?;
            let target_insn = self.tape.keyframe_insn(kf_idx).unwrap_or(0);
            self.run_replay_until(target_insn)?;
            if self.cur_insn != target_insn {
                return Err(EmuError::Backend(format!(
                    "时间旅行确定性校验指令数漂移 @ keyframe #{kf_idx}: actual={} expected={target_insn}",
                    self.cur_insn
                )));
            }
            // 多调用边界关键帧的 PC/X0..X7 由宿主 `prepare_call` 注入，校验完前序指令数后直接切换进入下一调用
            if self
                .tape
                .keyframe_label(kf_idx)
                .is_some_and(|l| l.starts_with("call_boundary_"))
            {
                self.restore_keyframe(kf_idx)?;
                continue;
            }
            let actual = capture_generic_context(self.emu.cpu())?;
            let exp = &expected_state.regs;
            if actual.pc != exp.pc
                || actual.sp != exp.sp
                || actual.x != exp.x
                || (actual.pstate & 0xF000_0000) != (exp.pstate & 0xF000_0000)
                || actual.tpidr_el0 != exp.tpidr_el0
                || actual.q != exp.q
                || actual.fpcr != exp.fpcr
                || actual.fpsr != exp.fpsr
            {
                return Err(EmuError::Backend(format!(
                    "时间旅行确定性校验漂移 @ keyframe #{kf_idx} (insn={target_insn}): \
                     PC actual=0x{:x} expected=0x{:x}, SP actual=0x{:x} expected=0x{:x}",
                    actual.pc, exp.pc, actual.sp, exp.sp
                )));
            }
        }
        Ok(kf_count)
    }

    /// 格式化当前 PC 附近的模块+偏移与寄存器摘要（供 MCP / GDB monitor / Web UI 使用）
    pub fn describe_location(&self, pc: u64) -> String {
        for m in self.emu.linker().all_modules() {
            if pc >= m.base_addr && pc < m.base_addr.saturating_add(m.image_size) {
                return format!("{}+0x{:x}", m.name, pc - m.base_addr);
            }
        }
        format!("0x{pc:016x}")
    }

    /// 按固定顺序读取全部 31 个 GPR + SP + PC + NZCV + TPIDR_EL0（供 JS / MCP / Web UI 确定性输出）
    pub fn snapshot_regs_ordered(&self) -> EmuResult<Vec<(String, u64)>> {
        let g = capture_generic_context(self.emu.cpu())?;
        let mut out = Vec::with_capacity(35);
        for (i, &val) in g.x.iter().enumerate() {
            out.push((format!("x{i}"), val));
        }
        out.push(("sp".to_string(), g.sp));
        out.push(("pc".to_string(), g.pc));
        out.push(("nzcv".to_string(), g.pstate));
        out.push(("tpidr_el0".to_string(), g.tpidr_el0));
        Ok(out)
    }

    /// 读取当前所有 31 个 GPR + SP + PC + NZCV + TPIDR_EL0 有序映射
    pub fn snapshot_regs_map(&self) -> EmuResult<BTreeMap<String, u64>> {
        Ok(self.snapshot_regs_ordered()?.into_iter().collect())
    }
}
