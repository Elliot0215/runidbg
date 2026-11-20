use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ptr;
use std::rc::Rc;

use anyhow::{bail, Result};
use rquickjs::function::Args;
use rquickjs::{Ctx, Function, Object, Persistent, Value};
use unicorn_engine::unicorn_const::{HookType, MemType};
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::emulator::EmuState;
use crate::script::jni_bridge::current_js_ctx;

thread_local! {
    /// 当 Unicorn 原生回调（code/mem/attach/replace/syscall）重入 QuickJS 时，
    /// 指向当前活跃的 `Unicorn<'static, EmuState>`，避免二次 `RefCell::borrow_mut` panic。
    static ACTIVE_UC: Cell<*mut Unicorn<'static, EmuState>> = const { Cell::new(ptr::null_mut()) };
}

/// RAII 守卫：在 Unicorn 回调执行 JS 期间暴露当前活跃的 `Unicorn` 指针
pub(crate) struct ActiveUcGuard {
    prev: *mut Unicorn<'static, EmuState>,
}

impl ActiveUcGuard {
    pub fn enter(uc: &mut Unicorn<'_, EmuState>) -> Self {
        let ptr = (uc as *mut Unicorn<'_, EmuState>).cast::<Unicorn<'static, EmuState>>();
        let prev = ACTIVE_UC.with(|c| c.replace(ptr));
        Self { prev }
    }
}

impl Drop for ActiveUcGuard {
    fn drop(&mut self) {
        ACTIVE_UC.with(|c| c.set(self.prev));
    }
}

/// 若当前正处于 Unicorn 原生回调重入 JS 的作用域内，直接借用活跃 `Unicorn` 执行操作
pub(crate) fn with_active_uc<R>(f: impl FnOnce(&mut Unicorn<'static, EmuState>) -> R) -> Option<R> {
    let ptr = ACTIVE_UC.with(Cell::get);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `ActiveUcGuard` 保证 `ptr` 在回调栈帧内唯一且有效
        Some(f(unsafe { &mut *ptr }))
    }
}

/// 解析 ARM64 寄存器名（大小写不敏感）
pub(crate) fn parse_reg_name(name: &str) -> Option<RegisterARM64> {
    let lower = name.trim().to_ascii_lowercase();
    let reg = match lower.as_str() {
        "x0" => RegisterARM64::X0,
        "x1" => RegisterARM64::X1,
        "x2" => RegisterARM64::X2,
        "x3" => RegisterARM64::X3,
        "x4" => RegisterARM64::X4,
        "x5" => RegisterARM64::X5,
        "x6" => RegisterARM64::X6,
        "x7" => RegisterARM64::X7,
        "x8" => RegisterARM64::X8,
        "x9" => RegisterARM64::X9,
        "x10" => RegisterARM64::X10,
        "x11" => RegisterARM64::X11,
        "x12" => RegisterARM64::X12,
        "x13" => RegisterARM64::X13,
        "x14" => RegisterARM64::X14,
        "x15" => RegisterARM64::X15,
        "x16" => RegisterARM64::X16,
        "x17" => RegisterARM64::X17,
        "x18" => RegisterARM64::X18,
        "x19" => RegisterARM64::X19,
        "x20" => RegisterARM64::X20,
        "x21" => RegisterARM64::X21,
        "x22" => RegisterARM64::X22,
        "x23" => RegisterARM64::X23,
        "x24" => RegisterARM64::X24,
        "x25" => RegisterARM64::X25,
        "x26" => RegisterARM64::X26,
        "x27" => RegisterARM64::X27,
        "x28" => RegisterARM64::X28,
        "x29" | "fp" => RegisterARM64::X29,
        "x30" | "lr" => RegisterARM64::X30,
        "w0" => RegisterARM64::W0,
        "w1" => RegisterARM64::W1,
        "w2" => RegisterARM64::W2,
        "w3" => RegisterARM64::W3,
        "w4" => RegisterARM64::W4,
        "w5" => RegisterARM64::W5,
        "w6" => RegisterARM64::W6,
        "w7" => RegisterARM64::W7,
        "w8" => RegisterARM64::W8,
        "w9" => RegisterARM64::W9,
        "w10" => RegisterARM64::W10,
        "w11" => RegisterARM64::W11,
        "w12" => RegisterARM64::W12,
        "w13" => RegisterARM64::W13,
        "w14" => RegisterARM64::W14,
        "w15" => RegisterARM64::W15,
        "w16" => RegisterARM64::W16,
        "w17" => RegisterARM64::W17,
        "w18" => RegisterARM64::W18,
        "w19" => RegisterARM64::W19,
        "w20" => RegisterARM64::W20,
        "w21" => RegisterARM64::W21,
        "w22" => RegisterARM64::W22,
        "w23" => RegisterARM64::W23,
        "w24" => RegisterARM64::W24,
        "w25" => RegisterARM64::W25,
        "w26" => RegisterARM64::W26,
        "w27" => RegisterARM64::W27,
        "w28" => RegisterARM64::W28,
        "w29" => RegisterARM64::W29,
        "w30" => RegisterARM64::W30,
        "sp" => RegisterARM64::SP,
        "pc" => RegisterARM64::PC,
        "nzcv" => RegisterARM64::NZCV,
        "tpidr_el0" => RegisterARM64::TPIDR_EL0,
        _ => return None,
    };
    Some(reg)
}

/// 导出常用通用寄存器快照
pub(crate) fn dump_regs(uc: &Unicorn<'_, EmuState>) -> Vec<(&'static str, u64)> {
    const REGS: &[(&str, RegisterARM64)] = &[
        ("x0", RegisterARM64::X0),
        ("x1", RegisterARM64::X1),
        ("x2", RegisterARM64::X2),
        ("x3", RegisterARM64::X3),
        ("x4", RegisterARM64::X4),
        ("x5", RegisterARM64::X5),
        ("x6", RegisterARM64::X6),
        ("x7", RegisterARM64::X7),
        ("x8", RegisterARM64::X8),
        ("x9", RegisterARM64::X9),
        ("x10", RegisterARM64::X10),
        ("x11", RegisterARM64::X11),
        ("x12", RegisterARM64::X12),
        ("x13", RegisterARM64::X13),
        ("x14", RegisterARM64::X14),
        ("x15", RegisterARM64::X15),
        ("x16", RegisterARM64::X16),
        ("x17", RegisterARM64::X17),
        ("x18", RegisterARM64::X18),
        ("x19", RegisterARM64::X19),
        ("x20", RegisterARM64::X20),
        ("x21", RegisterARM64::X21),
        ("x22", RegisterARM64::X22),
        ("x23", RegisterARM64::X23),
        ("x24", RegisterARM64::X24),
        ("x25", RegisterARM64::X25),
        ("x26", RegisterARM64::X26),
        ("x27", RegisterARM64::X27),
        ("x28", RegisterARM64::X28),
        ("x29", RegisterARM64::X29),
        ("x30", RegisterARM64::X30),
        ("sp", RegisterARM64::SP),
        ("pc", RegisterARM64::PC),
        ("nzcv", RegisterARM64::NZCV),
    ];
    REGS.iter()
        .map(|&(name, reg)| (name, uc.reg_read(reg).unwrap_or(0)))
        .collect()
}

/// 在当前 JS 上下文中构造轻量 `CpuContext` 对象（委托给 `bootstrap.js` 的 `__makeCpuCtx`）
fn make_cpu_ctx<'js>(ctx: &Ctx<'js>, emu_id: usize) -> rquickjs::Result<Value<'js>> {
    let factory: Function<'js> = ctx.globals().get("__makeCpuCtx")?;
    factory.call((emu_id,))
}

/// 将 JS 返回值转换为 u64（支持 number / bigint / boolean）
fn js_val_to_u64_opt(val: &Value<'_>) -> Option<u64> {
    if val.is_undefined() || val.is_null() {
        return None;
    }
    if let Some(i) = val.as_int() {
        return Some(i as i64 as u64);
    }
    if let Some(n) = val.as_number() {
        return Some(n as i64 as u64);
    }
    if let Some(bi) = val.as_big_int() {
        if let Ok(v) = bi.clone().to_i64() {
            return Some(v as u64);
        }
    }
    if let Some(b) = val.as_bool() {
        return Some(u64::from(b));
    }
    None
}

/// `emu.hook.attach` 的单次调用栈帧（支持递归调用）
struct AttachFrame {
    lr: u64,
    sp: u64,
    this_obj: Persistent<Object<'static>>,
}

struct AttachState {
    on_enter: Option<Persistent<Function<'static>>>,
    on_leave: Option<Persistent<Function<'static>>>,
    frames: Vec<AttachFrame>,
    lr_hooks: HashMap<u64, UcHookId>,
}

struct CodeHookRecord {
    uc_id: UcHookId,
    callback: Rc<RefCell<Option<Persistent<Function<'static>>>>>,
}

struct MemHookRecord {
    uc_id: UcHookId,
    callback: Rc<RefCell<Option<Persistent<Function<'static>>>>>,
}

struct ReplaceHookRecord {
    uc_id: UcHookId,
    addr: u64,
    orig_insn: [u8; 4],
    callback: Rc<RefCell<Option<Persistent<Function<'static>>>>>,
}

struct AttachHookRecord {
    entry_uc_id: UcHookId,
    addr: u64,
    state: Rc<RefCell<AttachState>>,
}

/// 按页粒度刷新 Unicorn JIT 翻译块缓存，确保动态挂/卸 Hook 与热补丁立即生效
fn flush_tb_page(uc: &mut Unicorn<'_, EmuState>, begin: u64, end: u64) {
    let page_start = begin & !0xFFF;
    let page_end = (end.saturating_add(4).saturating_add(0xFFF)) & !0xFFF;
    let _ = uc.ctl_remove_cache(page_start, page_end.max(page_start.saturating_add(0x1000)));
}

/// 通配 Syscall 拦截键（拦截全部系统调用）
pub(crate) const SYSCALL_WILDCARD: u64 = u64::MAX;

type SyscallHookMap = Rc<RefCell<HashMap<u64, (usize, Persistent<Function<'static>>)>>>;

/// 单个模拟器实例对应的原生 JS Hook 管理表
pub(crate) struct JsNativeHookTable {
    next_id: usize,
    code_hooks: HashMap<usize, CodeHookRecord>,
    mem_hooks: HashMap<usize, MemHookRecord>,
    replace_hooks: HashMap<usize, ReplaceHookRecord>,
    attach_hooks: HashMap<usize, AttachHookRecord>,
    syscall_hooks: SyscallHookMap,
    syscall_id_to_nr: HashMap<usize, u64>,
    syscall_wired: bool,
}

impl Default for JsNativeHookTable {
    fn default() -> Self {
        Self {
            next_id: 1,
            code_hooks: HashMap::new(),
            mem_hooks: HashMap::new(),
            replace_hooks: HashMap::new(),
            attach_hooks: HashMap::new(),
            syscall_hooks: Rc::new(RefCell::new(HashMap::new())),
            syscall_id_to_nr: HashMap::new(),
            syscall_wired: false,
        }
    }
}

impl JsNativeHookTable {
    fn alloc_id(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// 注册单地址或区间指令断点（`emu.hook.code`）
    pub fn add_code_hook(
        &mut self,
        emu_id: usize,
        uc: &mut Unicorn<'static, EmuState>,
        begin: u64,
        end: u64,
        max_hits: Option<u64>,
        callback: Persistent<Function<'static>>,
    ) -> Result<usize> {
        let cb_cell = Rc::new(RefCell::new(Some(callback)));
        let cb_ref = Rc::clone(&cb_cell);
        let hits = Rc::new(Cell::new(0u64));
        let hits_ref = Rc::clone(&hits);

        let uc_id = uc
            .add_code_hook(begin, end, move |uc, addr, size| {
                if let Some(limit) = max_hits {
                    let cur = hits_ref.get();
                    if cur >= limit {
                        return;
                    }
                    hits_ref.set(cur + 1);
                }
                let Some(raw_ctx) = current_js_ctx() else {
                    return;
                };
                let pfn = match cb_ref.borrow().clone() {
                    Some(f) => f,
                    None => return,
                };
                let _uc_guard = ActiveUcGuard::enter(uc);
                // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 指向当前线程存活的 QuickJS 上下文
                let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
                if let (Ok(func), Ok(cpu_ctx)) = (pfn.restore(&js_ctx), make_cpu_ctx(&js_ctx, emu_id))
                {
                    if let Err(err) = func.call::<_, Value<'_>>((cpu_ctx, addr as f64, size)) {
                        eprintln!("[JS CODE HOOK ERROR] @0x{addr:x}: {err}");
                    }
                }
            })
            .map_err(|e| anyhow::anyhow!("add_code_hook 失败: {e:?}"))?;
        let _ = uc.ctl_remove_cache(begin, end.saturating_add(4));

        let id = self.alloc_id();
        self.code_hooks.insert(
            id,
            CodeHookRecord {
                uc_id,
                callback: cb_cell,
            },
        );
        Ok(id)
    }

    /// 注册内存读写 Watchpoint（`emu.hook.mem`）
    #[allow(clippy::too_many_arguments)]
    pub fn add_mem_hook(
        &mut self,
        emu_id: usize,
        uc: &mut Unicorn<'static, EmuState>,
        begin: u64,
        end: u64,
        read: bool,
        write: bool,
        callback: Persistent<Function<'static>>,
    ) -> Result<usize> {
        let hook_type = match (read, write) {
            (true, true) => HookType::MEM_READ | HookType::MEM_WRITE,
            (true, false) => HookType::MEM_READ,
            (false, true) => HookType::MEM_WRITE,
            (false, false) => bail!("mem hook 至少需要启用 read 或 write"),
        };

        let cb_cell = Rc::new(RefCell::new(Some(callback)));
        let cb_ref = Rc::clone(&cb_cell);

        let uc_id = uc
            .add_mem_hook(hook_type, begin, end, move |uc, mem_type, addr, size, value| {
                let Some(raw_ctx) = current_js_ctx() else {
                    return true;
                };
                let pfn = match cb_ref.borrow().clone() {
                    Some(f) => f,
                    None => return true,
                };
                let access = match mem_type {
                    MemType::READ => "read",
                    MemType::WRITE => "write",
                    _ => "other",
                };
                let _uc_guard = ActiveUcGuard::enter(uc);
                // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 指向当前线程存活的 QuickJS 上下文
                let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
                if let (Ok(func), Ok(cpu_ctx)) = (pfn.restore(&js_ctx), make_cpu_ctx(&js_ctx, emu_id))
                {
                    if let Err(err) = func.call::<_, Value<'_>>((
                        cpu_ctx,
                        access,
                        addr as f64,
                        size,
                        value as f64,
                    )) {
                        eprintln!("[JS MEM HOOK ERROR] {access} @0x{addr:x}: {err}");
                    }
                }
                true
            })
            .map_err(|e| anyhow::anyhow!("add_mem_hook 失败: {e:?}"))?;

        let id = self.alloc_id();
        self.mem_hooks.insert(
            id,
            MemHookRecord {
                uc_id,
                callback: cb_cell,
            },
        );
        Ok(id)
    }

    /// 注册函数替换 Hook（`emu.hook.replace`）：
    /// 在目标入口写入 `RET`（卸载时恢复原指令），并在入口前执行 JS 回调写回 `X0`，
    /// 对内部调用与顶层 `mod.call()` 均 100% 跳过原函数体。
    pub fn add_replace_hook(
        &mut self,
        emu_id: usize,
        uc: &mut Unicorn<'static, EmuState>,
        addr: u64,
        callback: Persistent<Function<'static>>,
    ) -> Result<usize> {
        let mut orig_insn = [0u8; 4];
        uc.mem_read(addr, &mut orig_insn)
            .map_err(|e| anyhow::anyhow!("replace 读取原指令失败 @0x{addr:x}: {e:?}"))?;
        let ret_insn = 0xd65f_03c0_u32.to_le_bytes();
        uc.mem_write(addr, &ret_insn)
            .map_err(|e| anyhow::anyhow!("replace 写入 RET 失败 @0x{addr:x}: {e:?}"))?;

        let cb_cell = Rc::new(RefCell::new(Some(callback)));
        let cb_ref = Rc::clone(&cb_cell);

        let uc_id = uc
            .add_code_hook(addr, addr, move |uc, pc, _size| {
                let Some(raw_ctx) = current_js_ctx() else {
                    return;
                };
                let pfn = match cb_ref.borrow().clone() {
                    Some(f) => f,
                    None => return,
                };
                let _uc_guard = ActiveUcGuard::enter(uc);
                // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 指向当前线程存活的 QuickJS 上下文
                let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
                if let (Ok(func), Ok(cpu_ctx)) = (pfn.restore(&js_ctx), make_cpu_ctx(&js_ctx, emu_id))
                {
                    match func.call::<_, Value<'_>>((cpu_ctx,)) {
                        Ok(ret) => {
                            if let Some(v) = js_val_to_u64_opt(&ret) {
                                let _ = uc.reg_write(RegisterARM64::X0, v);
                            }
                        }
                        Err(err) => {
                            eprintln!("[JS REPLACE HOOK ERROR] @0x{pc:x}: {err}");
                        }
                    }
                }
            })
            .map_err(|e| anyhow::anyhow!("add_replace_hook 失败: {e:?}"))?;
        flush_tb_page(uc, addr, addr);

        let id = self.alloc_id();
        self.replace_hooks.insert(
            id,
            ReplaceHookRecord {
                uc_id,
                addr,
                orig_insn,
                callback: cb_cell,
            },
        );
        Ok(id)
    }

    /// 注册 Frida Interceptor 风格函数拦截 Hook（`emu.hook.attach`）
    pub fn add_attach_hook(
        &mut self,
        emu_id: usize,
        uc: &mut Unicorn<'static, EmuState>,
        addr: u64,
        on_enter: Option<Persistent<Function<'static>>>,
        on_leave: Option<Persistent<Function<'static>>>,
    ) -> Result<usize> {
        let state = Rc::new(RefCell::new(AttachState {
            on_enter,
            on_leave,
            frames: Vec::new(),
            lr_hooks: HashMap::new(),
        }));
        let state_ref = Rc::clone(&state);

        let entry_uc_id = uc
            .add_code_hook(addr, addr, move |uc, pc, _size| {
                let Some(raw_ctx) = current_js_ctx() else {
                    return;
                };
                let (enter_fn, has_leave) = {
                    let st = state_ref.borrow();
                    (st.on_enter.clone(), st.on_leave.is_some())
                };
                let lr = uc.reg_read(RegisterARM64::LR).unwrap_or(0);
                let sp = uc.reg_read(RegisterARM64::SP).unwrap_or(0);

                // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 指向当前线程存活的 QuickJS 上下文
                let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
                let this_obj = match Object::new(js_ctx.clone()) {
                    Ok(o) => o,
                    Err(_) => return,
                };

                if let Some(pfn) = enter_fn {
                    let _uc_guard = ActiveUcGuard::enter(uc);
                    if let (Ok(func), Ok(cpu_ctx)) =
                        (pfn.restore(&js_ctx), make_cpu_ctx(&js_ctx, emu_id))
                    {
                        let mut call_args = Args::new(js_ctx.clone(), 1);
                        let _ = call_args.this(this_obj.clone());
                        let _ = call_args.push_arg(cpu_ctx);
                        if let Err(err) = func.call_arg::<Value<'_>>(call_args) {
                            eprintln!("[JS ATTACH onEnter ERROR] @0x{pc:x}: {err}");
                        }
                    }
                }

                if has_leave && lr != 0 {
                    let persistent_this = Persistent::save(&js_ctx, this_obj);
                    let need_lr_hook = {
                        let mut st = state_ref.borrow_mut();
                        st.frames.push(AttachFrame {
                            lr,
                            sp,
                            this_obj: persistent_this,
                        });
                        lr != crate::cpu::RET_MAGIC_ADDR && !st.lr_hooks.contains_key(&lr)
                    };

                    if need_lr_hook {
                        let leave_state = Rc::clone(&state_ref);
                        if let Ok(lr_uc_id) = uc.add_code_hook(lr, lr, move |uc, ret_pc, _sz| {
                            let cur_sp = uc.reg_read(RegisterARM64::SP).unwrap_or(0);
                            let popped = {
                                let mut st = leave_state.borrow_mut();
                                // 从栈顶向栈底查找匹配的 (lr, sp) 帧，正确支持递归调用
                                if let Some(pos) = st
                                    .frames
                                    .iter()
                                    .rposition(|f| f.lr == ret_pc && cur_sp >= f.sp)
                                {
                                    let frame = st.frames.remove(pos);
                                    let leave_fn = st.on_leave.clone();
                                    let still_needed = st.frames.iter().any(|f| f.lr == ret_pc);
                                    let remove_hook = if !still_needed {
                                        st.lr_hooks.remove(&ret_pc)
                                    } else {
                                        None
                                    };
                                    Some((frame, leave_fn, remove_hook))
                                } else {
                                    None
                                }
                            };

                            if let Some((frame, leave_fn, remove_hook)) = popped {
                                if let Some(hid) = remove_hook {
                                    let _ = uc.remove_hook(hid);
                                }
                                if let (Some(raw_ctx), Some(pfn)) = (current_js_ctx(), leave_fn) {
                                    let _uc_guard = ActiveUcGuard::enter(uc);
                                    // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 有效
                                    let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
                                    if let (Ok(func), Ok(this_o), Ok(cpu_ctx)) = (
                                        pfn.restore(&js_ctx),
                                        frame.this_obj.restore(&js_ctx),
                                        make_cpu_ctx(&js_ctx, emu_id),
                                    ) {
                                        let mut call_args = Args::new(js_ctx.clone(), 1);
                                        let _ = call_args.this(this_o);
                                        let _ = call_args.push_arg(cpu_ctx);
                                        if let Err(err) = func.call_arg::<Value<'_>>(call_args) {
                                            eprintln!(
                                                "[JS ATTACH onLeave ERROR] @0x{ret_pc:x}: {err}"
                                            );
                                        }
                                    }
                                }
                            }
                        }) {
                            state_ref.borrow_mut().lr_hooks.insert(lr, lr_uc_id);
                        }
                    }
                }
            })
            .map_err(|e| anyhow::anyhow!("add_attach_hook 失败: {e:?}"))?;
        flush_tb_page(uc, addr, addr);

        let id = self.alloc_id();
        self.attach_hooks.insert(
            id,
            AttachHookRecord {
                entry_uc_id,
                addr,
                state,
            },
        );
        Ok(id)
    }

    /// 触发所有返回地址为 `RET_MAGIC_ADDR` 的顶层 `attach` `onLeave` 回调
    /// （因为 `emu_start(..., RET_MAGIC_ADDR)` 会在执行该地址前停机），并同步最新 `X0`
    pub fn flush_ret_magic_leaves(
        &self,
        emu_id: usize,
        uc: &mut Unicorn<'static, EmuState>,
    ) {
        let Some(raw_ctx) = current_js_ctx() else {
            return;
        };
        let mut pending = Vec::new();
        for rec in self.attach_hooks.values() {
            let mut st = rec.state.borrow_mut();
            let mut idx = st.frames.len();
            while idx > 0 {
                idx -= 1;
                if st.frames[idx].lr == crate::cpu::RET_MAGIC_ADDR {
                    let frame = st.frames.remove(idx);
                    if let Some(leave_fn) = st.on_leave.clone() {
                        pending.push((frame, leave_fn));
                    }
                }
            }
        }
        if pending.is_empty() {
            return;
        }
        let _uc_guard = ActiveUcGuard::enter(uc);
        // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 有效
        let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
        for (frame, pfn) in pending {
            if let (Ok(func), Ok(this_o), Ok(cpu_ctx)) = (
                pfn.restore(&js_ctx),
                frame.this_obj.restore(&js_ctx),
                make_cpu_ctx(&js_ctx, emu_id),
            ) {
                let mut call_args = Args::new(js_ctx.clone(), 1);
                let _ = call_args.this(this_o);
                let _ = call_args.push_arg(cpu_ctx);
                if let Err(err) = func.call_arg::<Value<'_>>(call_args) {
                    eprintln!("[JS ATTACH onLeave ERROR] @RET_MAGIC: {err}");
                }
            }
        }
    }

    /// 注册自定义 Syscall 拦截器（`emu.hook.syscall`）
    pub fn add_syscall_hook(
        &mut self,
        emu_id: usize,
        uc: &mut Unicorn<'static, EmuState>,
        nr: u64,
        callback: Persistent<Function<'static>>,
    ) -> usize {
        if !self.syscall_wired {
            let map_ref = Rc::clone(&self.syscall_hooks);
            uc.get_data_mut().syscall_interceptor = Some(Box::new(move |uc, sys_nr, _args| {
                let pfn = {
                    let map = map_ref.borrow();
                    map.get(&sys_nr)
                        .or_else(|| map.get(&SYSCALL_WILDCARD))
                        .map(|(_, f)| f.clone())
                }?;
                let raw_ctx = current_js_ctx()?;
                let _uc_guard = ActiveUcGuard::enter(uc);
                // SAFETY: `JsCtxGuard` 保证 `raw_ctx` 有效
                let js_ctx = unsafe { Ctx::from_raw(raw_ctx) };
                let func = pfn.restore(&js_ctx).ok()?;
                let cpu_ctx = make_cpu_ctx(&js_ctx, emu_id).ok()?;
                match func.call::<_, Value<'_>>((cpu_ctx, sys_nr as f64)) {
                    Ok(ret) => js_val_to_u64_opt(&ret),
                    Err(err) => {
                        eprintln!("[JS SYSCALL HOOK ERROR] nr={sys_nr}: {err}");
                        None
                    }
                }
            }));
            self.syscall_wired = true;
        }

        let id = self.alloc_id();
        self.syscall_hooks.borrow_mut().insert(nr, (id, callback));
        self.syscall_id_to_nr.insert(id, nr);
        id
    }

    /// 按 hook_id 卸载指定 Hook
    pub fn detach(&mut self, hook_id: usize, uc: &mut Unicorn<'static, EmuState>) -> bool {
        if let Some(rec) = self.code_hooks.remove(&hook_id) {
            let _ = uc.remove_hook(rec.uc_id);
            *rec.callback.borrow_mut() = None;
            return true;
        }
        if let Some(rec) = self.mem_hooks.remove(&hook_id) {
            let _ = uc.remove_hook(rec.uc_id);
            *rec.callback.borrow_mut() = None;
            return true;
        }
        if let Some(rec) = self.replace_hooks.remove(&hook_id) {
            let _ = uc.remove_hook(rec.uc_id);
            let _ = uc.mem_write(rec.addr, &rec.orig_insn);
            flush_tb_page(uc, rec.addr, rec.addr);
            *rec.callback.borrow_mut() = None;
            return true;
        }
        if let Some(rec) = self.attach_hooks.remove(&hook_id) {
            let _ = uc.remove_hook(rec.entry_uc_id);
            flush_tb_page(uc, rec.addr, rec.addr);
            let mut st = rec.state.borrow_mut();
            for (lr, lr_hid) in st.lr_hooks.drain() {
                let _ = uc.remove_hook(lr_hid);
                flush_tb_page(uc, lr, lr);
            }
            st.frames.clear();
            st.on_enter = None;
            st.on_leave = None;
            return true;
        }
        if let Some(nr) = self.syscall_id_to_nr.remove(&hook_id) {
            let mut map = self.syscall_hooks.borrow_mut();
            if map.get(&nr).is_some_and(|(id, _)| *id == hook_id) {
                map.remove(&nr);
            }
            return true;
        }
        false
    }

    /// 清理所有 Unicorn Hook 与 QuickJS `Persistent` 句柄（必须在 `Runtime` Drop 前调用）
    pub fn clear_all(&mut self, uc: &mut Unicorn<'static, EmuState>) {
        for (_, rec) in self.code_hooks.drain() {
            let _ = uc.remove_hook(rec.uc_id);
            *rec.callback.borrow_mut() = None;
        }
        for (_, rec) in self.mem_hooks.drain() {
            let _ = uc.remove_hook(rec.uc_id);
            *rec.callback.borrow_mut() = None;
        }
        for (_, rec) in self.replace_hooks.drain() {
            let _ = uc.remove_hook(rec.uc_id);
            let _ = uc.mem_write(rec.addr, &rec.orig_insn);
            *rec.callback.borrow_mut() = None;
        }
        for (_, rec) in self.attach_hooks.drain() {
            let _ = uc.remove_hook(rec.entry_uc_id);
            let mut st = rec.state.borrow_mut();
            for (_, lr_hid) in st.lr_hooks.drain() {
                let _ = uc.remove_hook(lr_hid);
            }
            st.frames.clear();
            st.on_enter = None;
            st.on_leave = None;
        }
        self.syscall_hooks.borrow_mut().clear();
        self.syscall_id_to_nr.clear();
        uc.get_data_mut().syscall_interceptor = None;
    }
}

/// 解析通配符十六进制特征码（如 `"fd 7b ?? a9 ?? ?? 00 94"`）
pub(crate) fn parse_hex_pattern(pattern: &str) -> Result<Vec<Option<u8>>> {
    let mut out = Vec::new();
    for tok in pattern.split_whitespace() {
        if tok == "?" || tok == "??" {
            out.push(None);
        } else {
            let byte = u8::from_str_radix(tok, 16)
                .map_err(|_| anyhow::anyhow!("无效的十六进制特征字节: {tok}"))?;
            out.push(Some(byte));
        }
    }
    if out.is_empty() {
        bail!("特征码不能为空");
    }
    Ok(out)
}

/// 在指定 Guest 内存区间内搜索通配符特征码，返回所有命中地址
pub(crate) fn scan_memory(
    uc: &Unicorn<'_, EmuState>,
    start: u64,
    len: u64,
    pattern: &[Option<u8>],
) -> Vec<u64> {
    if len == 0 || pattern.is_empty() || (pattern.len() as u64) > len {
        return Vec::new();
    }
    let end = start.saturating_add(len);
    let mut hits = Vec::new();

    // 优先尝试按已映射区域分段扫描，避免跨未映射洞导致整块 mem_read 失败
    let regions = uc.mem_regions().unwrap_or_default();
    for r in regions {
        let r_begin = r.begin.max(start);
        let r_end = r.end.saturating_add(1).min(end);
        if r_end <= r_begin || (r_end - r_begin) < pattern.len() as u64 {
            continue;
        }
        let seg_len = (r_end - r_begin) as usize;
        let mut buf = vec![0u8; seg_len];
        if uc.mem_read(r_begin, &mut buf).is_err() {
            continue;
        }
        for (i, window) in buf.windows(pattern.len()).enumerate() {
            if window
                .iter()
                .zip(pattern.iter())
                .all(|(b, pat)| pat.is_none_or(|p| *b == p))
            {
                hits.push(r_begin + i as u64);
            }
        }
    }
    hits
}

/// 生成 `count` 条 ARM64 `NOP` (`0xd503201f`) 机器码
pub(crate) fn encode_arm64_nop(count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count * 4);
    let nop = 0xd503_201f_u32.to_le_bytes();
    for _ in 0..count {
        out.extend_from_slice(&nop);
    }
    out
}

/// 生成 ARM64 `RET` 或 `MOV X0, #imm; RET` 机器码
pub(crate) fn encode_arm64_ret(retval: Option<i64>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(v) = retval {
        let u = v as u64;
        if (0..=0xFFFF).contains(&v) {
            // MOVZ X0, #u16 (0xd2800000 | (imm16 << 5))
            let insn = 0xd280_0000_u32 | ((u as u32) << 5);
            out.extend_from_slice(&insn.to_le_bytes());
        } else if (-0x1_0000..0).contains(&v) {
            // MOVN X0, #(!v & 0xFFFF) (0x92800000 | (imm16 << 5))
            let inv = (!u & 0xFFFF) as u32;
            let insn = 0x9280_0000_u32 | (inv << 5);
            out.extend_from_slice(&insn.to_le_bytes());
        } else {
            // 通用 64 位立即数：MOVZ X0, lo16 + 最多 3 条 MOVK X0, chunk, LSL #shift
            let lo = (u & 0xFFFF) as u32;
            out.extend_from_slice(&(0xd280_0000_u32 | (lo << 5)).to_le_bytes());
            for shift_idx in 1..4u32 {
                let chunk = ((u >> (shift_idx * 16)) & 0xFFFF) as u32;
                if chunk != 0 {
                    // MOVK X0, #chunk, LSL #(shift_idx * 16)
                    let insn = 0xf280_0000_u32 | (shift_idx << 21) | (chunk << 5);
                    out.extend_from_slice(&insn.to_le_bytes());
                }
            }
        }
    }
    // RET (0xd65f03c0)
    out.extend_from_slice(&0xd65f_03c0_u32.to_le_bytes());
    out
}
