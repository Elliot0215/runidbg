mod bridge;
mod hooks;
mod jni_bridge;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "rpc")]
pub mod rpc;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{Context as AnyhowContext, Result};
use rquickjs::{Context, Ctx, Error as JsError, Function, Object, Persistent, Runtime, Value};

use crate::loader::LoadedModule;
use crate::snapshot::EmuSnapshot;
use crate::AndroidEmulator;

use self::bridge::register_native_bridge;
use self::hooks::JsNativeHookTable;
use self::jni_bridge::JsHookTable;

/// 内置 TypeScript 声明文件内容（供 `runidbg-cli init-types` 导出）
pub const RUNIDBG_DTS: &str = include_str!("runidbg.d.ts");
const BOOTSTRAP_JS: &str = include_str!("bootstrap.js");

pub(super) struct EmuEntry {
    pub(super) emu: AndroidEmulator,
    pub(super) hooks: Rc<RefCell<JsHookTable>>,
    pub(super) native_hooks: Rc<RefCell<JsNativeHookTable>>,
    pub(super) modules: Rc<RefCell<Vec<LoadedModule>>>,
    pub(super) snapshots: Vec<EmuSnapshot>,
}

#[derive(Default)]
pub(super) struct ScriptHost {
    pub(super) emus: Vec<EmuEntry>,
    pub(super) script_dir_stack: Vec<PathBuf>,
    pub(super) module_cache: HashMap<PathBuf, Persistent<Value<'static>>>,
}

pub(super) type SharedHost = Rc<RefCell<ScriptHost>>;

pub(super) struct LogSink {
    pub(super) capture: bool,
    pub(super) buf: RefCell<Vec<String>>,
}

pub(super) type SharedLogSink = Rc<LogSink>;

/// 持久化 QuickJS + Unicorn 仿真会话（供 `JsRunner`、RPC Server 与 MCP Server 复用）
pub struct JsSession {
    host: SharedHost,
    log_sink: SharedLogSink,
    ctx: Context,
    _rt: Runtime,
}

impl JsSession {
    /// 创建持久化 QuickJS 会话；`capture_logs = true` 时将 `console.log` 捕获到内存缓冲而非 `stdout`（MCP stdio 必备）
    pub fn new(cli_args: &[String], base_dir: &Path, capture_logs: bool) -> Result<Self> {
        let rt = Runtime::new().context("初始化 QuickJS Runtime 失败")?;
        let ctx = Context::full(&rt).context("初始化 QuickJS Context 失败")?;
        let host: SharedHost = Rc::new(RefCell::new(ScriptHost {
            emus: Vec::new(),
            script_dir_stack: vec![base_dir.to_path_buf()],
            module_cache: HashMap::new(),
        }));
        let log_sink: SharedLogSink = Rc::new(LogSink {
            capture: capture_logs,
            buf: RefCell::new(Vec::new()),
        });

        ctx.with(|ctx| -> Result<()> {
            register_native_bridge(&ctx, &host, &log_sink, cli_args)
                .map_err(|e| format_js_error(&ctx, e))?;
            ctx.eval::<(), _>(BOOTSTRAP_JS)
                .map_err(|e| format_js_error(&ctx, e))?;
            Ok(())
        })?;

        Ok(Self {
            host,
            log_sink,
            ctx,
            _rt: rt,
        })
    }

    /// 在当前会话中执行一段 JavaScript 源码
    pub fn eval_source(&self, source: &str) -> Result<()> {
        self.ctx.with(|ctx| -> Result<()> {
            ctx.eval::<(), _>(source)
                .map_err(|e| format_js_error(&ctx, e))?;
            Ok(())
        })
    }

    /// 读取并执行 `.js` 脚本文件（自动将其所在目录压入 `require()` 解析栈）
    pub fn eval_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let src = fs::read_to_string(path)
            .with_context(|| format!("读取脚本失败: {}", path.display()))?;
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        self.host.borrow_mut().script_dir_stack.push(dir);
        let res = self.eval_source(&src);
        self.host.borrow_mut().script_dir_stack.pop();
        res
    }

    /// 在当前会话中求值一段 JS 表达式/脚本，返回 JSON 序列化字符串（自动解析 Promise）
    pub fn eval_json_string(&self, code: &str) -> Result<String> {
        let raw = self.ctx.with(|ctx| -> Result<String> {
            let f: Function<'_> = ctx
                .globals()
                .get("__evalToJson")
                .map_err(|e| format_js_error(&ctx, e))?;
            f.call::<_, String>((code,))
                .map_err(|e| format_js_error(&ctx, e))
        })?;
        self.resolve_if_pending(raw)
    }

    /// 列出当前会话 `rpc.exports` 导出的全部方法名（JSON 数组字符串）
    pub fn list_rpc_exports_json(&self) -> Result<String> {
        self.ctx.with(|ctx| -> Result<String> {
            let f: Function<'_> = ctx
                .globals()
                .get("__rpcList")
                .map_err(|e| format_js_error(&ctx, e))?;
            f.call::<_, String>(())
                .map_err(|e| format_js_error(&ctx, e))
        })
    }

    /// 调用 `rpc.exports[method](...params)`，入参与返回值均以 JSON 字符串传输（自动解析 Promise）
    pub fn call_rpc_json(&self, method: &str, params_json: &str) -> Result<String> {
        let raw = self.ctx.with(|ctx| -> Result<String> {
            let f: Function<'_> = ctx
                .globals()
                .get("__rpcCall")
                .map_err(|e| format_js_error(&ctx, e))?;
            f.call::<_, String>((method, params_json))
                .map_err(|e| format_js_error(&ctx, e))
        })?;
        self.resolve_if_pending(raw)
    }

    /// 驱动 QuickJS 微任务队列，解析 `async` 函数返回的 Promise
    fn resolve_if_pending(&self, raw: String) -> Result<String> {
        if raw != "__PENDING__" {
            return Ok(raw);
        }
        while self._rt.is_job_pending() {
            if let Err(err) = self._rt.execute_pending_job() {
                return Err(anyhow::anyhow!("JS 微任务执行失败: {err:?}"));
            }
        }
        self.ctx.with(|ctx| -> Result<String> {
            let slot: Object<'_> = ctx
                .globals()
                .get("__asyncSlot")
                .map_err(|e| format_js_error(&ctx, e))?;
            let state: String = slot
                .get("state")
                .map_err(|e| format_js_error(&ctx, e))?;
            match state.as_str() {
                "ok" => slot.get("json").map_err(|e| format_js_error(&ctx, e)),
                "err" => {
                    let msg: String = slot.get("err").unwrap_or_else(|_| "unknown error".into());
                    Err(anyhow::anyhow!("JS Promise 异常: {msg}"))
                }
                _ => Err(anyhow::anyhow!("JS Promise 未解决（无待执行微任务）")),
            }
        })
    }

    /// 为当前会话中的所有 `AndroidEmulator` 实例统一设置 Unicorn 硬超时与指令数预算
    pub fn set_all_emu_limits(&self, timeout_us: u64, max_instructions: usize) {
        let mut h = self.host.borrow_mut();
        for entry in &mut h.emus {
            entry.emu.set_execution_limits(timeout_us, max_instructions);
        }
    }

    /// 取出并清空 `capture_logs = true` 期间捕获的 `console.log` 日志行
    pub fn take_logs(&self) -> Vec<String> {
        std::mem::take(&mut *self.log_sink.buf.borrow_mut())
    }
}

impl Drop for JsSession {
    fn drop(&mut self) {
        // 在 QuickJS Context / Runtime drop 之前显式清空全部 Persistent 句柄，防止 GC 断言失败
        let mut h = self.host.borrow_mut();
        h.module_cache.clear();
        for entry in &mut h.emus {
            entry.hooks.borrow_mut().hooks.clear();
            entry.hooks.borrow_mut().unhandled = None;
            entry.native_hooks.borrow_mut().clear_all(entry.emu.uc_mut());
        }
    }
}

/// QuickJS 一次性脚本执行器（V1 + V2）
pub struct JsRunner;

impl JsRunner {
    /// 执行一段 JavaScript 源码
    pub fn run_source(source: &str) -> Result<()> {
        Self::run_source_with_args(source, &[])
    }

    /// 执行 JavaScript 源码并注入全局 `args: string[]`
    pub fn run_source_with_args(source: &str, cli_args: &[String]) -> Result<()> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::run_source_with_base(source, cli_args, &cwd)
    }

    /// 在指定基准目录下执行 JavaScript 源码（用于 `require()` 相对路径解析）
    pub fn run_source_with_base(
        source: &str,
        cli_args: &[String],
        base_dir: &Path,
    ) -> Result<()> {
        let session = JsSession::new(cli_args, base_dir, false)?;
        session.eval_source(source)
    }

    /// 读取并执行 `.js` 脚本文件
    pub fn run_file(path: impl AsRef<Path>, cli_args: &[String]) -> Result<()> {
        let path = path.as_ref();
        let src = fs::read_to_string(path)
            .with_context(|| format!("读取脚本失败: {}", path.display()))?;
        let base_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::run_source_with_base(&src, cli_args, &base_dir)
    }
}

fn format_js_error(ctx: &Ctx<'_>, err: JsError) -> anyhow::Error {
    if matches!(err, JsError::Exception) {
        let caught = ctx.catch();
        if let Some(exc) = caught.as_exception() {
            let msg = exc.message().unwrap_or_default();
            let stack = exc.stack().unwrap_or_default();
            if stack.is_empty() {
                return anyhow::anyhow!("JS 异常: {msg}");
            }
            return anyhow::anyhow!("JS 异常: {msg}\n{stack}");
        }
        return anyhow::anyhow!("JS 异常: {caught:?}");
    }
    anyhow::anyhow!("QuickJS 错误: {err}")
}

/// 便捷写入 `runidbg.d.ts` 到指定目录，返回写入的声明文件路径
pub fn write_type_definitions(dir: impl AsRef<Path>) -> Result<PathBuf> {
    let dir = dir.as_ref();
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("创建目标目录失败: {}", dir.display()))?;
    }
    let out = dir.join("runidbg.d.ts");
    fs::write(&out, RUNIDBG_DTS).with_context(|| format!("写入 {} 失败", out.display()))?;
    Ok(out)
}
