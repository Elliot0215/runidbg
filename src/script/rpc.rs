use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::script::JsSession;

/// RPC 服务启动脚本来源
#[derive(Debug, Clone)]
pub enum RpcSource {
    File(PathBuf),
    Inline { code: String, base_dir: PathBuf },
}

/// RPC HTTP / JSON-RPC 2.0 服务配置
#[derive(Debug, Clone)]
pub struct RpcServerConfig {
    /// 监听地址，默认 `127.0.0.1:8080`
    pub listen_addr: String,
    /// QuickJS + Unicorn Worker 实例数，默认 `1`（单实例）；可设为多核数实现无锁多核并行
    pub workers: usize,
    /// 有界任务队列容量（满时返回 HTTP 503 背压保护），默认 `1024`
    pub max_queue: usize,
    /// 单次请求超时时间（毫秒，0 表示不超时；同时作为 Unicorn 引擎硬超时），默认 `30_000`
    pub timeout_ms: u64,
    /// 单次 Unicorn 调用最大指令数预算（0 表示不限），默认 `0`
    pub max_instructions: usize,
    /// 是否启用 `POST /eval` 调试接口，默认 `false`
    pub allow_eval: bool,
    /// 是否启用 `POST /admin/reload` 滚动热重载接口，默认 `false`
    pub allow_reload: bool,
    /// 透传给脚本全局 `args` 的参数
    pub cli_args: Vec<String>,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_string(),
            workers: 1,
            max_queue: 1024,
            timeout_ms: 30_000,
            max_instructions: 0,
            allow_eval: false,
            allow_reload: false,
            cli_args: Vec::new(),
        }
    }
}

/// 延迟直方图分桶上界（毫秒）
const LATENCY_BUCKETS_MS: [u64; 10] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000];

/// 无锁原子运行指标（供 `GET /metrics` 输出 JSON / Prometheus 文本格式）
struct RpcMetrics {
    requests_total: AtomicU64,
    requests_ok: AtomicU64,
    requests_error: AtomicU64,
    requests_timeout: AtomicU64,
    requests_overloaded: AtomicU64,
    inflight: AtomicU64,
    reloads_total: AtomicU64,
    latency_sum_us: AtomicU64,
    latency_buckets: [AtomicU64; 11], // 10 finite buckets + +Inf
}

impl Default for RpcMetrics {
    fn default() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_ok: AtomicU64::new(0),
            requests_error: AtomicU64::new(0),
            requests_timeout: AtomicU64::new(0),
            requests_overloaded: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            reloads_total: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl RpcMetrics {
    fn record_latency(&self, elapsed: Duration) {
        let us = elapsed.as_micros() as u64;
        let ms = elapsed.as_millis() as u64;
        self.latency_sum_us.fetch_add(us, Ordering::Relaxed);
        let idx = LATENCY_BUCKETS_MS
            .iter()
            .position(|&bound| ms <= bound)
            .unwrap_or(LATENCY_BUCKETS_MS.len());
        self.latency_buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot_json(&self, workers: usize, queue_len: usize, queue_cap: usize, epoch: u64) -> Value {
        let total = self.requests_total.load(Ordering::Relaxed);
        let sum_us = self.latency_sum_us.load(Ordering::Relaxed);
        let avg_ms = if total > 0 {
            (sum_us as f64 / total as f64) / 1000.0
        } else {
            0.0
        };
        let mut buckets = serde_json::Map::new();
        for (i, &bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            buckets.insert(
                format!("le_{bound}ms"),
                json!(self.latency_buckets[i].load(Ordering::Relaxed)),
            );
        }
        buckets.insert(
            "gt_5000ms".to_string(),
            json!(self.latency_buckets[LATENCY_BUCKETS_MS.len()].load(Ordering::Relaxed)),
        );
        json!({
            "workers": workers,
            "queue_len": queue_len,
            "queue_capacity": queue_cap,
            "reload_epoch": epoch,
            "requests_total": total,
            "requests_ok": self.requests_ok.load(Ordering::Relaxed),
            "requests_error": self.requests_error.load(Ordering::Relaxed),
            "requests_timeout": self.requests_timeout.load(Ordering::Relaxed),
            "requests_overloaded": self.requests_overloaded.load(Ordering::Relaxed),
            "inflight": self.inflight.load(Ordering::Relaxed),
            "reloads_total": self.reloads_total.load(Ordering::Relaxed),
            "avg_latency_ms": avg_ms,
            "latency_buckets": buckets,
        })
    }

    fn render_prometheus(
        &self,
        workers: usize,
        queue_len: usize,
        queue_cap: usize,
        epoch: u64,
    ) -> String {
        let total = self.requests_total.load(Ordering::Relaxed);
        let ok = self.requests_ok.load(Ordering::Relaxed);
        let err = self.requests_error.load(Ordering::Relaxed);
        let timeout = self.requests_timeout.load(Ordering::Relaxed);
        let overloaded = self.requests_overloaded.load(Ordering::Relaxed);
        let inflight = self.inflight.load(Ordering::Relaxed);
        let reloads = self.reloads_total.load(Ordering::Relaxed);
        let sum_sec = self.latency_sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;

        let mut out = String::new();
        out.push_str("# TYPE runidbg_rpc_workers gauge\n");
        out.push_str(&format!("runidbg_rpc_workers {workers}\n"));
        out.push_str("# TYPE runidbg_rpc_queue_len gauge\n");
        out.push_str(&format!("runidbg_rpc_queue_len {queue_len}\n"));
        out.push_str("# TYPE runidbg_rpc_queue_capacity gauge\n");
        out.push_str(&format!("runidbg_rpc_queue_capacity {queue_cap}\n"));
        out.push_str("# TYPE runidbg_rpc_inflight gauge\n");
        out.push_str(&format!("runidbg_rpc_inflight {inflight}\n"));
        out.push_str("# TYPE runidbg_rpc_reload_epoch counter\n");
        out.push_str(&format!("runidbg_rpc_reload_epoch {epoch}\n"));
        out.push_str("# TYPE runidbg_rpc_reloads_total counter\n");
        out.push_str(&format!("runidbg_rpc_reloads_total {reloads}\n"));
        out.push_str("# TYPE runidbg_rpc_requests_total counter\n");
        out.push_str(&format!("runidbg_rpc_requests_total{{status=\"ok\"}} {ok}\n"));
        out.push_str(&format!(
            "runidbg_rpc_requests_total{{status=\"error\"}} {err}\n"
        ));
        out.push_str(&format!(
            "runidbg_rpc_requests_total{{status=\"timeout\"}} {timeout}\n"
        ));
        out.push_str(&format!(
            "runidbg_rpc_requests_total{{status=\"overloaded\"}} {overloaded}\n"
        ));
        out.push_str("# TYPE runidbg_rpc_request_duration_seconds histogram\n");
        let mut cumulative = 0u64;
        for (i, &bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative += self.latency_buckets[i].load(Ordering::Relaxed);
            let sec = bound as f64 / 1000.0;
            out.push_str(&format!(
                "runidbg_rpc_request_duration_seconds_bucket{{le=\"{sec}\"}} {cumulative}\n"
            ));
        }
        cumulative += self.latency_buckets[LATENCY_BUCKETS_MS.len()].load(Ordering::Relaxed);
        out.push_str(&format!(
            "runidbg_rpc_request_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}\n"
        ));
        out.push_str(&format!(
            "runidbg_rpc_request_duration_seconds_sum {sum_sec:.6}\n"
        ));
        out.push_str(&format!(
            "runidbg_rpc_request_duration_seconds_count {total}\n"
        ));
        out
    }
}

enum WorkerTask {
    ListExports {
        reply: oneshot::Sender<Result<Value>>,
    },
    Call {
        method: String,
        params_json: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    Eval {
        code: String,
        reply: oneshot::Sender<Result<(Value, Vec<String>)>>,
    },
}

#[derive(Clone)]
struct AppState {
    task_tx: async_channel::Sender<WorkerTask>,
    source: RpcSource,
    active_source: Arc<std::sync::RwLock<RpcSource>>,
    cli_args: Vec<String>,
    workers: usize,
    max_queue: usize,
    timeout: Option<Duration>,
    timeout_us: u64,
    max_instructions: usize,
    allow_eval: bool,
    allow_reload: bool,
    reload_epoch: Arc<AtomicU64>,
    metrics: Arc<RpcMetrics>,
    next_req_id: Arc<AtomicU64>,
}

#[derive(Debug)]
enum DispatchError {
    Overloaded,
    Timeout,
    WorkerClosed,
    Execution(String),
}

/// 运行中的异步高并发 RPC 服务句柄（支持优雅停机与阻塞监听）
pub struct RpcServerHandle {
    local_addr: SocketAddr,
    workers: usize,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task_tx: async_channel::Sender<WorkerTask>,
    server_thread: Option<JoinHandle<()>>,
    worker_threads: Vec<JoinHandle<()>>,
}

impl RpcServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn workers(&self) -> usize {
        self.workers
    }

    /// 阻塞等待服务线程结束（供 CLI `runidbg-cli serve` 使用）
    pub fn wait(mut self) {
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
        self.task_tx.close();
        for h in self.worker_threads.drain(..) {
            let _ = h.join();
        }
    }

    /// 优雅停止异步 HTTP 服务与全部 QuickJS Worker 线程
    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
        self.task_tx.close();
        for h in self.worker_threads.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for RpcServerHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

fn build_worker_session(
    source: &RpcSource,
    cli_args: &[String],
    allow_eval: bool,
    timeout_us: u64,
    max_instructions: usize,
    print_startup_logs: bool,
) -> Result<(JsSession, Vec<String>)> {
    let session = match source {
        RpcSource::File(path) => {
            let base = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            let s = JsSession::new(cli_args, &base, allow_eval)?;
            s.eval_file(path)?;
            s
        }
        RpcSource::Inline { code, base_dir } => {
            let s = JsSession::new(cli_args, base_dir, allow_eval)?;
            s.eval_source(code)?;
            s
        }
    };

    if print_startup_logs {
        for line in session.take_logs() {
            eprintln!("{line}");
        }
    } else {
        let _ = session.take_logs();
    }

    if timeout_us > 0 || max_instructions > 0 {
        session.set_all_emu_limits(timeout_us, max_instructions);
    }

    let exports = session
        .list_rpc_exports_json()
        .and_then(|j| Ok(serde_json::from_str::<Vec<String>>(&j)?))?;
    Ok((session, exports))
}

/// 启动基于异步 HTTP (`tokio` + `axum`) 与多 Worker 实例池的 RPC 服务
///
/// 架构：
/// - 异步 HTTP 接入层支持 Keep-Alive 连接复用、慢连接隔离、请求超时、队列满背压 (`503`)、`/metrics` 指标、滚动热重载与 JSON-RPC 2.0 Batch 并行分发；
/// - `workers` 个独立 OS 线程各独占 1 套 `!Send` 的 `JsSession`（QuickJS + Unicorn），通过有界 MPMC `async-channel` 实现无锁多核并行（默认 `workers = 1` 单实例）；
/// - Unicorn 底层同步施加 `timeout_ms` 硬超时与 `max_instructions` 指令预算，彻底杜绝死循环拖死 Worker。
pub fn start_rpc_server(source: RpcSource, config: RpcServerConfig) -> Result<RpcServerHandle> {
    let workers = config.workers.max(1);
    let max_queue = config.max_queue.max(1);
    let timeout = if config.timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(config.timeout_ms))
    };
    let timeout_us = config.timeout_ms.saturating_mul(1000);
    let max_instructions = config.max_instructions;
    let reload_epoch = Arc::new(AtomicU64::new(0));
    let active_source = Arc::new(std::sync::RwLock::new(source.clone()));
    let metrics = Arc::new(RpcMetrics::default());

    let (task_tx, task_rx) = async_channel::bounded::<WorkerTask>(max_queue);
    let mut worker_threads = Vec::with_capacity(workers);
    let mut init_rxs = Vec::with_capacity(workers);

    for idx in 0..workers {
        let rx = task_rx.clone();
        let src = source.clone();
        let active_src_ref = Arc::clone(&active_source);
        let cli_args = config.cli_args.clone();
        let allow_eval = config.allow_eval;
        let epoch_ref = Arc::clone(&reload_epoch);
        let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<Result<Vec<String>>>(1);
        init_rxs.push(init_rx);

        let handle = thread::Builder::new()
            .name(format!("runidbg-rpc-worker-{idx}"))
            .spawn(move || {
                let mut local_epoch = epoch_ref.load(Ordering::Acquire);
                let mut session = match build_worker_session(
                    &src,
                    &cli_args,
                    allow_eval,
                    timeout_us,
                    max_instructions,
                    idx == 0,
                ) {
                    Ok((s, exports)) => {
                        let _ = init_tx.send(Ok(exports));
                        s
                    }
                    Err(err) => {
                        let _ = init_tx.send(Err(err));
                        return;
                    }
                };

                while let Ok(task) = rx.recv_blocking() {
                    // 滚动热重载检测：从已校验的 active_source 快照重建本 Worker 的 JsSession
                    let cur_epoch = epoch_ref.load(Ordering::Acquire);
                    if cur_epoch != local_epoch {
                        let snap_src = active_src_ref
                            .read()
                            .map(|g| g.clone())
                            .unwrap_or_else(|_| src.clone());
                        if let Ok((new_session, _)) = build_worker_session(
                            &snap_src,
                            &cli_args,
                            allow_eval,
                            timeout_us,
                            max_instructions,
                            false,
                        ) {
                            session = new_session;
                            local_epoch = cur_epoch;
                        }
                    }

                    match task {
                        WorkerTask::ListExports { reply } => {
                            let res = session
                                .list_rpc_exports_json()
                                .and_then(|j| Ok(serde_json::from_str::<Value>(&j)?));
                            let _ = reply.send(res);
                        }
                        WorkerTask::Call {
                            method,
                            params_json,
                            reply,
                        } => {
                            let res = session
                                .call_rpc_json(&method, &params_json)
                                .and_then(|j| Ok(serde_json::from_str::<Value>(&j)?));
                            let _ = reply.send(res);
                        }
                        WorkerTask::Eval { code, reply } => {
                            let _ = session.take_logs();
                            let res = session.eval_json_string(&code).and_then(|j| {
                                let val = serde_json::from_str::<Value>(&j)?;
                                let logs = session.take_logs();
                                Ok((val, logs))
                            });
                            let _ = reply.send(res);
                        }
                    }
                }
            })
            .with_context(|| format!("创建 RPC Worker-{idx} 线程失败"))?;
        worker_threads.push(handle);
    }

    // 等待所有 Worker 完成脚本初始化；若任一失败则回收全部线程并返回错误
    for (idx, rx) in init_rxs.into_iter().enumerate() {
        let init_res = rx
            .recv()
            .map_err(|_| anyhow!("RPC Worker-{idx} 初始化时异常退出"))
            .and_then(|r| r);
        if let Err(err) = init_res {
            task_tx.close();
            for h in worker_threads {
                let _ = h.join();
            }
            return Err(err);
        }
    }

    let state = Arc::new(AppState {
        task_tx: task_tx.clone(),
        source,
        active_source,
        cli_args: config.cli_args,
        workers,
        max_queue,
        timeout,
        timeout_us,
        max_instructions,
        allow_eval: config.allow_eval,
        allow_reload: config.allow_reload,
        reload_epoch,
        metrics,
        next_req_id: Arc::new(AtomicU64::new(1)),
    });

    let listen_addr = config.listen_addr.clone();
    let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel::<Result<SocketAddr>>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server_thread = thread::Builder::new()
        .name("runidbg-rpc-http".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("runidbg-http-io")
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = bound_tx.send(Err(anyhow!("创建 Tokio 运行时失败: {e}")));
                    return;
                }
            };

            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = bound_tx.send(Err(anyhow!(
                            "绑定 RPC 监听地址失败 ({listen_addr}): {e}"
                        )));
                        return;
                    }
                };
                let local_addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = bound_tx.send(Err(anyhow!("获取本地监听地址失败: {e}")));
                        return;
                    }
                };
                let _ = bound_tx.send(Ok(local_addr));

                let app = build_router(state);
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
        })
        .context("创建 RPC 异步 HTTP 线程失败")?;

    let local_addr = match bound_rx.recv() {
        Ok(Ok(addr)) => addr,
        Ok(Err(err)) => {
            task_tx.close();
            let _ = server_thread.join();
            for h in worker_threads {
                let _ = h.join();
            }
            return Err(err);
        }
        Err(_) => {
            task_tx.close();
            let _ = server_thread.join();
            for h in worker_threads {
                let _ = h.join();
            }
            return Err(anyhow!("RPC 异步 HTTP 线程启动失败"));
        }
    };

    Ok(RpcServerHandle {
        local_addr,
        workers,
        shutdown_tx: Some(shutdown_tx),
        task_tx,
        server_thread: Some(server_thread),
        worker_threads,
    })
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handle_health).options(handle_cors_preflight))
        .route(
            "/exports",
            get(handle_exports).options(handle_cors_preflight),
        )
        .route(
            "/metrics",
            get(handle_metrics).options(handle_cors_preflight),
        )
        .route("/rpc", post(handle_jsonrpc).options(handle_cors_preflight))
        .route(
            "/call/{method}",
            post(handle_call_method).options(handle_cors_preflight),
        )
        .route("/eval", post(handle_eval).options(handle_cors_preflight))
        .route(
            "/admin/reload",
            post(handle_reload).options(handle_cors_preflight),
        )
        .fallback(handle_not_found)
        .with_state(state)
}

fn with_cors(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type"),
    );
    resp
}

fn json_resp(status: StatusCode, body: Value) -> Response {
    with_cors((status, Json(body)).into_response())
}

async fn handle_cors_preflight() -> Response {
    with_cors(StatusCode::NO_CONTENT.into_response())
}

async fn handle_not_found(method: Method) -> Response {
    if method == Method::OPTIONS {
        return handle_cors_preflight().await;
    }
    json_resp(
        StatusCode::NOT_FOUND,
        json!({
            "ok": false,
            "error": "not found; available endpoints: GET /health, GET /exports, GET /metrics, POST /rpc, POST /call/<method>, POST /eval, POST /admin/reload"
        }),
    )
}

async fn dispatch_task<T>(
    state: &AppState,
    task: WorkerTask,
    rx: oneshot::Receiver<Result<T>>,
    count_metric: bool,
) -> std::result::Result<T, DispatchError> {
    let started = Instant::now();
    if count_metric {
        state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        state.metrics.inflight.fetch_add(1, Ordering::Relaxed);
    }

    let send_res = state.task_tx.try_send(task);
    let result = match send_res {
        Ok(()) => {
            let outcome = match state.timeout {
                Some(dur) => match tokio::time::timeout(dur, rx).await {
                    Ok(res) => res,
                    Err(_) => {
                        if count_metric {
                            state.metrics.inflight.fetch_sub(1, Ordering::Relaxed);
                            state
                                .metrics
                                .requests_timeout
                                .fetch_add(1, Ordering::Relaxed);
                            state.metrics.record_latency(started.elapsed());
                        }
                        return Err(DispatchError::Timeout);
                    }
                },
                None => rx.await,
            };
            match outcome {
                Ok(Ok(val)) => Ok(val),
                Ok(Err(err)) => {
                    let msg = err.to_string();
                    if msg.contains("执行超时或超出指令预算") {
                        Err(DispatchError::Timeout)
                    } else {
                        Err(DispatchError::Execution(msg))
                    }
                }
                Err(_) => Err(DispatchError::WorkerClosed),
            }
        }
        Err(async_channel::TrySendError::Full(_)) => Err(DispatchError::Overloaded),
        Err(async_channel::TrySendError::Closed(_)) => Err(DispatchError::WorkerClosed),
    };

    if count_metric {
        state.metrics.inflight.fetch_sub(1, Ordering::Relaxed);
        match &result {
            Ok(_) => {
                state.metrics.requests_ok.fetch_add(1, Ordering::Relaxed);
            }
            Err(DispatchError::Overloaded) => {
                state
                    .metrics
                    .requests_overloaded
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(DispatchError::Timeout) => {
                state
                    .metrics
                    .requests_timeout
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                state.metrics.requests_error.fetch_add(1, Ordering::Relaxed);
            }
        }
        state.metrics.record_latency(started.elapsed());
    }

    result
}

fn dispatch_err_to_http(err: DispatchError) -> Response {
    match err {
        DispatchError::Overloaded => json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "error": "server overloaded: worker queue is full" }),
        ),
        DispatchError::Timeout => json_resp(
            StatusCode::GATEWAY_TIMEOUT,
            json!({ "ok": false, "error": "RPC request timed out or exceeded instruction budget" }),
        ),
        DispatchError::WorkerClosed => json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "error": "RPC worker pool is shutting down" }),
        ),
        DispatchError::Execution(msg) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": msg }),
        ),
    }
}

async fn query_exports(state: &AppState) -> std::result::Result<Value, DispatchError> {
    let (tx, rx) = oneshot::channel();
    dispatch_task(state, WorkerTask::ListExports { reply: tx }, rx, false).await
}

async fn invoke_rpc(
    state: &AppState,
    method: String,
    params_json: String,
) -> std::result::Result<Value, DispatchError> {
    let (tx, rx) = oneshot::channel();
    dispatch_task(
        state,
        WorkerTask::Call {
            method,
            params_json,
            reply: tx,
        },
        rx,
        true,
    )
    .await
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Response {
    match query_exports(&state).await {
        Ok(exports) => json_resp(
            StatusCode::OK,
            json!({
                "status": "ok",
                "workers": state.workers,
                "queue_capacity": state.max_queue,
                "queue_len": state.task_tx.len(),
                "inflight": state.metrics.inflight.load(Ordering::Relaxed),
                "reload_epoch": state.reload_epoch.load(Ordering::Acquire),
                "exports": exports,
            }),
        ),
        Err(err) => dispatch_err_to_http(err),
    }
}

async fn handle_exports(State(state): State<Arc<AppState>>) -> Response {
    match query_exports(&state).await {
        Ok(exports) => json_resp(StatusCode::OK, json!({ "exports": exports })),
        Err(err) => dispatch_err_to_http(err),
    }
}

async fn handle_metrics(State(state): State<Arc<AppState>>, uri: Uri) -> Response {
    let qlen = state.task_tx.len();
    let epoch = state.reload_epoch.load(Ordering::Acquire);
    let is_prom = uri
        .query()
        .is_some_and(|q| q.split('&').any(|kv| kv == "format=prom"));
    if is_prom {
        let body = state
            .metrics
            .render_prometheus(state.workers, qlen, state.max_queue, epoch);
        let mut resp = (StatusCode::OK, body).into_response();
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        return with_cors(resp);
    }
    json_resp(
        StatusCode::OK,
        state
            .metrics
            .snapshot_json(state.workers, qlen, state.max_queue, epoch),
    )
}

async fn handle_reload(State(state): State<Arc<AppState>>) -> Response {
    if !state.allow_reload {
        return json_resp(
            StatusCode::FORBIDDEN,
            json!({ "ok": false, "error": "POST /admin/reload is disabled (start server with --allow-reload)" }),
        );
    }

    // 先在独立验证线程试加载脚本，语法或初始化报错时绝不影响线上 Worker
    let src = state.source.clone();
    let cli_args = state.cli_args.clone();
    let allow_eval = state.allow_eval;
    let timeout_us = state.timeout_us;
    let max_insns = state.max_instructions;

    let validate_res = tokio::task::spawn_blocking(move || {
        let snapshot_src = match &src {
            RpcSource::File(path) => {
                let code = std::fs::read_to_string(path)
                    .with_context(|| format!("读取脚本失败: {}", path.display()))?;
                let base_dir = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(std::path::Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
                RpcSource::Inline { code, base_dir }
            }
            RpcSource::Inline { .. } => src.clone(),
        };
        build_worker_session(
            &snapshot_src,
            &cli_args,
            allow_eval,
            timeout_us,
            max_insns,
            false,
        )
        .map(|(_, exports)| (snapshot_src, exports))
    })
    .await;

    match validate_res {
        Ok(Ok((snapshot_src, exports))) => {
            if let Ok(mut guard) = state.active_source.write() {
                *guard = snapshot_src;
            }
            let new_epoch = state.reload_epoch.fetch_add(1, Ordering::AcqRel) + 1;
            state.metrics.reloads_total.fetch_add(1, Ordering::Relaxed);
            json_resp(
                StatusCode::OK,
                json!({
                    "ok": true,
                    "reload_epoch": new_epoch,
                    "exports": exports,
                }),
            )
        }
        Ok(Err(err)) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("热重载校验失败（已保留旧版本）: {err}") }),
        ),
        Err(join_err) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("热重载校验线程异常: {join_err}") }),
        ),
    }
}

fn next_req_id(state: &AppState) -> String {
    let n = state.next_req_id.fetch_add(1, Ordering::Relaxed);
    format!("req-{n}")
}

fn with_req_id(mut resp: Response, req_id: &str) -> Response {
    if let Ok(val) = HeaderValue::from_str(req_id) {
        resp.headers_mut().insert(
            header::HeaderName::from_static("x-request-id"),
            val,
        );
    }
    resp
}

fn sanitize_client_error(err: &DispatchError, req_id: &str) -> (StatusCode, Value) {
    match err {
        DispatchError::Overloaded => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "req_id": req_id, "error": "server overloaded: worker queue is full" }),
        ),
        DispatchError::Timeout => (
            StatusCode::GATEWAY_TIMEOUT,
            json!({ "ok": false, "req_id": req_id, "error": "RPC request timed out or exceeded instruction budget" }),
        ),
        DispatchError::WorkerClosed => (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "ok": false, "req_id": req_id, "error": "RPC worker pool is shutting down" }),
        ),
        DispatchError::Execution(msg) => {
            // 若底层触发完整 Guest 崩溃报告，服务端已通过 tracing::error! 记录详情；对外仅返回精简摘要
            let client_msg = if msg.contains("runidbg Guest Crash Report") {
                let reason = msg
                    .lines()
                    .find(|l| l.starts_with("Reason"))
                    .unwrap_or("Guest crash");
                format!("guest execution crashed ({reason}; see server logs for {req_id})")
            } else {
                msg.clone()
            };
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "ok": false, "req_id": req_id, "error": client_msg }),
            )
        }
    }
}

async fn handle_call_method(
    State(state): State<Arc<AppState>>,
    AxumPath(method): AxumPath<String>,
    body: Bytes,
) -> Response {
    let req_id = next_req_id(&state);
    let started = Instant::now();
    if method.is_empty() {
        return with_req_id(
            json_resp(
                StatusCode::BAD_REQUEST,
                json!({ "ok": false, "req_id": req_id, "error": "missing method name" }),
            ),
            &req_id,
        );
    }
    let params_json = if body.is_empty() {
        "[]".to_string()
    } else {
        String::from_utf8(body.to_vec()).unwrap_or_else(|_| "[]".to_string())
    };
    let resp = match invoke_rpc(&state, method.clone(), params_json).await {
        Ok(val) => {
            tracing::info!(
                target: "runidbg::rpc",
                req_id = %req_id,
                method = %method,
                status = 200u16,
                latency_ms = started.elapsed().as_millis() as u64,
                "rpc call ok"
            );
            json_resp(StatusCode::OK, json!({ "ok": true, "req_id": req_id, "result": val }))
        }
        Err(err) => {
            let (status, payload) = sanitize_client_error(&err, &req_id);
            tracing::warn!(
                target: "runidbg::rpc",
                req_id = %req_id,
                method = %method,
                status = status.as_u16(),
                latency_ms = started.elapsed().as_millis() as u64,
                error = ?err,
                "rpc call failed"
            );
            json_resp(status, payload)
        }
    };
    with_req_id(resp, &req_id)
}

async fn handle_eval(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let req_id = next_req_id(&state);
    if !state.allow_eval {
        return with_req_id(
            json_resp(
                StatusCode::FORBIDDEN,
                json!({ "ok": false, "req_id": req_id, "error": "POST /eval is disabled (start server with --allow-eval)" }),
            ),
            &req_id,
        );
    }
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return with_req_id(
                json_resp(
                    StatusCode::BAD_REQUEST,
                    json!({ "ok": false, "req_id": req_id, "error": format!("invalid JSON: {e}") }),
                ),
                &req_id,
            );
        }
    };
    let Some(code) = parsed.get("code").and_then(Value::as_str) else {
        return with_req_id(
            json_resp(
                StatusCode::BAD_REQUEST,
                json!({ "ok": false, "req_id": req_id, "error": "missing string field `code`" }),
            ),
            &req_id,
        );
    };
    let (tx, rx) = oneshot::channel();
    let resp = match dispatch_task(
        &state,
        WorkerTask::Eval {
            code: code.to_string(),
            reply: tx,
        },
        rx,
        true,
    )
    .await
    {
        Ok((val, logs)) => json_resp(
            StatusCode::OK,
            json!({ "ok": true, "req_id": req_id, "result": val, "logs": logs }),
        ),
        Err(err) => {
            let (status, payload) = sanitize_client_error(&err, &req_id);
            json_resp(status, payload)
        }
    };
    with_req_id(resp, &req_id)
}

async fn handle_jsonrpc(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_resp(
                StatusCode::OK,
                json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                }),
            );
        }
    };

    // JSON-RPC 2.0 Batch：并发分发到 Worker 池并按原顺序聚合响应
    if let Value::Array(items) = req {
        if items.is_empty() {
            return json_resp(
                StatusCode::OK,
                json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32600, "message": "Invalid Request: empty batch" }
                }),
            );
        }

        let mut join_set = tokio::task::JoinSet::new();
        for (idx, item) in items.into_iter().enumerate() {
            let st = Arc::clone(&state);
            join_set.spawn(async move { (idx, execute_single_jsonrpc(&st, item).await) });
        }

        let mut ordered: Vec<(usize, Value)> = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, Some(val))) = res {
                ordered.push((idx, val));
            }
        }
        ordered.sort_by_key(|(idx, _)| *idx);
        if ordered.is_empty() {
            return with_cors(StatusCode::NO_CONTENT.into_response());
        }
        let responses: Vec<Value> = ordered.into_iter().map(|(_, v)| v).collect();
        return json_resp(StatusCode::OK, Value::Array(responses));
    }

    match execute_single_jsonrpc(&state, req).await {
        Some(resp) => json_resp(StatusCode::OK, resp),
        None => with_cors(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn execute_single_jsonrpc(state: &AppState, req: Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let is_notification = id.is_none();
    let reply_id = id.unwrap_or(Value::Null);

    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": reply_id,
            "error": { "code": -32600, "message": "Invalid Request: missing `method`" }
        }));
    };

    let outcome = if method == "rpc.list" {
        query_exports(state).await
    } else {
        let params_json = match req.get("params") {
            Some(v) => serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string()),
            None => "[]".to_string(),
        };
        invoke_rpc(state, method.to_string(), params_json).await
    };

    if is_notification {
        return None;
    }

    Some(match outcome {
        Ok(val) => json!({
            "jsonrpc": "2.0",
            "id": reply_id,
            "result": val
        }),
        Err(DispatchError::Overloaded) => json!({
            "jsonrpc": "2.0",
            "id": reply_id,
            "error": { "code": -32001, "message": "Server overloaded: worker queue is full" }
        }),
        Err(DispatchError::Timeout) => json!({
            "jsonrpc": "2.0",
            "id": reply_id,
            "error": { "code": -32002, "message": "RPC request timed out or exceeded instruction budget" }
        }),
        Err(DispatchError::WorkerClosed) => json!({
            "jsonrpc": "2.0",
            "id": reply_id,
            "error": { "code": -32003, "message": "RPC worker pool is shutting down" }
        }),
        Err(DispatchError::Execution(msg)) => {
            let code = if msg.contains("RPC method not found") {
                -32601
            } else {
                -32000
            };
            json!({
                "jsonrpc": "2.0",
                "id": reply_id,
                "error": { "code": code, "message": msg }
            })
        }
    })
}
