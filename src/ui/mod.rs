use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use anyhow::{anyhow, Result};
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};

use crate::tracer::{format_ascii_hint, BinaryTracer, TraceReader};

/// 嵌入的单页 Web UI（零外部依赖，离线可用）
pub const INDEX_HTML: &str = include_str!("index.html");

/// Axum 路由处理器：返回单页 Web UI HTML（同时供 `runidbg-cli ui` 与 `runidbg-cli serve /ui` 复用）
pub async fn serve_spa_html() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// 可选自动拉起宿主机默认浏览器打开指定 URL
pub fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
}

struct TraceUiState {
    reader: TraceReader,
    trace_path: String,
    has_ext: bool,
    base_addr: u64,
}

impl TraceUiState {
    fn rel_offset(&self, pc: u64) -> Option<String> {
        (self.base_addr != 0 && pc >= self.base_addr)
            .then(|| format!("+0x{:x}", pc - self.base_addr))
    }
}

/// 离线 Trace Web UI 服务句柄（支持 `wait()` 阻塞或 `shutdown()` 优雅退出）
pub struct TraceUiHandle {
    local_addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    server_thread: Option<thread::JoinHandle<()>>,
}

impl TraceUiHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn wait(mut self) {
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
    }

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
    }
}

impl Drop for TraceUiHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// 启动离线 Trace 可视化 Web UI 服务
pub fn start_trace_ui_server(
    idx_path: &Path,
    ext_path: Option<&Path>,
    base_addr: u64,
    listen_addr: &str,
) -> Result<TraceUiHandle> {
    let reader = TraceReader::open(idx_path, ext_path)?;
    let state = Arc::new(TraceUiState {
        reader,
        trace_path: idx_path.display().to_string(),
        has_ext: ext_path.is_some(),
        base_addr,
    });

    let listen = listen_addr.to_string();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<SocketAddr>>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_thread = thread::Builder::new()
        .name("runidbg-ui-http".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(anyhow!("Tokio Runtime 启动失败: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&listen).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("绑定 {listen} 失败: {e}")));
                        return;
                    }
                };
                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("读取监听地址失败: {e}")));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(addr));

                let app = Router::new()
                    .route("/", get(serve_spa_html))
                    .route("/ui", get(serve_spa_html))
                    .route("/api/info", get(handle_info))
                    .route("/api/trace/dump", get(handle_dump))
                    .route("/api/trace/calltree", get(handle_calltree))
                    .route("/api/trace/crypto", get(handle_crypto))
                    .route("/api/trace/stats", get(handle_stats))
                    .route("/api/trace/search", get(handle_search))
                    .with_state(state);

                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
        })?;

    let local_addr = ready_rx
        .recv()
        .map_err(|_| anyhow!("Web UI 服务线程意外退出"))??;

    Ok(TraceUiHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        server_thread: Some(server_thread),
    })
}

fn json_resp(val: Value) -> Response {
    let mut resp = (StatusCode::OK, val.to_string()).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp
}

async fn handle_info(State(st): State<Arc<TraceUiState>>) -> Response {
    json_resp(json!({
        "mode": "trace",
        "tracePath": st.trace_path,
        "base": st.base_addr,
        "baseHex": format!("0x{:x}", st.base_addr),
        "totalRecords": st.reader.len(),
        "totalExtRecords": st.reader.ext_len(),
    }))
}

fn parse_query_map(uri: &Uri) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(q) = uri.query() else {
        return map;
    };
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode(k), percent_decode(v));
        }
    }
    map
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn handle_dump(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let skip: usize = params.get("skip").and_then(|s| s.parse().ok()).unwrap_or(0);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(500);
    let end = st.reader.len().min(skip.saturating_add(limit));
    let mut items = Vec::with_capacity(end.saturating_sub(skip));
    for idx in skip..end {
        if let Some(rec) = st.reader.get(idx) {
            let pc = rec.pc;
            let op = rec.opcode;
            let asm = match bad64::decode(op, pc) {
                Ok(insn) => insn.to_string(),
                Err(_) => format!(".word 0x{op:08x}"),
            };
            let regs: Vec<Value> = st
                .reader
                .reg_deltas_for(idx)
                .into_iter()
                .map(|(rid, rval)| {
                    let name = if rid == 31 {
                        "SP".to_string()
                    } else {
                        format!("X{rid}")
                    };
                    json!({
                        "name": name,
                        "valHex": format!("0x{rval:016x}"),
                        "ascii": format_ascii_hint(rval, 8),
                    })
                })
                .collect();
            let mems: Vec<String> = if st.has_ext {
                st.reader
                    .mem_events_for(idx)
                    .into_iter()
                    .map(|e| BinaryTracer::format_ext_record(&e).trim().to_string())
                    .collect()
            } else {
                Vec::new()
            };
            items.push(json!({
                "idx": idx,
                "pcHex": format!("0x{pc:016x}"),
                "offset": st.rel_offset(pc),
                "asm": asm,
                "regs": regs,
                "mems": mems,
            }));
        }
    }
    json_resp(json!({
        "skip": skip,
        "returned": items.len(),
        "total": st.reader.len(),
        "items": items,
    }))
}

async fn handle_calltree(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let max_depth: usize = params
        .get("maxDepth")
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let min_insns: usize = params
        .get("minInsns")
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let total = st.reader.len().max(1);
    let all = st.reader.build_calltree();
    let nodes: Vec<Value> = all
        .iter()
        .filter(|n| n.depth <= max_depth && (n.depth == 0 || n.insn_count() >= min_insns))
        .take(limit)
        .map(|n| {
            let cnt = n.insn_count();
            let pct = ((cnt as f64) * 1000.0 / (total as f64)).round() / 10.0;
            json!({
                "depth": n.depth,
                "startIdx": n.start_idx,
                "endIdx": n.end_idx,
                "insnCount": cnt,
                "percent": pct,
                "targetHex": format!("0x{:016x}", n.target_pc),
                "targetOffset": st.rel_offset(n.target_pc),
            })
        })
        .collect();
    json_resp(json!({
        "totalNodes": all.len(),
        "returned": nodes.len(),
        "nodes": nodes,
    }))
}

async fn handle_crypto(State(st): State<Arc<TraceUiState>>) -> Response {
    let groups: Vec<Value> = st
        .reader
        .scan_crypto()
        .into_iter()
        .map(|g| {
            let consts: Vec<String> = g
                .distinct_constants
                .iter()
                .map(|c| format!("0x{c:08x}"))
                .collect();
            json!({
                "algorithm": g.algorithm,
                "startIdx": g.start_idx,
                "endIdx": g.end_idx,
                "firstPcHex": format!("0x{:016x}", g.first_pc),
                "firstPcOffset": st.rel_offset(g.first_pc),
                "hitCount": g.hit_count,
                "distinctConstants": consts,
            })
        })
        .collect();
    json_resp(json!({
        "count": groups.len(),
        "groups": groups,
    }))
}

async fn handle_stats(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let top_n: usize = params.get("top").and_then(|s| s.parse().ok()).unwrap_or(20);
    let mut pc_counts: HashMap<u64, u64> = HashMap::new();
    let mut bl_targets: HashMap<u64, u64> = HashMap::new();
    for idx in 0..st.reader.len() {
        if let Some(rec) = st.reader.get(idx) {
            let pc = rec.pc;
            let op = rec.opcode;
            *pc_counts.entry(pc).or_insert(0) += 1;
            if (op & 0xFC00_0000) == 0x9400_0000 {
                let imm26 = ((op & 0x03FF_FFFF) as i32) << 6 >> 6;
                let target = pc.wrapping_add((imm26 as i64 * 4) as u64);
                *bl_targets.entry(target).or_insert(0) += 1;
            }
        }
    }
    let unique_pcs = pc_counts.len();
    let unique_bl = bl_targets.len();
    let mut top_bl: Vec<(u64, u64)> = bl_targets.into_iter().collect();
    top_bl.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut top_pc: Vec<(u64, u64)> = pc_counts.into_iter().collect();
    top_pc.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    json_resp(json!({
        "totalRecords": st.reader.len(),
        "uniquePcs": unique_pcs,
        "uniqueBl": unique_bl,
        "topBl": top_bl.into_iter().take(top_n).map(|(addr, count)| json!({
            "addrHex": format!("0x{addr:016x}"),
            "offset": st.rel_offset(addr),
            "count": count,
        })).collect::<Vec<_>>(),
        "topPc": top_pc.into_iter().take(top_n).map(|(addr, count)| json!({
            "addrHex": format!("0x{addr:016x}"),
            "offset": st.rel_offset(addr),
            "count": count,
        })).collect::<Vec<_>>(),
    }))
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ':')
        .collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).ok()?);
    }
    Some(out)
}

async fn handle_search(State(st): State<Arc<TraceUiState>>, uri: Uri) -> Response {
    let params = parse_query_map(&uri);
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .min(500);
    let mut hits: Vec<Value> = Vec::new();
    let mut total = 0usize;

    if let Some(val_s) = params.get("val") {
        if let Some(target) = parse_hex_u64(val_s) {
            let found = st.reader.search_value_attributed(target);
            total = found.len();
            for (idx, rec, rid) in found.into_iter().take(limit) {
                let pc = rec.pc;
                let op = rec.opcode;
                let off = st
                    .rel_offset(pc)
                    .map(|o| format!(" [{o}]"))
                    .unwrap_or_default();
                let line = format!(
                    "#{idx:06}{off} {}",
                    crate::tracer::decode_instruction_with_reg(pc, op, Some((rid, target)))
                );
                hits.push(json!({ "idx": idx, "text": line }));
            }
        }
    } else if let Some(ascii) = params.get("ascii") {
        let found = st.reader.search_mem_bytes(ascii.as_bytes());
        total = found.len();
        for h in found.into_iter().take(limit) {
            let off = st
                .rel_offset(h.pc)
                .map(|o| format!(" [{o}]"))
                .unwrap_or_default();
            let text = format!(
                "seq={} pc=0x{:016x}{off} [MEM W] addr=0x{:016x} len={} (\"{ascii}\")",
                h.seq_low32, h.pc, h.addr, h.matched_len
            );
            hits.push(json!({ "idx": h.seq_low32, "text": text }));
        }
    } else if let Some(bytes_s) = params.get("bytes") {
        if let Some(pat) = parse_hex_bytes(bytes_s) {
            let found = st.reader.search_mem_bytes(&pat);
            total = found.len();
            for h in found.into_iter().take(limit) {
                let off = st
                    .rel_offset(h.pc)
                    .map(|o| format!(" [{o}]"))
                    .unwrap_or_default();
                let text = format!(
                    "seq={} pc=0x{:016x}{off} [MEM W] addr=0x{:016x} len={}",
                    h.seq_low32, h.pc, h.addr, h.matched_len
                );
                hits.push(json!({ "idx": h.seq_low32, "text": text }));
            }
        }
    } else if let Some(addr_s) = params.get("addr") {
        if let Some(target_addr) = parse_hex_u64(addr_s) {
            let found = st.reader.search_mem_addr(target_addr);
            total = found.len();
            for ext in found.into_iter().take(limit) {
                let seq = ext.seq_low32;
                let pc = ext.pc;
                let off = st
                    .rel_offset(pc)
                    .map(|o| format!(" [{o}]"))
                    .unwrap_or_default();
                let text = format!(
                    "seq={seq} pc=0x{pc:016x}{off} {}",
                    BinaryTracer::format_ext_record(&ext).trim()
                );
                hits.push(json!({ "idx": seq, "text": text }));
            }
        }
    }

    json_resp(json!({
        "total": total,
        "returned": hits.len(),
        "hits": hits,
    }))
}
