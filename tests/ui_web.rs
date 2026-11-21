#![cfg(feature = "ui")]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;

use runidbg_arm64_emu_tracer::script::rpc::{start_rpc_server, RpcServerConfig, RpcSource};
use runidbg_arm64_emu_tracer::tracer::{BinaryTracer, TraceLevel};
use runidbg_arm64_emu_tracer::ui::start_trace_ui_server;
use runidbg_arm64_emu_tracer::AndroidEmulator;
use serde_json::Value;

fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect ui server");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("split http");
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, body.to_string())
}

#[test]
fn trace_ui_and_rpc_ui_endpoints() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let idx_path = std::env::temp_dir().join("runidbg_ui_web_test.idx");
    let ext_path = idx_path.with_extension("ext");

    // 1. 生成一份真实 libstatic-webp.so Trace 文件
    let mut emu = AndroidEmulator::builder().build().unwrap();
    let module = emu.load_library(root.join("samples/libstatic-webp.so")).unwrap();
    let base = module.base_addr;
    let tracer = BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 4096, TraceLevel::Full).unwrap();
    emu.set_tracer(tracer).unwrap();
    emu.attach_tracer(base, base + module.image_size).unwrap();
    let ver = emu.call_symbol(&module, "WebPGetDecoderVersion", &[]).unwrap();
    assert!(ver > 0);
    emu.detach_tracer().unwrap();

    // 2. 启动离线 Trace Web UI 服务并测试全部 API
    let ui = start_trace_ui_server(&idx_path, Some(&ext_path), base, "127.0.0.1:0").unwrap();
    let addr = ui.local_addr();

    let (st, html) = http_get(addr, "/");
    assert_eq!(st, 200);
    assert!(html.contains("runidbg"));

    let (st, info_raw) = http_get(addr, "/api/info");
    assert_eq!(st, 200);
    let info: Value = serde_json::from_str(&info_raw).unwrap();
    assert_eq!(info["mode"], "trace");
    assert!(info["totalRecords"].as_u64().unwrap() >= 3);

    let (st, dump_raw) = http_get(addr, "/api/trace/dump?skip=0&limit=10");
    assert_eq!(st, 200);
    let dump: Value = serde_json::from_str(&dump_raw).unwrap();
    assert!(dump["returned"].as_u64().unwrap() >= 3);

    let (st, ct_raw) = http_get(addr, "/api/trace/calltree?maxDepth=4&minInsns=1");
    assert_eq!(st, 200);
    let ct: Value = serde_json::from_str(&ct_raw).unwrap();
    assert!(ct["returned"].as_u64().unwrap() >= 1);

    let (st, cr_raw) = http_get(addr, "/api/trace/crypto");
    assert_eq!(st, 200);
    let cr: Value = serde_json::from_str(&cr_raw).unwrap();
    assert!(cr["groups"].is_array());

    let (st, stats_raw) = http_get(addr, "/api/trace/stats?top=5");
    assert_eq!(st, 200);
    let stats: Value = serde_json::from_str(&stats_raw).unwrap();
    assert!(stats["uniquePcs"].as_u64().unwrap() >= 3);

    let (st, search_raw) = http_get(addr, &format!("/api/trace/search?val=0x{ver:x}"));
    assert_eq!(st, 200);
    let search: Value = serde_json::from_str(&search_raw).unwrap();
    assert!(search["hits"].is_array());

    ui.shutdown();
    let _ = fs::remove_file(&idx_path);
    let _ = fs::remove_file(&ext_path);

    // 3. 验证 RPC serve 模式在启用 ui feature 时挂载 GET /ui
    let script = r#"rpc.exports = { ping() { return "pong"; } };"#;
    let rpc = start_rpc_server(
        RpcSource::Inline {
            code: script.to_string(),
            base_dir: root,
        },
        RpcServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            ..Default::default()
        },
    )
    .unwrap();
    let (st, rpc_html) = http_get(rpc.local_addr(), "/ui");
    assert_eq!(st, 200);
    assert!(rpc_html.contains("RPC 服务实时看板"));
    rpc.shutdown();
}
