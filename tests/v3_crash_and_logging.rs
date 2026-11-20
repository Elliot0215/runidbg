use std::path::PathBuf;

use runidbg_arm64_emu_tracer::error::EmuError;
use runidbg_arm64_emu_tracer::AndroidEmulator;

#[test]
fn test_guest_crash_report_captures_disasm_regs_backtrace_and_breadcrumbs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    let module = emu
        .load_library(root.join("samples/libstatic-webp.so"))
        .expect("load webp");
    let fn_addr = module
        .find_symbol("WebPGetDecoderVersion")
        .expect("find symbol");

    // 写入一条前置 Breadcrumb，模拟崩溃前外部交互
    emu.breadcrumbs()
        .push("[JNI CallObjectMethod] com/example/App.getKey() -> 0x0");

    // Patch WebPGetDecoderVersion:
    //   mov x9, #0xdead (0xd29bd5a9)
    //   ldr x0, [x9]    (0xf9400120)  <-- 故意触发 READ_UNMAPPED 崩溃
    //   ret             (0xd65f03c0)
    let code: [u8; 12] = [
        0xa9, 0xd5, 0x9b, 0xd2,
        0x20, 0x01, 0x40, 0xf9,
        0xc0, 0x03, 0x5f, 0xd6,
    ];
    emu.uc_mut().mem_write(fn_addr, &code).expect("patch code");
    let page = fn_addr & !0xfff;
    let _ = emu.uc_mut().ctl_remove_cache(page, page + 0x1000);

    let err = emu
        .call_address(fn_addr, &[0x1111, 0x2222])
        .expect_err("must fail with GuestCrash");
    match err {
        EmuError::GuestCrash(report) => {
            assert!(report.reason.contains("READ_UNMAPPED"));
            assert_eq!(report.pc, fn_addr + 4);
            assert!(
                report.pc_location.contains("libstatic-webp.so")
                    && report.pc_location.contains("WebPGetDecoderVersion"),
                "unexpected pc_location: {}",
                report.pc_location
            );
            assert_eq!(report.x[9], 0xdead);
            assert!(report.disasm.iter().any(|d| d.is_pc && d.asm.contains("ldr")));
            assert!(!report.backtrace.is_empty());
            assert!(report
                .breadcrumbs
                .iter()
                .any(|b| b.contains("com/example/App.getKey()")));

            let formatted = report.format_pretty();
            assert!(formatted.contains("runidbg Guest Crash Report"));
            assert!(formatted.contains(">>>"));
        }
        other => panic!("expected GuestCrash, got: {other:?}"),
    }

    assert!(emu.last_crash().is_some());
}

#[cfg(all(feature = "js", feature = "rpc", feature = "mcp"))]
#[test]
fn test_js_last_crash_mcp_last_crash_and_rpc_request_id_sanitization() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use runidbg_arm64_emu_tracer::script::mcp::McpServer;
    use runidbg_arm64_emu_tracer::script::rpc::{start_rpc_server, RpcServerConfig, RpcSource};
    use serde_json::{json, Value};

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let so_path = root
        .join("samples/libstatic-webp.so")
        .to_string_lossy()
        .into_owned();

    // 1. MCP: 触发崩溃并通过 emu_last_crash 拉取完整报告
    let mut mcp = McpServer::new(&root, None).expect("McpServer::new");
    let eval_crash = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "emu_eval_js",
            "arguments": {
                "code": format!(r#"
                    const e = Emu.create();
                    __mcp.emus[1] = e;
                    const m = e.load({so_path:?});
                    const fnAddr = m.symbol("WebPGetDecoderVersion");
                    e.mem.patch(fnAddr, new Uint8Array([0xa9, 0xd5, 0x9b, 0xd2, 0x20, 0x01, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6]));
                    let caught = false;
                    try {{ e.call(fnAddr); }} catch (_) {{ caught = true; }}
                    const c = e.lastCrash();
                    ({{ caught, reason: c.reason, loc: c.pcLocation, hasDisasm: c.disasm.length > 0 }})
                "#)
            }
        }
    })
    .to_string();
    let r1: Value = serde_json::from_str(&mcp.handle_message(&eval_crash).unwrap()).unwrap();
    let payload1: Value =
        serde_json::from_str(r1["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload1["result"]["caught"], true);
    assert!(payload1["result"]["reason"]
        .as_str()
        .unwrap()
        .contains("READ_UNMAPPED"));
    assert_eq!(payload1["result"]["hasDisasm"], true);

    let last_crash_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "emu_last_crash",
            "arguments": { "emuId": 1 }
        }
    })
    .to_string();
    let r2: Value = serde_json::from_str(&mcp.handle_message(&last_crash_req).unwrap()).unwrap();
    let payload2: Value =
        serde_json::from_str(r2["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(payload2["formatted"]
        .as_str()
        .unwrap()
        .contains("runidbg Guest Crash Report"));

    // 2. RPC: 验证 X-Request-Id 响应头与脱敏后的崩溃错误摘要
    let script = format!(
        r#"
const emu = Emu.create();
const m = emu.load({so_path:?});
const fnAddr = m.symbol("WebPGetDecoderVersion");
emu.mem.patch(fnAddr, new Uint8Array([0xa9, 0xd5, 0x9b, 0xd2, 0x20, 0x01, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6]));
rpc.exports = {{
    crash() {{ return emu.call(fnAddr); }}
}};
"#
    );
    let handle = start_rpc_server(
        RpcSource::Inline {
            code: script,
            base_dir: root,
        },
        RpcServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            ..Default::default()
        },
    )
    .expect("start rpc");
    let addr = handle.local_addr();

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .write_all(
            format!(
                "POST /call/crash HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(
        head.to_ascii_lowercase().contains("x-request-id: req-"),
        "missing X-Request-Id header:\n{head}"
    );
    let body_json: Value = serde_json::from_str(body).unwrap();
    let err_msg = body_json["error"].as_str().unwrap();
    assert!(
        err_msg.contains("guest execution crashed") && !err_msg.contains("--- Memory Maps"),
        "expected sanitized crash summary without VMA leak, got: {err_msg}"
    );
    handle.shutdown();
}
