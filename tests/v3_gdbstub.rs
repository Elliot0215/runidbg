use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

use runidbg_arm64_emu_tracer::debug::GdbServer;
use runidbg_arm64_emu_tracer::AndroidEmulator;

fn send_rsp(stream: &mut TcpStream, reader: &mut BufReader<TcpStream>, payload: &str) -> String {
    let csum: u8 = payload
        .as_bytes()
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    let frame = format!("${payload}#{csum:02x}");
    stream.write_all(frame.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut b = [0u8; 1];
    loop {
        reader.read_exact(&mut b).unwrap();
        if b[0] == b'$' {
            break;
        }
    }
    let mut out = Vec::new();
    loop {
        reader.read_exact(&mut b).unwrap();
        if b[0] == b'#' {
            break;
        }
        out.push(b[0]);
    }
    let mut tail = [0u8; 2];
    reader.read_exact(&mut tail).unwrap();
    String::from_utf8(out).unwrap()
}

fn parse_u64_le_hex(hex: &str) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    u64::from_le_bytes(bytes)
}

#[test]
fn test_phase4_gdb_rsp_breakpoints_step_and_regs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let so_path = root.join("samples/libstatic-webp.so");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind gdbstub");
    let addr = listener.local_addr().unwrap();

    // 在独立线程中加载 .so 并启动 GDB Stub
    let (info_tx, info_rx) = std::sync::mpsc::sync_channel::<(u64, u64)>(1);
    let server_thread = thread::spawn(move || {
        let mut emu = AndroidEmulator::builder().build().expect("build emu");
        let module = emu.load_library(&so_path).expect("load webp");
        let fn_addr = module
            .find_symbol("WebPGetDecoderVersion")
            .expect("find WebPGetDecoderVersion");
        info_tx.send((module.base_addr, fn_addr)).unwrap();
        GdbServer::serve_listener(&mut emu, listener, fn_addr, &[]).expect("gdb server");
    });

    let (base_addr, fn_addr) = info_rx.recv().unwrap();
    let mut stream = TcpStream::connect(addr).expect("connect gdb client");
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // 1. Handshake & target.xml
    let supported = send_rsp(&mut stream, &mut reader, "qSupported");
    assert!(supported.contains("qXfer:features:read+"));
    assert_eq!(send_rsp(&mut stream, &mut reader, "QStartNoAckMode"), "OK");

    let xml = send_rsp(
        &mut stream,
        &mut reader,
        "qXfer:features:read:target.xml:0,1000",
    );
    assert!(xml.contains("<architecture>aarch64</architecture>"));

    // 2. Read ELF magic via `m<addr>,4`
    let mem_hex = send_rsp(&mut stream, &mut reader, &format!("m{base_addr:x},4"));
    assert_eq!(mem_hex, "7f454c46");

    // 3. Read PC (reg index 32 = 0x20)
    let pc_hex = send_rsp(&mut stream, &mut reader, "p20");
    assert_eq!(parse_u64_le_hex(&pc_hex), fn_addr);

    // 4. Set breakpoint at fn_addr + 4, continue -> must stop at fn_addr + 4 with S05
    let bp_addr = fn_addr + 4;
    assert_eq!(
        send_rsp(&mut stream, &mut reader, &format!("Z0,{bp_addr:x},4")),
        "OK"
    );
    assert_eq!(send_rsp(&mut stream, &mut reader, "c"), "S05");
    let stopped_pc = parse_u64_le_hex(&send_rsp(&mut stream, &mut reader, "p20"));
    assert_eq!(stopped_pc, bp_addr);

    // 5. Remove breakpoint, single-step once, then continue to completion (W00)
    assert_eq!(
        send_rsp(&mut stream, &mut reader, &format!("z0,{bp_addr:x},4")),
        "OK"
    );
    let step_resp = send_rsp(&mut stream, &mut reader, "s");
    assert!(step_resp == "S05" || step_resp == "W00");
    if step_resp == "S05" {
        assert_eq!(send_rsp(&mut stream, &mut reader, "c"), "W00");
    }

    // 6. Verify return value in X0 (reg index 0) > 0
    let x0 = parse_u64_le_hex(&send_rsp(&mut stream, &mut reader, "p0"));
    assert!(x0 > 0, "expected WebPGetDecoderVersion > 0, got {x0}");

    // 7. Detach cleanly
    assert_eq!(send_rsp(&mut stream, &mut reader, "D"), "OK");
    server_thread.join().expect("gdb server thread join");
}
