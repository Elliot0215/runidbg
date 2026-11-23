use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(all(feature = "js", feature = "rpc"))]
use std::path::Path;

use runidbg_arm64_emu_tracer::backend::{BackendWithData, CpuBackend};
use runidbg_arm64_emu_tracer::debug::GdbServer;
#[cfg(all(feature = "dynarmic", feature = "js", feature = "rpc"))]
use runidbg_arm64_emu_tracer::tape::Tape;
use runidbg_arm64_emu_tracer::timetravel::{
    RecordConfig, TimeTravelPlayer, TimeTravelStop, WatchKind,
};
use runidbg_arm64_emu_tracer::AndroidEmulator;
use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::RegisterARM64;

fn temp_tt_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "runidbg_tt_{}_{}.rtape",
        tag,
        std::process::id()
    ))
}

fn rsp_checksum(body: &str) -> u8 {
    body.bytes().fold(0u8, |acc, b| acc.wrapping_add(b))
}

fn rsp_send(stream: &mut TcpStream, body: &str) -> String {
    let pkt = format!("${body}#{:02x}", rsp_checksum(body));
    stream.write_all(pkt.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).unwrap();
        if buf[0] == b'$' {
            break;
        }
    }
    let mut out = Vec::new();
    loop {
        stream.read_exact(&mut buf).unwrap();
        if buf[0] == b'#' {
            let mut csum = [0u8; 2];
            stream.read_exact(&mut csum).unwrap();
            let _ = stream.write_all(b"+");
            break;
        }
        out.push(buf[0]);
    }
    String::from_utf8(out).unwrap()
}

fn decode_hex_str(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn decode_le_u64_hex(s: &str) -> u64 {
    let bytes = decode_hex_str(s);
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn encode_hex_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[test]
fn timetravel_zstd_determinism_seek_micro_ring_and_reverse_watch() {
    let tape_path = temp_tt_path("zstd_tt");
    let _ = std::fs::remove_file(&tape_path);

    let payload: Vec<u8> = (0..2048u32)
        .map(|i| ((i * 31) ^ (i >> 2) ^ 0xA5) as u8)
        .collect();

    let (dst, comp_len) = {
        let mut emu = AndroidEmulator::builder()
            .package_name("com.example.tt.zstd")
            .build()
            .unwrap();
        let zstd = emu
            .load_library("samples/libzstd-jni-1.5.7-28.so")
            .unwrap();
        let bound = emu
            .call_symbol(&zstd, "ZSTD_compressBound", &[payload.len() as u64])
            .unwrap();
        let src = emu
            .cpu_mut()
            .get_data_mut()
            .mem
            .alloc_heap(payload.len() as u64)
            .unwrap();
        let dst = emu.cpu_mut().get_data_mut().mem.alloc_heap(bound).unwrap();
        emu.cpu_mut().mem_write(src, &payload).unwrap();

        // 开启二期时间旅行录制：每 5000 条指令自动打 1 个 4KB 增量关键帧
        emu.start_time_travel_record(RecordConfig {
            keyframe_interval: 5_000,
            max_insns: 0,
            capture_jni: true,
        })
        .unwrap();
        let comp_len = emu
            .call_symbol(
                &zstd,
                "ZSTD_compress",
                &[dst, bound, src, payload.len() as u64, 1],
            )
            .unwrap();
        let bm_insn = emu.record_bookmark("after_compress").unwrap();
        assert!(bm_insn > 5_000, "expected >5000 insns, got {bm_insn}");
        let summary = emu.stop_time_travel_record(&tape_path).unwrap();
        let tl = summary.timeline.expect("summary must include timeline");
        assert_eq!(tl.end_insn, bm_insn);
        assert!(summary.checkpoints.len() >= 3);
        (dst, comp_len)
    };
    assert!(comp_len > 4);

    // 1. 离线加载磁带并运行全关键帧 bit-exact 确定性自检
    let mut player = TimeTravelPlayer::open(&tape_path).unwrap();
    let verified = player.verify_determinism().unwrap();
    assert!(verified >= 3);

    // 2. 验证 seek_bookmark + 连续 16 次单步回退（触发微快照环）再单步前进回来完全一致
    let total = player.total_insns();
    player.seek_bookmark("after_compress").unwrap();
    assert_eq!(player.current_insn(), total);
    let end_bytes = player.emu().cpu().mem_read_as_vec(dst, 4).unwrap();
    assert_eq!(
        u32::from_le_bytes(end_bytes.try_into().unwrap()),
        0xFD2F_B528,
        "ZSTD magic must be present at end_insn"
    );

    let mid = total / 2;
    player.seek_insn(mid).unwrap();
    let mut back_pcs = Vec::new();
    for step in 1..=16u64 {
        let stop = player.step_backward(1).unwrap();
        match stop {
            TimeTravelStop::Step { insn, pc } => {
                assert_eq!(insn, mid - step);
                back_pcs.push((insn, pc));
            }
            other => panic!("unexpected stop: {other:?}"),
        }
    }
    back_pcs.reverse();
    for &(expected_insn, expected_pc) in &back_pcs {
        assert_eq!(player.current_insn(), expected_insn);
        assert_eq!(
            player.emu().cpu().reg_read(RegisterARM64::PC).unwrap(),
            expected_pc
        );
        player.step_forward(1).unwrap();
    }
    assert_eq!(player.current_insn(), mid);

    // 3. 反向内存写观察点：从末尾倒查写入 ZSTD magic (dst[0..4]) 的那条 ARM64 指令
    player.seek_insn(total).unwrap();
    let hit = player
        .find_prev_mem_access(dst, 4, WatchKind::Write)
        .unwrap()
        .expect("must find instruction that wrote ZSTD magic to dst");
    assert!(hit.insn < total);
    assert!(hit.addr >= dst && hit.addr < dst + 4);
    // 在命中指令执行之前，dst 前 4 字节尚未是完整 magic；单步执行 1 条指令后即可看到写入结果！
    let after_step = player.step_forward(1).unwrap();
    match after_step {
        TimeTravelStop::Step { insn, .. } => assert_eq!(insn, hit.insn + 1),
        other => panic!("unexpected stop: {other:?}"),
    }

    let _ = std::fs::remove_file(&tape_path);
}

#[test]
fn timetravel_gdb_rsp_reverse_step_continue_watchpoint_and_monitor() {
    let tape_path = temp_tt_path("gdb_tt");
    let _ = std::fs::remove_file(&tape_path);

    let code_addr = 0x5200_0000u64;
    let buf_addr = 0x5200_2000u64;
    {
        let mut emu = AndroidEmulator::builder().build().unwrap();
        {
            let mut mem = std::mem::replace(
                &mut emu.cpu_mut().get_data_mut().mem,
                runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
            );
            mem.map_labeled(
                emu.cpu_mut(),
                code_addr,
                0x1000,
                Prot::READ | Prot::EXEC,
                "[tt:code]",
                0,
            )
            .unwrap();
            mem.map_labeled(
                emu.cpu_mut(),
                buf_addr,
                0x1000,
                Prot::READ | Prot::WRITE,
                "[tt:data]",
                0,
            )
            .unwrap();
            emu.cpu_mut().get_data_mut().mem = mem;
        }
        // 构造一段 ARM64 机器码：分 3 次往 [X0] 写入 0x11 / 0x22 / 0x33，中间穿插 NOP 跨过多个关键帧！
        // 0: mov x1, #0x11       (0xD280_0221)
        // 1: str w1, [x0]        (0xB900_0001)  <-- write #1 @ insn 1
        // 2..5: nop x4           (0xD503_201F)
        // 6: mov x1, #0x22       (0xD280_0441)
        // 7: str w1, [x0]        (0xB900_0001)  <-- write #2 @ insn 7
        // 8..11: nop x4          (0xD503_201F)
        // 12: mov x1, #0x33      (0xD280_0661)
        // 13: str w1, [x0]       (0xB900_0001)  <-- write #3 @ insn 13
        // 14: nop                (0xD503_201F)
        // 15: ret                (0xD65F_03C0)
        let insns: [u32; 16] = [
            0xD280_0221,
            0xB900_0001,
            0xD503_201F,
            0xD503_201F,
            0xD503_201F,
            0xD503_201F,
            0xD280_0441,
            0xB900_0001,
            0xD503_201F,
            0xD503_201F,
            0xD503_201F,
            0xD503_201F,
            0xD280_0661,
            0xB900_0001,
            0xD503_201F,
            0xD65F_03C0,
        ];
        let mut bytes = Vec::with_capacity(insns.len() * 4);
        for insn in insns {
            bytes.extend_from_slice(&insn.to_le_bytes());
        }
        emu.cpu_mut().mem_write(code_addr, &bytes).unwrap();

        // keyframe_interval = 4 强制跨越多个关键帧窗口，测试多窗口倒序扫描！
        emu.start_time_travel_record(RecordConfig {
            keyframe_interval: 4,
            max_insns: 0,
            capture_jni: false,
        })
        .unwrap();
        emu.call_address(code_addr, &[buf_addr]).unwrap();
        emu.stop_time_travel_record(&tape_path).unwrap();
    }

    let mut player = TimeTravelPlayer::open(&tape_path).unwrap();
    assert_eq!(player.total_insns(), 16);
    assert!(player.verify_determinism().unwrap() >= 4);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let client = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        let sup = rsp_send(&mut s, "qSupported");
        assert!(sup.contains("ReverseStep+"));
        assert!(sup.contains("ReverseContinue+"));

        // 1. monitor seek 16 -> 跳到录制末尾
        let seek_cmd = format!("qRcmd,{}", encode_hex_str(b"seek 16"));
        let seek_out = String::from_utf8(decode_hex_str(&rsp_send(&mut s, &seek_cmd))).unwrap();
        assert!(seek_out.contains("insn #16"), "got: {seek_out}");

        // 2. 设置写观察点 Z2 并连续 3 次反向继续 bc：应依次命中 write #3 -> #2 -> #1！
        assert_eq!(rsp_send(&mut s, &format!("Z2,{buf_addr:x},4")), "OK");
        let w3 = rsp_send(&mut s, "bc");
        assert_eq!(w3, format!("T05watch:{buf_addr:x};"));
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 13 * 4);
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p1")), 0x33);

        let w2 = rsp_send(&mut s, "bc");
        assert_eq!(w2, format!("T05watch:{buf_addr:x};"));
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 7 * 4);
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p1")), 0x22);

        let w1 = rsp_send(&mut s, "bc");
        assert_eq!(w1, format!("T05watch:{buf_addr:x};"));
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 4);
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p1")), 0x11);

        // 3. 第 4 次 bc 到达历史起点 -> 返回标准 GDB T05replaylog:begin;
        let begin = rsp_send(&mut s, "bc");
        assert_eq!(begin, "T05replaylog:begin;");
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr);

        // 4. 移除观察点，前向单步 3 次再反向单步 bs 3 次验证精确回到 code_addr
        assert_eq!(rsp_send(&mut s, &format!("z2,{buf_addr:x},4")), "OK");
        for _ in 0..3 {
            assert_eq!(rsp_send(&mut s, "s"), "S05");
        }
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 12);
        for _ in 0..3 {
            assert_eq!(rsp_send(&mut s, "bs"), "S05");
        }
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr);

        // 5. monitor info 正常响应
        let info_cmd = format!("qRcmd,{}", encode_hex_str(b"info"));
        let info_out = String::from_utf8(decode_hex_str(&rsp_send(&mut s, &info_cmd))).unwrap();
        assert!(info_out.contains("insn=0/16"), "got: {info_out}");

        let _ = s.write_all(b"$k#6b");
        let _ = s.flush();
    });

    GdbServer::serve_listener_time_travel(&mut player, listener).unwrap();
    client.join().unwrap();
    let _ = std::fs::remove_file(&tape_path);
}

#[cfg(all(feature = "js", feature = "rpc"))]
#[test]
fn timetravel_js_api_record_open_seek_and_reverse_watch() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let tape_path = temp_tt_path("js_zstd");
    let _ = std::fs::remove_file(&tape_path);
    let tape_str = tape_path.to_string_lossy().into_owned();

    let script = format!(
        r#"
        const emu = Emu.create({{ packageName: "com.example.js.tt", realClock: true }});
        const zstd = emu.load("samples/libzstd-jni-1.5.7-28.so");
        const src = emu.mem.alloc(512);
        const payload = new Uint8Array(512);
        for (let i = 0; i < 512; i++) payload[i] = (i * 17) & 0xff;
        emu.mem.writeBytes(src, payload);
        const bound = zstd.call("ZSTD_compressBound", 512);
        const dst = emu.mem.alloc(bound);

        emu.record.start({{ keyframeInterval: 4000 }});
        const compLen = zstd.call("ZSTD_compress", dst, bound, src, 512, 1);
        const bmInsn = emu.record.bookmark("zstd_done");
        const summary = emu.record.stop({tape:?});

        const tt = Emu.openTimeTravel({tape:?});
        const det = tt.verifyDeterminism();
        tt.seekBookmark("zstd_done");
        const hit = tt.findPrevWrite(dst, 4);
        const back = tt.stepBack(3);
        const fwd = tt.stepForward(3);
        const regs = tt.regs();

        rpc.exports = {{
            result() {{
                return {{
                    compLen,
                    bmInsn,
                    totalInsns: tt.totalInsns,
                    timelineEnd: summary.timeline.endInsn,
                    verifiedKeyframes: det.verifiedKeyframes,
                    hitInsn: hit ? hit.insn : -1,
                    hitPc: hit ? hit.pc : 0,
                    backInsn: back.insn,
                    fwdInsn: fwd.insn,
                    pcAtFwd: regs.pc,
                }};
            }},
        }};
        "#,
        tape = tape_str
    );

    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    session.eval_source(&script).unwrap();
    let r: serde_json::Value =
        serde_json::from_str(&session.call_rpc_json("result", "[]").unwrap()).unwrap();
    assert!(r["compLen"].as_u64().unwrap() > 4);
    assert_eq!(r["bmInsn"], r["totalInsns"]);
    assert_eq!(r["timelineEnd"], r["totalInsns"]);
    assert!(r["verifiedKeyframes"].as_u64().unwrap() >= 2);
    let hit_insn = r["hitInsn"].as_u64().unwrap();
    assert!(hit_insn > 0 && hit_insn < r["totalInsns"].as_u64().unwrap());
    assert_eq!(r["backInsn"].as_u64().unwrap(), hit_insn - 3);
    assert_eq!(r["fwdInsn"].as_u64().unwrap(), hit_insn);
    assert_eq!(r["pcAtFwd"], r["hitPc"]);

    let _ = std::fs::remove_file(&tape_path);
}

#[cfg(all(feature = "dynarmic", feature = "js", feature = "rpc"))]
#[test]
fn timetravel_metasec_realclock_jni_offline_replay_determinism() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let metasec_so = Path::new("samples/metasec/libmetasec_ov.so");
    if !metasec_so.exists() {
        return;
    }

    let init_tape = temp_tt_path("metasec_init_p1");
    let tt_tape = temp_tt_path("metasec_sign_p2");
    let _ = std::fs::remove_file(&init_tape);
    let _ = std::fs::remove_file(&tt_tape);
    let init_str = init_tape.to_string_lossy().into_owned();
    let tt_str = tt_tape.to_string_lossy().into_owned();

    // 1. Dynarmic 极速初始化 -> 存一期磁带 -> 切 Unicorn + realClock=true + JS JNI Hook 精录签名时间旅行磁带！
    let record_script = format!(
        r#"
        const LICENSE = "Zs81WLZ0TYDnPHhokfrih9f2UVKMYsD6ygiN+al3YbsQTM5dSPr+VANPNr2yt/6QZ3JuYhSmDYBLiuwMS3cvrr+1/8cAwLDSGF69eSzBCn1V3+2mBLMP7NPqp1q3bRDYgEewnEm4DNlPCPW5U2nedHmDVvrEKzBMl8RWBPCnBmvNXNMcPonBLsZYQk+XnBO5ZUm5rFr56W5sezAigX8gmCIS9kaPMASRFaEb65F/f8pFvVlEWoxkWkVeUf8Z9pPT0ZaRrezEtk4JvuNwLu0lL1UHdxpc+feECCxfrESn8hKSFDyzg1zQ0YNT+ILxVw34ElmJ30SP74RN/dhjNJ5pDBtlu+RNtU1ebPwnGxtu79WacDkiCJjsmdrzGrGwbQ4nBl8bugOKsWV4FF/60FPwpZ8iZ+M=";
        const SAMPLE_DIR = "samples/metasec";
        const dyn = Emu.create({{
            backend: "dynarmic",
            packageName: "com.zhiliaoapp.musically",
            searchPaths: [SAMPLE_DIR],
            device: "pixel8pro",
            realClock: true,
        }});
        dyn.jni.hook("com/bytedance/mobsec/metasec/ov/MS", {{
            b(op) {{
                if (op === 65539) return "/data/user/0/com.zhiliaoapp.musically/files/.msdata";
                if (op === 16777233) return "47.6.3";
                return null;
            }},
        }});
        const mod = dyn.load(`${{SAMPLE_DIR}}/libmetasec_ov.so`);
        dyn.jniOnLoad(mod);
        const a0Cls = dyn.jni.findClass("ms/bd/o/a0");
        const strCls = dyn.jni.findClass("java/lang/String");
        dyn.mem.writeU64(mod.base + 0x209198, strCls);
        const cfg = ["1233", "", "", LICENSE, "v04.04.06-ov-android", "googleplay", "7000000000000000001", "", "7000000000000000002", "", "0", "0", "5", [], []];
        const cfgRef = dyn.jni.newString(JSON.stringify(cfg));
        dyn.call(mod.base + 0x120be0, dyn.jni.envPtr, a0Cls, 67108865, 0, 0, cfgRef, 0);
        dyn.saveTape({init:?}, "after_init");

        // 跨后端切入 Unicorn，开启 realClock + JS JNI Hook + 二期时间旅行精录
        const uc = Emu.loadTape({init:?}, {{ backend: "unicorn", checkpoint: "after_init", realClock: true }});
        uc.jni.hook("com/bytedance/mobsec/metasec/ov/MS", {{
            b(op) {{
                if (op === 65539) return "/data/user/0/com.zhiliaoapp.musically/files/.msdata";
                if (op === 16777233) return "47.6.3";
                return null;
            }},
        }});
        const ucMod = uc.module("libmetasec_ov.so");
        const ucA0 = uc.jni.findClass("ms/bd/o/a0");
        const urlRef = uc.jni.newString("https://api16-normal-no1a.tiktokv.eu/aweme/v2/comment/list/?aweme_id=99&aid=1233&device_id=7000000000000000001");
        const hdrRef = uc.jni.newStringArray(["cookie", "sessionid=ttdemo", "user-agent", "ua"]);
        uc.record.start({{ keyframeInterval: 100000, captureJni: true }});
        const arr = uc.jni.getStringArray(uc.call(ucMod.base + 0x120be0, uc.jni.envPtr, ucA0, 50331649, 0, 0, urlRef, hdrRef));
        uc.record.bookmark("sign_done");
        const summary = uc.record.stop({tt:?});
        rpc.exports = {{
            info() {{
                return {{
                    gorgon: arr[arr.indexOf("X-Gorgon") + 1],
                    totalInsns: summary.timeline.endInsn,
                    clockEvents: summary.timeline.clockEvents,
                    jniEvents: summary.timeline.jniEvents,
                }};
            }},
        }};
        "#,
        init = init_str,
        tt = tt_str
    );

    let s = JsSession::new(&[], Path::new("."), true).unwrap();
    s.eval_source(&record_script).unwrap();
    let rec_info: serde_json::Value =
        serde_json::from_str(&s.call_rpc_json("info", "[]").unwrap()).unwrap();
    assert!(rec_info["gorgon"].as_str().unwrap_or("").starts_with("8404"));
    assert!(rec_info["totalInsns"].as_u64().unwrap() > 100_000);
    assert!(
        rec_info["clockEvents"].as_u64().unwrap() > 0,
        "realClock=true should capture clock events"
    );

    // 2. 纯 Rust 完全离线脱离 JS 运行时加载，逐关键帧 bit-exact 校验确定性！
    let inspected = Tape::inspect_file(&tt_tape).unwrap();
    assert!(inspected.timeline.is_some());
    let mut player = TimeTravelPlayer::open(&tt_tape).unwrap();
    let verified_kfs = player.verify_determinism().unwrap();
    assert!(
        verified_kfs >= 2,
        "expected >=2 verified keyframes on real TikTok metasec_ov.so, got {verified_kfs}"
    );

    // 3. 验证单步回退 & seek 到末尾
    player.seek_bookmark("sign_done").unwrap();
    let end_insn = player.current_insn();
    player.step_backward(5).unwrap();
    assert_eq!(player.current_insn(), end_insn - 5);

    let _ = std::fs::remove_file(&init_tape);
    let _ = std::fs::remove_file(&tt_tape);
}

fn build_mem_rw_test_tape(tag: &str, kf_interval: u64) -> (std::path::PathBuf, u64, u64) {
    let tape_path = temp_tt_path(tag);
    let _ = std::fs::remove_file(&tape_path);
    let code_addr = 0x5210_0000u64;
    let buf_addr = 0x5210_2000u64;
    let mut emu = AndroidEmulator::builder().build().unwrap();
    {
        let mut mem = std::mem::replace(
            &mut emu.cpu_mut().get_data_mut().mem,
            runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
        );
        mem.map_labeled(
            emu.cpu_mut(),
            code_addr,
            0x1000,
            Prot::READ | Prot::EXEC,
            "[tt:rw_code]",
            0,
        )
        .unwrap();
        mem.map_labeled(
            emu.cpu_mut(),
            buf_addr,
            0x1000,
            Prot::READ | Prot::WRITE,
            "[tt:rw_data]",
            0,
        )
        .unwrap();
        emu.cpu_mut().get_data_mut().mem = mem;
    }
    // 0: mov x1, #0x11       (0xD280_0221)
    // 1: str w1, [x0]        (0xB900_0001)  <-- write #1 @ insn 1
    // 2: ldr w2, [x0]        (0xB940_0002)  <-- read  #1 @ insn 2
    // 3: nop                 (0xD503_201F)
    // 4: mov x1, #0x22       (0xD280_0441)
    // 5: str w1, [x0]        (0xB900_0001)  <-- write #2 @ insn 5
    // 6: nop                 (0xD503_201F)
    // 7: ldr w3, [x0]        (0xB940_0003)  <-- read  #2 @ insn 7
    // 8: mov x1, #0x33       (0xD280_0661)
    // 9: str w1, [x0]        (0xB900_0001)  <-- write #3 @ insn 9
    // 10: ret                (0xD65F_03C0)
    let insns: [u32; 11] = [
        0xD280_0221,
        0xB900_0001,
        0xB940_0002,
        0xD503_201F,
        0xD280_0441,
        0xB900_0001,
        0xD503_201F,
        0xB940_0003,
        0xD280_0661,
        0xB900_0001,
        0xD65F_03C0,
    ];
    let mut bytes = Vec::with_capacity(insns.len() * 4);
    for insn in insns {
        bytes.extend_from_slice(&insn.to_le_bytes());
    }
    emu.cpu_mut().mem_write(code_addr, &bytes).unwrap();
    emu.start_time_travel_record(RecordConfig {
        keyframe_interval: kf_interval,
        max_insns: 0,
        capture_jni: false,
    })
    .unwrap();
    emu.call_address(code_addr, &[buf_addr]).unwrap();
    emu.stop_time_travel_record(&tape_path).unwrap();
    (tape_path, code_addr, buf_addr)
}

#[test]
fn timetravel_forward_next_mem_access_read_access_and_preserve_cursor_on_miss() {
    let (tape_path, code_addr, buf_addr) = build_mem_rw_test_tape("rw_next", 3);
    let mut player = TimeTravelPlayer::open(&tape_path).unwrap();
    assert_eq!(player.total_insns(), 11);
    assert!(player.verify_determinism().unwrap() >= 3);

    // 1. 从 insn=0 开始连续调用 find_next_mem_access(Write)：必须精确命中 insn 1（不可双重跳过 cur_insn+1！）、5、9
    player.seek_insn(0).unwrap();
    let h1 = player
        .find_next_mem_access(buf_addr, 4, WatchKind::Write)
        .unwrap()
        .expect("must hit write #1 at insn 1");
    assert_eq!(h1.insn, 1);
    assert_eq!(h1.pc, code_addr + 4);
    assert!(h1.is_write);
    assert_eq!(player.current_insn(), 1);

    let h2 = player
        .find_next_mem_access(buf_addr, 4, WatchKind::Write)
        .unwrap()
        .expect("must hit write #2 at insn 5");
    assert_eq!(h2.insn, 5);
    assert_eq!(player.current_insn(), 5);

    let h3 = player
        .find_next_mem_access(buf_addr, 4, WatchKind::Write)
        .unwrap()
        .expect("must hit write #3 at insn 9");
    assert_eq!(h3.insn, 9);
    assert_eq!(player.current_insn(), 9);

    // 未命中时必须保持原 cur_insn = 9 不漂移
    assert!(player
        .find_next_mem_access(buf_addr, 4, WatchKind::Write)
        .unwrap()
        .is_none());
    assert_eq!(player.current_insn(), 9);

    // 2. 验证 WatchKind::Read（前向与反向）
    player.seek_insn(0).unwrap();
    let r1 = player
        .find_next_mem_access(buf_addr, 4, WatchKind::Read)
        .unwrap()
        .expect("read #1 at insn 2");
    assert_eq!(r1.insn, 2);
    assert!(!r1.is_write);
    assert_eq!(r1.kind, WatchKind::Read);

    let r2 = player
        .find_next_mem_access(buf_addr, 4, WatchKind::Read)
        .unwrap()
        .expect("read #2 at insn 7");
    assert_eq!(r2.insn, 7);
    assert!(!r2.is_write);

    // 3. 验证 WatchKind::Access 反向扫描依次命中 9(W) -> 7(R) -> 5(W) -> 2(R) -> 1(W)
    player.seek_insn(11).unwrap();
    let expected = [(9u64, true), (7, false), (5, true), (2, false), (1, true)];
    for (exp_insn, exp_w) in expected {
        let a = player
            .find_prev_mem_access(buf_addr, 4, WatchKind::Access)
            .unwrap()
            .expect("expected access hit");
        assert_eq!(a.insn, exp_insn);
        assert_eq!(a.kind, WatchKind::Access);
        assert_eq!(a.is_write, exp_w);
    }

    // 4. 反向未命中未访问地址时，必须保持原 cur_insn 不静默归零
    player.seek_insn(8).unwrap();
    assert!(player
        .find_prev_mem_access(buf_addr + 0x100, 4, WatchKind::Write)
        .unwrap()
        .is_none());
    assert_eq!(player.current_insn(), 8);

    // 5. 空断点/空观察点 continue_forward / continue_backward 快路径
    let empty = std::collections::HashSet::new();
    match player.continue_forward(&empty, &[]).unwrap() {
        TimeTravelStop::LogEnd { insn, .. } => assert_eq!(insn, 11),
        other => panic!("expected LogEnd, got {other:?}"),
    }
    match player.continue_backward(&empty, &[]).unwrap() {
        TimeTravelStop::LogBegin { insn, .. } => assert_eq!(insn, 0),
        other => panic!("expected LogBegin, got {other:?}"),
    }

    let _ = std::fs::remove_file(&tape_path);
}

#[test]
fn timetravel_gdb_live_fork_awatch_swbreak_and_forward_watch_post_insn() {
    let (tape_path, code_addr, buf_addr) = build_mem_rw_test_tape("gdb_adv", 3);
    let mut player = TimeTravelPlayer::open(&tape_path).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let client = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        let sup = rsp_send(&mut s, "qSupported");
        assert!(sup.contains("PacketSize=1000"));
        assert!(sup.contains("swbreak+;hwbreak+"));

        // 1. Z0 软件断点 + 正向 c 必须返回 T05swbreak:;
        let bp_pc = code_addr + 4 * 4; // insn 4: mov x1, #0x22
        assert_eq!(rsp_send(&mut s, &format!("Z0,{bp_pc:x},4")), "OK");
        assert_eq!(rsp_send(&mut s, "c"), "T05swbreak:;");
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), bp_pc);
        assert_eq!(rsp_send(&mut s, &format!("z0,{bp_pc:x},4")), "OK");

        // 2. Z2 写观察点 + 正向 c 停在指令执行后（insn 5 执行完毕 -> 停在 insn 6），此时读内存立即看到新值 0x22！
        assert_eq!(rsp_send(&mut s, &format!("Z2,{buf_addr:x},4")), "OK");
        assert_eq!(rsp_send(&mut s, "c"), format!("T05watch:{buf_addr:x};"));
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 6 * 4);
        let mem_hex = rsp_send(&mut s, &format!("m{buf_addr:x},4"));
        let val_after = u32::from_le_bytes(decode_hex_str(&mem_hex).try_into().unwrap());
        assert_eq!(val_after, 0x22, "forward watchpoint must stop post-insn with new value committed");
        assert_eq!(rsp_send(&mut s, &format!("z2,{buf_addr:x},4")), "OK");

        // 3. Z4 访问观察点（含非法 len=0 返回 E01）+ 反向 bc 必须返回 T05awatch:;
        assert_eq!(rsp_send(&mut s, &format!("Z4,{buf_addr:x},0")), "E01");
        assert_eq!(rsp_send(&mut s, &format!("Z4,{buf_addr:x},4")), "OK");
        let seek_end = format!("qRcmd,{}", encode_hex_str(b"seek 11"));
        let _ = rsp_send(&mut s, &seek_end);
        assert_eq!(rsp_send(&mut s, "bc"), format!("T05awatch:{buf_addr:x};")); // insn 9 (write)
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 9 * 4);
        assert_eq!(rsp_send(&mut s, "bc"), format!("T05awatch:{buf_addr:x};")); // insn 7 (read)
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 7 * 4);
        assert_eq!(rsp_send(&mut s, &format!("z4,{buf_addr:x},4")), "OK");

        // 4. 失败的内存写入 M0,4:... 返回 E0E 且不得误触发 Live Fork
        let seek_0 = format!("qRcmd,{}", encode_hex_str(b"seek 0"));
        let _ = rsp_send(&mut s, &seek_0);
        assert_eq!(rsp_send(&mut s, "M0,4:01000000"), "E0E");
        let info_cmd = format!("qRcmd,{}", encode_hex_str(b"info"));
        let info_out = String::from_utf8(decode_hex_str(&rsp_send(&mut s, &info_cmd))).unwrap();
        assert!(info_out.contains("forked=false"), "failed M must not fork: {info_out}");

        // 5. 在 insn=0 通过 P 修改寄存器进入 Live Fork -> 单步推进 -> bs 干净退出 Live Fork 并恢复原 insn=0！
        assert_eq!(rsp_send(&mut s, "P1=efbeadde00000000"), "OK");
        let info_fork = String::from_utf8(decode_hex_str(&rsp_send(&mut s, &info_cmd))).unwrap();
        assert!(info_fork.contains("forked=true"), "got: {info_fork}");
        assert_eq!(rsp_send(&mut s, "s"), "S05");
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr + 4);
        assert_eq!(rsp_send(&mut s, "bs"), "T05replaylog:begin;");
        let info_back = String::from_utf8(decode_hex_str(&rsp_send(&mut s, &info_cmd))).unwrap();
        assert!(info_back.contains("forked=false"), "bs at start_insn must exit Live Fork: {info_back}");
        assert_eq!(decode_le_u64_hex(&rsp_send(&mut s, "p20")), code_addr);

        // 6. monitor rw 支持十六进制长度并拒绝非法长度 0
        let bad_rw = format!("qRcmd,{}", encode_hex_str(format!("rw 0x{buf_addr:x} 0").as_bytes()));
        let bad_out = String::from_utf8(decode_hex_str(&rsp_send(&mut s, &bad_rw))).unwrap();
        assert!(bad_out.contains("Invalid watch length"), "got: {bad_out}");
        let _ = rsp_send(&mut s, &seek_end);
        let hex_rw = format!("qRcmd,{}", encode_hex_str(format!("rw 0x{buf_addr:x} 0x4").as_bytes()));
        let rw_out = String::from_utf8(decode_hex_str(&rsp_send(&mut s, &hex_rw))).unwrap();
        assert!(rw_out.contains("insn #9"), "got: {rw_out}");

        let _ = s.write_all(b"$k#6b");
        let _ = s.flush();
    });

    GdbServer::serve_listener_time_travel(&mut player, listener).unwrap();
    client.join().unwrap();
    let _ = std::fs::remove_file(&tape_path);
}

#[test]
fn timetravel_multi_call_host_fs_zero_insn_max_insns_and_guards() {
    // 1. 多调用录制（C2）+ 跨调用边界 verify_determinism / seek / 反向观察点
    let multi_tape = temp_tt_path("multi_call");
    let _ = std::fs::remove_file(&multi_tape);
    let code_addr = 0x5220_0000u64;
    let buf_addr = 0x5220_2000u64;
    {
        let mut emu = AndroidEmulator::builder().build().unwrap();
        {
            let mut mem = std::mem::replace(
                &mut emu.cpu_mut().get_data_mut().mem,
                runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
            );
            mem.map_labeled(emu.cpu_mut(), code_addr, 0x1000, Prot::READ | Prot::EXEC, "[mc:code]", 0).unwrap();
            mem.map_labeled(emu.cpu_mut(), buf_addr, 0x1000, Prot::READ | Prot::WRITE, "[mc:data]", 0).unwrap();
            emu.cpu_mut().get_data_mut().mem = mem;
        }
        // func(buf, val): str w1, [x0]; add x0, x1, #1; ret (3 insns per call)
        let insns: [u32; 3] = [0xB900_0001, 0x9100_0420, 0xD65F_03C0];
        let mut bytes = Vec::new();
        for insn in insns {
            bytes.extend_from_slice(&insn.to_le_bytes());
        }
        emu.cpu_mut().mem_write(code_addr, &bytes).unwrap();

        let snap_before = emu.capture_snapshot().unwrap();
        emu.start_time_travel_record(RecordConfig {
            keyframe_interval: 2,
            max_insns: 0,
            capture_jni: false,
        })
        .unwrap();
        // 录制期间禁止 restore_snapshot / load_library_bytes / 重复 start
        assert!(emu.restore_snapshot(&snap_before).is_err());
        assert!(emu.load_library_bytes("dummy.so", &[0u8; 64], false).is_err());
        assert!(emu.start_time_travel_record(RecordConfig::default()).is_err());

        let r1 = emu.call_address(code_addr, &[buf_addr, 0xAA]).unwrap();
        assert_eq!(r1, 0xAB);
        let r2 = emu.call_address(code_addr, &[buf_addr, 0xBB]).unwrap();
        assert_eq!(r2, 0xBC);
        assert_eq!(emu.recorded_insns(), 6);
        emu.stop_time_travel_record(&multi_tape).unwrap();
    }

    let mut player = TimeTravelPlayer::open(&multi_tape).unwrap();
    assert_eq!(player.total_insns(), 6);
    player.verify_determinism().unwrap();
    // 从第 2 次调用末尾反向追踪两次写入：依次命中 call #2 (insn 3, val=0xBB) 与 call #1 (insn 0, val=0xAA)
    player.seek_insn(6).unwrap();
    let w2 = player.find_prev_mem_access(buf_addr, 4, WatchKind::Write).unwrap().unwrap();
    assert_eq!(w2.insn, 3);
    assert_eq!(w2.value as u64, 0xBB);
    let w1 = player.find_prev_mem_access(buf_addr, 4, WatchKind::Write).unwrap().unwrap();
    assert_eq!(w1.insn, 0);
    assert_eq!(w1.value as u64, 0xAA);
    let _ = std::fs::remove_file(&multi_tape);

    // 2. 零指令录制 & Phase 1 磁带拒绝 & max_insns 截断不误报 ExecutionTimeout
    let zero_tape = temp_tt_path("zero_insn");
    let p1_tape = temp_tt_path("phase1_only");
    let max_tape = temp_tt_path("max_insns");
    for p in [&zero_tape, &p1_tape, &max_tape] {
        let _ = std::fs::remove_file(p);
    }
    {
        let mut emu = AndroidEmulator::builder().build().unwrap();
        emu.save_tape(&p1_tape, "p1_base").unwrap();
        assert!(TimeTravelPlayer::open(&p1_tape).is_err());

        emu.start_time_travel_record(RecordConfig::default()).unwrap();
        let sum = emu.stop_time_travel_record(&zero_tape).unwrap();
        assert_eq!(sum.timeline.unwrap().end_insn, 0);
        let zplayer = TimeTravelPlayer::open(&zero_tape).unwrap();
        assert_eq!(zplayer.total_insns(), 0);
    }
    {
        // max_insns=5 搭配 set_execution_limits(2s, 1000) 截断不得误报 ExecutionTimeout
        let mut emu = AndroidEmulator::builder().build().unwrap();
        emu.set_execution_limits(2_000_000, 1000);
        {
            let mut mem = std::mem::replace(
                &mut emu.cpu_mut().get_data_mut().mem,
                runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
            );
            mem.map_labeled(emu.cpu_mut(), code_addr, 0x1000, Prot::READ | Prot::EXEC, "[max:code]", 0).unwrap();
            emu.cpu_mut().get_data_mut().mem = mem;
        }
        // 10 x NOP + RET
        let mut bytes = Vec::new();
        for _ in 0..10 {
            bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes());
        }
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        emu.cpu_mut().mem_write(code_addr, &bytes).unwrap();
        emu.start_time_travel_record(RecordConfig {
            keyframe_interval: 2,
            max_insns: 5,
            capture_jni: false,
        })
        .unwrap();
        let _ = emu.call_address(code_addr, &[]).expect("max_insns stop must not trigger ExecutionTimeout");
        assert_eq!(emu.recorded_insns(), 5);
        assert!(emu.last_crash().is_none());
        emu.stop_time_travel_record(&max_tape).unwrap();
    }
    for p in [&zero_tape, &p1_tape, &max_tape] {
        let _ = std::fs::remove_file(p);
    }

    // 3. 宿主机只读 sysroot 文件捕获 + 删除原宿主机文件后离线只读回放（H3）
    let host_dir = std::env::temp_dir().join(format!("runidbg_tt_sysroot_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&host_dir);
    std::fs::create_dir_all(&host_dir).unwrap();
    let host_file = host_dir.join("secret.txt");
    std::fs::write(&host_file, b"offline-sysroot-payload").unwrap();
    let hfs_tape = temp_tt_path("host_fs");
    let _ = std::fs::remove_file(&hfs_tape);
    {
        let mut emu = AndroidEmulator::builder().build().unwrap();
        emu.vfs_mut().mount_readonly("/system", &host_dir);
        emu.start_time_travel_record(RecordConfig::default()).unwrap();
        let fd = {
            let d = emu.cpu_mut().get_data_mut();
            d.vfs.open("/system/secret.txt", &d.mem)
        };
        assert!(fd >= 3);
        let data = emu.vfs_mut().read(fd as i32, 64).unwrap();
        assert_eq!(data, b"offline-sysroot-payload");
        let _ = emu.vfs_mut().close(fd as i32);
        let sum = emu.stop_time_travel_record(&hfs_tape).unwrap();
        assert_eq!(sum.timeline.unwrap().host_file_count, 1);
    }
    // 彻底删除宿主机原目录与文件，证明离线回放 100% 不依赖原盘文件且保持只读语义
    std::fs::remove_dir_all(&host_dir).unwrap();
    let mut hplayer = TimeTravelPlayer::open(&hfs_tape).unwrap();
    let fd = {
        let d = hplayer.emu_mut().cpu_mut().get_data_mut();
        d.vfs.open("/system/secret.txt", &d.mem)
    };
    assert!(fd >= 3);
    assert_eq!(
        hplayer.emu_mut().vfs_mut().read(fd as i32, 64).unwrap(),
        b"offline-sysroot-payload"
    );
    // 只读 sysroot 语义：不得污染 overlay_files，因此 unlink 必须返回 ENOENT (<0)
    assert!(hplayer.emu_mut().vfs_mut().unlink("/system/secret.txt") < 0);
    let _ = std::fs::remove_file(&hfs_tape);
}

#[cfg(all(feature = "js", feature = "rpc"))]
#[test]
fn timetravel_js_edge_cases_replace_guard_null_opts_and_close() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let tape_path = temp_tt_path("js_edge");
    let _ = std::fs::remove_file(&tape_path);
    let tape_str = tape_path.to_string_lossy().into_owned();

    let script = format!(
        r#"
        const emu = Emu.create({{ packageName: "com.example.tt.edge" }});
        const mod = emu.load("samples/libzstd-jni-1.5.7-28.so");
        const fnAddr = mod.symbol("ZSTD_versionNumber");

        // 1. 活跃 replace hook 时必须拒绝启动时间旅行录制（避免把补丁 RET 烘烤进代码页）
        const h = emu.hook.replace(fnAddr, () => 0x1234);
        let replaceBlocked = false;
        try {{
            emu.record.start();
        }} catch (e) {{
            replaceBlocked = String(e).includes("Native Hook");
        }}
        h.detach();

        // 2. null 可选参数应回退安全默认值（不可禁用 keyframeInterval / captureJni）
        emu.record.start({{ keyframeInterval: null, maxInsns: null, captureJni: null }});
        const isRec = emu.record.isRecording();
        mod.call("ZSTD_versionNumber");
        const insns = emu.record.insns();
        const summary = emu.record.stop({tape:?});
        const isRecAfter = emu.record.isRecording();

        // 3. stepForward(0)/stepBack(0) 保持原地不动，负数/小数步数抛 RangeError
        const tt = Emu.openTimeTravel({tape:?});
        const s0 = tt.stepForward(0);
        const sb0 = tt.stepBack(0);
        let negBlocked = false;
        try {{ tt.stepForward(-1); }} catch (e) {{ negBlocked = true; }}
        let fracBlocked = false;
        try {{ tt.seekInsn(1.5); }} catch (e) {{ fracBlocked = true; }}

        // 4. tt.mem.readU32 / readU64 / close() 资源释放校验
        const u32Val = tt.mem.readU32(fnAddr);
        const u64Val = tt.mem.readU64(fnAddr);
        const closed1 = tt.close();
        const closed2 = tt.close();
        let closedBlocked = false;
        try {{ tt.currentInsn(); }} catch (e) {{ closedBlocked = true; }}

        rpc.exports = {{
            check() {{
                return {{
                    replaceBlocked,
                    isRec,
                    isRecAfter,
                    insns,
                    kfInterval: summary.timeline.keyframeInterval,
                    s0Insn: s0.insn,
                    sb0Insn: sb0.insn,
                    negBlocked,
                    fracBlocked,
                    u32NonZero: u32Val !== 0,
                    u64IsBigInt: typeof u64Val === "bigint",
                    closed1,
                    closed2,
                    closedBlocked,
                }};
            }},
        }};
        "#,
        tape = tape_str
    );

    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    session.eval_source(&script).unwrap();
    let r: serde_json::Value =
        serde_json::from_str(&session.call_rpc_json("check", "[]").unwrap()).unwrap();
    assert_eq!(r["replaceBlocked"], true);
    assert_eq!(r["isRec"], true);
    assert_eq!(r["isRecAfter"], false);
    assert!(r["insns"].as_u64().unwrap() >= 1);
    assert_eq!(r["kfInterval"], 100000);
    assert_eq!(r["s0Insn"], 0);
    assert_eq!(r["sb0Insn"], 0);
    assert_eq!(r["negBlocked"], true);
    assert_eq!(r["fracBlocked"], true);
    assert_eq!(r["u32NonZero"], true);
    assert_eq!(r["u64IsBigInt"], true);
    assert_eq!(r["closed1"], true);
    assert_eq!(r["closed2"], false);
    assert_eq!(r["closedBlocked"], true);

    let _ = std::fs::remove_file(&tape_path);
}

#[cfg(feature = "ui")]
#[test]
fn timetravel_web_ui_http_endpoints_end_to_end() {
    use runidbg_arm64_emu_tracer::ui::start_timetravel_ui_server;

    fn http_req(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut s = TcpStream::connect(addr).unwrap();
        let body_bytes = body.unwrap_or("").as_bytes();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body_bytes.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        if !body_bytes.is_empty() {
            s.write_all(body_bytes).unwrap();
        }
        s.flush().unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        let (head, payload) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);
        (status, payload.to_string())
    }

    let (tape_path, code_addr, buf_addr) = build_mem_rw_test_tape("web_ui", 3);
    let handle = start_timetravel_ui_server(&tape_path, "127.0.0.1:0").unwrap();
    let addr = handle.local_addr();

    // 1. GET / 返回嵌入单页 HTML（含时间旅行面板）
    let (st, html) = http_req(addr, "GET", "/", None);
    assert_eq!(st, 200);
    assert!(html.contains("view-tt") && html.contains("/api/tt/watch"));

    // 2. GET /api/info 返回 mode=timetravel 与关键帧列表
    let (st, body) = http_req(addr, "GET", "/api/info", None);
    assert_eq!(st, 200);
    let info: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(info["mode"], "timetravel");
    assert_eq!(info["totalInsns"], 11);
    assert!(info["keyframes"].as_array().unwrap().len() >= 3);

    // 3. GET /api/tt/state 返回当前寄存器与反汇编上下文
    let (st, body) = http_req(addr, "GET", "/api/tt/state", None);
    assert_eq!(st, 200);
    let state: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(state["currentInsn"], 0);
    assert_eq!(state["pc"].as_u64(), Some(code_addr));
    assert_eq!(state["regs"].as_array().unwrap().len(), 35);
    assert!(!state["disasm"].as_array().unwrap().is_empty());

    // 4. POST /api/tt/seek 到末尾 11 -> POST /api/tt/watch 反向查写 -> 命中 insn #9
    let (st, body) = http_req(addr, "POST", "/api/tt/seek", Some(r#"{"insn":11}"#));
    assert_eq!(st, 200);
    let seek_res: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(seek_res["state"]["currentInsn"], 11);

    let watch_req = format!(
        r#"{{"addr":"0x{buf_addr:x}","len":4,"kind":"write","direction":"prev"}}"#
    );
    let (st, body) = http_req(addr, "POST", "/api/tt/watch", Some(&watch_req));
    assert_eq!(st, 200);
    let w_res: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(w_res["hit"]["insn"], 9);
    assert_eq!(w_res["hit"]["actualKind"], "write");
    assert_eq!(w_res["state"]["currentInsn"], 9);

    // 5. POST /api/tt/step 前进 1 步执行 str w1,[x0] -> GET /api/tt/mem 验证内存新值 0x33
    let (st, body) = http_req(addr, "POST", "/api/tt/step", Some(r#"{"delta":1}"#));
    assert_eq!(st, 200);
    let step_res: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(step_res["state"]["currentInsn"], 10);

    let (st, body) = http_req(
        addr,
        "GET",
        &format!("/api/tt/mem?addr=0x{buf_addr:x}&len=16"),
        None,
    );
    assert_eq!(st, 200);
    let mem_res: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(mem_res["hex"].as_str().unwrap().starts_with("33000000"));

    // 6. POST /api/tt/verify 确定性自检并保持当前位置 insn=10 不变
    let (st, body) = http_req(addr, "POST", "/api/tt/verify", Some("{}"));
    assert_eq!(st, 200);
    let ver_res: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ver_res["ok"], true);
    assert!(ver_res["verifiedKeyframes"].as_u64().unwrap() >= 3);

    let (st, body) = http_req(addr, "GET", "/api/tt/state", None);
    assert_eq!(st, 200);
    let after_ver: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(after_ver["currentInsn"], 10);

    handle.shutdown();
    let _ = std::fs::remove_file(&tape_path);
}
