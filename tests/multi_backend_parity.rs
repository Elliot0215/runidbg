#[cfg(feature = "dynarmic")]
use std::collections::HashMap;
#[cfg(feature = "dynarmic")]
use std::path::Path;
#[cfg(feature = "dynarmic")]
use std::time::Instant;

use runidbg_arm64_emu_tracer::backend::BackendKind;
#[cfg(feature = "dynarmic")]
use runidbg_arm64_emu_tracer::backend::BackendWithData;
#[cfg(any(
    feature = "dynarmic",
    all(feature = "kvm", target_os = "linux", target_arch = "aarch64"),
    all(feature = "hypervisor", target_os = "macos", target_arch = "aarch64")
))]
use runidbg_arm64_emu_tracer::backend::CpuBackend;
#[cfg(any(
    feature = "dynarmic",
    all(feature = "kvm", target_os = "linux", target_arch = "aarch64"),
    all(feature = "hypervisor", target_os = "macos", target_arch = "aarch64")
))]
use runidbg_arm64_emu_tracer::cpu::RET_MAGIC_ADDR;
#[cfg(any(
    feature = "dynarmic",
    all(feature = "kvm", target_os = "linux", target_arch = "aarch64")
))]
use runidbg_arm64_emu_tracer::debug::GdbServer;
#[cfg(any(feature = "dynarmic", feature = "kvm", feature = "hypervisor"))]
use runidbg_arm64_emu_tracer::error::EmuError;
#[cfg(feature = "dynarmic")]
use runidbg_arm64_emu_tracer::jni::{JObject, JObjectRef, JValue};
#[cfg(feature = "dynarmic")]
use runidbg_arm64_emu_tracer::loader::HleBuiltin;
#[cfg(feature = "dynarmic")]
use runidbg_arm64_emu_tracer::memory::{read_guest_cstr, MemoryManager};
#[cfg(feature = "dynarmic")]
use runidbg_arm64_emu_tracer::tracer::TraceLevel;
#[cfg(any(feature = "dynarmic", feature = "kvm", feature = "hypervisor"))]
use runidbg_arm64_emu_tracer::AndroidEmulator;
#[cfg(any(
    feature = "dynarmic",
    all(feature = "kvm", target_os = "linux", target_arch = "aarch64"),
    all(feature = "hypervisor", target_os = "macos", target_arch = "aarch64")
))]
use unicorn_engine::unicorn_const::Prot;
#[cfg(any(
    all(feature = "kvm", target_os = "linux", target_arch = "aarch64"),
    all(feature = "hypervisor", target_os = "macos", target_arch = "aarch64")
))]
use unicorn_engine::RegisterARM64;

#[cfg(feature = "dynarmic")]
fn register_hle(emu: &mut AndroidEmulator, sym: &str) -> u64 {
    let builtin = HleBuiltin::from_symbol(sym).expect("known HLE symbol");
    let mut mem = std::mem::replace(
        &mut emu.cpu_mut().get_data_mut().mem,
        MemoryManager::new(0, 0),
    );
    let mut tramp = std::mem::take(&mut emu.cpu_mut().get_data_mut().trampolines);
    let addr = tramp
        .register(emu.cpu_mut(), &mut mem, sym, builtin)
        .expect("register HLE");
    emu.cpu_mut().get_data_mut().mem = mem;
    emu.cpu_mut().get_data_mut().trampolines = tramp;
    addr
}

#[cfg(feature = "dynarmic")]
#[test]
fn dynarmic_zstd_20_rounds_and_neon_cross_page_parity() {
    let so_path = Path::new("samples/libzstd-jni-1.5.7-28.so");
    if !so_path.exists() {
        return;
    }

    let run_zstd = |kind: BackendKind| -> (Vec<u8>, Vec<u8>, f64) {
        let mut emu = AndroidEmulator::builder()
            .backend(kind)
            .package_name("com.example.zstd")
            .build()
            .unwrap();
        let module = emu.load_library(so_path).unwrap();
        let ver_ptr = emu.call_symbol(&module, "ZSTD_versionString", &[]).unwrap();
        assert!(read_guest_cstr(emu.cpu(), ver_ptr, 64).starts_with("1.5."));

        let payload = b"ARM64_DYNARMIC_ZSTD_WILDCOPY_128BIT_CROSS_PAGE_PAYLOAD_0123456789!".repeat(400);
        let bound = emu
            .call_symbol(&module, "ZSTD_compressBound", &[payload.len() as u64])
            .unwrap();
        let src = emu
            .cpu_mut()
            .get_data_mut()
            .mem
            .alloc_heap(payload.len() as u64)
            .unwrap();
        let dst = emu.cpu_mut().get_data_mut().mem.alloc_heap(bound).unwrap();
        let out = emu
            .cpu_mut()
            .get_data_mut()
            .mem
            .alloc_heap(payload.len() as u64)
            .unwrap();
        emu.cpu_mut().mem_write(src, &payload).unwrap();

        let t0 = Instant::now();
        let mut last_comp = Vec::new();
        for _ in 0..20 {
            let comp_sz = emu
                .call_symbol(
                    &module,
                    "ZSTD_compress",
                    &[dst, bound, src, payload.len() as u64, 3],
                )
                .unwrap();
            assert!(comp_sz > 0 && comp_sz < payload.len() as u64);
            let decomp_sz = emu
                .call_symbol(
                    &module,
                    "ZSTD_decompress",
                    &[out, payload.len() as u64, dst, comp_sz],
                )
                .unwrap();
            assert_eq!(decomp_sz, payload.len() as u64);
            if last_comp.is_empty() {
                last_comp = emu.cpu().mem_read_as_vec(dst, comp_sz as usize).unwrap();
            }
        }
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let out_buf = emu.cpu().mem_read_as_vec(out, payload.len()).unwrap();
        assert_eq!(out_buf, payload);
        (last_comp, out_buf, elapsed_ms)
    };

    let (uc_comp, uc_out, uc_ms) = run_zstd(BackendKind::Unicorn);
    let (dy_comp, dy_out, dy_ms) = run_zstd(BackendKind::Dynarmic);
    assert_eq!(uc_comp, dy_comp, "ZSTD compressed output must be bit-identical");
    assert_eq!(uc_out, dy_out, "ZSTD decompressed output must be bit-identical");
    eprintln!(
        "[bench] ZSTD 20 rounds: Unicorn={uc_ms:.2}ms, Dynarmic={dy_ms:.2}ms, speedup={:.2}x",
        uc_ms / dy_ms.max(0.001)
    );
}

#[cfg(feature = "dynarmic")]
#[test]
fn dynarmic_mmkv_atomic_and_sqlite_and_webp_parity() {
    // 1. MMKV（验证 ExclusiveMonitor 原子指令 + AES-CFB + mmap/munmap resize）
    let mmkv_path = Path::new("samples/libmmkv.so");
    if mmkv_path.exists() {
        let mut emu = AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .package_name("com.tencent.mmkvdemo")
            .build()
            .unwrap();
        let module = emu.load_library(mmkv_path).unwrap();
        assert_eq!(emu.call_jni_onload(&module).unwrap(), Some(0x0001_0006));
        const CLS: &str = "com/tencent/mmkv/MMKV";
        let ver_ref = JObjectRef(emu.call_registered_native(CLS, "version", &[]).unwrap());
        assert_eq!(emu.read_jstring(ver_ref), Some("v1.3.9"));
        let root_dir = emu.new_jstring("/data/user/0/com.tencent.mmkvdemo/files/mmkv");
        let cache_dir = emu.new_jstring("/data/user/0/com.tencent.mmkvdemo/cache");
        emu.call_registered_native(CLS, "jniInitialize", &[root_dir.0, cache_dir.0, 2, 0])
            .unwrap();
        let key = emu.new_jstring("my_aes_128_key!!");
        let handle = emu
            .call_registered_native(CLS, "getDefaultMMKV", &[1, key.0])
            .unwrap();
        assert_ne!(handle, 0);
        let k = emu.new_jstring("k_dyn");
        let v = emu.new_jstring("dynarmic_mmkv_ok!");
        let fb = emu.new_jstring("fb");
        assert_ne!(
            emu.call_registered_native(CLS, "encodeString", &[handle, k.0, v.0])
                .unwrap(),
            0
        );
        let got = JObjectRef(
            emu.call_registered_native(CLS, "decodeString", &[handle, k.0, fb.0])
                .unwrap(),
        );
        assert_eq!(emu.read_jstring(got), Some("dynarmic_mmkv_ok!"));
        let kb = emu.new_jstring("raw_bin");
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44];
        let vb = emu.new_jbyte_array(raw.clone());
        assert_ne!(
            emu.call_registered_native(CLS, "encodeBytes", &[handle, kb.0, vb.0])
                .unwrap(),
            0
        );
        let dec = JObjectRef(
            emu.call_registered_native(CLS, "decodeBytes", &[handle, kb.0])
                .unwrap(),
        );
        assert!(matches!(emu.jni().objects.get(dec), Some(JObject::ByteArray(b)) if b == &raw));
    }

    // 2. SQLite3（验证 VFS 文件库 SQL + 堆分配 + 快照回滚）
    let sqlite_path = Path::new("samples/libsqliteJni.so");
    if sqlite_path.exists() {
        let mut emu = AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .package_name("com.example.sql")
            .build()
            .unwrap();
        let module = emu.load_library(sqlite_path).unwrap();
        let ver_ptr = emu.call_symbol(&module, "sqlite3_libversion", &[]).unwrap();
        assert!(read_guest_cstr(emu.cpu(), ver_ptr, 64).starts_with("3."));

        let snap = emu.capture_snapshot().unwrap();
        let db_path = b":memory:\0";
        let path_addr = emu
            .cpu_mut()
            .get_data_mut()
            .mem
            .alloc_heap(db_path.len() as u64)
            .unwrap();
        let db_ptr_addr = emu.cpu_mut().get_data_mut().mem.alloc_heap(8).unwrap();
        emu.cpu_mut().mem_write(path_addr, db_path).unwrap();
        assert_eq!(
            emu.call_symbol(&module, "sqlite3_open", &[path_addr, db_ptr_addr])
                .unwrap() as i32,
            0
        );
        emu.restore_snapshot(&snap).unwrap();
    }

    // 3. WebP（验证纯计算与跨后端结果一致）
    let webp_path = Path::new("samples/libstatic-webp.so");
    if webp_path.exists() {
        let mut uc_emu = AndroidEmulator::builder()
            .backend(BackendKind::Unicorn)
            .build()
            .unwrap();
        let uc_mod = uc_emu.load_library(webp_path).unwrap();
        let uc_ver = uc_emu
            .call_symbol(&uc_mod, "WebPGetDecoderVersion", &[])
            .unwrap();

        let mut dy_emu = AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .build()
            .unwrap();
        let dy_mod = dy_emu.load_library(webp_path).unwrap();
        let dy_ver = dy_emu
            .call_symbol(&dy_mod, "WebPGetDecoderVersion", &[])
            .unwrap();
        assert_eq!(uc_ver, dy_ver);
    }
}

#[cfg(feature = "dynarmic")]
#[test]
fn dynarmic_hle_pc_redirect_fault_pc_and_neon_128bit_cross_page() {
    let mut emu = AndroidEmulator::builder()
        .backend(BackendKind::Dynarmic)
        .build()
        .unwrap();

    // 1. 显式测试 128-bit NEON 跨 4KB 页边界访存 (0x4800_0FF8..0x4800_1008)
    let data_base = 0x4800_0000u64;
    let code_base = 0x4810_0000u64;
    emu.cpu_mut()
        .mem_map(data_base, 0x3000, Prot::READ | Prot::WRITE)
        .unwrap();
    emu.cpu_mut()
        .mem_map(code_base, 0x1000, Prot::READ | Prot::WRITE | Prot::EXEC)
        .unwrap();

    let pattern: [u8; 16] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE,
        0x0F,
    ];
    let src_cross = data_base + 0x0FF8; // 跨 page 0 / page 1 边界
    let dst_cross = data_base + 0x1FF8; // 跨 page 1 / page 2 边界
    emu.cpu_mut().mem_write(src_cross, &pattern).unwrap();

    // ldr q0, [x0]  (0x3DC0_0000)
    // str q0, [x1]  (0x3D80_0020)
    // ret           (0xD65F_03C0)
    let neon_copy: [u32; 3] = [0x3DC0_0000, 0x3D80_0020, 0xD65F_03C0];
    let mut neon_bytes = Vec::new();
    for i in neon_copy {
        neon_bytes.extend_from_slice(&i.to_le_bytes());
    }
    emu.cpu_mut().mem_write(code_base, &neon_bytes).unwrap();
    emu.call_address(code_base, &[src_cross, dst_cross]).unwrap();
    assert_eq!(emu.cpu().mem_read_as_vec(dst_cross, 16).unwrap(), pattern);

    // 2. 验证 HLE PC 重定向（setjmp / longjmp + pthread_create / pthread_join）
    let p_setjmp = register_hle(&mut emu, "setjmp");
    let p_longjmp = register_hle(&mut emu, "longjmp");
    let jmp_fn = code_base + 0x100;
    let insns: [u32; 14] = [
        0xA9BE_7BFD, // stp x29, x30, [sp, #-32]!
        0xF900_0BF3, // str x19, [sp, #16]
        0xAA00_03F3, // mov x19, x0
        0x5800_0169, // ldr x9, [pc, #44] -> +0x38
        0xD63F_0120, // blr x9 (setjmp)
        0xB500_00A0, // cbnz x0, +20 -> +0x28
        0xAA13_03E0, // mov x0, x19
        0xD280_0541, // mov x1, #42
        0x5800_0109, // ldr x9, [pc, #32] -> +0x40
        0xD63F_0120, // blr x9 (longjmp)
        0x9101_9000, // add x0, x0, #100
        0xF940_0BF3, // ldr x19, [sp, #16]
        0xA8C2_7BFD, // ldp x29, x30, [sp], #32
        0xD65F_03C0, // ret
    ];
    let mut jmp_bytes = Vec::new();
    for i in insns {
        jmp_bytes.extend_from_slice(&i.to_le_bytes());
    }
    jmp_bytes.extend_from_slice(&p_setjmp.to_le_bytes());
    jmp_bytes.extend_from_slice(&p_longjmp.to_le_bytes());
    emu.cpu_mut().mem_write(jmp_fn, &jmp_bytes).unwrap();
    let jmp_buf = emu.cpu_mut().get_data_mut().mem.alloc_heap(256).unwrap();
    assert_eq!(emu.call_address(jmp_fn, &[jmp_buf]).unwrap(), 142);

    // 3. 坑 5 验证：故障指令紧跟 ret 时，CrashReport.pc 必须精确指向故障 LDR 而非 RET_MAGIC_ADDR
    let fault_fn = code_base + 0x200;
    // ldr x0, [x0]  (0xF940_0000) -> x0 = 0x9999_0000 (未映射)
    // ret           (0xD65F_03C0)
    let mut fault_bytes = Vec::new();
    fault_bytes.extend_from_slice(&0xF940_0000u32.to_le_bytes());
    fault_bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
    emu.cpu_mut().mem_write(fault_fn, &fault_bytes).unwrap();
    let err = emu
        .call_address(fault_fn, &[0x9999_0000])
        .expect_err("unmapped read must fail");
    match err {
        EmuError::GuestCrash(report) => {
            assert_eq!(report.pc, fault_fn, "fault PC must not drift to RET_MAGIC_ADDR");
            assert_ne!(report.pc, RET_MAGIC_ADDR);
        }
        other => panic!("expected GuestCrash, got {other:?}"),
    }

    // 4. Unicorn-only 边界拦截：builder(with_memory_trace) / attach_tracer / GdbServer 在 Dynarmic 上必须显式报错
    assert!(matches!(
        AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .with_memory_trace(1024, TraceLevel::Fast)
            .build(),
        Err(EmuError::Backend(_))
    ));
    assert!(matches!(
        emu.attach_tracer(0, u64::MAX),
        Err(EmuError::Backend(_))
    ));
    assert!(GdbServer::serve(&mut emu, "127.0.0.1:0", code_base, &[]).is_err());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(GdbServer::serve_listener(&mut emu, listener, code_base, &[]).is_err());
}

#[cfg(all(feature = "dynarmic", feature = "js", feature = "rpc"))]
#[test]
fn dynarmic_js_backend_selection_and_metasec_parity() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    // 1. JS 指定 backend: "dynarmic" + 验证 Unicorn-only hook.code / trace.start 返回明确错误且不落盘
    let trace_tmp = std::env::temp_dir().join(format!(
        "runidbg_non_uc_trace_{}.idx",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_tmp);
    let script = format!(
        r#"
        const compiled = Emu.backends();
        const emu = Emu.create({{ backend: "dynarmic", packageName: "com.example.dyn" }});
        const mod = emu.load("samples/libstatic-webp.so");
        const ver = mod.call("WebPGetDecoderVersion");
        let hookErr = null;
        try {{
            emu.hook.code(mod.base, () => {{}});
        }} catch (e) {{
            hookErr = String(e);
        }}
        let traceErr = null;
        try {{
            emu.trace.start({{ output: {:?}, level: "fast" }});
        }} catch (e) {{
            traceErr = String(e);
        }}
        rpc.exports = {{
            verify() {{
                return {{
                    compiled,
                    backend: emu.backend,
                    supportsTrace: emu.supportsTrace,
                    supportsGdb: emu.supportsGdb,
                    ver,
                    hookErr,
                    traceErr,
                }};
            }},
        }};
    "#,
        trace_tmp.to_string_lossy()
    );
    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    session.eval_source(&script).unwrap();
    let raw = session.call_rpc_json("verify", "[]").unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["backend"].as_str(), Some("dynarmic"));
    assert_eq!(v["supportsTrace"].as_bool(), Some(false));
    assert_eq!(v["supportsGdb"].as_bool(), Some(false));
    assert!(v["ver"].as_u64().unwrap_or(0) > 0);
    assert!(
        v["hookErr"]
            .as_str()
            .is_some_and(|s| s.contains("unicorn")),
        "expected unicorn-only guard error, got: {:?}",
        v["hookErr"]
    );
    assert!(
        v["traceErr"]
            .as_str()
            .is_some_and(|s| s.contains("unicorn")),
        "expected unicorn-only trace guard error, got: {:?}",
        v["traceErr"]
    );
    assert!(
        !trace_tmp.exists(),
        "trace.start on non-Unicorn backend must fail before creating trace file"
    );

    // 2. TikTok libmetasec_ov.so 在 Dynarmic 上离线生成全套 X-Cylons/X-Argus/X-Gorgon/X-Khronos/X-Ladon
    let metasec_so = Path::new("samples/metasec/libmetasec_ov.so");
    if metasec_so.exists() {
        let ms_script = r#"
            const SAMPLE_DIR = "samples/metasec";
            const emu = Emu.create({
                backend: "dynarmic",
                packageName: "com.zhiliaoapp.musically",
                searchPaths: [SAMPLE_DIR],
                device: "pixel8pro",
                realClock: true,
            });
            emu.setLimits({ timeoutMs: 30000, maxInstructions: 0 });
            const LICENSE =
                "Zs81WLZ0TYDnPHhokfrih9f2UVKMYsD6ygiN+al3YbsQTM5dSPr+VANPNr2yt/6QZ3JuYhSmDYBLiuwMS3cvrr+1/8cAwLDSGF69eSzBCn1V3+2mBLMP7NPqp1q3bRDYgEewnEm4DNlPCPW5U2nedHmDVvrEKzBMl8RWBPCnBmvNXNMcPonBLsZYQk+XnBO5ZUm5rFr56W5sezAigX8gmCIS9kaPMASRFaEb65F/f8pFvVlEWoxkWkVeUf8Z9pPT0ZaRrezEtk4JvuNwLu0lL1UHdxpc+feECCxfrESn8hKSFDyzg1zQ0YNT+ILxVw34ElmJ30SP74RN/dhjNJ5pDBtlu+RNtU1ebPwnGxtu79WacDkiCJjsmdrzGrGwbQ4nBl8bugOKsWV4FF/60FPwpZ8iZ+M=";
            emu.jni.hook("com/bytedance/mobsec/metasec/ov/MS", {
                b(op) {
                    if (op === 65539) return "/data/user/0/com.zhiliaoapp.musically/files/.msdata";
                    if (op === 16777233) return "47.6.3";
                    return null;
                },
            });
            const mod = emu.load(`${SAMPLE_DIR}/libmetasec_ov.so`);
            const ver = emu.jniOnLoad(mod);
            const a0Cls = emu.jni.findClass("ms/bd/o/a0");
            const strCls = emu.jni.findClass("java/lang/String");
            emu.mem.writeU64(mod.base + 0x209198, strCls);
            function callK(op, strVal, objRef) {
                const sRef = strVal ? emu.jni.newString(strVal) : 0;
                return emu.call(mod.base + 0x120be0, emu.jni.envPtr, a0Cls, op, 0, 0, sRef, objRef || 0);
            }
            const cfg = [
                "1233", "", "", LICENSE, "v04.04.06-ov-android", "googleplay",
                "7000000000000000001", "", "7000000000000000002", "",
                "0", "0", "5", [], []
            ];
            callK(67108865, JSON.stringify(cfg), 0);
            const headersArr = emu.jni.newStringArray(["cookie", "sessionid=demo", "user-agent", "ua"]);
            const cArr = emu.jni.getStringArray(callK(100663297, "https://x/y", headersArr));
            const gArr = emu.jni.getStringArray(callK(
                50331649,
                "https://api16-normal-no1a.tiktokv.eu/aweme/v2/comment/list/?aweme_id=1&aid=1233&device_id=7000000000000000001",
                headersArr
            ));
            const toMap = (a) => {
                const m = {};
                for (let i = 0; i + 1 < a.length; i += 2) m[a[i]] = a[i + 1];
                return m;
            };
            rpc.exports = {
                verify() {
                    const c = toMap(cArr);
                    const g = toMap(gArr);
                    return {
                        ver,
                        cylonsLen: (c["X-Cylons"] || "").length,
                        argusLen: (g["X-Argus"] || "").length,
                        gorgonLen: (g["X-Gorgon"] || "").length,
                        gorgonPrefix: (g["X-Gorgon"] || "").slice(0, 4),
                        khronosLen: (g["X-Khronos"] || "").length,
                        ladonLen: (g["X-Ladon"] || "").length,
                    };
                },
            };
        "#;
        let t0 = Instant::now();
        let ms_session = JsSession::new(&[], Path::new("."), true).unwrap();
        ms_session.eval_source(ms_script).unwrap();
        let ms_raw = ms_session.call_rpc_json("verify", "[]").unwrap();
        let mv: serde_json::Value = serde_json::from_str(&ms_raw).unwrap();
        assert_eq!(mv["ver"].as_u64(), Some(0x10006));
        assert!(mv["cylonsLen"].as_u64().unwrap_or(0) >= 16);
        assert!(mv["argusLen"].as_u64().unwrap_or(0) >= 300);
        assert_eq!(mv["gorgonLen"].as_u64(), Some(52));
        assert_eq!(mv["gorgonPrefix"].as_str(), Some("8404"));
        assert_eq!(mv["khronosLen"].as_u64(), Some(10));
        assert_eq!(mv["ladonLen"].as_u64(), Some(48));
        eprintln!(
            "[bench] TikTok metasec_ov full offline sign on Dynarmic: {:.2}ms",
            t0.elapsed().as_secs_f64() * 1000.0
        );
    }
}

#[cfg(feature = "dynarmic")]
#[test]
fn dynarmic_conscrypt_boringssl_and_cronet_143_parity() {
    // 1. Conscrypt / BoringSSL (300+ RegisterNatives + SHA-256 精确比特比对)
    let conscrypt_path = Path::new("samples/libconscrypt_jni.so");
    if conscrypt_path.exists() {
        let mut emu = AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .package_name("com.example.conscrypt")
            .build()
            .unwrap();
        let module = emu.load_library(conscrypt_path).unwrap();
        assert_eq!(emu.call_jni_onload(&module).unwrap(), Some(0x0001_0006));
        assert!(emu.jni().registered_natives.len() >= 300);

        const CLS: &str = "org/conscrypt/NativeCrypto";
        let algo = emu.new_jstring("sha256");
        let evp_md = emu
            .call_registered_native(CLS, "EVP_get_digestbyname", &[algo.0])
            .unwrap();
        let md_ctx_ptr = emu
            .call_registered_native(CLS, "EVP_MD_CTX_create", &[])
            .unwrap();
        let mut fields = HashMap::new();
        fields.insert("address".to_string(), JValue::Long(md_ctx_ptr as i64));
        let ctx_ref = emu.jni_mut().objects.add_local(JObject::Custom {
            class_name: "org/conscrypt/NativeRef$EVP_MD_CTX".to_string(),
            fields,
        });
        assert_eq!(
            emu.call_registered_native(CLS, "EVP_DigestInit_ex", &[ctx_ref.0, evp_md])
                .unwrap() as i32,
            1
        );
        let msg = b"hello arm64-emu-tracer";
        let msg_arr = emu.new_jbyte_array(msg.to_vec());
        emu.call_registered_native(
            CLS,
            "EVP_DigestUpdate",
            &[ctx_ref.0, msg_arr.0, 0, msg.len() as u64],
        )
        .unwrap();
        let out_arr = emu.new_jbyte_array(vec![0u8; 32]);
        assert_eq!(
            emu.call_registered_native(CLS, "EVP_DigestFinal_ex", &[ctx_ref.0, out_arr.0, 0])
                .unwrap() as i32,
            32
        );
        let digest_hex: String = match emu.jni().objects.get(out_arr) {
            Some(JObject::ByteArray(b)) => b.iter().map(|x| format!("{x:02x}")).collect(),
            _ => String::new(),
        };
        assert_eq!(
            digest_hex,
            "faa5350e1990f7a9ac3dc87e907de931f10b83c8e203ff053f54f0c62fcf7ac5"
        );
        emu.call_registered_native(CLS, "EVP_MD_CTX_destroy", &[md_ctx_ptr])
            .unwrap();
    }

    // 2. Chromium Cronet 143 (6.5MB ELF + JNI 完整生命周期)
    let cronet_path = Path::new("samples/libcronet.so");
    if cronet_path.exists() {
        struct CronetHandler;
        impl runidbg_arm64_emu_tracer::jni::JniHandler for CronetHandler {
            fn call_static_object_method(
                &mut self,
                ctx: &mut runidbg_arm64_emu_tracer::jni::JniContext<'_>,
                class_name: &str,
                method: &runidbg_arm64_emu_tracer::jni::MethodDesc,
                _args: &[JValue],
            ) -> JObjectRef {
                if class_name == "org/chromium/base/JNIUtils" && method.name == "getSplitClassLoader"
                {
                    return ctx.objects.add_local(JObject::Custom {
                        class_name: "java/lang/ClassLoader".to_string(),
                        fields: HashMap::new(),
                    });
                }
                if class_name == "internal/org/jni_zero/JniInit" && method.name == "init" {
                    let empty_map = ctx.objects.add_local(JObject::Custom {
                        class_name: "java/util/Collections$EmptyMap".to_string(),
                        fields: HashMap::new(),
                    });
                    return ctx
                        .objects
                        .add_local(JObject::ObjectArray(vec![empty_map, JObjectRef::NULL]));
                }
                JObjectRef::NULL
            }
        }
        let mut emu = AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .package_name("com.example.cronetdemo")
            .jni_handler(Box::new(CronetHandler))
            .build()
            .unwrap();
        let module = emu.load_library(cronet_path).unwrap();
        assert_eq!(emu.call_jni_onload(&module).unwrap(), Some(0x0001_0006));
        assert!(emu.jni().registered_natives.len() >= 100);
        let engine = emu.call_symbol(&module, "Cronet_Engine_Create", &[]).unwrap();
        assert_ne!(engine, 0);
        let ver_ptr = emu
            .call_symbol(&module, "Cronet_Engine_GetVersionString", &[engine])
            .unwrap();
        assert!(read_guest_cstr(emu.cpu(), ver_ptr, 64).starts_with("143.0."));
        emu.call_symbol(&module, "Cronet_Engine_Destroy", &[engine])
            .unwrap();
    }
}

#[test]
fn kvm_and_hypervisor_platform_guards_and_capabilities() {
    assert!(BackendKind::Unicorn.supports_trace());
    assert!(BackendKind::Unicorn.supports_gdb());
    assert!(BackendKind::Unicorn.supports_native_hooks());
    assert!(!BackendKind::Dynarmic.supports_trace());
    assert!(!BackendKind::Dynarmic.supports_gdb());
    assert!(!BackendKind::Dynarmic.supports_native_hooks());
    assert!(!BackendKind::Kvm.supports_trace());
    assert!(!BackendKind::Kvm.supports_gdb());
    assert!(!BackendKind::Hypervisor.supports_trace());
    assert!(!BackendKind::Hypervisor.supports_gdb());
    assert_eq!("dynarmic".parse::<BackendKind>().unwrap(), BackendKind::Dynarmic);
    assert_eq!("hyper".parse::<BackendKind>().unwrap(), BackendKind::Hypervisor);
    assert_eq!("hvf".parse::<BackendKind>().unwrap(), BackendKind::Hypervisor);

    // 平台条件编译校验：Linux 默认编译 unicorn+dynarmic+kvm，macOS 默认编译 unicorn+dynarmic+hypervisor
    let compiled = BackendKind::compiled_backends();
    assert!(compiled.contains(&BackendKind::Unicorn));
    assert!(BackendKind::Unicorn.is_compiled());
    #[cfg(all(target_os = "macos", feature = "dynarmic", feature = "hypervisor"))]
    {
        assert_eq!(
            compiled,
            &[
                BackendKind::Unicorn,
                BackendKind::Dynarmic,
                BackendKind::Hypervisor
            ]
        );
        assert!(!BackendKind::Kvm.is_compiled());
    }
    #[cfg(all(target_os = "linux", feature = "dynarmic", feature = "kvm"))]
    {
        assert_eq!(
            compiled,
            &[
                BackendKind::Unicorn,
                BackendKind::Dynarmic,
                BackendKind::Kvm
            ]
        );
        assert!(!BackendKind::Hypervisor.is_compiled());
    }

    // 非 Linux aarch64 宿主机请求 KVM 应返回清晰 Backend 错误
    #[cfg(all(feature = "kvm", not(all(target_os = "linux", target_arch = "aarch64"))))]
    {
        let res = AndroidEmulator::builder()
            .backend(BackendKind::Kvm)
            .build();
        assert!(matches!(res, Err(EmuError::Backend(_))));
    }

    // Linux aarch64 宿主机请求 KVM：若 /dev/kvm 可用则直接实跑 ARM64 指令、IRELATIVE run_simple、
    // Guest EL0 BRK、FPCR/FPSR、局部 mem_unmap、flush_cache 与 Unicorn-only 守卫
    #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "aarch64"))]
    {
        match AndroidEmulator::builder().backend(BackendKind::Kvm).build() {
            Ok(mut emu) => {
                let code_base = 0x4800_0000u64;
                emu.cpu_mut()
                    .mem_map(code_base, 0x4000, Prot::READ | Prot::WRITE | Prot::EXEC)
                    .unwrap();
                // 1. 基本 ARM64 执行 + flush_cache: add x0, x0, x1; ret
                let mut code = Vec::new();
                code.extend_from_slice(&0x8B01_0000u32.to_le_bytes());
                code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
                emu.cpu_mut().mem_write(code_base, &code).unwrap();
                emu.cpu_mut().flush_cache(code_base, code_base + 8).unwrap();
                assert_eq!(emu.call_address(code_base, &[19, 23]).unwrap(), 42);

                // 2. run_simple（模拟 R_AARCH64_IRELATIVE resolver）: movz x0, #0x1234; ret
                let ifunc_addr = code_base + 0x100;
                let mut ifunc_code = Vec::new();
                ifunc_code.extend_from_slice(&0xD282_4680u32.to_le_bytes());
                ifunc_code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
                emu.cpu_mut().mem_write(ifunc_addr, &ifunc_code).unwrap();
                emu.cpu_mut()
                    .flush_cache(ifunc_addr, ifunc_addr + 8)
                    .unwrap();
                emu.cpu_mut().reg_write(RegisterARM64::X0, 0).unwrap();
                emu.cpu_mut()
                    .reg_write(RegisterARM64::LR, RET_MAGIC_ADDR)
                    .unwrap();
                emu.cpu_mut()
                    .run_simple(ifunc_addr, RET_MAGIC_ADDR, 0, 0)
                    .unwrap();
                assert_eq!(emu.cpu().reg_read(RegisterARM64::X0).unwrap(), 0x1234);

                // 3. Guest EL0 自身执行 BRK #0x42：不能误读上一次 SVC 残留 ESR_EL1
                let brk_addr = code_base + 0x200;
                emu.cpu_mut()
                    .mem_write(brk_addr, &0xD420_0840u32.to_le_bytes())
                    .unwrap();
                emu.cpu_mut().flush_cache(brk_addr, brk_addr + 4).unwrap();
                let brk_err = emu
                    .call_address(brk_addr, &[])
                    .expect_err("EL0 BRK must raise GuestCrash, not stale SVC");
                match brk_err {
                    EmuError::GuestCrash(report) => {
                        assert_eq!(report.pc, brk_addr);
                        assert!(
                            report.reason.contains("BRK"),
                            "expected EL0 BRK crash reason, got: {}",
                            report.reason
                        );
                    }
                    other => panic!("expected GuestCrash on EL0 BRK, got {other:?}"),
                }

                // 4. FPCR / FPSR (KVM_REG_SIZE_U32) 读写
                let orig_fpcr = emu.cpu().reg_read(RegisterARM64::FPCR).unwrap();
                let test_fpcr = orig_fpcr | (1 << 24);
                emu.cpu_mut()
                    .reg_write(RegisterARM64::FPCR, test_fpcr)
                    .unwrap();
                assert_eq!(
                    emu.cpu().reg_read(RegisterARM64::FPCR).unwrap() & (1 << 24),
                    1 << 24
                );
                emu.cpu_mut()
                    .reg_write(RegisterARM64::FPCR, orig_fpcr)
                    .unwrap();
                let _ = emu.cpu().reg_read(RegisterARM64::FPSR).unwrap();

                // 5. 局部 mem_unmap：映射 3 页，仅卸载中间页，验证首尾页数据保留且中间页已卸载并可重新映射
                let split_base = 0x4900_0000u64;
                emu.cpu_mut()
                    .mem_map(split_base, 0x3000, Prot::READ | Prot::WRITE)
                    .unwrap();
                emu.cpu_mut().mem_write(split_base, b"PAGE0").unwrap();
                emu.cpu_mut()
                    .mem_write(split_base + 0x1000, b"PAGE1")
                    .unwrap();
                emu.cpu_mut()
                    .mem_write(split_base + 0x2000, b"PAGE2")
                    .unwrap();
                emu.cpu_mut().mem_unmap(split_base + 0x1000, 0x1000).unwrap();
                assert_eq!(
                    emu.cpu().mem_read_as_vec(split_base, 5).unwrap(),
                    b"PAGE0"
                );
                assert_eq!(
                    emu.cpu().mem_read_as_vec(split_base + 0x2000, 5).unwrap(),
                    b"PAGE2"
                );
                assert!(matches!(
                    emu.cpu().mem_read_as_vec(split_base + 0x1000, 5),
                    Err(EmuError::UnmappedMemory { .. })
                ));
                emu.cpu_mut()
                    .mem_map(split_base + 0x1000, 0x1000, Prot::READ | Prot::WRITE)
                    .unwrap();
                assert_eq!(
                    emu.cpu().mem_read_as_vec(split_base + 0x1000, 5).unwrap(),
                    [0u8; 5]
                );

                // 6. Unicorn-only 守卫
                assert!(matches!(
                    emu.attach_tracer(0, u64::MAX),
                    Err(EmuError::Backend(_))
                ));
                assert!(GdbServer::serve(&mut emu, "127.0.0.1:0", code_base, &[]).is_err());
            }
            Err(EmuError::Backend(msg)) => {
                assert!(
                    msg.contains("/dev/kvm") || msg.contains("KVM"),
                    "unexpected kvm error: {msg}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    // 非 macOS 宿主机请求 Hypervisor 应返回清晰 Backend 错误
    #[cfg(all(feature = "hypervisor", not(target_os = "macos")))]
    {
        let res = AndroidEmulator::builder()
            .backend(BackendKind::Hypervisor)
            .build();
        assert!(matches!(res, Err(EmuError::Backend(_))));
    }

    // macOS Apple Silicon 请求 Hypervisor：若有 entitlement 则直接实跑 ARM64 指令与 run_simple，否则应返回清晰的 HV_DENIED 签名指引
    #[cfg(all(feature = "hypervisor", target_os = "macos", target_arch = "aarch64"))]
    {
        match AndroidEmulator::builder()
            .backend(BackendKind::Hypervisor)
            .build()
        {
            Ok(mut emu) => {
                let code_base = 0x4800_0000u64;
                emu.cpu_mut()
                    .mem_map(code_base, 0x4000, Prot::READ | Prot::WRITE | Prot::EXEC)
                    .unwrap();
                // add x0, x0, x1; ret
                let mut code = Vec::new();
                code.extend_from_slice(&0x8B01_0000u32.to_le_bytes());
                code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
                emu.cpu_mut().mem_write(code_base, &code).unwrap();
                emu.cpu_mut().flush_cache(code_base, code_base + 8).unwrap();
                assert_eq!(emu.call_address(code_base, &[19, 23]).unwrap(), 42);

                // run_simple (IRELATIVE resolver): movz x0, #0x1234; ret
                let ifunc_addr = code_base + 0x100;
                let mut ifunc_code = Vec::new();
                ifunc_code.extend_from_slice(&0xD282_4680u32.to_le_bytes());
                ifunc_code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
                emu.cpu_mut().mem_write(ifunc_addr, &ifunc_code).unwrap();
                emu.cpu_mut()
                    .flush_cache(ifunc_addr, ifunc_addr + 8)
                    .unwrap();
                emu.cpu_mut().reg_write(RegisterARM64::X0, 0).unwrap();
                emu.cpu_mut()
                    .reg_write(RegisterARM64::LR, RET_MAGIC_ADDR)
                    .unwrap();
                emu.cpu_mut()
                    .run_simple(ifunc_addr, RET_MAGIC_ADDR, 0, 0)
                    .unwrap();
                assert_eq!(emu.cpu().reg_read(RegisterARM64::X0).unwrap(), 0x1234);
            }
            Err(EmuError::Backend(msg)) => {
                assert!(
                    msg.contains("HV_DENIED") || msg.contains("entitlement") || msg.contains("Hypervisor"),
                    "unexpected hypervisor error: {msg}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }
}
