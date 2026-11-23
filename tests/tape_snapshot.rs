use std::path::Path;

use runidbg_arm64_emu_tracer::backend::{BackendKind, BackendWithData, CpuBackend};
use runidbg_arm64_emu_tracer::jni::JValue;
use runidbg_arm64_emu_tracer::tape::{Tape, TapeSelector};
use runidbg_arm64_emu_tracer::tracer::TraceLevel;
use runidbg_arm64_emu_tracer::AndroidEmulator;

fn temp_tape_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "runidbg_test_{}_{}.rtape",
        tag,
        std::process::id()
    ))
}

#[test]
fn tape_multi_checkpoint_delta_and_rewind() {
    let tape_path = temp_tape_path("delta_rewind");
    let _ = std::fs::remove_file(&tape_path);

    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.tape")
        .build()
        .unwrap();
    let zstd = emu
        .load_library("samples/libzstd-jni-1.5.7-28.so")
        .unwrap();
    let buf_addr = emu.cpu_mut().get_data_mut().mem.alloc_heap(64).unwrap();
    emu.cpu_mut().mem_write(buf_addr, b"BEFORE_MUTATION!").unwrap();
    emu.jni_mut()
        .set_static_field("com/test/TapeState", "counter", JValue::Int(100));
    emu.vfs_mut()
        .add_overlay_file("/data/local/tmp/tape_flag.txt", b"v0".to_vec());

    // Checkpoint 0 (BASE)
    let summary0 = emu.save_tape(&tape_path, "cp0_init").unwrap();
    assert_eq!(summary0.checkpoints.len(), 1);
    assert!(!summary0.checkpoints[0].is_delta);
    assert_eq!(summary0.checkpoints[0].label, "cp0_init");

    // 变更堆内存、JNI 静态字段、VFS 文件，并运行一次真实 ZSTD 压缩解压
    emu.cpu_mut().mem_write(buf_addr, b"AFTER_MUTATION!!").unwrap();
    emu.jni_mut()
        .set_static_field("com/test/TapeState", "counter", JValue::Int(200));
    emu.vfs_mut()
        .add_overlay_file("/data/local/tmp/tape_flag.txt", b"v1".to_vec());

    let payload: Vec<u8> = (0..4096u32).map(|i| ((i * 29) ^ (i >> 3)) as u8).collect();
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
    let out = emu
        .cpu_mut()
        .get_data_mut()
        .mem
        .alloc_heap(payload.len() as u64)
        .unwrap();
    emu.cpu_mut().mem_write(src, &payload).unwrap();
    let comp_len = emu
        .call_symbol(
            &zstd,
            "ZSTD_compress",
            &[dst, bound, src, payload.len() as u64, 3],
        )
        .unwrap();
    let dec_len = emu
        .call_symbol(
            &zstd,
            "ZSTD_decompress",
            &[out, payload.len() as u64, dst, comp_len],
        )
        .unwrap();
    assert_eq!(dec_len as usize, payload.len());

    // Checkpoint 1 (DELTA: 仅保存 4KB 脏页 diff)
    let cp1 = emu
        .append_tape_checkpoint(&tape_path, "cp1_after_zstd")
        .unwrap();
    assert!(cp1.is_delta);
    assert_eq!(cp1.index, 1);

    let inspected = Tape::inspect_file(&tape_path).unwrap();
    assert_eq!(inspected.checkpoints.len(), 2);
    assert!(
        inspected.checkpoints[1].compressed_bytes < inspected.checkpoints[0].compressed_bytes,
        "delta checkpoint ({}B) should be smaller than base ({}B)",
        inspected.checkpoints[1].compressed_bytes,
        inspected.checkpoints[0].compressed_bytes
    );

    // 倒带回 cp0_init，校验内存、JNI 与 VFS 全部精确回滚
    let rewound = emu
        .seek_tape_file(&tape_path, &TapeSelector::Label("cp0_init".to_string()))
        .unwrap();
    assert_eq!(rewound.index, 0);
    assert_eq!(
        emu.cpu().mem_read_as_vec(buf_addr, 16).unwrap(),
        b"BEFORE_MUTATION!"
    );
    assert_eq!(
        emu.jni()
            .get_static_field("com/test/TapeState", "counter")
            .copied(),
        Some(JValue::Int(100))
    );
    assert_eq!(
        emu.vfs()
            .get_overlay_file("/data/local/tmp/tape_flag.txt")
            .unwrap(),
        b"v0"
    );

    // 快进到 cp1_after_zstd，校验所有变更完整恢复
    let forwarded = emu
        .seek_tape_file(&tape_path, &TapeSelector::Index(1))
        .unwrap();
    assert_eq!(forwarded.label, "cp1_after_zstd");
    assert_eq!(
        emu.cpu().mem_read_as_vec(buf_addr, 16).unwrap(),
        b"AFTER_MUTATION!!"
    );
    assert_eq!(
        emu.jni()
            .get_static_field("com/test/TapeState", "counter")
            .copied(),
        Some(JValue::Int(200))
    );
    assert_eq!(
        emu.vfs()
            .get_overlay_file("/data/local/tmp/tape_flag.txt")
            .unwrap(),
        b"v1"
    );
    assert_eq!(
        emu.cpu().mem_read_as_vec(out, payload.len()).unwrap(),
        payload
    );

    let _ = std::fs::remove_file(&tape_path);
}

#[cfg(feature = "dynarmic")]
#[test]
fn tape_cross_backend_relay_dynarmic_and_unicorn_with_trace() {
    let tape_dyn = temp_tape_path("relay_dyn_to_uc");
    let tape_uc = temp_tape_path("relay_uc_to_dyn");
    let _ = std::fs::remove_file(&tape_dyn);
    let _ = std::fs::remove_file(&tape_uc);

    let payload: Vec<u8> = (0..8192u32)
        .map(|i| ((i * 37) ^ (i >> 4) ^ ((i % 251) * 13)) as u8)
        .collect();

    // 1. 在 Dynarmic 上初始化 ZSTD + 写入输入缓冲，录制磁带
    let (bound, src, dst, out) = {
        let mut dyn_emu = AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .package_name("com.example.relay")
            .build()
            .unwrap();
        let zstd = dyn_emu
            .load_library("samples/libzstd-jni-1.5.7-28.so")
            .unwrap();
        let bound = dyn_emu
            .call_symbol(&zstd, "ZSTD_compressBound", &[payload.len() as u64])
            .unwrap();
        let src = dyn_emu
            .cpu_mut()
            .get_data_mut()
            .mem
            .alloc_heap(payload.len() as u64)
            .unwrap();
        let dst = dyn_emu
            .cpu_mut()
            .get_data_mut()
            .mem
            .alloc_heap(bound)
            .unwrap();
        let out = dyn_emu
            .cpu_mut()
            .get_data_mut()
            .mem
            .alloc_heap(payload.len() as u64)
            .unwrap();
        dyn_emu.cpu_mut().mem_write(src, &payload).unwrap();
        dyn_emu.save_tape(&tape_dyn, "dyn_ready").unwrap();
        (bound, src, dst, out)
    };

    // 2. 跨后端接力：把 Dynarmic 录制的磁带直接加载进 Unicorn，开启指令级 Trace 执行 ZSTD！
    {
        let (mut uc_emu, info) =
            AndroidEmulator::from_tape(&tape_dyn, BackendKind::Unicorn).unwrap();
        assert_eq!(info.source_backend, "dynarmic");
        assert_eq!(uc_emu.backend_kind(), BackendKind::Unicorn);
        let zstd = uc_emu
            .linker()
            .get_module("libzstd-jni-1.5.7-28.so")
            .cloned()
            .expect("zstd module must be restored from tape");

        uc_emu
            .set_tracer(runidbg_arm64_emu_tracer::tracer::BinaryTracer::new_in_memory_with_level(
                262_144,
                TraceLevel::Fast,
            ))
            .unwrap();
        let comp_len = uc_emu
            .call_symbol(
                &zstd,
                "ZSTD_compress",
                &[dst, bound, src, payload.len() as u64, 3],
            )
            .unwrap();
        let dec_len = uc_emu
            .call_symbol(
                &zstd,
                "ZSTD_decompress",
                &[out, payload.len() as u64, dst, comp_len],
            )
            .unwrap();
        uc_emu.detach_tracer().unwrap();

        assert_eq!(dec_len as usize, payload.len());
        assert_eq!(
            uc_emu.cpu().mem_read_as_vec(out, payload.len()).unwrap(),
            payload
        );
        assert!(
            uc_emu.tracer().stats.recorded_insns > 1000,
            "Unicorn relayed from Dynarmic tape must record trace instructions"
        );

        // 3. 反向跨后端接力：Unicorn 存盘 -> Dynarmic 加载执行
        uc_emu.save_tape(&tape_uc, "uc_after_zstd").unwrap();
    }

    {
        let (mut dyn_emu2, info) =
            AndroidEmulator::from_tape(&tape_uc, BackendKind::Dynarmic).unwrap();
        assert_eq!(info.source_backend, "unicorn");
        assert_eq!(dyn_emu2.backend_kind(), BackendKind::Dynarmic);
        let zstd = dyn_emu2
            .linker()
            .get_module("libzstd-jni-1.5.7-28.so")
            .cloned()
            .expect("zstd module restored into dynarmic");
        let comp_len = dyn_emu2
            .call_symbol(
                &zstd,
                "ZSTD_compress",
                &[dst, bound, src, payload.len() as u64, 3],
            )
            .unwrap();
        let dec_len = dyn_emu2
            .call_symbol(
                &zstd,
                "ZSTD_decompress",
                &[out, payload.len() as u64, dst, comp_len],
            )
            .unwrap();
        assert_eq!(dec_len as usize, payload.len());
        assert_eq!(
            dyn_emu2.cpu().mem_read_as_vec(out, payload.len()).unwrap(),
            payload
        );
    }

    let _ = std::fs::remove_file(&tape_dyn);
    let _ = std::fs::remove_file(&tape_uc);
}

#[cfg(all(feature = "dynarmic", feature = "js", feature = "rpc"))]
#[test]
fn tape_js_api_and_metasec_cross_backend_relay() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let metasec_so = Path::new("samples/metasec/libmetasec_ov.so");
    if !metasec_so.exists() {
        return;
    }

    let tape_path = temp_tape_path("js_metasec_relay");
    let _ = std::fs::remove_file(&tape_path);
    let tape_str = tape_path.to_string_lossy().into_owned();

    // Session 1: 用 Dynarmic 极速完成 TikTok metasec_ov 初始化，打两个检查点落盘
    let record_script = format!(
        r#"
        const LICENSE = "Zs81WLZ0TYDnPHhokfrih9f2UVKMYsD6ygiN+al3YbsQTM5dSPr+VANPNr2yt/6QZ3JuYhSmDYBLiuwMS3cvrr+1/8cAwLDSGF69eSzBCn1V3+2mBLMP7NPqp1q3bRDYgEewnEm4DNlPCPW5U2nedHmDVvrEKzBMl8RWBPCnBmvNXNMcPonBLsZYQk+XnBO5ZUm5rFr56W5sezAigX8gmCIS9kaPMASRFaEb65F/f8pFvVlEWoxkWkVeUf8Z9pPT0ZaRrezEtk4JvuNwLu0lL1UHdxpc+feECCxfrESn8hKSFDyzg1zQ0YNT+ILxVw34ElmJ30SP74RN/dhjNJ5pDBtlu+RNtU1ebPwnGxtu79WacDkiCJjsmdrzGrGwbQ4nBl8bugOKsWV4FF/60FPwpZ8iZ+M=";
        const SAMPLE_DIR = "samples/metasec";
        const emu = Emu.create({{
            backend: "dynarmic",
            packageName: "com.zhiliaoapp.musically",
            searchPaths: [SAMPLE_DIR],
            device: "pixel8pro",
            realClock: true,
        }});
        emu.jni.hook("com/bytedance/mobsec/metasec/ov/MS", {{
            b(op) {{
                if (op === 65539) return "/data/user/0/com.zhiliaoapp.musically/files/.msdata";
                if (op === 16777233) return "47.6.3";
                return null;
            }},
        }});
        const mod = emu.load(`${{SAMPLE_DIR}}/libmetasec_ov.so`);
        emu.jniOnLoad(mod);
        const a0Cls = emu.jni.findClass("ms/bd/o/a0");
        const strCls = emu.jni.findClass("java/lang/String");
        emu.mem.writeU64(mod.base + 0x209198, strCls);
        const cfg = ["1233", "", "", LICENSE, "v04.04.06-ov-android", "googleplay", "7000000000000000001", "", "7000000000000000002", "", "0", "0", "5", [], []];
        const cfgRef = emu.jni.newString(JSON.stringify(cfg));
        emu.call(mod.base + 0x120be0, emu.jni.envPtr, a0Cls, 67108865, 0, 0, cfgRef, 0);

        const summary = emu.saveTape({tape:?}, "after_init");
        const urlRef = emu.jni.newString("https://api16-normal-no1a.tiktokv.eu/aweme/v2/comment/list/?aweme_id=1&aid=1233&device_id=7000000000000000001");
        const hdrRef = emu.jni.newStringArray(["cookie", "sessionid=demo", "user-agent", "ua"]);
        const arr = emu.jni.getStringArray(emu.call(mod.base + 0x120be0, emu.jni.envPtr, a0Cls, 50331649, 0, 0, urlRef, hdrRef));
        const cp1 = emu.checkpointTape({tape:?}, "after_first_sign");
        rpc.exports = {{
            info() {{
                return {{
                    gorgon: arr[arr.indexOf("X-Gorgon") + 1],
                    baseSize: summary.checkpoints[0].compressedBytes,
                    deltaSize: cp1.compressedBytes,
                }};
            }},
        }};
        "#,
        tape = tape_str
    );

    let s1 = JsSession::new(&[], Path::new("."), true).unwrap();
    s1.eval_source(&record_script).unwrap();
    let r1: serde_json::Value =
        serde_json::from_str(&s1.call_rpc_json("info", "[]").unwrap()).unwrap();
    assert!(r1["gorgon"].as_str().unwrap_or("").starts_with("8404"));
    assert!(r1["deltaSize"].as_u64().unwrap() < r1["baseSize"].as_u64().unwrap());

    // Session 2: 全新会话直接从磁带秒启，且跨后端切入 Unicorn 开启 Trace 执行签名（完全免 load / jniOnLoad / init）！
    let replay_script = format!(
        r#"
        const inspected = Emu.inspectTape({tape:?});
        const emu = Emu.loadTape({tape:?}, {{ backend: "unicorn", checkpoint: "after_init" }});
        emu.jni.hook("com/bytedance/mobsec/metasec/ov/MS", {{
            b(op) {{
                if (op === 65539) return "/data/user/0/com.zhiliaoapp.musically/files/.msdata";
                if (op === 16777233) return "47.6.3";
                return null;
            }},
        }});
        const mod = emu.module("libmetasec_ov.so");
        if (!mod) throw new Error("missing libmetasec_ov.so from tape");
        const a0Cls = emu.jni.findClass("ms/bd/o/a0");
        const urlRef = emu.jni.newString("https://api16-normal-no1a.tiktokv.eu/aweme/v2/comment/list/?aweme_id=2&aid=1233&device_id=7000000000000000001");
        const hdrRef = emu.jni.newStringArray(["cookie", "sessionid=demo", "user-agent", "ua"]);
        emu.trace.start({{ level: "fast", start: mod.base, end: mod.base + mod.size, capacity: 262144 }});
        const arr = emu.jni.getStringArray(emu.call(mod.base + 0x120be0, emu.jni.envPtr, a0Cls, 50331649, 0, 0, urlRef, hdrRef));
        const traceStats = emu.trace.stop();
        rpc.exports = {{
            verify() {{
                return {{
                    checkpoints: inspected.checkpoints.length,
                    sourceBackend: emu.tapeCheckpoint.sourceBackend,
                    backend: emu.backend,
                    gorgon: arr[arr.indexOf("X-Gorgon") + 1],
                    tracedInsns: traceStats.records,
                }};
            }},
        }};
        "#,
        tape = tape_str
    );

    let s2 = JsSession::new(&[], Path::new("."), true).unwrap();
    s2.eval_source(&replay_script).unwrap();
    let r2: serde_json::Value =
        serde_json::from_str(&s2.call_rpc_json("verify", "[]").unwrap()).unwrap();
    assert_eq!(r2["checkpoints"].as_u64(), Some(2));
    assert_eq!(r2["sourceBackend"].as_str(), Some("dynarmic"));
    assert_eq!(r2["backend"].as_str(), Some("unicorn"));
    assert!(r2["gorgon"].as_str().unwrap_or("").starts_with("8404"));
    assert!(
        r2["tracedInsns"].as_u64().unwrap_or(0) > 10_000,
        "expected >10k traced insns after cross-backend tape relay, got {:?}",
        r2["tracedInsns"]
    );

    let _ = std::fs::remove_file(&tape_path);
}

#[test]
fn tape_delta_chain_zero_unmap_remap_mprotect_and_duplicate_label() {
    use unicorn_engine::unicorn_const::Prot;

    let tape_path = temp_tape_path("delta_chain_full");
    let _ = std::fs::remove_file(&tape_path);

    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.chain")
        .build()
        .unwrap();

    // CP0 (BASE): 映射两块匿名区域 A (RW) 与 B (RW)，写入非零数据
    let region_a = {
        let mut mem = std::mem::replace(
            &mut emu.cpu_mut().get_data_mut().mem,
            runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
        );
        let addr = mem
            .mmap(
                emu.cpu_mut(),
                0,
                0x2000,
                Prot::READ | Prot::WRITE,
                "[anon:A]",
                0,
            )
            .unwrap();
        emu.cpu_mut().get_data_mut().mem = mem;
        addr
    };
    emu.cpu_mut().mem_write(region_a, b"PAGE_A_V0_NONZERO").unwrap();
    emu.cpu_mut()
        .mem_write(region_a + 0x1000, b"PAGE_A2_V0_DATA!!")
        .unwrap();
    emu.save_tape(&tape_path, "cp0_base").unwrap();

    // CP1 (DELTA): 额外映射区域 B 并写数据；修改 A 第 1 页
    let region_b = {
        let mut mem = std::mem::replace(
            &mut emu.cpu_mut().get_data_mut().mem,
            runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
        );
        let addr = mem
            .mmap(
                emu.cpu_mut(),
                0,
                0x1000,
                Prot::READ | Prot::WRITE,
                "[anon:B]",
                0,
            )
            .unwrap();
        emu.cpu_mut().get_data_mut().mem = mem;
        addr
    };
    emu.cpu_mut().mem_write(region_a, b"PAGE_A_V1_UPDATED").unwrap();
    emu.cpu_mut().mem_write(region_b, b"REGION_B_V1_ALIVE").unwrap();
    let cp1 = emu.append_tape_checkpoint(&tape_path, "cp1_map_b").unwrap();
    assert!(cp1.is_delta);
    assert!(cp1.stored_pages >= 2);

    // 重复书签名必须被拒绝
    assert!(
        emu.append_tape_checkpoint(&tape_path, "cp1_map_b").is_err(),
        "duplicate checkpoint label must be rejected"
    );

    // CP2 (DELTA): 清零 A+0x1000（触发 zeroed_pages > 0），munmap 区域 B（触发 removed_pages > 0），将 A 改为只读
    let zeros = [0u8; 4096];
    emu.cpu_mut().mem_write(region_a + 0x1000, &zeros).unwrap();
    {
        let mut mem = std::mem::replace(
            &mut emu.cpu_mut().get_data_mut().mem,
            runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
        );
        mem.munmap(emu.cpu_mut(), region_b, 0x1000).unwrap();
        mem.mprotect(emu.cpu_mut(), region_a, 0x2000, Prot::READ).unwrap();
        emu.cpu_mut().get_data_mut().mem = mem;
    }
    let cp2 = emu
        .append_tape_checkpoint(&tape_path, "cp2_zero_unmap_ro")
        .unwrap();
    assert!(cp2.zeroed_pages >= 1, "expected zeroed_pages >= 1, got {}", cp2.zeroed_pages);
    assert!(cp2.removed_pages >= 1, "expected removed_pages >= 1, got {}", cp2.removed_pages);

    // CP3 (DELTA): 重新在 region_b 映射并写入全新数据
    {
        let mut mem = std::mem::replace(
            &mut emu.cpu_mut().get_data_mut().mem,
            runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
        );
        mem.map_labeled(
            emu.cpu_mut(),
            region_b,
            0x1000,
            Prot::READ | Prot::WRITE,
            "[anon:B_reborn]",
            0,
        )
        .unwrap();
        emu.cpu_mut().get_data_mut().mem = mem;
    }
    emu.cpu_mut().mem_write(region_b, b"REGION_B_V3_REBORN").unwrap();
    let cp3 = emu.append_tape_checkpoint(&tape_path, "cp3_remap_b").unwrap();
    assert_eq!(cp3.index, 3);

    // 乱序穿梭验证：CP3 -> CP0 -> CP2 -> CP1 -> CP3
    let tape = Tape::load_file(&tape_path).unwrap();
    assert_eq!(tape.len(), 4);

    // -> CP0: A+0 与 A+0x1000 均为 V0，region_b 未映射
    emu.seek_tape(&tape, &TapeSelector::Index(0)).unwrap();
    assert_eq!(
        emu.cpu().mem_read_as_vec(region_a, 17).unwrap(),
        b"PAGE_A_V0_NONZERO"
    );
    assert_eq!(
        emu.cpu().mem_read_as_vec(region_a + 0x1000, 17).unwrap(),
        b"PAGE_A2_V0_DATA!!"
    );
    assert!(emu.cpu().mem_read_as_vec(region_b, 8).is_err());

    // -> CP2: A+0x1000 已精确清零，region_b 已卸载，A 权限为只读
    emu.seek_tape(&tape, &TapeSelector::Label("cp2_zero_unmap_ro".into()))
        .unwrap();
    assert_eq!(
        emu.cpu().mem_read_as_vec(region_a, 17).unwrap(),
        b"PAGE_A_V1_UPDATED"
    );
    assert_eq!(
        emu.cpu().mem_read_as_vec(region_a + 0x1000, 32).unwrap(),
        vec![0u8; 32]
    );
    assert!(emu.cpu().mem_read_as_vec(region_b, 8).is_err());
    let vma_a = emu
        .cpu()
        .get_data()
        .mem
        .regions()
        .find(|r| r.start == region_a)
        .expect("vma A must exist");
    assert_eq!(vma_a.perms, Prot::READ);

    // -> CP1: region_b 恢复为 V1
    emu.seek_tape(&tape, &TapeSelector::Index(1)).unwrap();
    assert_eq!(
        emu.cpu().mem_read_as_vec(region_b, 17).unwrap(),
        b"REGION_B_V1_ALIVE"
    );

    // -> CP3: region_b 恢复为 V3
    emu.seek_tape(&tape, &TapeSelector::Latest).unwrap();
    assert_eq!(
        emu.cpu().mem_read_as_vec(region_b, 18).unwrap(),
        b"REGION_B_V3_REBORN"
    );

    let _ = std::fs::remove_file(&tape_path);
}

#[test]
fn tape_corrupted_malformed_rejection_and_eventlog_forward_compat() {
    let base_tape_path = temp_tape_path("valid_seed");
    let bad_path = temp_tape_path("malformed_case");
    let _ = std::fs::remove_file(&base_tape_path);
    let _ = std::fs::remove_file(&bad_path);

    // 1. 0 字节占位文件允许 append_tape_checkpoint 自动初始化为 BASE 磁带
    std::fs::write(&base_tape_path, b"").unwrap();
    let emu = AndroidEmulator::builder().build().unwrap();
    let cp0 = emu.append_tape_checkpoint(&base_tape_path, "from_empty").unwrap();
    assert!(!cp0.is_delta);
    assert_eq!(cp0.label, "from_empty");
    let valid_bytes = std::fs::read(&base_tape_path).unwrap();

    // 2. 过短 (<32B)
    std::fs::write(&bad_path, b"RTAPE001").unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 3. 错误魔数
    let mut wrong_magic = valid_bytes.clone();
    wrong_magic[0..8].copy_from_slice(b"BADMAGIC");
    std::fs::write(&bad_path, &wrong_magic).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 4. 不支持的版本 v99
    let mut wrong_ver = valid_bytes.clone();
    wrong_ver[8..12].copy_from_slice(&99u32.to_le_bytes());
    std::fs::write(&bad_path, &wrong_ver).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 5. 未知 flags 位
    let mut bad_flags = valid_bytes.clone();
    bad_flags[12..16].copy_from_slice(&0xFFu32.to_le_bytes());
    std::fs::write(&bad_path, &bad_flags).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 6. 篡改 chunk_count（声明 5 帧但文件只有 1 帧）
    let mut bad_count = valid_bytes.clone();
    bad_count[20..24].copy_from_slice(&5u32.to_le_bytes());
    std::fs::write(&bad_path, &bad_count).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 7. 首帧篡改为 DELTA (tag = 2)
    let mut delta_first = valid_bytes.clone();
    delta_first[32..36].copy_from_slice(&2u32.to_le_bytes());
    std::fs::write(&bad_path, &delta_first).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 8. 未知 chunk tag (tag = 99)
    let mut bad_tag = valid_bytes.clone();
    bad_tag[32..36].copy_from_slice(&99u32.to_le_bytes());
    std::fs::write(&bad_path, &bad_tag).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 9. 畸形超大 uncomp_len (0xFFFF_FFFF) 不得触发 OOM，必须安全返回 Err
    let mut oom_hdr = valid_bytes.clone();
    oom_hdr[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&bad_path, &oom_hdr).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 10. 损坏的 zlib 字节流
    let mut corrupt_zlib = valid_bytes.clone();
    let last = corrupt_zlib.len() - 1;
    corrupt_zlib[last] ^= 0xFF;
    corrupt_zlib[last - 3] ^= 0xAA;
    std::fs::write(&bad_path, &corrupt_zlib).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 11. 截断的 chunk 载荷
    std::fs::write(&bad_path, &valid_bytes[..valid_bytes.len() - 10]).unwrap();
    assert!(Tape::load_file(&bad_path).is_err());

    // 12. 附带二期预留 EVENT_LOG (tag = 3) Chunk 必须前向兼容并安全跳过
    let mut with_event_log = valid_bytes.clone();
    with_event_log.extend_from_slice(&3u32.to_le_bytes()); // tag = CHUNK_EVENT_LOG_RESERVED
    with_event_log.extend_from_slice(&8u32.to_le_bytes()); // uncomp_len
    with_event_log.extend_from_slice(&8u32.to_le_bytes()); // comp_len
    with_event_log.extend_from_slice(b"EVTLOGV2");
    std::fs::write(&bad_path, &with_event_log).unwrap();
    let loaded = Tape::load_file(&bad_path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.checkpoints()[0].label, "from_empty");

    let _ = std::fs::remove_file(&base_tape_path);
    let _ = std::fs::remove_file(&bad_path);
}

#[test]
fn tape_subsystems_vfs_fds_net_regs_and_shared_pt_load_perms() {
    use unicorn_engine::unicorn_const::Prot;
    use unicorn_engine::RegisterARM64;

    let tape_path = temp_tape_path("subsystems_full");
    let _ = std::fs::remove_file(&tape_path);

    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.subsys")
        .build()
        .unwrap();

    // 1. VFS 打开 FD + 写入 + 推进游标 + 自定义 VirtualNic
    emu.vfs_mut()
        .add_overlay_file("/data/local/tmp/stream.bin", b"0123456789ABCDEF".to_vec());
    let fd = {
        let data = emu.cpu_mut().get_data_mut();
        data.vfs.open("/data/local/tmp/stream.bin", &data.mem) as i32
    };
    assert!(fd >= 3);
    let head = emu.vfs_mut().read(fd, 6).unwrap();
    assert_eq!(head, b"012345");
    emu.vfs_mut().net.config.nic.name = "eth9".to_string();
    emu.vfs_mut().net.config.nic.mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x09];
    emu.vfs_mut().net.config.nic.ipv4 = [10, 42, 0, 7];

    // 2. 共享 4KB 页：先 RX 后 RW 映射同一页（模拟真实 ELF 相邻 PT_LOAD 共享页边界）
    let shared_page = 0x5000_0000u64;
    {
        let mut mem = std::mem::replace(
            &mut emu.cpu_mut().get_data_mut().mem,
            runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
        );
        mem.map_labeled(
            emu.cpu_mut(),
            shared_page,
            0x1000,
            Prot::READ | Prot::EXEC,
            "shared.so",
            0,
        )
        .unwrap();
        mem.map_labeled(
            emu.cpu_mut(),
            shared_page,
            0x1000,
            Prot::READ | Prot::WRITE,
            "shared.so",
            0,
        )
        .unwrap();
        emu.cpu_mut().get_data_mut().mem = mem;
    }
    // 在共享页写入 2 条 ARM64 指令: mov x0, #0x42; ret
    let code: [u32; 2] = [0xD280_0840, 0xD65F_03C0];
    let mut code_bytes = [0u8; 8];
    code_bytes[0..4].copy_from_slice(&code[0].to_le_bytes());
    code_bytes[4..8].copy_from_slice(&code[1].to_le_bytes());
    emu.cpu_mut().mem_write(shared_page, &code_bytes).unwrap();

    // 3. 完整寄存器：Q0 / Q31 (128-bit NEON)、NZCV、TPIDR_EL0、FPCR/FPSR
    let q0_val: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
    let q31_val: u128 = 0xCAFE_BABE_DEAD_BEEF_1122_3344_5566_7788;
    emu.cpu_mut().reg_write_q(0, q0_val).unwrap();
    emu.cpu_mut().reg_write_q(31, q31_val).unwrap();
    emu.cpu_mut().reg_write(RegisterARM64::NZCV, 0xA000_0000).unwrap();
    emu.cpu_mut().reg_write(RegisterARM64::TPIDR_EL0, 0x1234_5678).unwrap();

    // 4. JNI 自定义对象实例字段
    let obj = emu.jni_mut().objects.add_local(
        runidbg_arm64_emu_tracer::jni::JObject::Custom {
            class_name: "com/example/Box".to_string(),
            fields: std::collections::HashMap::new(),
        },
    );
    emu.jni_mut()
        .set_instance_field(obj, "secret", JValue::Long(9876543210));
    emu.jni_mut().objects.new_global(obj);

    emu.save_tape(&tape_path, "subsys_base").unwrap();

    // 从磁盘重新恢复到全新 Unicorn 实例并逐项验证
    let (mut emu2, _) = AndroidEmulator::from_tape(&tape_path, BackendKind::Unicorn).unwrap();

    // 验证 VFS FD 游标续读（紧接着 "012345" 应读到 "6789"）
    let tail = emu2.vfs_mut().read(fd, 4).unwrap();
    assert_eq!(tail, b"6789");
    // 验证 VirtualNic 保留
    assert_eq!(emu2.vfs().net.config.nic.name, "eth9");
    assert_eq!(emu2.vfs().net.config.nic.mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x09]);
    assert_eq!(emu2.vfs().net.config.nic.ipv4, [10, 42, 0, 7]);
    // 验证寄存器（Q0/Q31/NZCV/TPIDR_EL0）精确还原
    assert_eq!(emu2.cpu().reg_read_q(0).unwrap(), q0_val);
    assert_eq!(emu2.cpu().reg_read_q(31).unwrap(), q31_val);
    assert_eq!(
        emu2.cpu().reg_read(RegisterARM64::NZCV).unwrap() & 0xF000_0000,
        0xA000_0000
    );
    assert_eq!(
        emu2.cpu().reg_read(RegisterARM64::TPIDR_EL0).unwrap(),
        0x1234_5678
    );
    // 验证 JNI 实例字段还原
    assert_eq!(
        emu2.jni().get_instance_field(obj, "secret"),
        Some(JValue::Long(9876543210))
    );
    // 验证共享 4KB 页未发生权限降级（Unicorn 可直接取指执行且可写）
    let ret = emu2.call_address(shared_page, &[]).unwrap();
    assert_eq!(ret, 0x42);

    let _ = std::fs::remove_file(&tape_path);
}

#[cfg(feature = "dynarmic")]
#[test]
fn tape_gdb_resume_preserves_lr_and_cross_backend_symbol_debug() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use unicorn_engine::unicorn_const::Prot;
    use unicorn_engine::RegisterARM64;

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

    let tape_path = temp_tape_path("gdb_resume_dyn_to_uc");
    let _ = std::fs::remove_file(&tape_path);

    // 在 Dynarmic 上构造中段暂停现场：PC=0x5100_0000, LR=0x5100_0088, X0=10, X1=32
    // 指令: add x0, x0, x1; ret
    let code_addr = 0x5100_0000u64;
    let fake_caller_lr = 0x5100_0088u64;
    {
        let mut dyn_emu = AndroidEmulator::builder()
            .backend(BackendKind::Dynarmic)
            .build()
            .unwrap();
        {
            let mut mem = std::mem::replace(
                &mut dyn_emu.cpu_mut().get_data_mut().mem,
                runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
            );
            mem.map_labeled(
                dyn_emu.cpu_mut(),
                code_addr,
                0x1000,
                Prot::READ | Prot::EXEC,
                "[anon:code]",
                0,
            )
            .unwrap();
            dyn_emu.cpu_mut().get_data_mut().mem = mem;
        }
        let insns: [u32; 2] = [0x8B01_0000, 0xD65F_03C0]; // add x0, x0, x1; ret
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&insns[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&insns[1].to_le_bytes());
        dyn_emu.cpu_mut().mem_write(code_addr, &bytes).unwrap();
        dyn_emu.cpu_mut().reg_write(RegisterARM64::X0, 10).unwrap();
        dyn_emu.cpu_mut().reg_write(RegisterARM64::X1, 32).unwrap();
        dyn_emu.cpu_mut().reg_write(RegisterARM64::LR, fake_caller_lr).unwrap();
        dyn_emu.cpu_mut().reg_write(RegisterARM64::PC, code_addr).unwrap();
        dyn_emu.save_tape(&tape_path, "mid_fn").unwrap();
    }

    // 跨后端加载进 Unicorn 并以 serve_listener_resume 启动 GDB RSP，验证 LR 不被覆写且单步执行生效
    let (mut uc_emu, _) = AndroidEmulator::from_tape(&tape_path, BackendKind::Unicorn).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    fn decode_le_u64_hex(s: &str) -> u64 {
        assert_eq!(s.len(), 16, "expected 16 hex chars for u64, got `{s}`");
        let mut bytes = [0u8; 8];
        for i in 0..8 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        u64::from_le_bytes(bytes)
    }

    let client_thread = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        assert_eq!(rsp_send(&mut s, "?"), "S05");
        // 读取 LR (reg 30 = 0x1e) 与 PC (reg 32 = 0x20)
        let lr_hex = rsp_send(&mut s, "p1e");
        let pc_hex = rsp_send(&mut s, "p20");
        assert_eq!(
            decode_le_u64_hex(&lr_hex),
            fake_caller_lr,
            "serve_listener_resume must preserve saved LR instead of overwriting with RET_MAGIC_ADDR"
        );
        assert_eq!(decode_le_u64_hex(&pc_hex), code_addr);
        // 单步执行 `add x0, x0, x1`
        assert_eq!(rsp_send(&mut s, "s"), "S05");
        let x0_hex = rsp_send(&mut s, "p0");
        let pc2_hex = rsp_send(&mut s, "p20");
        assert_eq!(decode_le_u64_hex(&x0_hex), 42);
        assert_eq!(decode_le_u64_hex(&pc2_hex), code_addr + 4);
        // `k` (kill) 关闭调试会话，无响应包
        let _ = s.write_all(b"$k#6b");
        let _ = s.flush();
    });

    runidbg_arm64_emu_tracer::debug::GdbServer::serve_listener_resume(&mut uc_emu, listener)
        .unwrap();
    client_thread.join().unwrap();

    let _ = std::fs::remove_file(&tape_path);
}

#[cfg(all(feature = "js", feature = "rpc"))]
#[test]
fn tape_js_comprehensive_api_hooks_and_mod_stability() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let tape_path = temp_tape_path("js_comprehensive");
    let _ = std::fs::remove_file(&tape_path);
    let tape_str = tape_path.to_string_lossy().into_owned();

    let script = format!(
        r#"
        const emu = Emu.create({{ backend: null, packageName: "com.example.js.tape" }});
        const webp = emu.load("samples/libstatic-webp.so");
        const verFn = webp.symbol("WebPGetDecoderVersion");
        if (!verFn) throw new Error("missing WebPGetDecoderVersion");

        // 1. 缺省/null label 应回退为 "base" / "cp_1"，而不是字面量 "null"
        const s0 = emu.saveTape({tape:?}, null);
        if (s0.checkpoints[0].label !== "base") {{
            throw new Error("expected default label 'base', got " + s0.checkpoints[0].label);
        }}

        // 2. 安装 replace hook 后录制增量检查点：保存的磁带绝不能把补丁 RET 烘烤进去！
        let hookTriggered = 0;
        const hRep = emu.hook.replace(verFn, () => {{
            hookTriggered++;
            return 0x1337;
        }});
        if (webp.call("WebPGetDecoderVersion") !== 0x1337) {{
            throw new Error("replace hook did not intercept");
        }}
        const cp1 = emu.checkpointTape({tape:?}, null);
        if (cp1.label !== "cp_1") {{
            throw new Error("expected default delta label 'cp_1', got " + cp1.label);
        }}

        // 3. 在 hook.code 回调内调用 saveTape 必须抛出 JS 异常，不能 Rust panic
        let reentrantBlocked = false;
        const hCode = emu.hook.code([verFn, verFn + 4], () => {{
            try {{
                emu.saveTape({tape:?}, "bad_reentrant");
            }} catch (e) {{
                reentrantBlocked = true;
            }}
        }});
        webp.call("WebPGetDecoderVersion");
        hCode.detach();
        if (!reentrantBlocked) throw new Error("reentrant saveTape should throw JS error");

        // 4. 加载第二个模块后倒带回 cp0，验证既有 webp mod._id 仍指向 libstatic-webp.so，
        //    同时 zstd 句柄失效报错，且活跃 replace hook 在 seekTape 后依然有效，emu.tapeCheckpoint 同步更新
        const zstd = emu.load("samples/libzstd-jni-1.5.7-28.so");
        const cp2 = emu.checkpointTape({tape:?}, "with_zstd");
        const rewound = emu.seekTape({tape:?}, 0);
        if (!emu.tapeCheckpoint || emu.tapeCheckpoint.label !== "base" || rewound.index !== 0) {{
            throw new Error("emu.tapeCheckpoint getter did not update on seekTape");
        }}
        if (webp.call("WebPGetDecoderVersion") !== 0x1337) {{
            throw new Error("replace hook stopped working after seekTape");
        }}
        let staleModErrored = false;
        try {{
            zstd.symbol("ZSTD_compressBound");
        }} catch (e) {{
            staleModErrored = true;
        }}
        if (!staleModErrored) throw new Error("unloaded module handle should fail after rewind");

        // 5. 开启 Unicorn Tracer 后执行 seekTape：绝不能产生任何幽灵 0xDEAD_1040 内部指令记录
        emu.trace.start({{ level: "fast", capacity: 1024 }});
        emu.seekTape({tape:?}, "with_zstd");
        const tStats = emu.trace.stop();
        if (tStats.records !== 0) {{
            throw new Error("seekTape polluted active tracer with " + tStats.records + " records");
        }}
        hRep.detach();

        // 6. 新实例加载 cp1（曾安装 replace hook 时录盘），验证未烘烤 RET 且返回真实 WebP 版本号
        const emu2 = Emu.loadTape({tape:?}, {{ checkpoint: "cp_1", backend: null }});
        const mByPath = emu2.module("samples/libstatic-webp.so");
        if (!mByPath) throw new Error("emu.module(path) should match basename");
        const realVer = mByPath.call("WebPGetDecoderVersion");
        if (realVer === 0x1337 || realVer === 0) {{
            throw new Error("replace hook RET leaked into saved tape! got " + realVer);
        }}

        // 7. 非法 checkpoint 参数（负数、小数、空字符串）必须显式抛错
        const badCps = [-1, 1.5, ""];
        let badRejected = 0;
        for (const bad of badCps) {{
            try {{
                emu2.seekTape({tape:?}, bad);
            }} catch (e) {{
                badRejected++;
            }}
        }}
        if (badRejected !== badCps.length) {{
            throw new Error("expected all invalid checkpoints rejected, got " + badRejected);
        }}

        rpc.exports = {{
            summary() {{
                return {{
                    realVer,
                    hookTriggered,
                    cpCount: Emu.inspectTape({tape:?}).checkpoints.length,
                    cp2Label: cp2.label,
                }};
            }},
        }};
        "#,
        tape = tape_str
    );

    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    session.eval_source(&script).unwrap();
    let res: serde_json::Value =
        serde_json::from_str(&session.call_rpc_json("summary", "[]").unwrap()).unwrap();
    assert!(res["realVer"].as_u64().unwrap_or(0) > 0x010000);
    assert!(res["hookTriggered"].as_u64().unwrap_or(0) >= 3);
    assert_eq!(res["cpCount"].as_u64(), Some(3));
    assert_eq!(res["cp2Label"].as_str(), Some("with_zstd"));

    let _ = std::fs::remove_file(&tape_path);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "hypervisor"))]
#[test]
fn tape_hypervisor_cross_backend_relay_and_trace() {
    use unicorn_engine::RegisterARM64;

    // 若测试二进制未签 com.apple.security.hypervisor entitlement，优雅跳过；签名后在真机 M4 上完整实测
    let probe = AndroidEmulator::builder()
        .backend(BackendKind::Hypervisor)
        .build();
    let mut hv_emu = match probe {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "[skip] Hypervisor.framework entitlement not signed on test binary: {err}"
            );
            return;
        }
    };

    let tape_hv = temp_tape_path("relay_hv_to_uc");
    let tape_uc = temp_tape_path("relay_uc_to_hv");
    let _ = std::fs::remove_file(&tape_hv);
    let _ = std::fs::remove_file(&tape_uc);

    let payload: Vec<u8> = (0..4096u32)
        .map(|i| ((i * 53) ^ (i >> 2) ^ 0x5A) as u8)
        .collect();

    // 1. Hypervisor.framework 加载 ZSTD + 准备输入缓冲 + 写入自定义 NZCV/Q0 -> 落盘磁带
    let zstd = hv_emu
        .load_library("samples/libzstd-jni-1.5.7-28.so")
        .unwrap();
    let bound = hv_emu
        .call_symbol(&zstd, "ZSTD_compressBound", &[payload.len() as u64])
        .unwrap();
    let src = hv_emu
        .cpu_mut()
        .get_data_mut()
        .mem
        .alloc_heap(payload.len() as u64)
        .unwrap();
    let dst = hv_emu.cpu_mut().get_data_mut().mem.alloc_heap(bound).unwrap();
    let out = hv_emu
        .cpu_mut()
        .get_data_mut()
        .mem
        .alloc_heap(payload.len() as u64)
        .unwrap();
    hv_emu.cpu_mut().mem_write(src, &payload).unwrap();
    let q7_magic: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;
    hv_emu.cpu_mut().reg_write_q(7, q7_magic).unwrap();
    hv_emu
        .cpu_mut()
        .reg_write(RegisterARM64::NZCV, 0x6000_0000)
        .unwrap();
    hv_emu.save_tape(&tape_hv, "hv_ready").unwrap();
    drop(hv_emu);

    // 2. Hypervisor -> Unicorn 接力 + 指令级 Trace！
    {
        let (mut uc_emu, info) =
            AndroidEmulator::from_tape(&tape_hv, BackendKind::Unicorn).unwrap();
        assert_eq!(info.source_backend, "hypervisor");
        assert_eq!(uc_emu.cpu().reg_read_q(7).unwrap(), q7_magic);
        assert_eq!(
            uc_emu.cpu().reg_read(RegisterARM64::NZCV).unwrap() & 0xF000_0000,
            0x6000_0000
        );
        let zstd = uc_emu
            .linker()
            .get_module("libzstd-jni-1.5.7-28.so")
            .cloned()
            .unwrap();
        uc_emu
            .set_tracer(
                runidbg_arm64_emu_tracer::tracer::BinaryTracer::new_in_memory_with_level(
                    262_144,
                    TraceLevel::Fast,
                ),
            )
            .unwrap();
        let comp_len = uc_emu
            .call_symbol(
                &zstd,
                "ZSTD_compress",
                &[dst, bound, src, payload.len() as u64, 3],
            )
            .unwrap();
        let dec_len = uc_emu
            .call_symbol(
                &zstd,
                "ZSTD_decompress",
                &[out, payload.len() as u64, dst, comp_len],
            )
            .unwrap();
        uc_emu.detach_tracer().unwrap();
        assert_eq!(dec_len as usize, payload.len());
        assert_eq!(
            uc_emu.cpu().mem_read_as_vec(out, payload.len()).unwrap(),
            payload
        );
        assert!(uc_emu.tracer().stats.recorded_insns > 1000);
        uc_emu.save_tape(&tape_uc, "uc_back_to_hv").unwrap();
    }

    // 3. Unicorn -> Hypervisor 反向接力并再次在 Apple Silicon 真机硬件虚拟化执行 ZSTD！
    {
        let (mut hv_emu2, info) =
            AndroidEmulator::from_tape(&tape_uc, BackendKind::Hypervisor).unwrap();
        assert_eq!(info.source_backend, "unicorn");
        let zstd = hv_emu2
            .linker()
            .get_module("libzstd-jni-1.5.7-28.so")
            .cloned()
            .unwrap();
        let comp_len = hv_emu2
            .call_symbol(
                &zstd,
                "ZSTD_compress",
                &[dst, bound, src, payload.len() as u64, 3],
            )
            .unwrap();
        let dec_len = hv_emu2
            .call_symbol(
                &zstd,
                "ZSTD_decompress",
                &[out, payload.len() as u64, dst, comp_len],
            )
            .unwrap();
        assert_eq!(dec_len as usize, payload.len());
        assert_eq!(
            hv_emu2.cpu().mem_read_as_vec(out, payload.len()).unwrap(),
            payload
        );
    }

    let _ = std::fs::remove_file(&tape_hv);
    let _ = std::fs::remove_file(&tape_uc);
}
