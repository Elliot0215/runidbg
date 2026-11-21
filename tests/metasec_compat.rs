#![cfg(all(feature = "js", any(feature = "rpc", feature = "mcp")))]

use std::path::Path;

use runidbg_arm64_emu_tracer::script::JsSession;

#[test]
fn tiktok_metasec_offline_cylons_and_gorgon_family() {
    let so_path = Path::new("samples/metasec/libmetasec_ov.so");
    assert!(so_path.exists(), "缺少测试样本: {}", so_path.display());

    let script = r#"
        const SAMPLE_DIR = "samples/metasec";
        const emu = Emu.create({
            packageName: "com.zhiliaoapp.musically",
            searchPaths: [SAMPLE_DIR],
            device: "pixel8pro",
            realClock: true,
        });
        emu.diag.enable();
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
                const diag = emu.diag.report();
                return {
                    ver,
                    cylonsLen: (c["X-Cylons"] || "").length,
                    argusLen: (g["X-Argus"] || "").length,
                    gorgonLen: (g["X-Gorgon"] || "").length,
                    gorgonPrefix: (g["X-Gorgon"] || "").slice(0, 4),
                    khronosLen: (g["X-Khronos"] || "").length,
                    ladonLen: (g["X-Ladon"] || "").length,
                    missingJniCount: Object.keys(diag.missingJni).length,
                    missingJni: diag.missingJni,
                };
            },
        };
    "#;

    let session = JsSession::new(&[], Path::new("."), true).expect("create JsSession");
    session.eval_source(script).expect("eval metasec script");
    let raw = session
        .call_rpc_json("verify", "[]")
        .expect("call verify export");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse verify json");

    assert_eq!(v["ver"].as_u64(), Some(0x10006));
    assert!(v["cylonsLen"].as_u64().unwrap_or(0) >= 16);
    assert!(v["argusLen"].as_u64().unwrap_or(0) >= 300);
    assert_eq!(v["gorgonLen"].as_u64(), Some(52));
    assert_eq!(v["gorgonPrefix"].as_str(), Some("8404"));
    assert_eq!(v["khronosLen"].as_u64(), Some(10));
    assert_eq!(v["ladonLen"].as_u64(), Some(48));
    assert_eq!(
        v["missingJniCount"].as_u64(),
        Some(0),
        "unexpected missingJni: {}",
        v["missingJni"]
    );
}

#[test]
fn native_hook_can_read_jni_objects_and_build_fields_match_device_profile() {
    let script = r#"
        const emu = Emu.create({
            packageName: "com.example.test",
            device: "pixel8pro",
        });
        emu.diag.enable();

        // 1. 验证 Native code hook 中调用 emu.jni.getString 不会触发 RefCell panic
        const mod = emu.load("samples/libstatic-webp.so");
        const fnAddr = mod.symbol("WebPGetDecoderVersion");
        const testStrRef = emu.jni.newString("hello_from_hook");
        let observedInHook = null;
        emu.hook.code(fnAddr, () => {
            observedInHook = emu.jni.getString(testStrRef);
        }, { once: true });
        mod.call("WebPGetDecoderVersion");

        // 2. 验证 android/os/Build 与 Build$VERSION 静态字段自动同步 DeviceProfile
        const JNI_TRAMP = 0x18010000;
        const slot = (n) => JNI_TRAMP + (16 + n) * 4;
        const cstr = (s) => {
            const p = emu.mem.alloc(s.length + 1);
            emu.mem.writeCString(p, s);
            return p;
        };
        const buildCls = emu.jni.findClass("android/os/Build");
        const verCls = emu.jni.findClass("android/os/Build$VERSION");
        const modelFid = emu.call(slot(144), emu.jni.envPtr, buildCls, cstr("MODEL"), cstr("Ljava/lang/String;"));
        const modelRef = emu.call(slot(145), emu.jni.envPtr, buildCls, modelFid);
        const sdkFid = emu.call(slot(144), emu.jni.envPtr, verCls, cstr("SDK_INT"), cstr("I"));
        const sdkInt = emu.call(slot(150), emu.jni.envPtr, verCls, sdkFid);

        rpc.exports = {
            check() {
                return {
                    observedInHook,
                    model: emu.jni.getString(modelRef),
                    sdkInt,
                };
            },
        };
    "#;

    let session = JsSession::new(&[], Path::new("."), true).expect("create JsSession");
    session.eval_source(script).expect("eval hook+build test");
    let raw = session.call_rpc_json("check", "[]").expect("call check");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse check json");

    assert_eq!(v["observedInHook"].as_str(), Some("hello_from_hook"));
    assert_eq!(v["model"].as_str(), Some("Pixel 8 Pro"));
    assert_eq!(v["sdkInt"].as_u64(), Some(34));
}

#[test]
fn heap_freelist_local_frame_and_snapshot_restore_reclaim_memory() {
    let script = r#"
        const emu = Emu.create({ packageName: "com.example.heaptest" });
        const baselineHeap = emu.mem.heapUsed();
        const baselineObjs = emu.jni.objectCount();

        // 1. 反复 alloc + free 1000 次（4KB * 1000 = 4MB），验证空闲链表合并复用不会涨堆
        for (let i = 0; i < 1000; i++) {
            const p = emu.mem.alloc(4096);
            if (!emu.mem.free(p)) throw new Error("free failed at " + i);
        }
        const afterAllocFreeHeap = emu.mem.heapUsed();

        // 2. 反复在 withLocalFrame 内创建 JNI 字符串与数组，验证对象表恒定不涨
        for (let i = 0; i < 200; i++) {
            emu.jni.withLocalFrame(() => {
                emu.jni.newString("tmp_" + i);
                emu.jni.newStringArray(["k1", "v1", "k2", "v2"]);
            });
        }
        const afterLocalFrameObjs = emu.jni.objectCount();

        // 3. 验证 snapshot() + restore() 会同时重置模拟堆分配器与 JNI 引用表
        const snap = emu.snapshot();
        const leakedPtr = emu.mem.alloc(65536);
        emu.jni.newString("leaked_before_restore");
        const beforeRestoreHeap = emu.mem.heapUsed();
        const beforeRestoreObjs = emu.jni.objectCount();

        emu.restore(snap);
        const afterRestoreHeap = emu.mem.heapUsed();
        const afterRestoreObjs = emu.jni.objectCount();

        rpc.exports = {
            report() {
                return {
                    baselineHeap,
                    afterAllocFreeHeap,
                    baselineObjs,
                    afterLocalFrameObjs,
                    leakedPtr,
                    beforeRestoreHeap,
                    afterRestoreHeap,
                    beforeRestoreObjs,
                    afterRestoreObjs,
                };
            },
        };
    "#;

    let session = JsSession::new(&[], Path::new("."), true).expect("create JsSession");
    session.eval_source(script).expect("eval heap/snapshot test");
    let raw = session.call_rpc_json("report", "[]").expect("call report");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse report json");

    assert_eq!(v["afterAllocFreeHeap"], v["baselineHeap"]);
    assert_eq!(v["afterLocalFrameObjs"], v["baselineObjs"]);
    assert!(v["beforeRestoreHeap"].as_u64().unwrap() >= v["baselineHeap"].as_u64().unwrap() + 65536);
    assert_eq!(v["afterRestoreHeap"], v["baselineHeap"]);
    assert_eq!(v["beforeRestoreObjs"].as_u64().unwrap(), v["baselineObjs"].as_u64().unwrap() + 1);
    assert_eq!(v["afterRestoreObjs"], v["baselineObjs"]);
}
