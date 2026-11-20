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
    assert_eq!(v["missingJniCount"].as_u64(), Some(0));
}
