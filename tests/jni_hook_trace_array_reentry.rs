#![cfg(all(feature = "js", feature = "rpc"))]

use std::path::Path;

use runidbg_arm64_emu_tracer::script::JsSession;

#[test]
fn jni_trace_hook_hits_array_readers_and_reentrant_get_field() {
    let script = r#"
        const emu = Emu.create({ packageName: "com.example.cas" });

        // 1. 验证数组创建与读取接口（含 number[] 直接传给 newByteArray 与无效句柄保护）
        const bRef = emu.jni.newByteArray([1, 2, 255]);
        const cRef = emu.jni.newCharArray("hi");
        const iRef = emu.jni.newIntArray([-10, 0, 42]);
        const jRef = emu.jni.newLongArray([100, 200, 300]);

        const readBytes = emu.jni.getByteArray(bRef);
        const readChars = emu.jni.getCharArray(cRef);
        const readInts = emu.jni.getIntArray(iRef);
        const readLongs = emu.jni.getLongArray(jRef);
        const invalidBytes = emu.jni.getByteArray(0);
        const invalidChars = emu.jni.getCharArray(bRef);

        // 2. 准备 cas/t0 实例（带字段 a），并注册：
        //    - java/util/Map.get 恒返回 null 的 hook（验证 handled=true + hookId）
        //    - cas/t0.a([J)Ljava/lang/String; 回调内重入调用 getField / setField / getLongArray
        //    - 一个从不触发的 hook（验证 listHooks().hits === 0）
        const t0Obj = emu.jni.newObject("cas/t0");
        emu.jni.setField(t0Obj, "a", "field_a_val");
        const mapObj = emu.jni.newObject("java/util/HashMap");

        let reentrantCatchMsg = null;
        emu.jni.hookMethod("java/util/Map", {
            "get(Ljava/lang/Object;)Ljava/lang/Object;": function () {
                return null;
            },
        });
        emu.jni.hookMethod("cas/t0", {
            "a([J)Ljava/lang/String;": function (self, arrRef) {
                const fRef = emu.jni.getField(self, "a");
                const fVal = emu.jni.getString(fRef);
                emu.jni.setField(self, "seen", "yes");
                const longs = emu.jni.getLongArray(arrRef);
                // 验证非重入 API 在回调内抛出可捕获的 JS Error，而非 RefCell abort
                try {
                    emu.jni.getStaticField("cas/t0", "nonexistent");
                } catch (e) {
                    reentrantCatchMsg = String(e);
                }
                return emu.jni.newString(`${fVal}:${longs.join(",")}`);
            },
        });
        emu.jni.hookMethod("cas/never", {
            "unused()V": function () {},
        });

        // 3. 通过 JNIEnv 虚表直接发起 CallObjectMethod（模拟 native .so 调用）
        const envPtr = emu.jni.envPtr;
        const vtablePtr = Number(emu.mem.readU64(envPtr));
        const fnFindClass = Number(emu.mem.readU64(vtablePtr + 6 * 8));
        const fnGetMethodId = Number(emu.mem.readU64(vtablePtr + 33 * 8));
        const fnCallObjectMethod = Number(emu.mem.readU64(vtablePtr + 34 * 8));

        function cstr(s) {
            const p = emu.mem.alloc(s.length + 1);
            emu.mem.writeCString(p, s);
            return p;
        }

        const clsMap = emu.call(fnFindClass, envPtr, cstr("java/util/Map"));
        const midMapGet = emu.call(
            fnGetMethodId,
            envPtr,
            clsMap,
            cstr("get"),
            cstr("(Ljava/lang/Object;)Ljava/lang/Object;")
        );

        const clsT0 = emu.call(fnFindClass, envPtr, cstr("cas/t0"));
        const midT0A = emu.call(
            fnGetMethodId,
            envPtr,
            clsT0,
            cstr("a"),
            cstr("([J)Ljava/lang/String;")
        );
        const midT0Unhooked = emu.call(
            fnGetMethodId,
            envPtr,
            clsT0,
            cstr("unhooked"),
            cstr("()Ljava/lang/String;")
        );

        emu.jni.trace.start();
        const keyRef = emu.jni.newString("missing_key");
        const mapRet = emu.call(fnCallObjectMethod, envPtr, mapObj, midMapGet, keyRef);
        const t0Ret = emu.call(fnCallObjectMethod, envPtr, t0Obj, midT0A, jRef);
        const unhookedRet = emu.call(fnCallObjectMethod, envPtr, t0Obj, midT0Unhooked);
        const events = emu.jni.trace.events();
        emu.jni.trace.stop();

        const hooks = emu.jni.listHooks();
        const seenField = emu.jni.getString(emu.jni.getField(t0Obj, "seen"));

        rpc.exports = {
            verify() {
                return {
                    readBytes,
                    readChars,
                    readInts,
                    readLongs,
                    invalidBytes,
                    invalidChars,
                    mapRet,
                    t0RetStr: emu.jni.getString(t0Ret),
                    unhookedRet,
                    seenField,
                    reentrantCatchMsg,
                    events,
                    hooks,
                };
            },
        };
    "#;

    let session = JsSession::new(&[], Path::new("."), true).expect("create JsSession");
    session.eval_source(script).expect("eval script");
    let raw = session
        .call_rpc_json("verify", "[]")
        .expect("call verify export");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse verify json");

    // Issue 2: 数组读取接口
    assert_eq!(v["readBytes"], serde_json::json!([1, 2, 255]));
    assert_eq!(v["readChars"], serde_json::json!("hi"));
    assert_eq!(v["readInts"], serde_json::json!([-10, 0, 42]));
    assert_eq!(v["readLongs"], serde_json::json!([100, 200, 300]));
    assert_eq!(v["invalidBytes"], serde_json::json!([]));
    assert_eq!(v["invalidChars"], serde_json::json!(""));

    // Issue 3: hook 回调内重入 getField / setField / getLongArray + 非重入抛可捕获异常
    assert_eq!(v["t0RetStr"].as_str(), Some("field_a_val:100,200,300"));
    assert_eq!(v["seenField"].as_str(), Some("yes"));
    assert!(
        v["reentrantCatchMsg"]
            .as_str()
            .is_some_and(|s| s.contains("不可重入")),
        "expected catchable reentrancy error, got: {:?}",
        v["reentrantCatchMsg"]
    );

    // Issue 1: trace 事件 handled + hookId 与 listHooks().hits
    let hooks = v["hooks"].as_array().expect("hooks array");
    let map_hook = hooks
        .iter()
        .find(|h| h["className"] == "java/util/Map" && h["name"] == "get")
        .expect("map hook");
    let t0_hook = hooks
        .iter()
        .find(|h| h["className"] == "cas/t0" && h["name"] == "a")
        .expect("t0 hook");
    let never_hook = hooks
        .iter()
        .find(|h| h["className"] == "cas/never" && h["name"] == "unused")
        .expect("never hook");
    assert_eq!(map_hook["hits"].as_u64(), Some(1));
    assert_eq!(t0_hook["hits"].as_u64(), Some(1));
    assert_eq!(never_hook["hits"].as_u64(), Some(0));

    let events = v["events"].as_array().expect("events array");
    let map_ev = events
        .iter()
        .find(|e| e["op"] == "CallObjectMethod" && e["member"] == "get")
        .expect("map get event");
    assert_eq!(map_ev["isNull"].as_bool(), Some(true));
    assert_eq!(map_ev["handled"].as_bool(), Some(true));
    assert_eq!(map_ev["hookId"], map_hook["id"]);

    let t0_ev = events
        .iter()
        .find(|e| e["op"] == "CallObjectMethod" && e["member"] == "a")
        .expect("t0.a event");
    assert_eq!(t0_ev["handled"].as_bool(), Some(true));
    assert_eq!(t0_ev["hookId"], t0_hook["id"]);

    let unhooked_ev = events
        .iter()
        .find(|e| e["op"] == "CallObjectMethod" && e["member"] == "unhooked")
        .expect("unhooked event");
    assert_eq!(unhooked_ev["isNull"].as_bool(), Some(true));
    assert_eq!(unhooked_ev["handled"].as_bool(), Some(false));
    assert!(unhooked_ev["hookId"].is_null());
}
