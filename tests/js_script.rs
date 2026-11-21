#![cfg(feature = "js")]

use std::path::Path;

use runidbg_arm64_emu_tracer::script::{write_type_definitions, JsRunner};

#[test]
fn js_mem_vfs_snapshot_and_helpers() {
    let script = r#"
        if (args.length !== 2 || args[0] !== "hello" || args[1] !== "42") {
            throw new Error("unexpected args: " + JSON.stringify(args));
        }

        const emu = Emu.create({ packageName: "com.test.js", hleAccel: true });

        // Memory read/write
        const buf = emu.mem.alloc(128);
        if (buf === 0) throw new Error("alloc failed");

        emu.mem.writeCString(buf, "runidbg-quickjs");
        const s = emu.mem.readCString(buf);
        if (s !== "runidbg-quickjs") throw new Error("readCString mismatch: " + s);

        emu.mem.writeU32(buf + 32, 0xdeadbeef);
        if (emu.mem.readU32(buf + 32) !== 0xdeadbeef) {
            throw new Error("readU32 mismatch");
        }

        const bigVal = 0x1122334455667788n;
        emu.mem.writeU64(buf + 40, bigVal);
        if (emu.mem.readU64(buf + 40) !== bigVal) {
            throw new Error("readU64 mismatch: " + emu.mem.readU64(buf + 40));
        }

        const raw = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        emu.mem.writeBytes(buf + 64, raw);
        const got = emu.mem.readBytes(buf + 64, 4);
        if (hex(got) !== "deadbeef") throw new Error("hex/readBytes mismatch: " + hex(got));

        // Snapshot & restore
        const snap = emu.snapshot();
        emu.mem.writeU32(buf + 32, 0x12345678);
        if (emu.mem.readU32(buf + 32) !== 0x12345678) throw new Error("mutate failed");
        emu.restore(snap);
        if (emu.mem.readU32(buf + 32) !== 0xdeadbeef) {
            throw new Error("snapshot restore failed");
        }

        // VFS
        emu.vfs.setProperty("ro.product.model", "Pixel 8 Pro");
        emu.vfs.writeFile("/data/local/tmp/test.txt", "hello-vfs");
        const fileBytes = emu.vfs.readFile("/data/local/tmp/test.txt");
        if (!fileBytes || fileBytes.length !== 9) {
            throw new Error("vfs readFile text mismatch");
        }
        emu.vfs.writeFile("/data/local/tmp/bin.dat", new Uint8Array([1, 2, 3, 4]));
        const binBytes = emu.vfs.readFile("/data/local/tmp/bin.dat");
        if (!binBytes || hex(binBytes) !== "01020304") {
            throw new Error("vfs readFile bytes mismatch");
        }
        if (emu.vfs.readFile("/nonexistent/path") !== null) {
            throw new Error("expected null for missing vfs file");
        }

        // JNI object helpers
        const sRef = emu.jni.newString("jni-str");
        if (emu.jni.getString(sRef) !== "jni-str") {
            throw new Error("jni string roundtrip failed");
        }
        const bRef = emu.jni.newByteArray(new Uint8Array([0xaa, 0xbb, 0xcc]));
        const bOut = emu.jni.getBytes(bRef);
        if (!bOut || hex(bOut) !== "aabbcc") {
            throw new Error("jni byteArray roundtrip failed");
        }
        const objRef = emu.jni.newObject("android/content/Context", { tag: "demo", code: 7 });
        if (objRef === 0) throw new Error("newObject failed");

        console.log("js_mem_vfs_snapshot_and_helpers OK", hex(raw));
    "#;

    JsRunner::run_source_with_args(script, &["hello".to_string(), "42".to_string()])
        .expect("JS core API test failed");

    // Verify init-types writes valid d.ts
    let tmp_dir = std::env::temp_dir().join("runidbg_js_types_test");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let dts_path = write_type_definitions(&tmp_dir).unwrap();
    let content = std::fs::read_to_string(&dts_path).unwrap();
    assert!(content.contains("declare namespace Emu"));
    assert!(content.contains("interface JniNamespace"));
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn js_conscrypt_jni_call_native_and_trace() {
    if !Path::new("samples/libconscrypt_jni.so").exists() {
        return;
    }

    let script = r#"
        const emu = Emu.create({ packageName: "com.example.jsconscrypt" });
        const mod = emu.load("samples/libconscrypt_jni.so");
        if (!mod.base || !mod.size) throw new Error("invalid module info");

        const ver = emu.jniOnLoad(mod);
        if (ver !== 0x00010006) {
            throw new Error("unexpected JNI_OnLoad version: " + ver);
        }

        const natives = emu.jni.registeredNatives();
        if (natives.length < 300) {
            throw new Error("expected >= 300 registered natives, got " + natives.length);
        }

        emu.trace.start({ level: "reg_delta", capacity: 65536 });
        const randArr = emu.jni.newByteArray(new Uint8Array(16));
        emu.jni.callNative("org/conscrypt/NativeCrypto", "RAND_bytes", [randArr]);
        const stats = emu.trace.stop();

        const out = emu.jni.getBytes(randArr);
        if (!out || out.length !== 16) throw new Error("RAND_bytes output missing");
        let nonZero = 0;
        for (let i = 0; i < out.length; i++) {
            if (out[i] !== 0) nonZero++;
        }
        if (nonZero === 0) throw new Error("RAND_bytes returned all zeros");
        if (stats.records === 0) throw new Error("expected non-zero trace records");

        console.log("Conscrypt RAND_bytes:", hex(out), "trace records:", stats.records);
    "#;

    JsRunner::run_source(script).expect("JS Conscrypt test failed");
}

#[test]
fn js_cronet_jni_hooks_and_lifecycle() {
    if !Path::new("samples/libcronet.so").exists() {
        return;
    }

    let script = r#"
        const emu = Emu.create({ packageName: "com.example.jscronet" });

        let splitLoaderCalled = 0;
        let unhandledCount = 0;

        emu.jni.hook("org/chromium/base/JNIUtils", {
            getSplitClassLoader(name) {
                splitLoaderCalled++;
                // Test re-entrant JNI object allocation inside a JS JNI hook!
                return emu.jni.newObject("java/lang/ClassLoader", { split: String(name) });
            },
        });

        emu.jni.hook("internal/org/jni_zero/JniInit", {
            init() {
                const emptyMap = emu.jni.newObject("java/util/Collections$EmptyMap");
                return [emptyMap, null];
            },
        });

        emu.jni.onUnhandled((info) => {
            unhandledCount++;
            return null;
        });

        const mod = emu.load("samples/libcronet.so");
        const ver = emu.jniOnLoad(mod);
        if (ver !== 0x00010006) {
            throw new Error("unexpected Cronet JNI_OnLoad version: " + ver);
        }

        const exports = mod.exports();
        if (!exports.includes("Cronet_Engine_Create")) {
            throw new Error("missing Cronet_Engine_Create export");
        }

        const engine = mod.call("Cronet_Engine_Create");
        if (!engine) throw new Error("Cronet_Engine_Create returned 0");

        const verPtr = mod.call("Cronet_Engine_GetVersionString", engine);
        const verStr = emu.mem.readCString(verPtr);
        if (!verStr.startsWith("143.0.")) {
            throw new Error("unexpected Cronet version: " + verStr);
        }

        const params = mod.call("Cronet_EngineParams_Create");
        const langAddr = emu.mem.alloc(64);
        emu.mem.writeCString(langAddr, "zh-CN,en-US;q=0.9");
        mod.call("Cronet_EngineParams_accept_language_set", params, langAddr);
        const gotLangPtr = mod.call("Cronet_EngineParams_accept_language_get", params);
        const gotLang = emu.mem.readCString(gotLangPtr);
        if (gotLang !== "zh-CN,en-US;q=0.9") {
            throw new Error("accept_language mismatch: " + gotLang);
        }

        mod.call("Cronet_EngineParams_Destroy", params);
        mod.call("Cronet_Engine_Destroy", engine);

        console.log("Cronet JS OK:", verStr, "splitLoaderCalled:", splitLoaderCalled, "unhandled:", unhandledCount);
    "#;

    JsRunner::run_source(script).expect("JS Cronet test failed");
}

#[test]
fn js_v2_hook_attach_replace_and_regs() {
    if !Path::new("samples/libstatic-webp.so").exists() {
        return;
    }

    let script = r#"
        const emu = Emu.create({ packageName: "com.example.v2hooks" });
        const mod = emu.load("samples/libstatic-webp.so");
        const fnAddr = mod.symbol("WebPGetDecoderVersion");
        if (!fnAddr) throw new Error("WebPGetDecoderVersion not found");

        const origVer = mod.call("WebPGetDecoderVersion");
        if (origVer === 0) throw new Error("expected non-zero WebP version");

        // 1. emu.hook.attach (onEnter + onLeave + this state + retval override)
        let entered = 0;
        let left = 0;
        let seenOrig = 0;
        const h1 = emu.hook.attach(fnAddr, {
            onEnter(ctx) {
                entered++;
                this.marker = "webp-enter";
                if (ctx.pc !== fnAddr) throw new Error("unexpected pc in onEnter");
            },
            onLeave(ctx) {
                left++;
                if (this.marker !== "webp-enter") throw new Error("this state lost");
                seenOrig = ctx.retval;
                ctx.retval = 0x01020304;
            },
        });

        const hookedVer = mod.call("WebPGetDecoderVersion");
        if (entered !== 1 || left !== 1) {
            throw new Error(`attach counts wrong: entered=${entered} left=${left} hookedVer=0x${hookedVer.toString(16)}`);
        }
        if (seenOrig !== origVer) throw new Error("onLeave saw wrong retval");
        if (hookedVer !== 0x01020304) throw new Error("retval override failed: " + hookedVer);

        // Detach attach hook -> original behavior restored
        if (!h1.detach()) throw new Error("h1.detach() returned false");
        if (mod.call("WebPGetDecoderVersion") !== origVer) {
            throw new Error("after detach, version did not restore");
        }

        // 2. emu.hook.replace
        let replaceHits = 0;
        const h2 = emu.hook.replace(fnAddr, (ctx) => {
            replaceHits++;
            return 0x778899;
        });
        const repVal = mod.call("WebPGetDecoderVersion");
        if (repVal !== 0x778899 || replaceHits !== 1) {
            throw new Error(`hook.replace failed: repVal=0x${repVal.toString(16)} hits=${replaceHits}`);
        }
        h2.detach();
        if (mod.call("WebPGetDecoderVersion") !== origVer) {
            throw new Error("after replace detach, version did not restore");
        }

        // 3. Top-level emu.regs
        emu.regs.set("x1", 0x123456);
        if (emu.regs.get("x1") !== 0x123456) throw new Error("regs.get/set failed");
        const dump = emu.regs.dump();
        if (dump.x1 !== 0x123456 || typeof dump.sp !== "number") {
            throw new Error("regs.dump failed");
        }

        console.log("V2 attach/replace/regs OK, origVer=0x" + origVer.toString(16));
    "#;

    JsRunner::run_source(script).expect("JS V2 attach/replace/regs test failed");
}

#[test]
fn js_v2_code_mem_hooks_scan_and_patch() {
    if !Path::new("samples/libstatic-webp.so").exists() {
        return;
    }

    let script = r#"
        const emu = Emu.create({ packageName: "com.example.v2scan" });
        const mod = emu.load("samples/libstatic-webp.so");
        const fnAddr = mod.symbol("WebPGetDecoderVersion");

        // 1. Wildcard pattern scan on module code
        const first8 = emu.mem.readBytes(fnAddr, 8);
        const h = hex(first8);
        const pat = `${h.slice(0,2)} ${h.slice(2,4)} ?? ${h.slice(6,8)} ${h.slice(8,10)} ?? ${h.slice(12,14)} ${h.slice(14,16)}`;
        const hits = emu.mem.scan(mod.base, mod.size, pat);
        if (!hits.includes(fnAddr)) {
            throw new Error("mem.scan did not find WebPGetDecoderVersion");
        }

        // 2. Single-address code hook with once: true
        let codeHits = 0;
        const ch = emu.hook.code(fnAddr, (ctx, pc, size) => {
            codeHits++;
            if (pc !== fnAddr || size !== 4) throw new Error("unexpected code hook pc/size");
        }, { once: true });
        mod.call("WebPGetDecoderVersion");
        mod.call("WebPGetDecoderVersion");
        if (codeHits !== 1) throw new Error("code hook once failed: " + codeHits);
        ch.detach();

        // 3. Memory write watchpoint on WebPGetInfo width output pointer
        const webpData = new Uint8Array([
            82, 73, 70, 70, 44, 0, 0, 0, 87, 69, 66, 80, 86, 80, 56, 76,
            31, 0, 0, 0, 47, 1, 64, 0, 0, 31, 32, 16, 72, 218, 31, 122,
            141, 249, 23, 16, 20, 249, 63, 218, 252, 7, 95, 36, 224, 7,
            8, 17, 253, 15, 1, 0,
        ]);
        const dataAddr = emu.mem.alloc(webpData.length);
        const wAddr = emu.mem.alloc(4);
        const hAddr = emu.mem.alloc(4);
        emu.mem.writeBytes(dataAddr, webpData);

        let writeSeen = 0;
        let writtenVal = -1;
        const mh = emu.hook.mem([wAddr, wAddr + 3], { write: true }, (ctx, access, addr, size, val) => {
            if (access === "write" && addr === wAddr) {
                writeSeen++;
                writtenVal = val;
            }
        });
        const ok = mod.call("WebPGetInfo", dataAddr, webpData.length, wAddr, hAddr);
        mh.detach();
        if (ok !== 1 || writeSeen === 0 || writtenVal !== 2) {
            throw new Error(`mem watchpoint failed: ok=${ok} writeSeen=${writeSeen} val=${writtenVal}`);
        }

        // 4. Patch RX code directly: mem.ret & mem.nop
        const nopBuf = emu.mem.alloc(16);
        emu.mem.nop(nopBuf, 2);
        if (hex(emu.mem.readBytes(nopBuf, 8)) !== "1f2003d51f2003d5") {
            throw new Error("mem.nop encoding mismatch");
        }

        emu.mem.ret(fnAddr, 0xcafe);
        const patched = mod.call("WebPGetDecoderVersion");
        if (patched !== 0xcafe) {
            throw new Error("mem.ret patch failed: " + patched);
        }

        console.log("V2 scan/code/mem/patch OK, hits=" + hits.length);
    "#;

    JsRunner::run_source(script).expect("JS V2 scan/code/mem/patch test failed");
}

#[test]
fn js_v2_syscall_hook_fs_and_require() {
    if !Path::new("samples/libstatic-webp.so").exists() {
        return;
    }

    let tmp_dir = std::env::temp_dir().join("runidbg_v2_require_test");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();

    // Write a CommonJS helper module
    let helper_path = tmp_dir.join("helper.js");
    std::fs::write(
        &helper_path,
        r#"
        let loadCount = 0;
        loadCount++;
        module.exports = {
            magicByte: 0x42,
            getLoadCount: () => loadCount,
        };
        "#,
    )
    .unwrap();

    let out_file = tmp_dir.join("out.bin");
    let main_script = tmp_dir.join("main.js");
    let so_abs = std::fs::canonicalize("samples/libstatic-webp.so").unwrap();

    std::fs::write(
        &main_script,
        format!(
            r#"
            const h1 = require("./helper");
            const h2 = require("./helper.js");
            if (h1 !== h2 || h1.getLoadCount() !== 1) {{
                throw new Error("require cache failed");
            }}

            const emu = Emu.create({{ packageName: "com.example.v2sys" }});

            // Hook Linux ARM64 SYS_GETRANDOM (278) -> deterministic 0x42 bytes
            let getrandomCalls = 0;
            const sh = emu.hook.syscall(278, (ctx, nr) => {{
                getrandomCalls++;
                const len = ctx.x1;
                const filled = new Uint8Array(len);
                filled.fill(h1.magicByte);
                ctx.mem.writeBytes(ctx.x0, filled);
                return len;
            }});

            const mod = emu.load({so_path:?});
            const stubAddr = mod.symbol("WebPGetDecoderVersion");
            // Patch stub with: MOV X8, #278 (0xd28022c8); SVC #0 (0xd4000001); RET (0xd65f03c0)
            emu.mem.patch(stubAddr, new Uint8Array([
                0xc8, 0x22, 0x80, 0xd2,
                0x01, 0x00, 0x00, 0xd4,
                0xc0, 0x03, 0x5f, 0xd6,
            ]));

            const buf = emu.mem.alloc(16);
            const ret = mod.call("WebPGetDecoderVersion", buf, 16, 0);
            sh.detach();

            if (ret !== 16 || getrandomCalls !== 1) {{
                throw new Error(`SYS_GETRANDOM hook failed: ret=${{ret}} calls=${{getrandomCalls}}`);
            }}
            const out = emu.mem.readBytes(buf, 16);
            if (hex(out) !== "42".repeat(16)) {{
                throw new Error("unexpected deterministic getrandom bytes: " + hex(out));
            }}

            // Host fs read/write check
            const outPath = {out_path:?};
            fs.writeBytes(outPath, out);
            if (!fs.exists(outPath)) throw new Error("fs.exists false");
            const readBack = fs.readBytes(outPath);
            if (hex(readBack) !== hex(out)) throw new Error("fs read/write mismatch");

            console.log("V2 syscall/fs/require OK, getrandomCalls=" + getrandomCalls, "out=" + hex(out));
            "#,
            so_path = so_abs.to_string_lossy(),
            out_path = out_file.to_string_lossy(),
        ),
    )
    .unwrap();

    JsRunner::run_file(&main_script, &[]).expect("JS V2 syscall/fs/require test failed");
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn js_reentrant_hook_attach_and_detach_inside_callback() {
    let script = r#"
        const emu = Emu.create({ packageName: "com.test.reentrant", hleAccel: true });
        // 使用已映射的 r-xp cpu_init 页尾部放置两段测试用 ARM64 代码
        const codeBase = 0xdead1100;

        // outer(cb_addr, val): stp x29,x30,[sp,#-16]!; mov x2,x0; mov x0,x1; blr x2; ldp x29,x30,[sp],#16; ret
        const outer = codeBase;
        const outerInsns = [
            0xA9BF7BFD,
            0xAA0003E2,
            0xAA0103E0,
            0xD63F0040,
            0xA8C17BFD,
            0xD65F03C0,
        ];
        for (let i = 0; i < outerInsns.length; i++) {
            emu.mem.writeU32(outer + i * 4, outerInsns[i]);
        }

        // inner(val): add x0, x0, #10; ret
        const inner = codeBase + 0x40;
        emu.mem.writeU32(inner, 0x91002800);
        emu.mem.writeU32(inner + 4, 0xD65F03C0);

        let innerEnterHits = 0;
        let innerLeaveHits = 0;
        let innerHandle = null;

        const outerHandle = emu.hook.attach(outer, {
            onEnter(ctx) {
                const cbAddr = ctx.x0;
                // 关键回归测试：在 Hook 回调内再次调用 emu.hook.attach（原 bug 触发 RefCell already borrowed）
                innerHandle = emu.hook.attach(cbAddr, {
                    onEnter(c) {
                        innerEnterHits++;
                        if (c.x0 !== 32) {
                            throw new Error("expected inner arg 32, got " + c.x0);
                        }
                    },
                    onLeave(c) {
                        innerLeaveHits++;
                        // 32 + 10 = 42 -> 改写为 84，并验证回调内 detach 也不 panic
                        c.x0 = c.x0 * 2;
                        if (innerHandle) {
                            innerHandle.detach();
                            innerHandle = null;
                        }
                    },
                });
            },
        });

        const r1 = emu.call(outer, inner, 32);
        if (r1 !== 84 || innerEnterHits !== 1 || innerLeaveHits !== 1) {
            throw new Error(`reentrant attach failed: r1=${r1}, enter=${innerEnterHits}, leave=${innerLeaveHits}`);
        }

        outerHandle.detach();
        const r2 = emu.call(outer, inner, 32);
        if (r2 !== 42) {
            throw new Error(`after detach expected 42, got ${r2}`);
        }
    "#;

    JsRunner::run_source_with_args(script, &[])
        .expect("reentrant hook attach/detach inside callback failed");

    // 顺带验证 emu.load(path, { runInit: false }) + mod.runInit()
    if Path::new("samples/libstatic-webp.so").exists() {
        let init_script = r#"
            const emu = Emu.create({ packageName: "com.test.deferred_init" });
            const mod = emu.load("samples/libstatic-webp.so", { runInit: false });
            const verAddr = mod.symbol("WebPGetDecoderVersion");
            if (!verAddr) throw new Error("symbol missing before runInit");
            mod.runInit();
            if (mod.call("WebPGetDecoderVersion") === 0) {
                throw new Error("WebPGetDecoderVersion failed after deferred runInit");
            }
        "#;
        JsRunner::run_source_with_args(init_script, &[])
            .expect("deferred runInit test failed");
    }
}

#[test]
fn js_static_fields_and_char_array() {
    let script = r#"
        const emu = Emu.create({ packageName: "com.test.staticfields", hleAccel: true });

        // 1. newCharArray + getChars (UTF-16 [C)
        const arrRef = emu.jni.newCharArray("AB中");
        if (!arrRef) throw new Error("newCharArray returned 0");
        const chars = emu.jni.getChars(arrRef);
        if (!chars || chars.length !== 3 || chars[0] !== 0x41 || chars[1] !== 0x42 || chars[2] !== 0x4e2d) {
            throw new Error("getChars mismatch: " + JSON.stringify(Array.from(chars || [])));
        }

        // 2. setStaticField with [C (char[]) & int, plus dynamic hook for [C
        const secretRef = emu.jni.newCharArray("XYZ");
        emu.jni.setStaticField("com/example/Config", "SECRET", secretRef);
        emu.jni.setStaticField("com/example/Config", "VERSION", 77);
        if (emu.jni.getStaticField("com/example/Config", "VERSION") !== 77) {
            throw new Error("getStaticField VERSION mismatch");
        }

        emu.jni.hook("com/example/Dynamic", {
            DYN_CHARS() {
                return "OK";
            },
        });

        // 3. 通过真实 JNIEnv vtable 槽位调用 FindClass(6) / GetStaticFieldID(144) / GetStaticObjectField(145) / GetArrayLength(171) / GetCharArrayElements(185) / SetStaticIntField(159)
        const envPtr = emu.jni.envPtr;
        const vtable = Number(emu.mem.readU64(envPtr));
        const fnFindClass = Number(emu.mem.readU64(vtable + 6 * 8));
        const fnGetStaticFieldID = Number(emu.mem.readU64(vtable + 144 * 8));
        const fnGetStaticObjectField = Number(emu.mem.readU64(vtable + 145 * 8));
        const fnGetStaticIntField = Number(emu.mem.readU64(vtable + 150 * 8));
        const fnSetStaticIntField = Number(emu.mem.readU64(vtable + 159 * 8));
        const fnGetArrayLength = Number(emu.mem.readU64(vtable + 171 * 8));
        const fnGetCharArrayElements = Number(emu.mem.readU64(vtable + 185 * 8));

        const sBuf = emu.mem.alloc(256);
        const writeStr = (off, s) => { emu.mem.writeCString(sBuf + off, s); return sBuf + off; };
        const pClsCfg = writeStr(0, "com/example/Config");
        const pFieldSec = writeStr(32, "SECRET");
        const pSigCharArr = writeStr(48, "[C");
        const pFieldVer = writeStr(64, "VERSION");
        const pSigInt = writeStr(80, "I");
        const pClsDyn = writeStr(96, "com/example/Dynamic");
        const pFieldDyn = writeStr(128, "DYN_CHARS");

        const clsCfg = emu.call(fnFindClass, envPtr, pClsCfg);
        const fidSec = emu.call(fnGetStaticFieldID, envPtr, clsCfg, pFieldSec, pSigCharArr);
        const gotSecRef = emu.call(fnGetStaticObjectField, envPtr, clsCfg, fidSec);
        if (gotSecRef !== secretRef) {
            throw new Error(`GetStaticObjectField SECRET mismatch: got=${gotSecRef} expected=${secretRef}`);
        }
        const secLen = emu.call(fnGetArrayLength, envPtr, gotSecRef);
        if (secLen !== 3) throw new Error("expected [C length 3, got " + secLen);
        const elemPtr = emu.call(fnGetCharArrayElements, envPtr, gotSecRef, 0);
        const rawChars = emu.mem.readBytes(elemPtr, 6);
        if (hex(rawChars) !== "580059005a00") {
            throw new Error(`GetCharArrayElements mismatch: ${hex(rawChars)}`);
        }

        // GetStaticIntField + SetStaticIntField roundtrip
        const fidVer = emu.call(fnGetStaticFieldID, envPtr, clsCfg, pFieldVer, pSigInt);
        if (emu.call(fnGetStaticIntField, envPtr, clsCfg, fidVer) !== 77) {
            throw new Error("GetStaticIntField VERSION expected 77");
        }
        emu.call(fnSetStaticIntField, envPtr, clsCfg, fidVer, 99);
        if (emu.call(fnGetStaticIntField, envPtr, clsCfg, fidVer) !== 99) {
            throw new Error("SetStaticIntField roundtrip expected 99");
        }
        if (emu.jni.getStaticField("com/example/Config", "VERSION") !== 99) {
            throw new Error("JS getStaticField expected 99 after SetStaticIntField");
        }

        // Dynamic JS hook returning string for [C static field -> auto-converted to jcharArray
        const clsDyn = emu.call(fnFindClass, envPtr, pClsDyn);
        const fidDyn = emu.call(fnGetStaticFieldID, envPtr, clsDyn, pFieldDyn, pSigCharArr);
        const gotDynRef = emu.call(fnGetStaticObjectField, envPtr, clsDyn, fidDyn);
        const dynChars = emu.jni.getChars(gotDynRef);
        if (!dynChars || dynChars.length !== 2 || dynChars[0] !== 0x4f || dynChars[1] !== 0x4b) {
            throw new Error("dynamic [C hook failed: " + JSON.stringify(Array.from(dynChars || [])));
        }

        // 4. 对称测试：[I (int[]) / [J (long[]) + 实例字段 setField/getField & GetIntField/SetIntField
        const intArrRef = emu.jni.newIntArray([10, -20, 30]);
        const gotInts = emu.jni.getInts(intArrRef);
        if (!gotInts || gotInts.length !== 3 || gotInts[0] !== 10 || gotInts[1] !== -20 || gotInts[2] !== 30) {
            throw new Error("int[] roundtrip failed");
        }
        const longArrRef = emu.jni.newLongArray([1000n, 9007199254740993n]);
        const gotLongs = emu.jni.getLongs(longArrRef);
        if (!gotLongs || gotLongs.length !== 2 || gotLongs[0] !== 1000n || gotLongs[1] !== 9007199254740993n) {
            throw new Error("long[] roundtrip failed");
        }

        const fnGetFieldID = Number(emu.mem.readU64(vtable + 94 * 8));
        const fnGetIntField = Number(emu.mem.readU64(vtable + 100 * 8));
        const fnSetIntField = Number(emu.mem.readU64(vtable + 109 * 8));
        const obj = emu.jni.newObject("com/example/Config");
        emu.jni.setField(obj, "VERSION", 123);
        const fidInstVer = emu.call(fnGetFieldID, envPtr, clsCfg, pFieldVer, pSigInt);
        if (emu.call(fnGetIntField, envPtr, obj, fidInstVer) !== 123) {
            throw new Error("GetIntField expected 123");
        }
        emu.call(fnSetIntField, envPtr, obj, fidInstVer, 456);
        if (emu.jni.getField(obj, "VERSION") !== 456) {
            throw new Error("SetIntField / getField roundtrip expected 456");
        }
    "#;

    JsRunner::run_source_with_args(script, &[])
        .expect("static fields and [C char[] test failed");
}

#[test]
fn js_v015_feedback_fixes() {
    let script = r#"
        const emu = Emu.create({ packageName: "com.test.v015", hleAccel: true });
        emu.diag.enable();

        // 1. getStaticField / getField 未设置时返回 null（非 undefined）
        if (emu.jni.getStaticField("com/foo/Bar", "NOPE") !== null) {
            throw new Error("expected null for unset static field");
        }
        const instObj = emu.jni.newObject("com/foo/Bar");
        if (emu.jni.getField(instObj, "NOPE") !== null) {
            throw new Error("expected null for unset instance field");
        }

        // 2. hook.attach 到未映射地址必须抛明确错误，不再静默失效
        let attachThrew = false;
        try {
            emu.hook.attach(0x12340000, { onEnter() {} });
        } catch (e) {
            attachThrew = String(e).includes("未映射") || String(e).includes("0x12340000");
        }
        if (!attachThrew) {
            throw new Error("expected hook.attach on unmapped address to throw");
        }

        // 3. emu.hook.importReplace("lrand48", ...) 按符号名直接替换导入函数
        let lrandHits = 0;
        const hImp = emu.hook.importReplace("lrand48", () => {
            lrandHits++;
            return 0x1337;
        });
        // 通过未实现符号 + getauxval(999) + GetStaticObjectField 触发 EnvDiag 三个新维度
        const unimplAddr = __native.hookImportResolve(0, "fake_missing_sym");
        emu.call(unimplAddr);
        emu.call(unimplAddr); // 二次命中应只打印一次 WARN，但 diag 计数为 2
        const auxvAddr = __native.hookImportResolve(0, "getauxval");
        emu.call(auxvAddr, 999);
        const lrandAddr = __native.hookImportResolve(0, "lrand48");
        const r = emu.call(lrandAddr);
        if (r !== 0x1337 || lrandHits !== 1) {
            throw new Error(`hook.importReplace failed: r=${r}, hits=${lrandHits}`);
        }
        hImp.detach();

        // 触发 GetStaticObjectField 返回 NULL -> 记录 missingJniFields
        const envPtr = emu.jni.envPtr;
        const vtable = Number(emu.mem.readU64(envPtr));
        const fnFindClass = Number(emu.mem.readU64(vtable + 6 * 8));
        const fnGetStaticFieldID = Number(emu.mem.readU64(vtable + 144 * 8));
        const fnGetStaticObjectField = Number(emu.mem.readU64(vtable + 145 * 8));
        const fnRegisterNatives = Number(emu.mem.readU64(vtable + 215 * 8));
        const sBuf = emu.mem.alloc(256);
        const ws = (off, s) => { emu.mem.writeCString(sBuf + off, s); return sBuf + off; };
        const cls = emu.call(fnFindClass, envPtr, ws(0, "com/foo/Bar"));
        const fid = emu.call(fnGetStaticFieldID, envPtr, cls, ws(32, "missingField"), ws(64, "[C"));
        emu.call(fnGetStaticObjectField, envPtr, cls, fid);

        const rep = emu.diag.report();
        if (rep.missingHle["fake_missing_sym"] !== 2) {
            throw new Error("missingHle mismatch: " + JSON.stringify(rep.missingHle));
        }
        if (rep.missingAuxv["999"] !== 1) {
            throw new Error("missingAuxv mismatch: " + JSON.stringify(rep.missingAuxv));
        }
        if (!rep.missingJniFields["com/foo/Bar.missingField([C)"]) {
            throw new Error("missingJniFields mismatch: " + JSON.stringify(rep.missingJniFields));
        }

        // 4. callNative(..., { this: instObj }) 与 callNativeOn(instObj, ...) 传递真实 this
        // 在 r-xp cpu_init 页尾部写一个简单 native 函数：mov x0, x1; ret（直接返回收到的 X1/this）
        const fnEchoThis = 0xdead1200;
        emu.mem.writeU32(fnEchoThis, 0xAA0103E0); // mov x0, x1
        emu.mem.writeU32(fnEchoThis + 4, 0xD65F03C0); // ret
        const regStruct = emu.mem.alloc(24);
        emu.mem.writeU64(regStruct, BigInt(ws(96, "echoThis")));
        emu.mem.writeU64(regStruct + 8, BigInt(ws(120, "()J")));
        emu.mem.writeU64(regStruct + 16, BigInt(fnEchoThis));
        emu.call(fnRegisterNatives, envPtr, cls, regStruct, 1);

        const got1 = emu.jni.callNative("com/foo/Bar", "echoThis", [], { this: instObj });
        const got2 = emu.jni.callNativeOn(instObj, "com/foo/Bar", "echoThis", []);
        const gotStatic = emu.jni.callNative("com/foo/Bar", "echoThis", []);
        if (got1 !== instObj || got2 !== instObj) {
            throw new Error(`callNative with this failed: got1=${got1}, got2=${got2}, expected=${instObj}`);
        }
        if (gotStatic !== cls) {
            throw new Error(`callNative static expected cls=${cls}, got=${gotStatic}`);
        }
    "#;

    JsRunner::run_source_with_args(script, &[]).expect("v0.1.5 feedback fixes test failed");
}

#[test]
fn js_jni_describe_field_method_and_object() {
    let script = r#"
        const emu = Emu.create({ packageName: "com.test.introspect", hleAccel: true });
        const envPtr = emu.jni.envPtr;
        const vtable = Number(emu.mem.readU64(envPtr));
        const fnFindClass = Number(emu.mem.readU64(vtable + 6 * 8));
        const fnGetMethodID = Number(emu.mem.readU64(vtable + 33 * 8));
        const fnGetFieldID = Number(emu.mem.readU64(vtable + 94 * 8));
        const fnGetObjectField = Number(emu.mem.readU64(vtable + 95 * 8));
        const fnGetStaticFieldID = Number(emu.mem.readU64(vtable + 144 * 8));

        const buf = emu.mem.alloc(256);
        const ws = (off, s) => { emu.mem.writeCString(buf + off, s); return buf + off; };

        const clsG0 = emu.call(fnFindClass, envPtr, ws(0, "cas/g0"));
        const clsJ0 = emu.call(fnFindClass, envPtr, ws(16, "cas/j0"));

        // 同名不同类字段：cas/g0.j[I 与 cas/j0.jLjava/lang/String;
        const fidG0J = emu.call(fnGetFieldID, envPtr, clsG0, ws(32, "j"), ws(40, "[I"));
        const fidJ0J = emu.call(fnGetFieldID, envPtr, clsJ0, ws(32, "j"), ws(48, "Ljava/lang/String;"));
        const fidStaticA = emu.call(fnGetStaticFieldID, envPtr, clsG0, ws(80, "a"), ws(88, "[C"));
        const midH = emu.call(fnGetMethodID, envPtr, clsG0, ws(96, "h"), ws(104, "()Ljava/lang/String;"));

        // 1. describeField 精确区分所属类
        const f1 = emu.jni.describeField(fidG0J);
        const f2 = emu.jni.describeField(fidJ0J);
        const f3 = emu.jni.describeField(fidStaticA);
        if (!f1 || f1.className !== "cas/g0" || f1.name !== "j" || f1.sig !== "[I" || f1.isStatic !== false) {
            throw new Error("describeField fidG0J mismatch: " + JSON.stringify(f1));
        }
        if (!f2 || f2.className !== "cas/j0" || f2.name !== "j" || f2.sig !== "Ljava/lang/String;" || f2.isStatic !== false) {
            throw new Error("describeField fidJ0J mismatch: " + JSON.stringify(f2));
        }
        if (!f3 || f3.className !== "cas/g0" || f3.name !== "a" || f3.isStatic !== true) {
            throw new Error("describeField fidStaticA mismatch: " + JSON.stringify(f3));
        }
        if (emu.jni.describeField(0x999999) !== null) {
            throw new Error("unknown fieldId should return null");
        }
        if (emu.jni.listFields().length < 3) {
            throw new Error("listFields expected >= 3");
        }

        // 2. describeMethod & listMethods
        const m1 = emu.jni.describeMethod(midH);
        if (!m1 || m1.className !== "cas/g0" || m1.name !== "h" || m1.sig !== "()Ljava/lang/String;" || m1.isStatic !== false) {
            throw new Error("describeMethod mismatch: " + JSON.stringify(m1));
        }
        if (emu.jni.describeMethod(0x999999) !== null) {
            throw new Error("unknown methodId should return null");
        }
        if (emu.jni.listMethods().length < 1) {
            throw new Error("listMethods expected >= 1");
        }

        // 3. describeObject 支持 jclass / custom / string / array
        const objJ0 = emu.jni.newObject("cas/j0");
        const strRef = emu.jni.newString("hello");
        emu.jni.setField(objJ0, "j", strRef);
        const dCls = emu.jni.describeObject(clsG0);
        const dObj = emu.jni.describeObject(objJ0);
        const dStr = emu.jni.describeObject(strRef);
        if (!dCls || dCls.className !== "cas/g0" || dCls.kind !== "class") {
            throw new Error("describeObject class mismatch: " + JSON.stringify(dCls));
        }
        if (!dObj || dObj.className !== "cas/j0" || dObj.kind !== "custom") {
            throw new Error("describeObject custom mismatch: " + JSON.stringify(dObj));
        }
        if (!dStr || dStr.kind !== "string") {
            throw new Error("describeObject string mismatch: " + JSON.stringify(dStr));
        }
        if (emu.jni.describeObject(0) !== null) {
            throw new Error("describeObject(0) should return null");
        }

        // 4. 在 GetObjectField (slot 95) Hook 回调内重入调用 describeField + describeObject
        let seenField = null;
        let seenObj = null;
        const h = emu.hook.attach(fnGetObjectField, {
            onEnter(ctx) {
                seenObj = emu.jni.describeObject(ctx.x1);
                seenField = emu.jni.describeField(ctx.x2);
            },
        });
        const gotRef = emu.call(fnGetObjectField, envPtr, objJ0, fidJ0J);
        h.detach();
        if (gotRef !== strRef) throw new Error("GetObjectField returned wrong ref");
        if (!seenField || seenField.className !== "cas/j0" || seenField.name !== "j") {
            throw new Error("reentrant describeField failed: " + JSON.stringify(seenField));
        }
        if (!seenObj || seenObj.className !== "cas/j0") {
            throw new Error("reentrant describeObject failed: " + JSON.stringify(seenObj));
        }
    "#;

    JsRunner::run_source_with_args(script, &[])
        .expect("JNI describeField/Method/Object test failed");
}

