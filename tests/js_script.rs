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

