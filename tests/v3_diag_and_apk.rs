#![cfg(all(feature = "js", feature = "apk"))]

use std::io::Write;
use std::path::PathBuf;

use runidbg_arm64_emu_tracer::script::JsRunner;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn test_phase2_env_diag_and_apk_loader() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let webp_bytes = std::fs::read(root.join("samples/libstatic-webp.so")).expect("read webp so");

    let tmp_dir = std::env::temp_dir().join(format!("runidbg_p2_apk_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let apk_path = tmp_dir.join("demo.apk");

    // 构造一个包含 Manifest、arm64-v8a .so、assets 与签名证书的真实 APK (ZIP)
    {
        let file = std::fs::File::create(&apk_path).expect("create apk");
        let mut zw = ZipWriter::new(file);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zw.start_file("AndroidManifest.xml", opts).unwrap();
        zw.write_all(br#"<manifest package="com.runidbg.demoapk" android:versionName="1.0"/>"#)
            .unwrap();

        zw.start_file("lib/arm64-v8a/libstatic-webp.so", opts)
            .unwrap();
        zw.write_all(&webp_bytes).unwrap();

        zw.start_file("assets/config.json", opts).unwrap();
        zw.write_all(br#"{"env":"prod","ver":42}"#).unwrap();

        zw.start_file("META-INF/CERT.RSA", opts).unwrap();
        zw.write_all(&[0x30, 0x82, 0x01, 0x23, 0xde, 0xad, 0xbe, 0xef])
            .unwrap();

        zw.finish().unwrap();
    }

    let apk_str = apk_path.to_string_lossy().into_owned();
    let script = format!(
        r#"
const emu = Emu.create();
emu.diag.enable();

// 1. APK 一键加载
const apk = emu.loadApk({apk_str:?});
if (apk.packageName !== "com.runidbg.demoapk") {{
    throw new Error("unexpected packageName: " + apk.packageName);
}}
if (!apk.libs.includes("libstatic-webp.so")) {{
    throw new Error("missing libstatic-webp.so in apk.libs");
}}
if (!apk.assets.includes("config.json")) {{
    throw new Error("missing config.json in apk.assets");
}}
if (apk.signatureSize !== 8) {{
    throw new Error("unexpected signatureSize: " + apk.signatureSize);
}}

// 2. 验证 assets 已自动挂载到 VFS
const cfgBytes = emu.vfs.readFile("/assets/config.json");
if (!cfgBytes || cfgBytes.length === 0) {{
    throw new Error("assets/config.json not mounted in VFS");
}}

// 3. 直接从 APK 内存加载 libstatic-webp.so 并调用导出函数
const mod = apk.loadLib("libstatic-webp.so");
const ver = mod.call("WebPGetDecoderVersion");
if (!(ver > 0)) {{
    throw new Error("invalid WebPGetDecoderVersion: " + ver);
}}

// 4. 触发一次缺失系统属性与缺失文件查询（通过 SVC / VFS），验证 EnvDiag 捕获并生成补环境模板
const fnAddr = mod.symbol("WebPGetDecoderVersion");
// Patch: mov x8, #9999 (unimplemented syscall); svc #0; ret
// 0xd284e1e8 = mov x8, #0x270f (9999)
// 0xd4000001 = svc #0
// 0xd65f03c0 = ret
emu.mem.patch(fnAddr, new Uint8Array([
    0xe8, 0xe1, 0x84, 0xd2,
    0x01, 0x00, 0x00, 0xd4,
    0xc0, 0x03, 0x5f, 0xd6,
]));
emu.call(fnAddr);

const rep = emu.diag.report();
if (!rep.missingSyscalls["9999"]) {{
    throw new Error("missing syscall 9999 not recorded: " + JSON.stringify(rep));
}}
const patchJs = emu.diag.generatePatchJs();
if (!patchJs.includes("emu.hook.syscall(9999")) {{
    throw new Error("patchJs missing syscall 9999 template:\n" + patchJs);
}}
"#
    );

    JsRunner::run_source(&script).expect("Phase 2 JS test failed");
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
