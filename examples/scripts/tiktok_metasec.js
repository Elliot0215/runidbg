/// <reference path="./runidbg.d.ts" />
// TikTok MSSDK (libmetasec_ov.so) 纯离线签名示例（脱敏测试参数，不含任何真实会话凭据）
// 运行:
//   cargo run --release --bin runidbg-cli -- run examples/scripts/tiktok_metasec.js
// 启动多核 RPC 服务:
//   cargo run --release --bin runidbg-cli -- serve examples/scripts/tiktok_metasec.js --workers auto --listen 127.0.0.1:8080

const SAMPLE_DIR = "samples/metasec";

const emu = Emu.create({
  packageName: "com.zhiliaoapp.musically",
  searchPaths: [SAMPLE_DIR],
  device: "pixel8pro",
  realClock: true,
});

emu.diag.enable();
emu.setLimits({ timeoutMs: 30000, maxInstructions: 0 });

// MSSDK 公开内置配置所需的 License 与基础回调（测试占位参数）
const LICENSE =
  "Zs81WLZ0TYDnPHhokfrih9f2UVKMYsD6ygiN+al3YbsQTM5dSPr+VANPNr2yt/6QZ3JuYhSmDYBLiuwMS3cvrr+1/8cAwLDSGF69eSzBCn1V3+2mBLMP7NPqp1q3bRDYgEewnEm4DNlPCPW5U2nedHmDVvrEKzBMl8RWBPCnBmvNXNMcPonBLsZYQk+XnBO5ZUm5rFr56W5sezAigX8gmCIS9kaPMASRFaEb65F/f8pFvVlEWoxkWkVeUf8Z9pPT0ZaRrezEtk4JvuNwLu0lL1UHdxpc+feECCxfrESn8hKSFDyzg1zQ0YNT+ILxVw34ElmJ30SP74RN/dhjNJ5pDBtlu+RNtU1ebPwnGxtu79WacDkiCJjsmdrzGrGwbQ4nBl8bugOKsWV4FF/60FPwpZ8iZ+M=";

emu.jni.hook("com/bytedance/mobsec/metasec/ov/MS", {
  b(op) {
    if (op === 65539) {
      return "/data/user/0/com.zhiliaoapp.musically/files/.msdata";
    }
    if (op === 16777233) {
      return "47.6.3";
    }
    return null;
  },
});

const mod = emu.load(`${SAMPLE_DIR}/libmetasec_ov.so`);
const jniVer = emu.jniOnLoad(mod);

const a0Cls = emu.jni.findClass("ms/bd/o/a0");
const strCls = emu.jni.findClass("java/lang/String");
// 注入门控全局 jclass（java/lang/String）
emu.mem.writeU64(mod.base + 0x209198, strCls);

function callNativeA(op, i2, j, strVal, objRef) {
  const sRef = strVal !== null && strVal !== undefined ? emu.jni.newString(String(strVal)) : 0;
  return emu.call(mod.base + 0x120be0, emu.jni.envPtr, a0Cls, op, i2, j, sRef, objRef || 0);
}

// 初始化 MSSDK 实例配置（opcode 0x4000001，使用占位设备/安装 ID）
const cfg = [
  "1233",
  "",
  "",
  LICENSE,
  "v04.04.06-ov-android",
  "googleplay",
  "7000000000000000001",
  "",
  "7000000000000000002",
  "",
  "0",
  "0",
  "5",
  [],
  [],
];
callNativeA(67108865, 0, 0, JSON.stringify(cfg), 0);

function pairsToMap(arr) {
  const out = {};
  if (!arr) return out;
  for (let i = 0; i + 1 < arr.length; i += 2) {
    out[arr[i]] = arr[i + 1] || "";
  }
  return out;
}

function sign(url, opcode = 50331649, headers = ["cookie", "sessionid=demo", "user-agent", "ua"]) {
  return emu.jni.withLocalFrame(() => {
    const headersArr = emu.jni.newStringArray(headers);
    const ret = callNativeA(opcode, 0, 0, url, headersArr);
    return pairsToMap(emu.jni.getStringArray(ret));
  });
}

rpc.exports = {
  sign_cylons(url) {
    return sign(url || "https://x/y", 100663297);
  },
  sign_gorgon(url) {
    return sign(
      url ||
        "https://api16-normal-no1a.tiktokv.eu/aweme/v2/comment/list/?aweme_id=1&aid=1233&device_id=7000000000000000001",
      50331649
    );
  },
};

// 直接通过 `runidbg-cli run` 执行时输出自检结果
const demoUrl =
  args[0] ||
  "https://api16-normal-no1a.tiktokv.eu/aweme/v2/comment/list/?aweme_id=1&cursor=0&count=8&aid=1233&device_id=7000000000000000001&iid=7000000000000000002&version_name=47.6.3&channel=googleplay";

const cylons = rpc.exports.sign_cylons("https://x/y");
const gorgon = rpc.exports.sign_gorgon(demoUrl);

console.log(`[metasec] JNI_OnLoad=0x${jniVer.toString(16)}`);
console.log(`[metasec] X-Cylons: len=${(cylons["X-Cylons"] || "").length}`);
for (const k of ["X-Argus", "X-Gorgon", "X-Khronos", "X-Ladon"]) {
  const v = gorgon[k] || "";
  console.log(`[metasec] ${k} (len=${v.length}): ${v.length > 48 ? v.slice(0, 48) + "..." : v}`);
}
