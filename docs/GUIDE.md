# runidbg 组件与工具完整使用指南

本文档涵盖 `runidbg` 全部 CLI 子命令、QuickJS 脚本 API、设备画像（`DeviceProfile`）、二进制 Trace 工具链、异步多核 RPC 服务、MCP AI 接入、GDB 远程调试以及 Rust 库接口。

---

## 1. 命令行工具 `runidbg-cli`

全局日志选项需置于子命令之前：
```bash
runidbg-cli [--log-level <trace|debug|info|warn|error>] [--log-format <compact|json>] <subcommand> ...
```

| 子命令 | 用途 | 常用示例 |
| --- | --- | --- |
| `run` | 运行 QuickJS 仿真脚本 | `runidbg-cli run examples/scripts/tiktok_metasec.js -- "https://..."` |
| `serve` | 启动异步 HTTP / JSON-RPC 2.0 服务 | `runidbg-cli serve script.js --listen 0.0.0.0:8080 --workers auto --max-queue 2048 --timeout-ms 15000 --max-insns 5000000 --allow-reload` |
| `mcp` | 启动 MCP 服务端（stdio / Streamable HTTP） | `runidbg-cli mcp --cwd .` 或 `runidbg-cli mcp --http 127.0.0.1:8090 --cwd .` |
| `debug` | 启动 ARM64 GDB RSP 远程调试服务端 | `runidbg-cli debug samples/libstatic-webp.so WebPGetDecoderVersion --listen 127.0.0.1:1234` |
| `init-types` | 导出 TypeScript 类型声明 `runidbg.d.ts` | `runidbg-cli init-types examples/scripts` |
| `dump` | 离线反汇编 Trace（自动探测同级 `.ext`） | `runidbg-cli dump trace.idx --base 0x40000000 --skip 0 --limit 50` |
| `search` | 离线检索寄存器值 / 访存地址 / PC | `runidbg-cli search trace.idx --base 0x40000000 --val 0x03000001` |
| `stats` | 离线热点统计（唯一 PC、Top-N 热点指令与 `BL` 目标） | `runidbg-cli stats trace.idx --base 0x40000000 --top 20` |
| `export-ida` | 导出 IDA Pro 执行覆盖率高亮脚本 | `runidbg-cli export-ida trace.idx --base 0x40000000 --out ida_cov.py` |
| `export-bn` | 导出 Binary Ninja 执行覆盖率高亮脚本 | `runidbg-cli export-bn trace.idx --base 0x40000000 --out bn_cov.py` |

---

## 2. QuickJS 脚本引擎 API

完整 TypeScript 声明见 [src/script/runidbg.d.ts](../src/script/runidbg.d.ts)。

### 2.1 创建模拟器与设备画像（`DeviceProfile`）
```javascript
const emu = Emu.create({
  packageName: "com.example.app",
  searchPaths: ["./libs"],          // DT_NEEDED 依赖搜索路径
  hleAccel: true,                   // 默认 true，开启高频 libc/libm HLE 加速
  heapSize: 32 * 1024 * 1024,       // 默认 32 MB
  realClock: true,                  // true=宿主机实时时间；false=确定性虚拟时钟（默认）
  device: {                         // 可直接传预设名 "pixel5" | "pixel8pro" | "s24ultra" | "xiaomi14"
    preset: "pixel8pro",
    model: "23049RAD8C",
    brand: "Redmi",
    sdkInt: 35,
    androidRelease: "15",
  },
});
```
应用 `device` 后自动同步：
- 30+ 项 Android 系统属性（`ro.product.*`、`ro.build.*`、`ro.hardware`、`ro.board.platform`、`ro.serialno`、`persist.sys.*`、`gsm.*`）
- 动态虚拟文件：`/proc/cpuinfo`、`/proc/meminfo`、`/proc/version`、`/sys/devices/system/cpu/online|possible`
- `uname` 系统调用（`kernel_release`、`kernel_version`）
- JNI 静态字段：`android/os/Build.*` 与 `android/os/Build$VERSION.*`（含 `SDK_INT`）

运行时可随时通过 `emu.vfs.setDevice(...)`、`emu.vfs.deviceProfile()`、`emu.vfs.setTime(unixSecs)`、`emu.vfs.useRealClock(bool)` 动态切换。

### 2.2 加载 `.so` / APK 与执行控制
```javascript
// 加载独立 .so（自动递归加载 DT_NEEDED、执行重定位与 .init_array）
const mod = emu.load("./libs/libtarget.so");
const ver = emu.jniOnLoad(mod);

// 或一键内存加载 APK（自动解析包名、ABI、assets 与签名）
const apk = emu.loadApk("./app.apk");
const lib = apk.loadLib("libtarget.so");

// 设置单次调用硬超时与指令预算（0 表示不限）
emu.setLimits({ timeoutMs: 15000, maxInstructions: 5_000_000 });

// 快照与毫秒级回放
const snapId = emu.snapshot();
const r1 = mod.call("sign", ptr1, len1);
emu.restore(snapId);
const r2 = mod.call("sign", ptr2, len2);
```

### 2.3 JNI 桥接与 Hook
```javascript
// Hook 任意 Java 类方法（实例方法 / 静态方法均适用）
emu.jni.hook("com/example/Env", {
  getToken(arg0) {
    return "mock-token";
  },
});

// 监听未处理的 JNI 调用
emu.jni.onUnhandled((info) => {
  console.log(info.kind, info.className, info.name, info.sig, info.args);
  return 0;
});

// 常用 JNI 对象构造与读取（均可在 Native Hook 回调中安全调用）
const cls = emu.jni.findClass("com/example/Api");
const sRef = emu.jni.newString("payload");
const bRef = emu.jni.newByteArray(new Uint8Array([1, 2, 3]));
const arrRef = emu.jni.newStringArray(["k", "v"]);
const outArr = emu.jni.getStringArray(retRef);
const outStr = emu.jni.getString(strRef);
const outBytes = emu.jni.getBytes(byteArrRef);

// 调用 RegisterNatives 注册的原生方法，或直接按偏移调用
const natives = emu.jni.registeredNatives();
emu.jni.callNative("com/example/Api", "nativeSign", [sRef]);
emu.call(mod.base + 0x120be0, emu.jni.envPtr, cls, sRef, arrRef);
```

### 2.4 Frida 风格 Native Hook 与内存操作
```javascript
// 1. 函数入口/返回 Hook（this 可在 onEnter 与 onLeave 间共享状态）
const h1 = emu.hook.attach(mod.base + 0x12340, {
  onEnter(ctx) {
    this.buf = ctx.x0;
    console.log("x0=", ctx.x0, "argStr=", ctx.mem.readCString(ctx.x1, 128));
  },
  onLeave(ctx) {
    console.log("retval=", ctx.retval);
  },
});

// 2. 函数替换（直接返回自定义值，跳过原函数执行）
const h2 = emu.hook.replace(mod.base + 0x56780, (ctx) => 0);

// 3. 指令级 / 内存 R/W / Syscall Hook
emu.hook.code([mod.base, mod.base + 0x1000], (ctx, pc, size) => {}, { once: true });
emu.hook.mem([buf, buf + 64], { write: true }, (ctx, access, addr, size, val) => {});
emu.hook.syscall("*", (ctx, nr) => undefined); // 返回 undefined 放行给默认内核处理

h1.detach();
h2.detach();

// 内存读写、特征扫描与热修补（自动刷新 Unicorn TB 缓存）
const p = emu.mem.alloc(256);
emu.mem.writeCString(p, "hello");
const hits = emu.mem.scan(mod.base, mod.size, "FD 7B ?? A9");
emu.mem.nop(mod.base + 0x9000, 2);
emu.mem.ret(mod.base + 0x9100, 1);
```

### 2.5 缺环境诊断（`EnvDiag`）与崩溃报告（`CrashReport`）
```javascript
emu.diag.enable();
// ... 运行目标函数 ...
console.log(JSON.stringify(emu.diag.report(), null, 2));
console.log(emu.diag.generatePatchJs()); // 自动生成缺失环境补丁模板

const crash = emu.lastCrash();
if (crash) {
  console.error(crash.formatted); // 反汇编 + 寄存器 + FP 调用栈 + 面包屑 + VMA
}
```

---

## 3. 高性能二进制 Trace 引擎

| 级别 | 记录内容 | 实测吞吐 | 适用场景 |
| --- | --- | ---: | --- |
| `fast` | PC + 32-bit opcode（32B/条） | ~17 M insns/s | 覆盖率统计、IDA/BN 高亮、路径对比 |
| `reg_delta` | 指令 + 变更寄存器增量（32B/条） | ~5 M insns/s | 算法逆向、值溯源（`search --val`） |
| `full` | `reg_delta` + `.ext` 内存读写双流 | ~4.7 M insns/s | 缓冲区追踪、密码学 S-Box / 密钥定位 |

- 落盘采用零拷贝 `mmap`，在 `emu.trace.stop()` / `detach_tracer()` 时自动截断为精确写入字节数（无尾部零填充）。
- `runidbg-cli dump` 与 `search` 会自动探测同级 `.ext` 文件，并支持 `--base <hex>` 输出 `[+0xoffset]` 相对偏移。

---

## 4. 异步多核 RPC 服务（`runidbg-cli serve`）

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/health` | `GET` | 健康状态、Worker 数、队列占用、热重载版本、导出方法列表 |
| `/metrics` | `GET` | 运行指标（加 `?format=prom` 输出 Prometheus 文本格式） |
| `/exports` | `GET` | 列出 `rpc.exports` 全部导出方法 |
| `/call/<method>` | `POST` | 直接调用方法，Body 为 JSON 参数数组 `[arg0, arg1, ...]` |
| `/rpc` | `POST` | 标准 JSON-RPC 2.0（支持单条与 Batch 数组多核并行） |
| `/admin/reload` | `POST` | 先校验新脚本再原子滚动重建 Worker 池（需 `--allow-reload`） |
| `/eval` | `POST` | 动态执行 JS 表达式（需 `--allow-eval`） |

背压与熔断：
- 队列满返回 `HTTP 503`
- 超出 `--timeout-ms` 或 `--max-insns` 触发 Unicorn 硬中断并返回 `HTTP 504`

---

## 5. MCP 服务端（15 个 AI 逆向工具）

支持 **stdio**（`runidbg-cli mcp --cwd .`）与 **Streamable HTTP**（`runidbg-cli mcp --http 127.0.0.1:8090 --cwd .`）：

| 类别 | 工具名 | 说明 |
| --- | --- | --- |
| 生命周期与执行 | `emu_create` / `emu_load` / `emu_jni_onload` / `emu_exports` / `emu_call` / `emu_eval_js` | 创建实例、加载 `.so`、查导出、调函数与执行 JS |
| 状态与反汇编 | `emu_regs` / `emu_mem_read` / `emu_mem_scan` / `emu_disasm` | 读寄存器、读/扫内存、`bad64` 反汇编 |
| 追踪与 Hook | `emu_trace_call` / `trace_inspect` / `emu_hook_capture` | 函数级 Trace、检索 Trace、一次性 Hook 抓取入参/返回值 |
| 诊断 | `emu_diag_missing` / `emu_last_crash` | 获取 `EnvDiag` 缺失环境报告与最新崩溃现场 |

---

## 6. GDB RSP 远程调试

```bash
runidbg-cli debug samples/libstatic-webp.so WebPGetDecoderVersion --listen 127.0.0.1:1234
```
支持标准 ARM64 GDB Remote Serial Protocol（寄存器读写、内存读写、软件断点 `Z0`/`z0`、单步 `s`、继续 `c`），可直接用 `gdb-multiarch` / `pwndbg` / IDA Pro / Binary Ninja 连接：`target remote 127.0.0.1:1234`。

---

## 7. Rust 库嵌入用法

```rust
use runidbg_arm64_emu_tracer::os::DeviceProfile;
use runidbg_arm64_emu_tracer::tracer::TraceLevel;
use runidbg_arm64_emu_tracer::AndroidEmulator;

let mut emu = AndroidEmulator::builder()
    .package_name("com.example.app")
    .device_profile(DeviceProfile::pixel_8_pro())
    .add_search_path("./libs")
    .with_memory_trace(200_000, TraceLevel::RegDelta)
    .build()?;

let module = emu.load_library("./libs/libtarget.so")?;
emu.call_jni_onload(&module)?;
let ret = emu.call_symbol(&module, "target_func", &[0, 0])?;
```
