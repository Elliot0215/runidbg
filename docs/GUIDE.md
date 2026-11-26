# runidbg 组件与工具完整使用指南

本文档涵盖 `runidbg` 全部 CLI 子命令、多执行后端、QuickJS 脚本 API、设备画像（`DeviceProfile`）、零拷贝 Trace / HLE 统一流 / 离线污点切片 / 全知查询 / 双跑 Diff / VM 专项分析、`.rtape` 时间旅行调试、异步多核 RPC 服务、MCP 36 工具、GDB RSP 远程调试以及 Rust 库接口。

---

## 1. 命令行工具 `runidbg-cli`

全局日志选项需置于子命令之前：
```bash
runidbg-cli [--log-level <trace|debug|info|warn|error>] [--log-format <compact|json>] <subcommand> ...
```

| 子命令 | 用途 | 常用示例 |
| --- | --- | --- |
| `run` | 运行 QuickJS 仿真脚本（支持 `--freeze-layout` 隔离宿主分配） | `runidbg-cli run --freeze-layout probe.js -- "arg1"` |
| `serve` | 启动异步 HTTP / JSON-RPC 2.0 服务 | `runidbg-cli serve script.js --listen 0.0.0.0:8080 --workers auto --max-queue 2048 --timeout-ms 15000 --max-insns 5000000 --allow-reload` |
| `mcp` | 启动 MCP 服务端（stdio / Streamable HTTP，36 个工具） | `runidbg-cli mcp --cwd .` 或 `runidbg-cli mcp --http 127.0.0.1:8090 --cwd .` |
| `debug` | 启动 ARM64 GDB RSP 远程调试服务端（支持 `.so` 或 `--tape` 时间旅行反向调试） | `runidbg-cli debug --tape sign_tt.rtape --listen 127.0.0.1:1234` |
| `tape` | 查看 `.rtape` 磁带检查点、时间轴事件与压缩统计 | `runidbg-cli tape info ./sign_tt.rtape` |
| `ui` | 启动内置暗黑 Web UI（Trace 分析 + `.rtape` 时间旅行驾驶舱） | `runidbg-cli ui ./trace.idx --base 0x40000000 --open` |
| `init-types` | 导出 TypeScript 类型声明 `runidbg.d.ts` | `runidbg-cli init-types examples/scripts` |
| `dump` | 离线反汇编 Trace（自动探测同级 `.ext`，含访存 R/W 与 HLE 事件） | `runidbg-cli dump trace.idx --base 0x40000000 --skip 0 --limit 50` |
| `search` / `find` | 离线检索寄存器值 / 访存地址 / PC / ASCII / 字节序列 | `runidbg-cli find trace.idx --base 0x40000000 --val 0x03000001` |
| `taint` | 离线字节级前向污点传播与反向因果切片（跨 HLE `memcpy` 与 S-Box 查表） | `runidbg-cli taint trace.idx --mode backward --addr 0x50006470 --len 8 --base 0x40000000` |
| `diff` | 双跑 Trace 差分（定位首次控制流分歧与首次寄存器/内存/HLE 数据分歧） | `runidbg-cli diff a.idx b.idx --base 0x40000000 --limit 64` |
| `vm` | OLLVM / 自定义字节码 VM 专项分析（自动识别调度循环、跳转表、opmap 步长与寄存器堆差分） | `runidbg-cli vm trace.idx --base 0x40000000 --base-reg x25 --layout 6:6,12,17,22,27` |
| `stats` | 离线热点统计（唯一 PC、Top-N 热点指令与 `BL` 目标） | `runidbg-cli stats trace.idx --base 0x40000000 --top 20` |
| `calltree` | 离线时间轴调用树构建与热点函数耗时统计 | `runidbg-cli calltree trace.idx --base 0x40000000 --max-depth 5 --min-insns 1000` |
| `crypto-scan` | 离线密码学原语自动扫描（AES / MD5 / SHA / SM3 / SM4 / RC4 / ChaCha 等常量） | `runidbg-cli crypto-scan trace.idx --base 0x40000000` |
| `export-ida` | 导出 IDA Pro 执行覆盖率高亮脚本 | `runidbg-cli export-ida trace.idx --base 0x40000000 --out ida_cov.py` |
| `export-bn` | 导出 Binary Ninja 执行覆盖率高亮脚本 | `runidbg-cli export-bn trace.idx --base 0x40000000 --out bn_cov.py` |

---

## 2. QuickJS 脚本引擎 API

完整 TypeScript 声明见 [src/script/runidbg.d.ts](../src/script/runidbg.d.ts)。

### 2.1 创建模拟器、多后端、堆布局冻结与设备画像（`DeviceProfile`）
```javascript
const emu = Emu.create({
  backend: "unicorn",               // "unicorn"(全功能) | "dynarmic" | "kvm"(Linux) | "hypervisor"/"hyper"(macOS)
  packageName: "com.example.app",
  searchPaths: ["./libs"],          // DT_NEEDED 依赖搜索路径
  hleAccel: true,                   // 默认 true，开启高频 libc/libm HLE 加速
  freezeLayout: true,               // 开启后 emu.mem.alloc() 隔离到 [host-scratch]，绝不漂移 guest malloc 堆地址！
  heapSize: 32 * 1024 * 1024,       // 默认 32 MB
  realClock: false,                 // true=宿主机实时时间；false=确定性虚拟时钟（默认）
  device: {                         // 可直接传预设名 "pixel5" | "pixel8pro" | "s24ultra" | "xiaomi14"
    preset: "pixel8pro",
    model: "23049RAD8C",
    brand: "Redmi",
    sdkInt: 35,
    androidRelease: "15",
  },
});

// 随时查看 guest 堆布局指纹与关键分配点，排查跨跑地址变化：
console.log(JSON.stringify(emu.heapLayout(50), null, 2));
```
应用 `device` 后自动同步 30+ 项 Android 系统属性、`/proc/cpuinfo`、`/proc/meminfo`、`/proc/version`、`/sys/devices/system/cpu/online|possible`、`uname` 与 JNI `android/os/Build.*` 静态字段。

> **PRNG 桩说明**：HLE `rand()`/`random()`/`srand()`/`srandom()` 使用确定性 `xorshift64*` 实现（非真 glibc TYPE_3 状态机），首次触发会在日志打印一次提醒；如需自定义序列可用 `emu.hook.importReplace("rand", ...)` 替换。

### 2.2 加载 `.so` / APK、快照与 `.rtape` 时间旅行
```javascript
// 加载独立 .so（自动递归加载 DT_NEEDED、执行重定位与 .init_array）
const mod = emu.load("./libs/libtarget.so");
const ver = emu.jniOnLoad(mod);

// 或一键内存加载 APK（自动解析包名、ABI、assets 与签名）
const apk = emu.loadApk("./app.apk");
const lib = apk.loadLib("libtarget.so");

// 设置单次调用硬超时与指令预算（0 表示不限）
emu.setLimits({ timeoutMs: 15000, maxInstructions: 5_000_000 });

// 进程内内存快照回滚
const snapId = emu.snapshot();
const r1 = mod.call("sign", ptr1, len1);
emu.restore(snapId);
const r2 = mod.call("sign", ptr2, len2);

// 持久化 .rtape 磁带与跨后端接力（Dynarmic/Hypervisor 初始化 -> Unicorn 时间旅行）
emu.saveTape("./init.rtape", "after_init");
const uc = Emu.loadTape("./init.rtape", { backend: "unicorn", checkpoint: "after_init" });
uc.record.start({ keyframeInterval: 100000, captureJni: true });
uc.module("libtarget.so").call("sign", ptr1, len1);
uc.record.bookmark("done");
uc.record.stop("./sign_tt.rtape");

const tt = Emu.openTimeTravel("./sign_tt.rtape");
tt.verifyDeterminism();
tt.seekBookmark("done");
const writer = tt.findPrevWrite(ptr1, 8);
tt.close();
```

### 2.3 JNI 桥接与 Hook
```javascript
emu.jni.hook("com/example/Env", {
  getToken(arg0) { return "mock-token"; },
});
emu.jni.onUnhandled((info) => {
  console.log(info.kind, info.className, info.name, info.sig, info.args);
  return 0;
});

// 常驻 RPC 建议包裹在 withLocalFrame 中自动回收本地引用与临时缓冲
const out = emu.jni.withLocalFrame(() => {
  const cls = emu.jni.findClass("com/example/Api");
  const sRef = emu.jni.newString("payload");
  const ret = emu.call(mod.base + 0x120be0, emu.jni.envPtr, cls, sRef);
  return emu.jni.getStringArray(ret);
});
```

### 2.4 Frida 风格 Native Hook、无损 64-bit 寄存器与 Rust 侧内存过滤
> **重要时序与精度说明**：
> - **`emu.hook.code` 在目标指令执行前触发**，回调里读到的寄存器是该指令执行前的状态；
> - **`ctx.reg("x8")` 返回 JS `number`**，超过 `2^53 - 1` 会丢低位精度。读取 64 位整数/哈希/指针请使用 **`ctx.reg64("x8")`** 或 **`emu.regs.get64("x8")`**（返回无损 `BigInt`）。

```javascript
// 1. 函数入口/返回 Hook（this 可在 onEnter 与 onLeave 间共享状态）
const h1 = emu.hook.attach(mod.base + 0x12340, {
  onEnter(ctx) {
    this.x8 = ctx.reg64("x8"); // 无损 64-bit BigInt
    console.log("x0=", ctx.reg64("x0").toString(16), "str=", ctx.mem.readCString(ctx.x1, 128));
  },
  onLeave(ctx) {
    console.log("retval=", ctx.reg64("x0").toString(16));
  },
});

// 2. 函数替换 / 导入表替换
const h2 = emu.hook.replace(mod.base + 0x56780, (ctx) => 0);
const h3 = emu.hook.importReplace("rand", () => 0x1234);

// 3. 区间写/读监视（emu.hook.watch）与 Rust 侧零开销过滤（emu.hook.mem）
//    当目标区间尚无已映射页时，会输出警告并设置 handle.unmapped === true
const wh = emu.hook.watch([buf, buf + 64], "w", (ctx, access, addr, size, val, val64) => {
  console.log(`pc=0x${ctx.pc.toString(16)} write addr=0x${addr.toString(16)} val64=0x${val64.toString(16)}`);
});

const mh = emu.hook.mem(
  [buf, buf + 64],
  { write: true, value: 0xdeadbeefn, size: 4, pcRange: [mod.base, mod.base + mod.size], bigInt: true },
  (ctx, access, addr, size, val, val64) => { /* 仅在 Rust 侧条件全命中时进入 JS */ }
);
if (mh.unmapped) console.warn("目标区间尚未映射！");

// 4. 原生内存特征扫描与热修补（自动刷新 Unicorn TB 缓存）
const hits = emu.mem.scan(mod.base, mod.size, "FD 7B ?? A9");
emu.mem.nop(mod.base + 0x9000, 2);
emu.mem.ret(mod.base + 0x9100, 1);
```

### 2.5 VM 专项辅助（在线 `emu.vm` + 离线 `Trace.open().vmAnalyze`）
```javascript
// 在线实时监听自定义字节码 VM 寄存器堆（自动追踪 baseReg 栈帧搬家 + 解码字节码指令字 + 统计步长）
const watcher = emu.vm.watchRegfile({
  baseReg: "x25",
  count: 32,
  size: 8,
  dispatcherPc: mod.base + 0x12340,
  bcReg: "x23",      // 若 [x23] 内存里存着字节码指针，加 bcDeref: true
  wordSize: 4,
  layout: { op: [6, 6], fields: [12, 17, 22, 27] },
});
emu.call(mod.base + 0x10000, ...);
console.log(watcher.format(100)); // step#0001 bc=0x...(+8B) op=49 f=[1,5,0,7] | R[3]: 0x10->0x42
console.log(watcher.stats());     // 按 op 汇总频次与消费字节步长直方图
watcher.detach();

// 单独解码任意字节码指令字（支持 64-bit 无损 BigInt）：
const dec = emu.vm.decodeWord(0x38005c40, { op: [6, 6], fields: [12, 17, 22, 27] });
```

### 2.6 缺环境诊断（`EnvDiag`）与崩溃报告（`CrashReport`）
```javascript
emu.diag.enable();
console.log(JSON.stringify(emu.diag.report(), null, 2));
console.log(emu.diag.generatePatchJs());

const crash = emu.lastCrash();
if (crash) console.error(crash.formatted);
```

---

## 3. 高性能二进制 Trace、离线污点切片与全知查询

| 级别 | 记录内容 | 实测吞吐 | 适用场景 |
| --- | --- | ---: | --- |
| `fast` | PC + 32-bit opcode（32B/条，无 `.ext`） | ~17 M insns/s | 覆盖率统计、IDA/BN 高亮、控制流路径对比 |
| `reg_delta` | 指令 + 变更寄存器增量（32B/条，无内存 `.ext`） | ~5 M insns/s | 轻量算法逆向、寄存器值溯源 |
| `full` | `reg_delta` + `.ext`（访存 R/W + HLE `memcpy`/`memmove`/`memset`/`bzero`/`malloc`/`calloc`/`realloc`/`free`） | ~4.7 M insns/s | 离线污点与反向因果切片、全知值/地址查询、VM 离线分析 |

- 默认容量为 `262144` 条指令（`.ext` 双倍容量）；容量耗尽时会在 `emu.trace.stop()` 打印截断警告并返回 `stats.truncated === true` 与 `droppedInsns`/`droppedExt`。
- QuickJS 离线 `Trace.open()` API：
```javascript
const tr = Trace.open("trace_full.idx"); // 自动关联同级 .ext
const wHits = tr.findWrites(0xdeadbeefn, { width: 4 });
const aHist = tr.findReads(0x50006470, { len: 8, minSeq: 1000, maxSeq: 50000 });
const hles  = tr.hleEvents(200);
const snap  = tr.reconstructMem(0x50006470, 16); // 可省略第 3 参 atSeq，默认重建至末尾
const bwd   = tr.taintBackward({ addr: 0x50006470, len: 8 });
const fwd   = tr.taintForward({ addr: 0x50001000, len: 16 });
const vmRep = tr.vmAnalyze({ baseReg: "x25", layout: { op: [6, 6], fields: [12, 17, 22, 27] } });
tr.close();

const diff = Trace.diff("run_a.idx", "run_b.idx", 100);
```

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

背压与熔断：队列满返回 `HTTP 503`；超出 `--timeout-ms` 或 `--max-insns` 触发硬中断并返回 `HTTP 504`。

---

## 5. MCP 服务端（36 个 AI 逆向工具）

支持 **stdio**（`runidbg-cli mcp --cwd .`）与 **Streamable HTTP**（`runidbg-cli mcp --http 127.0.0.1:8090 --cwd .`）：

| 类别 | 工具名 | 说明 |
| --- | --- | --- |
| 生命周期与执行 | `emu_create` / `emu_load` / `emu_jni_onload` / `emu_exports` / `emu_call` / `emu_eval_js` | 创建实例（支持 `backend`/`freezeLayout`）、加载 `.so`、查导出、调函数与执行 JS |
| DEX 与 JNI | `emu_load_dex` / `emu_dex_class_info` / `emu_jni_set_field` / `emu_jni_call_native` | 加载 DEX 元数据索引、查询类/字段/方法、读写 JNI 字段与直接调用原生方法 |
| 状态与反汇编 | `emu_regs` / `emu_mem_read` / `emu_mem_scan` / `emu_disasm` | 读寄存器、读/扫内存、`bad64` 反汇编 |
| Trace / 污点 / Diff / VM / Hook | `emu_trace_call` / `trace_inspect` / `trace_calltree` / `trace_crypto_scan` / `trace_taint` / `trace_query` / `trace_diff` / `trace_vm_analyze` / `emu_hook_capture` | 函数级 Trace、检索、调用树、密码学扫描、离线污点切片、全知查询、双跑差分、VM 自动分析与一次性 Hook 抓取 |
| `.rtape` 磁带与时间旅行 | `emu_save_tape` / `emu_load_tape` / `emu_seek_tape` / `tape_info` / `tt_record_start` / `tt_record_stop` / `tt_open` / `tt_seek` / `tt_reverse_watch` / `tt_mem_read` / `tt_close` | 跨后端磁带接力、二期时间旅行录制、任意指令跳转与反向内存写/读/访问观察点 |
| 诊断 | `emu_diag_missing` / `emu_last_crash` | 获取 `EnvDiag` 缺失环境报告与最新崩溃现场 |

---

## 6. GDB RSP 远程调试（含时间旅行反向调试）

```bash
# 普通 .so 调试
runidbg-cli debug samples/libstatic-webp.so WebPGetDecoderVersion --listen 127.0.0.1:1234

# .rtape 磁带时间旅行反向调试（支持 rs / rc / watch / rwatch / awatch / monitor seek / monitor rw）
runidbg-cli debug --tape ./sign_tt.rtape --listen 127.0.0.1:1234
```
支持标准 ARM64 GDB Remote Serial Protocol，可直接用 `gdb-multiarch` / `pwndbg` / IDA Pro / Binary Ninja 连接：`target remote 127.0.0.1:1234`。

---

## 7. Rust 库嵌入用法

```rust
use runidbg_arm64_emu_tracer::os::DeviceProfile;
use runidbg_arm64_emu_tracer::tracer::{
    TaintOptions, TaintSeed, TraceLevel, TraceReader, VmAnalysisOptions,
};
use runidbg_arm64_emu_tracer::AndroidEmulator;

let mut emu = AndroidEmulator::builder()
    .package_name("com.example.app")
    .device_profile(DeviceProfile::pixel_8_pro())
    .add_search_path("./libs")
    .with_memory_trace(200_000, TraceLevel::Full)
    .build()?;

let module = emu.load_library("./libs/libtarget.so")?;
emu.call_jni_onload(&module)?;
let ret = emu.call_symbol(&module, "target_func", &[0, 0])?;

// 离线污点切片与 VM 专项分析同样可直接从 Rust 调用：
let reader = TraceReader::open("trace.idx", Some(std::path::Path::new("trace.ext")))?;
let bwd = reader.taint_backward(&TaintSeed::Mem { addr: 0x5000_6470, len: 8 }, &TaintOptions::default());
let vm  = reader.analyze_vm(&VmAnalysisOptions::default());
```
