---
name: runidbg
description: Use runidbg (runidbg-cli) to emulate Android ARM64 .so libraries, write QuickJS JNI/Hook scripts, diagnose missing Android environments with EnvDiag, capture high-speed binary instruction traces (dump/search/stats/IDA/BN), launch multi-core HTTP/JSON-RPC signing services, connect via MCP (15 tools), or debug with GDB RSP.
---

# runidbg Agent Skill

Use `runidbg` when reversing, emulating, tracing, or serving **Android ARM64 (`aarch64`) `.so` libraries** without an Android device or JVM.

## Prerequisites & Build

```bash
# macOS (requires pkgconf + cmake + ninja)
brew install pkgconf cmake ninja
cargo build --release

# Binaries produced:
#   target/release/runidbg-cli
#   target/release/runidbg-arm64-emu-tracer
```

## Standard Reverse-Engineering Workflow (Iterative Loop)

Follow this fast closed loop whenever bringing up a new `.so`:

1. **Create a minimal QuickJS probe script** with `emu.diag.enable()`, `device`, and `realClock`:
   ```javascript
   const emu = Emu.create({
     packageName: "com.example.app",
     searchPaths: ["./libs"],
     device: "pixel8pro", // pixel5 | pixel8pro | s24ultra | xiaomi14 | { ... }
     realClock: true,
   });
   emu.diag.enable();
   emu.setLimits({ timeoutMs: 30000, maxInstructions: 0 });

   emu.jni.onUnhandled((info) => {
     console.log(`[JNI] ${info.kind} ${info.className}.${info.name}${info.sig} args=${JSON.stringify(info.args)}`);
     return 0;
   });

   const mod = emu.load("./libs/libtarget.so");
   try {
     const ver = emu.jniOnLoad(mod);
     console.log("JNI_OnLoad =", ver ? "0x" + ver.toString(16) : null);
   } catch (e) {
     console.error(emu.lastCrash()?.formatted || e);
   }
   console.log("RegisteredNatives:", JSON.stringify(emu.jni.registeredNatives()));
   console.log("EnvDiag:", JSON.stringify(emu.diag.report(), null, 2));
   ```
2. **Run with structured logging**:
   ```bash
   ./target/release/runidbg-cli --log-level info run probe.js
   ```
3. **Patch missing environment using `EnvDiag`**:
   - `missingFiles` -> `emu.vfs.writeFile(path, content)` or `emu.vfs.mountOverlay(guestDir, hostDir)`
   - `missingProperties` -> `emu.vfs.setProperty(key, val)` or `emu.vfs.setDevice(...)`
   - `missingSyscalls` -> `emu.hook.syscall(nr, (ctx, nr) => retVal)`
   - `missingJni` -> `emu.jni.hook("pkg/Class", { method(a, b) { ... } })`
   - Or call `emu.diag.generatePatchJs()` to auto-generate a starter patch template.
4. **Inspect crashes immediately**:
   - Always print `emu.lastCrash()?.formatted` on error — it includes fault PC + module offset, ARM64 disassembly around PC, all X0–X30/SP/FP/NZCV registers, FP backtrace, recent HLE/JNI/Syscall breadcrumbs, and VMA maps.
   - If a heavy `.init_array` or `JNI_OnLoad` hits `ExecutionTimeout`, raise or remove the cap via `emu.setLimits({ timeoutMs: 30000, maxInstructions: 0 })`.

## Essential QuickJS Patterns

### Calling Native Functions & JNI Helpers
```javascript
const cls = emu.jni.findClass("com/example/Native");
const strRef = emu.jni.newString("hello");
const arrRef = emu.jni.newStringArray(["k1", "v1", "k2", "v2"]);

// Direct call by offset (passing emu.jni.envPtr as X0):
const retRef = emu.call(mod.base + 0x120be0, emu.jni.envPtr, cls, 50331649, 0, 0, strRef, arrRef);
const outStrings = emu.jni.getStringArray(retRef);

// Or call registered JNI native directly by class + method name:
const r = emu.jni.callNative("com/example/Native", "sign", [strRef]);
```

### Frida-Style Native Hooks (JNI-Safe Inside Callbacks)
```javascript
emu.hook.attach(mod.base + 0x12340, {
  onEnter(ctx) {
    this.arg0 = ctx.x0;
    console.log("enter x0=", ctx.x0, "str=", emu.jni.getString(ctx.x1));
  },
  onLeave(ctx) {
    console.log("leave ret=", ctx.retval);
  },
});

emu.hook.replace(mod.base + 0x56780, (ctx) => 1);
emu.hook.syscall(160, (ctx, nr) => undefined); // return undefined to fall through
```

### High-Speed Binary Tracing & Offline Analysis
```javascript
emu.trace.start({
  output: "run.idx",     // auto-creates run.ext in "full" mode, truncated on stop()
  level: "full",         // "fast" (~17M/s) | "reg_delta" (~5M/s) | "full" (~4.7M/s + mem R/W)
  start: mod.base,
  end: mod.base + mod.size,
  capacity: 2000000,
});
emu.call(mod.base + 0x120be0, ...);
const stats = emu.trace.stop(); // { records, extRecords, totalInsns, droppedInsns, droppedExt }
```
Analyze offline with `runidbg-cli`:
```bash
runidbg-cli stats  run.idx --base 0x40000000 --top 20
runidbg-cli dump   run.idx --base 0x40000000 --skip 0 --limit 50
runidbg-cli search run.idx --base 0x40000000 --val 0x03000001
runidbg-cli export-ida run.idx --base 0x40000000 --out ida_cov.py
runidbg-cli export-bn  run.idx --base 0x40000000 --out bn_cov.py
```

### Serving as Multi-Core HTTP/JSON-RPC 2.0 Service
Export functions on `rpc.exports = { sign(url) { ... } }`, then run:
```bash
runidbg-cli serve script.js --listen 127.0.0.1:8080 --workers auto --timeout-ms 15000 --allow-reload
# Endpoints: GET /health, GET /metrics, GET /exports, POST /call/<method>, POST /rpc, POST /admin/reload
```

### Using MCP Tools (AI Agent Direct Control)
Start MCP server via stdio (`runidbg-cli mcp --cwd .`) or Streamable HTTP (`runidbg-cli mcp --http 127.0.0.1:8090 --cwd .`). Available 15 tools:
- Lifecycle & Execution: `emu_create`, `emu_load`, `emu_jni_onload`, `emu_exports`, `emu_call`, `emu_eval_js`
- Inspection & Memory: `emu_regs`, `emu_mem_read`, `emu_mem_scan`, `emu_disasm`
- Tracing & Hooks: `emu_trace_call`, `trace_inspect`, `emu_hook_capture`
- Diagnostics: `emu_diag_missing`, `emu_last_crash`

## Guardrails & Best Practices
- Only targets **Android ARM64 (`aarch64`)** ELF shared libraries.
- Never hardcode or commit real cookies, session tokens, or private keys into scripts or tests.
- When tracing large calls, always scope `start`/`end` to `[mod.base, mod.base + mod.size]` to exclude libc HLE trampolines and keep traces compact.
- For full API details, read [docs/GUIDE.md](./GUIDE.md) and [src/script/runidbg.d.ts](../src/script/runidbg.d.ts).
