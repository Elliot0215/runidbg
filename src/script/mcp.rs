use std::io::{self, BufRead, Write};
use std::path::Path;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::script::JsSession;
use crate::tracer::{BinaryTracer, TraceReader};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

const MCP_INIT_JS: &str = r#"
globalThis.__mcp = {
  emus: {},
  mods: {},
  nextEmuId: 1,
  nextModId: 1,
};
"#;

/// Model Context Protocol (MCP) stdio JSON-RPC 2.0 服务端
///
/// 底层持有持久化 `JsSession`（开启 `capture_logs = true` 防止 `console.log` 污染 `stdout` 协议流），
/// 让 Claude / Cursor / Antigravity 等 AI Agent 直接驱动 ARM64 `.so` 仿真、Hook、内存扫描与 Trace 分析。
pub struct McpServer {
    session: JsSession,
}

impl McpServer {
    /// 创建 MCP Server 实例；可选预加载初始化脚本（如环境补丁或 `rpc.exports`）
    pub fn new(base_dir: &Path, init_script: Option<&Path>) -> Result<Self> {
        let session = JsSession::new(&[], base_dir, true)?;
        session.eval_source(MCP_INIT_JS)?;
        if let Some(script) = init_script {
            session.eval_file(script)?;
            let _ = session.take_logs();
        }
        Ok(Self { session })
    }

    /// 阻塞运行 stdio JSON-RPC 2.0 主循环（每行一个 JSON 消息）
    pub fn run_stdio(&mut self) -> Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout().lock();
        for line in stdin.lock().lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(resp) = self.handle_message(trimmed) {
                writeln!(stdout, "{resp}")?;
                stdout.flush()?;
            }
        }
        Ok(())
    }

    /// 处理单条 JSON-RPC 2.0 消息；通知类消息返回 `None`，请求返回序列化后的响应字符串
    pub fn handle_message(&mut self, line: &str) -> Option<String> {
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32700, "message": format!("Parse error: {e}") }
                    })
                    .to_string(),
                );
            }
        };

        let id = req.get("id").cloned();
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32600, "message": "Invalid Request: missing method" }
                })
                .to_string()
            });
        };

        // MCP 通知（无 id）无需回包
        let id = id?;
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        let resp = match method {
            "initialize" => {
                let client_ver = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(MCP_PROTOCOL_VERSION);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": client_ver,
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "runidbg",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                })
            }
            "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tool_definitions() }
            }),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                match self.dispatch_tool(name, &args) {
                    Ok(payload) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&payload).unwrap_or_default()
                            }],
                            "isError": false
                        }
                    }),
                    Err(err) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": format!("Tool `{name}` failed: {err}")
                            }],
                            "isError": true
                        }
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {method}") }
            }),
        };

        Some(resp.to_string())
    }

    fn eval_js_value(&self, code: &str) -> Result<Value> {
        let json_str = self.session.eval_json_string(code)?;
        Ok(serde_json::from_str(&json_str)?)
    }

    fn dispatch_tool(&mut self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "emu_create" => {
                let opts_json = serde_json::to_string(args)?;
                let code = format!(
                    "(() => {{ \
                        const id = __mcp.nextEmuId++; \
                        __mcp.emus[id] = Emu.create({opts_json}); \
                        return {{ emuId: id }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_load" => {
                let emu_id = req_u64(args, "emuId")?;
                let path = req_str(args, "path")?;
                let path_json = serde_json::to_string(path)?;
                let code = format!(
                    "(() => {{ \
                        const emu = __mcp.emus[{emu_id}]; \
                        if (!emu) throw new Error('unknown emuId: {emu_id}'); \
                        const mod = emu.load({path_json}); \
                        const modId = __mcp.nextModId++; \
                        __mcp.mods[modId] = {{ emuId: {emu_id}, mod }}; \
                        return {{ modId, name: mod.name, base: mod.base, baseHex: '0x' + mod.base.toString(16), size: mod.size, exportCount: mod.exports().length }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_jni_onload" => {
                let mod_id = req_u64(args, "modId")?;
                let code = format!(
                    "(() => {{ \
                        const entry = __mcp.mods[{mod_id}]; \
                        if (!entry) throw new Error('unknown modId: {mod_id}'); \
                        const emu = __mcp.emus[entry.emuId]; \
                        const ver = emu.jniOnLoad(entry.mod); \
                        return {{ version: ver, versionHex: ver !== null ? '0x' + ver.toString(16) : null, registeredNativesCount: emu.jni.registeredNatives().length }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_exports" => {
                let mod_id = req_u64(args, "modId")?;
                let filter = args.get("filter").and_then(Value::as_str).unwrap_or("");
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(100);
                let filter_json = serde_json::to_string(filter)?;
                let code = format!(
                    "(() => {{ \
                        const entry = __mcp.mods[{mod_id}]; \
                        if (!entry) throw new Error('unknown modId: {mod_id}'); \
                        const needle = {filter_json}.toLowerCase(); \
                        const all = entry.mod.exports(); \
                        const filtered = needle ? all.filter(s => s.toLowerCase().includes(needle)) : all; \
                        return {{ total: filtered.length, exports: filtered.slice(0, {limit}) }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_call" => {
                let emu_id = req_u64(args, "emuId")?;
                let mod_id = args.get("modId").and_then(Value::as_u64);
                let target = args
                    .get("target")
                    .ok_or_else(|| anyhow!("缺少参数 target（符号名或地址）"))?;
                let target_json = serde_json::to_string(target)?;
                let call_args_json = args
                    .get("args")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "[]".to_string());
                let code = if let Some(mid) = mod_id {
                    format!(
                        "(() => {{ \
                            const entry = __mcp.mods[{mid}]; \
                            if (!entry) throw new Error('unknown modId: {mid}'); \
                            const ret = entry.mod.call({target_json}, ...{call_args_json}); \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16) }}; \
                        }})()"
                    )
                } else {
                    format!(
                        "(() => {{ \
                            const emu = __mcp.emus[{emu_id}]; \
                            if (!emu) throw new Error('unknown emuId: {emu_id}'); \
                            const ret = emu.call({target_json}, ...{call_args_json}); \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16) }}; \
                        }})()"
                    )
                };
                self.eval_js_value(&code)
            }
            "emu_mem_read" => {
                let emu_id = req_u64(args, "emuId")?;
                let addr = parse_addr_val(args.get("addr"))?;
                let format_kind = args
                    .get("format")
                    .and_then(Value::as_str)
                    .unwrap_or("hex");
                let len = args.get("len").and_then(Value::as_u64).unwrap_or(64);
                let code = match format_kind {
                    "cstring" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return {{ value: e.mem.readCString({addr}, {len}) }}; }})()"
                    ),
                    "u32" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); const v = e.mem.readU32({addr}); return {{ value: v, hex: '0x' + v.toString(16) }}; }})()"
                    ),
                    "u64" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); const v = e.mem.readU64({addr}); return {{ value: v.toString(), hex: '0x' + v.toString(16) }}; }})()"
                    ),
                    _ => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); const b = e.mem.readBytes({addr}, {len}); return {{ hex: hex(b), length: b.length }}; }})()"
                    ),
                };
                self.eval_js_value(&code)
            }
            "emu_mem_scan" => {
                let emu_id = req_u64(args, "emuId")?;
                let start = parse_addr_val(args.get("start"))?;
                let len = req_u64(args, "len")?;
                let pattern = req_str(args, "pattern")?;
                let pat_json = serde_json::to_string(pattern)?;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(64);
                let code = format!(
                    "(() => {{ \
                        const e = __mcp.emus[{emu_id}]; \
                        if (!e) throw new Error('unknown emuId'); \
                        const hits = e.mem.scan({start}, {len}, {pat_json}); \
                        return {{ total: hits.length, hits: hits.slice(0, {limit}).map(a => ({{ addr: a, hex: '0x' + a.toString(16) }})) }}; \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_regs" => {
                let emu_id = req_u64(args, "emuId")?;
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.regs.dump(); }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_eval_js" => {
                let code = req_str(args, "code")?;
                let _ = self.session.take_logs();
                let result = self.eval_js_value(code)?;
                let logs = self.session.take_logs();
                Ok(json!({ "result": result, "logs": logs }))
            }
            "trace_inspect" => {
                let idx_path = req_str(args, "idxPath")?;
                let ext_path = args.get("extPath").and_then(Value::as_str);
                let action = args.get("action").and_then(Value::as_str).unwrap_or("dump");
                let skip = args.get("skip").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
                let reader = TraceReader::open(Path::new(idx_path), ext_path.map(Path::new))?;

                let mut lines = Vec::new();
                match action {
                    "search_val" => {
                        let target = parse_addr_val(args.get("value"))?;
                        for (idx, rec) in reader.search_value(target).into_iter().skip(skip).take(limit) {
                            lines.push(format!("#{idx:06} {}", BinaryTracer::decode_record(&rec)));
                        }
                    }
                    "search_addr" => {
                        let target = parse_addr_val(args.get("addr"))?;
                        for ext in reader.search_mem_addr(target).into_iter().skip(skip).take(limit) {
                            let seq = ext.seq_low32;
                            let pc = ext.pc;
                            lines.push(format!(
                                "seq={seq} pc=0x{pc:016x} {}",
                                BinaryTracer::format_ext_record(&ext).trim()
                            ));
                        }
                    }
                    _ => {
                        let end = reader.len().min(skip.saturating_add(limit));
                        for idx in skip..end {
                            if let Some(rec) = reader.get(idx) {
                                lines.push(format!("#{idx:06} {}", BinaryTracer::decode_record(&rec)));
                            }
                        }
                    }
                }
                Ok(json!({
                    "totalRecords": reader.len(),
                    "totalExtRecords": reader.ext_len(),
                    "returned": lines.len(),
                    "lines": lines,
                }))
            }
            "emu_disasm" => {
                let emu_id = req_u64(args, "emuId")?;
                let addr = parse_addr_val(args.get("addr"))?;
                let count = args.get("count").and_then(Value::as_u64).unwrap_or(16).clamp(1, 256);
                let byte_len = count * 4;
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return hex(e.mem.readBytes({addr}, {byte_len})); }})()"
                );
                let hex_val = self.eval_js_value(&code)?;
                let hex_str = hex_val
                    .as_str()
                    .ok_or_else(|| anyhow!("读取内存失败：未返回 hex 字符串"))?;
                let raw = decode_hex_bytes(hex_str)?;
                let mut insns = Vec::with_capacity(count as usize);
                for (i, chunk) in raw.as_chunks::<4>().0.iter().enumerate() {
                    let pc = addr + (i as u64) * 4;
                    let word = u32::from_le_bytes(*chunk);
                    let asm = match bad64::decode(word, pc) {
                        Ok(inst) => format!("{inst}"),
                        Err(_) => format!(".word 0x{word:08x}"),
                    };
                    insns.push(json!({
                        "addr": pc,
                        "addrHex": format!("0x{pc:016x}"),
                        "word": format!("0x{word:08x}"),
                        "asm": asm,
                    }));
                }
                Ok(json!({
                    "start": format!("0x{addr:016x}"),
                    "count": insns.len(),
                    "instructions": insns,
                }))
            }
            "emu_trace_call" => {
                let emu_id = req_u64(args, "emuId")?;
                let mod_id = args.get("modId").and_then(Value::as_u64);
                let target = args
                    .get("target")
                    .ok_or_else(|| anyhow!("缺少参数 `target`"))?;
                let target_json = serde_json::to_string(target)?;
                let call_args_json = args
                    .get("args")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "[]".to_string());
                let level = args
                    .get("level")
                    .and_then(Value::as_str)
                    .unwrap_or("reg_delta");
                let level_json = serde_json::to_string(level)?;
                let capacity = args.get("capacity").and_then(Value::as_u64).unwrap_or(65536);

                let invoke_expr = if let Some(mid) = mod_id {
                    format!(
                        "const entry = __mcp.mods[{mid}]; if (!entry) throw new Error('unknown modId'); const ret = entry.mod.call({target_json}, ...{call_args_json});"
                    )
                } else {
                    format!("const ret = e.call({target_json}, ...{call_args_json});")
                };
                let code = format!(
                    "(() => {{ \
                        const e = __mcp.emus[{emu_id}]; \
                        if (!e) throw new Error('unknown emuId'); \
                        e.trace.start({{ level: {level_json}, capacity: {capacity} }}); \
                        let stats; \
                        try {{ \
                            {invoke_expr} \
                            stats = e.trace.stop(); \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16), trace: stats }}; \
                        }} catch (err) {{ \
                            try {{ e.trace.stop(); }} catch (_) {{}} \
                            throw err; \
                        }} \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_hook_capture" => {
                let emu_id = req_u64(args, "emuId")?;
                let hook_addr = parse_addr_val(args.get("hookAddr"))?;
                let mod_id = args.get("modId").and_then(Value::as_u64);
                let call_target = args
                    .get("callTarget")
                    .ok_or_else(|| anyhow!("缺少参数 `callTarget`"))?;
                let target_json = serde_json::to_string(call_target)?;
                let call_args_json = args
                    .get("args")
                    .map(serde_json::to_string)
                    .transpose()?
                    .unwrap_or_else(|| "[]".to_string());
                let arg_count = args.get("argCount").and_then(Value::as_u64).unwrap_or(4).min(8);

                let invoke_expr = if let Some(mid) = mod_id {
                    format!(
                        "const entry = __mcp.mods[{mid}]; if (!entry) throw new Error('unknown modId'); const ret = entry.mod.call({target_json}, ...{call_args_json});"
                    )
                } else {
                    format!("const ret = e.call({target_json}, ...{call_args_json});")
                };
                let code = format!(
                    "(() => {{ \
                        const e = __mcp.emus[{emu_id}]; \
                        if (!e) throw new Error('unknown emuId'); \
                        const captures = []; \
                        const h = e.hook.attach({hook_addr}, {{ \
                            onEnter(ctx) {{ \
                                this._cap = {{ args: ctx.args({arg_count}).map(v => '0x' + v.toString(16)), retval: null }}; \
                                captures.push(this._cap); \
                            }}, \
                            onLeave(ctx) {{ \
                                if (this._cap) this._cap.retval = '0x' + ctx.retval.toString(16); \
                            }} \
                        }}); \
                        try {{ \
                            {invoke_expr} \
                            return {{ retval: ret, retvalHex: '0x' + ret.toString(16), hits: captures.length, captures }}; \
                        }} finally {{ \
                            h.detach(); \
                        }} \
                    }})()"
                );
                self.eval_js_value(&code)
            }
            "emu_diag_missing" => {
                let emu_id = req_u64(args, "emuId")?;
                let action = args
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("report");
                let code = match action {
                    "enable" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.diag.enable(); return {{ enabled: true }}; }})()"
                    ),
                    "disable" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.diag.disable(); return {{ enabled: false }}; }})()"
                    ),
                    "clear" => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); e.diag.clear(); return {{ cleared: true }}; }})()"
                    ),
                    _ => format!(
                        "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return {{ report: e.diag.report(), patchJs: e.diag.generatePatchJs() }}; }})()"
                    ),
                };
                self.eval_js_value(&code)
            }
            "emu_last_crash" => {
                let emu_id = req_u64(args, "emuId")?;
                let code = format!(
                    "(() => {{ const e = __mcp.emus[{emu_id}]; if (!e) throw new Error('unknown emuId'); return e.lastCrash(); }})()"
                );
                self.eval_js_value(&code)
            }
            _ => Err(anyhow!("未知的 MCP 工具: {name}")),
        }
    }
}

fn decode_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err(anyhow!("无效的十六进制长度"));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| anyhow!("解析十六进制字节失败: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn req_u64(args: &Value, key: &str) -> Result<u64> {
    args.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("缺少整数参数 `{key}`"))
}

fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("缺少字符串参数 `{key}`"))
}

fn parse_addr_val(v: Option<&Value>) -> Result<u64> {
    let v = v.ok_or_else(|| anyhow!("缺少地址/数值参数"))?;
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16)
                .map_err(|_| anyhow!("无效的十六进制数: {s}"));
        }
        return s.parse::<u64>().map_err(|_| anyhow!("无效的整数: {s}"));
    }
    Err(anyhow!("地址/数值参数必须是整数或十六进制字符串"))
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "emu_create",
            "description": "Create a new Android ARM64 emulator instance in the persistent runidbg session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "packageName": { "type": "string", "description": "Android package name (default: com.example.app)" },
                    "searchPaths": { "type": "array", "items": { "type": "string" }, "description": "Sysroot / .so search directories" },
                    "hleAccel": { "type": "boolean", "description": "Enable Rust HLE libc acceleration (default: true)" }
                }
            }
        },
        {
            "name": "emu_load",
            "description": "Load an Android ARM64 ELF .so library and execute its .init_array constructors.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "path"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "path": { "type": "string", "description": "Host path to the ARM64 .so file" }
                }
            }
        },
        {
            "name": "emu_jni_onload",
            "description": "Invoke JNI_OnLoad on a loaded module and return JNI version and RegisterNatives count.",
            "inputSchema": {
                "type": "object",
                "required": ["modId"],
                "properties": {
                    "modId": { "type": "integer" }
                }
            }
        },
        {
            "name": "emu_exports",
            "description": "List exported symbols of a loaded module with optional case-insensitive substring filter.",
            "inputSchema": {
                "type": "object",
                "required": ["modId"],
                "properties": {
                    "modId": { "type": "integer" },
                    "filter": { "type": "string" },
                    "limit": { "type": "integer", "default": 100 }
                }
            }
        },
        {
            "name": "emu_call",
            "description": "Call an exported symbol name or raw ARM64 address with up to 8 integer arguments.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "target"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "modId": { "type": "integer", "description": "Required when target is a symbol name" },
                    "target": { "description": "Exported symbol name (string) or raw address (integer)" },
                    "args": { "type": "array", "items": { "type": "integer" } }
                }
            }
        },
        {
            "name": "emu_mem_read",
            "description": "Read guest memory as hex bytes, C string, u32, or u64.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "addr"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "addr": { "description": "Guest address (integer or '0x...' hex string)" },
                    "format": { "type": "string", "enum": ["hex", "cstring", "u32", "u64"], "default": "hex" },
                    "len": { "type": "integer", "default": 64 }
                }
            }
        },
        {
            "name": "emu_mem_scan",
            "description": "Scan guest memory for a hex byte pattern with '??' wildcards.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "start", "len", "pattern"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "start": { "description": "Start address (integer or '0x...' string)" },
                    "len": { "type": "integer" },
                    "pattern": { "type": "string", "description": "Hex pattern e.g. 'fd 7b ?? a9'" },
                    "limit": { "type": "integer", "default": 64 }
                }
            }
        },
        {
            "name": "emu_regs",
            "description": "Dump current ARM64 registers (x0..x30, sp, pc, nzcv) of an emulator instance.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" }
                }
            }
        },
        {
            "name": "emu_eval_js",
            "description": "Evaluate arbitrary runidbg QuickJS code in the persistent session (access __mcp.emus[id], __mcp.mods[id], Emu, hooks, patches, trace, etc.).",
            "inputSchema": {
                "type": "object",
                "required": ["code"],
                "properties": {
                    "code": { "type": "string" }
                }
            }
        },
        {
            "name": "trace_inspect",
            "description": "Inspect offline binary trace files (trace.idx / trace.ext) via dump, search_val, or search_addr.",
            "inputSchema": {
                "type": "object",
                "required": ["idxPath"],
                "properties": {
                    "idxPath": { "type": "string" },
                    "extPath": { "type": "string" },
                    "action": { "type": "string", "enum": ["dump", "search_val", "search_addr"], "default": "dump" },
                    "value": { "description": "Target register value for search_val (int or '0x...')" },
                    "addr": { "description": "Target memory address for search_addr (int or '0x...')" },
                    "skip": { "type": "integer", "default": 0 },
                    "limit": { "type": "integer", "default": 50 }
                }
            }
        },
        {
            "name": "emu_disasm",
            "description": "Disassemble ARM64 instructions starting at a guest address using bad64.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "addr"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "addr": { "description": "Start guest address (int or '0x...' hex string)" },
                    "count": { "type": "integer", "default": 16, "description": "Number of ARM64 instructions (1..256)" }
                }
            }
        },
        {
            "name": "emu_trace_call",
            "description": "Attach a temporary tracer, invoke a symbol/address, detach tracer, and return return value + trace stats.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "target"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "modId": { "type": "integer" },
                    "target": { "description": "Exported symbol name or raw address" },
                    "args": { "type": "array", "items": { "type": "integer" } },
                    "level": { "type": "string", "enum": ["fast", "reg_delta", "full"], "default": "reg_delta" },
                    "capacity": { "type": "integer", "default": 65536 }
                }
            }
        },
        {
            "name": "emu_hook_capture",
            "description": "Temporarily attach onEnter/onLeave hook at hookAddr, call callTarget, and return all captured arguments and return values.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId", "hookAddr", "callTarget"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "hookAddr": { "description": "Guest address to hook (int or '0x...')" },
                    "modId": { "type": "integer" },
                    "callTarget": { "description": "Exported symbol name or address to invoke" },
                    "args": { "type": "array", "items": { "type": "integer" } },
                    "argCount": { "type": "integer", "default": 4 }
                }
            }
        },
        {
            "name": "emu_diag_missing",
            "description": "Control or query missing-environment diagnostics (missing files, properties, syscalls, JNI) and generate JS patch template.",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" },
                    "action": { "type": "string", "enum": ["enable", "disable", "clear", "report"], "default": "report" }
                }
            }
        },
        {
            "name": "emu_last_crash",
            "description": "Retrieve the last Guest ARM64 crash report (PC, module+offset, bad64 disassembly, registers, FP backtrace, recent breadcrumbs).",
            "inputSchema": {
                "type": "object",
                "required": ["emuId"],
                "properties": {
                    "emuId": { "type": "integer" }
                }
            }
        }
    ])
}

/// Streamable HTTP MCP 服务端句柄（基于 `tokio` + `axum`，`POST /mcp`）
#[cfg(feature = "rpc")]
pub struct McpHttpHandle {
    local_addr: std::net::SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    worker_tx: async_channel::Sender<(String, tokio::sync::oneshot::Sender<Option<String>>)>,
    server_thread: Option<std::thread::JoinHandle<()>>,
    worker_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "rpc")]
impl McpHttpHandle {
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    pub fn wait(mut self) {
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
        self.worker_tx.close();
        if let Some(h) = self.worker_thread.take() {
            let _ = h.join();
        }
    }

    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.server_thread.take() {
            let _ = h.join();
        }
        self.worker_tx.close();
        if let Some(h) = self.worker_thread.take() {
            let _ = h.join();
        }
    }
}

#[cfg(feature = "rpc")]
impl Drop for McpHttpHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// 启动 Streamable HTTP MCP 服务端（`POST /mcp` JSON-RPC 2.0，支持多远程 Agent 并发接入）
#[cfg(feature = "rpc")]
pub fn start_mcp_http_server(
    listen_addr: &str,
    base_dir: &Path,
    init_script: Option<&Path>,
) -> Result<McpHttpHandle> {
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{header, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::Router;
    use std::sync::Arc;

    let (worker_tx, worker_rx) =
        async_channel::bounded::<(String, tokio::sync::oneshot::Sender<Option<String>>)>(256);
    let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);
    let base_owned = base_dir.to_path_buf();
    let script_owned = init_script.map(Path::to_path_buf);

    let worker_thread = std::thread::Builder::new()
        .name("runidbg-mcp-worker".to_string())
        .spawn(move || {
            let mut server = match McpServer::new(&base_owned, script_owned.as_deref()) {
                Ok(s) => {
                    let _ = init_tx.send(Ok(()));
                    s
                }
                Err(err) => {
                    let _ = init_tx.send(Err(err));
                    return;
                }
            };
            while let Ok((line, reply)) = worker_rx.recv_blocking() {
                let resp = server.handle_message(&line);
                let _ = reply.send(resp);
            }
        })?;

    init_rx
        .recv()
        .map_err(|_| anyhow!("MCP Worker 初始化异常退出"))??;

    let listen_owned = listen_addr.to_string();
    let tx_state = Arc::new(worker_tx.clone());
    let (bound_tx, bound_rx) = std::sync::mpsc::sync_channel::<Result<std::net::SocketAddr>>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_thread = std::thread::Builder::new()
        .name("runidbg-mcp-http".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = bound_tx.send(Err(anyhow!("创建 Tokio 运行时失败: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(&listen_owned).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = bound_tx.send(Err(anyhow!("绑定 MCP HTTP 地址失败: {e}")));
                        return;
                    }
                };
                let local_addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = bound_tx.send(Err(anyhow!("获取本地地址失败: {e}")));
                        return;
                    }
                };
                let _ = bound_tx.send(Ok(local_addr));

                type McpTaskSender = async_channel::Sender<(
                    String,
                    tokio::sync::oneshot::Sender<Option<String>>,
                )>;

                async fn handle_mcp_post(
                    State(tx): State<Arc<McpTaskSender>>,
                    body: Bytes,
                ) -> Response {
                    let line = String::from_utf8_lossy(&body).into_owned();
                    let (rtx, rrx) = tokio::sync::oneshot::channel();
                    if tx.send((line, rtx)).await.is_err() {
                        return (StatusCode::SERVICE_UNAVAILABLE, "MCP worker closed")
                            .into_response();
                    }
                    match rrx.await {
                        Ok(Some(json_str)) => {
                            let mut resp = (StatusCode::OK, json_str).into_response();
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            );
                            resp
                        }
                        Ok(None) => StatusCode::ACCEPTED.into_response(),
                        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "MCP worker dropped")
                            .into_response(),
                    }
                }

                let app = Router::new()
                    .route("/mcp", post(handle_mcp_post))
                    .with_state(tx_state);
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
        })?;

    let local_addr = bound_rx
        .recv()
        .map_err(|_| anyhow!("MCP HTTP 线程启动失败"))??;

    Ok(McpHttpHandle {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        worker_tx,
        server_thread: Some(server_thread),
        worker_thread: Some(worker_thread),
    })
}
