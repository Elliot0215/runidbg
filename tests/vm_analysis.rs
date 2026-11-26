//! 定制字节码虚拟机（VM）专项辅助集成测试：
//! 构造真实可执行的 ARM64 字节码解释器（含跳转表 + `BR X16` 调度循环、变长 4B/8B 指令、
//! 位域编码指令字 `op=[6,6], f=[12,17,22,27]`、以及运行中会发生基址搬家的虚拟寄存器堆 `[X25 + n*8]`），
//! 端到端验证：
//! 1. 纯 Rust 离线 `TraceReader::analyze_vm`（零提示自动发现调度循环、跳转表、字节码 PC 寄存器、Handler 步长直方图、符号差分与基址搬家）
//! 2. QuickJS 在线 `emu.vm.decodeWord` / `emu.vm.watchRegfile` 与离线 `Trace.open().vmAnalyze`
//! 3. MCP 工具 `trace_vm_analyze`

use runidbg_arm64_emu_tracer::tracer::{
    BinaryTracer, TraceLevel, TraceReader, VmAnalysisOptions, VmRegfileConfig, VmWordLayout,
};
use runidbg_arm64_emu_tracer::{AndroidEmulator, CpuBackend};
use unicorn_engine::unicorn_const::Prot;

/// 编码一条 32-bit 自定义 VM 字节码指令字：
/// bits[11:6] = op (6b), bits[16:12] = f0 (5b), bits[21:17] = f1 (5b), bits[26:22] = f2 (5b), bits[31:27] = f3 (5b)
const fn encode_vm_word(op: u32, f0: u32, f1: u32, f2: u32, f3: u32) -> u32 {
    ((op & 0x3F) << 6)
        | ((f0 & 0x1F) << 12)
        | ((f1 & 0x1F) << 17)
        | ((f2 & 0x1F) << 22)
        | ((f3 & 0x1F) << 27)
}

/// 编码 ARM64 `B #imm`（PC 相对字节偏移）
fn encode_b(from_pc: u64, to_pc: u64) -> u32 {
    let diff = (to_pc as i64) - (from_pc as i64);
    assert!(diff % 4 == 0);
    let imm26 = ((diff / 4) as u32) & 0x03FF_FFFF;
    0x1400_0000 | imm26
}

fn write_insns(emu: &mut AndroidEmulator, base: u64, insns: &[u32]) {
    let mut bytes = Vec::with_capacity(insns.len() * 4);
    for &w in insns {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    emu.cpu_mut().mem_write(base, &bytes).unwrap();
}

/// 在模拟器中布置一个完整可执行的 ARM64 字节码 VM 解释器：
/// - `X23` = 字节码指针（bc_pc）
/// - `X24` = 跳转表基址（8B 绝对地址表，4 个 Handler）
/// - `X25` = 虚拟寄存器堆基址（`R[0..31]`，每槽 8 字节）
/// - `X26` = 备用虚拟寄存器堆基址（用于 Handler 2 触发寄存器堆搬家！）
/// - Handler 0 (`op=0`, 消费 8 字节)：`MOVI R[f0], <u32_inline_imm>`（消费 4B 指令字 + 4B 内联立即数 = 8B）
/// - Handler 1 (`op=1`, 消费 4 字节)：`ADD R[f0], R[f1], R[f2]`
/// - Handler 2 (`op=2`, 消费 4 字节)：`RELOC`（把 `X25` 搬家到 `X26`，并写入 `R[f0] = f1`）
/// - Handler 3 (`op=3`, 消费 4 字节)：`HALT`（返回 `R[f0]`）
struct MiniVmFixture {
    code_base: u64,
    dispatcher_pc: u64,
    handler_pcs: [u64; 4],
    jtbl_addr: u64,
    bc_addr: u64,
    rf1_addr: u64,
    rf2_addr: u64,
}

fn setup_mini_vm(emu: &mut AndroidEmulator) -> MiniVmFixture {
    let code_base: u64 = 0x4700_0000;
    let data_base: u64 = 0x4710_0000;
    emu.cpu_mut().mem_map(code_base, 0x4000, Prot::ALL).unwrap();
    emu.cpu_mut()
        .mem_map(data_base, 0x4000, Prot::READ | Prot::WRITE)
        .unwrap();

    let jtbl_addr = data_base;
    let bc_addr = data_base + 0x100;
    let rf1_addr = data_base + 0x200;
    let rf2_addr = data_base + 0x400;

    // 入口序言在 code_base + 0x000:
    //   x0=bc_addr, x1=jtbl_addr, x2=rf1_addr, x3=rf2_addr
    // 调度循环在 code_base + 0x020:
    //   ldr w8, [x23]                // 读取 32-bit 字节码指令字
    //   ubfx x9, x8, #6, #6          // 提取 6-bit opcode (bits[11:6])
    //   ldr x16, [x24, x9, lsl #3]   // 查 8B 跳转表
    //   br x16                       // <- dispatcher_pc (code_base + 0x02C)
    let disp_loop_pc = code_base + 0x020;
    let dispatcher_pc = disp_loop_pc + 12;

    let h0_pc = code_base + 0x100; // MOVI (8B)
    let h1_pc = code_base + 0x200; // ADD  (4B)
    let h2_pc = code_base + 0x300; // RELOC (4B)
    let h3_pc = code_base + 0x400; // HALT (4B)

    // 序言：保存参数到 x23..x26 后跳到 disp_loop_pc
    let entry_insns = [
        0xAA00_03F7, // mov x23, x0
        0xAA01_03F8, // mov x24, x1
        0xAA02_03F9, // mov x25, x2
        0xAA03_03FA, // mov x26, x3
        encode_b(code_base + 16, disp_loop_pc),
    ];
    write_insns(emu, code_base, &entry_insns);

    // 调度循环
    let disp_insns = [
        0xB940_02E8, // ldr w8, [x23]
        0xD346_2D09, // ubfx x9, x8, #6, #6
        0xF869_7B10, // ldr x16, [x24, x9, lsl #3]
        0xD61F_0200, // br x16
    ];
    write_insns(emu, disp_loop_pc, &disp_insns);

    // Handler 0: MOVI R[f0], <inline u32 at [x23+4]>; x23 += 8; b disp_loop_pc
    let h0_insns = [
        0xD34C_410A, // ubfx x10, x8, #12, #5  (f0)
        0xB940_06EB, // ldr w11, [x23, #4]     (inline 32-bit immediate)
        0xF82A_7B2B, // str x11, [x25, x10, lsl #3]
        0x9100_22F7, // add x23, x23, #8
        encode_b(h0_pc + 16, disp_loop_pc),
    ];
    write_insns(emu, h0_pc, &h0_insns);

    // Handler 1: ADD R[f0], R[f1], R[f2]; x23 += 4; b disp_loop_pc
    let h1_insns = [
        0xD34C_410A, // ubfx x10, x8, #12, #5 (f0)
        0xD351_550B, // ubfx x11, x8, #17, #5 (f1)
        0xD356_690C, // ubfx x12, x8, #22, #5 (f2)
        0xF86B_7B2D, // ldr x13, [x25, x11, lsl #3]
        0xF86C_7B2E, // ldr x14, [x25, x12, lsl #3]
        0x8B0E_01AD, // add x13, x13, x14
        0xF82A_7B2D, // str x13, [x25, x10, lsl #3]
        0x9100_12F7, // add x23, x23, #4
        encode_b(h1_pc + 32, disp_loop_pc),
    ];
    write_insns(emu, h1_pc, &h1_insns);

    // Handler 2: RELOC — x25 = x26（寄存器堆搬家！），写入 R[f0] = f1; x23 += 4; b disp_loop_pc
    let h2_insns = [
        0xAA1A_03F9, // mov x25, x26
        0xD34C_410A, // ubfx x10, x8, #12, #5 (f0)
        0xD351_550B, // ubfx x11, x8, #17, #5 (f1)
        0xF82A_7B2B, // str x11, [x25, x10, lsl #3]
        0x9100_12F7, // add x23, x23, #4
        encode_b(h2_pc + 20, disp_loop_pc),
    ];
    write_insns(emu, h2_pc, &h2_insns);

    // Handler 3: HALT — x0 = R[f0]; x23 += 4; ret
    let h3_insns = [
        0xD34C_410A, // ubfx x10, x8, #12, #5 (f0)
        0xF86A_7B20, // ldr x0, [x25, x10, lsl #3]
        0x9100_12F7, // add x23, x23, #4
        0xD65F_03C0, // ret
    ];
    write_insns(emu, h3_pc, &h3_insns);

    // 写入 8B 跳转表
    let mut jtbl_bytes = Vec::with_capacity(32);
    for &hp in &[h0_pc, h1_pc, h2_pc, h3_pc] {
        jtbl_bytes.extend_from_slice(&hp.to_le_bytes());
    }
    emu.cpu_mut().mem_write(jtbl_addr, &jtbl_bytes).unwrap();

    // 写入字节码程序（共 10 条 VM 指令，特意 > 8 步以回归验证 4B 取指流绝不会被误判为 4B 跳转表！）：
    //   step 0: MOVI  R[1], 0x100   (op=0, len=8B)
    //   step 1: MOVI  R[2], 0x023   (op=0, len=8B)
    //   step 2: ADD   R[3], R[1], R[2] -> 0x123 (op=1, len=4B)
    //   step 3: ADD   R[3], R[3], R[2] -> 0x146 (op=1, len=4B)
    //   step 4: MOVI  R[5], 7       (op=0, len=8B — 旧帧 rf1 写 R[5]=7，测试搬家后同名写绝不被吞！)
    //   step 5: ADD   R[4], R[1], R[3] -> 0x246 (op=1, len=4B)
    //   step 6: ADD   R[4], R[4], R[2] -> 0x269 (op=1, len=4B)
    //   step 7: RELOC (X25 -> rf2_addr), 新帧 R[5] = 7 (op=2, f=[5,7,0,0], len=4B)
    //   step 8: MOVI  R[5], 8       (op=0, len=8B — 新帧 rf2 把 R[5] 从 7 改为 8，验证上步新帧镜像未被清空！)
    //   step 9: HALT  ret R[5] -> 8 (op=3, f=[5,0,0,0], len=4B)
    let bc_words: [u32; 14] = [
        encode_vm_word(0, 1, 0, 0, 0),
        0x0000_0100, // inline imm for step 0
        encode_vm_word(0, 2, 0, 0, 0),
        0x0000_0023, // inline imm for step 1
        encode_vm_word(1, 3, 1, 2, 0),
        encode_vm_word(1, 3, 3, 2, 0),
        encode_vm_word(0, 5, 0, 0, 0),
        0x0000_0007, // inline imm for step 4 (old frame R[5]=7)
        encode_vm_word(1, 4, 1, 3, 0),
        encode_vm_word(1, 4, 4, 2, 0),
        encode_vm_word(2, 5, 7, 0, 0), // step 7: RELOC + new frame R[5]=7
        encode_vm_word(0, 5, 0, 0, 0),
        0x0000_0008, // inline imm for step 8 (new frame R[5]: 7 -> 8)
        encode_vm_word(3, 5, 0, 0, 0), // step 9: HALT ret R[5]=8
    ];
    write_insns(emu, bc_addr, &bc_words);

    MiniVmFixture {
        code_base,
        dispatcher_pc,
        handler_pcs: [h0_pc, h1_pc, h2_pc, h3_pc],
        jtbl_addr,
        bc_addr,
        rf1_addr,
        rf2_addr,
    }
}

#[test]
fn test_offline_vm_auto_detection_opmap_step_length_and_regfile_relocation() {
    let tmp = std::env::temp_dir().join(format!("runidbg_vm_offline_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let idx_path = tmp.join("vm.idx");
    let ext_path = tmp.join("vm.ext");

    let mut emu = AndroidEmulator::builder().hle_accel(true).build().expect("emu");
    let fx = setup_mini_vm(&mut emu);

    let tracer = BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 16384, TraceLevel::Full)
        .expect("tracer");
    emu.set_tracer(tracer).unwrap();
    emu.attach_tracer(fx.code_base, fx.code_base + 0x1000).unwrap();
    let ret = emu
        .call_address(fx.code_base, &[fx.bc_addr, fx.jtbl_addr, fx.rf1_addr, fx.rf2_addr])
        .expect("run mini vm");
    assert_eq!(ret, 8, "VM HALT should return relocated R[5]=8");
    emu.tracer().flush().unwrap();

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();

    // 1. 零提示自动识别：10 步 > 8 步，必须仍精准锁定 8B 跳转表 jtbl_addr（绝不被 4B 字节码取指误覆盖）
    let auto_report = reader.analyze_vm(&VmAnalysisOptions::default());
    assert_eq!(
        auto_report.selected_dispatcher,
        Some(fx.dispatcher_pc),
        "must auto-detect BR X16 dispatcher PC"
    );
    assert_eq!(auto_report.detected_bc_reg.as_deref(), Some("X23"));
    assert_eq!(auto_report.total_vm_steps, 10);
    assert_eq!(auto_report.handlers.len(), 4);
    let top_disp = &auto_report.dispatchers[0];
    assert_eq!(
        top_disp.jump_table_base,
        Some(fx.jtbl_addr),
        "must NOT misidentify 4B bytecode fetch stream as jump table"
    );
    assert_eq!(top_disp.jump_table_entry_size, Some(8));

    // 校验 Handler 0 (MOVI) 消费 8 字节，Handler 1 (ADD) 消费 4 字节！
    let h0 = auto_report
        .handlers
        .iter()
        .find(|h| h.handler_pc == fx.handler_pcs[0])
        .expect("h0 stat");
    assert_eq!(h0.hit_count, 4);
    assert_eq!(h0.bc_step_hist.get(&8), Some(&4), "MOVI consumes 8B");
    let h1 = auto_report
        .handlers
        .iter()
        .find(|h| h.handler_pc == fx.handler_pcs[1])
        .expect("h1 stat");
    assert_eq!(h1.hit_count, 4);
    assert_eq!(h1.bc_step_hist.get(&4), Some(&4), "ADD consumes 4B");

    // 2. 开启指令字位域解码器 + 虚拟寄存器堆基址搬家追踪
    let layout = VmWordLayout::parse_spec("6:6,12,17,22,27").expect("parse layout");
    let full_report = reader.analyze_vm(&VmAnalysisOptions {
        layout: Some(layout),
        regfile: Some(VmRegfileConfig {
            base_reg: 25,
            count: 32,
            size: 8,
        }),
        ..Default::default()
    });

    // step 2: ADD R[3], R[1], R[2] -> 0x100 + 0x23 = 0x123
    let st2 = &full_report.steps[2];
    assert_eq!(
        st2.decoded.as_ref().map(|d| d.format_compact()).as_deref(),
        Some("op=1 f=[3,1,2,0]")
    );
    assert!(
        st2.reg_diffs
            .iter()
            .any(|d| d.reg_index == 3 && d.new_val == 0x123),
        "step 2 must show R[3] -> 0x123: {:?}",
        st2.reg_diffs
    );
    // step 3: ADD R[3], R[3], R[2] -> 0x123 -> 0x146
    let st3 = &full_report.steps[3];
    assert!(
        st3.reg_diffs
            .iter()
            .any(|d| d.reg_index == 3 && d.old_val == Some(0x123) && d.new_val == 0x146),
        "step 3 must show R[3]: 0x123 -> 0x146: {:?}",
        st3.reg_diffs
    );
    // step 7 (RELOC): 旧帧 rf1 写过 R[5]=7，搬家到 rf2 后立即写 R[5]=7 绝不能被吞掉，且 old_val 必须是 None（隔离旧帧）！
    let st7 = &full_report.steps[7];
    assert!(st7.base_relocated && st7.regfile_base == Some(fx.rf2_addr));
    assert!(
        st7.reg_diffs
            .iter()
            .any(|d| d.reg_index == 5 && d.old_val.is_none() && d.new_val == 7),
        "RELOC step must report fresh new-frame R[5]: ?->0x7 without cross-frame contamination: {:?}",
        st7.reg_diffs
    );
    // step 8 (MOVI R[5], 8): 必须承接上一步新帧的 0x7 -> 0x8，绝不能在 dispatch 处被误清空！
    let st8 = &full_report.steps[8];
    assert!(
        st8.reg_diffs
            .iter()
            .any(|d| d.reg_index == 5 && d.old_val == Some(7) && d.new_val == 8),
        "step 8 must preserve new-frame shadow R[5]: 0x7->0x8: {:?}",
        st8.reg_diffs
    );

    let summary = full_report.format_summary(fx.code_base);
    assert!(summary.contains("Handler 分布图"));
    assert!(summary.contains("op=1 f=[3,1,2,0]"));
    assert!(summary.contains("REGFILE->"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[cfg(all(feature = "js", feature = "mcp"))]
#[test]
fn test_js_online_vm_watch_regfile_and_offline_vm_analyze_and_mcp() {
    use runidbg_arm64_emu_tracer::script::mcp::McpServer;
    use runidbg_arm64_emu_tracer::script::JsSession;
    use serde_json::json;
    use std::path::PathBuf;

    let tmp = std::env::temp_dir().join(format!("runidbg_vm_js_mcp_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let idx_path = tmp.join("vm_js.idx");
    let ext_path = tmp.join("vm_js.ext");

    // 先生成一份离线 Trace 供 JS Trace.open().vmAnalyze 与 MCP trace_vm_analyze 共同验证
    let mut emu = AndroidEmulator::builder().hle_accel(true).build().expect("emu");
    let fx = setup_mini_vm(&mut emu);
    let tracer = BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 16384, TraceLevel::Full)
        .expect("tracer");
    emu.set_tracer(tracer).unwrap();
    emu.attach_tracer(fx.code_base, fx.code_base + 0x1000).unwrap();
    let _ = emu
        .call_address(fx.code_base, &[fx.bc_addr, fx.jtbl_addr, fx.rf1_addr, fx.rf2_addr])
        .unwrap();
    emu.tracer().flush().unwrap();

    // 1. 测试 JS 在线 emu.vm.decodeWord + emu.vm.watchRegfile + 离线 Trace.open().vmAnalyze
    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples/libstatic-webp.so");
    let so_str = so_path.to_string_lossy().into_owned();
    let idx_str = idx_path.to_string_lossy().into_owned();
    let session = JsSession::new(&[], &tmp, true).expect("session");
    let script = format!(
        r#"(() => {{
            const emu = Emu.create({{ freezeLayout: true }});
            const mod = emu.load({so_str:?});
            const fnAddr = mod.symbol("WebPGetDecoderVersion");

            // 1) 测试 vm.decodeWord: op=49, f=[1,5,0,7]
            const w = ((49 << 6) | (1 << 12) | (5 << 17) | (0 << 22) | (7 << 27)) >>> 0;
            const dec = emu.vm.decodeWord(w, {{ op: [6, 6], fields: [12, 17, 22, 27] }});

            // 2) 在线构造小型循环测试 emu.vm.watchRegfile（含基址搬家与 R[3] 差分）
            const rf1 = emu.mem.alloc(256);
            const rf2 = emu.mem.alloc(256);
            const bc = emu.mem.alloc(64);
            emu.mem.writeU32(bc, w);
            emu.mem.writeU32(bc + 4, ((12 << 6) | (3 << 12)) >>> 0);
            emu.mem.writeU32(bc + 12, ((7 << 6) | (2 << 12)) >>> 0);
            emu.mem.writeU64(rf1 + 3 * 8, 0x10n);

            // 构造 3 次经过调度点 (fnAddr+16) 的短指令序列：
            //   x25=x0(rf1), x23=x1(bc), x26=x2(rf2), w20=0
            // loop (fnAddr+16):
            //   nop (hook 点!)
            //   cmp w20, #0; b.ne check1
            //   mov x9, #0x42; str x9, [x25, #24] (R[3]=0x42); add x23, x23, #4; add w20, w20, #1; b loop
            // check1:
            //   cmp w20, #1; b.ne done
            //   mov x25, x26 (基址搬家!); add x23, x23, #8; add w20, w20, #1; b loop
            // done: ret
            const insns = new Uint32Array([
                0xAA0003F9, // 0:  mov x25, x0 (rf1)
                0xAA0103F7, // 4:  mov x23, x1 (bc)
                0xAA0203FA, // 8:  mov x26, x2 (rf2)
                0x52800014, // 12: mov w20, #0
                0xD503201F, // 16: nop  <-- dispatcherPc = fnAddr + 16
                0x7100029F, // 20: cmp w20, #0
                0x540000C1, // 24: b.ne +24 (-> 48)
                0xD2800849, // 28: mov x9, #0x42
                0xF9000F29, // 32: str x9, [x25, #24] (R[3] = 0x42)
                0x910012F7, // 36: add x23, x23, #4
                0x11000694, // 40: add w20, w20, #1
                0x17FFFFF9, // 44: b -28 (-> 16)
                0x7100069F, // 48: cmp w20, #1
                0x540000A1, // 52: b.ne +20 (-> 72)
                0xAA1A03F9, // 56: mov x25, x26 (relocate!)
                0x910022F7, // 60: add x23, x23, #8
                0x11000694, // 64: add w20, w20, #1
                0x17FFFFF3, // 68: b -52 (-> 16)
                0xD65F03C0, // 72: ret
            ]);
            emu.mem.patch(fnAddr, new Uint8Array(insns.buffer));

            const watcher = emu.vm.watchRegfile({{
                baseReg: "x25",
                count: 8,
                size: 8,
                dispatcherPc: fnAddr + 16,
                bcReg: "x23",
                layout: {{ op: [6, 6], fields: [12, 17, 22, 27] }},
            }});
            emu.call(fnAddr, rf1, bc, rf2);
            watcher.detach();
            const evs = watcher.events();

            // 3) 离线 Trace.open().vmAnalyze + 各类负向边界回归校验
            const tr = Trace.open({idx_str:?});
            const vmRep = tr.vmAnalyze({{
                baseReg: "x25",
                layout: {{ op: [6, 6], fields: [12, 17, 22, 27] }},
            }});

            // 回归 1: layout.op [262, 6] 绝不能经 `as u8` 回绕绕过越界校验
            let wrapLayoutThrew = false;
            try {{ tr.vmAnalyze({{ layout: {{ op: [262, 6] }} }}); }} catch (e) {{ wrapLayoutThrew = true; }}

            // 回归 2: 未传 baseReg 时非法 regSize=99 / bcDeref:true 无 bcReg / bcReg+bcPtrAddr 互斥必须抛错
            let badRegSizeThrew = false;
            try {{ tr.vmAnalyze({{ regSize: 99 }}); }} catch (e) {{ badRegSizeThrew = true; }}
            let badBcDerefThrew = false;
            try {{ tr.vmAnalyze({{ bcDeref: true }}); }} catch (e) {{ badBcDerefThrew = true; }}
            let badBcMutexThrew = false;
            try {{ tr.vmAnalyze({{ bcReg: "x23", bcPtrAddr: bc }}); }} catch (e) {{ badBcMutexThrew = true; }}

            // 回归 3: decodeWord 64-bit 无损 BigInt 与非法参数校验
            const dec64 = emu.vm.decodeWord(0xFFFFFFFFFFFFFFFFn, {{ op: [0, 64] }});
            let badWordSizeThrew = false;
            try {{ emu.vm.watchRegfile({{ baseReg: "x25", dispatcherPc: fnAddr + 16, wordSize: 3 }}); }} catch (e) {{ badWordSizeThrew = true; }}
            let badRangeThrew = false;
            try {{ emu.vm.watchRegfile({{ baseReg: "x25", dispatcherPc: [fnAddr + 32, fnAddr + 16] }}); }} catch (e) {{ badRangeThrew = true; }}

            // 回归 4: maxSteps=1 不得在后续步骤覆写 events[0].bcStep（应保持 +4B 而非被 step1 的 +8B 覆盖）
            const wCap = emu.vm.watchRegfile({{
                baseReg: "x25",
                count: 8,
                size: 8,
                dispatcherPc: fnAddr + 16,
                bcReg: "x23",
                maxSteps: 1,
                layout: {{ op: [6, 6], fields: [12, 17, 22, 27] }},
            }});
            emu.call(fnAddr, rf1, bc, rf2);
            wCap.detach();
            const capEv0Step = wCap.events()[0].bcStep;

            // 回归 5: rawBytes 读取失败（未映射基址 0x1000）不得把全 undefined 塞进 prevVals 导致下一步崩溃
            const wUnmapped = emu.vm.watchRegfile({{
                baseReg: "x25",
                count: 8,
                size: 8,
                dispatcherPc: fnAddr + 16,
                bcReg: "x23",
            }});
            // 传入未映射 rf1=0x1000（注意仅测试前 2 步未写内存会安全跳过或触发 relocation，这里用不写内存的短循环测未映射->已映射切换）
            const safeLoopAddr = fnAddr + 0x100;
            // mov x25, x0; mov w20, #0; loop: nop; cmp w20, #0; b.ne end; mov x25, x1; add w20, w20, #1; b loop; end: ret
            const safeInsns = new Uint32Array([
                0xAA0003F9, // 0: mov x25, x0 (unmapped 0x1000)
                0x52800014, // 4: mov w20, #0
                0xD503201F, // 8: nop <-- hook
                0x7100029F, // 12: cmp w20, #0
                0x540000A1, // 16: b.ne +20 (-> 36)
                0xAA0103F9, // 20: mov x25, x1 (mapped rf2)
                0x11000694, // 24: add w20, w20, #1
                0x17FFFFFB, // 28: b -20 (-> 8)
                0xD503201F, // 32: nop
                0xD65F03C0, // 36: ret
            ]);
            emu.mem.patch(safeLoopAddr, new Uint8Array(safeInsns.buffer));
            wUnmapped.detach();
            const wUnmapped2 = emu.vm.watchRegfile({{
                baseReg: "x25",
                count: 4,
                size: 8,
                dispatcherPc: safeLoopAddr + 8,
            }});
            emu.call(safeLoopAddr, 0x1000, rf2);
            wUnmapped2.detach();
            const unmappedSurvived = wUnmapped2.events().length === 2;

            tr.close();

            return {{
                decText: dec.text,
                dec64Hex: dec64.opHex,
                watchSteps: evs.length,
                step0Op: evs[0].op,
                step0BcStep: evs[0].bcStep,
                step1Diffs: evs[1].diffs.map(d => d.name + ":" + d.oldHex + "->" + d.newHex),
                step1BcStep: evs[1].bcStep,
                step2Relocated: evs[2].baseRelocated,
                offlineSteps: vmRep.totalVmSteps,
                offlineHandlers: vmRep.handlers.length,
                offlineBcReg: vmRep.detectedBcReg,
                offlineStep2Dec: vmRep.steps[2].decodedText,
                wrapLayoutThrew,
                badRegSizeThrew,
                badBcDerefThrew,
                badBcMutexThrew,
                badWordSizeThrew,
                badRangeThrew,
                capEv0Step,
                unmappedSurvived,
            }};
        }})()"#
    );
    let out = session.eval_json_string(&script).expect("vm js script");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["decText"], "op=49 f=[1,5,0,7]");
    assert_eq!(v["dec64Hex"], "0xffffffffffffffff");
    assert_eq!(v["watchSteps"], 3);
    assert_eq!(v["step0Op"], 49);
    assert_eq!(v["step0BcStep"], 4);
    assert_eq!(v["step1Diffs"], json!(["R[3]:0x10->0x42"]));
    assert_eq!(v["step1BcStep"], 8);
    assert_eq!(v["step2Relocated"], true);
    assert_eq!(v["offlineSteps"], 10);
    assert_eq!(v["offlineHandlers"], 4);
    assert_eq!(v["offlineBcReg"], "X23");
    assert_eq!(v["offlineStep2Dec"], "op=1 f=[3,1,2,0]");
    assert_eq!(v["wrapLayoutThrew"], true);
    assert_eq!(v["badRegSizeThrew"], true);
    assert_eq!(v["badBcDerefThrew"], true);
    assert_eq!(v["badBcMutexThrew"], true);
    assert_eq!(v["badWordSizeThrew"], true);
    assert_eq!(v["badRangeThrew"], true);
    assert_eq!(v["capEv0Step"], 4);
    assert_eq!(v["unmappedSurvived"], true);

    // 2. 测试 MCP 工具 trace_vm_analyze（正常路径 + 负向校验）
    let mut server = McpServer::new(&tmp, None).expect("mcp server");
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "trace_vm_analyze",
            "arguments": {
                "idxPath": idx_path.to_string_lossy(),
                "baseReg": "x25",
                "layout": "6:6,12,17,22,27"
            }
        }
    });
    let resp_str = server.handle_message(&req.to_string()).expect("mcp response");
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["totalVmSteps"], 10);
    assert_eq!(payload["detectedBcReg"], "X23");
    assert_eq!(payload["handlers"].as_array().unwrap().len(), 4);
    assert_eq!(payload["steps"][2]["decodedText"], "op=1 f=[3,1,2,0]");

    let bad_mcp = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "trace_vm_analyze",
            "arguments": {
                "idxPath": idx_path.to_string_lossy(),
                "bcDeref": true
            }
        }
    });
    let bad_resp_str = server.handle_message(&bad_mcp.to_string()).expect("bad mcp response");
    let bad_resp: serde_json::Value = serde_json::from_str(&bad_resp_str).unwrap();
    assert_eq!(bad_resp["result"]["isError"], true);

    let _ = std::fs::remove_dir_all(&tmp);
}
