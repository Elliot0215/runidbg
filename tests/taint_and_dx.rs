use std::path::PathBuf;

use runidbg_arm64_emu_tracer::backend::CpuBackend;
use runidbg_arm64_emu_tracer::cpu::RET_MAGIC_ADDR;
use runidbg_arm64_emu_tracer::loader::trampoline::HleBuiltin;
use runidbg_arm64_emu_tracer::tracer::{
    BinaryTracer, TaintOptions, TaintSeed, TraceLevel, TraceReader,
};
use runidbg_arm64_emu_tracer::AndroidEmulator;
use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::RegisterARM64;

fn temp_trace_paths(tag: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "runidbg_dx_test_{}_{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    (dir.join("trace.idx"), dir.join("trace.ext"))
}

fn emit_mov_imm64(out: &mut Vec<u32>, rd: u32, val: u64) {
    out.push(0xD280_0000 | (((val & 0xFFFF) as u32) << 5) | rd); // movz xd, imm16
    if (val >> 16) & 0xFFFF != 0 {
        out.push(0xF2A0_0000 | ((((val >> 16) & 0xFFFF) as u32) << 5) | rd); // movk xd, imm16, lsl #16
    }
    if (val >> 32) & 0xFFFF != 0 {
        out.push(0xF2C0_0000 | ((((val >> 32) & 0xFFFF) as u32) << 5) | rd); // movk xd, imm16, lsl #32
    }
    if (val >> 48) & 0xFFFF != 0 {
        out.push(0xF2E0_0000 | ((((val >> 48) & 0xFFFF) as u32) << 5) | rd); // movk xd, imm16, lsl #48
    }
}

fn emit_blr_target(out: &mut Vec<u32>, target: u64) {
    emit_mov_imm64(out, 16, target);
    out.push(0xD63F_0200); // blr x16
}

fn write_insns(emu: &mut AndroidEmulator, base: u64, insns: &[u32]) {
    let mut bytes = Vec::with_capacity(insns.len() * 4);
    for &w in insns {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    emu.cpu_mut().mem_write(base, &bytes).expect("write insns");
}

#[test]
fn test_hle_trace_recording_and_omniscient_query() {
    let (idx_path, ext_path) = temp_trace_paths("hle_query");
    let mut emu = AndroidEmulator::builder().hle_accel(true).build().expect("emu");

    // 分配代码页与数据页
    let code_base: u64 = 0x4100_0000;
    let data_base: u64 = 0x4110_0000;
    emu.cpu_mut()
        .mem_map(code_base, 0x4000, Prot::ALL)
        .expect("map code");
    emu.cpu_mut()
        .mem_map(data_base, 0x4000, Prot::READ | Prot::WRITE)
        .expect("map data");

    // 注册内置 HLE 跳板地址（malloc / memcpy / memset / free）
    let malloc_slot = emu
        .register_hle_builtin("malloc", HleBuiltin::Malloc)
        .expect("malloc HLE");
    let memcpy_slot = emu
        .register_hle_builtin("memcpy", HleBuiltin::Memcpy)
        .expect("memcpy HLE");
    let memset_slot = emu
        .register_hle_builtin("memset", HleBuiltin::Memset)
        .expect("memset HLE");
    let free_slot = emu
        .register_hle_builtin("free", HleBuiltin::Free)
        .expect("free HLE");

    let mut insns: Vec<u32> = vec![
        0xAA1E_03FB, // mov x27, x30  (保存返回地址 LR)
        0xAA00_03F5, // mov x21, x0   (保存输入值)
        0xAA01_03F6, // mov x22, x1   (保存 data_base)
        0xD280_0800, // mov x0, #64
    ];
    emit_blr_target(&mut insns, malloc_slot);
    insns.push(0xAA00_03F3); // mov x19, x0
    insns.push(0xF900_0275); // str x21, [x19]
    insns.push(0xD280_0800); // mov x0, #64
    emit_blr_target(&mut insns, malloc_slot);
    insns.push(0xAA00_03F4); // mov x20, x0
    insns.push(0xAA14_03E0); // mov x0, x20
    insns.push(0xAA13_03E1); // mov x1, x19
    insns.push(0xD280_0202); // mov x2, #16
    emit_blr_target(&mut insns, memcpy_slot);
    insns.push(0xAA13_03E0); // mov x0, x19
    insns.push(0xD280_1541); // mov x1, #0xaa
    insns.push(0xD280_0202); // mov x2, #16
    emit_blr_target(&mut insns, memset_slot);
    insns.push(0xF900_02D3); // str x19, [x22]
    insns.push(0xF900_06D4); // str x20, [x22, #8]
    insns.push(0xAA13_03E0); // mov x0, x19
    emit_blr_target(&mut insns, free_slot);
    insns.push(0xAA14_03E0); // mov x0, x20
    emit_blr_target(&mut insns, free_slot);
    insns.push(0xAA14_03E0); // mov x0, x20
    insns.push(0xAA1B_03FE); // mov x30, x27  (恢复返回地址 LR)
    insns.push(0xD65F_03C0); // ret
    write_insns(&mut emu, code_base, &insns);

    let tracer = BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 16384, TraceLevel::Full)
        .expect("mmap tracer");
    emu.set_tracer(tracer).expect("set_tracer");
    emu.attach_tracer(code_base, code_base + 0x1000)
        .expect("attach_tracer");

    let magic_val: u64 = 0x1122_3344_dead_beef;
    let ret = emu
        .call_address(code_base, &[magic_val, data_base])
        .expect("call_address");
    emu.tracer().flush().expect("flush");

    let mut ptr_bytes = [0u8; 16];
    emu.cpu().mem_read(data_base, &mut ptr_bytes).unwrap();
    let p1 = u64::from_le_bytes(ptr_bytes[0..8].try_into().unwrap());
    let p2 = u64::from_le_bytes(ptr_bytes[8..16].try_into().unwrap());
    assert_eq!(ret, p2);
    assert_ne!(p1, 0);
    assert_ne!(p2, 0);
    assert_ne!(p1, p2);

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).expect("open trace");
    let hle = reader.hle_events();
    assert!(
        hle.iter().any(|e| e.op == "malloc" && e.dst == p1 && e.len == 64),
        "missing malloc(p1): {hle:?}"
    );
    assert!(
        hle.iter().any(|e| e.op == "memcpy" && e.dst == p2 && e.src == p1 && e.len == 16),
        "missing memcpy(p2, p1, 16): {hle:?}"
    );
    assert!(
        hle.iter().any(|e| e.op == "memset" && e.dst == p1 && e.src == 0xAA && e.len == 16),
        "missing memset(p1, 0xaa, 16): {hle:?}"
    );
    assert!(
        hle.iter().any(|e| e.op == "free" && e.dst == p1),
        "missing free(p1): {hle:?}"
    );

    // 验证 dump 混合输出包含 [HLE memcpy]
    let all_lines: Vec<String> = (0..reader.len())
        .flat_map(|i| reader.mem_and_hle_lines_for(i))
        .collect();
    assert!(
        all_lines.iter().any(|l| l.contains("[HLE memcpy]")),
        "expected [HLE memcpy] in mem_and_hle_lines_for: {all_lines:?}"
    );

    // 验证全知按值查询 (4 字节低位 0xdeadbeef 与 8 字节全值，同时命中原始 STR 与 HLE memcpy 目标 p2！)
    let hits4 = reader.query_writes_by_value(0xdead_beef, 4, None, None, 32);
    assert!(
        hits4.iter().any(|h| h.addr == p1 && h.kind == "write"),
        "expected 0xdeadbeef write to p1: {hits4:?}"
    );
    assert!(
        hits4.iter().any(|h| h.addr == p2),
        "expected 0xdeadbeef propagated to p2 via HLE memcpy: {hits4:?}"
    );
    let hits8 = reader.query_writes_by_value(magic_val, 8, None, None, 32);
    assert!(
        hits8.iter().any(|h| h.addr == p1),
        "expected 64-bit write to p1: {hits8:?}"
    );

    // 验证离线内存重建（跨越 HLE memcpy + memset！）
    let rec_p2 = reader.reconstruct_mem_at(p2, 8, u32::MAX);
    let got_p2: Vec<u8> = rec_p2.into_iter().map(|b| b.expect("known byte")).collect();
    assert_eq!(got_p2, magic_val.to_le_bytes());

    let rec_p1 = reader.reconstruct_mem_at(p1, 8, u32::MAX);
    let got_p1: Vec<u8> = rec_p1.into_iter().map(|b| b.expect("known byte")).collect();
    assert_eq!(got_p1, [0xAAu8; 8]);

    // 验证按地址查询历史同时捕获 STR 和 HLE memcpy/memset
    let hist_p2 = reader.query_addr_history(p2, 8, None, false, 64);
    assert!(
        hist_p2.iter().any(|h| h.kind == "hle_memcpy"),
        "expected hle_memcpy in p2 history: {hist_p2:?}"
    );

    let _ = std::fs::remove_dir_all(idx_path.parent().unwrap());
}

#[test]
fn test_offline_taint_forward_and_backward_with_stack_reuse_and_hle_memcpy() {
    let (idx_path, ext_path) = temp_trace_paths("taint_slicing");
    let mut emu = AndroidEmulator::builder().hle_accel(true).build().expect("emu");

    let code_base: u64 = 0x4200_0000;
    let data_base: u64 = 0x4210_0000;
    emu.cpu_mut()
        .mem_map(code_base, 0x4000, Prot::ALL)
        .expect("map code");
    emu.cpu_mut()
        .mem_map(data_base, 0x4000, Prot::READ | Prot::WRITE)
        .expect("map data");

    let input_buf = data_base;
    let stage_buf = data_base + 0x100;
    let output_buf = data_base + 0x200;
    let unrelated_buf = data_base + 0x300;
    let sbox_table = data_base + 0x400;
    let sbox_out = data_base + 0x500;

    // 写入输入数据与 S-Box 表
    emu.cpu_mut()
        .mem_write(input_buf, &0x0102_0304_0506_0708u64.to_le_bytes())
        .unwrap();
    let mut sbox = [0u8; 256];
    for (i, b) in sbox.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    emu.cpu_mut().mem_write(sbox_table, &sbox).unwrap();

    let memcpy_slot = emu
        .register_hle_builtin("memcpy", HleBuiltin::Memcpy)
        .expect("memcpy HLE");

    let mut insns: Vec<u32> = vec![
        0xAA1E_03FB, // mov x27, x30  (保存返回地址 LR)
        0xAA00_03F3, // mov x19, x0
        0xAA01_03F4, // mov x20, x1
        0xAA02_03F5, // mov x21, x2
        0xAA03_03F6, // mov x22, x3
        0xAA04_03F7, // mov x23, x4
        0xAA05_03F8, // mov x24, x5
        0xF940_0260, // ldr x0, [x19]
        0xD28B_4B4A, // movz x10, #0x5a5a
        0xCA0A_0001, // eor x1, x0, x10
        0x9100_4C22, // add x2, x1, #0x13
        0xF81F_0FE2, // str x2, [sp, #-16]!
        0xF940_03E3, // ldr x3, [sp]
        0xCA0A_0064, // eor x4, x3, x10
        0xF900_0284, // str x4, [x20]
        0xD293_3329, // movz x9, #0x9999
        0xF900_03E9, // str x9, [sp]        ; 同栈槽覆写无关常量！
        0xD282_4688, // movz x8, #0x1234
        0xF900_02C8, // str x8, [x22]       ; 无关地址写入
        0xAA15_03E0, // mov x0, x21
        0xAA14_03E1, // mov x1, x20
        0xD280_0102, // mov x2, #8
    ];
    emit_blr_target(&mut insns, memcpy_slot);
    insns.extend_from_slice(&[
        0xF940_0260, // ldr x0, [x19]       ; 再读输入低字节做 S-Box 索引
        0x9240_1C05, // and x5, x0, #0xff
        0x3865_6AE6, // ldrb w6, [x23, x5]  ; S-Box 查表
        0x3900_0306, // strb w6, [x24]
        0x9100_43FF, // add sp, sp, #16
        0xAA1B_03FE, // mov x30, x27  (恢复返回地址 LR)
        0xD65F_03C0, // ret
    ]);
    write_insns(&mut emu, code_base, &insns);

    let sp_before = emu.cpu().reg_read(RegisterARM64::SP).unwrap();
    let tmp_slot = sp_before - 16;

    let tracer = BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 16384, TraceLevel::Full)
        .expect("mmap tracer");
    emu.set_tracer(tracer).expect("set_tracer");
    emu.attach_tracer(code_base, code_base + 0x1000)
        .expect("attach_tracer");

    emu.call_address(
        code_base,
        &[
            input_buf,
            stage_buf,
            output_buf,
            unrelated_buf,
            sbox_table,
            sbox_out,
        ],
    )
    .expect("run");
    emu.tracer().flush().expect("flush");

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).expect("open");

    // 1. Forward Taint：从 input_buf[0..8] 出发
    let fwd = reader.taint_forward(
        &TaintSeed::Mem {
            addr: input_buf,
            len: 8,
        },
        &TaintOptions::default(),
    );
    assert!(
        fwd.steps.iter().any(|s| s.kind == "hle_copy"),
        "forward taint must cross HLE memcpy: {:?}",
        fwd.steps
    );
    assert!(
        fwd.tainted_mem_ranges
            .iter()
            .any(|&(a, l, mask)| a == output_buf && l == 8 && mask == 0xff),
        "output_buf must be tainted with full 8-byte mask 0xff: {:?}",
        fwd.tainted_mem_ranges
    );
    assert!(
        fwd.tainted_mem_ranges
            .iter()
            .any(|&(a, l, _)| a == sbox_out && l == 1),
        "sbox_out must be tainted via S-Box MemExt index dependency: {:?}",
        fwd.tainted_mem_ranges
    );
    // 关键断言：tmp_slot 被无关常量覆写后，最终不再携带污点！
    assert!(
        !fwd.tainted_mem_ranges.iter().any(|&(a, _, _)| a == tmp_slot),
        "reused tmp_slot must NOT remain tainted after unrelated overwrite: {:?}",
        fwd.tainted_mem_ranges
    );
    assert!(
        !fwd.tainted_mem_ranges
            .iter()
            .any(|&(a, _, _)| a == unrelated_buf),
        "unrelated_buf must NOT be tainted"
    );

    // 2. Backward Causal Slicing：从 output_buf[0..8] 倒推起源
    let bwd = reader.taint_backward(
        &TaintSeed::Mem {
            addr: output_buf,
            len: 8,
        },
        &TaintOptions::default(),
    );
    assert!(
        bwd.steps.iter().any(|s| s.kind == "hle_copy"),
        "backward slice must cross HLE memcpy: {:?}",
        bwd.steps
    );
    assert!(
        bwd.tainted_mem_ranges
            .iter()
            .any(|&(a, l, _)| a == input_buf && l == 8),
        "backward slice must resolve back to input_buf[0..8]: {:?}",
        bwd.tainted_mem_ranges
    );
    // 关键断言：反向切片绝不应包含覆写 tmp_slot 的无关指令 `movz x9, #0x9999` / `str x9, [sp]`！
    assert!(
        !bwd.steps.iter().any(|s| s.asm.contains("x9")),
        "backward slice must NOT be polluted by later reuse of tmp_slot: {:?}",
        bwd.steps
    );

    // 3. Backward Slicing 跨越 S-Box 查表直达 input_buf！
    let bwd_sbox = reader.taint_backward(
        &TaintSeed::Mem {
            addr: sbox_out,
            len: 1,
        },
        &TaintOptions::default(),
    );
    assert!(
        bwd_sbox
            .tainted_mem_ranges
            .iter()
            .any(|&(a, l, _)| a == input_buf && l == 8),
        "backward slice from S-Box output must trace back to input_buf: {:?}",
        bwd_sbox.tainted_mem_ranges
    );

    // 校验 format_summary 非空且包含关键段落
    let txt = bwd.format_summary(code_base);
    assert!(txt.contains("HLE memcpy"));
    assert!(txt.contains("溯源输入起源"));

    let _ = std::fs::remove_dir_all(idx_path.parent().unwrap());
}

#[test]
fn test_dual_run_trace_diff() {
    let dir = std::env::temp_dir().join(format!("runidbg_diff_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let idx_a = dir.join("a.idx");
    let ext_a = dir.join("a.ext");
    let idx_b = dir.join("b.idx");
    let ext_b = dir.join("b.ext");

    let run_once = |x0_in: u64, ip: &PathBuf, ep: &PathBuf| {
        let mut emu = AndroidEmulator::builder().build().expect("emu");
        let code_base: u64 = 0x4300_0000;
        emu.cpu_mut()
            .mem_map(code_base, 0x4000, Prot::ALL)
            .unwrap();
        // add x1, x0, #1
        // cmp x0, #0
        // b.eq +8 (skip next insn)
        // add x1, x1, #10
        // mov x0, x1
        // ret
        let insns: [u32; 6] = [
            0x9100_0401, // add x1, x0, #1
            0xF100_001F, // cmp x0, #0
            0x5400_0040, // b.eq +8 -> pc+8 = insn[4]
            0x9100_2821, // add x1, x1, #10
            0xAA01_03E0, // mov x0, x1
            0xD65F_03C0, // ret
        ];
        write_insns(&mut emu, code_base, &insns);
        let tracer = BinaryTracer::new_dual_mmap(ip, ep, 1024, 4096, TraceLevel::Full).unwrap();
        emu.set_tracer(tracer).unwrap();
        emu.attach_tracer(code_base, code_base + 0x1000).unwrap();
        let ret = emu.call_address(code_base, &[x0_in]).unwrap();
        emu.tracer().flush().unwrap();
        let _ = RET_MAGIC_ADDR;
        ret
    };

    assert_eq!(run_once(0, &idx_a, &ext_a), 1);
    assert_eq!(run_once(5, &idx_b, &ext_b), 16);

    let ra = TraceReader::open(&idx_a, Some(&ext_a)).unwrap();
    let rb = TraceReader::open(&idx_b, Some(&ext_b)).unwrap();
    let diff = TraceReader::diff_traces(&ra, &rb, 32);

    assert_eq!(diff.first_data_divergence_idx, Some(0));
    assert_eq!(diff.first_control_divergence_idx, Some(3));
    assert!(diff.diffs.iter().any(|d| d.kind == "reg"));
    assert!(diff.diffs.iter().any(|d| d.kind == "control"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(feature = "js", feature = "mcp"))]
#[test]
fn test_js_reg64_mem_hook_filters_freeze_layout_and_trace_api() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let tmp_dir = std::env::temp_dir().join(format!("runidbg_js_dx_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let idx_a = tmp_dir.join("run_a.idx");
    let idx_b = tmp_dir.join("run_b.idx");

    let session = JsSession::new(&[], &tmp_dir, true).expect("js session");

    // 1. 验证 freezeLayout: 插入任意次数 emu.mem.alloc() 后，guest heapUsed 纹丝不动，alloc 落在 host-scratch (0x6400_0000+)
    let layout_json = session
        .eval_json_string(
            r#"(() => {
                const emu = Emu.create({ freezeLayout: true });
                const beforeUsed = emu.mem.heapUsed();
                const s1 = emu.mem.alloc(128);
                const s2 = emu.mem.allocScratch(256);
                const afterUsed = emu.mem.heapUsed();
                const layout = emu.heapLayout();
                return { beforeUsed, afterUsed, s1, s2, frozen: layout.frozen, heapBaseHex: layout.heapBaseHex };
            })()"#,
        )
        .expect("freezeLayout eval");
    let layout_v: serde_json::Value = serde_json::from_str(&layout_json).unwrap();
    assert_eq!(layout_v["beforeUsed"], 0);
    assert_eq!(layout_v["afterUsed"], 0);
    assert_eq!(layout_v["frozen"], true);
    assert!(layout_v["s1"].as_u64().unwrap() >= 0x6400_0000);
    assert!(layout_v["s2"].as_u64().unwrap() >= 0x6400_0000);

    // 2. 验证 reg64 / get64 无损 64 位精度 (> 2^53) + hook.mem 过滤 + bigInt + unmapped 标记
    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples/libstatic-webp.so");
    let so_str = so_path.to_string_lossy().into_owned();
    let idx_a_str = idx_a.to_string_lossy().into_owned();
    let idx_b_str = idx_b.to_string_lossy().into_owned();

    let dx_script = format!(
        r#"(() => {{
            const emu = Emu.create({{ freezeLayout: true }});
            const mod = emu.load({so_str:?});

            // 64 位精度测试 (0xFEDCBA9876543211n > 2^53)
            const bigVal = 0xFEDCBA9876543211n;
            emu.regs.set("x8", bigVal);
            const gotGet64 = emu.regs.get64("x8");

            // 未映射区间 hook.mem 返回 unmapped === true
            const unmappedHandle = emu.hook.mem([0x77770000, 0x77771000], () => {{}});
            const wasUnmapped = Boolean(unmappedHandle.unmapped);
            unmappedHandle.detach();

            // 构造一段代码：写 0x11111111、写 0xdeadbeef、写 0x22222222 到 buf，同时在 hook.code 中验证 ctx.reg64("x8")
            const fnAddr = mod.symbol("WebPGetDecoderVersion");
            const buf = emu.mem.allocScratch(64);
            // mov w9, #0x1111; str w9, [x0]; mov w9, #0xbeef; movk w9, #0xdead, lsl #16; str w9, [x0, #4]; mov w9, #0x2222; str w9, [x0, #8]; mov x0, x1; ret
            const patchInsns = new Uint32Array([
                0x52822229, // mov w9, #0x1111
                0xB9000009, // str w9, [x0]
                0x5297DDE9, // mov w9, #0xbeef
                0x72BBD5A9, // movk w9, #0xdead, lsl #16
                0xB9000409, // str w9, [x0, #4]
                0x52844449, // mov w9, #0x2222
                0xB9000809, // str w9, [x0, #8]
                0xAA0103E0, // mov x0, x1
                0xD65F03C0, // ret
            ]);
            emu.mem.patch(fnAddr, new Uint8Array(patchInsns.buffer));

            let hookReg64Hex = "";
            const ch = emu.hook.code(fnAddr, (ctx) => {{
                hookReg64Hex = ctx.reg64("x8").toString(16);
            }}, {{ once: true }});

            const filteredHits = [];
            const mh = emu.hook.mem(
                [buf, buf + 64],
                {{ read: false, write: true, value: 0xdeadbeef, size: 4, bigInt: true }},
                (ctx, access, addr, size, value, value64) => {{
                    filteredHits.push({{
                        access,
                        addrType: typeof addr,
                        valType: typeof value,
                        val64Type: typeof value64,
                        valHex: value64.toString(16),
                        size,
                    }});
                }}
            );
            const mappedFlag = Boolean(mh.unmapped);

            // 跑第一遍 Trace (x1 = 10)
            emu.trace.start({{ output: {idx_a_str:?}, level: "full", start: fnAddr, end: fnAddr + 64, capacity: 1024 }});
            emu.call(fnAddr, buf, 10);
            emu.trace.stop();
            mh.detach();
            ch.detach();

            // 跑第二遍 Trace (x1 = 20) 用于 Trace.diff
            emu.trace.start({{ output: {idx_b_str:?}, level: "full", start: fnAddr, end: fnAddr + 64, capacity: 1024 }});
            emu.call(fnAddr, buf, 20);
            emu.trace.stop();

            // 离线 Trace.open + query + reconstructMem + taintBackward + diff
            const tr = Trace.open({idx_a_str:?});
            const qHits = tr.query({{ value: 0xdeadbeef, width: 4 }});
            const rec = tr.reconstructMem(buf + 4, 4, 9999);
            const bwd = tr.taintBackward({{ addr: buf + 4, len: 4 }});
            const closed = tr.close();
            const diff = Trace.diff({idx_a_str:?}, {idx_b_str:?}, 16);

            return {{
                get64Hex: gotGet64.toString(16),
                hookReg64Hex,
                wasUnmapped,
                mappedFlag,
                filteredHits,
                qHitCount: qHits.length,
                recHex: rec.hex,
                bwdSteps: bwd.steps.length,
                closed,
                diffFirstData: diff.firstDataDivergenceIdx,
                diffCount: diff.diffs.length,
            }};
        }})()"#
    );

    let out_json = session.eval_json_string(&dx_script).expect("dx script");
    let v: serde_json::Value = serde_json::from_str(&out_json).unwrap();
    assert_eq!(v["get64Hex"], "fedcba9876543211");
    assert_eq!(v["hookReg64Hex"], "fedcba9876543211");
    assert_eq!(v["wasUnmapped"], true);
    assert_eq!(v["mappedFlag"], false);
    assert_eq!(v["filteredHits"].as_array().unwrap().len(), 1);
    assert_eq!(v["filteredHits"][0]["addrType"], "bigint");
    assert_eq!(v["filteredHits"][0]["valType"], "bigint");
    assert_eq!(v["filteredHits"][0]["val64Type"], "bigint");
    assert_eq!(v["filteredHits"][0]["valHex"], "deadbeef");
    assert!(v["qHitCount"].as_u64().unwrap() >= 1);
    assert_eq!(v["recHex"], "efbeadde");
    assert!(v["bwdSteps"].as_u64().unwrap() >= 2);
    assert_eq!(v["closed"], true);
    assert!(v["diffFirstData"].is_number());
    assert!(v["diffCount"].as_u64().unwrap() >= 1);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[cfg(feature = "mcp")]
#[test]
fn test_mcp_trace_taint_query_diff() {
    use runidbg_arm64_emu_tracer::script::mcp::McpServer;
    use serde_json::{json, Value};

    let (idx_a, ext_a) = temp_trace_paths("mcp_a");
    let (idx_b, ext_b) = temp_trace_paths("mcp_b");

    let record_sample = |in_val: u64, ip: &PathBuf, ep: &PathBuf| -> (u64, u64) {
        let mut emu = AndroidEmulator::builder().build().unwrap();
        let code: u64 = 0x4400_0000;
        let data: u64 = 0x4410_0000;
        emu.cpu_mut().mem_map(code, 0x4000, Prot::ALL).unwrap();
        emu.cpu_mut()
            .mem_map(data, 0x4000, Prot::READ | Prot::WRITE)
            .unwrap();
        let in_addr = data;
        let out_addr = data + 0x40;
        emu.cpu_mut()
            .mem_write(in_addr, &in_val.to_le_bytes())
            .unwrap();
        let insns: [u32; 4] = [
            0xF940_0002, // ldr x2, [x0]
            0x9100_0442, // add x2, x2, #1
            0xF900_0022, // str x2, [x1]
            0xD65F_03C0, // ret
        ];
        write_insns(&mut emu, code, &insns);
        let tracer = BinaryTracer::new_dual_mmap(ip, ep, 1024, 4096, TraceLevel::Full).unwrap();
        emu.set_tracer(tracer).unwrap();
        emu.attach_tracer(code, code + 0x1000).unwrap();
        emu.call_address(code, &[in_addr, out_addr]).unwrap();
        emu.tracer().flush().unwrap();
        (in_addr, out_addr)
    };

    let (in_addr, out_addr) = record_sample(0x1122_3344, &idx_a, &ext_a);
    let _ = record_sample(0x5566_7788, &idx_b, &ext_b);

    let mut server = McpServer::new(idx_a.parent().unwrap(), None).expect("mcp server");
    let call_tool = |srv: &mut McpServer, id: u64, name: &str, args: Value| -> Value {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": args }
        })
        .to_string();
        let raw = srv.handle_message(&msg).expect("resp");
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["result"]["isError"], false, "tool {name} error: {v}");
        let txt = v["result"]["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(txt).unwrap()
    };

    // 1. trace_taint backward
    let bwd = call_tool(
        &mut server,
        1,
        "trace_taint",
        json!({
            "idxPath": idx_a.to_string_lossy(),
            "mode": "backward",
            "addr": format!("0x{out_addr:x}"),
            "len": 8
        }),
    );
    assert_eq!(bwd["mode"], "backward");
    assert_eq!(bwd["taintedMemRanges"][0]["addr"], in_addr);

    // 2. trace_query by written value (0x11223344 + 1 = 0x11223345)
    let qry = call_tool(
        &mut server,
        2,
        "trace_query",
        json!({
            "idxPath": idx_a.to_string_lossy(),
            "value": "0x11223345",
            "width": 4
        }),
    );
    assert!(qry["count"].as_u64().unwrap() >= 1);
    assert_eq!(qry["hits"][0]["addr"], out_addr);

    // 3. trace_diff
    let diff = call_tool(
        &mut server,
        3,
        "trace_diff",
        json!({
            "idxPathA": idx_a.to_string_lossy(),
            "idxPathB": idx_b.to_string_lossy()
        }),
    );
    assert!(diff["firstDataDivergenceIdx"].is_number());
    assert!(!diff["diffs"].as_array().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(idx_a.parent().unwrap());
    let _ = std::fs::remove_dir_all(idx_b.parent().unwrap());
}

#[test]
fn test_snapshot_and_rtape_preserve_host_scratch_and_freeze_layout() {
    use runidbg_arm64_emu_tracer::backend::BackendWithData;
    use runidbg_arm64_emu_tracer::TapeSelector;

    let dir = std::env::temp_dir().join(format!("runidbg_scratch_tape_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let tape_path = dir.join("scratch.rtape");

    let mut emu = AndroidEmulator::builder().build().expect("emu");
    emu.cpu_mut().get_data_mut().mem.set_freeze_layout(true);

    // 1. 保存 cp0（此时尚未分配任何 host_scratch 页）
    emu.save_tape(&tape_path, "cp0").expect("save cp0");

    // 2. 分配 host_scratch 缓冲并写入魔数，捕获 EmuSnapshot
    let s1 = emu.alloc_host_scratch_for_test(256);
    emu.cpu_mut()
        .mem_write(s1, &0xCAFE_BABE_1234_5678u64.to_le_bytes())
        .expect("write s1");
    let snap = emu.capture_snapshot().expect("capture_snapshot");

    // 3. 在快照之后再分配一块 host_scratch，然后回滚快照：下一次分配必须复用该区间而非永久泄漏
    let s2 = emu.alloc_host_scratch_for_test(256);
    assert_ne!(s1, s2);
    emu.restore_snapshot(&snap).expect("restore_snapshot");
    let s2_again = emu.alloc_host_scratch_for_test(256);
    assert_eq!(s2_again, s2, "EmuSnapshot must roll back host_scratch allocator");

    // 4. 保存 cp1（包含存活的 s1/s2 与 freeze_layout=true），随后倒带回 cp0（卸载了 [host-scratch] 页）
    emu.append_tape_checkpoint(&tape_path, "cp1")
        .expect("checkpoint cp1");
    emu.seek_tape_file(&tape_path, &TapeSelector::Label("cp0".to_string()))
        .expect("seek cp0");
    // 倒带回 cp0 后再次 alloc_host_scratch + 写入绝不能因 host_scratch_mapped_end 过期触发 UnmappedMemory！
    let s_after_rewind = emu.alloc_host_scratch_for_test(128);
    emu.cpu_mut()
        .mem_write(s_after_rewind, &[0xAB; 16])
        .expect("write after rewind to cp0 must succeed");

    // 5. 从 cp1 拉起全新实例，验证 freeze_layout 与 host_scratch 游标完整恢复（不会 UAF 覆写 s1）
    let (mut restored, _) = AndroidEmulator::from_tape_with_builder(
        &tape_path,
        &TapeSelector::Label("cp1".to_string()),
        AndroidEmulator::builder(),
    )
    .expect("from_tape cp1");
    assert!(restored.cpu().get_data().mem.is_layout_frozen());
    let s3 = restored.alloc_host_scratch_for_test(128);
    assert_ne!(s3, s1, "restored host_scratch must not overlap live s1");
    assert_ne!(s3, s2, "restored host_scratch must not overlap live s2");
    let mut check_s1 = [0u8; 8];
    restored.cpu().mem_read(s1, &mut check_s1).unwrap();
    assert_eq!(u64::from_le_bytes(check_s1), 0xCAFE_BABE_1234_5678);

    let _ = std::fs::remove_dir_all(&dir);
}

trait EmuScratchTestExt {
    fn alloc_host_scratch_for_test(&mut self, size: u64) -> u64;
}

impl EmuScratchTestExt for AndroidEmulator {
    fn alloc_host_scratch_for_test(&mut self, size: u64) -> u64 {
        use runidbg_arm64_emu_tracer::backend::BackendWithData;
        use runidbg_arm64_emu_tracer::memory::MemoryManager;
        let mut mem = std::mem::replace(
            &mut self.cpu_mut().get_data_mut().mem,
            MemoryManager::new(0, 0),
        );
        let ptr = mem.alloc_host_scratch(self.cpu_mut(), size).expect("alloc_host_scratch");
        self.cpu_mut().get_data_mut().mem = mem;
        ptr
    }
}

#[test]
fn test_taint_ldp_stp_xzr_qpair_neon_and_hle_memmove_memset() {
    let (idx_path, ext_path) = temp_trace_paths("taint_pair_neon");
    let mut emu = AndroidEmulator::builder().hle_accel(true).build().expect("emu");

    let code_base: u64 = 0x4500_0000;
    let data_base: u64 = 0x4510_0000;
    emu.cpu_mut().mem_map(code_base, 0x4000, Prot::ALL).unwrap();
    emu.cpu_mut()
        .mem_map(data_base, 0x4000, Prot::READ | Prot::WRITE)
        .unwrap();

    let in_addr = data_base;
    let pair_buf = data_base + 0x100;
    let q_buf = data_base + 0x200;
    let q_out = data_base + 0x280;
    let lane_out = data_base + 0x300;
    let zero_out = data_base + 0x340;
    let move_buf = data_base + 0x400;

    emu.cpu_mut()
        .mem_write(in_addr, &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();

    let memmove_slot = emu
        .register_hle_builtin("memmove", HleBuiltin::Memmove)
        .expect("memmove");
    let memset_slot = emu
        .register_hle_builtin("memset", HleBuiltin::Memset)
        .expect("memset");

    // 测试覆盖：
    //   1. STP XZR, X1, [pair_buf]：slot0 (pair_buf+0..8) 写 0（无污点），slot1 (pair_buf+8..16) 写污点 X1
    //   2. LDP XZR, X2, [pair_buf]：X2 拿到 slot1 污点
    //   3. MOV V1.B[0], W2; MOV V1.B[1], WZR：NEON 通道插入，第二条写 lane 1 不能清零 V1 污点！
    //   4. STP Q0, Q1, [q_buf]; LDP Q2, Q3, [q_buf]; STR Q3, [q_out]：128-bit 向量对 4 条 8B 写/读精确传播 Q1 -> Q3 -> q_out！
    //   5. STR Q1, [lane_out]；随后 EOR V1.16B, V1.16B, V1.16B; STR Q1, [zero_out]：向量自清零 kill 污点！
    //   6. memmove(move_buf+4, pair_buf+8, 8) 重叠移动 + memset(pair_buf+8, 0, 8) 清零原槽位
    let mut insns: Vec<u32> = vec![
        0xAA1E_03FB, // mov x27, x30
        0xAA00_03F3, // mov x19, x0 (in_addr)
        0xAA01_03F4, // mov x20, x1 (pair_buf)
        0xAA02_03F5, // mov x21, x2 (q_buf)
        0xAA03_03F6, // mov x22, x3 (q_out)
        0xAA04_03F7, // mov x23, x4 (lane_out)
        0xAA05_03F8, // mov x24, x5 (zero_out)
        0xAA06_03F9, // mov x25, x6 (move_buf)
        0xF940_0261, // ldr x1, [x19]
        0xA900_069F, // stp xzr, x1, [x20]
        0xA940_0A9F, // ldp xzr, x2, [x20]
        0x4E01_1C41, // mov v1.b[0], w2   (ins v1.b[0], w2)
        0x4E03_1FF1, // mov v1.b[1], wzr  (ins v1.b[1], wzr — 不得清除 v1 污点!)
        0xAD00_06A0, // stp q0, q1, [x21] (q0 无污点，q1 有污点 -> q_buf+16..32)
        0xAD40_0EA2, // ldp q2, q3, [x21] (q2 无污点，q3 继承 q1 污点!)
        0x3D80_02C3, // str q3, [x22]     (写入 q_out)
        0x3D80_02E1, // str q1, [x23]     (写入 lane_out)
        0x6E21_1C21, // eor v1.16b, v1.16b, v1.16b (向量自清零 kill v1 污点!)
        0x3D80_0301, // str q1, [x24]     (写入 zero_out — 必须无污点!)
        0x9100_1320, // add x0, x25, #4   (move_buf+4)
        0x9100_2281, // add x1, x20, #8   (pair_buf+8)
        0xD280_0102, // mov x2, #8
    ];
    emit_blr_target(&mut insns, memmove_slot);
    insns.extend_from_slice(&[
        0x9100_2280, // add x0, x20, #8   (pair_buf+8)
        0xD280_0001, // mov x1, #0
        0xD280_0102, // mov x2, #8
    ]);
    emit_blr_target(&mut insns, memset_slot);
    insns.extend_from_slice(&[
        0xAA1B_03FE, // mov x30, x27
        0xD65F_03C0, // ret
    ]);
    write_insns(&mut emu, code_base, &insns);

    let tracer = BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 4096, 16384, TraceLevel::Full)
        .expect("tracer");
    emu.set_tracer(tracer).unwrap();
    emu.attach_tracer(code_base, code_base + 0x1000).unwrap();
    emu.call_address(
        code_base,
        &[in_addr, pair_buf, q_buf, q_out, lane_out, zero_out, move_buf],
    )
    .unwrap();
    emu.tracer().flush().unwrap();

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let fwd = reader.taint_forward(
        &TaintSeed::Mem {
            addr: in_addr,
            len: 8,
        },
        &TaintOptions::default(),
    );

    // 1. STP XZR, X1: slot0 (pair_buf+0..8) 绝对不能被污染
    assert!(
        !fwd.tainted_mem_ranges.iter().any(|&(a, _, _)| a == pair_buf),
        "XZR slot of STP must NOT be tainted: {:?}",
        fwd.tainted_mem_ranges
    );
    // 2. pair_buf+8 被 HLE memset 清零后不再携带污点，但 move_buf+4 已通过 memmove 继承污点！
    assert!(
        !fwd.tainted_mem_ranges
            .iter()
            .any(|&(a, _, _)| a == pair_buf + 8),
        "memset-cleared pair_buf+8 must NOT remain tainted: {:?}",
        fwd.tainted_mem_ranges
    );
    assert!(
        fwd.tainted_mem_ranges
            .iter()
            .any(|&(a, l, _)| a == move_buf + 4 && l == 8),
        "memmove target move_buf+4 must be tainted: {:?}",
        fwd.tainted_mem_ranges
    );
    // 3. NEON lane 插入 + 128-bit STP/LDP Q0, Q1 -> Q3 -> q_out 必须带污点，但 q_buf+0 (Q0) 不带污点！
    assert!(
        fwd.tainted_mem_ranges
            .iter()
            .any(|&(a, l, _)| a == q_out && l == 16),
        "128-bit Q-pair destination q_out must be tainted: {:?}",
        fwd.tainted_mem_ranges
    );
    assert!(
        !fwd.tainted_mem_ranges.iter().any(|&(a, _, _)| a == q_buf),
        "untainted Q0 slot in STP Q0, Q1 must NOT be tainted: {:?}",
        fwd.tainted_mem_ranges
    );
    // 4. 向量自清零 EOR V1.16B, V1.16B, V1.16B 之后写入 zero_out 必须无污点！
    assert!(
        !fwd.tainted_mem_ranges.iter().any(|&(a, _, _)| a == zero_out),
        "vector self-zero output zero_out must NOT be tainted: {:?}",
        fwd.tainted_mem_ranges
    );

    // 5. 反向切片从 q_out[0..16] 必须能穿过 LDP/STP Q0,Q1 与 MOV V1.B[0], W2 直达 in_addr！
    let bwd_q = reader.taint_backward(
        &TaintSeed::Mem {
            addr: q_out,
            len: 16,
        },
        &TaintOptions::default(),
    );
    assert!(
        bwd_q
            .tainted_mem_ranges
            .iter()
            .any(|&(a, l, _)| a == in_addr && l == 8),
        "backward slice from Q3 output must resolve to in_addr: {:?}",
        bwd_q.tainted_mem_ranges
    );

    let _ = std::fs::remove_dir_all(idx_path.parent().unwrap());
}

#[cfg(all(feature = "js", feature = "mcp"))]
#[test]
fn test_js_highbit_bigint_and_mem_read_filter_regression() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let tmp_dir = std::env::temp_dir().join(format!("runidbg_js_reg_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let idx_path = tmp_dir.join("hi.idx");
    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples/libstatic-webp.so");
    let so_str = so_path.to_string_lossy().into_owned();
    let idx_str = idx_path.to_string_lossy().into_owned();

    let session = JsSession::new_with_freeze_layout(&[], &tmp_dir, true, true).expect("session");
    let script = format!(
        r#"(() => {{
            const emu = Emu.create();
            const frozenBySession = emu.heapLayout().frozen;
            const mod = emu.load({so_str:?});
            const fnAddr = mod.symbol("WebPGetDecoderVersion");
            const buf = emu.mem.alloc(64);
            const hiVal = 0xFEDCBA9876543211n; // bit 63 = 1 (> i64::MAX)
            emu.mem.writeU64(buf, hiVal);

            // ldr x9, [x0]; str x9, [x0, #8]; ret
            const insns = new Uint32Array([0xF9400009, 0xF9000409, 0xD65F03C0]);
            emu.mem.patch(fnAddr, new Uint8Array(insns.buffer));

            // 1. 验证 MEM_READ 真实值过滤 + 高位为 1 的 BigInt + 闭区间单点 pcRange [fnAddr, fnAddr] + emu.hook.watch('w')
            let readHits = 0;
            let watchWriteHits = 0;
            const rh = emu.hook.mem(
                [buf, buf + 64],
                {{ read: true, write: false, value: hiVal, size: 8, pcRange: [fnAddr, fnAddr], bigInt: true }},
                (ctx, access, addr, size, value, value64) => {{
                    if (access === "read" && value === hiVal && value64 === hiVal) readHits++;
                }}
            );
            const wh = emu.hook.watch([buf + 8, buf + 16], "w", (ctx, access, addr, size, val, val64) => {{
                if (access === "write" && val64 === hiVal) watchWriteHits++;
            }});

            // 设 capacity = 1024（最小容量）跑 400 次（1200 条指令 > 1024）验证 truncated === true，再正常抓全量
            emu.trace.start({{ output: {idx_str:?}, level: "full", start: fnAddr, end: fnAddr + 16, capacity: 1024 }});
            for (let k = 0; k < 400; k++) {{
                emu.call(fnAddr, buf);
            }}
            const truncStats = emu.trace.stop();

            emu.trace.start({{ output: {idx_str:?}, level: "full", start: fnAddr, end: fnAddr + 16, capacity: 2048 }});
            emu.call(fnAddr, buf);
            const okStats = emu.trace.stop();
            rh.detach();
            wh.detach();

            // 2. 验证 Trace.open().findWrites(hiVal) / findReads(buf) 与省略 atSeq 的 reconstructMem
            const tr = Trace.open({idx_str:?});
            const qHits = tr.findWrites(hiVal, {{ width: 8 }});
            const rHits = tr.findReads(buf, {{ len: 8 }});
            const rec = tr.reconstructMem(buf + 8, 8); // 省略第 3 参 atSeq
            tr.close();
            const diff = Trace.diff({idx_str:?}, {idx_str:?}, 16);

            return {{
                frozenBySession,
                readHits,
                watchWriteHits,
                wasTruncated: truncStats.truncated,
                okTruncated: okStats.truncated,
                qHitCount: qHits.length,
                rHitCount: rHits.length,
                recHex: rec.hex,
                diffCount: diff.diffs.length,
            }};
        }})()"#
    );
    let out = session.eval_json_string(&script).expect("regression script");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["frozenBySession"], true);
    assert_eq!(v["readHits"], 401);
    assert_eq!(v["watchWriteHits"], 401);
    assert_eq!(v["wasTruncated"], true);
    assert_eq!(v["okTruncated"], false);
    assert!(v["qHitCount"].as_u64().unwrap() >= 1);
    assert!(v["rHitCount"].as_u64().unwrap() >= 1);
    assert_eq!(v["recHex"], "1132547698badcfe");
    assert_eq!(v["diffCount"], 0);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_second_pass_core_and_taint_regressions() {
    use runidbg_arm64_emu_tracer::backend::BackendWithData;
    use runidbg_arm64_emu_tracer::tracer::resolve_sibling_ext_path;

    // 1. mmap 容量乘法溢出必须安全返回 Err，严禁 Release 静默回绕导致越界写 UB
    let tmp = std::env::temp_dir().join(format!("runidbg_p2_core_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let ovf_idx = tmp.join("ovf.idx");
    let ovf_ext = tmp.join("ovf.ext");
    assert!(BinaryTracer::new_mmap(&ovf_idx, usize::MAX / 4).is_err());
    assert!(BinaryTracer::new_dual_mmap(&ovf_idx, &ovf_ext, 1024, usize::MAX / 4, TraceLevel::Full).is_err());

    // 2. resolve_sibling_ext_path 同时支持 a.idx -> a.ext 与 a.bin -> a.bin.ext
    let bin_idx = tmp.join("custom.bin");
    let bin_ext = tmp.join("custom.bin.ext");
    std::fs::write(&bin_idx, b"").unwrap();
    std::fs::write(&bin_ext, b"").unwrap();
    assert_eq!(resolve_sibling_ext_path(&bin_idx).as_deref(), Some(bin_ext.as_path()));

    // 3. aligned_with_header + hle_free 精确回收且不泄漏/不破坏相邻块
    let mut emu = AndroidEmulator::builder().hle_accel(true).build().expect("emu");
    {
        let mem = &mut emu.cpu_mut().get_data_mut().mem;
        let in_use_before = mem.heap_used();
        let raw_a = mem.alloc_heap_aligned_with_header(32, 64).expect("aligned 64");
        let ptr_a = raw_a + 16;
        assert_eq!(ptr_a % 64, 0, "user pointer must be 64-byte aligned");
        let raw_b = mem.alloc_heap_aligned_with_header(48, 256).expect("aligned 256");
        let ptr_b = raw_b + 16;
        assert_eq!(ptr_b % 256, 0, "user pointer must be 256-byte aligned");
        assert!(mem.hle_free(ptr_b));
        assert!(mem.hle_free(ptr_a));
        assert_eq!(mem.heap_used(), in_use_before, "aligned blocks must be reclaimed with zero leak");
    }

    // 4. HLE asprintf + memalign 带 16B HEAPBLK1 头：free(b) 不错杀存活相邻块 a，realloc 完整保留数据
    let code_base: u64 = 0x4600_0000;
    let data_base: u64 = 0x4610_0000;
    emu.cpu_mut().mem_map(code_base, 0x4000, Prot::ALL).unwrap();
    emu.cpu_mut().mem_map(data_base, 0x4000, Prot::READ | Prot::WRITE).unwrap();
    let fmt_addr = data_base;
    let strp_a = data_base + 0x100;
    let strp_b = data_base + 0x108;
    emu.cpu_mut().mem_write(fmt_addr, b"hello\0").unwrap();
    let asprintf_slot = emu.register_hle_builtin("asprintf", HleBuiltin::Asprintf).unwrap();
    let realloc_slot = emu.register_hle_builtin("realloc", HleBuiltin::Realloc).unwrap();
    let free_slot = emu.register_hle_builtin("free", HleBuiltin::Free).unwrap();
    let memalign_slot = emu.register_hle_builtin("memalign", HleBuiltin::Memalign).unwrap();

    let mut insns: Vec<u32> = vec![
        0xAA1E_03FB, // mov x27, x30
        0xAA00_03F3, // mov x19, x0 (fmt_addr)
        0xAA01_03F4, // mov x20, x1 (strp_a)
        0xAA02_03F5, // mov x21, x2 (strp_b)
        // asprintf(strp_a, fmt_addr)
        0xAA14_03E0, // mov x0, x20
        0xAA13_03E1, // mov x1, x19
    ];
    emit_blr_target(&mut insns, asprintf_slot);
    insns.extend_from_slice(&[
        // asprintf(strp_b, fmt_addr)
        0xAA15_03E0, // mov x0, x21
        0xAA13_03E1, // mov x1, x19
    ]);
    emit_blr_target(&mut insns, asprintf_slot);
    insns.extend_from_slice(&[
        // free(*strp_b) — 必须仅释放 b，不得错释放 a
        0xF940_02A0, // ldr x0, [x21]
    ]);
    emit_blr_target(&mut insns, free_slot);
    insns.extend_from_slice(&[
        // x22 = realloc(*strp_a, 32) — 必须拷贝 "hello\0"
        0xF940_0280, // ldr x0, [x20]
        0xD280_0401, // mov x1, #32
    ]);
    emit_blr_target(&mut insns, realloc_slot);
    insns.extend_from_slice(&[
        0xAA00_03F6, // mov x22, x0
        // x0 = memalign(64, 32) -> 写入后 realloc 到 64 字节
        0xD280_0800, // mov x0, #64
        0xD280_0401, // mov x1, #32
    ]);
    emit_blr_target(&mut insns, memalign_slot);
    insns.extend_from_slice(&[
        0xAA00_03F7, // mov x23, x0
        0xAA16_03E0, // mov x0, x22 (return realloc'd asprintf ptr)
        0xAA1B_03FE, // mov x30, x27
        0xD65F_03C0, // ret
    ]);
    write_insns(&mut emu, code_base, &insns);
    let realloc_ptr = emu.call_address(code_base, &[fmt_addr, strp_a, strp_b]).unwrap();
    let mut got = [0u8; 6];
    emu.cpu().mem_read(realloc_ptr, &mut got).unwrap();
    assert_eq!(&got, b"hello\0", "realloc on asprintf buffer must preserve payload");

    // 5. .plt 风格 BR X17 跳入 malloc：前向必须清除 X0 旧污点，反向切片必须在 hle_ret 终止不穿透到 size
    let (plt_idx, plt_ext) = temp_trace_paths("taint_plt_br");
    let malloc_slot = emu.register_hle_builtin("malloc", HleBuiltin::Malloc).unwrap();
    let plt_code = code_base + 0x1000;
    let plt_stub = code_base + 0x1800;
    let out_slot = data_base + 0x300;
    // plt_stub: movz/movk x17, malloc_slot; br x17 (InsnCategory::NoDataFlow!)
    let mut stub_insns: Vec<u32> = vec![
        0xD280_0011 | (((malloc_slot & 0xFFFF) as u32) << 5),
        0xF2A0_0011 | ((((malloc_slot >> 16) & 0xFFFF) as u32) << 5),
        0xF2C0_0011 | ((((malloc_slot >> 32) & 0xFFFF) as u32) << 5),
        0xD61F_0220, // br x17
    ];
    write_insns(&mut emu, plt_stub, &stub_insns);
    let _ = &mut stub_insns;

    let mut caller_insns: Vec<u32> = vec![
        0xAA1E_03FB, // mov x27, x30
        0xAA01_03F4, // mov x20, x1 (out_slot)
        // x0 初始带污点（malloc size），通过 BL plt_stub -> BR x17 -> HLE malloc
    ];
    emit_blr_target(&mut caller_insns, plt_stub);
    caller_insns.extend_from_slice(&[
        0xF900_0280, // str x0, [x20]
        0xAA1B_03FE, // mov x30, x27
        0xD65F_03C0, // ret
    ]);
    write_insns(&mut emu, plt_code, &caller_insns);

    let tracer = BinaryTracer::new_dual_mmap(&plt_idx, &plt_ext, 4096, 16384, TraceLevel::Full).unwrap();
    emu.set_tracer(tracer).unwrap();
    emu.attach_tracer(plt_code, plt_code + 0x1000).unwrap();
    emu.call_address(plt_code, &[64, out_slot]).unwrap();
    emu.tracer().flush().unwrap();

    let reader = TraceReader::open(&plt_idx, Some(&plt_ext)).unwrap();
    let fwd = reader.taint_forward(&TaintSeed::Reg { reg_id: 0 }, &TaintOptions::default());
    assert!(
        !fwd.tainted_mem_ranges.iter().any(|&(a, _, _)| a == out_slot),
        "BR X17 PLT malloc must clear tainted size X0 before STR [out_slot]: {:?}",
        fwd.tainted_mem_ranges
    );
    let bwd = reader.taint_backward(&TaintSeed::Mem { addr: out_slot, len: 8 }, &TaintOptions::default());
    assert!(
        bwd.steps.iter().any(|s| s.kind == "hle_ret"),
        "backward slice through PLT BR X17 malloc must terminate at hle_ret: {:?}",
        bwd.steps
    );
    assert!(
        bwd.tainted_regs.is_empty(),
        "backward slice must not leak past PLT malloc hle_ret into size arg: {:?}",
        bwd.tainted_regs
    );

    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(plt_idx.parent().unwrap());
}

#[cfg(all(feature = "js", feature = "mcp"))]
#[test]
fn test_second_pass_js_watch_filter_and_validation_regressions() {
    use runidbg_arm64_emu_tracer::script::JsSession;

    let tmp_dir = std::env::temp_dir().join(format!("runidbg_js_p2_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let idx_path = tmp_dir.join("p2.bin"); // 非 .idx 后缀，顺便测 .bin -> .bin.ext 自动发现
    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples/libstatic-webp.so");
    let so_str = so_path.to_string_lossy().into_owned();
    let idx_str = idx_path.to_string_lossy().into_owned();

    let session = JsSession::new(&[], &tmp_dir, true).expect("session");
    let script = format!(
        r#"(() => {{
            const emu = Emu.create({{ freezeLayout: true }});
            const mod = emu.load({so_str:?});
            const fnAddr = mod.symbol("WebPGetDecoderVersion");
            const buf = emu.mem.alloc(64);
            emu.mem.writeU64(buf, 0x11223344n);

            // ldrb w9, [x0]; strb wzr, [x0, #1]; str w9, [x0, #8]; ret
            const insns = new Uint32Array([0x39400009, 0x3900041F, 0xB9000809, 0xD65F03C0]);
            emu.mem.patch(fnAddr, new Uint8Array(insns.buffer));

            // 1. watch({{ mode: "write" }}) 绝不能被 "write".includes("r") 误判成读！
            let objWriteModeReadHits = 0;
            let objWriteModeWriteHits = 0;
            const h1 = emu.hook.watch([buf, buf + 16], {{ mode: "write" }}, (ctx, access) => {{
                if (access === "read") objWriteModeReadHits++;
                if (access === "write") objWriteModeWriteHits++;
            }});

            // 2. watch({{ read: true }}) 绝不能被默认注入 write: true！
            let objReadOnlyReadHits = 0;
            let objReadOnlyWriteHits = 0;
            const h2 = emu.hook.watch([buf, buf + 16], {{ read: true }}, (ctx, access) => {{
                if (access === "read") objReadOnlyReadHits++;
                if (access === "write") objReadOnlyWriteHits++;
            }});

            // 3. hook.mem({{ write: true, value: 0x100 }}) 绝不能被 STRB WZR (1B 写 0x00) 误命中！
            let narrowFalseHits = 0;
            const h3 = emu.hook.mem([buf, buf + 16], {{ write: true, value: 0x100 }}, () => {{
                narrowFalseHits++;
            }});

            // 4. 非法 mode 必须抛 TypeError
            let badModeThrew = false;
            try {{ emu.hook.watch([buf, buf + 16], {{ mode: "error" }}, () => {{}}); }} catch (e) {{ badModeThrew = true; }}

            // 5. trace.start 超大 capacity (2**58) 必须抛错而不是 mmap 乘法溢出 UB
            let hugeCapThrew = false;
            try {{ emu.trace.start({{ output: {idx_str:?}, level: "full", capacity: 2 ** 58 }}); }} catch (e) {{ hugeCapThrew = true; }}

            // 6. js_addr_to_u64_strict 必须拒绝 > Number.MAX_SAFE_INTEGER 的 JS number（防止 2^64 静默饱和/丢精度）
            let unsafeNumThrew = false;
            try {{ emu.hook.mem([buf, buf + 16], {{ write: true, value: 2 ** 64 }}, () => {{}}); }} catch (e) {{ unsafeNumThrew = true; }}

            emu.trace.start({{ output: {idx_str:?}, level: "full", start: fnAddr, end: fnAddr + 16, capacity: 2048 }});
            emu.call(fnAddr, buf);
            emu.trace.stop();
            h1.detach();
            h2.detach();
            h3.detach();

            // 7. Trace.open("p2.bin") 自动发现 p2.bin.ext + 互斥校验 + reconstructMem(len=0) + minSeq on addr
            const tr = Trace.open({idx_str:?});
            let mutexThrew = false;
            try {{ tr.query({{ value: 0x44, addr: buf }}); }} catch (e) {{ mutexThrew = true; }}
            let badRegTypeThrew = false;
            try {{ tr.taintBackward({{ reg: 123 }}); }} catch (e) {{ badRegTypeThrew = true; }}
            const emptyRec = tr.reconstructMem(buf, 0);
            const allAddrHits = tr.query({{ addr: buf, len: 16 }});
            const minSeqFiltered = tr.query({{ addr: buf, len: 16, minSeq: 999999 }});
            const extLen = tr.totalExt;
            tr.close();

            return {{
                objWriteModeReadHits,
                objWriteModeWriteHits,
                objReadOnlyReadHits,
                objReadOnlyWriteHits,
                narrowFalseHits,
                badModeThrew,
                hugeCapThrew,
                unsafeNumThrew,
                mutexThrew,
                badRegTypeThrew,
                emptyRecLen: emptyRec.bytes.length,
                allAddrHits: allAddrHits.length,
                minSeqFiltered: minSeqFiltered.length,
                extLen,
            }};
        }})()"#
    );
    let out = session.eval_json_string(&script).expect("p2 js regression");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["objWriteModeReadHits"], 0);
    assert_eq!(v["objWriteModeWriteHits"], 2);
    assert_eq!(v["objReadOnlyReadHits"], 1);
    assert_eq!(v["objReadOnlyWriteHits"], 0);
    assert_eq!(v["narrowFalseHits"], 0);
    assert_eq!(v["badModeThrew"], true);
    assert_eq!(v["hugeCapThrew"], true);
    assert_eq!(v["unsafeNumThrew"], true);
    assert_eq!(v["mutexThrew"], true);
    assert_eq!(v["badRegTypeThrew"], true);
    assert_eq!(v["emptyRecLen"], 0);
    assert!(v["allAddrHits"].as_u64().unwrap() >= 3);
    assert_eq!(v["minSeqFiltered"], 0);
    assert!(v["extLen"].as_u64().unwrap() >= 3);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
