//! `good64` 轻量 ARM64 汇编器端到端执行与 Inline Hook 集成测试
//!
//! 不仅用 `bad64` 反向校验机器码，还直接将 `good64` 汇编出的机器码写入真实 `AndroidEmulator`
//! （Unicorn + Dynarmic）中执行，验证控制流、算术/位运算、栈帧与 4B/16B Inline Hook 跳板真实可用。

use runidbg_arm64_emu_tracer::good64::{
    assemble, encode_branch_trampoline, encode_call_trampoline, relocate_instructions, Arm64Emitter,
};
use runidbg_arm64_emu_tracer::{AndroidEmulator, BackendKind, CpuBackend};

fn run_good64_suite_on_backend(backend: BackendKind) {
    let mut emu = AndroidEmulator::builder()
        .backend(backend)
        .build()
        .expect("build emu");

    // 1. 测试带前向/后向标签、栈帧 stp/ldp、条件分支、移位与大立即数的完整函数：
    //    f(n, k) = (sum(1..=n) ^ (k << 4)) + 0x11223344
    let code_base = 0x4000_0000u64;
    emu.cpu_mut()
        .mem_map(code_base, 0x10000, unicorn_engine::unicorn_const::Prot::ALL)
        .expect("map code");

    let fn_src = r#"
        stp x29, x30, [sp, #-16]!
        mov x29, sp
        mov x2, #0              // sum = 0
    loop:
        cbz x0, done
        add x2, x2, x0
        sub x0, x0, #1
        b loop
    done:
        lsl x3, x1, #4
        eor x2, x2, x3
        mov x4, #0x11223344
        add x0, x2, x4
        ldp x29, x30, [sp], #16
        ret
    "#;
    let fn_bytes = assemble(fn_src, code_base).expect("assemble fn");
    emu.cpu_mut().mem_write(code_base, &fn_bytes).unwrap();

    // n=10 -> sum=55; k=3 -> k<<4=48; 55^48 = 7; 7 + 0x11223344 = 0x1122334B
    let res = emu.call_address(code_base, &[10, 3]).expect("call fn");
    assert_eq!(res, 0x1122_334B, "backend={backend:?} fn result mismatch");

    // 2. 测试 4B 近跳 Inline Hook（hook_entry -> hook_handler）
    let orig_pc = code_base + 0x2000;
    let handler_pc = code_base + 0x4000;
    let orig_code = assemble("mov x0, #111; ret", orig_pc).unwrap();
    let handler_code = assemble("add x0, x0, #0x100; ret", handler_pc).unwrap();
    emu.cpu_mut().mem_write(orig_pc, &orig_code).unwrap();
    emu.cpu_mut().mem_write(handler_pc, &handler_code).unwrap();
    assert_eq!(emu.call_address(orig_pc, &[5]).unwrap(), 111);

    let near_jmp = encode_branch_trampoline(orig_pc, handler_pc);
    assert_eq!(near_jmp.len(), 4);
    emu.cpu_mut().mem_write(orig_pc, &near_jmp).unwrap();
    let _ = emu.cpu_mut().flush_cache(orig_pc, orig_pc + 4);
    assert_eq!(
        emu.call_address(orig_pc, &[5]).unwrap(),
        0x105,
        "backend={backend:?} near inline jump failed"
    );

    // 3. 测试 16B 远跳 Inline Hook（跨 >128MB 地址空间：0x4000_6000 -> 0x8000_0100）
    let far_base = 0x8000_0000u64;
    emu.cpu_mut()
        .mem_map(far_base, 0x4000, unicorn_engine::unicorn_const::Prot::ALL)
        .expect("map far code");
    let far_orig = code_base + 0x6000;
    let far_handler = far_base + 0x100;
    let far_handler_code = assemble("mov x0, #0xCAFEBABE; ret", far_handler).unwrap();
    emu.cpu_mut()
        .mem_write(far_handler, &far_handler_code)
        .unwrap();

    let far_jmp = encode_branch_trampoline(far_orig, far_handler);
    assert_eq!(far_jmp.len(), 16);
    emu.cpu_mut().mem_write(far_orig, &far_jmp).unwrap();
    let _ = emu.cpu_mut().flush_cache(far_orig, far_orig + 16);
    assert_eq!(
        emu.call_address(far_orig, &[]).unwrap(),
        0xCAFE_BABE,
        "backend={backend:?} far 16B inline jump failed"
    );

    // 4. 测试 20B 远调用跳板（encode_call_trampoline）+ Arm64Emitter
    let caller_pc = code_base + 0x8000;
    let mut em = Arm64Emitter::new(caller_pc);
    em.emit_u32(assemble("stp x29, x30, [sp, #-16]!", caller_pc).unwrap()[0..4].try_into().map(u32::from_le_bytes).unwrap());
    let call_stub = encode_call_trampoline(em.pc(), far_handler);
    assert_eq!(call_stub.len(), 20);
    let mut caller_bytes = em.into_bytes();
    caller_bytes.extend_from_slice(&call_stub);
    let tail_pc = caller_pc + caller_bytes.len() as u64;
    let tail = assemble("add x0, x0, #1; ldp x29, x30, [sp], #16; ret", tail_pc).unwrap();
    caller_bytes.extend_from_slice(&tail);
    emu.cpu_mut().mem_write(caller_pc, &caller_bytes).unwrap();
    let _ = emu
        .cpu_mut()
        .flush_cache(caller_pc, caller_pc + caller_bytes.len() as u64);
    assert_eq!(
        emu.call_address(caller_pc, &[]).unwrap(),
        0xCAFE_BABF,
        "backend={backend:?} far 20B call trampoline failed"
    );

    // 5. 测试 Route A 扩展整数指令真实执行（位域/位反转/前导零/长乘/条件比较/寄存器索引访存）
    let data_buf = code_base + 0xB000;
    let table: [u64; 4] = [0x10, 0x20, 0x30, 0x1000];
    for (i, v) in table.iter().enumerate() {
        emu.cpu_mut()
            .mem_write(data_buf + (i as u64) * 8, &v.to_le_bytes())
            .unwrap();
    }
    let route_a_int_pc = code_base + 0x9000;
    let route_a_int = assemble(
        r#"
        // x0 = 0x12345678, x1 = data_buf, x2 = 3
        ubfx x3, x0, #8, #8          // 0x56
        rev w4, w0                   // 0x78563412
        clz w5, w3                   // leading zeros of 0x56 (u32) = 25
        umull x6, w3, w5             // 0x56 * 25 = 86 * 25 = 2150 = 0x866
        ldr x7, [x1, x2, lsl #3]     // table[3] = 0x1000
        add x6, x6, x7               // 0x1866
        cmp x3, #0x56
        ccmp x5, #25, #4, eq         // Z=1 because both match
        cinc x0, x6, eq              // 0x1867
        bfi x0, x4, #16, #8          // insert low byte of rev (0x12) at bits [23:16] -> 0x0012_1867
        ret
        "#,
        route_a_int_pc,
    )
    .expect("assemble route_a_int");
    emu.cpu_mut().mem_write(route_a_int_pc, &route_a_int).unwrap();
    let r_int = emu
        .call_address(route_a_int_pc, &[0x1234_5678, data_buf, 3])
        .expect("call route_a_int");
    assert_eq!(
        r_int, 0x0012_1867,
        "backend={backend:?} Route A integer execution mismatch"
    );

    // 6. 测试 Route A 标量浮点 + 128-bit NEON 真实执行（scvtf/fadd/fmul/fcvtzs + movi/eor/add/ins/umov/stp q）
    let route_a_simd_pc = code_base + 0x9400;
    let route_a_simd = assemble(
        r#"
        stp q0, q1, [sp, #-32]!
        scvtf d0, x0                 // d0 = 7.0
        scvtf d1, x1                 // d1 = 3.0
        fadd d2, d0, d1              // d2 = 10.0
        fmul d2, d2, d1              // d2 = 30.0
        fcvtzs x2, d2                // x2 = 30
        movi v0.16b, #0x11
        movi v1.16b, #0x02
        add v0.4s, v0.4s, v1.4s      // every lane u32 = 0x13131313
        ins v0.s[1], w2              // lane 1 = 30
        umov w3, v0.s[0]             // 0x13131313
        umov w4, v0.s[1]             // 30
        add x0, x3, x4               // 0x13131331
        ldp q0, q1, [sp], #32
        ret
        "#,
        route_a_simd_pc,
    )
    .expect("assemble route_a_simd");
    emu.cpu_mut()
        .mem_write(route_a_simd_pc, &route_a_simd)
        .unwrap();
    let r_simd = emu
        .call_address(route_a_simd_pc, &[7, 3])
        .expect("call route_a_simd");
    assert_eq!(
        r_simd, 0x1313_1331,
        "backend={backend:?} Route A FP/NEON execution mismatch"
    );

    // 7. 测试 Route A Relocator 跨 >1 GiB 真实执行（原函数含 adr / cbz / ldr literal / bl，搬运到 0x8000_1000）
    let old_fn_pc = code_base + 0xA000;
    let helper_pc = code_base + 0xA400;
    let zero_branch_pc = code_base + 0xA440;
    let const_pool_pc = code_base + 0xA480;
    emu.cpu_mut()
        .mem_write(
            helper_pc,
            &assemble("add x0, x0, #0x200; ret", helper_pc).unwrap(),
        )
        .unwrap();
    emu.cpu_mut()
        .mem_write(
            zero_branch_pc,
            &assemble("mov x0, #0x999; ldp x29, x30, [sp], #16; ret", zero_branch_pc).unwrap(),
        )
        .unwrap();
    emu.cpu_mut()
        .mem_write(const_pool_pc, &0x0000_0000_0000_0055u64.to_le_bytes())
        .unwrap();

    let orig_reloc_fn = assemble(
        &format!(
            r#"
            stp x29, x30, [sp, #-16]!
            cbz x0, {zero_branch_pc:#x}
            adr x9, {const_pool_pc:#x}
            ldr x10, [x9]
            add x0, x0, x10
            bl {helper_pc:#x}
            ldp x29, x30, [sp], #16
            ret
            "#
        ),
        old_fn_pc,
    )
    .expect("assemble orig_reloc_fn");

    let new_fn_pc = far_base + 0x1000;
    let relocated_bytes =
        relocate_instructions(&orig_reloc_fn, old_fn_pc, new_fn_pc).expect("relocate_instructions");
    assert!(
        relocated_bytes.len() > orig_reloc_fn.len(),
        "far relocation should expand PC-relative instructions"
    );
    emu.cpu_mut()
        .mem_write(new_fn_pc, &relocated_bytes)
        .unwrap();
    let _ = emu
        .cpu_mut()
        .flush_cache(new_fn_pc, new_fn_pc + relocated_bytes.len() as u64);

    // x0 = 0 -> cbz 跳到 0x4000_A440 返回 0x999
    assert_eq!(
        emu.call_address(new_fn_pc, &[0]).unwrap(),
        0x999,
        "backend={backend:?} relocated cbz branch failed"
    );
    // x0 = 0x10 -> +0x55 (from adr const_pool) +0x200 (from bl helper) = 0x265
    assert_eq!(
        emu.call_address(new_fn_pc, &[0x10]).unwrap(),
        0x265,
        "backend={backend:?} relocated adr+bl path failed"
    );

    // 8. 测试块内短分支跨超距展开 ADR 搬运 + 原函数头部被 BRK 覆写后仍安全执行
    let intra_old_pc = code_base + 0xA800;
    let intra_new_pc = far_base + 0x2000;
    let intra_orig = assemble(
        &format!(
            r#"
            cbz x0, skip
            adr x9, {const_pool_pc:#x}
            ldr x10, [x9]
            add x0, x0, x10
        skip:
            add x0, x0, #7
            ret
            "#
        ),
        intra_old_pc,
    )
    .expect("assemble intra_orig");
    let intra_reloc =
        relocate_instructions(&intra_orig, intra_old_pc, intra_new_pc).expect("relocate intra");
    // 故意用 brk #0 覆写原始块，证明重定位后的 cbz 跳转到新块内 skip 而绝不回跳原地址
    let poison = assemble("brk #0; brk #0; brk #0; brk #0; brk #0; brk #0", intra_old_pc).unwrap();
    emu.cpu_mut().mem_write(intra_old_pc, &poison).unwrap();
    emu.cpu_mut().mem_write(intra_new_pc, &intra_reloc).unwrap();
    let _ = emu
        .cpu_mut()
        .flush_cache(intra_new_pc, intra_new_pc + intra_reloc.len() as u64);
    assert_eq!(
        emu.call_address(intra_new_pc, &[0]).unwrap(),
        7,
        "backend={backend:?} intra-block cbz taken path failed"
    );
    assert_eq!(
        emu.call_address(intra_new_pc, &[0x10]).unwrap(),
        0x10 + 0x55 + 7,
        "backend={backend:?} intra-block fallthrough path failed"
    );
}

#[test]
fn test_good64_execute_on_unicorn() {
    run_good64_suite_on_backend(BackendKind::Unicorn);
}

#[cfg(feature = "dynarmic")]
#[test]
fn test_good64_execute_on_dynarmic() {
    run_good64_suite_on_backend(BackendKind::Dynarmic);
}

#[cfg(feature = "js")]
#[test]
fn test_good64_js_patch_asm_and_inline_jump() {
    use std::path::Path;
    use runidbg_arm64_emu_tracer::script::JsSession;

    let script = r#"
        (() => {
            const bytes = Emu.asm("mov x0, #0x42; ret", 0x1000);
            if (!(bytes instanceof Uint8Array) || bytes.length !== 8) {
                throw new Error("unexpected Emu.asm bytes len=" + bytes.length);
            }
            const adrBytes = Emu.asm("adr x1, 0x40001234", "0x40001000");
            const relocFar = Emu.relocateAsm(adrBytes, "0x40001000", 0x90000000n);
            if (!(relocFar instanceof Uint8Array) || relocFar.length < 8) {
                throw new Error("unexpected Emu.relocateAsm len=" + relocFar.length);
            }
            let threw = false;
            try { Emu.asm("nop", true); } catch (_) { threw = true; }
            if (!threw) throw new Error("expected Emu.asm(nop, true) to throw");
            const emu = Emu.create();
            const mod = emu.load("samples/libstatic-webp.so");
            const fnA = mod.symbol("WebPGetDecoderVersion");
            const fnB = fnA + 0x200;
            // 在可执行 .text 页内用 patchAsm 覆写 fnA 与 fnB，验证实时 Inline Hook 与 TB 缓存刷新
            const nA = emu.mem.patchAsm(fnA, `
                mov x0, #10
                ret
            `);
            const nB = emu.mem.patchAsm(fnB, `
                mov x1, #0x1000
                add x0, x0, x1
                ret
            `);
            const r1 = emu.call(fnA, 7);
            if (r1 !== 10) throw new Error("expected 10 before hook, got " + r1);
            // 用 inlineJump 把 fnA 直接重定向到 fnB
            const jLen = emu.mem.inlineJump(fnA, fnB);
            const r2 = emu.call(fnA, 7);
            if (r2 !== 0x1007) throw new Error("expected 0x1007 after inlineJump, got " + r2);
            return { nA, nB, jLen, r1, r2 };
        })()
    "#;
    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    let res = session.eval_json_string(script).unwrap();
    assert!(res.contains("\"r2\":4103"), "unexpected result: {res}");
}

#[cfg(feature = "mcp")]
#[test]
fn test_good64_mcp_emu_asm() {
    use serde_json::json;
    use std::path::Path;
    use runidbg_arm64_emu_tracer::script::mcp::McpServer;

    let mut srv = McpServer::new(Path::new("."), None).unwrap();
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "emu_asm",
            "arguments": {
                "source": "mov x0, #0x1337; ret",
                "addr": "0x40001000"
            }
        }
    });
    let resp_str = srv.handle_message(&req.to_string()).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["byteLen"], 8);
    assert_eq!(payload["patched"], false);
    assert!(payload["disasm"][0].as_str().unwrap().contains("0x1337"));
    assert!(payload["disasm"][1].as_str().unwrap().contains("ret"));

    // 校验 addr: null 与非 4 字节对齐尾部 .byte 回显
    let req_rem = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "emu_asm",
            "arguments": {
                "source": "nop; .byte 0xde, 0xad",
                "addr": null
            }
        }
    });
    let resp_rem: serde_json::Value =
        serde_json::from_str(&srv.handle_message(&req_rem.to_string()).unwrap()).unwrap();
    let payload_rem: serde_json::Value =
        serde_json::from_str(resp_rem["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload_rem["byteLen"], 6);
    assert_eq!(payload_rem["disasm"].as_array().unwrap().len(), 2);
    assert!(payload_rem["disasm"][1]
        .as_str()
        .unwrap()
        .contains(".byte 0xde, 0xad"));

    // 校验 patch: true 缺少 addr 时报错
    let req_bad_patch = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "emu_asm",
            "arguments": {
                "source": "nop",
                "patch": true,
                "emuId": 0
            }
        }
    });
    let resp_bad: serde_json::Value =
        serde_json::from_str(&srv.handle_message(&req_bad_patch.to_string()).unwrap()).unwrap();
    assert_eq!(resp_bad["result"]["isError"], true);
}
