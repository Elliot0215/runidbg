//! 确定性与 Golden 行为守卫测试（回应 Issue #1）
//!
//! 守卫目标：
//! 1. **双跑确定性**：相同输入在两个独立模拟器实例中必须产生 100% 逐位一致的堆分配地址序列、
//!    HLE `realloc`/`memalign`/`asprintf`/`free` 布局、PRNG 序列及开源样本函数输出；
//! 2. **跨版本 Golden 锚点**：固化当前 HLE 堆分配序列与 PRNG 序列的黄金值，
//!    未来任何对分配器、块头、回收复用或 PRNG 状态机的改动都会在 CI 显式暴露，避免静默漂移。

use std::path::PathBuf;

use runidbg_arm64_emu_tracer::loader::HleBuiltin;
use runidbg_arm64_emu_tracer::{AndroidEmulator, CpuBackend};
use unicorn_engine::unicorn_const::Prot;

fn emit_blr_target(insns: &mut Vec<u32>, target: u64) {
    let w0 = (target & 0xFFFF) as u32;
    let w1 = ((target >> 16) & 0xFFFF) as u32;
    let w2 = ((target >> 32) & 0xFFFF) as u32;
    let w3 = ((target >> 48) & 0xFFFF) as u32;
    insns.push(0xD280_0010 | (w0 << 5)); // movz x16, #w0
    if w1 != 0 {
        insns.push(0xF2A0_0010 | (w1 << 5)); // movk x16, #w1, lsl #16
    }
    if w2 != 0 {
        insns.push(0xF2C0_0010 | (w2 << 5)); // movk x16, #w2, lsl #32
    }
    if w3 != 0 {
        insns.push(0xF2E0_0010 | (w3 << 5)); // movk x16, #w3, lsl #48
    }
    insns.push(0xD63F_0200); // blr x16
}

fn write_insns(emu: &mut AndroidEmulator, base: u64, insns: &[u32]) {
    let mut bytes = Vec::with_capacity(insns.len() * 4);
    for &w in insns {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    emu.cpu_mut().mem_write(base, &bytes).unwrap();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GoldenRunOutput {
    webp_version: u64,
    heap_ptrs: [u64; 6],
    rand_seq: [u64; 4],
    realloc_payload: [u8; 8],
}

fn run_deterministic_workload() -> GoldenRunOutput {
    let so_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples/libstatic-webp.so");
    let mut emu = AndroidEmulator::builder()
        .hle_accel(true)
        .build()
        .expect("build emu");
    let module = emu.load_library(&so_path).expect("load libstatic-webp.so");
    let webp_ver_addr = module
        .find_symbol("WebPGetDecoderVersion")
        .expect("WebPGetDecoderVersion");
    let webp_version = emu.call_address(webp_ver_addr, &[]).expect("call webp ver");

    let code_base: u64 = 0x4800_0000;
    let data_base: u64 = 0x4810_0000;
    emu.cpu_mut().mem_map(code_base, 0x4000, Prot::ALL).unwrap();
    emu.cpu_mut()
        .mem_map(data_base, 0x4000, Prot::READ | Prot::WRITE)
        .unwrap();

    let fmt_addr = data_base;
    let out_ptrs = data_base + 0x100; // 6 x u64
    let out_rands = data_base + 0x200; // 4 x u64
    let strp_slot = data_base + 0x300;
    let pm_slot = data_base + 0x308;
    emu.cpu_mut().mem_write(fmt_addr, b"golden!\0").unwrap();

    let malloc_fn = emu.register_hle_builtin("malloc", HleBuiltin::Malloc).unwrap();
    let realloc_fn = emu.register_hle_builtin("realloc", HleBuiltin::Realloc).unwrap();
    let calloc_fn = emu.register_hle_builtin("calloc", HleBuiltin::Calloc).unwrap();
    let pm_fn = emu
        .register_hle_builtin("posix_memalign", HleBuiltin::PosixMemalign)
        .unwrap();
    let asprintf_fn = emu
        .register_hle_builtin("asprintf", HleBuiltin::Asprintf)
        .unwrap();
    let free_fn = emu.register_hle_builtin("free", HleBuiltin::Free).unwrap();
    let srand_fn = emu.register_hle_builtin("srand", HleBuiltin::Srand).unwrap();
    let rand_fn = emu.register_hle_builtin("rand", HleBuiltin::Rand).unwrap();

    let mut insns: Vec<u32> = vec![
        0xAA1E_03FB, // mov x27, x30
        0xAA00_03F3, // mov x19, x0 (fmt_addr)
        0xAA01_03F4, // mov x20, x1 (out_ptrs)
        0xAA02_03F5, // mov x21, x2 (out_rands)
        0xAA03_03F6, // mov x22, x3 (strp_slot)
        0xAA04_03F7, // mov x23, x4 (pm_slot)
        // [0] p0 = malloc(48)
        0xD280_0600, // mov x0, #48
    ];
    emit_blr_target(&mut insns, malloc_fn);
    insns.extend_from_slice(&[
        0xF900_0280, // str x0, [x20, #0]
        0xAA00_03F8, // mov x24, x0
        // [1] p1 = realloc(p0, 96)  (释放 p0 并复用/推进)
        0xAA18_03E0, // mov x0, x24
        0xD280_0C01, // mov x1, #96
    ]);
    emit_blr_target(&mut insns, realloc_fn);
    insns.extend_from_slice(&[
        0xF900_0680, // str x0, [x20, #8]
        // [2] p2 = calloc(1, 32)    (应精确复用刚被 realloc 释放的 p0 槽位！)
        0xD280_0020, // mov x0, #1
        0xD280_0401, // mov x1, #32
    ]);
    emit_blr_target(&mut insns, calloc_fn);
    insns.extend_from_slice(&[
        0xF900_0A80, // str x0, [x20, #16]
        // [3] posix_memalign(&pm_slot, 64, 40)
        0xAA17_03E0, // mov x0, x23
        0xD280_0801, // mov x1, #64
        0xD280_0502, // mov x2, #40
    ]);
    emit_blr_target(&mut insns, pm_fn);
    insns.extend_from_slice(&[
        0xF940_02E0, // ldr x0, [x23]
        0xF900_0E80, // str x0, [x20, #24]
        // [4] asprintf(&strp_slot, "golden!")
        0xAA16_03E0, // mov x0, x22
        0xAA13_03E1, // mov x1, x19
    ]);
    emit_blr_target(&mut insns, asprintf_fn);
    insns.extend_from_slice(&[
        0xF940_02C0, // ldr x0, [x22]
        0xF900_1280, // str x0, [x20, #32]
        // [5] p5 = realloc(*strp_slot, 64) (验证 asprintf 16B 头拷贝完整)
        0xD280_0801, // mov x1, #64
    ]);
    emit_blr_target(&mut insns, realloc_fn);
    insns.extend_from_slice(&[
        0xF900_1680, // str x0, [x20, #40]
        // free(pm_slot)
        0xF940_02E0, // ldr x0, [x23]
    ]);
    emit_blr_target(&mut insns, free_fn);
    insns.extend_from_slice(&[
        // srand(0x12345678)
        0xD28A_CF00, // movz x0, #0x5678
        0xF2A2_4680, // movk x0, #0x1234, lsl #16
    ]);
    emit_blr_target(&mut insns, srand_fn);
    for k in 0..4u32 {
        emit_blr_target(&mut insns, rand_fn);
        insns.push(0xF900_02A0 | (k << 10)); // str x0, [x21, #(k*8)]
    }
    insns.extend_from_slice(&[
        0xAA1B_03FE, // mov x30, x27
        0xD65F_03C0, // ret
    ]);
    write_insns(&mut emu, code_base, &insns);

    emu.call_address(
        code_base,
        &[fmt_addr, out_ptrs, out_rands, strp_slot, pm_slot],
    )
    .expect("run workload");

    let mut ptrs = [0u64; 6];
    for (i, slot) in ptrs.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        emu.cpu()
            .mem_read(out_ptrs + (i as u64) * 8, &mut b)
            .unwrap();
        *slot = u64::from_le_bytes(b);
    }
    let mut rands = [0u64; 4];
    for (i, slot) in rands.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        emu.cpu()
            .mem_read(out_rands + (i as u64) * 8, &mut b)
            .unwrap();
        *slot = u64::from_le_bytes(b);
    }
    let mut realloc_payload = [0u8; 8];
    emu.cpu().mem_read(ptrs[5], &mut realloc_payload).unwrap();

    GoldenRunOutput {
        webp_version,
        heap_ptrs: ptrs,
        rand_seq: rands,
        realloc_payload,
    }
}

#[test]
fn test_determinism_and_golden_hle_heap_and_prng() {
    // 1. 双跑严格一致（同输入跑两次断言所有输出逐位一致）
    let run1 = run_deterministic_workload();
    let run2 = run_deterministic_workload();
    assert_eq!(
        run1, run2,
        "two identical runs must produce bit-for-bit identical outputs"
    );

    // 2. 语义不变量验证：
    //    - calloc(1, 32) 必须复用刚被 realloc(p0, 96) 释放的 p0 槽位
    assert_eq!(
        run1.heap_ptrs[2], run1.heap_ptrs[0],
        "calloc(1, 32) must reuse the old block freed by realloc"
    );
    //    - posix_memalign(..., 64, 40) 返回指针严格 64 字节对齐
    assert_eq!(run1.heap_ptrs[3] % 64, 0);
    //    - realloc(asprintf("golden!"), 64) 必须完整保留原始载荷
    assert_eq!(&run1.realloc_payload, b"golden!\0");

    // 3. Golden 锚点（v0.4.2 基准）：任何对 HLE 堆分配、回收策略或 PRNG 状态机的静默修改都会立即触发红灯
    assert_eq!(run1.webp_version, 0x0001_0302);
    assert_eq!(
        run1.heap_ptrs,
        [
            0x5000_0010, // p0 = malloc(48)
            0x5000_0050, // p1 = realloc(p0, 96) -> frees p0
            0x5000_0010, // p2 = calloc(1, 32)   -> reuses p0!
            0x5000_00c0, // p3 = posix_memalign(64, 40)
            0x5000_0100, // p4 = asprintf("golden!")
            0x5000_0120, // p5 = realloc(p4, 64)
        ],
        "HLE heap layout golden changed! Actual: {:x?}",
        run1.heap_ptrs
    );
    assert_eq!(
        run1.rand_seq,
        [0x1474_95d4, 0x1832_3685, 0x3d49_29ee, 0x072f_37fc],
        "PRNG golden sequence changed! Actual: {:x?}",
        run1.rand_seq
    );
}

#[test]
fn test_rng_streams_isolated_between_libc_rand_and_os_entropy() {
    use runidbg_arm64_emu_tracer::backend::BackendWithData;
    use runidbg_arm64_emu_tracer::TapeSelector;

    // 验证：
    // 1. 反复调用 srand()/rand() 绝不影响 OS 熵源（arc4random_buf / getrandom / /dev/urandom）；
    // 2. 反复消费 OS 熵源绝不影响 libc rand() 序列；
    // 3. .rtape 磁带保存与恢复完整保留两条独立随机流状态。
    let mut emu_clean = AndroidEmulator::builder().hle_accel(true).build().unwrap();
    let mut emu_noisy = AndroidEmulator::builder().hle_accel(true).build().unwrap();

    // 在 noisy 实例中先大量扰动 libc_rand_state（srand + 64 次 rand）
    {
        let vfs = &mut emu_noisy.cpu_mut().get_data_mut().vfs;
        vfs.seed_libc_rand(0xDEAD_BEEF);
        for _ in 0..64 {
            let _ = vfs.next_libc_rand();
        }
    }

    // 两个实例的 OS 熵源输出必须 100% 一致！
    let mut os_clean = [0u8; 32];
    let mut os_noisy = [0u8; 32];
    emu_clean.cpu_mut().get_data_mut().vfs.fill_random(&mut os_clean);
    emu_noisy.cpu_mut().get_data_mut().vfs.fill_random(&mut os_noisy);
    assert_eq!(
        os_clean, os_noisy,
        "srand()/rand() must NEVER perturb OS /dev/urandom/getrandom/arc4random stream"
    );

    // 反之：大量消费 OS 熵源绝不影响 libc rand() 序列！
    let mut junk = [0u8; 256];
    emu_clean.cpu_mut().get_data_mut().vfs.fill_random(&mut junk);
    emu_clean.cpu_mut().get_data_mut().vfs.seed_libc_rand(0x1234_5678);
    emu_noisy.cpu_mut().get_data_mut().vfs.seed_libc_rand(0x1234_5678);
    emu_noisy.cpu_mut().get_data_mut().vfs.fill_random(&mut junk);
    let r_clean: Vec<u32> = (0..8)
        .map(|_| emu_clean.cpu_mut().get_data_mut().vfs.next_libc_rand())
        .collect();
    let r_noisy: Vec<u32> = (0..8)
        .map(|_| emu_noisy.cpu_mut().get_data_mut().vfs.next_libc_rand())
        .collect();
    assert_eq!(
        r_clean, r_noisy,
        "OS entropy consumption must NEVER perturb libc rand() stream"
    );

    // .rtape 往返持久化同时保留两条独立流状态
    let dir = std::env::temp_dir().join(format!("runidbg_rng_iso_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let tape = dir.join("rng2.rtape");
    emu_clean.save_tape(&tape, "cp0").expect("save tape");
    let (mut restored, _) = AndroidEmulator::from_tape_with_builder(
        &tape,
        &TapeSelector::Label("cp0".to_string()),
        AndroidEmulator::builder(),
    )
    .expect("load tape");

    let mut next_os_orig = [0u8; 16];
    let mut next_os_rest = [0u8; 16];
    emu_clean.cpu_mut().get_data_mut().vfs.fill_random(&mut next_os_orig);
    restored.cpu_mut().get_data_mut().vfs.fill_random(&mut next_os_rest);
    assert_eq!(next_os_orig, next_os_rest);

    let next_rand_orig = emu_clean.cpu_mut().get_data_mut().vfs.next_libc_rand();
    let next_rand_rest = restored.cpu_mut().get_data_mut().vfs.next_libc_rand();
    assert_eq!(next_rand_orig, next_rand_rest);

    let _ = std::fs::remove_dir_all(&dir);
}
