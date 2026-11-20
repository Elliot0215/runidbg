use std::time::Instant;

use runidbg_arm64_emu_tracer::cpu::{CpuContext, RET_MAGIC_ADDR};
use runidbg_arm64_emu_tracer::memory::{MemoryManager, PAGE_SIZE};
use runidbg_arm64_emu_tracer::os::syscall::{SYS_CLOCK_GETTIME, SYS_NANOSLEEP, SYS_PTRACE};
use runidbg_arm64_emu_tracer::os::{attach_syscall_hook, TaskScheduler, VirtualFs};
use runidbg_arm64_emu_tracer::snapshot::EmuSnapshot;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

fn write_insns<D>(uc: &mut Unicorn<'_, D>, addr: u64, insns: &[u32]) {
    let mut raw = Vec::with_capacity(insns.len() * 4);
    for &i in insns {
        raw.extend_from_slice(&i.to_le_bytes());
    }
    uc.mem_write(addr, &raw).unwrap();
}

#[test]
fn test_cooperative_task_scheduler_round_robin() {
    let mut uc = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();
    let mut mem = MemoryManager::new(0x5000_0000, 0x0100_0000);
    mem.init_heap(&mut uc).unwrap();
    CpuContext::init(&mut uc, &mut mem).unwrap();

    let code_base = 0x4300_0000u64;
    mem.map_labeled(&mut uc, code_base, PAGE_SIZE, Prot::ALL, "[test:worker]", 0)
        .unwrap();

    // 工作线程函数：计算 sum(1..=X0) 并返回 X0
    //   MOV  X1, #0        (acc = 0)
    // loop:
    //   CBZ  X0, done      (+12 bytes -> insn 4)
    //   ADD  X1, X1, X0
    //   SUB  X0, X0, #1
    //   B    loop          (-12 bytes -> insn 1)
    // done:
    //   MOV  X0, X1
    //   RET
    let insns: [u32; 7] = [
        0xD280_0001, // MOVZ X1, #0
        0xB400_0080, // CBZ  X0, +16 (pc + 16 -> insn 5: MOV X0, X1)
        0x8B00_0021, // ADD  X1, X1, X0
        0xD100_0400, // SUB  X0, X0, #1
        0x17FF_FFFD, // B    -12 (回到 CBZ)
        0xAA01_03E0, // MOV  X0, X1
        0xD65F_03C0, // RET
    ];
    write_insns(&mut uc, code_base, &insns);

    let mut sched = TaskScheduler::new();
    let tid1 = sched.spawn_thread(&mut uc, &mut mem, code_base, 10).unwrap();
    let tid2 = sched.spawn_thread(&mut uc, &mut mem, code_base, 20).unwrap();

    // 每次仅执行 4 条指令即强制切换上下文，充分验证时间片轮转与快照保存/恢复
    let total_slices = sched.run_until_idle(&mut uc, 4).unwrap();
    assert!(total_slices >= 10, "应经历多次协作式上下文切换");

    assert_eq!(sched.join_result(tid1), Some(55)); // 1+2+...+10
    assert_eq!(sched.join_result(tid2), Some(210)); // 1+2+...+20
}

struct AntiDebugState {
    mem: MemoryManager,
    vfs: VirtualFs,
}

#[test]
fn test_antidebug_ptrace_and_virtual_nanosleep() {
    let mut uc = Unicorn::new_with_data(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN,
        AntiDebugState {
            mem: MemoryManager::new(0x5000_0000, 0x0100_0000),
            vfs: VirtualFs::new("com.test.antidebug"),
        },
    )
    .unwrap();

    let mut mem = MemoryManager::new(0x5000_0000, 0x0100_0000);
    mem.init_heap(&mut uc).unwrap();
    CpuContext::init(&mut uc, &mut mem).unwrap();

    let code_base = 0x4310_0000u64;
    let data_base = 0x4311_0000u64;
    mem.map_labeled(&mut uc, code_base, PAGE_SIZE, Prot::ALL, "[test:ad_code]", 0)
        .unwrap();
    mem.map_labeled(
        &mut uc,
        data_base,
        PAGE_SIZE,
        Prot::READ | Prot::WRITE,
        "[test:ad_data]",
        0,
    )
    .unwrap();

    uc.get_data_mut().mem = mem;
    attach_syscall_hook(&mut uc, |s| (&mut s.mem, &mut s.vfs)).unwrap();

    // 写入 5 秒 nanosleep 请求 timespec { tv_sec: 5, tv_nsec: 0 }
    let req_ts_addr = data_base;
    let out_ts_addr = data_base + 0x20;
    uc.mem_write(req_ts_addr, &5i64.to_le_bytes()).unwrap();
    uc.mem_write(req_ts_addr + 8, &0i64.to_le_bytes()).unwrap();

    let before_ns = uc.get_data().vfs.mono_clock_ns;

    // 1. ptrace(PTRACE_TRACEME=0, 0, 0, 0) -> X19 保存返回值
    // 2. nanosleep(req_ts_addr, 0) -> 瞬间快进虚拟时钟 5 秒
    // 3. clock_gettime(1, out_ts_addr)
    // 4. 返回 X19 (ptrace 结果)
    let insns: [u32; 14] = [
        0xD280_0000,                                // MOVZ X0, #0
        0xD280_0001,                                // MOVZ X1, #0
        0xD280_0002,                                // MOVZ X2, #0
        0xD280_0003,                                // MOVZ X3, #0
        0xD280_0008 | ((SYS_PTRACE as u32) << 5),   // MOVZ X8, #SYS_PTRACE
        0xD400_0001,                                // SVC  #0
        0xAA00_03F3,                                // MOV  X19, X0
        0xAA14_03E0,                                // MOV  X0, X20 (req_ts_addr)
        0xD280_0001,                                // MOVZ X1, #0
        0xD280_0008 | ((SYS_NANOSLEEP as u32) << 5),// MOVZ X8, #SYS_NANOSLEEP
        0xD400_0001,                                // SVC  #0
        0xD280_0020,                                // MOVZ X0, #1 (CLOCK_MONOTONIC)
        0xAA15_03E1,                                // MOV  X1, X21 (out_ts_addr)
        0xD280_0008 | ((SYS_CLOCK_GETTIME as u32) << 5),
    ];
    let tail: [u32; 3] = [
        0xD400_0001, // SVC #0
        0xAA13_03E0, // MOV X0, X19
        0xD65F_03C0, // RET
    ];
    let mut full = insns.to_vec();
    full.extend_from_slice(&tail);
    write_insns(&mut uc, code_base, &full);

    let wall_start = Instant::now();
    uc.reg_write(RegisterARM64::X20, req_ts_addr).unwrap();
    uc.reg_write(RegisterARM64::X21, out_ts_addr).unwrap();
    uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR).unwrap();
    uc.emu_start(code_base, RET_MAGIC_ADDR, 0, 1000).unwrap();
    let wall_elapsed = wall_start.elapsed();

    // ptrace 返回 0（绕过反调试）
    assert_eq!(uc.reg_read(RegisterARM64::X0).unwrap(), 0);
    // 宿主真实耗时应远小于 1 秒（未发生真实睡眠）
    assert!(wall_elapsed.as_millis() < 500);
    // 虚拟时钟应至少前进 5 秒
    let after_ns = uc.get_data().vfs.mono_clock_ns;
    assert!(after_ns >= before_ns + 5_000_000_000);
}

#[test]
fn test_emu_snapshot_batch_replay() {
    let mut uc = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();
    let mut mem = MemoryManager::new(0x5000_0000, 0x0010_0000);
    mem.init_heap(&mut uc).unwrap();
    CpuContext::init(&mut uc, &mut mem).unwrap();

    let code_base = 0x4320_0000u64;
    let data_base = 0x4321_0000u64;
    mem.map_labeled(&mut uc, code_base, PAGE_SIZE, Prot::READ | Prot::EXEC, "[test:snap_code]", 0)
        .unwrap();
    mem.map_labeled(
        &mut uc,
        data_base,
        PAGE_SIZE,
        Prot::READ | Prot::WRITE,
        "[test:snap_data]",
        0,
    )
    .unwrap();

    // 全局状态变量初始值为 100
    mem.write_u64(&mut uc, data_base, 100).unwrap();

    // 有副作用函数：*X1 += X0; return *X1;
    let insns: [u32; 4] = [
        0xF940_0022, // LDR X2, [X1]
        0x8B00_0040, // ADD X0, X2, X0
        0xF900_0020, // STR X0, [X1]
        0xD65F_03C0, // RET
    ];
    write_insns(&mut uc, code_base, &insns);

    // 冻结初始化完毕后的干净状态快照
    let snapshot = EmuSnapshot::capture(&uc, &mem).unwrap();
    let (region_cnt, total_bytes) = snapshot.stats();
    assert!(region_cnt >= 3 && total_bytes > 0);

    // 批量回放 50 次不同输入，每次回滚快照，确保全局状态不会被前一次执行污染
    for i in 0u64..50 {
        snapshot.restore(&mut uc).unwrap();
        uc.reg_write(RegisterARM64::X0, i).unwrap();
        uc.reg_write(RegisterARM64::X1, data_base).unwrap();
        uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR).unwrap();
        uc.emu_start(code_base, RET_MAGIC_ADDR, 0, 100).unwrap();

        let ret = uc.reg_read(RegisterARM64::X0).unwrap();
        assert_eq!(ret, 100 + i, "第 {i} 次快照回放结果应为 100 + {i}");
    }
}
