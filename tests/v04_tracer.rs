use std::fs;

use runidbg_arm64_emu_tracer::cpu::{CpuContext, RET_MAGIC_ADDR};
use runidbg_arm64_emu_tracer::memory::{MemoryManager, PAGE_SIZE};
use runidbg_arm64_emu_tracer::tracer::{
    attach_code_hook, attach_mem_trace_hook, BinaryTracer, ExtKind, TraceLevel, TraceReader,
};
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

struct TracerTestState {
    tracer: BinaryTracer,
}

#[test]
fn test_dual_stream_full_trace_and_offline_reader() {
    let idx_path = std::env::temp_dir().join("arm64_emu_v04_test.idx");
    let ext_path = std::env::temp_dir().join("arm64_emu_v04_test.ext");

    let mut tracer =
        BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 128, 256, TraceLevel::Full).unwrap();

    let code_base = 0x4200_0000u64;
    let data_base = 0x4201_0000u64;
    // 仅追踪 code_base 这一页（验证地址过滤器）
    tracer.filter_mut().allow_range(code_base, code_base + PAGE_SIZE);

    let mut uc = Unicorn::new_with_data(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN,
        TracerTestState { tracer },
    )
    .unwrap();
    let mut mem = MemoryManager::new(0x5000_0000, 0x0100_0000);
    mem.init_heap(&mut uc).unwrap();
    CpuContext::init(&mut uc, &mut mem).unwrap();

    mem.map_labeled(&mut uc, code_base, PAGE_SIZE, Prot::ALL, "[test:v04_code]", 0)
        .unwrap();
    mem.map_labeled(
        &mut uc,
        data_base,
        PAGE_SIZE,
        Prot::READ | Prot::WRITE,
        "[test:v04_data]",
        0,
    )
    .unwrap();

    // 写入测试代码：
    //   MOV X1, #0x1337
    //   STR X1, [X0]         (写入 data_base，触发 MemWrite)
    //   LDR X2, [X0]         (读回 data_base，触发 MemRead)
    //   ADD X0, X2, #1       (X0 = 0x1338)
    //   RET
    let insns: [u32; 5] = [
        0xD282_66E1, // MOVZ X1, #0x1337
        0xF900_0001, // STR  X1, [X0]
        0xF940_0002, // LDR  X2, [X0]
        0x9100_0440, // ADD  X0, X2, #1
        0xD65F_03C0, // RET
    ];
    let mut code = Vec::new();
    for &i in &insns {
        code.extend_from_slice(&i.to_le_bytes());
    }
    uc.mem_write(code_base, &code).unwrap();

    attach_code_hook(&mut uc, 0, u64::MAX, |s| &mut s.tracer).unwrap();
    attach_mem_trace_hook(&mut uc, data_base, data_base + PAGE_SIZE, |s| &mut s.tracer).unwrap();

    uc.reg_write(RegisterARM64::X0, data_base).unwrap();
    uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR).unwrap();
    uc.emu_start(code_base, RET_MAGIC_ADDR, 0, 1000).unwrap();

    assert_eq!(uc.reg_read(RegisterARM64::X0).unwrap(), 0x1338);
    uc.get_data().tracer.flush().unwrap();

    // 使用离线 TraceReader 零拷贝验证双流落盘数据
    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    assert_eq!(reader.len(), 5, "应精确记录 5 条指令");
    assert!(reader.ext_len() >= 2, "应记录至少 1 次 MemWrite 与 1 次 MemRead");

    // 检索寄存器写入 0x1337 的记录
    let val_hits = reader.search_value(0x1337);
    assert!(!val_hits.is_empty(), "应检索到 X1=0x1337 的寄存器增量变化");

    // 检索对 data_base 的访存事件
    let mem_hits = reader.search_mem_addr(data_base);
    assert_eq!(mem_hits.len(), 2, "应捕获对 data_base 的 1 次写与 1 次读");
    assert_eq!(ExtKind::from_u8(mem_hits[0].kind), Some(ExtKind::MemWrite));
    let w_val = mem_hits[0].value;
    assert_eq!(w_val, 0x1337);
    assert_eq!(ExtKind::from_u8(mem_hits[1].kind), Some(ExtKind::MemRead));
    let r_val = mem_hits[1].value;
    assert_eq!(r_val, 0x1337);

    // 验证 IDAPython 与 Binary Ninja 覆盖率导出脚本
    let ida = reader.export_ida_python(code_base);
    assert!(ida.contains("idc.set_color"));
    assert!(ida.contains("0x10,"));
    let bn = reader.export_binja_python(code_base);
    assert!(bn.contains("set_user_instr_highlight"));

    let _ = fs::remove_file(idx_path);
    let _ = fs::remove_file(ext_path);
}

#[test]
fn test_fast_trace_mode_zero_reg_diff() {
    let tracer = BinaryTracer::new_in_memory_with_level(32, TraceLevel::Fast);
    let mut uc = Unicorn::new_with_data(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN,
        TracerTestState { tracer },
    )
    .unwrap();
    let mut mem = MemoryManager::new(0x5000_0000, 0x0100_0000);
    mem.init_heap(&mut uc).unwrap();
    CpuContext::init(&mut uc, &mut mem).unwrap();

    let code_base = 0x4210_0000u64;
    mem.map_labeled(&mut uc, code_base, PAGE_SIZE, Prot::ALL, "[test:fast]", 0)
        .unwrap();
    let insns: [u32; 2] = [
        0xD280_0540, // MOVZ X0, #42
        0xD65F_03C0, // RET
    ];
    let mut code = Vec::new();
    for &i in &insns {
        code.extend_from_slice(&i.to_le_bytes());
    }
    uc.mem_write(code_base, &code).unwrap();

    attach_code_hook(&mut uc, code_base, code_base + 8, |s| &mut s.tracer).unwrap();
    uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR).unwrap();
    uc.emu_start(code_base, RET_MAGIC_ADDR, 0, 100).unwrap();

    let recs = uc.get_data().tracer.records();
    assert_eq!(recs.len(), 2);
    // Fast 模式下不采样寄存器，primary_reg_id 恒为 0xFF
    assert_eq!(recs[0].primary_reg_id, 0xFF);
    assert_eq!(recs[1].primary_reg_id, 0xFF);
}
