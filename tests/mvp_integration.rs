use std::fs;
use std::mem::size_of;

use runidbg_arm64_emu_tracer::cpu::{CpuContext, RET_MAGIC_ADDR};
use runidbg_arm64_emu_tracer::loader::ElfLoader;
use runidbg_arm64_emu_tracer::memory::{align_down, align_up, MemoryManager, PAGE_SIZE};
use runidbg_arm64_emu_tracer::tracer::{attach_code_hook, BinaryTracer, TraceRecord};
use unicorn_engine::unicorn_const::{Arch, Mode};
use unicorn_engine::{RegisterARM64, Unicorn};

struct TestState {
    tracer: BinaryTracer,
}

/// 构造一个最小合法的 64-bit AArch64 ELF `.so` 镜像：
/// - 1 个 PT_LOAD 段（RWX，包含代码、.dynamic、.dynsym、.dynstr、.rela.dyn 与可重定位指针槽）
/// - 1 个 PT_DYNAMIC 段（供 goblin 零拷贝解析动态符号表与重定位表）
/// - 导出符号 `neon_add`：使用 NEON/FP 寄存器计算 X0 + X1 并返回，验证 CPACR_EL1 开启成功
/// - 1 条 R_AARCH64_RELATIVE 重定位项，验证重定位回填 `base + addend` 正确
fn build_minimal_aarch64_so() -> (Vec<u8>, u64, i64) {
    // ELF 布局（全部在同一个 4KB 页内）：
    // 0x0000..0x0040 : Elf64_Ehdr (64B)
    // 0x0040..0x00B0 : 2 * Elf64_Phdr (PT_LOAD + PT_DYNAMIC, 112B)
    // 0x0100..0x0114 : neon_add 机器码 (5 条 ARM64 指令 = 20B)
    // 0x0200..0x0280 : .dynamic (8 项 * 16B = 128B)
    // 0x0300..0x0330 : .dynsym (2 项 * 24B = 48B: NULL + neon_add)
    // 0x0340..0x0350 : .dynstr ("\0neon_add\0")
    // 0x0380..0x0398 : .rela.dyn (1 项 * 24B: R_AARCH64_RELATIVE)
    // 0x0400..0x0408 : 被重定位的目标指针槽位
    const CODE_OFF: u64 = 0x0100;
    const DYN_OFF: u64 = 0x0200;
    const DYNSYM_OFF: u64 = 0x0300;
    const DYNSTR_OFF: u64 = 0x0340;
    const RELA_OFF: u64 = 0x0380;
    const HASH_OFF: u64 = 0x03B0;
    const RELOC_SLOT_OFF: u64 = 0x0400;
    const RELOC_ADDEND: i64 = 0x0100;
    const FILE_SIZE: usize = 0x0500;

    let mut img = vec![0u8; FILE_SIZE];

    let put_u16 = |buf: &mut [u8], off: usize, v: u16| {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    };
    let put_u32 = |buf: &mut [u8], off: usize, v: u32| {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    let put_u64 = |buf: &mut [u8], off: usize, v: u64| {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };
    let put_i64 = |buf: &mut [u8], off: usize, v: i64| {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };

    // --- 1. Elf64_Ehdr ---
    img[0..4].copy_from_slice(b"\x7fELF");
    img[4] = 2; // ELFCLASS64
    img[5] = 1; // ELFDATA2LSB (Little Endian)
    img[6] = 1; // EV_CURRENT
    put_u16(&mut img, 16, 3); // e_type = ET_DYN
    put_u16(&mut img, 18, 183); // e_machine = EM_AARCH64 (183)
    put_u32(&mut img, 20, 1); // e_version = EV_CURRENT
    put_u64(&mut img, 24, CODE_OFF); // e_entry
    put_u64(&mut img, 32, 0x40); // e_phoff
    put_u64(&mut img, 40, 0); // e_shoff (无节头，纯 PT_DYNAMIC)
    put_u16(&mut img, 52, 64); // e_ehsize
    put_u16(&mut img, 54, 56); // e_phentsize
    put_u16(&mut img, 56, 2); // e_phnum (PT_LOAD + PT_DYNAMIC)

    // --- 2. Elf64_Phdr[0]: PT_LOAD ---
    let ph0 = 0x40;
    put_u32(&mut img, ph0, 1); // p_type = PT_LOAD
    put_u32(&mut img, ph0 + 4, 7); // p_flags = PF_R | PF_W | PF_X
    put_u64(&mut img, ph0 + 8, 0); // p_offset
    put_u64(&mut img, ph0 + 16, 0); // p_vaddr
    put_u64(&mut img, ph0 + 24, 0); // p_paddr
    put_u64(&mut img, ph0 + 32, FILE_SIZE as u64); // p_filesz
    put_u64(&mut img, ph0 + 40, FILE_SIZE as u64); // p_memsz
    put_u64(&mut img, ph0 + 48, PAGE_SIZE); // p_align

    // --- 3. Elf64_Phdr[1]: PT_DYNAMIC ---
    let ph1 = 0x40 + 56;
    put_u32(&mut img, ph1, 2); // p_type = PT_DYNAMIC
    put_u32(&mut img, ph1 + 4, 6); // p_flags = PF_R | PF_W
    put_u64(&mut img, ph1 + 8, DYN_OFF);
    put_u64(&mut img, ph1 + 16, DYN_OFF);
    put_u64(&mut img, ph1 + 24, DYN_OFF);
    put_u64(&mut img, ph1 + 32, 9 * 16);
    put_u64(&mut img, ph1 + 40, 9 * 16);
    put_u64(&mut img, ph1 + 48, 8);

    // --- 4. ARM64 NEON 函数 neon_add(x0, x1) -> x0 + x1 ---
    // 若 CPACR_EL1 未开启 NEON/FP，执行 fmov d0, x0 时将直接触发异常
    let insns: [u32; 5] = [
        0x9E67_0000, // fmov d0, x0
        0x9E67_0021, // fmov d1, x1
        0x5EE1_8400, // add  d0, d0, d1  (NEON 64-bit scalar SIMD add)
        0x9E66_0000, // fmov x0, d0
        0xD65F_03C0, // ret
    ];
    for (i, &insn) in insns.iter().enumerate() {
        put_u32(&mut img, CODE_OFF as usize + i * 4, insn);
    }

    // --- 5. .dynstr ---
    let strtab = b"\0neon_add\0";
    img[DYNSTR_OFF as usize..DYNSTR_OFF as usize + strtab.len()].copy_from_slice(strtab);

    // --- 6. .dynsym ---
    // index 0: STN_UNDEF (全 0)
    // index 1: neon_add (st_name=1, st_info=STB_GLOBAL|STT_FUNC=0x12, st_shndx=1, st_value=CODE_OFF)
    let sym1 = DYNSYM_OFF as usize + 24;
    put_u32(&mut img, sym1, 1); // st_name -> "neon_add"
    img[sym1 + 4] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
    put_u16(&mut img, sym1 + 6, 1); // st_shndx (non-zero)
    put_u64(&mut img, sym1 + 8, CODE_OFF); // st_value
    put_u64(&mut img, sym1 + 16, 20); // st_size

    // --- 7. .rela.dyn (R_AARCH64_RELATIVE = 1027) ---
    let rela0 = RELA_OFF as usize;
    put_u64(&mut img, rela0, RELOC_SLOT_OFF); // r_offset
    put_u64(&mut img, rela0 + 8, 1027); // r_info = R_AARCH64_RELATIVE (1027)
    put_i64(&mut img, rela0 + 16, RELOC_ADDEND); // r_addend

    // --- 8. SysV DT_HASH (nbucket=1, nchain=2，告知 goblin dynsym 共有 2 个表项) ---
    let hash0 = HASH_OFF as usize;
    put_u32(&mut img, hash0, 1); // nbucket = 1
    put_u32(&mut img, hash0 + 4, 2); // nchain = 2 (STN_UNDEF + neon_add)
    put_u32(&mut img, hash0 + 8, 1); // bucket[0] = 1
    put_u32(&mut img, hash0 + 12, 0); // chain[0] = 0
    put_u32(&mut img, hash0 + 16, 0); // chain[1] = 0

    // --- 9. .dynamic ---
    let dyn_entries: [(u64, u64); 9] = [
        (4, HASH_OFF),                 // DT_HASH
        (5, DYNSTR_OFF),               // DT_STRTAB
        (6, DYNSYM_OFF),               // DT_SYMTAB
        (10, strtab.len() as u64),     // DT_STRSZ
        (11, 24),                      // DT_SYMENT
        (7, RELA_OFF),                 // DT_RELA
        (8, 24),                       // DT_RELASZ
        (9, 24),                       // DT_RELAENT
        (0, 0),                        // DT_NULL
    ];
    for (i, &(tag, val)) in dyn_entries.iter().enumerate() {
        let off = DYN_OFF as usize + i * 16;
        put_u64(&mut img, off, tag);
        put_u64(&mut img, off + 8, val);
    }

    (img, RELOC_SLOT_OFF, RELOC_ADDEND)
}

#[test]
fn test_align_helpers() {
    assert_eq!(align_down(0x1234, PAGE_SIZE), 0x1000);
    assert_eq!(align_up(0x1234, PAGE_SIZE), 0x2000);
    assert_eq!(align_up(0x2000, PAGE_SIZE), 0x2000);
}

#[test]
fn test_end_to_end_elf_neon_and_tracer() {
    let (elf_bytes, reloc_slot_off, reloc_addend) = build_minimal_aarch64_so();
    let module_base = 0x4000_0000u64;

    let tracer = BinaryTracer::new_in_memory(1024);
    let mut uc = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, TestState { tracer })
        .expect("创建 Unicorn 实例失败");

    let mut mem = MemoryManager::new(0x5000_0000, 0x0010_0000);
    mem.init_heap(&mut uc).expect("初始化堆失败");

    let cpu = CpuContext::init(&mut uc, &mut mem).expect("初始化 CPU 上下文失败");

    let module = ElfLoader::load_bytes(
        &mut uc,
        &mut mem,
        &elf_bytes,
        "libsynthetic.so".to_string(),
        module_base,
    )
    .expect("加载合成 ARM64 ELF 失败");

    // 1. 验证 R_AARCH64_RELATIVE 重定位回填正确
    let relocated_val = mem
        .read_u64(&uc, module_base + reloc_slot_off)
        .expect("读取重定位槽位失败");
    assert_eq!(
        relocated_val,
        module_base.wrapping_add_signed(reloc_addend),
        "R_AARCH64_RELATIVE 重定位结果不匹配"
    );

    // 2. 查找导出符号 neon_add
    let func_addr = module.find_symbol("neon_add").expect("未找到 neon_add 符号");

    // 3. 挂载高速 Trace Hook
    let hook_id = attach_code_hook(
        &mut uc,
        module.base_addr,
        module.base_addr + module.image_size,
        |s| &mut s.tracer,
    )
    .expect("挂载 Trace Hook 失败");

    // 4. 传入 X0=0x1234, X1=0x5678 执行 NEON 运算
    cpu.prepare_call(&mut uc, &[0x1234, 0x5678])
        .expect("准备调用帧失败");
    uc.emu_start(func_addr, RET_MAGIC_ADDR, 0, 0)
        .expect("模拟执行 neon_add 失败（若 CPACR_EL1 未正确开启 NEON 会在此处崩溃）");
    let _ = uc.remove_hook(hook_id);

    // 5. 验证返回值 X0 = 0x1234 + 0x5678 = 0x68AC
    let ret_x0 = uc.reg_read(RegisterARM64::X0).expect("读取 X0 失败");
    assert_eq!(ret_x0, 0x1234 + 0x5678);

    // 6. 验证 Trace 记录完整性与 bad64 解码
    let stats = uc.get_data().tracer.stats;
    assert_eq!(stats.total_insns, 5);
    assert_eq!(stats.recorded_insns, 5);
    assert_eq!(stats.dropped_insns, 0);

    let records = uc.get_data().tracer.records();
    assert_eq!(records.len(), 5);
    let first_line = BinaryTracer::decode_record(&records[0]);
    assert!(
        first_line.to_lowercase().contains("fmov"),
        "首条指令应反汇编为 fmov，实际为: {first_line}"
    );
    let last_line = BinaryTracer::decode_record(&records[4]);
    assert!(
        last_line.to_lowercase().contains("ret"),
        "末条指令应反汇编为 ret，实际为: {last_line}"
    );
}

#[test]
fn test_mmap_tracer_persistence() {
    let trace_path = std::env::temp_dir().join("arm64_emu_tracer_test.bin");
    let mut tracer = BinaryTracer::new_mmap(&trace_path, 16).expect("创建 mmap tracer 失败");

    let mut regs = [0u64; 32];
    regs[0] = 0x1111;
    tracer.record_step(0x4000_0100, 0xD503_201F, &regs); // nop
    regs[0] = 0x2222;
    tracer.record_step(0x4000_0104, 0xD65F_03C0, &regs); // ret
    tracer.flush().expect("flush mmap 失败");

    let raw = fs::read(&trace_path).expect("读取落盘 trace 文件失败");
    assert_eq!(raw.len(), 16 * size_of::<TraceRecord>());

    // 验证第 2 条记录中的 PC 与 X0 变化值已准确写入磁盘
    let rec1: TraceRecord = unsafe {
        std::ptr::read_unaligned(raw.as_ptr().add(size_of::<TraceRecord>()) as *const TraceRecord)
    };
    let pc = rec1.pc;
    let reg_id = rec1.primary_reg_id;
    let reg_val = rec1.primary_reg_val;
    assert_eq!(pc, 0x4000_0104);
    assert_eq!(reg_id, 0);
    assert_eq!(reg_val, 0x2222);

    let _ = fs::remove_file(&trace_path);
}
