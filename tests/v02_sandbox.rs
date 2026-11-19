use arm64_emu_tracer::cpu::{CpuContext, DEFAULT_STACK_GUARD, RET_MAGIC_ADDR, TLS_BASE};
use arm64_emu_tracer::loader::{attach_trampoline_hook, DynamicLinker, TrampolineTable};
use arm64_emu_tracer::memory::{MemoryManager, PAGE_SIZE};
use arm64_emu_tracer::os::syscall::{
    SYS_CLOCK_GETTIME, SYS_CLOSE, SYS_GETPID, SYS_OPENAT, SYS_READ,
};
use arm64_emu_tracer::os::{attach_syscall_hook, VirtualFs};
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

struct SandboxState {
    mem: MemoryManager,
    vfs: VirtualFs,
    trampolines: TrampolineTable,
}

fn new_sandbox() -> (Unicorn<'static, SandboxState>, CpuContext) {
    let state = SandboxState {
        mem: MemoryManager::new(0x5000_0000, 0x0100_0000),
        vfs: VirtualFs::new("com.sandbox.test"),
        trampolines: TrampolineTable::new(),
    };
    let mut uc = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, state)
        .expect("创建 Unicorn 实例失败");

    // 临时把 mem 取出初始化堆、CPU 和跳板区（避免同时借用 uc 与 uc.get_data_mut()）
    let mut mem = std::mem::replace(
        &mut uc.get_data_mut().mem,
        MemoryManager::new(0x5000_0000, 0x0100_0000),
    );
    let mut trampolines = std::mem::take(&mut uc.get_data_mut().trampolines);

    mem.init_heap(&mut uc).expect("初始化堆失败");
    let cpu = CpuContext::init(&mut uc, &mut mem).expect("初始化 CPU 上下文失败");
    trampolines
        .init(&mut uc, &mut mem)
        .expect("初始化 HLE 跳板区失败");

    uc.get_data_mut().mem = mem;
    uc.get_data_mut().trampolines = trampolines;

    attach_syscall_hook(&mut uc, |s| (&mut s.mem, &mut s.vfs)).expect("挂载 Syscall Hook 失败");
    attach_trampoline_hook(&mut uc, |s| (&mut s.trampolines, &mut s.mem, &mut s.vfs))
        .expect("挂载 HLE 跳板 Hook 失败");

    (uc, cpu)
}

#[test]
fn test_tls_tpidr_el0_and_stack_guard() {
    let (mut uc, cpu) = new_sandbox();
    let code_addr = 0x4100_0000u64;
    uc.mem_map(code_addr, PAGE_SIZE, Prot::READ | Prot::EXEC)
        .unwrap();

    // mrs x0, tpidr_el0
    // ldr x1, [x0, #0x28]   ; 读取 TLS_SLOT_STACK_GUARD (slot 5)
    // ret
    let insns: [u32; 3] = [0xD53B_D040, 0xF940_1401, 0xD65F_03C0];
    let mut code = Vec::new();
    for i in insns {
        code.extend_from_slice(&i.to_le_bytes());
    }
    uc.mem_write(code_addr, &code).unwrap();

    cpu.prepare_call(&mut uc, &[]).unwrap();
    uc.emu_start(code_addr, RET_MAGIC_ADDR, 0, 0).unwrap();

    assert_eq!(uc.reg_read(RegisterARM64::X0).unwrap(), TLS_BASE);
    assert_eq!(uc.reg_read(RegisterARM64::X1).unwrap(), DEFAULT_STACK_GUARD);
}

#[test]
fn test_mmu_vma_mmap_mprotect_and_proc_maps() {
    let mut uc = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).unwrap();
    let mut mem = MemoryManager::new(0x5000_0000, 0x0010_0000);
    mem.init_heap(&mut uc).unwrap();

    let addr = mem
        .mmap(
            &mut uc,
            0,
            PAGE_SIZE * 3,
            Prot::READ | Prot::WRITE,
            "/system/lib64/libdemo.so",
            0,
        )
        .unwrap();

    // 将中间页改为 RX，验证区间分裂后 `/proc/self/maps` 正确反映权限变化
    mem.mprotect(&mut uc, addr + PAGE_SIZE, PAGE_SIZE, Prot::READ | Prot::EXEC)
        .unwrap();

    let maps = mem.format_proc_maps();
    assert!(maps.contains("[heap]"), "maps 应包含 [heap]:\n{maps}");
    assert!(
        maps.contains("r-xp") && maps.contains("/system/lib64/libdemo.so"),
        "maps 应包含分裂后的 r-xp 区间:\n{maps}"
    );

    mem.munmap(&mut uc, addr, PAGE_SIZE * 3).unwrap();
    let maps_after = mem.format_proc_maps();
    assert!(!maps_after.contains("/system/lib64/libdemo.so"));
}

#[test]
fn test_svc_syscall_open_read_proc_status_and_getpid() {
    let (mut uc, cpu) = new_sandbox();
    let code_addr = 0x4200_0000u64;
    let data_addr = 0x4201_0000u64;
    uc.mem_map(code_addr, PAGE_SIZE, Prot::READ | Prot::EXEC)
        .unwrap();
    uc.mem_map(data_addr, PAGE_SIZE, Prot::READ | Prot::WRITE)
        .unwrap();

    // data_addr + 0x000: "/proc/self/status\0"
    // data_addr + 0x100: 读取输出缓冲 (256B)
    // data_addr + 0x200: timespec 缓冲 (16B)
    uc.mem_write(data_addr, b"/proc/self/status\0").unwrap();

    let mov_imm = |rd: u32, imm: u16| -> u32 { 0xD280_0000 | ((imm as u32) << 5) | rd };
    let svc0 = 0xD400_0001u32;

    // 传入 X0 = path_ptr, X1 = out_buf, X2 = timespec_ptr
    // 保存到 X19/X20/X21 后依次发起 openat / read / close / clock_gettime / getpid
    let insns: [u32; 22] = [
        0xAA00_03F3,                    // mov x19, x0 (path_ptr)
        0xAA01_03F4,                    // mov x20, x1 (out_buf)
        0xAA02_03F5,                    // mov x21, x2 (timespec_ptr)
        // 1. openat(AT_FDCWD=-100, path, O_RDONLY=0, 0)
        mov_imm(0, 0),                  // x0 = 0 (dirfd)
        0xAA13_03E1,                    // mov x1, x19
        mov_imm(2, 0),                  // x2 = 0
        mov_imm(3, 0),                  // x3 = 0
        mov_imm(8, SYS_OPENAT as u16),  // x8 = SYS_OPENAT
        svc0,                           // svc #0 -> x0 = fd
        0xAA00_03F6,                    // mov x22, x0 (save fd)
        // 2. read(fd, out_buf, 200)
        0xAA14_03E1,                    // mov x1, x20
        mov_imm(2, 200),                // x2 = 200
        mov_imm(8, SYS_READ as u16),    // x8 = SYS_READ
        svc0,                           // svc #0 -> x0 = bytes_read
        // 3. close(fd)
        0xAA16_03E0,                    // mov x0, x22
        mov_imm(8, SYS_CLOSE as u16),   // x8 = SYS_CLOSE
        svc0,
        // 4. clock_gettime(CLOCK_MONOTONIC=1, timespec_ptr)
        mov_imm(0, 1),
        0xAA15_03E1,                    // mov x1, x21
        mov_imm(8, SYS_CLOCK_GETTIME as u16),
        svc0,
        // 5. getpid() -> 返回值留在 X0
        mov_imm(8, SYS_GETPID as u16),
    ];

    let mut code = Vec::new();
    for i in insns {
        code.extend_from_slice(&i.to_le_bytes());
    }
    code.extend_from_slice(&svc0.to_le_bytes());
    code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret
    uc.mem_write(code_addr, &code).unwrap();

    cpu.prepare_call(&mut uc, &[data_addr, data_addr + 0x100, data_addr + 0x200])
        .unwrap();
    uc.emu_start(code_addr, RET_MAGIC_ADDR, 0, 0).unwrap();

    // 校验 getpid 返回值
    let pid = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_eq!(pid, 10420);

    // 校验 /proc/self/status 包含 TracerPid: 0 与包名
    let mut status_buf = [0u8; 200];
    uc.mem_read(data_addr + 0x100, &mut status_buf).unwrap();
    let status_str = String::from_utf8_lossy(&status_buf);
    assert!(
        status_str.contains("TracerPid:\t0") && status_str.contains("com.sandbox.test"),
        "读取到的 /proc/self/status 内容异常:\n{status_str}"
    );

    // 校验 clock_gettime 写入了非零时间戳
    let mut ts = [0u8; 16];
    uc.mem_read(data_addr + 0x200, &mut ts).unwrap();
    let tv_sec = i64::from_le_bytes(ts[0..8].try_into().unwrap());
    assert!(tv_sec >= 1_700_000_000);
}

/// 构造包含 `.init_array`、`R_AARCH64_IRELATIVE` 以及外部符号 `malloc` / `__system_property_get` 的合成 ELF
fn build_v02_linker_test_so() -> Vec<u8> {
    const INIT_FN_OFF: u64 = 0x0100;
    const IREL_RESOLVER_OFF: u64 = 0x0120;
    const ENTRY_FN_OFF: u64 = 0x0140;
    const INIT_ARRAY_OFF: u64 = 0x0200;
    const DYN_OFF: u64 = 0x0220;
    const DYNSYM_OFF: u64 = 0x0320;
    const DYNSTR_OFF: u64 = 0x0390;
    const RELA_OFF: u64 = 0x0400;
    const HASH_OFF: u64 = 0x0480;
    const GOT_MALLOC_OFF: u64 = 0x0500;
    const GOT_PROP_OFF: u64 = 0x0508;
    const GOT_IREL_OFF: u64 = 0x0510;
    const GLOBAL_FLAG_OFF: u64 = 0x0518;
    const FILE_SIZE: usize = 0x0600;

    let mut img = vec![0u8; FILE_SIZE];
    let put_u16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let put_u32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let put_u64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    let put_i64 = |b: &mut [u8], o: usize, v: i64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());

    // 1. Elf64_Ehdr
    img[0..4].copy_from_slice(b"\x7fELF");
    img[4] = 2;
    img[5] = 1;
    img[6] = 1;
    put_u16(&mut img, 16, 3); // ET_DYN
    put_u16(&mut img, 18, 183); // EM_AARCH64
    put_u32(&mut img, 20, 1);
    put_u64(&mut img, 32, 0x40);
    put_u16(&mut img, 52, 64);
    put_u16(&mut img, 54, 56);
    put_u16(&mut img, 56, 2);

    // 2. PT_LOAD + PT_DYNAMIC
    put_u32(&mut img, 0x40, 1);
    put_u32(&mut img, 0x44, 7);
    put_u64(&mut img, 0x60, FILE_SIZE as u64);
    put_u64(&mut img, 0x68, FILE_SIZE as u64);
    put_u64(&mut img, 0x70, PAGE_SIZE);

    let ph1 = 0x40 + 56;
    put_u32(&mut img, ph1, 2);
    put_u32(&mut img, ph1 + 4, 6);
    put_u64(&mut img, ph1 + 8, DYN_OFF);
    put_u64(&mut img, ph1 + 16, DYN_OFF);
    put_u64(&mut img, ph1 + 24, DYN_OFF);
    put_u64(&mut img, ph1 + 32, 12 * 16);
    put_u64(&mut img, ph1 + 40, 12 * 16);
    put_u64(&mut img, ph1 + 48, 8);

    // 3. init_fn @ 0x0100: 将 0xCAFE 写入 GLOBAL_FLAG_OFF (通过 adr x1, #0x414)
    //   0x0100: mov x0, #0xCAFE      -> 0xD299_5FC0
    //   0x0104: adr x1, #0x414       -> 计算 PC(0x104) + 0x414 = 0x518
    //   0x0108: str x0, [x1]         -> 0xF900_0020
    //   0x010C: ret                  -> 0xD65F_03C0
    let adr_encode = |rd: u32, imm: i32| -> u32 {
        let u = imm as u32;
        let immlo = u & 0x3;
        let immhi = (u >> 2) & 0x7FFFF;
        0x1000_0000 | (immlo << 29) | (immhi << 5) | rd
    };
    let init_insns: [u32; 4] = [
        0xD299_5FC0,                             // mov x0, #0xCAFE
        adr_encode(1, (GLOBAL_FLAG_OFF - 0x104) as i32),
        0xF900_0020,                             // str x0, [x1]
        0xD65F_03C0,                             // ret
    ];
    for (i, &insn) in init_insns.iter().enumerate() {
        put_u32(&mut img, INIT_FN_OFF as usize + i * 4, insn);
    }

    // 4. irel_resolver @ 0x0120: 返回 0xBEEF
    put_u32(&mut img, IREL_RESOLVER_OFF as usize, 0xD297_DDE0); // mov x0, #0xBEEF
    put_u32(&mut img, IREL_RESOLVER_OFF as usize + 4, 0xD65F_03C0); // ret

    // 5. entry_fn(key_ptr: X0, out_buf_ptr_out: X1) @ 0x0140:
    //    调用 GOT[malloc](64) 得到 buf -> 存入 *X1 -> 调用 GOT[__system_property_get](key_ptr, buf) -> 返回长度
    let entry_insns: [u32; 14] = [
        0xA9BF_7BFD,                                         // stp x29, x30, [sp, #-16]!
        0xAA00_03F3,                                         // mov x19, x0 (key_ptr)
        0xAA01_03F4,                                         // mov x20, x1 (out_ptr_slot)
        0xD280_0800,                                         // mov x0, #64
        adr_encode(16, (GOT_MALLOC_OFF - 0x150) as i32),     // adr x16, GOT_MALLOC_OFF
        0xF940_0210,                                         // ldr x16, [x16]
        0xD63F_0200,                                         // blr x16 (HLE malloc(64))
        0xAA00_03F5,                                         // mov x21, x0 (allocated buf)
        0xF900_0295,                                         // str x21, [x20]
        0xAA13_03E0,                                         // mov x0, x19 (key_ptr)
        0xAA15_03E1,                                         // mov x1, x21 (buf)
        adr_encode(16, (GOT_PROP_OFF - 0x16C) as i32),       // adr x16, GOT_PROP_OFF
        0xF940_0210,                                         // ldr x16, [x16]
        0xD63F_0200,                                         // blr x16 (HLE __system_property_get)
    ];
    for (i, &insn) in entry_insns.iter().enumerate() {
        put_u32(&mut img, ENTRY_FN_OFF as usize + i * 4, insn);
    }
    put_u32(&mut img, ENTRY_FN_OFF as usize + 14 * 4, 0xA8C1_7BFD); // ldp x29, x30, [sp], #16
    put_u32(&mut img, ENTRY_FN_OFF as usize + 15 * 4, 0xD65F_03C0); // ret

    // 6. .dynstr: "\0entry_fn\0malloc\0__system_property_get\0"
    let strtab = b"\0entry_fn\0malloc\0__system_property_get\0";
    img[DYNSTR_OFF as usize..DYNSTR_OFF as usize + strtab.len()].copy_from_slice(strtab);

    // 7. .dynsym (4 项: UNDEF, entry_fn, malloc[UNDEF], __system_property_get[UNDEF])
    let sym1 = DYNSYM_OFF as usize + 24;
    put_u32(&mut img, sym1, 1); // "entry_fn"
    img[sym1 + 4] = 0x12;
    put_u16(&mut img, sym1 + 6, 1);
    put_u64(&mut img, sym1 + 8, ENTRY_FN_OFF);

    let sym2 = DYNSYM_OFF as usize + 48;
    put_u32(&mut img, sym2, 10); // "malloc" (st_value = 0 外部导入)
    img[sym2 + 4] = 0x12;

    let sym3 = DYNSYM_OFF as usize + 72;
    put_u32(&mut img, sym3, 17); // "__system_property_get" (st_value = 0 外部导入)
    img[sym3 + 4] = 0x12;

    // 8. .rela.dyn (4 条重定位):
    //   [0] R_AARCH64_RELATIVE (1027) -> INIT_ARRAY_OFF = base + INIT_FN_OFF
    //   [1] R_AARCH64_GLOB_DAT (1025) sym=2 (malloc) -> GOT_MALLOC_OFF
    //   [2] R_AARCH64_JUMP_SLOT (1026) sym=3 (__system_property_get) -> GOT_PROP_OFF
    //   [3] R_AARCH64_IRELATIVE (1032) -> GOT_IREL_OFF = resolver(base + IREL_RESOLVER_OFF)()
    let r0 = RELA_OFF as usize;
    put_u64(&mut img, r0, INIT_ARRAY_OFF);
    put_u64(&mut img, r0 + 8, 1027);
    put_i64(&mut img, r0 + 16, INIT_FN_OFF as i64);

    let r1 = RELA_OFF as usize + 24;
    put_u64(&mut img, r1, GOT_MALLOC_OFF);
    put_u64(&mut img, r1 + 8, (2u64 << 32) | 1025);

    let r2 = RELA_OFF as usize + 48;
    put_u64(&mut img, r2, GOT_PROP_OFF);
    put_u64(&mut img, r2 + 8, (3u64 << 32) | 1026);

    let r3 = RELA_OFF as usize + 72;
    put_u64(&mut img, r3, GOT_IREL_OFF);
    put_u64(&mut img, r3 + 8, 1032);
    put_i64(&mut img, r3 + 16, IREL_RESOLVER_OFF as i64);

    // 9. DT_HASH (nbucket=1, nchain=4)
    let h = HASH_OFF as usize;
    put_u32(&mut img, h, 1);
    put_u32(&mut img, h + 4, 4);
    put_u32(&mut img, h + 8, 1);

    // 10. .dynamic
    let dyn_entries: [(u64, u64); 12] = [
        (4, HASH_OFF),             // DT_HASH
        (5, DYNSTR_OFF),           // DT_STRTAB
        (6, DYNSYM_OFF),           // DT_SYMTAB
        (10, strtab.len() as u64), // DT_STRSZ
        (11, 24),                  // DT_SYMENT
        (7, RELA_OFF),             // DT_RELA
        (8, 4 * 24),               // DT_RELASZ
        (9, 24),                   // DT_RELAENT
        (25, INIT_ARRAY_OFF),      // DT_INIT_ARRAY
        (27, 8),                   // DT_INIT_ARRAYSZ
        (0, 0),                    // DT_NULL
        (0, 0),
    ];
    for (i, &(tag, val)) in dyn_entries.iter().enumerate() {
        let off = DYN_OFF as usize + i * 16;
        put_u64(&mut img, off, tag);
        put_u64(&mut img, off + 8, val);
    }

    img
}

#[test]
fn test_dynamic_linker_init_array_irelative_and_hle_trampoline() {
    let (mut uc, cpu) = new_sandbox();
    let elf_bytes = build_v02_linker_test_so();

    let mut linker = DynamicLinker::new(true);

    // 临时取出 mem 和 trampolines 供 linker 加载模块
    let mut mem = std::mem::replace(
        &mut uc.get_data_mut().mem,
        MemoryManager::new(0x5000_0000, 0x0100_0000),
    );
    let mut trampolines = std::mem::take(&mut uc.get_data_mut().trampolines);

    let module = linker
        .load_bytes(
            &mut uc,
            &mut mem,
            &cpu,
            &mut trampolines,
            &elf_bytes,
            "libv02_test.so".into(),
            false,
            true, // 自动执行 .init_array
        )
        .expect("DynamicLinker 加载失败");

    // 放回 state（执行 entry_fn 时 HLE Hook 会访问它们）
    let key_addr = mem.alloc_heap(64).unwrap();
    let out_slot_addr = mem.alloc_heap(8).unwrap();
    mem.write_c_string(&mut uc, key_addr, "ro.build.version.sdk")
        .unwrap();

    // 1. 验证 .init_array 已执行：GLOBAL_FLAG_OFF == 0xCAFE
    let flag_val = mem.read_u64(&uc, module.base_addr + 0x0518).unwrap();
    assert_eq!(flag_val, 0xCAFE, ".init_array 构造器未正确执行");

    // 2. 验证 R_AARCH64_IRELATIVE 已执行并回填 resolver 返回值 0xBEEF
    let irel_val = mem.read_u64(&uc, module.base_addr + 0x0510).unwrap();
    assert_eq!(irel_val, 0xBEEF, "R_AARCH64_IRELATIVE 回填失败");

    uc.get_data_mut().mem = mem;
    uc.get_data_mut().trampolines = trampolines;

    // 3. 调用 entry_fn，验证 HLE malloc 与 __system_property_get 跳板劫持闭环
    let entry_addr = module.find_symbol("entry_fn").unwrap();
    cpu.prepare_call(&mut uc, &[key_addr, out_slot_addr])
        .unwrap();
    uc.emu_start(entry_addr, RET_MAGIC_ADDR, 0, 0)
        .expect("执行 entry_fn 失败");

    let prop_len = uc.reg_read(RegisterARM64::X0).unwrap();
    assert_eq!(prop_len, 2, "ro.build.version.sdk ('30') 长度应为 2");

    let mut ptr_bytes = [0u8; 8];
    uc.mem_read(out_slot_addr, &mut ptr_bytes).unwrap();
    let alloc_buf_ptr = u64::from_le_bytes(ptr_bytes);
    assert!(alloc_buf_ptr >= 0x5000_0000, "malloc 应返回堆区间内地址");

    let mut val_bytes = [0u8; 3];
    uc.mem_read(alloc_buf_ptr, &mut val_bytes).unwrap();
    assert_eq!(&val_bytes, b"30\0");
}
