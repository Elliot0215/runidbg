use runidbg_arm64_emu_tracer::loader::HleBuiltin;
use runidbg_arm64_emu_tracer::memory::MemoryManager;
use runidbg_arm64_emu_tracer::AndroidEmulator;
use unicorn_engine::unicorn_const::Prot;

fn get_hle(emu: &mut AndroidEmulator, sym: &str) -> u64 {
    let builtin = HleBuiltin::from_symbol(sym).expect("known HLE symbol");
    let mut mem = std::mem::replace(
        &mut emu.uc_mut().get_data_mut().mem,
        MemoryManager::new(0, 0),
    );
    let mut tramp = std::mem::take(&mut emu.uc_mut().get_data_mut().trampolines);
    let addr = tramp
        .register(emu.uc_mut(), &mut mem, sym, builtin)
        .expect("register HLE");
    emu.uc_mut().get_data_mut().mem = mem;
    emu.uc_mut().get_data_mut().trampolines = tramp;
    addr
}

fn alloc(emu: &mut AndroidEmulator, size: u64) -> u64 {
    emu.uc_mut().get_data_mut().mem.alloc_heap(size).unwrap()
}

fn write_bytes(emu: &mut AndroidEmulator, addr: u64, data: &[u8]) {
    emu.uc_mut().mem_write(addr, data).unwrap();
}

fn read_bytes(emu: &AndroidEmulator, addr: u64, len: usize) -> Vec<u8> {
    emu.uc().mem_read_as_vec(addr, len).unwrap()
}

fn alloc_cstr(emu: &mut AndroidEmulator, s: &str) -> u64 {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    let ptr = alloc(emu, bytes.len() as u64);
    write_bytes(emu, ptr, &bytes);
    ptr
}

#[test]
fn cooperative_pthread_create_join_and_pthread_exit() {
    let mut emu = AndroidEmulator::builder().build().unwrap();
    let p_create = get_hle(&mut emu, "pthread_create");
    let p_join = get_hle(&mut emu, "pthread_join");
    let p_exit = get_hle(&mut emu, "pthread_exit");

    // 映射一小段 guest 代码页，放两个线程函数：
    // 1) worker_return(arg): return arg + 0x100
    // 2) worker_exit(arg):   pthread_exit(arg + 0x200)
    let code_base = 0x4900_0000u64;
    emu.uc_mut()
        .mem_map(code_base, 0x1000, Prot::READ | Prot::WRITE | Prot::EXEC)
        .unwrap();

    // worker_return @ code_base + 0x00:
    //   add x0, x0, #0x100   (0x9104_0000)
    //   ret                  (0xD65F_03C0)
    let worker_return = code_base;
    write_bytes(
        &mut emu,
        worker_return,
        &[
            0x9104_0000u32.to_le_bytes(),
            0xD65F_03C0u32.to_le_bytes(),
        ]
        .concat(),
    );

    // worker_exit @ code_base + 0x20:
    //   add x0, x0, #0x200   (0x9108_0000)
    //   ldr x9, [pc, #8]     (0x5800_0049)  -> 加载 p_exit 地址
    //   br  x9               (0xD61F_0120)
    //   .quad p_exit
    let worker_exit = code_base + 0x20;
    let mut exit_code = Vec::new();
    exit_code.extend_from_slice(&0x9108_0000u32.to_le_bytes()); // add x0, x0, #0x200
    exit_code.extend_from_slice(&0x5800_0049u32.to_le_bytes()); // ldr x9, .+8
    exit_code.extend_from_slice(&0xD61F_0120u32.to_le_bytes()); // br x9
    exit_code.extend_from_slice(&p_exit.to_le_bytes());
    write_bytes(&mut emu, worker_exit, &exit_code);

    // 测试 1：正常 return 的线程函数
    let tid_ptr = alloc(&mut emu, 8);
    let ret_ptr = alloc(&mut emu, 8);
    let rc = emu
        .call_address(p_create, &[tid_ptr, 0, worker_return, 0x20])
        .unwrap();
    assert_eq!(rc, 0);
    let tid1 = u64::from_le_bytes(read_bytes(&emu, tid_ptr, 8).try_into().unwrap());
    assert!(tid1 >= 0x1001);

    let jrc = emu.call_address(p_join, &[tid1, ret_ptr]).unwrap();
    assert_eq!(jrc, 0);
    let ret1 = u64::from_le_bytes(read_bytes(&emu, ret_ptr, 8).try_into().unwrap());
    assert_eq!(ret1, 0x120);

    // 测试 2：调用 pthread_exit 退出的线程函数
    let rc2 = emu
        .call_address(p_create, &[tid_ptr, 0, worker_exit, 0x33])
        .unwrap();
    assert_eq!(rc2, 0);
    let tid2 = u64::from_le_bytes(read_bytes(&emu, tid_ptr, 8).try_into().unwrap());
    assert_eq!(tid2, tid1 + 1);

    let jrc2 = emu.call_address(p_join, &[tid2, ret_ptr]).unwrap();
    assert_eq!(jrc2, 0);
    let ret2 = u64::from_le_bytes(read_bytes(&emu, ret_ptr, 8).try_into().unwrap());
    assert_eq!(ret2, 0x233);
}

#[test]
fn setjmp_longjmp_and_signal_apis() {
    let mut emu = AndroidEmulator::builder().build().unwrap();
    let p_setjmp = get_hle(&mut emu, "setjmp");
    let p_longjmp = get_hle(&mut emu, "longjmp");
    let p_sigaction = get_hle(&mut emu, "sigaction");
    let p_sigemptyset = get_hle(&mut emu, "sigemptyset");
    let p_sigaddset = get_hle(&mut emu, "sigaddset");
    let p_sigismember = get_hle(&mut emu, "sigismember");
    let p_sigprocmask = get_hle(&mut emu, "sigprocmask");

    // 构造 ARM64 函数 test_jmp(jmp_buf):
    //   stp x29, x30, [sp, #-32]!
    //   str x19, [sp, #16]
    //   mov x19, x0             ; 保存 jmp_buf 到 callee-saved x19
    //   ldr x9, .Lsetjmp
    //   blr x9                  ; setjmp(jmp_buf)
    //   cbnz x0, .Ldone         ; 非 0 表示从 longjmp 返回
    //   mov x0, x19
    //   mov x1, #42
    //   ldr x9, .Llongjmp
    //   blr x9                  ; longjmp(jmp_buf, 42)
    // .Ldone:
    //   add x0, x0, #100        ; 42 + 100 = 142
    //   ldr x19, [sp, #16]
    //   ldp x29, x30, [sp], #32
    //   ret
    let code_base = 0x5200_0000u64;
    emu.uc_mut()
        .mem_map(code_base, 0x1000, Prot::READ | Prot::WRITE | Prot::EXEC)
        .unwrap();

    let insns: [u32; 14] = [
        0xA9BE_7BFD, // 0x00: stp x29, x30, [sp, #-32]!
        0xF900_0BF3, // 0x04: str x19, [sp, #16]
        0xAA00_03F3, // 0x08: mov x19, x0
        0x5800_0169, // 0x0C: ldr x9, [pc, #44] -> 0x38 (.Lsetjmp)
        0xD63F_0120, // 0x10: blr x9
        0xB500_00A0, // 0x14: cbnz x0, +20 -> 0x28 (.Ldone)
        0xAA13_03E0, // 0x18: mov x0, x19
        0xD280_0541, // 0x1C: mov x1, #42
        0x5800_0109, // 0x20: ldr x9, [pc, #32] -> 0x40 (.Llongjmp)
        0xD63F_0120, // 0x24: blr x9
        0x9101_9000, // 0x28: add x0, x0, #100
        0xF940_0BF3, // 0x2C: ldr x19, [sp, #16]
        0xA8C2_7BFD, // 0x30: ldp x29, x30, [sp], #32
        0xD65F_03C0, // 0x34: ret
    ];
    let mut code = Vec::new();
    for insn in insns {
        code.extend_from_slice(&insn.to_le_bytes());
    }
    code.extend_from_slice(&p_setjmp.to_le_bytes()); // 0x38
    code.extend_from_slice(&p_longjmp.to_le_bytes()); // 0x40
    write_bytes(&mut emu, code_base, &code);

    let jmp_buf = alloc(&mut emu, 256);
    let res = emu.call_address(code_base, &[jmp_buf]).unwrap();
    assert_eq!(res, 142);

    // 验证 sigaction 保存与查询 oldact
    let act = alloc(&mut emu, 32);
    let oldact = alloc(&mut emu, 32);
    write_bytes(&mut emu, act, &0x1234_5678u64.to_le_bytes());
    assert_eq!(emu.call_address(p_sigaction, &[11, act, 0]).unwrap(), 0);
    assert_eq!(emu.call_address(p_sigaction, &[11, 0, oldact]).unwrap(), 0);
    let saved_handler = u64::from_le_bytes(read_bytes(&emu, oldact, 8).try_into().unwrap());
    assert_eq!(saved_handler, 0x1234_5678);

    // 验证 sigset + sigprocmask
    let set_ptr = alloc(&mut emu, 8);
    let oldset_ptr = alloc(&mut emu, 8);
    emu.call_address(p_sigemptyset, &[set_ptr]).unwrap();
    emu.call_address(p_sigaddset, &[set_ptr, 15]).unwrap();
    assert_eq!(emu.call_address(p_sigismember, &[set_ptr, 15]).unwrap(), 1);
    assert_eq!(emu.call_address(p_sigismember, &[set_ptr, 9]).unwrap(), 0);
    emu.call_address(p_sigprocmask, &[0, set_ptr, 0]).unwrap();
    emu.call_address(p_sigprocmask, &[0, 0, oldset_ptr]).unwrap();
    let mask = u64::from_le_bytes(read_bytes(&emu, oldset_ptr, 8).try_into().unwrap());
    assert_eq!(mask, 1u64 << 14);
}

#[test]
fn asset_manager_and_zlib_hle() {
    let mut emu = AndroidEmulator::builder().build().unwrap();
    emu.vfs_mut()
        .add_overlay_file("/assets/config.json", b"{\"ok\":true}".to_vec());
    emu.vfs_mut()
        .add_overlay_file("/assets/readme.txt", b"hello_asset".to_vec());

    // 1. AAssetManager_fromJava / open / read / seek / getBuffer / close
    let p_from_java = get_hle(&mut emu, "AAssetManager_fromJava");
    let p_open = get_hle(&mut emu, "AAssetManager_open");
    let p_open_dir = get_hle(&mut emu, "AAssetManager_openDir");
    let p_read = get_hle(&mut emu, "AAsset_read");
    let p_seek = get_hle(&mut emu, "AAsset_seek");
    let p_len = get_hle(&mut emu, "AAsset_getLength");
    let p_rem = get_hle(&mut emu, "AAsset_getRemainingLength");
    let p_buf = get_hle(&mut emu, "AAsset_getBuffer");
    let p_close = get_hle(&mut emu, "AAsset_close");
    let p_next = get_hle(&mut emu, "AAssetDir_getNextFileName");
    let p_dir_close = get_hle(&mut emu, "AAssetDir_close");

    let mgr = emu.call_address(p_from_java, &[0, 0]).unwrap();
    assert_ne!(mgr, 0);

    let fname = alloc_cstr(&mut emu, "config.json");
    let asset = emu.call_address(p_open, &[mgr, fname, 2]).unwrap();
    assert_ne!(asset, 0);
    assert_eq!(emu.call_address(p_len, &[asset]).unwrap(), 11);

    let out_buf = alloc(&mut emu, 32);
    let n = emu.call_address(p_read, &[asset, out_buf, 5]).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&read_bytes(&emu, out_buf, 5), b"{\"ok\"");
    assert_eq!(emu.call_address(p_rem, &[asset]).unwrap(), 6);

    assert_eq!(emu.call_address(p_seek, &[asset, 0, 0]).unwrap(), 0);
    let raw_ptr = emu.call_address(p_buf, &[asset]).unwrap();
    assert_eq!(&read_bytes(&emu, raw_ptr, 11), b"{\"ok\":true}");
    emu.call_address(p_close, &[asset]).unwrap();

    // 目录枚举
    let empty_dir = alloc_cstr(&mut emu, "");
    let adir = emu.call_address(p_open_dir, &[mgr, empty_dir]).unwrap();
    assert_ne!(adir, 0);
    let mut names = Vec::new();
    loop {
        let p = emu.call_address(p_next, &[adir]).unwrap();
        if p == 0 {
            break;
        }
        let raw = read_bytes(&emu, p, 64);
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        names.push(String::from_utf8_lossy(&raw[..end]).into_owned());
    }
    emu.call_address(p_dir_close, &[adir]).unwrap();
    assert!(names.contains(&"config.json".to_string()));
    assert!(names.contains(&"readme.txt".to_string()));

    // 2. zlib: adler32 / compress2 / uncompress / deflateInit_+deflate / inflateInit_+inflate
    let p_adler = get_hle(&mut emu, "adler32");
    let p_bound = get_hle(&mut emu, "compressBound");
    let p_compress2 = get_hle(&mut emu, "compress2");
    let p_uncompress = get_hle(&mut emu, "uncompress");
    let p_deflate_init = get_hle(&mut emu, "deflateInit_");
    let p_deflate = get_hle(&mut emu, "deflate");
    let p_deflate_end = get_hle(&mut emu, "deflateEnd");
    let p_inflate_init = get_hle(&mut emu, "inflateInit_");
    let p_inflate = get_hle(&mut emu, "inflate");
    let p_inflate_end = get_hle(&mut emu, "inflateEnd");

    let payload = b"runidbg zlib compression test payload! runidbg zlib compression test payload!";
    let src_ptr = alloc(&mut emu, payload.len() as u64);
    write_bytes(&mut emu, src_ptr, payload);

    let adler = emu
        .call_address(p_adler, &[1, src_ptr, payload.len() as u64])
        .unwrap();
    assert_ne!(adler, 0);

    let bound = emu
        .call_address(p_bound, &[payload.len() as u64])
        .unwrap();
    let comp_buf = alloc(&mut emu, bound);
    let comp_len_ptr = alloc(&mut emu, 8);
    write_bytes(&mut emu, comp_len_ptr, &bound.to_le_bytes());
    assert_eq!(
        emu.call_address(
            p_compress2,
            &[comp_buf, comp_len_ptr, src_ptr, payload.len() as u64, 6]
        )
        .unwrap(),
        0
    );
    let comp_len = u64::from_le_bytes(read_bytes(&emu, comp_len_ptr, 8).try_into().unwrap());
    assert!(comp_len > 0 && comp_len < payload.len() as u64);

    let uncomp_buf = alloc(&mut emu, 256);
    let uncomp_len_ptr = alloc(&mut emu, 8);
    write_bytes(&mut emu, uncomp_len_ptr, &256u64.to_le_bytes());
    assert_eq!(
        emu.call_address(
            p_uncompress,
            &[uncomp_buf, uncomp_len_ptr, comp_buf, comp_len]
        )
        .unwrap(),
        0
    );
    let uncomp_len = u64::from_le_bytes(read_bytes(&emu, uncomp_len_ptr, 8).try_into().unwrap());
    assert_eq!(uncomp_len as usize, payload.len());
    assert_eq!(read_bytes(&emu, uncomp_buf, payload.len()), payload);

    // 流式 deflate -> inflate
    let strm = alloc(&mut emu, 128);
    let z_out = alloc(&mut emu, 256);
    assert_eq!(emu.call_address(p_deflate_init, &[strm, 6, 0, 112]).unwrap(), 0);
    write_bytes(&mut emu, strm, &src_ptr.to_le_bytes()); // next_in
    write_bytes(&mut emu, strm + 8, &(payload.len() as u32).to_le_bytes()); // avail_in
    write_bytes(&mut emu, strm + 0x18, &z_out.to_le_bytes()); // next_out
    write_bytes(&mut emu, strm + 0x20, &256u32.to_le_bytes()); // avail_out
    assert_eq!(emu.call_address(p_deflate, &[strm, 4]).unwrap(), 1); // Z_STREAM_END
    let stream_comp_len = u64::from_le_bytes(read_bytes(&emu, strm + 0x28, 8).try_into().unwrap());
    emu.call_address(p_deflate_end, &[strm]).unwrap();

    let strm2 = alloc(&mut emu, 128);
    let z_dec = alloc(&mut emu, 256);
    assert_eq!(emu.call_address(p_inflate_init, &[strm2, 0, 112]).unwrap(), 0);
    write_bytes(&mut emu, strm2, &z_out.to_le_bytes());
    write_bytes(&mut emu, strm2 + 8, &(stream_comp_len as u32).to_le_bytes());
    write_bytes(&mut emu, strm2 + 0x18, &z_dec.to_le_bytes());
    write_bytes(&mut emu, strm2 + 0x20, &256u32.to_le_bytes());
    assert_eq!(emu.call_address(p_inflate, &[strm2, 4]).unwrap(), 1); // Z_STREAM_END
    let stream_dec_len = u64::from_le_bytes(read_bytes(&emu, strm2 + 0x28, 8).try_into().unwrap());
    emu.call_address(p_inflate_end, &[strm2]).unwrap();
    assert_eq!(stream_dec_len as usize, payload.len());
    assert_eq!(read_bytes(&emu, z_dec, payload.len()), payload);
}
