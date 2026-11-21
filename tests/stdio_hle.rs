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

#[test]
fn stdio_fopen_fread_fgets_fscanf_fseek_fwrite_end_to_end() {
    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    emu.vfs_mut().add_overlay_file(
        "/data/local/tmp/sample.txt",
        b"alpha:42\nbeta:0x1a\ngamma 3.5\n".to_vec(),
    );

    let scratch = 0x4400_0000u64;
    emu.uc_mut()
        .mem_map(scratch, 0x4000, Prot::READ | Prot::WRITE)
        .unwrap();

    let p_path = scratch;
    let p_mode_r = scratch + 0x100;
    let p_mode_w = scratch + 0x120;
    let p_wpath = scratch + 0x140;
    let p_buf = scratch + 0x200;
    let p_fmt1 = scratch + 0x400;
    let p_fmt2 = scratch + 0x440;
    let p_out_str = scratch + 0x500;
    let p_out_int = scratch + 0x600;
    let p_out_hex = scratch + 0x620;

    emu.uc_mut()
        .mem_write(p_path, b"/data/local/tmp/sample.txt\0")
        .unwrap();
    emu.uc_mut().mem_write(p_mode_r, b"r\0").unwrap();
    emu.uc_mut().mem_write(p_mode_w, b"wb\0").unwrap();
    emu.uc_mut()
        .mem_write(p_wpath, b"/data/local/tmp/out.bin\0")
        .unwrap();
    emu.uc_mut().mem_write(p_fmt1, b"%[^:]:%d\n\0").unwrap();
    emu.uc_mut().mem_write(p_fmt2, b"%[^:]:0x%x\n\0").unwrap();

    let fn_fopen = get_hle(&mut emu, "fopen");
    let fn_fgets = get_hle(&mut emu, "fgets");
    let fn_fread = get_hle(&mut emu, "fread");
    let fn_fwrite = get_hle(&mut emu, "fwrite");
    let fn_fscanf = get_hle(&mut emu, "fscanf");
    let fn_fseek = get_hle(&mut emu, "fseek");
    let fn_ftell = get_hle(&mut emu, "ftell");
    let fn_feof = get_hle(&mut emu, "feof");
    let fn_fclose = get_hle(&mut emu, "fclose");

    // 1. fopen("/data/local/tmp/sample.txt", "r")
    let fp = emu.call_address(fn_fopen, &[p_path, p_mode_r]).unwrap();
    assert_ne!(fp, 0, "fopen should return non-NULL FILE*");

    // 2. fscanf 第 1 行 ("alpha:42\n") 与 第 2 行 ("beta:0x1a\n")，验证游标精确衔接
    let n1 = emu
        .call_address(fn_fscanf, &[fp, p_fmt1, p_out_str, p_out_int])
        .unwrap() as i32;
    assert_eq!(n1, 2);
    let key1 = emu.uc().mem_read_as_vec(p_out_str, 6).unwrap();
    assert_eq!(&key1[..5], b"alpha");
    let val1 = i32::from_le_bytes(emu.uc().mem_read_as_vec(p_out_int, 4).unwrap().try_into().unwrap());
    assert_eq!(val1, 42);

    let n2 = emu
        .call_address(fn_fscanf, &[fp, p_fmt2, p_out_str, p_out_hex])
        .unwrap() as i32;
    assert_eq!(n2, 2);
    let key2 = emu.uc().mem_read_as_vec(p_out_str, 5).unwrap();
    assert_eq!(&key2[..4], b"beta");
    let val2 = u32::from_le_bytes(emu.uc().mem_read_as_vec(p_out_hex, 4).unwrap().try_into().unwrap());
    assert_eq!(val2, 0x1a);

    // 3. fgets 读取剩余第 3 行 ("gamma 3.5\n")
    let line_ptr = emu.call_address(fn_fgets, &[p_buf, 64, fp]).unwrap();
    assert_eq!(line_ptr, p_buf);
    let line3 = emu.uc().mem_read_as_vec(p_buf, 10).unwrap();
    assert_eq!(&line3, b"gamma 3.5\n");

    // 再读应返回 NULL 且 feof == 1
    assert_eq!(emu.call_address(fn_fgets, &[p_buf, 64, fp]).unwrap(), 0);
    assert_eq!(emu.call_address(fn_feof, &[fp]).unwrap(), 1);

    // 4. fseek(fp, 0, SEEK_SET) + fread 读取前 5 字节 + ftell == 5
    assert_eq!(emu.call_address(fn_fseek, &[fp, 0, 0]).unwrap(), 0);
    let items = emu.call_address(fn_fread, &[p_buf, 1, 5, fp]).unwrap();
    assert_eq!(items, 5);
    assert_eq!(&emu.uc().mem_read_as_vec(p_buf, 5).unwrap(), b"alpha");
    assert_eq!(emu.call_address(fn_ftell, &[fp]).unwrap(), 5);
    assert_eq!(emu.call_address(fn_fclose, &[fp]).unwrap(), 0);

    // 5. fopen(..., "wb") + fwrite + fclose 写回 Overlay 文件
    let wfp = emu.call_address(fn_fopen, &[p_wpath, p_mode_w]).unwrap();
    assert_ne!(wfp, 0);
    emu.uc_mut().mem_write(p_buf, b"RUNIDBG_STDIO").unwrap();
    assert_eq!(emu.call_address(fn_fwrite, &[p_buf, 1, 13, wfp]).unwrap(), 13);
    assert_eq!(emu.call_address(fn_fclose, &[wfp]).unwrap(), 0);
    assert_eq!(
        emu.vfs().get_overlay_file("/data/local/tmp/out.bin"),
        Some(b"RUNIDBG_STDIO".as_slice())
    );

    // 6. 验证 fopen("/proc/cpuinfo", "r") + fgets 可直接读取虚拟 /proc 文件
    emu.uc_mut().mem_write(p_path, b"/proc/cpuinfo\0").unwrap();
    let cfp = emu.call_address(fn_fopen, &[p_path, p_mode_r]).unwrap();
    assert_ne!(cfp, 0);
    let l = emu.call_address(fn_fgets, &[p_buf, 128, cfp]).unwrap();
    assert_eq!(l, p_buf);
    let first_line = String::from_utf8_lossy(&emu.uc().mem_read_as_vec(p_buf, 16).unwrap()).into_owned();
    assert!(first_line.contains("Processor") || first_line.contains("processor"));
    assert_eq!(emu.call_address(fn_fclose, &[cfp]).unwrap(), 0);
}

#[test]
fn stdio_fgetc_ungetc_getline_fileno_and_freopen() {
    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    emu.vfs_mut().add_overlay_file(
        "/data/local/tmp/lines.txt",
        b"hello\nworld\n".to_vec(),
    );

    let scratch = 0x4500_0000u64;
    emu.uc_mut()
        .mem_map(scratch, 0x4000, Prot::READ | Prot::WRITE)
        .unwrap();

    let p_path = scratch;
    let p_mode_r = scratch + 0x100;
    let p_lineptr = scratch + 0x200;
    let p_cap = scratch + 0x208;
    let p_buf = scratch + 0x300;
    emu.uc_mut()
        .mem_write(p_path, b"/data/local/tmp/lines.txt\0")
        .unwrap();
    emu.uc_mut().mem_write(p_mode_r, b"r\0").unwrap();
    emu.uc_mut().mem_write(p_lineptr, &0u64.to_le_bytes()).unwrap();
    emu.uc_mut().mem_write(p_cap, &0u64.to_le_bytes()).unwrap();

    let fn_fopen = get_hle(&mut emu, "fopen");
    let fn_fgetc = get_hle(&mut emu, "fgetc");
    let fn_ungetc = get_hle(&mut emu, "ungetc");
    let fn_getline = get_hle(&mut emu, "getline");
    let fn_fileno = get_hle(&mut emu, "fileno");
    let fn_rewind = get_hle(&mut emu, "rewind");
    let fn_fgets_chk = get_hle(&mut emu, "__fgets_chk");
    let fn_ferror = get_hle(&mut emu, "ferror");
    let fn_clearerr = get_hle(&mut emu, "clearerr");
    let fn_fclose = get_hle(&mut emu, "fclose");

    let fp = emu.call_address(fn_fopen, &[p_path, p_mode_r]).unwrap();
    assert_ne!(fp, 0);
    let fd = emu.call_address(fn_fileno, &[fp]).unwrap() as i32;
    assert!(fd >= 3, "fileno should return valid VFS fd, got {fd}");

    // fgetc + ungetc + getline
    assert_eq!(emu.call_address(fn_fgetc, &[fp]).unwrap(), b'h' as u64);
    assert_eq!(
        emu.call_address(fn_ungetc, &[b'H' as u64, fp]).unwrap(),
        b'H' as u64
    );
    let n = emu.call_address(fn_getline, &[p_lineptr, p_cap, fp]).unwrap() as i64;
    assert_eq!(n, 6);
    let heap_buf = u64::from_le_bytes(
        emu.uc()
            .mem_read_as_vec(p_lineptr, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(&emu.uc().mem_read_as_vec(heap_buf, 6).unwrap(), b"Hello\n");

    // rewind + __fgets_chk
    let _ = emu.call_address(fn_rewind, &[fp]).unwrap();
    let res = emu.call_address(fn_fgets_chk, &[p_buf, 32, fp, 32]).unwrap();
    assert_eq!(res, p_buf);
    assert_eq!(&emu.uc().mem_read_as_vec(p_buf, 6).unwrap(), b"hello\n");

    assert_eq!(emu.call_address(fn_ferror, &[fp]).unwrap(), 0);
    let _ = emu.call_address(fn_clearerr, &[fp]).unwrap();
    assert_eq!(emu.call_address(fn_fclose, &[fp]).unwrap(), 0);

    // fprintf -> overlay 文件格式化写入 + setvbuf/fflush_unlocked 别名
    let fn_fprintf = get_hle(&mut emu, "fprintf");
    let fn_setvbuf = get_hle(&mut emu, "setvbuf");
    let fn_fread_u = get_hle(&mut emu, "fread_unlocked");
    let p_fpath = scratch + 0x400;
    let p_mode_w = scratch + 0x440;
    let p_ffmt = scratch + 0x460;
    let p_tag = scratch + 0x480;
    emu.uc_mut()
        .mem_write(p_fpath, b"/data/local/tmp/fmt.txt\0")
        .unwrap();
    emu.uc_mut().mem_write(p_mode_w, b"w\0").unwrap();
    emu.uc_mut().mem_write(p_ffmt, b"id=%d tag=%s\n\0").unwrap();
    emu.uc_mut().mem_write(p_tag, b"ok\0").unwrap();

    let wfp = emu.call_address(fn_fopen, &[p_fpath, p_mode_w]).unwrap();
    assert_ne!(wfp, 0);
    assert_eq!(emu.call_address(fn_setvbuf, &[wfp, 0, 2, 0]).unwrap(), 0);
    let n_written = emu
        .call_address(fn_fprintf, &[wfp, p_ffmt, 7, p_tag])
        .unwrap();
    assert_eq!(n_written, 12);
    assert_eq!(emu.call_address(fn_fclose, &[wfp]).unwrap(), 0);

    let rfp = emu.call_address(fn_fopen, &[p_fpath, p_mode_r]).unwrap();
    assert_eq!(emu.call_address(fn_fread_u, &[p_buf, 1, 12, rfp]).unwrap(), 12);
    assert_eq!(&emu.uc().mem_read_as_vec(p_buf, 12).unwrap(), b"id=7 tag=ok\n");
    assert_eq!(emu.call_address(fn_fclose, &[rfp]).unwrap(), 0);
}
