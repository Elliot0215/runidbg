use std::collections::HashMap;

use runidbg_arm64_emu_tracer::loader::trampoline::DlModuleEntry;
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

fn read_cstr(emu: &AndroidEmulator, addr: u64) -> String {
    let bytes = emu.uc().mem_read_as_vec(addr, 128).unwrap();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[test]
fn dlopen_dlsym_dladdr_and_dl_iterate_phdr() {
    let mut emu = AndroidEmulator::builder().build().expect("build emu");

    // 注册模拟模块 libdemo.so (base=0x4000_0000, demo_fn=0x4000_1200)
    let mut syms = HashMap::new();
    syms.insert("demo_fn".to_string(), 0x4000_1200);
    emu.uc_mut()
        .get_data_mut()
        .trampolines
        .register_loaded_module(DlModuleEntry {
            name: "libdemo.so".to_string(),
            base_addr: 0x4000_0000,
            image_size: 0x10000,
            symbols: syms,
        });

    let scratch = 0x4800_0000u64;
    emu.uc_mut()
        .mem_map(scratch, 0x4000, Prot::READ | Prot::WRITE)
        .unwrap();

    let p_demo = scratch;
    let p_demo_fn = scratch + 0x40;
    let p_libc = scratch + 0x80;
    let p_strlen = scratch + 0xC0;
    let p_hello = scratch + 0x100;
    let p_dlinfo = scratch + 0x200;
    let p_cookie = scratch + 0x300;
    emu.uc_mut().mem_write(p_demo, b"libdemo.so\0").unwrap();
    emu.uc_mut().mem_write(p_demo_fn, b"demo_fn\0").unwrap();
    emu.uc_mut().mem_write(p_libc, b"libc.so\0").unwrap();
    emu.uc_mut().mem_write(p_strlen, b"strlen\0").unwrap();
    emu.uc_mut().mem_write(p_hello, b"hello\0").unwrap();

    let fn_dlopen = get_hle(&mut emu, "dlopen");
    let fn_dlsym = get_hle(&mut emu, "dlsym");
    let fn_dlclose = get_hle(&mut emu, "dlclose");
    let fn_dladdr = get_hle(&mut emu, "dladdr");
    let fn_dl_iter = get_hle(&mut emu, "dl_iterate_phdr");

    // 1. dlopen("libdemo.so") + dlsym(h, "demo_fn")
    let h_demo = emu.call_address(fn_dlopen, &[p_demo, 0]).unwrap();
    assert_ne!(h_demo, 0);
    let sym_addr = emu.call_address(fn_dlsym, &[h_demo, p_demo_fn]).unwrap();
    assert_eq!(sym_addr, 0x4000_1200);
    assert_eq!(emu.call_address(fn_dlclose, &[h_demo]).unwrap(), 0);

    // 2. dlopen("libc.so") + dlsym(h, "strlen") -> 可直接调用的真实 HLE 跳板
    let h_libc = emu.call_address(fn_dlopen, &[p_libc, 0]).unwrap();
    assert_ne!(h_libc, 0);
    let strlen_addr = emu.call_address(fn_dlsym, &[h_libc, p_strlen]).unwrap();
    assert_ne!(strlen_addr, 0);
    assert_eq!(emu.call_address(strlen_addr, &[p_hello]).unwrap(), 5);

    // 3. dladdr(0x4000_1208, &Dl_info)
    let ok = emu
        .call_address(fn_dladdr, &[0x4000_1208, p_dlinfo])
        .unwrap();
    assert_eq!(ok, 1);
    let raw_info = emu.uc().mem_read_as_vec(p_dlinfo, 32).unwrap();
    let dli_fname = u64::from_le_bytes(raw_info[0..8].try_into().unwrap());
    let dli_fbase = u64::from_le_bytes(raw_info[8..16].try_into().unwrap());
    let dli_sname = u64::from_le_bytes(raw_info[16..24].try_into().unwrap());
    let dli_saddr = u64::from_le_bytes(raw_info[24..32].try_into().unwrap());
    assert_eq!(read_cstr(&emu, dli_fname), "libdemo.so");
    assert_eq!(dli_fbase, 0x4000_0000);
    assert_eq!(read_cstr(&emu, dli_sname), "demo_fn");
    assert_eq!(dli_saddr, 0x4000_1200);

    // 4. dl_iterate_phdr(cb, cookie): cb 读取 info->dlpi_addr ([x0]) 存进 [x2]，返回 7 提前终止
    let cb_addr = 0xdead_1300u64;
    let cb_insns: [u32; 4] = [
        0xF940_0003, // ldr x3, [x0]
        0xF900_0043, // str x3, [x2]
        0xD280_00E0, // mov x0, #7
        0xD65F_03C0, // ret
    ];
    for (i, insn) in cb_insns.iter().enumerate() {
        emu.uc_mut()
            .mem_write(cb_addr + (i as u64) * 4, &insn.to_le_bytes())
            .unwrap();
    }
    let iter_ret = emu.call_address(fn_dl_iter, &[cb_addr, p_cookie]).unwrap();
    assert_eq!(iter_ret, 7);
    let seen_base = u64::from_le_bytes(
        emu.uc()
            .mem_read_as_vec(p_cookie, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(seen_base, 0x4000_0000);
}

#[test]
fn opendir_readdir_and_system_property_find_read_callback() {
    let mut emu = AndroidEmulator::builder().build().expect("build emu");
    emu.vfs_mut()
        .add_overlay_file("/data/local/tmp/alpha.txt", b"111".to_vec());
    emu.vfs_mut()
        .add_overlay_file("/data/local/tmp/beta.txt", b"222".to_vec());
    emu.vfs_mut()
        .set_property("ro.product.model", "Pixel 9 Pro");

    let scratch = 0x4900_0000u64;
    emu.uc_mut()
        .mem_map(scratch, 0x4000, Prot::READ | Prot::WRITE)
        .unwrap();

    let p_dir = scratch;
    let p_prop_key = scratch + 0x100;
    let p_name_out = scratch + 0x200;
    let p_val_out = scratch + 0x300;
    let p_cookie = scratch + 0x400;
    emu.uc_mut()
        .mem_write(p_dir, b"/data/local/tmp\0")
        .unwrap();
    emu.uc_mut()
        .mem_write(p_prop_key, b"ro.product.model\0")
        .unwrap();

    let fn_opendir = get_hle(&mut emu, "opendir");
    let fn_readdir = get_hle(&mut emu, "readdir");
    let fn_rewinddir = get_hle(&mut emu, "rewinddir");
    let fn_closedir = get_hle(&mut emu, "closedir");
    let fn_prop_find = get_hle(&mut emu, "__system_property_find");
    let fn_prop_read = get_hle(&mut emu, "__system_property_read");
    let fn_prop_cb = get_hle(&mut emu, "__system_property_read_callback");

    // 1. opendir + readdir + rewinddir + closedir
    let dirp = emu.call_address(fn_opendir, &[p_dir]).unwrap();
    assert_ne!(dirp, 0);
    let mut names = Vec::new();
    loop {
        let ent = emu.call_address(fn_readdir, &[dirp]).unwrap();
        if ent == 0 {
            break;
        }
        names.push(read_cstr(&emu, ent + 19));
    }
    assert!(names.contains(&".".to_string()));
    assert!(names.contains(&"..".to_string()));
    assert!(names.contains(&"alpha.txt".to_string()));
    assert!(names.contains(&"beta.txt".to_string()));

    let _ = emu.call_address(fn_rewinddir, &[dirp]).unwrap();
    let first_again = emu.call_address(fn_readdir, &[dirp]).unwrap();
    assert_eq!(read_cstr(&emu, first_again + 19), ".");
    assert_eq!(emu.call_address(fn_closedir, &[dirp]).unwrap(), 0);

    // 2. __system_property_find + __system_property_read + __system_property_read_callback
    let pi = emu.call_address(fn_prop_find, &[p_prop_key]).unwrap();
    assert_ne!(pi, 0);
    let vlen = emu
        .call_address(fn_prop_read, &[pi, p_name_out, p_val_out])
        .unwrap();
    assert_eq!(vlen, "Pixel 9 Pro".len() as u64);
    assert_eq!(read_cstr(&emu, p_name_out), "ro.product.model");
    assert_eq!(read_cstr(&emu, p_val_out), "Pixel 9 Pro");

    // cb(cookie=x0, name=x1, value=x2, serial=x3): 将 x2 (value_ptr) 存进 [x0]
    let cb_addr = 0xdead_1340u64;
    let cb_insns: [u32; 2] = [
        0xF900_0002, // str x2, [x0]
        0xD65F_03C0, // ret
    ];
    for (i, insn) in cb_insns.iter().enumerate() {
        emu.uc_mut()
            .mem_write(cb_addr + (i as u64) * 4, &insn.to_le_bytes())
            .unwrap();
    }
    let _ = emu
        .call_address(fn_prop_cb, &[pi, cb_addr, p_cookie])
        .unwrap();
    let seen_val_ptr = u64::from_le_bytes(
        emu.uc()
            .mem_read_as_vec(p_cookie, 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(read_cstr(&emu, seen_val_ptr), "Pixel 9 Pro");
}
