use runidbg_arm64_emu_tracer::emulator::AndroidEmulator;
use runidbg_arm64_emu_tracer::loader::HleBuiltin;
use runidbg_arm64_emu_tracer::memory::PAGE_SIZE;
use runidbg_arm64_emu_tracer::tracer::TraceLevel;
use unicorn_engine::unicorn_const::Prot;

#[test]
fn test_android_emulator_facade_and_expanded_hle() {
    let mut emu = AndroidEmulator::builder()
        .package_name("com.sample.target")
        .with_memory_trace(2048, TraceLevel::RegDelta)
        .build()
        .unwrap();

    // 分配工作缓冲区并验证扩展的 HLE `snprintf`（含 %s 与 %02x 零填充）
    let buf_addr = 0x4400_0000u64;
    let fmt_addr = 0x4400_0100u64;
    let tag_addr = 0x4400_0140u64;
    let key_addr = 0x4400_0180u64;

    emu.uc_mut()
        .mem_map(buf_addr, PAGE_SIZE, Prot::READ | Prot::WRITE)
        .unwrap();
    emu.uc_mut().mem_write(fmt_addr, b"%s:%02x\0").unwrap();
    emu.uc_mut().mem_write(tag_addr, b"sig\0").unwrap();

    // 注册 snprintf / pthread_key_create / pthread_setspecific / pthread_getspecific 跳板
    let (snprintf_addr, key_create_addr, set_spec_addr, get_spec_addr) = {
        let mut mem = std::mem::replace(
            &mut emu.uc_mut().get_data_mut().mem,
            runidbg_arm64_emu_tracer::memory::MemoryManager::new(0, 0),
        );
        let mut tramp = std::mem::take(&mut emu.uc_mut().get_data_mut().trampolines);
        let a1 = tramp
            .register(emu.uc_mut(), &mut mem, "snprintf", HleBuiltin::Snprintf)
            .unwrap();
        let a2 = tramp
            .register(
                emu.uc_mut(),
                &mut mem,
                "pthread_key_create",
                HleBuiltin::PthreadKeyCreate,
            )
            .unwrap();
        let a3 = tramp
            .register(
                emu.uc_mut(),
                &mut mem,
                "pthread_setspecific",
                HleBuiltin::PthreadSetSpecific,
            )
            .unwrap();
        let a4 = tramp
            .register(
                emu.uc_mut(),
                &mut mem,
                "pthread_getspecific",
                HleBuiltin::PthreadGetSpecific,
            )
            .unwrap();
        emu.uc_mut().get_data_mut().mem = mem;
        emu.uc_mut().get_data_mut().trampolines = tramp;
        (a1, a2, a3, a4)
    };

    // 1. 直接通过门面调用 snprintf(buf, 64, "%s:%02x", "sig", 0x0a)
    let len = emu
        .call_address(snprintf_addr, &[buf_addr, 64, fmt_addr, tag_addr, 0x0a])
        .unwrap();
    assert_eq!(len, 6);

    let mut out = [0u8; 7];
    emu.uc().mem_read(buf_addr, &mut out).unwrap();
    assert_eq!(&out, b"sig:0a\0");

    // 2. 验证 pthread TLS key 创建/读写
    assert_eq!(emu.call_address(key_create_addr, &[key_addr, 0]).unwrap(), 0);
    let mut key_bytes = [0u8; 4];
    emu.uc().mem_read(key_addr, &mut key_bytes).unwrap();
    let key = u32::from_le_bytes(key_bytes) as u64;
    assert!(key >= 1);

    assert_eq!(
        emu.call_address(set_spec_addr, &[key, 0xCAFE_BABE]).unwrap(),
        0
    );
    assert_eq!(
        emu.call_address(get_spec_addr, &[key]).unwrap(),
        0xCAFE_BABE
    );

    // 3. 验证门面内置 Tracer 已记录执行指令
    assert!(emu.tracer().records().len() >= 4);

    // 4. 验证门面快捷 JNI jstring 与快照接口
    let s_ref = emu.new_jstring("ready_for_real_so");
    assert_eq!(emu.read_jstring(s_ref), Some("ready_for_real_so"));
    let snap = emu.capture_snapshot().unwrap();
    emu.restore_snapshot(&snap).unwrap();
}
