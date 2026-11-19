use arm64_emu_tracer::cpu::{CpuContext, RET_MAGIC_ADDR};
use arm64_emu_tracer::jni::{
    attach_jni_hook, JObject, JObjectRef, JValue, JniContext, JniHandler, JniVm, MethodDesc,
    JNI_VERSION_1_6,
};
use arm64_emu_tracer::memory::{MemoryManager, PAGE_SIZE};
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM64, Unicorn};

const HEAP_BASE: u64 = 0x5000_0000;
const HEAP_SIZE: u64 = 0x0100_0000;

struct JniTestState {
    mem: MemoryManager,
    jni: JniVm,
}

/// 自定义业务 JniHandler：模拟拦截 `com/test/Signer.getSignKey(Ljava/lang/String;I)Ljava/lang/String;`
struct CustomSignHandler;

impl JniHandler for CustomSignHandler {
    fn call_object_method(
        &mut self,
        ctx: &mut JniContext<'_>,
        obj: JObjectRef,
        method: &MethodDesc,
        args: &[JValue],
    ) -> JObjectRef {
        if method.name == "getSignKey" {
            let text = args
                .first()
                .and_then(|v| v.as_object())
                .and_then(|r| ctx.objects.get_string(r))
                .unwrap_or("")
                .to_string();
            let magic = args.get(1).and_then(|v| v.as_int()).unwrap_or(0);
            return ctx.objects.add_string(format!("KEY_{magic}_{text}"));
        }
        arm64_emu_tracer::jni::handler::default_call_object_method(ctx, obj, method, args)
    }
}

/// 编码 ARM64 `LDR Xd, [Xn, #byte_offset]`（要求 byte_offset 为 8 的倍数且 < 32768）
const fn arm64_ldr_u64(rd: u32, rn: u32, byte_offset: u32) -> u32 {
    0xF940_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rd
}

/// 编码 ARM64 `MOVZ Xd, #imm16, LSL #(hw*16)`
const fn arm64_movz(rd: u32, imm16: u16, hw: u32) -> u32 {
    0xD280_0000 | (hw << 21) | ((imm16 as u32) << 5) | rd
}

/// 编码 ARM64 `MOVK Xd, #imm16, LSL #(hw*16)`
const fn arm64_movk(rd: u32, imm16: u16, hw: u32) -> u32 {
    0xF280_0000 | (hw << 21) | ((imm16 as u32) << 5) | rd
}

/// 编码 ARM64 `MOV Xd, Xm`（即 `ORR Xd, XZR, Xm`）
const fn arm64_mov_reg(rd: u32, rm: u32) -> u32 {
    0xAA00_03E0 | (rm << 16) | rd
}

/// 生成加载 64 位立即数到 `Xd` 的指令序列（最多 4 条）
fn emit_mov_u64(code: &mut Vec<u32>, rd: u32, val: u64) {
    code.push(arm64_movz(rd, (val & 0xFFFF) as u16, 0));
    if (val >> 16) & 0xFFFF != 0 {
        code.push(arm64_movk(rd, ((val >> 16) & 0xFFFF) as u16, 1));
    }
    if (val >> 32) & 0xFFFF != 0 {
        code.push(arm64_movk(rd, ((val >> 32) & 0xFFFF) as u16, 2));
    }
    if (val >> 48) & 0xFFFF != 0 {
        code.push(arm64_movk(rd, ((val >> 48) & 0xFFFF) as u16, 3));
    }
}

fn write_insns<D>(uc: &mut Unicorn<'_, D>, addr: u64, insns: &[u32]) {
    let mut raw = Vec::with_capacity(insns.len() * 4);
    for &i in insns {
        raw.extend_from_slice(&i.to_le_bytes());
    }
    uc.mem_write(addr, &raw).unwrap();
}

#[test]
fn test_jni_onload_register_natives_and_callback() {
    let state = JniTestState {
        mem: MemoryManager::new(HEAP_BASE, HEAP_SIZE),
        jni: JniVm::new(Box::new(CustomSignHandler)).with_package_name("com.test.demo"),
    };
    let mut uc = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, state).unwrap();

    // 初始化堆、CPU 上下文、JNI vtables 与 JNI 跳板 Hook
    let mut mem = MemoryManager::new(HEAP_BASE, HEAP_SIZE);
    let mut jni = JniVm::new(Box::new(CustomSignHandler)).with_package_name("com.test.demo");
    mem.init_heap(&mut uc).unwrap();
    CpuContext::init(&mut uc, &mut mem).unwrap();
    jni.init(&mut uc, &mut mem).unwrap();

    // 映射测试代码页与数据页
    let code_base = 0x4100_0000u64;
    let data_base = 0x4101_0000u64;
    mem.map_labeled(&mut uc, code_base, PAGE_SIZE, Prot::ALL, "[test:jni_code]", 0)
        .unwrap();
    mem.map_labeled(&mut uc, data_base, PAGE_SIZE, Prot::READ | Prot::WRITE, "[test:jni_data]", 0)
        .unwrap();

    let vm_ptr = jni.java_vm_ptr();
    let env_ptr = jni.jni_env_ptr();

    // 写入状态到 Unicorn
    uc.get_data_mut().mem = mem;
    uc.get_data_mut().jni = jni;
    attach_jni_hook(&mut uc, |s| (&mut s.jni, &mut s.mem)).unwrap();

    // 数据区布局
    let env_out_slot = data_base; // +0x00: JNIEnv* 输出槽
    let cls_name_addr = data_base + 0x10; // "com/test/Native"
    let method_name_addr = data_base + 0x30; // "sign"
    let method_sig_addr = data_base + 0x40; // "(Ljava/lang/String;[BLcom/test/Signer;)Ljava/lang/String;"
    let jni_methods_addr = data_base + 0x90; // JNINativeMethod[1] (24 bytes)
    let cb_name_addr = data_base + 0xC0; // "getSignKey"
    let cb_sig_addr = data_base + 0xE0; // "(Ljava/lang/String;I)Ljava/lang/String;"

    let onload_addr = code_base;
    let native_sign_addr = code_base + 0x200;

    uc.mem_write(cls_name_addr, b"com/test/Native\0").unwrap();
    uc.mem_write(method_name_addr, b"sign\0").unwrap();
    uc.mem_write(
        method_sig_addr,
        b"(Ljava/lang/String;[BLcom/test/Signer;)Ljava/lang/String;\0",
    )
    .unwrap();
    uc.mem_write(cb_name_addr, b"getSignKey\0").unwrap();
    uc.mem_write(cb_sig_addr, b"(Ljava/lang/String;I)Ljava/lang/String;\0")
        .unwrap();

    // 写入 JNINativeMethod { name, sig, fnPtr }
    uc.mem_write(jni_methods_addr, &method_name_addr.to_le_bytes())
        .unwrap();
    uc.mem_write(jni_methods_addr + 8, &method_sig_addr.to_le_bytes())
        .unwrap();
    uc.mem_write(jni_methods_addr + 16, &native_sign_addr.to_le_bytes())
        .unwrap();

    // -------------------------------------------------------------------------
    // 1. 构造 JNI_OnLoad(JavaVM* vm, void* reserved)
    // -------------------------------------------------------------------------
    let mut onload = vec![
        0xD101_03FF, // SUB SP, SP, #0x40
        0xA900_7BFD, // STP X29, X30, [SP, #0x00]
        0xA901_53F3, // STP X19, X20, [SP, #0x10]
        // (*vm)->GetEnv(vm, &env_out_slot, JNI_VERSION_1_6) -> slot 6 (offset 48)
        arm64_ldr_u64(8, 0, 0),     // LDR X8, [X0]
        arm64_ldr_u64(9, 8, 6 * 8), // LDR X9, [X8, #48]
    ];
    emit_mov_u64(&mut onload, 1, env_out_slot);
    emit_mov_u64(&mut onload, 2, JNI_VERSION_1_6 as u64);
    onload.push(0xD63F_0120); // BLR X9

    // X19 = *env_out_slot (JNIEnv*)
    emit_mov_u64(&mut onload, 8, env_out_slot);
    onload.push(arm64_ldr_u64(19, 8, 0));

    // X20 = (*env)->FindClass(env, "com/test/Native") -> slot 6 (offset 48)
    onload.push(arm64_mov_reg(0, 19));
    emit_mov_u64(&mut onload, 1, cls_name_addr);
    onload.push(arm64_ldr_u64(8, 19, 0));
    onload.push(arm64_ldr_u64(9, 8, 6 * 8));
    onload.push(0xD63F_0120); // BLR X9
    onload.push(arm64_mov_reg(20, 0));

    // (*env)->RegisterNatives(env, cls, &methods, 1) -> slot 215 (offset 215*8)
    onload.push(arm64_mov_reg(0, 19));
    onload.push(arm64_mov_reg(1, 20));
    emit_mov_u64(&mut onload, 2, jni_methods_addr);
    onload.push(arm64_movz(3, 1, 0));
    onload.push(arm64_ldr_u64(8, 19, 0));
    onload.push(arm64_ldr_u64(9, 8, 215 * 8));
    onload.push(0xD63F_0120); // BLR X9

    // return JNI_VERSION_1_6
    emit_mov_u64(&mut onload, 0, JNI_VERSION_1_6 as u64);
    onload.push(0xA941_53F3); // LDP X19, X20, [SP, #0x10]
    onload.push(0xA940_7BFD); // LDP X29, X30, [SP, #0x00]
    onload.push(0x9101_03FF); // ADD SP, SP, #0x40
    onload.push(0xD65F_03C0); // RET

    write_insns(&mut uc, onload_addr, &onload);

    // -------------------------------------------------------------------------
    // 2. 构造 native_sign(JNIEnv* env, jclass cls, jstring input, jbyteArray salt, jobject signer)
    // -------------------------------------------------------------------------
    let mut native = vec![
        0xD101_03FF, // SUB SP, SP, #0x40
        0xA900_7BFD, // STP X29, X30, [SP, #0x00]
        0xA901_53F3, // STP X19, X20, [SP, #0x10]
        0xA902_5BF5, // STP X21, X22, [SP, #0x20]
        0xF900_1BF7, // STR X23, [SP, #0x30]
        arm64_mov_reg(19, 0), // X19 = env
        arm64_mov_reg(20, 2), // X20 = input (jstring)
        arm64_mov_reg(21, 3), // X21 = salt (jbyteArray)
        arm64_mov_reg(22, 4), // X22 = signer (jobject)
        // a) elems = (*env)->GetByteArrayElements(env, salt, NULL) -> slot 184
        arm64_mov_reg(0, 19),
        arm64_mov_reg(1, 21),
        arm64_movz(2, 0, 0),
        arm64_ldr_u64(8, 19, 0),
        arm64_ldr_u64(9, 8, 184 * 8),
        0xD63F_0120,          // BLR X9
        arm64_mov_reg(23, 0), // X23 = elems
        // elems[0] += 1
        0x3940_02E8, // LDRB W8, [X23]
        0x1100_0508, // ADD W8, W8, #1
        0x3900_02E8, // STRB W8, [X23]
        // (*env)->ReleaseByteArrayElements(env, salt, elems, 0) -> slot 192 (回写修改)
        arm64_mov_reg(0, 19),
        arm64_mov_reg(1, 21),
        arm64_mov_reg(2, 23),
        arm64_movz(3, 0, 0),
        arm64_ldr_u64(8, 19, 0),
        arm64_ldr_u64(9, 8, 192 * 8),
        0xD63F_0120, // BLR X9
        // b) cls = (*env)->GetObjectClass(env, signer) -> slot 31
        arm64_mov_reg(0, 19),
        arm64_mov_reg(1, 22),
        arm64_ldr_u64(8, 19, 0),
        arm64_ldr_u64(9, 8, 31 * 8),
        0xD63F_0120,         // BLR X9
        arm64_mov_reg(1, 0), // X1 = cls
        // c) mid = (*env)->GetMethodID(env, cls, "getSignKey", "(Ljava/lang/String;I)Ljava/lang/String;") -> slot 33
        arm64_mov_reg(0, 19),
    ];
    emit_mov_u64(&mut native, 2, cb_name_addr);
    emit_mov_u64(&mut native, 3, cb_sig_addr);
    native.push(arm64_ldr_u64(8, 19, 0));
    native.push(arm64_ldr_u64(9, 8, 33 * 8));
    native.push(0xD63F_0120); // BLR X9
    native.push(arm64_mov_reg(2, 0)); // X2 = mid

    // d) res = (*env)->CallObjectMethod(env, signer, mid, input, 42) -> slot 34
    native.push(arm64_mov_reg(0, 19));
    native.push(arm64_mov_reg(1, 22));
    native.push(arm64_mov_reg(3, 20)); // arg0: jstring input
    native.push(arm64_movz(4, 42, 0)); // arg1: jint 42
    native.push(arm64_ldr_u64(8, 19, 0));
    native.push(arm64_ldr_u64(9, 8, 34 * 8));
    native.push(0xD63F_0120); // BLR X9 (返回新 jstring 到 X0)

    native.push(0xF940_1BF7); // LDR X23, [SP, #0x30]
    native.push(0xA942_5BF5); // LDP X21, X22, [SP, #0x20]
    native.push(0xA941_53F3); // LDP X19, X20, [SP, #0x10]
    native.push(0xA940_7BFD); // LDP X29, X30, [SP, #0x00]
    native.push(0x9101_03FF); // ADD SP, SP, #0x40
    native.push(0xD65F_03C0); // RET

    write_insns(&mut uc, native_sign_addr, &native);

    // 执行 JNI_OnLoad(vm_ptr, 0)
    uc.reg_write(RegisterARM64::X0, vm_ptr).unwrap();
    uc.reg_write(RegisterARM64::X1, 0).unwrap();
    uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR).unwrap();
    uc.emu_start(onload_addr, RET_MAGIC_ADDR, 0, 10_000).unwrap();

    let onload_ret = uc.reg_read(RegisterARM64::X0).unwrap() as i32;
    assert_eq!(onload_ret, JNI_VERSION_1_6);

    // 验证 RegisterNatives 捕获到了动态注册的 sign 函数指针
    let reg = uc
        .get_data()
        .jni
        .find_registered_native("com/test/Native", "sign")
        .expect("RegisterNatives 应已注册 sign 方法")
        .clone();
    assert_eq!(reg.fn_ptr, native_sign_addr);

    // 准备入参并调用动态注册的 native_sign
    let (cls_ref, input_ref, salt_ref, signer_ref) = {
        let jni = &mut uc.get_data_mut().jni;
        let cls = jni.objects.find_or_create_class("com/test/Native");
        let input = jni.objects.add_string("hello");
        let salt = jni.objects.add_byte_array(vec![0x10, 0x20, 0x30]);
        let signer = jni.objects.add_local(JObject::Custom {
            class_name: "com/test/Signer".to_string(),
            fields: Default::default(),
        });
        (cls, input, salt, signer)
    };

    uc.reg_write(RegisterARM64::X0, env_ptr).unwrap();
    uc.reg_write(RegisterARM64::X1, cls_ref.0).unwrap();
    uc.reg_write(RegisterARM64::X2, input_ref.0).unwrap();
    uc.reg_write(RegisterARM64::X3, salt_ref.0).unwrap();
    uc.reg_write(RegisterARM64::X4, signer_ref.0).unwrap();
    uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR).unwrap();
    uc.emu_start(reg.fn_ptr, RET_MAGIC_ADDR, 0, 10_000).unwrap();

    let ret_str_ref = JObjectRef(uc.reg_read(RegisterARM64::X0).unwrap());
    let ret_str = uc
        .get_data()
        .jni
        .objects
        .get_string(ret_str_ref)
        .expect("返回值应为有效 jstring");
    assert_eq!(ret_str, "KEY_42_hello");

    // 验证 ReleaseByteArrayElements(mode=0) 已将 Guest 的字节修改回写到 Rust 侧 Vec<u8>
    let salt_bytes = uc.get_data().jni.objects.get_bytes(salt_ref).unwrap();
    assert_eq!(salt_bytes, &[0x11, 0x20, 0x30]);
}

#[test]
fn test_jni_object_table_refs_and_builtin_models() {
    let mut jni = JniVm::default().with_package_name("com.android.sample");
    let ctx_ref = jni.objects.add_local(JObject::Context {
        package_name: "com.android.sample".to_string(),
    });
    let sig_ref = jni.objects.add_local(JObject::Signature(vec![0xDE, 0xAD, 0xBE, 0xEF]));

    // LocalRef -> GlobalRef 提升后，DeleteLocalRef 不应回收对象
    let g = jni.objects.new_global(sig_ref);
    jni.objects.delete_local(sig_ref);
    assert!(jni.objects.get(g).is_some());
    jni.objects.delete_global(g);
    assert!(jni.objects.get(g).is_none());

    // 测试内置 Context.getPackageName() 默认分发
    let mut jni_ctx = JniContext {
        objects: &mut jni.objects,
        package_name: "com.android.sample",
    };
    let m = MethodDesc {
        class_name: "android/content/Context".to_string(),
        name: "getPackageName".to_string(),
        sig: "()Ljava/lang/String;".to_string(),
        is_static: false,
    };
    let pkg_ref = arm64_emu_tracer::jni::handler::default_call_object_method(
        &mut jni_ctx,
        ctx_ref,
        &m,
        &[],
    );
    assert_eq!(jni.objects.get_string(pkg_ref), Some("com.android.sample"));
}

#[test]
fn test_jni_1_6_primitive_arrays_direct_buffer_and_ref_types() {
    let mut jni = JniVm::default();

    // 1. LocalRef / GlobalRef / Invalid ref_type
    let local_str = jni.objects.add_string("abc");
    assert_eq!(jni.objects.ref_type(local_str), 1); // JNILocalRefType
    jni.objects.new_global(local_str);
    assert_eq!(jni.objects.ref_type(local_str), 2); // JNIGlobalRefType
    assert_eq!(jni.objects.ref_type(JObjectRef::NULL), 0); // JNIInvalidRefType

    // 2. 全部基础类型数组读写序列化
    let mut ints = JObject::IntArray(vec![10, 20, 30]);
    assert_eq!(ints.array_len(), Some(3));
    assert_eq!(ints.primitive_elem_size(), Some(4));
    assert!(ints.write_primitive_bytes(1, &99i32.to_le_bytes()));
    let bytes = ints.to_primitive_bytes().unwrap();
    assert_eq!(&bytes[4..8], &99i32.to_le_bytes());

    let mut doubles = JObject::DoubleArray(vec![1.5, 2.5]);
    assert_eq!(doubles.primitive_elem_size(), Some(8));
    assert!(doubles.write_primitive_bytes(0, &3.25f64.to_le_bytes()));
    let dbytes = doubles.to_primitive_bytes().unwrap();
    assert_eq!(f64::from_le_bytes(dbytes[0..8].try_into().unwrap()), 3.25);

    // 3. DirectByteBuffer 模型
    let dbuf = jni.objects.add_local(JObject::DirectBuffer {
        addr: 0x5000_1000,
        capacity: 4096,
    });
    assert_eq!(
        jni.objects.get(dbuf).map(JObject::class_name),
        Some("java/nio/DirectByteBuffer")
    );
}

