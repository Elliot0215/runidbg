use runidbg_arm64_emu_tracer::jni::JObjectRef;
use runidbg_arm64_emu_tracer::loader::DexValue;
use runidbg_arm64_emu_tracer::AndroidEmulator;
use unicorn_engine::unicorn_const::Prot;

fn write_uleb128(buf: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// 构造一个最小合法 DEX 035 字节流，包含：
/// - `com/example/Base` (extends `java/lang/Object`)
/// - `com/example/Config` (extends `com/example/Base`)
///   - `static final String API_KEY = "RUNIDBG-DEX-KEY"`
///   - `static final int MAGIC = 2026`
///   - `static final char[] PIN = {'A', 'B', 'C'}`
fn build_minimal_dex() -> Vec<u8> {
    // 严格按字典序排列的字符串表
    let strings = [
        "API_KEY",              // 0
        "I",                    // 1
        "Lcom/example/Base;",   // 2
        "Lcom/example/Config;", // 3
        "Ljava/lang/Object;",   // 4
        "Ljava/lang/String;",   // 5
        "MAGIC",                // 6
        "PIN",                  // 7
        "RUNIDBG-DEX-KEY",      // 8
        "[C",                   // 9
    ];
    // type_ids: index -> string_idx
    // 0: I (1)
    // 1: Lcom/example/Base; (2)
    // 2: Lcom/example/Config; (3)
    // 3: Ljava/lang/Object; (4)
    // 4: Ljava/lang/String; (5)
    // 5: [C (9)
    let type_str_idxs: [u32; 6] = [1, 2, 3, 4, 5, 9];

    // field_ids: (class_type_idx, type_idx, name_str_idx)
    // 0: Config.API_KEY : Ljava/lang/String;
    // 1: Config.MAGIC   : I
    // 2: Config.PIN     : [C
    let fields: [(u16, u16, u32); 3] = [
        (2, 4, 0),
        (2, 0, 6),
        (2, 5, 7),
    ];

    let header_size = 112usize;
    let string_ids_off = header_size;
    let type_ids_off = string_ids_off + strings.len() * 4;
    let field_ids_off = type_ids_off + type_str_idxs.len() * 4;
    let class_defs_off = field_ids_off + fields.len() * 8;
    let data_start = class_defs_off + 2 * 32;

    let mut buf = vec![0u8; data_start];

    // 写入 string_data_item 并回填 string_ids
    for (i, s) in strings.iter().enumerate() {
        let off = buf.len() as u32;
        buf[string_ids_off + i * 4..string_ids_off + i * 4 + 4]
            .copy_from_slice(&off.to_le_bytes());
        write_uleb128(&mut buf, s.encode_utf16().count() as u32);
        buf.extend_from_slice(s.as_bytes());
        buf.push(0);
    }

    // 写入 type_ids
    for (i, &sidx) in type_str_idxs.iter().enumerate() {
        buf[type_ids_off + i * 4..type_ids_off + i * 4 + 4].copy_from_slice(&sidx.to_le_bytes());
    }

    // 写入 field_ids
    for (i, &(cidx, tidx, nidx)) in fields.iter().enumerate() {
        let base = field_ids_off + i * 8;
        buf[base..base + 2].copy_from_slice(&cidx.to_le_bytes());
        buf[base + 2..base + 4].copy_from_slice(&tidx.to_le_bytes());
        buf[base + 4..base + 8].copy_from_slice(&nidx.to_le_bytes());
    }

    // Config 的 class_data_item（3 个 static fields，0 instance/direct/virtual）
    let config_class_data_off = buf.len() as u32;
    write_uleb128(&mut buf, 3); // static_fields_size
    write_uleb128(&mut buf, 0);
    write_uleb128(&mut buf, 0);
    write_uleb128(&mut buf, 0);
    // field 0 (diff=0), field 1 (diff=1), field 2 (diff=1)
    write_uleb128(&mut buf, 0);
    write_uleb128(&mut buf, 0x0019); // public static final
    write_uleb128(&mut buf, 1);
    write_uleb128(&mut buf, 0x0019);
    write_uleb128(&mut buf, 1);
    write_uleb128(&mut buf, 0x0019);

    // Config 的 static_values_off (encoded_array_item: 3 个值)
    let config_static_values_off = buf.len() as u32;
    write_uleb128(&mut buf, 3);
    // [0] VALUE_STRING(0x17), arg=0 (1 byte idx = 8 -> "RUNIDBG-DEX-KEY")
    buf.push(0x17);
    buf.push(8);
    // [1] VALUE_INT(0x04), arg=1 (2 bytes LE = 2026 = 0x07EA)
    buf.push((1 << 5) | 0x04);
    buf.extend_from_slice(&2026u16.to_le_bytes());
    // [2] VALUE_ARRAY(0x1C): 3 个 VALUE_CHAR(0x03) = 'A', 'B', 'C'
    buf.push(0x1C);
    write_uleb128(&mut buf, 3);
    for ch in *b"ABC" {
        buf.push(0x03); // VALUE_CHAR, arg=0 (1 byte)
        buf.push(ch);
    }

    // class_def 0: com/example/Base (super = Object)
    let c0 = class_defs_off;
    buf[c0..c0 + 4].copy_from_slice(&1u32.to_le_bytes()); // class_idx = Base
    buf[c0 + 4..c0 + 8].copy_from_slice(&0x0001u32.to_le_bytes()); // public
    buf[c0 + 8..c0 + 12].copy_from_slice(&3u32.to_le_bytes()); // superclass = Object
    buf[c0 + 16..c0 + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // class_def 1: com/example/Config (super = Base, class_data + static_values)
    let c1 = class_defs_off + 32;
    buf[c1..c1 + 4].copy_from_slice(&2u32.to_le_bytes()); // class_idx = Config
    buf[c1 + 4..c1 + 8].copy_from_slice(&0x0001u32.to_le_bytes());
    buf[c1 + 8..c1 + 12].copy_from_slice(&1u32.to_le_bytes()); // superclass = Base
    buf[c1 + 16..c1 + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf[c1 + 24..c1 + 28].copy_from_slice(&config_class_data_off.to_le_bytes());
    buf[c1 + 28..c1 + 32].copy_from_slice(&config_static_values_off.to_le_bytes());

    // 填充 DEX header (112 bytes)
    buf[0..8].copy_from_slice(b"dex\n035\0");
    let file_size = buf.len() as u32;
    buf[32..36].copy_from_slice(&file_size.to_le_bytes());
    buf[36..40].copy_from_slice(&112u32.to_le_bytes());
    buf[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    buf[56..60].copy_from_slice(&(strings.len() as u32).to_le_bytes());
    buf[60..64].copy_from_slice(&(string_ids_off as u32).to_le_bytes());
    buf[64..68].copy_from_slice(&(type_str_idxs.len() as u32).to_le_bytes());
    buf[68..72].copy_from_slice(&(type_ids_off as u32).to_le_bytes());
    buf[80..84].copy_from_slice(&(fields.len() as u32).to_le_bytes());
    buf[84..88].copy_from_slice(&(field_ids_off as u32).to_le_bytes());
    buf[96..100].copy_from_slice(&2u32.to_le_bytes());
    buf[100..104].copy_from_slice(&(class_defs_off as u32).to_le_bytes());

    buf
}

#[test]
fn dex_metadata_static_values_superclass_and_strict_find_class() {
    let dex = build_minimal_dex();
    let mut emu = AndroidEmulator::builder()
        .package_name("com.example.demo")
        .build()
        .expect("build emu");

    let count = emu.load_dex_bytes("classes.dex", &dex).expect("load dex");
    assert_eq!(count, 2);
    assert!(emu.jni().dex_index.has_class("com/example/Config"));
    assert_eq!(
        emu.jni().dex_index.get_static_value("com/example/Config", "MAGIC"),
        Some(&DexValue::Int(2026))
    );
    assert!(emu
        .vfs()
        .get_overlay_file("/data/app/com.example.demo/classes.dex")
        .is_some());

    // 通过真实 JNIEnv vtable 测试 GetStaticObjectField / GetStaticIntField / GetSuperclass / IsAssignableFrom / strict FindClass
    let env_ptr = emu.jni().jni_env_ptr();
    let mut vtable_bytes = [0u8; 8];
    emu.uc().mem_read(env_ptr, &mut vtable_bytes).unwrap();
    let vtable = u64::from_le_bytes(vtable_bytes);
    let read_slot = |emu: &AndroidEmulator, slot: u64| -> u64 {
        let mut b = [0u8; 8];
        emu.uc().mem_read(vtable + slot * 8, &mut b).unwrap();
        u64::from_le_bytes(b)
    };
    let fn_find_class = read_slot(&emu, 6);
    let fn_get_superclass = read_slot(&emu, 10);
    let fn_is_assignable = read_slot(&emu, 11);
    let fn_exc_check = read_slot(&emu, 228);
    let fn_exc_clear = read_slot(&emu, 17);
    let fn_get_static_fid = read_slot(&emu, 144);
    let fn_get_static_obj = read_slot(&emu, 145);
    let fn_get_static_int = read_slot(&emu, 150);

    let scratch = 0x4700_0000u64;
    emu.uc_mut()
        .mem_map(scratch, 0x2000, Prot::READ | Prot::WRITE)
        .unwrap();
    let mut write_s = |off: u64, s: &str| -> u64 {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0);
        emu.uc_mut().mem_write(scratch + off, &bytes).unwrap();
        scratch + off
    };
    let p_cfg = write_s(0, "com/example/Config");
    let p_base = write_s(32, "com/example/Base");
    let p_fake = write_s(64, "com/fake/AntiEmu");
    let p_sys = write_s(96, "java/lang/String");
    let p_api_key = write_s(128, "API_KEY");
    let p_sig_str = write_s(144, "Ljava/lang/String;");
    let p_magic = write_s(176, "MAGIC");
    let p_sig_int = write_s(192, "I");
    let p_pin = write_s(208, "PIN");
    let p_sig_carr = write_s(224, "[C");

    let cls_cfg = emu.call_address(fn_find_class, &[env_ptr, p_cfg]).unwrap();
    let cls_base = emu.call_address(fn_find_class, &[env_ptr, p_base]).unwrap();
    assert_ne!(cls_cfg, 0);
    assert_ne!(cls_base, 0);

    // 1. 静态 String / int / [C 字段自动从 DEX static_values 回填
    let fid_key = emu
        .call_address(fn_get_static_fid, &[env_ptr, cls_cfg, p_api_key, p_sig_str])
        .unwrap();
    let key_ref = emu
        .call_address(fn_get_static_obj, &[env_ptr, cls_cfg, fid_key])
        .unwrap();
    assert_eq!(
        emu.jni().objects.get_string(JObjectRef(key_ref)),
        Some("RUNIDBG-DEX-KEY")
    );

    let fid_magic = emu
        .call_address(fn_get_static_fid, &[env_ptr, cls_cfg, p_magic, p_sig_int])
        .unwrap();
    assert_eq!(
        emu.call_address(fn_get_static_int, &[env_ptr, cls_cfg, fid_magic])
            .unwrap(),
        2026
    );

    let fid_pin = emu
        .call_address(fn_get_static_fid, &[env_ptr, cls_cfg, p_pin, p_sig_carr])
        .unwrap();
    let pin_ref = emu
        .call_address(fn_get_static_obj, &[env_ptr, cls_cfg, fid_pin])
        .unwrap();
    assert_eq!(
        emu.jni().objects.get_chars(JObjectRef(pin_ref)),
        Some([b'A' as u16, b'B' as u16, b'C' as u16].as_slice())
    );

    // 2. GetSuperclass & IsAssignableFrom
    let sup = emu
        .call_address(fn_get_superclass, &[env_ptr, cls_cfg])
        .unwrap();
    assert_eq!(sup, cls_base);
    assert_eq!(
        emu.call_address(fn_is_assignable, &[env_ptr, cls_cfg, cls_base])
            .unwrap(),
        1
    );
    assert_eq!(
        emu.call_address(fn_is_assignable, &[env_ptr, cls_base, cls_cfg])
            .unwrap(),
        0
    );

    // 3. FindClass 严格模式：假类返回 NULL + 抛 ClassNotFoundException，系统类与真实类放行
    emu.jni_mut().strict_find_class = true;
    assert_eq!(
        emu.call_address(fn_find_class, &[env_ptr, p_fake]).unwrap(),
        0
    );
    assert_eq!(emu.call_address(fn_exc_check, &[env_ptr]).unwrap(), 1);
    let _ = emu.call_address(fn_exc_clear, &[env_ptr]).unwrap();
    assert_ne!(
        emu.call_address(fn_find_class, &[env_ptr, p_sys]).unwrap(),
        0
    );
    assert_ne!(
        emu.call_address(fn_find_class, &[env_ptr, p_cfg]).unwrap(),
        0
    );
}

#[cfg(feature = "js")]
#[test]
fn js_dex_load_and_query() {
    use runidbg_arm64_emu_tracer::script::JsRunner;

    let dex = build_minimal_dex();
    let tmp = std::env::temp_dir().join("runidbg_test_classes.dex");
    std::fs::write(&tmp, &dex).unwrap();

    let script = format!(
        r#"
        const emu = Emu.create({{ packageName: "com.example.jsdex" }});
        const res = emu.loadDex({path:?});
        if (res.classes !== 2 || res.dexCount !== 1) {{
            throw new Error("unexpected loadDex result: " + JSON.stringify(res));
        }}
        const list = emu.dex.classes("com/example/");
        if (list.length !== 2 || list[0] !== "com/example/Base" || list[1] !== "com/example/Config") {{
            throw new Error("unexpected dex.classes: " + JSON.stringify(list));
        }}
        const info = emu.dex.classInfo("com/example/Config");
        if (!info || info.superClass !== "com/example/Base" || info.staticValues.API_KEY !== "RUNIDBG-DEX-KEY" || info.staticValues.MAGIC !== 2026) {{
            throw new Error("unexpected dex.classInfo: " + JSON.stringify(info));
        }}
        emu.jni.setStrictFindClass(true);
        "#,
        path = tmp.to_string_lossy()
    );

    JsRunner::run_source_with_args(&script, &[]).expect("JS DEX test failed");
    let _ = std::fs::remove_file(&tmp);
}
