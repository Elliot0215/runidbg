use unicorn_engine::{RegisterARM64, Unicorn};

use crate::jni::types::{JObjectRef, JValue};
use crate::memory::{read_guest_i32 as read_i32_guest, read_guest_u64 as read_u64_guest};

/// JNI 方法签名中的参数类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JniParamType {
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Object,
}

/// 解析 JNI 方法签名括号内的参数列表
///
/// 例如：`(Ljava/lang/String;[BIJ)Ljava/lang/String;`
/// -> `[Object, Object, Int, Long]`
pub fn parse_jni_param_types(sig: &str) -> Vec<JniParamType> {
    let mut out = Vec::new();
    let bytes = sig.as_bytes();
    let mut i = match sig.find('(') {
        Some(pos) => pos + 1,
        None => return out,
    };

    while i < bytes.len() && bytes[i] != b')' {
        match bytes[i] {
            b'Z' => {
                out.push(JniParamType::Boolean);
                i += 1;
            }
            b'B' => {
                out.push(JniParamType::Byte);
                i += 1;
            }
            b'C' => {
                out.push(JniParamType::Char);
                i += 1;
            }
            b'S' => {
                out.push(JniParamType::Short);
                i += 1;
            }
            b'I' => {
                out.push(JniParamType::Int);
                i += 1;
            }
            b'J' => {
                out.push(JniParamType::Long);
                i += 1;
            }
            b'F' => {
                out.push(JniParamType::Float);
                i += 1;
            }
            b'D' => {
                out.push(JniParamType::Double);
                i += 1;
            }
            b'L' => {
                out.push(JniParamType::Object);
                i += 1;
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            b'[' => {
                out.push(JniParamType::Object);
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() {
                    if bytes[i] == b'L' {
                        while i < bytes.len() && bytes[i] != b';' {
                            i += 1;
                        }
                        if i < bytes.len() {
                            i += 1;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// 将原始 64 位槽位值按 JNI 参数类型解码为 `JValue`
fn decode_slot(ty: JniParamType, raw: u64) -> JValue {
    match ty {
        JniParamType::Boolean => JValue::Boolean((raw & 0xFF) != 0),
        JniParamType::Byte => JValue::Byte(raw as i8),
        JniParamType::Char => JValue::Char(raw as u16),
        JniParamType::Short => JValue::Short(raw as i16),
        JniParamType::Int => JValue::Int(raw as i32),
        JniParamType::Long => JValue::Long(raw as i64),
        JniParamType::Float => JValue::Float(f32::from_bits(raw as u32)),
        JniParamType::Double => JValue::Double(f64::from_bits(raw)),
        JniParamType::Object => JValue::Object(JObjectRef(raw)),
    }
}

/// 读取直接通过 AAPCS64 寄存器/栈传递的变参 (`Call*Method(..., ...)`)
///
/// `first_gpr_idx` 为变参起始通用寄存器编号（例如 `CallObjectMethod(env, obj, mid, ...)`
/// 占用了 `X0, X1, X2`，故 `first_gpr_idx = 3`，从 `X3..X7` 开始读取，超出部分从 `[SP + offset]` 读取）。
pub fn read_varargs_direct<D>(
    uc: &Unicorn<'_, D>,
    first_gpr_idx: usize,
    sig: &str,
) -> Vec<JValue> {
    const GPRS: [RegisterARM64; 8] = [
        RegisterARM64::X0,
        RegisterARM64::X1,
        RegisterARM64::X2,
        RegisterARM64::X3,
        RegisterARM64::X4,
        RegisterARM64::X5,
        RegisterARM64::X6,
        RegisterARM64::X7,
    ];
    const FPRS: [RegisterARM64; 8] = [
        RegisterARM64::D0,
        RegisterARM64::D1,
        RegisterARM64::D2,
        RegisterARM64::D3,
        RegisterARM64::D4,
        RegisterARM64::D5,
        RegisterARM64::D6,
        RegisterARM64::D7,
    ];

    let params = parse_jni_param_types(sig);
    let sp = uc.reg_read(RegisterARM64::SP).unwrap_or(0);
    let mut gpr = first_gpr_idx;
    let mut fpr = 0usize;
    let mut stack_off = 0u64;
    let mut values = Vec::with_capacity(params.len());

    for ty in params {
        match ty {
            // C 变参规则下 float 提升为 double 通过浮点寄存器 D0..D7 传递
            JniParamType::Float | JniParamType::Double => {
                let raw = if fpr < FPRS.len() {
                    let v = uc.reg_read(FPRS[fpr]).unwrap_or(0);
                    fpr += 1;
                    v
                } else {
                    let v = read_u64_guest(uc, sp + stack_off);
                    stack_off += 8;
                    v
                };
                if ty == JniParamType::Float {
                    values.push(JValue::Float(f64::from_bits(raw) as f32));
                } else {
                    values.push(JValue::Double(f64::from_bits(raw)));
                }
            }
            _ => {
                let raw = if gpr < GPRS.len() {
                    let v = uc.reg_read(GPRS[gpr]).unwrap_or(0);
                    gpr += 1;
                    v
                } else {
                    let v = read_u64_guest(uc, sp + stack_off);
                    stack_off += 8;
                    v
                };
                values.push(decode_slot(ty, raw));
            }
        }
    }

    values
}

/// 读取 AAPCS64 `va_list` 结构体 (`Call*MethodV`)
///
/// AAPCS64 `va_list` 内存布局（32 字节）：
/// - `+0x00`: `void *__stack`
/// - `+0x08`: `void *__gr_top`
/// - `+0x10`: `void *__vr_top`
/// - `+0x18`: `int __gr_offs`（负偏移，每次 +8）
/// - `+0x1c`: `int __vr_offs`（负偏移，每次 +16）
pub fn read_varargs_va_list<D>(uc: &Unicorn<'_, D>, va_list_ptr: u64, sig: &str) -> Vec<JValue> {
    if va_list_ptr == 0 {
        return Vec::new();
    }
    let mut stack_ptr = read_u64_guest(uc, va_list_ptr);
    let gr_top = read_u64_guest(uc, va_list_ptr + 0x08);
    let vr_top = read_u64_guest(uc, va_list_ptr + 0x10);
    let mut gr_offs = read_i32_guest(uc, va_list_ptr + 0x18);
    let mut vr_offs = read_i32_guest(uc, va_list_ptr + 0x1c);

    let params = parse_jni_param_types(sig);
    let mut values = Vec::with_capacity(params.len());

    for ty in params {
        match ty {
            JniParamType::Float | JniParamType::Double => {
                let raw = if vr_offs < 0 && vr_offs + 16 <= 0 {
                    let addr = vr_top.wrapping_add(vr_offs as i64 as u64);
                    vr_offs += 16;
                    read_u64_guest(uc, addr)
                } else {
                    let v = read_u64_guest(uc, stack_ptr);
                    stack_ptr += 8;
                    v
                };
                if ty == JniParamType::Float {
                    values.push(JValue::Float(f64::from_bits(raw) as f32));
                } else {
                    values.push(JValue::Double(f64::from_bits(raw)));
                }
            }
            _ => {
                let raw = if gr_offs < 0 && gr_offs + 8 <= 0 {
                    let addr = gr_top.wrapping_add(gr_offs as i64 as u64);
                    gr_offs += 8;
                    read_u64_guest(uc, addr)
                } else {
                    let v = read_u64_guest(uc, stack_ptr);
                    stack_ptr += 8;
                    v
                };
                values.push(decode_slot(ty, raw));
            }
        }
    }

    values
}

/// 读取 `const jvalue*` 数组 (`Call*MethodA`)
/// 每个 `jvalue` union 固定占 8 字节
pub fn read_varargs_jvalue_array<D>(
    uc: &Unicorn<'_, D>,
    jvalue_ptr: u64,
    sig: &str,
) -> Vec<JValue> {
    if jvalue_ptr == 0 {
        return Vec::new();
    }
    let params = parse_jni_param_types(sig);
    let mut values = Vec::with_capacity(params.len());
    for (idx, ty) in params.into_iter().enumerate() {
        let raw = read_u64_guest(uc, jvalue_ptr + (idx as u64) * 8);
        values.push(decode_slot(ty, raw));
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jni_signature() {
        let params = parse_jni_param_types("(Ljava/lang/String;[B[[IJZFD)Ljava/lang/String;");
        assert_eq!(
            params,
            vec![
                JniParamType::Object,
                JniParamType::Object,
                JniParamType::Object,
                JniParamType::Long,
                JniParamType::Boolean,
                JniParamType::Float,
                JniParamType::Double,
            ]
        );
    }
}
