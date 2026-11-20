use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;

use zip::ZipArchive;

use crate::error::{EmuError, EmuResult};

/// 解析后的 Android APK 内存镜像（`lib/arm64-v8a/*.so`、`assets/**`、签名证书与包名）
#[derive(Debug, Clone)]
pub struct ApkPackage {
    pub package_name: Option<String>,
    pub abi: String,
    pub native_libs: BTreeMap<String, Vec<u8>>,
    pub assets: BTreeMap<String, Vec<u8>>,
    pub signature_cert: Option<Vec<u8>>,
    pub raw_apk: Vec<u8>,
}

impl ApkPackage {
    /// 从磁盘路径读取并解析 APK
    pub fn from_path(path: impl AsRef<Path>) -> EmuResult<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(bytes)
    }

    /// 从内存字节流解析 APK（自动提取 `lib/arm64-v8a/*.so`、`assets/**`、`META-INF/*.RSA` 与 `AndroidManifest.xml` 包名）
    pub fn from_bytes(raw_apk: Vec<u8>) -> EmuResult<Self> {
        let cursor = Cursor::new(raw_apk.as_slice());
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| EmuError::InvalidElf(format!("解析 APK ZIP 失败: {e}")))?;

        let mut package_name: Option<String> = None;
        let mut native_libs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut assets: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut signature_cert: Option<Vec<u8>> = None;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| EmuError::InvalidElf(format!("读取 APK 条目失败: {e}")))?;
            if file.is_dir() {
                continue;
            }
            let name = file.name().to_string();

            if name == "AndroidManifest.xml" {
                let mut buf = Vec::with_capacity(file.size() as usize);
                file.read_to_end(&mut buf)?;
                package_name = parse_manifest_package_name(&buf);
            } else if let Some(lib_name) = name.strip_prefix("lib/arm64-v8a/") {
                if !lib_name.is_empty() && !lib_name.contains('/') && lib_name.ends_with(".so") {
                    let mut buf = Vec::with_capacity(file.size() as usize);
                    file.read_to_end(&mut buf)?;
                    native_libs.insert(lib_name.to_string(), buf);
                }
            } else if let Some(asset_rel) = name.strip_prefix("assets/") {
                if !asset_rel.is_empty() {
                    let mut buf = Vec::with_capacity(file.size() as usize);
                    file.read_to_end(&mut buf)?;
                    assets.insert(asset_rel.to_string(), buf);
                }
            } else if signature_cert.is_none()
                && name.starts_with("META-INF/")
                && (name.ends_with(".RSA") || name.ends_with(".DSA") || name.ends_with(".EC"))
            {
                let mut buf = Vec::with_capacity(file.size() as usize);
                file.read_to_end(&mut buf)?;
                if !buf.is_empty() {
                    signature_cert = Some(buf);
                }
            }
        }

        Ok(Self {
            package_name,
            abi: "arm64-v8a".to_string(),
            native_libs,
            assets,
            signature_cert,
            raw_apk,
        })
    }
}

/// 从 `AndroidManifest.xml` 提取 `package` 名：
/// 同时兼容标准二进制 AXML（Chunk Type `0x0003` + StringPool `0x0001` + START_ELEMENT `0x0102`）与明文 XML。
fn parse_manifest_package_name(data: &[u8]) -> Option<String> {
    // 1. 兼容明文 XML（测试或未编译清单）
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(pos) = text.find("package=\"") {
            let rest = &text[pos + "package=\"".len()..];
            if let Some(end) = rest.find('"') {
                let pkg = rest[..end].trim();
                if !pkg.is_empty() {
                    return Some(pkg.to_string());
                }
            }
        }
    }

    // 2. 二进制 AXML 解析（RES_XML_TYPE = 0x0003）
    if data.len() < 8 || read_u16(data, 0)? != 0x0003 {
        return None;
    }
    let header_size = read_u16(data, 2)? as usize;
    let mut offset = header_size;
    let mut strings: Vec<String> = Vec::new();

    while offset + 8 <= data.len() {
        let chunk_type = read_u16(data, offset)?;
        let chunk_hdr = read_u16(data, offset + 2)? as usize;
        let chunk_size = read_u32(data, offset + 4)? as usize;
        if chunk_size < 8 || offset + chunk_size > data.len() {
            break;
        }
        let chunk = &data[offset..offset + chunk_size];

        match chunk_type {
            // RES_STRING_POOL_TYPE = 0x0001
            0x0001 if chunk.len() >= 28 => {
                strings = parse_axml_string_pool(chunk);
            }
            // RES_XML_START_ELEMENT_TYPE = 0x0102
            0x0102 if chunk.len() >= chunk_hdr + 20 => {
                let body = &chunk[chunk_hdr..];
                let name_idx = read_u32(body, 4)? as usize;
                let attr_size = read_u16(body, 10)? as usize;
                let attr_count = read_u16(body, 12)? as usize;
                let elem_name = strings.get(name_idx).map(String::as_str).unwrap_or("");
                if elem_name == "manifest" && attr_size >= 20 {
                    let mut a_off = 20;
                    for _ in 0..attr_count {
                        if a_off + attr_size > body.len() {
                            break;
                        }
                        let attr_name_idx = read_u32(body, a_off + 4)? as usize;
                        let raw_val_idx = read_u32(body, a_off + 8)?;
                        let data_val = read_u32(body, a_off + 16)?;
                        if strings.get(attr_name_idx).map(String::as_str) == Some("package") {
                            let idx = if raw_val_idx != u32::MAX {
                                raw_val_idx as usize
                            } else {
                                data_val as usize
                            };
                            if let Some(pkg) = strings.get(idx) {
                                if !pkg.is_empty() {
                                    return Some(pkg.clone());
                                }
                            }
                        }
                        a_off += attr_size;
                    }
                }
            }
            _ => {}
        }
        offset += chunk_size;
    }
    None
}

fn parse_axml_string_pool(chunk: &[u8]) -> Vec<String> {
    let Some(string_count) = read_u32(chunk, 8).map(|v| v as usize) else {
        return Vec::new();
    };
    let Some(flags) = read_u32(chunk, 16) else {
        return Vec::new();
    };
    let Some(strings_start) = read_u32(chunk, 20).map(|v| v as usize) else {
        return Vec::new();
    };
    let is_utf8 = (flags & (1 << 8)) != 0;
    let offsets_base = 28usize;
    let mut out = Vec::with_capacity(string_count.min(4096));

    for i in 0..string_count {
        let Some(rel_off) = read_u32(chunk, offsets_base + i * 4).map(|v| v as usize) else {
            break;
        };
        let pos = strings_start.saturating_add(rel_off);
        if pos >= chunk.len() {
            out.push(String::new());
            continue;
        }
        if is_utf8 {
            let mut p = pos;
            // 跳过 UTF-16 字符数（1或2字节）
            if chunk[p] & 0x80 != 0 {
                p += 2;
            } else {
                p += 1;
            }
            if p >= chunk.len() {
                out.push(String::new());
                continue;
            }
            let byte_len = if chunk[p] & 0x80 != 0 {
                if p + 1 >= chunk.len() {
                    0
                } else {
                    let v = (((chunk[p] & 0x7f) as usize) << 8) | (chunk[p + 1] as usize);
                    p += 2;
                    v
                }
            } else {
                let v = chunk[p] as usize;
                p += 1;
                v
            };
            let end = p.saturating_add(byte_len).min(chunk.len());
            out.push(String::from_utf8_lossy(&chunk[p..end]).into_owned());
        } else {
            // UTF-16LE
            let Some(first) = read_u16(chunk, pos) else {
                out.push(String::new());
                continue;
            };
            let (char_len, start) = if first & 0x8000 != 0 {
                let Some(second) = read_u16(chunk, pos + 2) else {
                    out.push(String::new());
                    continue;
                };
                ((((first & 0x7fff) as usize) << 16) | (second as usize), pos + 4)
            } else {
                (first as usize, pos + 2)
            };
            let end = start.saturating_add(char_len * 2).min(chunk.len());
            let mut u16s = Vec::with_capacity(char_len);
            let mut p = start;
            while p + 1 < end {
                u16s.push(u16::from_le_bytes([chunk[p], chunk[p + 1]]));
                p += 2;
            }
            out.push(String::from_utf16_lossy(&u16s));
        }
    }
    out
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let slice = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}
