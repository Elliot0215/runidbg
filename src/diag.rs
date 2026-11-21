use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// 缺环境诊断快照（按字典序/编号排序，便于 JSON 输出与生成补环境脚本）
#[derive(Debug, Clone, Default)]
pub struct EnvDiagSnapshot {
    pub missing_files: BTreeMap<String, u64>,
    pub missing_properties: BTreeMap<String, u64>,
    pub missing_syscalls: BTreeMap<u64, u64>,
    pub missing_jni: BTreeMap<String, u64>,
    pub missing_hle: BTreeMap<String, u64>,
    pub missing_jni_fields: BTreeMap<String, u64>,
    pub missing_auxv: BTreeMap<u64, u64>,
}

impl EnvDiagSnapshot {
    pub fn is_empty(&self) -> bool {
        self.missing_files.is_empty()
            && self.missing_properties.is_empty()
            && self.missing_syscalls.is_empty()
            && self.missing_jni.is_empty()
            && self.missing_hle.is_empty()
            && self.missing_jni_fields.is_empty()
            && self.missing_auxv.is_empty()
    }

    /// 自动生成可直接粘贴运行的 QuickJS 补环境骨架代码
    pub fn generate_patch_js(&self) -> String {
        let mut out = String::new();
        out.push_str("// === runidbg 自动生成的补环境模板 ===\n");
        out.push_str("// 将以下片段粘贴到你的仿真脚本中，按需填写真实返回值：\n\n");

        if !self.missing_properties.is_empty() {
            out.push_str("// 1. 缺失的系统属性 (android.os.SystemProperties / __system_property_get)\n");
            for (key, count) in &self.missing_properties {
                out.push_str(&format!(
                    "emu.vfs.setProperty({key:?}, \"\"); // 命中 {count} 次\n"
                ));
            }
            out.push('\n');
        }

        if !self.missing_files.is_empty() {
            out.push_str("// 2. 缺失的虚拟文件 (openat / stat / access -> ENOENT)\n");
            for (path, count) in &self.missing_files {
                out.push_str(&format!(
                    "emu.vfs.writeFile({path:?}, \"\"); // 命中 {count} 次\n"
                ));
            }
            out.push('\n');
        }

        if !self.missing_jni.is_empty() {
            out.push_str("// 3. 缺失或未处理的 JNI 调用\n");
            for (sig, count) in &self.missing_jni {
                out.push_str(&format!(
                    "emu.jni.hook({sig:?}, (ctx) => {{ /* TODO: 命中 {count} 次 */ return 0; }});\n"
                ));
            }
            out.push('\n');
        }

        if !self.missing_syscalls.is_empty() {
            out.push_str("// 4. 未实现的 ARM64 Linux Syscall (ENOSYS)\n");
            for (nr, count) in &self.missing_syscalls {
                out.push_str(&format!(
                    "emu.hook.syscall({nr}, (ctx) => {{ /* TODO: syscall #{nr} 命中 {count} 次 */ return 0; }});\n"
                ));
            }
            out.push('\n');
        }

        if !self.missing_hle.is_empty() {
            out.push_str("// 5. 未实现的外部 HLE 导入符号（返回 0）\n");
            for (sym, count) in &self.missing_hle {
                out.push_str(&format!(
                    "emu.hook.importReplace({sym:?}, (ctx) => {{ /* TODO: 命中 {count} 次 */ return 0; }});\n"
                ));
            }
            out.push('\n');
        }

        if !self.missing_jni_fields.is_empty() {
            out.push_str("// 6. 缺失的 JNI 静态/实例字段（返回 NULL/0）\n");
            for (field_key, count) in &self.missing_jni_fields {
                out.push_str(&format!(
                    "// {field_key} (命中 {count} 次) -> 可用 emu.jni.setStaticField / emu.jni.setField 注入\n"
                ));
            }
            out.push('\n');
        }

        if !self.missing_auxv.is_empty() {
            out.push_str("// 7. 未覆盖的 getauxval(type) 类型\n");
            for (at_type, count) in &self.missing_auxv {
                out.push_str(&format!(
                    "// getauxval({at_type}) 命中 {count} 次 -> 可用 emu.hook.import(\"getauxval\", ...) 注入\n"
                ));
            }
            out.push('\n');
        }

        if self.is_empty() {
            out.push_str("// 未检测到缺失的环境依赖。\n");
        }
        out
    }
}

/// 线程安全、低开销的缺环境自动诊断器（关闭时仅 1 次 Relaxed 原子读）
#[derive(Debug, Clone, Default)]
pub struct EnvDiag {
    enabled: Arc<AtomicBool>,
    data: Arc<Mutex<EnvDiagSnapshot>>,
}

impl EnvDiag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.data.lock() {
            *g = EnvDiagSnapshot::default();
        }
    }

    pub fn record_missing_file(&self, path: &str) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut g) = self.data.lock() {
            *g.missing_files.entry(path.to_string()).or_insert(0) += 1;
        }
    }

    pub fn record_missing_property(&self, key: &str) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut g) = self.data.lock() {
            *g.missing_properties.entry(key.to_string()).or_insert(0) += 1;
        }
    }

    pub fn record_missing_syscall(&self, nr: u64) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut g) = self.data.lock() {
            *g.missing_syscalls.entry(nr).or_insert(0) += 1;
        }
    }

    pub fn record_missing_jni(&self, desc: &str) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut g) = self.data.lock() {
            *g.missing_jni.entry(desc.to_string()).or_insert(0) += 1;
        }
    }

    pub fn record_missing_hle(&self, sym: &str) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut g) = self.data.lock() {
            *g.missing_hle.entry(sym.to_string()).or_insert(0) += 1;
        }
    }

    pub fn record_missing_jni_field(&self, field_key: &str) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut g) = self.data.lock() {
            *g.missing_jni_fields
                .entry(field_key.to_string())
                .or_insert(0) += 1;
        }
    }

    pub fn record_missing_auxv(&self, at_type: u64) {
        if !self.is_enabled() {
            return;
        }
        if let Ok(mut g) = self.data.lock() {
            *g.missing_auxv.entry(at_type).or_insert(0) += 1;
        }
    }

    pub fn snapshot(&self) -> EnvDiagSnapshot {
        self.data
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn generate_patch_js(&self) -> String {
        self.snapshot().generate_patch_js()
    }
}
