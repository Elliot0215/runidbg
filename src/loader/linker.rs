use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use goblin::elf::header::EM_AARCH64;
use goblin::elf::reloc::{
    R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_IRELATIVE, R_AARCH64_JUMP_SLOT,
    R_AARCH64_RELATIVE, R_AARCH64_TLS_TPREL,
};
use goblin::elf::Elf;
use unicorn_engine::RegisterARM64;

use crate::backend::CpuBackend;

use crate::cpu::{CpuContext, RET_MAGIC_ADDR};
use crate::error::{EmuError, EmuResult};
use crate::loader::elf::{
    extract_dynsyms, extract_init_array, map_pt_load_segments, LoadedModule,
};
use crate::loader::trampoline::{HleBuiltin, TrampolineTable};
use crate::memory::{align_up, MemoryManager, PAGE_SIZE};

/// 默认系统库与业务库加载起始基址
const SYS_MODULE_BASE: u64 = 0x2000_0000;
const APP_MODULE_BASE: u64 = 0x4000_0000;
const MODULE_ALIGN: u64 = 0x0010_0000; // 1MB 模块间隔对齐

/// 双轨混合动态链接器
///
/// 支持：
/// 1. 递归加载 `DT_NEEDED` 依赖库（从配置的 Sysroot / 搜索目录查找真实 Android Bionic `.so`）。
/// 2. 热点函数 HLE 劫持表（如 `malloc`/`memcpy`/`__system_property_get`），优先路由至原生 Rust 跳板实现。
/// 3. 完整 AArch64 重定位（含 `R_AARCH64_IRELATIVE` 与 `R_AARCH64_TLS_TPREL64`）。
/// 4. 按依赖顺序自动执行 `.init_array` / `DT_INIT` 构造器。
pub struct DynamicLinker {
    search_paths: Vec<PathBuf>,
    memory_libs: HashMap<String, Vec<u8>>,
    modules: HashMap<String, LoadedModule>,
    load_order: Vec<String>,
    next_sys_base: u64,
    next_app_base: u64,
    /// 强制劫持到 HLE 跳板的符号集合（即便加载了真实 `libc.so` 也会被原生 Rust 实现接管）
    hle_overrides: HashSet<String>,
    /// 静态 TLS 偏移分配游标（相对于 `TPIDR_EL0`）
    next_tls_offset: u64,
}

impl Default for DynamicLinker {
    fn default() -> Self {
        Self::new(true)
    }
}

impl DynamicLinker {
    /// 创建动态链接器；`enable_default_hle_accel = true` 时默认开启高频 libc 函数 HLE 加速
    pub fn new(enable_default_hle_accel: bool) -> Self {
        let mut hle_overrides = HashSet::new();
        if enable_default_hle_accel {
            for sym in [
                "malloc",
                "calloc",
                "realloc",
                "free",
                "memcpy",
                "memmove",
                "memset",
                "memcmp",
                "strlen",
                "__system_property_get",
                "__android_log_print",
            ] {
                hle_overrides.insert(sym.to_string());
            }
        }

        Self {
            search_paths: Vec::new(),
            memory_libs: HashMap::new(),
            modules: HashMap::new(),
            load_order: Vec::new(),
            next_sys_base: SYS_MODULE_BASE,
            next_app_base: APP_MODULE_BASE,
            hle_overrides,
            next_tls_offset: 0x3000, // 避开前部 Bionic 固定槽位与 pthread/errno 区
        }
    }

    /// 添加 `.so` 依赖搜索目录（例如 Android API 30 sysroot `/system/lib64`）
    pub fn add_search_path(&mut self, dir: impl AsRef<Path>) {
        self.search_paths.push(dir.as_ref().to_path_buf());
    }

    /// 注册内存中的 `.so` 字节流（供 APK 加载后自动解析 `DT_NEEDED` 依赖，无需写临时文件）
    pub fn add_memory_library(&mut self, name: impl Into<String>, bytes: Vec<u8>) {
        self.memory_libs.insert(name.into(), bytes);
    }

    /// 按库名读取已注册的内存 `.so` 字节流
    pub fn get_memory_library(&self, name: &str) -> Option<&[u8]> {
        self.memory_libs.get(name).map(Vec::as_slice)
    }

    /// 手动启用或取消某个符号的 HLE 劫持覆盖
    pub fn set_hle_override(&mut self, symbol: &str, enabled: bool) {
        if enabled {
            self.hle_overrides.insert(symbol.to_string());
        } else {
            self.hle_overrides.remove(symbol);
        }
    }

    /// 返回按依赖拓扑顺序排列的已加载模块名列表
    pub fn load_order(&self) -> &[String] {
        &self.load_order
    }

    /// 按模块名查询已加载的 `LoadedModule`
    pub fn get_module(&self, name: &str) -> Option<&LoadedModule> {
        self.modules.get(name)
    }

    /// 从文件路径加载目标 `.so`（递归加载 `DT_NEEDED` 依赖，并可选执行 `.init_array`）
    pub fn load_file<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        mem: &mut MemoryManager,
        cpu: &CpuContext,
        trampolines: &mut TrampolineTable,
        path: impl AsRef<Path>,
        run_init: bool,
    ) -> EmuResult<LoadedModule> {
        let path_ref = path.as_ref();
        let name = path_ref
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.so")
            .to_string();

        if let Some(existing) = self.modules.get(&name) {
            return Ok(existing.clone());
        }

        let bytes = fs::read(path_ref)?;
        self.load_bytes(uc, mem, cpu, trampolines, &bytes, name, false, run_init)
    }

    /// 从字节切片加载 `.so`（供主流程与测试使用）
    #[allow(clippy::too_many_arguments)]
    pub fn load_bytes<B: CpuBackend + ?Sized>(
        &mut self,
        uc: &mut B,
        mem: &mut MemoryManager,
        cpu: &CpuContext,
        trampolines: &mut TrampolineTable,
        bytes: &[u8],
        name: String,
        is_system_lib: bool,
        run_init: bool,
    ) -> EmuResult<LoadedModule> {
        if let Some(existing) = self.modules.get(&name) {
            return Ok(existing.clone());
        }

        let elf = Elf::parse(bytes)?;
        if !elf.is_64 || elf.header.e_machine != EM_AARCH64 {
            return Err(EmuError::InvalidElf(format!(
                "模块 `{name}` 非 64 位 AArch64 ELF"
            )));
        }

        // 1. 递归加载 DT_NEEDED 依赖（优先查内存库如 APK 内置 .so，再查磁盘搜索路径；找不到则交给 HLE/Stub 兜底）
        let needed: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();
        for dep in &needed {
            if self.modules.contains_key(dep) {
                continue;
            }
            if let Some(dep_bytes) = self.memory_libs.get(dep).cloned() {
                let _ = self.load_bytes(
                    uc,
                    mem,
                    cpu,
                    trampolines,
                    &dep_bytes,
                    dep.clone(),
                    false,
                    run_init,
                )?;
            } else if let Some(dep_path) = self.find_in_search_paths(dep) {
                let dep_bytes = fs::read(&dep_path)?;
                let _ = self.load_bytes(
                    uc,
                    mem,
                    cpu,
                    trampolines,
                    &dep_bytes,
                    dep.clone(),
                    true,
                    run_init,
                )?;
            }
        }

        // 2. 分配模块加载基址并映射 PT_LOAD 段
        let base_addr = if is_system_lib {
            self.next_sys_base
        } else {
            self.next_app_base
        };
        let vma_label = if is_system_lib {
            format!("/system/lib64/{name}")
        } else {
            format!("/data/local/tmp/{name}")
        };
        let max_vaddr = map_pt_load_segments(uc, mem, &elf, bytes, base_addr, &vma_label)?;
        let image_size = align_up(max_vaddr.max(PAGE_SIZE), PAGE_SIZE);

        if is_system_lib {
            self.next_sys_base = align_up(base_addr + image_size + PAGE_SIZE, MODULE_ALIGN);
        } else {
            self.next_app_base = align_up(base_addr + image_size + PAGE_SIZE, MODULE_ALIGN);
        }

        // 3. 解析导出符号表
        let symbols = extract_dynsyms(&elf, base_addr);

        // 4. 应用完整 AArch64 重定位
        let mut irelatives = Vec::new();
        let all_relocs = elf.dynrelas.iter().chain(elf.pltrelocs.iter());
        for reloc in all_relocs {
            let patch_addr = base_addr + reloc.r_offset;
            let addend = reloc.r_addend.unwrap_or(0);

            match reloc.r_type {
                R_AARCH64_RELATIVE => {
                    let target = base_addr.wrapping_add_signed(addend);
                    mem.write_u64(uc, patch_addr, target)?;
                }
                R_AARCH64_GLOB_DAT | R_AARCH64_ABS64 | R_AARCH64_JUMP_SLOT => {
                    if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                        let sym_name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
                        let is_weak = sym.st_bind() == goblin::elf::sym::STB_WEAK;
                        let resolved = self.resolve_symbol(
                            uc,
                            mem,
                            trampolines,
                            sym_name,
                            if sym.st_value != 0 {
                                Some(base_addr + sym.st_value)
                            } else {
                                None
                            },
                            is_weak,
                        )?;
                        let target = resolved.wrapping_add_signed(addend);
                        mem.write_u64(uc, patch_addr, target)?;
                    }
                }
                R_AARCH64_IRELATIVE => {
                    // 延迟到其余常规重定位完成后执行 resolver 函数
                    let resolver_addr = base_addr.wrapping_add_signed(addend);
                    irelatives.push((patch_addr, resolver_addr));
                }
                R_AARCH64_TLS_TPREL => {
                    // 分配静态 TLS 偏移并回填
                    let tls_off = self.next_tls_offset;
                    self.next_tls_offset += 8;
                    mem.write_u64(uc, patch_addr, tls_off.wrapping_add_signed(addend))?;
                }
                _ => {}
            }
        }

        // 5. 执行 R_AARCH64_IRELATIVE 解析器并回填返回值 X0
        for (patch_addr, resolver_addr) in irelatives {
            cpu.prepare_call(uc, &[])?;
            uc.run_simple(resolver_addr, RET_MAGIC_ADDR, 0, 0)?;
            let resolved_fn = uc.reg_read(RegisterARM64::X0)?;
            mem.write_u64(uc, patch_addr, resolved_fn)?;
        }

        // 6. 提取 .init_array（必须在重定位完成后读取！）
        let init_array = extract_init_array(uc, mem, &elf, base_addr)?;

        let module = LoadedModule {
            name: name.clone(),
            base_addr,
            image_size,
            symbols,
            needed,
            init_array,
        };

        self.modules.insert(name.clone(), module.clone());
        self.load_order.push(name);

        // 7. 按需执行 .init_array / DT_INIT 构造器
        if run_init {
            Self::run_init_array(uc, cpu, &module)?;
        }

        Ok(module)
    }

    /// 符号解析优先级：
    /// 1) 若在 `hle_overrides` 加速白名单中 -> 强制路由到内置 HLE 跳板
    /// 2) 本模块内部定义符号 (`local_addr`)
    /// 3) 已加载依赖模块的全局导出符号
    /// 4) 若有内置 HLE 实现 -> 路由到内置 HLE 跳板
    /// 5) 兜底分配 `UnimplementedStub` 跳板桩
    fn resolve_symbol<B: CpuBackend + ?Sized>(
        &self,
        uc: &mut B,
        mem: &mut MemoryManager,
        trampolines: &mut TrampolineTable,
        sym_name: &str,
        local_addr: Option<u64>,
        is_weak: bool,
    ) -> EmuResult<u64> {
        if self.hle_overrides.contains(sym_name) {
            if let Some(builtin) = HleBuiltin::from_symbol(sym_name) {
                return trampolines.register(uc, mem, sym_name, builtin);
            }
        }

        if let Some(addr) = local_addr {
            return Ok(addr);
        }

        for mod_name in &self.load_order {
            if let Some(m) = self.modules.get(mod_name) {
                if let Some(&addr) = m.symbols.get(sym_name) {
                    return Ok(addr);
                }
            }
        }

        if let Some(builtin) = HleBuiltin::from_symbol(sym_name) {
            return trampolines.register(uc, mem, sym_name, builtin);
        }

        if is_weak {
            return Ok(0);
        }

        trampolines.register(
            uc,
            mem,
            sym_name,
            HleBuiltin::UnimplementedStub(sym_name.to_string()),
        )
    }

    /// 依次执行模块的 `DT_INIT` 与 `.init_array` 构造器
    pub fn run_init_array<B: CpuBackend + ?Sized>(
        uc: &mut B,
        cpu: &CpuContext,
        module: &LoadedModule,
    ) -> EmuResult<()> {
        for &init_fn in &module.init_array {
            cpu.prepare_call(uc, &[0, 0, 0])?;
            uc.run_simple(init_fn, RET_MAGIC_ADDR, 0, 0)?;
        }
        Ok(())
    }

    fn find_in_search_paths(&self, lib_name: &str) -> Option<PathBuf> {
        for dir in &self.search_paths {
            let candidate = dir.join(lib_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}
