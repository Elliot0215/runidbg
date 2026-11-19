use std::collections::HashMap;
use std::fs;
use std::path::Path;

use goblin::elf::header::EM_AARCH64;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::reloc::{
    R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE,
};
use goblin::elf::Elf;
use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::Unicorn;

use crate::error::{EmuError, EmuResult};
use crate::memory::{align_up, MemoryManager, PAGE_SIZE};

/// 已加载的 ELF 模块元数据
#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub base_addr: u64,
    pub image_size: u64,
    /// 导出符号表：符号名 -> 运行时绝对虚拟地址
    pub symbols: HashMap<String, u64>,
    /// `DT_NEEDED` 依赖库列表
    pub needed: Vec<String>,
    /// `DT_INIT` 与 `DT_INIT_ARRAY` 构造器绝对地址列表（按执行顺序）
    pub init_array: Vec<u64>,
}

impl LoadedModule {
    /// 按名称查找导出函数/全局变量地址
    pub fn find_symbol(&self, name: &str) -> EmuResult<u64> {
        self.symbols
            .get(name)
            .copied()
            .ok_or_else(|| EmuError::SymbolNotFound(name.to_string()))
    }
}

/// 精简版 ARM64 ELF Loader（保留 v0.1 简洁接口，供单模块快速加载）
pub struct ElfLoader;

impl ElfLoader {
    /// 从文件路径加载 Android ARM64 `.so`
    pub fn load_so<D>(
        uc: &mut Unicorn<'_, D>,
        mem: &mut MemoryManager,
        path: impl AsRef<Path>,
        base_addr: u64,
    ) -> EmuResult<LoadedModule> {
        let path_ref = path.as_ref();
        let bytes = fs::read(path_ref)?;
        let name = path_ref
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.so")
            .to_string();
        Self::load_bytes(uc, mem, &bytes, name, base_addr)
    }

    /// 从内存字节切片加载 Android ARM64 ELF 并完成基础重定位
    pub fn load_bytes<D>(
        uc: &mut Unicorn<'_, D>,
        mem: &mut MemoryManager,
        bytes: &[u8],
        name: String,
        base_addr: u64,
    ) -> EmuResult<LoadedModule> {
        let elf = Elf::parse(bytes)?;

        // 1. 校验架构与位宽：必须为 64-bit AArch64 ELF
        if !elf.is_64 || elf.header.e_machine != EM_AARCH64 {
            return Err(EmuError::InvalidElf(format!(
                "仅支持 64 位 AArch64 ELF (is_64={}, e_machine={})",
                elf.is_64, elf.header.e_machine
            )));
        }

        // 2. 遍历并映射所有 PT_LOAD 段
        let vma_label = format!("/data/local/tmp/{name}");
        let max_vaddr = map_pt_load_segments(uc, mem, &elf, bytes, base_addr, &vma_label)?;

        // 3. 解析 .dynsym 导出符号表
        let symbols = extract_dynsyms(&elf, base_addr);

        // 4. 处理基础重定位 (.rela.dyn 与 .rela.plt)
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
                        if sym.st_value != 0 {
                            let sym_addr = base_addr + sym.st_value;
                            let target = sym_addr.wrapping_add_signed(addend);
                            mem.write_u64(uc, patch_addr, target)?;
                        }
                    }
                }
                _ => {}
            }
        }

        let needed = elf.libraries.iter().map(|s| s.to_string()).collect();
        let init_array = extract_init_array(uc, mem, &elf, base_addr)?;

        Ok(LoadedModule {
            name,
            base_addr,
            image_size: align_up(max_vaddr, PAGE_SIZE),
            symbols,
            needed,
            init_array,
        })
    }
}

/// 映射 ELF 中所有 `PT_LOAD` 段并返回最高虚拟地址偏移
pub(crate) fn map_pt_load_segments<D>(
    uc: &mut Unicorn<'_, D>,
    mem: &mut MemoryManager,
    elf: &Elf<'_>,
    bytes: &[u8],
    base_addr: u64,
    vma_label: &str,
) -> EmuResult<u64> {
    let mut max_vaddr: u64 = 0;
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }

        let seg_vaddr = base_addr + ph.p_vaddr;
        let perms = elf_flags_to_prot(ph.p_flags);

        mem.map_labeled(uc, seg_vaddr, ph.p_memsz, perms, vma_label, ph.p_offset)?;

        let file_off = ph.p_offset as usize;
        let file_sz = ph.p_filesz as usize;
        if file_sz > 0 {
            let file_end = file_off + file_sz;
            if file_end > bytes.len() {
                return Err(EmuError::InvalidElf(format!(
                    "PT_LOAD 段越界: offset=0x{file_off:x}, filesz=0x{file_sz:x}"
                )));
            }
            mem.write(uc, seg_vaddr, &bytes[file_off..file_end])?;
        }

        max_vaddr = max_vaddr.max(ph.p_vaddr + ph.p_memsz);
    }
    Ok(max_vaddr)
}

/// 提取 `.dynsym` 中本模块定义的导出符号
pub(crate) fn extract_dynsyms(elf: &Elf<'_>, base_addr: u64) -> HashMap<String, u64> {
    let mut symbols = HashMap::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_value == 0 {
            continue;
        }
        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            if !sym_name.is_empty() {
                symbols.insert(sym_name.to_string(), base_addr + sym.st_value);
            }
        }
    }
    symbols
}

/// 从 `PT_DYNAMIC` 中提取 `DT_INIT` 与 `DT_INIT_ARRAY` 构造器函数地址列表
/// 注意：必须在完成重定位之后调用，因为 `.init_array` 内的指针通常依赖 `R_AARCH64_RELATIVE` 回填
pub(crate) fn extract_init_array<D>(
    uc: &Unicorn<'_, D>,
    mem: &MemoryManager,
    elf: &Elf<'_>,
    base_addr: u64,
) -> EmuResult<Vec<u64>> {
    let mut funcs = Vec::new();
    let Some(dynamic) = &elf.dynamic else {
        return Ok(funcs);
    };

    // 注意：goblin 的 `dynamic.info` 会将部分指针字段做 `vm_to_offset` 转换为文件偏移，
    // 在多段 PT_LOAD（p_vaddr != p_offset）的真实 Android `.so` 上会导致地址错位！
    // 因此直接遍历原始 `dynamic.dyns` 读取未转换的虚拟地址（DT_INIT / DT_INIT_ARRAY / DT_INIT_ARRAYSZ）。
    let mut init_vaddr: u64 = 0;
    let mut init_array_vaddr: u64 = 0;
    let mut init_array_sz: u64 = 0;

    for dyn_entry in &dynamic.dyns {
        match dyn_entry.d_tag {
            goblin::elf::dynamic::DT_INIT => init_vaddr = dyn_entry.d_val,
            goblin::elf::dynamic::DT_INIT_ARRAY => init_array_vaddr = dyn_entry.d_val,
            goblin::elf::dynamic::DT_INIT_ARRAYSZ => init_array_sz = dyn_entry.d_val,
            _ => {}
        }
    }

    if init_vaddr != 0 {
        funcs.push(base_addr + init_vaddr);
    }
    if init_array_vaddr != 0 && init_array_sz > 0 {
        let array_addr = base_addr + init_array_vaddr;
        let count = init_array_sz / 8;
        for i in 0..count {
            let fn_ptr = mem.read_u64(uc, array_addr + i * 8)?;
            // 按 ELF 规范跳过 0 和 -1 (0xFFFF_FFFF_FFFF_FFFF) 哨兵值
            if fn_ptr != 0 && fn_ptr != u64::MAX {
                funcs.push(fn_ptr);
            }
        }
    }

    Ok(funcs)
}

/// 将 ELF ProgramHeader 的 PF_R/PF_W/PF_X 权限位转换为 Unicorn Prot
#[inline]
pub(crate) fn elf_flags_to_prot(flags: u32) -> Prot {
    let mut prot = Prot::NONE;
    if flags & PF_R != 0 {
        prot |= Prot::READ;
    }
    if flags & PF_W != 0 {
        prot |= Prot::WRITE;
    }
    if flags & PF_X != 0 {
        prot |= Prot::EXEC;
    }
    prot
}
