use std::path::{Path, PathBuf};

use unicorn_engine::unicorn_const::{Arch, Mode};
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

use crate::cpu::{CpuContext, RET_MAGIC_ADDR};
use crate::error::{EmuError, EmuResult};
use crate::jni::{attach_jni_hook, DefaultJniHandler, JObjectRef, JniHandler, JniVm};
use crate::loader::{attach_trampoline_hook, DynamicLinker, LoadedModule, TrampolineTable};
use crate::memory::MemoryManager;
use crate::os::{attach_syscall_hook, VirtualFs};
use crate::snapshot::EmuSnapshot;
use crate::tracer::{attach_code_hook, attach_mem_trace_hook, BinaryTracer, TraceLevel};

/// 默认模拟堆基址与大小（32MB）
pub const DEFAULT_HEAP_BASE: u64 = 0x5000_0000;
pub const DEFAULT_HEAP_SIZE: u64 = 0x0200_0000;

/// 挂载在 Unicorn UserData 中的统一运行时状态
pub struct EmuState {
    pub mem: MemoryManager,
    pub vfs: VirtualFs,
    pub trampolines: TrampolineTable,
    pub jni: JniVm,
    pub tracer: BinaryTracer,
}

/// 开箱即用的 Android ARM64 模拟器构建器
pub struct AndroidEmulatorBuilder {
    package_name: String,
    heap_base: u64,
    heap_size: u64,
    sysroot_dirs: Vec<PathBuf>,
    enable_hle_accel: bool,
    jni_handler: Box<dyn JniHandler>,
    trace_capacity: usize,
    trace_level: TraceLevel,
    auto_attach_trace: bool,
}

impl Default for AndroidEmulatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidEmulatorBuilder {
    pub fn new() -> Self {
        Self {
            package_name: "com.example.app".to_string(),
            heap_base: DEFAULT_HEAP_BASE,
            heap_size: DEFAULT_HEAP_SIZE,
            sysroot_dirs: Vec::new(),
            enable_hle_accel: true,
            jni_handler: Box::new(DefaultJniHandler),
            trace_capacity: 65_536,
            trace_level: TraceLevel::RegDelta,
            auto_attach_trace: false,
        }
    }

    /// 设置模拟进程包名（同步生效于 `/proc/self/cmdline` 与 `JniVm`）
    pub fn package_name(mut self, pkg: impl Into<String>) -> Self {
        self.package_name = pkg.into();
        self
    }

    /// 配置模拟堆基址与容量
    pub fn heap(mut self, base: u64, size: u64) -> Self {
        self.heap_base = base;
        self.heap_size = size;
        self
    }

    /// 添加 Android ARM64 Sysroot / `.so` 搜索目录（如 `/system/lib64`）
    pub fn add_search_path(mut self, dir: impl AsRef<Path>) -> Self {
        self.sysroot_dirs.push(dir.as_ref().to_path_buf());
        self
    }

    /// 是否启用高频 libc 热点函数原生 Rust HLE 加速（默认开启）
    pub fn hle_accel(mut self, enabled: bool) -> Self {
        self.enable_hle_accel = enabled;
        self
    }

    /// 注入自定义业务 `JniHandler`
    pub fn jni_handler(mut self, handler: Box<dyn JniHandler>) -> Self {
        self.jni_handler = handler;
        self
    }

    /// 启用内存模式 Trace（指定预分配条数与分层级别）
    pub fn with_memory_trace(mut self, capacity: usize, level: TraceLevel) -> Self {
        self.trace_capacity = capacity;
        self.trace_level = level;
        self.auto_attach_trace = true;
        self
    }

    /// 构建并初始化完整的 `AndroidEmulator` 实例
    pub fn build(self) -> EmuResult<AndroidEmulator> {
        let mut mem = MemoryManager::new(self.heap_base, self.heap_size);
        let mut vfs = VirtualFs::new(&self.package_name);
        let mut trampolines = TrampolineTable::new();
        let mut jni = JniVm::new(self.jni_handler).with_package_name(&self.package_name);
        let tracer = BinaryTracer::new_in_memory_with_level(self.trace_capacity, self.trace_level);

        for dir in &self.sysroot_dirs {
            vfs.mount_readonly("/system", dir);
        }

        let placeholder = EmuState {
            mem: MemoryManager::new(0, 0),
            vfs: VirtualFs::new(&self.package_name),
            trampolines: TrampolineTable::new(),
            jni: JniVm::default(),
            tracer: BinaryTracer::new_in_memory(0),
        };
        let mut uc = Unicorn::new_with_data(Arch::ARM64, Mode::LITTLE_ENDIAN, placeholder)?;

        // 1. 初始化堆、CPU(NEON + TLS)、HLE 跳板区与 JNI 虚函数表
        mem.init_heap(&mut uc)?;
        let cpu = CpuContext::init(&mut uc, &mut mem)?;
        trampolines.errno_addr = cpu.errno_addr;
        trampolines.init(&mut uc, &mut mem)?;
        jni.init(&mut uc, &mut mem)?;

        // 2. 注入完整状态到 Unicorn UserData
        let state = uc.get_data_mut();
        state.mem = mem;
        state.vfs = vfs;
        state.trampolines = trampolines;
        state.jni = jni;
        state.tracer = tracer;

        // 3. 自动挂载 Syscall / HLE Trampoline / JNI 三个核心 Hook
        attach_syscall_hook(&mut uc, |s| (&mut s.mem, &mut s.vfs))?;
        attach_trampoline_hook(&mut uc, |s| (&mut s.trampolines, &mut s.mem, &mut s.vfs))?;
        attach_jni_hook(&mut uc, |s| (&mut s.jni, &mut s.mem))?;

        let mut linker = DynamicLinker::new(self.enable_hle_accel);
        for dir in &self.sysroot_dirs {
            linker.add_search_path(dir);
        }

        let mut emu = AndroidEmulator {
            uc,
            cpu,
            linker,
            trace_code_hook: None,
            trace_mem_hook: None,
        };

        if self.auto_attach_trace {
            emu.attach_tracer(0, u64::MAX)?;
        }

        Ok(emu)
    }
}

/// 统一高层 Android ARM64 模拟器门面
///
/// 封装了 Unicorn 引擎、MMU、Overlay VFS、动态链接器、HLE 跳板、JNI 桥接与 Trace 引擎，
/// 提供开箱即用的 `.so` 加载、`JNI_OnLoad` 引导、函数调用与快照回放接口。
pub struct AndroidEmulator {
    uc: Unicorn<'static, EmuState>,
    cpu: CpuContext,
    linker: DynamicLinker,
    trace_code_hook: Option<UcHookId>,
    trace_mem_hook: Option<UcHookId>,
}

impl AndroidEmulator {
    pub fn builder() -> AndroidEmulatorBuilder {
        AndroidEmulatorBuilder::new()
    }

    /// 从文件路径加载目标 `.so`（自动解析 `DT_NEEDED`、执行重定位与 `.init_array`）
    pub fn load_library(&mut self, path: impl AsRef<Path>) -> EmuResult<LoadedModule> {
        let path_ref = path.as_ref();
        let name = path_ref
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "target.so".to_string());
        let bytes = std::fs::read(path_ref)?;
        self.load_library_bytes(&name, &bytes, true)
    }

    /// 从内存字节流加载目标 `.so`（可选是否立即执行 `.init_array`）
    pub fn load_library_bytes(
        &mut self,
        name: &str,
        bytes: &[u8],
        run_init_array: bool,
    ) -> EmuResult<LoadedModule> {
        let prev_loaded = self.linker.load_order().len();

        // 暂移 mem 与 trampolines 进行静态映射与重定位（避免同时借用 &mut uc 与 UserData）
        let mut mem = std::mem::replace(
            &mut self.uc.get_data_mut().mem,
            MemoryManager::new(0, 0),
        );
        let mut trampolines = std::mem::take(&mut self.uc.get_data_mut().trampolines);

        let load_res = self.linker.load_bytes(
            &mut self.uc,
            &mut mem,
            &self.cpu,
            &mut trampolines,
            bytes,
            name.to_string(),
            false,
            false,
        );

        // 归还 mem 与 trampolines，确保后续执行 .init_array 时 Syscall/HLE Hook 可正常访问
        self.uc.get_data_mut().mem = mem;
        self.uc.get_data_mut().trampolines = trampolines;

        let module = load_res?;

        if run_init_array {
            // 按依赖拓扑顺序依次执行所有新加载模块（含 DT_NEEDED 依赖）的 .init_array
            let init_fns: Vec<u64> = self.linker.load_order()[prev_loaded..]
                .iter()
                .filter_map(|m| self.linker.get_module(m))
                .flat_map(|m| m.init_array.iter().copied())
                .filter(|&addr| addr != 0)
                .collect();
            for init_fn in init_fns {
                let _ = self.call_address(init_fn, &[]);
            }
        }

        Ok(module)
    }

    /// 若模块导出了 `JNI_OnLoad`，自动传入 `(JavaVM*, NULL)` 执行并返回 JNI 版本号
    pub fn call_jni_onload(&mut self, module: &LoadedModule) -> EmuResult<Option<i32>> {
        let Ok(addr) = module.find_symbol("JNI_OnLoad") else {
            return Ok(None);
        };
        let vm_ptr = self.uc.get_data().jni.java_vm_ptr();
        let ret = self.call_address(addr, &[vm_ptr, 0])?;
        Ok(Some(ret as i32))
    }

    /// 按导出符号名调用目标函数（最多 8 个寄存器参数 `X0..X7`），返回 `X0`
    pub fn call_symbol(
        &mut self,
        module: &LoadedModule,
        symbol: &str,
        args: &[u64],
    ) -> EmuResult<u64> {
        let addr = module.find_symbol(symbol)?;
        self.call_address(addr, args)
    }

    /// 调用通过 `RegisterNatives` 动态注册的 JNI 本地方法
    ///
    /// 自动在参数列表前拼装 `(JNIEnv*, jclass)`，`extra_args` 从 `X2` 开始传入。
    pub fn call_registered_native(
        &mut self,
        class_name: &str,
        method_name: &str,
        extra_args: &[u64],
    ) -> EmuResult<u64> {
        let fn_ptr = self
            .uc
            .get_data()
            .jni
            .find_registered_native(class_name, method_name)
            .map(|r| r.fn_ptr)
            .ok_or_else(|| {
                EmuError::SymbolNotFound(format!("{class_name}.{method_name} (RegisterNatives)"))
            })?;

        let env_ptr = self.uc.get_data().jni.jni_env_ptr();
        let cls_ref = self
            .uc
            .get_data_mut()
            .jni
            .objects
            .find_or_create_class(class_name);

        let mut all_args = Vec::with_capacity(2 + extra_args.len());
        all_args.push(env_ptr);
        all_args.push(cls_ref.0);
        all_args.extend_from_slice(extra_args);

        self.call_address(fn_ptr, &all_args)
    }

    /// 调用任意指定地址的函数（重置 `LR = RET_MAGIC_ADDR`），返回 `X0`
    pub fn call_address(&mut self, pc: u64, args: &[u64]) -> EmuResult<u64> {
        self.cpu.prepare_call(&mut self.uc, args)?;
        self.uc.emu_start(pc, RET_MAGIC_ADDR, 0, 0)?;
        Ok(self.uc.reg_read(RegisterARM64::X0)?)
    }

    /// 挂载指令级（及 `Full` 模式下的内存级）Trace Hook
    pub fn attach_tracer(&mut self, begin: u64, end: u64) -> EmuResult<()> {
        if self.trace_code_hook.is_none() {
            let h = attach_code_hook(&mut self.uc, begin, end, |s| &mut s.tracer)?;
            self.trace_code_hook = Some(h);
        }
        if self.uc.get_data().tracer.level() == TraceLevel::Full && self.trace_mem_hook.is_none() {
            let mh = attach_mem_trace_hook(&mut self.uc, 0, u64::MAX, |s| &mut s.tracer)?;
            self.trace_mem_hook = Some(mh);
        }
        Ok(())
    }

    /// 替换底层 Tracer（例如切换为双流 `memmap2` 落盘）并自动挂载 Hook
    pub fn set_tracer(&mut self, tracer: BinaryTracer) -> EmuResult<()> {
        self.uc.get_data_mut().tracer = tracer;
        self.attach_tracer(0, u64::MAX)
    }

    /// 捕获完整 CPU + 可写内存快照（供批量回放）
    pub fn capture_snapshot(&self) -> EmuResult<EmuSnapshot> {
        EmuSnapshot::capture(&self.uc, &self.uc.get_data().mem)
    }

    /// 回滚至指定快照状态
    pub fn restore_snapshot(&mut self, snapshot: &EmuSnapshot) -> EmuResult<()> {
        snapshot.restore(&mut self.uc)
    }

    /// 便捷创建 `jstring`
    pub fn new_jstring(&mut self, s: impl Into<String>) -> JObjectRef {
        self.uc.get_data_mut().jni.objects.add_string(s)
    }

    /// 便捷读取 `jstring` 内容
    pub fn read_jstring(&self, r: JObjectRef) -> Option<&str> {
        self.uc.get_data().jni.objects.get_string(r)
    }

    /// 便捷创建 `jbyteArray`
    pub fn new_jbyte_array(&mut self, bytes: impl Into<Vec<u8>>) -> JObjectRef {
        self.uc.get_data_mut().jni.objects.add_byte_array(bytes)
    }

    pub fn jni(&self) -> &JniVm {
        &self.uc.get_data().jni
    }

    pub fn jni_mut(&mut self) -> &mut JniVm {
        &mut self.uc.get_data_mut().jni
    }

    pub fn vfs_mut(&mut self) -> &mut VirtualFs {
        &mut self.uc.get_data_mut().vfs
    }

    pub fn tracer(&self) -> &BinaryTracer {
        &self.uc.get_data().tracer
    }

    pub fn tracer_mut(&mut self) -> &mut BinaryTracer {
        &mut self.uc.get_data_mut().tracer
    }

    pub fn uc(&self) -> &Unicorn<'static, EmuState> {
        &self.uc
    }

    pub fn uc_mut(&mut self) -> &mut Unicorn<'static, EmuState> {
        &mut self.uc
    }

    pub fn linker(&self) -> &DynamicLinker {
        &self.linker
    }
}
