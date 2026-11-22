use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use unicorn_engine::unicorn_const::{Arch, Mode};
use unicorn_engine::{RegisterARM64, UcHookId, Unicorn};

#[cfg(feature = "dynarmic")]
use crate::backend::dynarmic_backend::DynarmicCpu;
#[cfg(feature = "hypervisor")]
use crate::backend::hypervisor_backend::HypervisorCpu;
#[cfg(feature = "kvm")]
use crate::backend::kvm_backend::KvmCpu;
#[cfg(any(feature = "dynarmic", feature = "kvm", feature = "hypervisor"))]
use crate::backend::ExternalBackend;
use crate::backend::{
    BackendKind, BackendWithData, CpuBackend, CpuEngine, RunStopReason, SVC_IMM_HLE_TRAMPOLINE,
    SVC_IMM_JNI_TRAMPOLINE, SVC_IMM_RET_MAGIC, SVC_IMM_SYSCALL,
};
use crate::cpu::{CpuContext, RET_MAGIC_ADDR};
use crate::crash::{BreadcrumbRing, CrashReport};
use crate::diag::EnvDiag;
use crate::error::{EmuError, EmuResult};
use crate::jni::{
    attach_jni_hook, dispatch_jni_slot, DefaultJniHandler, JObjectRef, JniHandler, JniVm,
};
#[cfg(feature = "apk")]
use crate::loader::ApkPackage;
use crate::loader::{
    attach_trampoline_hook, dispatch_trampoline_slot, DynamicLinker, LoadedModule, TrampolineTable,
};
use crate::memory::MemoryManager;
use crate::os::{
    attach_syscall_hook_with_interceptor, dispatch_syscall, DeviceProfile, VirtualFs,
};
use crate::snapshot::EmuSnapshot;
use crate::tracer::{attach_code_hook, attach_mem_trace_hook, BinaryTracer, TraceLevel};

/// 默认模拟堆基址与大小（32MB）
pub const DEFAULT_HEAP_BASE: u64 = 0x5000_0000;
pub const DEFAULT_HEAP_SIZE: u64 = 0x0200_0000;

/// 可选的自定义 Syscall 前置拦截回调
pub type SyscallInterceptor =
    Box<dyn FnMut(&mut Unicorn<'_, EmuState>, u64, &[u64; 6]) -> Option<u64>>;

/// 挂载在 Unicorn UserData 中的统一运行时状态
pub struct EmuState {
    pub mem: MemoryManager,
    pub vfs: VirtualFs,
    pub trampolines: TrampolineTable,
    pub jni: JniVm,
    pub tracer: BinaryTracer,
    pub syscall_interceptor: Option<SyscallInterceptor>,
    pub manual_stop: bool,
}

/// 开箱即用的 Android ARM64 模拟器构建器
pub struct AndroidEmulatorBuilder {
    backend: BackendKind,
    package_name: String,
    heap_base: u64,
    heap_size: u64,
    sysroot_dirs: Vec<PathBuf>,
    enable_hle_accel: bool,
    jni_handler: Box<dyn JniHandler>,
    device_profile: Option<DeviceProfile>,
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
            backend: BackendKind::Unicorn,
            package_name: "com.example.app".to_string(),
            heap_base: DEFAULT_HEAP_BASE,
            heap_size: DEFAULT_HEAP_SIZE,
            sysroot_dirs: Vec::new(),
            enable_hle_accel: true,
            jni_handler: Box::new(DefaultJniHandler),
            device_profile: None,
            trace_capacity: 65_536,
            trace_level: TraceLevel::RegDelta,
            auto_attach_trace: false,
        }
    }

    /// 指定底层 CPU 执行后端（默认 `BackendKind::Unicorn`，可选 `Dynarmic` / `Kvm` / `Hypervisor`）
    pub fn backend(mut self, kind: BackendKind) -> Self {
        self.backend = kind;
        self
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

    /// 配置模拟设备参数画像（自动同步系统属性、`/proc/*` 与 `uname`）
    pub fn device_profile(mut self, profile: DeviceProfile) -> Self {
        self.device_profile = Some(profile);
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
        jni.diag = vfs.diag().clone();
        jni.breadcrumbs = vfs.breadcrumbs().clone();
        if let Some(profile) = self.device_profile {
            vfs.apply_device_profile(profile.clone());
            jni.set_device_profile(profile);
        }
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
            syscall_interceptor: None,
            manual_stop: false,
        };
        let mut engine: CpuEngine<EmuState> = match self.backend {
            BackendKind::Unicorn => CpuEngine::Unicorn(Unicorn::new_with_data(
                Arch::ARM64,
                Mode::LITTLE_ENDIAN,
                placeholder,
            )?),
            BackendKind::Dynarmic => {
                #[cfg(feature = "dynarmic")]
                {
                    CpuEngine::Dynarmic(Box::new(ExternalBackend::new(
                        DynarmicCpu::new()?,
                        placeholder,
                    )))
                }
                #[cfg(not(feature = "dynarmic"))]
                {
                    return Err(EmuError::Backend(
                        "当前构建未启用 `dynarmic` feature".to_string(),
                    ));
                }
            }
            BackendKind::Kvm => {
                #[cfg(feature = "kvm")]
                {
                    CpuEngine::Kvm(Box::new(ExternalBackend::new(KvmCpu::new()?, placeholder)))
                }
                #[cfg(not(feature = "kvm"))]
                {
                    return Err(EmuError::Backend("当前构建未启用 `kvm` feature".to_string()));
                }
            }
            BackendKind::Hypervisor => {
                #[cfg(feature = "hypervisor")]
                {
                    CpuEngine::Hypervisor(Box::new(ExternalBackend::new(
                        HypervisorCpu::new()?,
                        placeholder,
                    )))
                }
                #[cfg(not(feature = "hypervisor"))]
                {
                    return Err(EmuError::Backend(
                        "当前构建未启用 `hypervisor` feature".to_string(),
                    ));
                }
            }
        };

        // 1. 初始化堆、CPU(NEON + TLS)、HLE 跳板区与 JNI 虚函数表
        mem.init_heap(&mut engine)?;
        let cpu = CpuContext::init(&mut engine, &mut mem)?;
        trampolines.errno_addr = cpu.errno_addr;
        trampolines.init(&mut engine, &mut mem)?;
        jni.init(&mut engine, &mut mem)?;

        // 2. 注入完整状态到后端 UserData
        let state = engine.get_data_mut();
        state.mem = mem;
        state.vfs = vfs;
        state.trampolines = trampolines;
        state.jni = jni;
        state.tracer = tracer;
        state.syscall_interceptor = None;
        state.manual_stop = false;

        // 3. Unicorn 后端挂载 Syscall / HLE / JNI Hook；非 Unicorn 后端通过 SVC #imm16 统一外部循环分派
        if let Some(uc) = engine.as_unicorn_mut() {
            attach_syscall_hook_with_interceptor(
                uc,
                |s| (&mut s.mem, &mut s.vfs),
                |uc, nr, args| {
                    let mut cb = uc.get_data_mut().syscall_interceptor.take()?;
                    let res = cb(uc, nr, args);
                    if uc.get_data().syscall_interceptor.is_none() {
                        uc.get_data_mut().syscall_interceptor = Some(cb);
                    }
                    res
                },
            )?;
            attach_trampoline_hook(uc, |s| (&mut s.trampolines, &mut s.mem, &mut s.vfs))?;
            attach_jni_hook(uc, |s| (&mut s.jni, &mut s.mem))?;
        }

        let mut linker = DynamicLinker::new(self.enable_hle_accel);
        for dir in &self.sysroot_dirs {
            linker.add_search_path(dir);
        }

        let mut emu = AndroidEmulator {
            engine,
            cpu,
            linker,
            trace_code_hook: None,
            trace_mem_hook: None,
            exec_timeout_us: 0,
            max_instructions: 0,
            last_crash: None,
        };

        if self.auto_attach_trace {
            emu.attach_tracer(0, u64::MAX)?;
        }

        Ok(emu)
    }
}

/// 统一高层 Android ARM64 模拟器门面
///
/// 封装了多执行后端（Unicorn / Dynarmic / KVM / Hypervisor）、MMU、Overlay VFS、动态链接器、
/// HLE 跳板、JNI 桥接与 Trace 引擎，提供开箱即用的 `.so` 加载、`JNI_OnLoad` 引导、函数调用与快照回放接口。
pub struct AndroidEmulator {
    engine: CpuEngine<EmuState>,
    cpu: CpuContext,
    linker: DynamicLinker,
    trace_code_hook: Option<UcHookId>,
    trace_mem_hook: Option<UcHookId>,
    exec_timeout_us: u64,
    max_instructions: usize,
    last_crash: Option<CrashReport>,
}

impl AndroidEmulator {
    pub fn builder() -> AndroidEmulatorBuilder {
        AndroidEmulatorBuilder::new()
    }

    /// 从文件路径加载目标 `.so`（自动解析 `DT_NEEDED`、执行重定位与 `.init_array`）
    pub fn load_library(&mut self, path: impl AsRef<Path>) -> EmuResult<LoadedModule> {
        self.load_library_with_init(path, true)
    }

    /// 从文件路径加载目标 `.so`（可选是否立即执行 `.init_array`，便于在构造器运行前挂 Hook）
    pub fn load_library_with_init(
        &mut self,
        path: impl AsRef<Path>,
        run_init_array: bool,
    ) -> EmuResult<LoadedModule> {
        let path_ref = path.as_ref();
        let name = path_ref
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "target.so".to_string());
        let bytes = std::fs::read(path_ref)?;
        self.load_library_bytes(&name, &bytes, run_init_array)
    }

    /// 手动执行指定模块的 `DT_INIT` / `.init_array` 构造器（配合 `load_library_with_init(..., false)` 使用）
    pub fn run_module_init_array(&mut self, module: &LoadedModule) -> EmuResult<()> {
        for &init_fn in &module.init_array {
            if init_fn != 0 {
                let _ = self.call_address(init_fn, &[]);
            }
        }
        Ok(())
    }

    /// 从内存字节流加载目标 `.so`（可选是否立即执行 `.init_array`）
    pub fn load_library_bytes(
        &mut self,
        name: &str,
        bytes: &[u8],
        run_init_array: bool,
    ) -> EmuResult<LoadedModule> {
        let prev_loaded = self.linker.load_order().len();

        // 暂移 mem 与 trampolines 进行静态映射与重定位（避免同时借用 &mut engine 与 UserData）
        let mut mem = std::mem::replace(
            &mut self.engine.get_data_mut().mem,
            MemoryManager::new(0, 0),
        );
        let mut trampolines = std::mem::take(&mut self.engine.get_data_mut().trampolines);

        let load_res = self.linker.load_bytes(
            &mut self.engine,
            &mut mem,
            &self.cpu,
            &mut trampolines,
            bytes,
            name.to_string(),
            false,
            false,
        );

        // 归还 mem 与 trampolines，确保后续执行 .init_array 时 Syscall/HLE Hook 可正常访问
        self.engine.get_data_mut().mem = mem;
        self.engine.get_data_mut().trampolines = trampolines;

        let module = load_res?;

        // 将所有新加载模块元数据同步到 TrampolineTable（供 dlopen/dlsym/dladdr/dl_iterate_phdr 使用）
        {
            let new_mods: Vec<crate::loader::trampoline::DlModuleEntry> = self.linker.load_order()
                [prev_loaded..]
                .iter()
                .filter_map(|m| self.linker.get_module(m))
                .map(|m| crate::loader::trampoline::DlModuleEntry {
                    name: m.name.clone(),
                    base_addr: m.base_addr,
                    image_size: m.image_size,
                    symbols: m.symbols.clone(),
                })
                .collect();
            let tramp = &mut self.engine.get_data_mut().trampolines;
            for entry in new_mods {
                tramp.register_loaded_module(entry);
            }
        }

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
        let vm_ptr = self.engine.get_data().jni.java_vm_ptr();
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
        self.call_registered_native_with_this(class_name, method_name, None, extra_args)
    }

    /// 调用通过 `RegisterNatives` 动态注册的 JNI 本地方法，支持显式传入实例 `this`（`jobject`）
    ///
    /// - `this_obj = Some(obj)` 时，`X1` 传入 `obj`（用于实例方法 `GetObjectField(this, ...)`）；
    /// - `this_obj = None` 时，`X1` 传入 `FindClass(class_name)`（用于静态方法）。
    pub fn call_registered_native_with_this(
        &mut self,
        class_name: &str,
        method_name: &str,
        this_obj: Option<JObjectRef>,
        extra_args: &[u64],
    ) -> EmuResult<u64> {
        let fn_ptr = self
            .engine
            .get_data()
            .jni
            .find_registered_native(class_name, method_name)
            .map(|r| r.fn_ptr)
            .ok_or_else(|| {
                EmuError::SymbolNotFound(format!("{class_name}.{method_name} (RegisterNatives)"))
            })?;

        let env_ptr = self.engine.get_data().jni.jni_env_ptr();
        let second_arg = match this_obj {
            Some(obj) if !obj.is_null() => obj.0,
            _ => self
                .engine
                .get_data_mut()
                .jni
                .objects
                .find_or_create_class(class_name)
                .0,
        };

        let mut all_args = Vec::with_capacity(2 + extra_args.len());
        all_args.push(env_ptr);
        all_args.push(second_arg);
        all_args.extend_from_slice(extra_args);

        self.call_address(fn_ptr, &all_args)
    }

    /// 设置单次执行的硬超时（微秒，0 表示不限）与最大指令数（0 表示不限）
    pub fn set_execution_limits(&mut self, timeout_us: u64, max_instructions: usize) {
        self.exec_timeout_us = timeout_us;
        self.max_instructions = max_instructions;
    }

    /// 获取当前执行限制 `(timeout_us, max_instructions)`
    pub fn execution_limits(&self) -> (u64, usize) {
        (self.exec_timeout_us, self.max_instructions)
    }

    /// 主动请求中止当前执行（与超时强杀区分）
    pub fn request_stop(&mut self) -> EmuResult<()> {
        self.engine.get_data_mut().manual_stop = true;
        self.engine.stop()?;
        Ok(())
    }

    /// 获取最近一次 Guest 崩溃或超时的完整现场报告
    pub fn last_crash(&self) -> Option<&CrashReport> {
        self.last_crash.as_ref()
    }

    /// 获取最近外部事件环形缓冲（供 HLE/JNI/Syscall 写入前因轨迹）
    pub fn breadcrumbs(&self) -> &BreadcrumbRing {
        self.engine.get_data().vfs.breadcrumbs()
    }

    /// 调用任意指定地址的函数（重置 `LR = RET_MAGIC_ADDR`），返回 `X0`
    pub fn call_address(&mut self, pc: u64, args: &[u64]) -> EmuResult<u64> {
        self.cpu.prepare_call(&mut self.engine, args)?;
        self.engine.get_data_mut().manual_stop = false;
        self.last_crash = None;

        if self.engine.uses_svc_trampolines() {
            return self.run_external_trap_loop(pc);
        }

        let exec_res = {
            let uc = self.engine.as_unicorn_mut().expect("Unicorn backend");
            uc.emu_start(
                pc,
                RET_MAGIC_ADDR,
                self.exec_timeout_us,
                self.max_instructions,
            )
        };
        if let Err(uc_err) = exec_res {
            let report = CrashReport::capture(
                &self.engine,
                &self.linker,
                &self.engine.get_data().mem,
                self.engine.get_data().vfs.breadcrumbs(),
                format!("Unicorn({uc_err:?})"),
            );
            tracing::error!(
                target: "runidbg::crash",
                pc = format_args!("0x{:016x}", report.pc),
                location = %report.pc_location,
                reason = %report.reason,
                "\n{report}"
            );
            self.last_crash = Some(report.clone());
            return Err(EmuError::GuestCrash(Box::new(report)));
        }

        let end_pc = self.engine.reg_read(RegisterARM64::PC)?;
        let manual_stop = self.engine.get_data().manual_stop;
        if (self.exec_timeout_us > 0 || self.max_instructions > 0)
            && !manual_stop
            && end_pc != RET_MAGIC_ADDR
        {
            let report = CrashReport::capture(
                &self.engine,
                &self.linker,
                &self.engine.get_data().mem,
                self.engine.get_data().vfs.breadcrumbs(),
                format!(
                    "ExecutionTimeout(timeout_us={}, max_instructions={})",
                    self.exec_timeout_us, self.max_instructions
                ),
            );
            tracing::warn!(
                target: "runidbg::crash",
                pc = format_args!("0x{:016x}", report.pc),
                location = %report.pc_location,
                reason = %report.reason,
                "\n{report}"
            );
            self.last_crash = Some(report);
            return Err(EmuError::ExecutionTimeout {
                pc: end_pc,
                timeout_us: self.exec_timeout_us,
                max_instructions: self.max_instructions,
            });
        }
        self.engine.reg_read(RegisterARM64::X0)
    }

    /// 非 Unicorn 后端（Dynarmic / KVM / Hypervisor）统一的 `SVC #imm16` 外部调度循环
    fn run_external_trap_loop(&mut self, start_pc: u64) -> EmuResult<u64> {
        let mut cur_pc = start_pc;
        let deadline = if self.exec_timeout_us > 0 {
            Some(Instant::now() + Duration::from_micros(self.exec_timeout_us))
        } else {
            None
        };

        loop {
            let remaining_us = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        let pc = self.engine.reg_read(RegisterARM64::PC).unwrap_or(cur_pc);
                        let report = CrashReport::capture(
                            &self.engine,
                            &self.linker,
                            &self.engine.get_data().mem,
                            self.engine.get_data().vfs.breadcrumbs(),
                            format!(
                                "ExecutionTimeout(timeout_us={}, max_instructions={})",
                                self.exec_timeout_us, self.max_instructions
                            ),
                        );
                        self.last_crash = Some(report);
                        return Err(EmuError::ExecutionTimeout {
                            pc,
                            timeout_us: self.exec_timeout_us,
                            max_instructions: self.max_instructions,
                        });
                    }
                    dl.duration_since(now).as_micros().max(1) as u64
                }
                None => 0,
            };

            match self
                .engine
                .run_external_step(cur_pc, remaining_us, self.max_instructions)?
            {
                RunStopReason::Svc { imm, next_pc } => match imm {
                    SVC_IMM_RET_MAGIC => {
                        return self.engine.reg_read(RegisterARM64::X0);
                    }
                    SVC_IMM_SYSCALL => {
                        let nr = self.engine.reg_read(RegisterARM64::X8)?;
                        let args = [
                            self.engine.reg_read(RegisterARM64::X0)?,
                            self.engine.reg_read(RegisterARM64::X1)?,
                            self.engine.reg_read(RegisterARM64::X2)?,
                            self.engine.reg_read(RegisterARM64::X3)?,
                            self.engine.reg_read(RegisterARM64::X4)?,
                            self.engine.reg_read(RegisterARM64::X5)?,
                        ];
                        let ret = dispatch_syscall(&mut self.engine, nr, args, &mut |s| {
                            (&mut s.mem, &mut s.vfs)
                        });
                        self.engine.reg_write(RegisterARM64::X0, ret as u64)?;
                        if self.engine.get_data().manual_stop || self.engine.is_stop_requested() {
                            return self.engine.reg_read(RegisterARM64::X0);
                        }
                        cur_pc = next_pc;
                    }
                    SVC_IMM_HLE_TRAMPOLINE => {
                        let slot_addr = next_pc.wrapping_sub(4);
                        // 将 PC 置于槽位地址，以便检测 HLE 是否显式重定向了 PC
                        // （如 pthread_once / pthread_join / longjmp / dl_iterate_phdr / __system_property_read_callback）
                        self.engine.reg_write(RegisterARM64::PC, slot_addr)?;
                        dispatch_trampoline_slot(&mut self.engine, slot_addr, &mut |s| {
                            (&mut s.trampolines, &mut s.mem, &mut s.vfs)
                        });
                        if self.engine.get_data().manual_stop || self.engine.is_stop_requested() {
                            return self.engine.reg_read(RegisterARM64::X0);
                        }
                        let pc_after = self.engine.reg_read(RegisterARM64::PC)?;
                        cur_pc = if pc_after != slot_addr && pc_after != next_pc {
                            pc_after
                        } else {
                            self.engine.reg_read(RegisterARM64::LR)?
                        };
                    }
                    SVC_IMM_JNI_TRAMPOLINE => {
                        let slot_addr = next_pc.wrapping_sub(4);
                        dispatch_jni_slot(&mut self.engine, slot_addr, &mut |s| {
                            (&mut s.jni, &mut s.mem)
                        });
                        if self.engine.get_data().manual_stop || self.engine.is_stop_requested() {
                            return self.engine.reg_read(RegisterARM64::X0);
                        }
                        cur_pc = self.engine.reg_read(RegisterARM64::LR)?;
                    }
                    other => {
                        let fault_pc = next_pc.wrapping_sub(4);
                        let _ = self.engine.reg_write(RegisterARM64::PC, fault_pc);
                        let report = CrashReport::capture(
                            &self.engine,
                            &self.linker,
                            &self.engine.get_data().mem,
                            self.engine.get_data().vfs.breadcrumbs(),
                            format!("UnknownSvc(imm=0x{other:04x})"),
                        );
                        self.last_crash = Some(report.clone());
                        return Err(EmuError::GuestCrash(Box::new(report)));
                    }
                },
                RunStopReason::MemoryFault { pc, detail, .. }
                | RunStopReason::IllegalInstruction { pc, detail } => {
                    let _ = self.engine.reg_write(RegisterARM64::PC, pc);
                    let report = CrashReport::capture(
                        &self.engine,
                        &self.linker,
                        &self.engine.get_data().mem,
                        self.engine.get_data().vfs.breadcrumbs(),
                        detail,
                    );
                    tracing::error!(
                        target: "runidbg::crash",
                        pc = format_args!("0x{:016x}", report.pc),
                        location = %report.pc_location,
                        reason = %report.reason,
                        "\n{report}"
                    );
                    self.last_crash = Some(report.clone());
                    return Err(EmuError::GuestCrash(Box::new(report)));
                }
                RunStopReason::Timeout { pc } => {
                    let _ = self.engine.reg_write(RegisterARM64::PC, pc);
                    let report = CrashReport::capture(
                        &self.engine,
                        &self.linker,
                        &self.engine.get_data().mem,
                        self.engine.get_data().vfs.breadcrumbs(),
                        format!(
                            "ExecutionTimeout(timeout_us={}, max_instructions={})",
                            self.exec_timeout_us, self.max_instructions
                        ),
                    );
                    self.last_crash = Some(report);
                    return Err(EmuError::ExecutionTimeout {
                        pc,
                        timeout_us: self.exec_timeout_us,
                        max_instructions: self.max_instructions,
                    });
                }
                RunStopReason::Stopped => {
                    return self.engine.reg_read(RegisterARM64::X0);
                }
            }
        }
    }

    /// 挂载指令级（及 `Full` 模式下的内存级）Trace Hook（仅 Unicorn 后端支持）
    pub fn attach_tracer(&mut self, begin: u64, end: u64) -> EmuResult<()> {
        if !self.backend_kind().supports_trace() {
            return Err(EmuError::Backend(format!(
                "当前后端 `{}` 不支持指令级 Trace（请切换到 `unicorn` 后端）",
                self.backend_kind()
            )));
        }
        let uc = self.engine.as_unicorn_mut().expect("Unicorn backend");
        if self.trace_code_hook.is_none() {
            let h = attach_code_hook(uc, begin, end, |s| &mut s.tracer)?;
            self.trace_code_hook = Some(h);
            for name in self.linker.load_order() {
                if let Some(m) = self.linker.get_module(name) {
                    let _ = uc
                        .ctl_remove_cache(m.base_addr, m.base_addr.saturating_add(m.image_size));
                }
            }
        }
        if uc.get_data().tracer.level() == TraceLevel::Full && self.trace_mem_hook.is_none() {
            let mh = attach_mem_trace_hook(uc, 0, u64::MAX, |s| &mut s.tracer)?;
            self.trace_mem_hook = Some(mh);
        }
        Ok(())
    }

    /// 替换底层 Tracer（例如切换为双流 `memmap2` 落盘）并自动挂载 Hook（仅 Unicorn 后端支持）
    pub fn set_tracer(&mut self, tracer: BinaryTracer) -> EmuResult<()> {
        if !self.backend_kind().supports_trace() {
            return Err(EmuError::Backend(format!(
                "当前后端 `{}` 不支持指令级 Trace（请切换到 `unicorn` 后端）",
                self.backend_kind()
            )));
        }
        self.engine.get_data_mut().tracer = tracer;
        self.attach_tracer(0, u64::MAX)
    }

    /// 卸载 Trace Hook 并刷盘
    pub fn detach_tracer(&mut self) -> EmuResult<()> {
        if let Some(uc) = self.engine.as_unicorn_mut() {
            if let Some(h) = self.trace_code_hook.take() {
                let _ = uc.remove_hook(h);
            }
            if let Some(mh) = self.trace_mem_hook.take() {
                let _ = uc.remove_hook(mh);
            }
        }
        self.engine.get_data_mut().tracer.finalize()
    }

    /// 捕获完整 CPU + 可写内存 + 模拟堆分配器 + JNI 引用表快照（供批量回放或常驻重置）
    pub fn capture_snapshot(&self) -> EmuResult<EmuSnapshot> {
        let data = self.engine.get_data();
        EmuSnapshot::capture_full(&self.engine, &data.mem, &data.jni)
    }

    /// 完整回滚至指定快照状态（同步恢复 CPU、可写内存、堆指针/空闲链表与 JNI 引用表）
    pub fn restore_snapshot(&mut self, snapshot: &EmuSnapshot) -> EmuResult<()> {
        snapshot.restore_full(&mut self.engine, |d| (&mut d.mem, &mut d.jni))
    }

    /// 便捷创建 `jstring`
    pub fn new_jstring(&mut self, s: impl Into<String>) -> JObjectRef {
        self.engine.get_data_mut().jni.objects.add_string(s)
    }

    /// 便捷读取 `jstring` 内容
    pub fn read_jstring(&self, r: JObjectRef) -> Option<&str> {
        self.engine.get_data().jni.objects.get_string(r)
    }

    /// 便捷创建 `jbyteArray`
    pub fn new_jbyte_array(&mut self, bytes: impl Into<Vec<u8>>) -> JObjectRef {
        self.engine.get_data_mut().jni.objects.add_byte_array(bytes)
    }

    pub fn jni(&self) -> &JniVm {
        &self.engine.get_data().jni
    }

    pub fn jni_mut(&mut self) -> &mut JniVm {
        &mut self.engine.get_data_mut().jni
    }

    pub fn vfs(&self) -> &VirtualFs {
        &self.engine.get_data().vfs
    }

    pub fn vfs_mut(&mut self) -> &mut VirtualFs {
        &mut self.engine.get_data_mut().vfs
    }

    /// 统一应用设备画像，同步更新 VFS（系统属性、`/proc/*`、`uname`）与 JNI（`android/os/Build`）
    pub fn apply_device_profile(&mut self, profile: DeviceProfile) {
        let data = self.engine.get_data_mut();
        data.vfs.apply_device_profile(profile.clone());
        data.jni.set_device_profile(profile);
    }

    /// 获取缺环境自动诊断器（共享引用，可动态开启/关闭/导出补环境脚本）
    pub fn diag(&self) -> &EnvDiag {
        self.engine.get_data().vfs.diag()
    }

    /// 从磁盘加载单个 `.dex` 文件到轻量元数据索引并挂载到 VFS，返回解析出的类数量
    pub fn load_dex(&mut self, path: impl AsRef<Path>) -> EmuResult<usize> {
        let path_ref = path.as_ref();
        let name = path_ref
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "classes.dex".to_string());
        let bytes = std::fs::read(path_ref)?;
        self.load_dex_bytes(&name, &bytes)
    }

    /// 从字节流加载 `.dex` 到轻量元数据索引并挂载到 VFS，返回解析出的类数量
    pub fn load_dex_bytes(&mut self, name: &str, bytes: &[u8]) -> EmuResult<usize> {
        let data = self.engine.get_data_mut();
        let pkg = data.vfs.package_name.clone();
        data.vfs
            .add_overlay_file(format!("/data/app/{pkg}/{name}"), bytes.to_vec());
        data.jni.dex_index.add_dex_bytes(bytes)
    }

    /// 一键加载 Android APK
    #[cfg(feature = "apk")]
    pub fn load_apk(&mut self, path: impl AsRef<Path>) -> EmuResult<ApkPackage> {
        let apk = ApkPackage::from_path(path)?;
        self.install_apk(&apk);
        Ok(apk)
    }

    /// 从已解析的 `ApkPackage` 注入运行环境（包名、内存 `.so` 库、VFS `assets/`、`classes*.dex` 与 `base.apk`）
    #[cfg(feature = "apk")]
    pub fn install_apk(&mut self, apk: &ApkPackage) {
        let pkg_name = apk
            .package_name
            .clone()
            .unwrap_or_else(|| self.engine.get_data().vfs.package_name.clone());
        {
            let data = self.engine.get_data_mut();
            data.vfs.package_name = pkg_name.clone();
            data.vfs
                .add_overlay_file(format!("/data/app/{pkg_name}/base.apk"), apk.raw_apk.clone());
            for (rel, bytes) in &apk.assets {
                data.vfs
                    .add_overlay_file(format!("/assets/{rel}"), bytes.clone());
                data.vfs
                    .add_overlay_file(format!("/data/app/{pkg_name}/assets/{rel}"), bytes.clone());
            }
            for (dex_name, dex_bytes) in &apk.dex_files {
                data.vfs.add_overlay_file(
                    format!("/data/app/{pkg_name}/{dex_name}"),
                    dex_bytes.clone(),
                );
                if let Err(e) = data.jni.dex_index.add_dex_bytes(dex_bytes) {
                    tracing::warn!(target: "runidbg::dex", "解析 APK 内 {dex_name} 失败（已跳过）: {e}");
                }
            }
            if let Some(cert) = &apk.signature_cert {
                data.vfs.add_overlay_file(
                    format!("/data/app/{pkg_name}/META-INF/CERT.RSA"),
                    cert.clone(),
                );
            }
        }
        for (lib_name, bytes) in &apk.native_libs {
            self.linker.add_memory_library(lib_name.clone(), bytes.clone());
        }
    }

    /// 加载先前通过 `load_apk` 注册到内存中的 `lib/arm64-v8a/<lib_name>`
    #[cfg(feature = "apk")]
    pub fn load_apk_library(&mut self, lib_name: &str) -> EmuResult<LoadedModule> {
        self.load_apk_library_with_init(lib_name, true)
    }

    pub fn load_apk_library_with_init(
        &mut self,
        lib_name: &str,
        run_init_array: bool,
    ) -> EmuResult<LoadedModule> {
        let bytes = self
            .linker
            .get_memory_library(lib_name)
            .ok_or_else(|| EmuError::InvalidElf(format!("APK 中未找到 arm64-v8a 库: {lib_name}")))?
            .to_vec();
        self.load_library_bytes(lib_name, &bytes, run_init_array)
    }

    pub fn tracer(&self) -> &BinaryTracer {
        &self.engine.get_data().tracer
    }

    pub fn tracer_mut(&mut self) -> &mut BinaryTracer {
        &mut self.engine.get_data_mut().tracer
    }

    /// 返回当前使用的底层 CPU 执行后端类型
    pub fn backend_kind(&self) -> BackendKind {
        self.engine.kind()
    }

    /// 获取跨后端统一的 `CpuEngine` 只读引用（实现 `CpuBackend + BackendWithData<EmuState>`）
    pub fn cpu(&self) -> &CpuEngine<EmuState> {
        &self.engine
    }

    /// 获取跨后端统一的 `CpuEngine` 可变引用（实现 `CpuBackend + BackendWithData<EmuState>`）
    pub fn cpu_mut(&mut self) -> &mut CpuEngine<EmuState> {
        &mut self.engine
    }

    /// 若当前为 Unicorn 后端，返回底层 `Unicorn` 引用；否则返回 `None`
    pub fn try_uc(&self) -> Option<&Unicorn<'static, EmuState>> {
        self.engine.as_unicorn()
    }

    /// 若当前为 Unicorn 后端，返回底层 `Unicorn` 可变引用；否则返回 `None`
    pub fn try_uc_mut(&mut self) -> Option<&mut Unicorn<'static, EmuState>> {
        self.engine.as_unicorn_mut()
    }

    /// 获取底层 `Unicorn` 只读引用（仅 Unicorn 后端可用；非 Unicorn 后端请改用 `cpu()` / `try_uc()`）
    pub fn uc(&self) -> &Unicorn<'static, EmuState> {
        self.engine.as_unicorn().unwrap_or_else(|| {
            panic!(
                "当前后端 `{}` 不是 Unicorn，请改用 `emu.cpu()` 或 `emu.try_uc()`",
                self.engine.kind()
            )
        })
    }

    /// 获取底层 `Unicorn` 可变引用（仅 Unicorn 后端可用；非 Unicorn 后端请改用 `cpu_mut()` / `try_uc_mut()`）
    pub fn uc_mut(&mut self) -> &mut Unicorn<'static, EmuState> {
        let kind = self.engine.kind();
        self.engine.as_unicorn_mut().unwrap_or_else(|| {
            panic!("当前后端 `{kind}` 不是 Unicorn，请改用 `emu.cpu_mut()` 或 `emu.try_uc_mut()`")
        })
    }

    pub fn linker(&self) -> &DynamicLinker {
        &self.linker
    }
}
