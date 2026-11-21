use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::Unicorn;

use crate::cpu::CpuSnapshot;
use crate::error::EmuResult;
use crate::jni::env::{JniSnapshot, JniVm};
use crate::memory::{HeapSnapshot, MemoryManager};

/// 完整虚拟机状态快照（CPU 全量寄存器 + 可写内存页镜像 + 模拟堆分配器元数据 + 可选 JNI 引用表）
///
/// 典型用途：**Snapshot 批量高速回放 / 常驻 RPC 周期性重置**
/// 1. 加载 `.so`、执行 `.init_array` 与 `JNI_OnLoad`
/// 2. 调用 `emu.capture_snapshot()` 冻结初始干净状态
/// 3. 循环 `emu.restore_snapshot(&snap)`，毫秒级将寄存器、可写内存、堆分配器与 JNI 引用表全部复位
pub struct EmuSnapshot {
    cpu: CpuSnapshot,
    writable_regions: Vec<(u64, Vec<u8>)>,
    heap: HeapSnapshot,
    jni: Option<JniSnapshot>,
}

impl EmuSnapshot {
    /// 捕获当前 CPU 寄存器状态、所有可写 VMA 内存镜像及堆分配器状态
    pub fn capture<D>(uc: &Unicorn<'_, D>, mem: &MemoryManager) -> EmuResult<Self> {
        Self::capture_inner(uc, mem, None)
    }

    /// 捕获完整状态（包含 JNI 对象引用表与临时缓冲区映射）
    pub fn capture_full<D>(
        uc: &Unicorn<'_, D>,
        mem: &MemoryManager,
        jni: &JniVm,
    ) -> EmuResult<Self> {
        Self::capture_inner(uc, mem, Some(jni.snapshot_state()))
    }

    fn capture_inner<D>(
        uc: &Unicorn<'_, D>,
        mem: &MemoryManager,
        jni: Option<JniSnapshot>,
    ) -> EmuResult<Self> {
        let cpu = CpuSnapshot::capture(uc)?;
        let mut writable_regions = Vec::new();

        for region in mem.regions() {
            if (region.perms.0 & Prot::WRITE.0) != 0 {
                let len = (region.end - region.start) as usize;
                let mut buf = vec![0u8; len];
                if uc.mem_read(region.start, &mut buf).is_ok() {
                    writable_regions.push((region.start, buf));
                }
            }
        }

        Ok(Self {
            cpu,
            writable_regions,
            heap: mem.heap_snapshot(),
            jni,
        })
    }

    /// 极速回滚 CPU 寄存器与全部可写内存页到快照时刻（底层兼容接口）
    pub fn restore<D>(&self, uc: &mut Unicorn<'_, D>) -> EmuResult<()> {
        for (start, bytes) in &self.writable_regions {
            uc.mem_write(*start, bytes)?;
        }
        self.cpu.restore(uc)?;
        Ok(())
    }

    /// 完整回滚 CPU 寄存器、可写内存页、堆分配器元数据与 JNI 对象引用表
    pub fn restore_full<D>(
        &self,
        uc: &mut Unicorn<'_, D>,
        get_state: impl Fn(&mut D) -> (&mut MemoryManager, &mut JniVm),
    ) -> EmuResult<()> {
        self.restore(uc)?;
        let (mem, jni) = get_state(uc.get_data_mut());
        mem.restore_heap_snapshot(&self.heap);
        if let Some(ref jni_snap) = self.jni {
            jni.restore_state(jni_snap);
        }
        Ok(())
    }

    /// 返回快照捕获的可写内存区域数量与总字节数
    pub fn stats(&self) -> (usize, usize) {
        let total_bytes: usize = self.writable_regions.iter().map(|(_, b)| b.len()).sum();
        (self.writable_regions.len(), total_bytes)
    }
}
