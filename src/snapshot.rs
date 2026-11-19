use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::Unicorn;

use crate::cpu::CpuSnapshot;
use crate::error::EmuResult;
use crate::memory::MemoryManager;

/// 完整虚拟机状态快照（CPU 全量寄存器 + 所有可写内存页镜像）
///
/// 典型用途：**Snapshot 批量高速回放**
/// 1. 加载 `.so`、执行 `.init_array` 与 `JNI_OnLoad`
/// 2. 调用 `EmuSnapshot::capture(&uc, &mem)` 冻结初始干净状态
/// 3. 循环 `snapshot.restore(&mut uc)` -> 注入不同测试参数 -> `emu_start`，毫秒级完成批量重放
pub struct EmuSnapshot {
    cpu: CpuSnapshot,
    writable_regions: Vec<(u64, Vec<u8>)>,
}

impl EmuSnapshot {
    /// 捕获当前 CPU 寄存器状态与所有可写 VMA 内存镜像
    pub fn capture<D>(uc: &Unicorn<'_, D>, mem: &MemoryManager) -> EmuResult<Self> {
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
        })
    }

    /// 极速回滚 CPU 寄存器与全部可写内存页到快照时刻
    pub fn restore<D>(&self, uc: &mut Unicorn<'_, D>) -> EmuResult<()> {
        for (start, bytes) in &self.writable_regions {
            uc.mem_write(*start, bytes)?;
        }
        self.cpu.restore(uc)?;
        Ok(())
    }

    /// 返回快照捕获的可写内存区域数量与总字节数
    pub fn stats(&self) -> (usize, usize) {
        let total_bytes: usize = self.writable_regions.iter().map(|(_, b)| b.len()).sum();
        (self.writable_regions.len(), total_bytes)
    }
}
