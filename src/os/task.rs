use std::collections::VecDeque;

use unicorn_engine::unicorn_const::Prot;
use unicorn_engine::{RegisterARM64, Unicorn};

use crate::cpu::{CpuSnapshot, RET_MAGIC_ADDR};
use crate::error::EmuResult;
use crate::memory::{MemoryManager, PAGE_SIZE};

/// 工作线程独立栈池基址（每线程 1MB，位于 0x7100_0000 之上）
pub const WORKER_STACK_POOL_BASE: u64 = 0x7100_0000;
pub const WORKER_STACK_SIZE: u64 = 0x0010_0000;

/// 工作线程独立 TLS 池基址（每线程 64KB，位于 0x6010_0000 之上）
pub const WORKER_TLS_POOL_BASE: u64 = 0x6010_0000;
pub const WORKER_TLS_SIZE: u64 = 0x0001_0000;

/// 协作式任务生命周期状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    BlockedFutex { uaddr: u64, expected: u32 },
    Finished(u64),
}

/// 轻量级模拟线程控制块 (TCB)
pub struct Task {
    pub tid: u32,
    pub entry_pc: u64,
    pub pc: u64,
    pub arg_x0: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub stack_top: u64,
    pub tls_base: u64,
    pub state: TaskState,
    pub snapshot: Option<CpuSnapshot>,
    pub executed_slices: u64,
}

/// 协作式单线程任务调度器
///
/// 采用时间片轮转（Round-Robin）在单个 Unicorn 实例上确定性调度多个模拟线程：
/// - 彻底避免宿主多线程竞争同一 Unicorn 引擎的锁开销与不可复现性
/// - 支持 `spawn_thread`（对应 `pthread_create`/`clone`）、`futex_wait`/`futex_wake` 与 `join`
pub struct TaskScheduler {
    next_tid: u32,
    next_slot: u64,
    tasks: Vec<Task>,
    run_queue: VecDeque<usize>,
}

impl Default for TaskScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskScheduler {
    pub fn new() -> Self {
        Self {
            next_tid: 10001,
            next_slot: 0,
            tasks: Vec::new(),
            run_queue: VecDeque::new(),
        }
    }

    /// 创建一个新的模拟工作线程，分配独立栈与 TLS 空间并加入就绪队列
    pub fn spawn_thread<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
        mem: &mut MemoryManager,
        entry_pc: u64,
        arg_x0: u64,
    ) -> EmuResult<u32> {
        let tid = self.next_tid;
        self.next_tid += 1;
        let slot = self.next_slot;
        self.next_slot += 1;

        let stack_base = WORKER_STACK_POOL_BASE + slot * WORKER_STACK_SIZE;
        let stack_top = (stack_base + WORKER_STACK_SIZE - 0x100) & !0xFu64;
        mem.map_labeled(
            uc,
            stack_base,
            WORKER_STACK_SIZE,
            Prot::READ | Prot::WRITE,
            format!("[stack:tid={tid}]"),
            0,
        )?;

        let tls_base = WORKER_TLS_POOL_BASE + slot * WORKER_TLS_SIZE;
        mem.map_labeled(
            uc,
            tls_base,
            WORKER_TLS_SIZE,
            Prot::READ | Prot::WRITE,
            format!("[tls:tid={tid}]"),
            0,
        )?;
        // 初始化工作线程 TLS 槽位（SELF / STACK_GUARD）
        mem.write_u64(uc, tls_base, tls_base)?;
        mem.write_u64(uc, tls_base + 5 * 8, crate::cpu::DEFAULT_STACK_GUARD)?;

        // 确保返回魔数页已映射
        let _ = mem.map_labeled(
            uc,
            RET_MAGIC_ADDR,
            PAGE_SIZE,
            Prot::READ | Prot::EXEC,
            "[emu:ret_magic]",
            0,
        );

        let idx = self.tasks.len();
        self.tasks.push(Task {
            tid,
            entry_pc,
            pc: entry_pc,
            arg_x0,
            stack_base,
            stack_size: WORKER_STACK_SIZE,
            stack_top,
            tls_base,
            state: TaskState::Ready,
            snapshot: None,
            executed_slices: 0,
        });
        self.run_queue.push_back(idx);
        Ok(tid)
    }

    /// 将指定线程挂起在 futex 地址上
    pub fn futex_wait(&mut self, tid: u32, uaddr: u64, expected: u32) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.tid == tid) {
            task.state = TaskState::BlockedFutex { uaddr, expected };
        }
    }

    /// 唤醒等待在指定 futex 地址上的最多 `max_wake` 个线程
    pub fn futex_wake(&mut self, uaddr: u64, max_wake: usize) -> usize {
        let mut woken = 0usize;
        for (idx, task) in self.tasks.iter_mut().enumerate() {
            if woken >= max_wake {
                break;
            }
            if let TaskState::BlockedFutex {
                uaddr: wait_addr, ..
            } = task.state
            {
                if wait_addr == uaddr {
                    task.state = TaskState::Ready;
                    self.run_queue.push_back(idx);
                    woken += 1;
                }
            }
        }
        woken
    }

    /// 按固定指令时间片轮转执行所有就绪线程，直至全部完成或阻塞
    ///
    /// 返回本次调度循环累计执行的线程时间片总数。
    pub fn run_until_idle<D>(
        &mut self,
        uc: &mut Unicorn<'_, D>,
        time_slice_insns: usize,
    ) -> EmuResult<u64> {
        let slice = time_slice_insns.max(1);
        let mut total_slices = 0u64;

        // 保存宿主/主线程当前寄存器上下文，调度结束后恢复
        let host_snap = CpuSnapshot::capture(uc)?;

        while let Some(idx) = self.run_queue.pop_front() {
            if !matches!(self.tasks[idx].state, TaskState::Ready) {
                continue;
            }
            self.tasks[idx].state = TaskState::Running;

            // 恢复或首次初始化该工作线程上下文
            if let Some(snap) = &self.tasks[idx].snapshot {
                snap.restore(uc)?;
            } else {
                uc.reg_write(RegisterARM64::SP, self.tasks[idx].stack_top)?;
                uc.reg_write(RegisterARM64::LR, RET_MAGIC_ADDR)?;
                uc.reg_write(RegisterARM64::X0, self.tasks[idx].arg_x0)?;
                uc.reg_write(RegisterARM64::TPIDR_EL0, self.tasks[idx].tls_base)?;
            }

            let start_pc = self.tasks[idx].pc;
            uc.emu_start(start_pc, RET_MAGIC_ADDR, 0, slice)?;
            total_slices += 1;
            self.tasks[idx].executed_slices += 1;

            let end_pc = uc.reg_read(RegisterARM64::PC)?;
            if end_pc == RET_MAGIC_ADDR {
                let ret_x0 = uc.reg_read(RegisterARM64::X0)?;
                self.tasks[idx].state = TaskState::Finished(ret_x0);
                self.tasks[idx].snapshot = None;
            } else {
                // 时间片耗尽，保存寄存器快照与当前 PC，放回就绪队列尾部
                self.tasks[idx].pc = end_pc;
                self.tasks[idx].snapshot = Some(CpuSnapshot::capture(uc)?);
                if matches!(self.tasks[idx].state, TaskState::Running) {
                    self.tasks[idx].state = TaskState::Ready;
                    self.run_queue.push_back(idx);
                }
            }
        }

        host_snap.restore(uc)?;
        Ok(total_slices)
    }

    /// 获取已结束线程的返回值（对应 `pthread_join`）
    pub fn join_result(&self, tid: u32) -> Option<u64> {
        self.tasks.iter().find(|t| t.tid == tid).and_then(|t| match t.state {
            TaskState::Finished(v) => Some(v),
            _ => None,
        })
    }

    pub fn tasks(&self) -> &[Task] {
        &self.tasks
    }
}
