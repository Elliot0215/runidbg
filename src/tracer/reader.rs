use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::mem::size_of;
use std::path::Path;
use std::ptr;

use memmap2::Mmap;

use crate::error::EmuResult;
use crate::tracer::record::{ExtKind, ExtRecord, TraceRecord};

/// 内存写入字节流匹配命中项
#[derive(Debug, Clone)]
pub struct MemPatternHit {
    pub seq_low32: u32,
    pub pc: u64,
    pub addr: u64,
    pub matched_len: usize,
}

/// 基于 `BL`/`BLR`/`RET` 构建的时间轴调用树节点
#[derive(Debug, Clone)]
pub struct CallTreeNode {
    pub target_pc: u64,
    pub caller_pc: u64,
    pub start_idx: usize,
    pub end_idx: usize,
    pub depth: usize,
}

impl CallTreeNode {
    pub const fn insn_count(&self) -> usize {
        self.end_idx.saturating_sub(self.start_idx) + 1
    }
}

/// 密码学常量扫描归并后的算法调用窗口
#[derive(Debug, Clone)]
pub struct CryptoHitGroup {
    pub algorithm: &'static str,
    pub start_idx: usize,
    pub end_idx: usize,
    pub first_pc: u64,
    pub hit_count: usize,
    pub distinct_constants: Vec<u32>,
}

/// 离线零拷贝 Trace 读取器（供 `runidbg-cli` 与离线分析脚本使用）
pub struct TraceReader {
    idx_mmap: Mmap,
    idx_count: usize,
    ext_mmap: Option<Mmap>,
    ext_count: usize,
    ext_monotonic: bool,
}

impl TraceReader {
    /// 打开 `trace.idx`（及可选的 `trace.ext`）
    pub fn open(idx_path: impl AsRef<Path>, ext_path: Option<&Path>) -> EmuResult<Self> {
        let idx_file = File::open(idx_path)?;
        // SAFETY: 离线只读映射
        let idx_mmap = unsafe { Mmap::map(&idx_file)? };
        let total_idx_slots = idx_mmap.len() / size_of::<TraceRecord>();

        let mut idx_count = 0usize;
        for i in 0..total_idx_slots {
            let rec = read_packed::<TraceRecord>(&idx_mmap, i);
            let pc = rec.pc;
            let op = rec.opcode;
            if pc == 0 && op == 0 {
                break;
            }
            idx_count += 1;
        }

        let (ext_mmap, ext_count, ext_monotonic) = if let Some(ep) = ext_path {
            let ext_file = File::open(ep)?;
            let mmap = unsafe { Mmap::map(&ext_file)? };
            let total_ext_slots = mmap.len() / size_of::<ExtRecord>();
            let mut count = 0usize;
            let mut monotonic = true;
            let mut prev_seq = 0u32;
            for i in 0..total_ext_slots {
                let rec = read_packed::<ExtRecord>(&mmap, i);
                if rec.kind == 0 {
                    break;
                }
                let seq = rec.seq_low32;
                if count > 0 && seq < prev_seq {
                    monotonic = false;
                }
                prev_seq = seq;
                count += 1;
            }
            (Some(mmap), count, monotonic)
        } else {
            (None, 0, true)
        };

        Ok(Self {
            idx_mmap,
            idx_count,
            ext_mmap,
            ext_count,
            ext_monotonic,
        })
    }

    pub const fn len(&self) -> usize {
        self.idx_count
    }

    pub const fn is_empty(&self) -> bool {
        self.idx_count == 0
    }

    pub const fn ext_len(&self) -> usize {
        self.ext_count
    }

    pub fn get(&self, index: usize) -> Option<TraceRecord> {
        if index < self.idx_count {
            Some(read_packed::<TraceRecord>(&self.idx_mmap, index))
        } else {
            None
        }
    }

    pub fn get_ext(&self, index: usize) -> Option<ExtRecord> {
        let mmap = self.ext_mmap.as_ref()?;
        if index < self.ext_count {
            Some(read_packed::<ExtRecord>(mmap, index))
        } else {
            None
        }
    }

    /// 按指令序号查找所有关联的扩展事件（单调序列自动走二分查找）
    pub fn ext_for_seq(&self, seq_low32: u32) -> Vec<ExtRecord> {
        let Some(mmap) = self.ext_mmap.as_ref() else {
            return Vec::new();
        };
        if self.ext_count == 0 {
            return Vec::new();
        }
        if self.ext_monotonic {
            let mut lo = 0usize;
            let mut hi = self.ext_count;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let s = read_packed::<ExtRecord>(mmap, mid).seq_low32;
                if s < seq_low32 {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let mut out = Vec::new();
            let mut i = lo;
            while i < self.ext_count {
                let rec = read_packed::<ExtRecord>(mmap, i);
                if rec.seq_low32 != seq_low32 {
                    break;
                }
                out.push(rec);
                i += 1;
            }
            return out;
        }
        let mut out = Vec::new();
        for i in 0..self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            if rec.seq_low32 == seq_low32 {
                out.push(rec);
            }
        }
        out
    }

    /// 获取指令 `idx` **执行后**产生的寄存器变更列表（修正 Unicorn pre-exec hook 1 条指令偏移）
    ///
    /// Unicorn 的 `hook_code` 在指令执行前触发，因此第 `idx+1` 条记录中的 `reg_delta`
    /// （以及 `ext` 中 `seq == rec[idx+1].seq_low32` 的 `RegDeltaExtra`）才是指令 `idx` 的执行结果。
    pub fn reg_deltas_for(&self, idx: usize) -> Vec<(u8, u64)> {
        let Some(cur) = self.get(idx) else {
            return Vec::new();
        };
        let Some(next) = self.get(idx + 1) else {
            return Vec::new();
        };
        if next.seq_low32 != cur.seq_low32.wrapping_add(1) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let pid = next.primary_reg_id;
        let pval = next.primary_reg_val;
        if pid != 0xFF {
            out.push((pid, pval));
        }
        if (next._reserved[0] & 1) != 0 {
            for ext in self.ext_for_seq(next.seq_low32) {
                if ext.kind == ExtKind::RegDeltaExtra as u8 {
                    out.push((ext.size_or_reg, ext.value));
                }
            }
        }
        out
    }

    /// 获取指令 `idx` 自身产生的内存读写事件（过滤掉 `RegDeltaExtra`）
    pub fn mem_events_for(&self, idx: usize) -> Vec<ExtRecord> {
        let Some(rec) = self.get(idx) else {
            return Vec::new();
        };
        self.ext_for_seq(rec.seq_low32)
            .into_iter()
            .filter(|e| e.kind == ExtKind::MemRead as u8 || e.kind == ExtKind::MemWrite as u8)
            .collect()
    }

    /// 搜索主索引寄存器值匹配的指令记录（原始未偏移接口，保留兼容性）
    pub fn search_value(&self, target: u64) -> Vec<(usize, TraceRecord)> {
        let mut hits = Vec::new();
        for i in 0..self.idx_count {
            let rec = read_packed::<TraceRecord>(&self.idx_mmap, i);
            let reg_id = rec.primary_reg_id;
            let reg_val = rec.primary_reg_val;
            if reg_id != 0xFF && reg_val == target {
                hits.push((i, rec));
            }
        }
        hits
    }

    /// 搜索产生目标寄存器值的指令（覆盖 `primary_reg` 与 `RegDeltaExtra`，并归属到实际执行该写入的指令）
    pub fn search_value_attributed(&self, target: u64) -> Vec<(usize, TraceRecord, u8)> {
        let mut hits = Vec::new();
        let mut seq_to_idx: Option<HashMap<u32, usize>> = None;

        for i in 0..self.idx_count {
            let rec = read_packed::<TraceRecord>(&self.idx_mmap, i);
            let reg_id = rec.primary_reg_id;
            let reg_val = rec.primary_reg_val;
            if reg_id != 0xFF && reg_val == target {
                let (attr_idx, attr_rec) = self.attribute_pre_exec(i, rec);
                hits.push((attr_idx, attr_rec, reg_id));
            }
        }

        if let Some(mmap) = self.ext_mmap.as_ref() {
            for i in 0..self.ext_count {
                let ext = read_packed::<ExtRecord>(mmap, i);
                if ext.kind == ExtKind::RegDeltaExtra as u8 && ext.value == target {
                    let seq = ext.seq_low32;
                    let map = seq_to_idx.get_or_insert_with(|| self.build_seq_index_map());
                    if let Some(&raw_idx) = map.get(&seq) {
                        if let Some(raw_rec) = self.get(raw_idx) {
                            let (attr_idx, attr_rec) = self.attribute_pre_exec(raw_idx, raw_rec);
                            hits.push((attr_idx, attr_rec, ext.size_or_reg));
                        }
                    }
                }
            }
        }

        hits.sort_by_key(|(idx, _, reg)| (*idx, *reg));
        hits
    }

    /// 搜索扩展流中读写值匹配 `target` 的内存事件
    pub fn search_mem_value(&self, target: u64) -> Vec<ExtRecord> {
        let Some(mmap) = self.ext_mmap.as_ref() else {
            return Vec::new();
        };
        let mut hits = Vec::new();
        for i in 0..self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            if rec.kind == ExtKind::MemRead as u8 || rec.kind == ExtKind::MemWrite as u8 {
                let val = rec.value;
                if val == target {
                    hits.push(rec);
                }
            }
        }
        hits
    }

    /// 搜索扩展流中访问了目标内存地址的事件
    pub fn search_mem_addr(&self, target_addr: u64) -> Vec<ExtRecord> {
        let Some(mmap) = self.ext_mmap.as_ref() else {
            return Vec::new();
        };
        let mut hits = Vec::new();
        for i in 0..self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            if (rec.kind == ExtKind::MemRead as u8 || rec.kind == ExtKind::MemWrite as u8)
                && rec.addr == target_addr
            {
                hits.push(rec);
            }
        }
        hits
    }

    /// 回放 `.ext` 中的 `MemWrite` 字节流，搜索连续内存写入拼出的目标字节序列（如 ASCII 字符串或签名头字节）
    pub fn search_mem_bytes(&self, pattern: &[u8]) -> Vec<MemPatternHit> {
        if pattern.is_empty() {
            return Vec::new();
        }
        let Some(mmap) = self.ext_mmap.as_ref() else {
            return Vec::new();
        };
        let pat_len = pattern.len();
        let mut mem: HashMap<u64, u8> = HashMap::new();
        let mut hits = Vec::new();
        let mut last_hit_addr_seq: Option<(u64, u32)> = None;

        for i in 0..self.ext_count {
            let rec = read_packed::<ExtRecord>(mmap, i);
            if rec.kind != ExtKind::MemWrite as u8 {
                continue;
            }
            let sz = (rec.size_or_reg as usize).clamp(1, 8);
            let addr = rec.addr;
            let bytes = rec.value.to_le_bytes();
            for (off, &b) in bytes.iter().take(sz).enumerate() {
                mem.insert(addr.wrapping_add(off as u64), b);
            }

            // 检查所有可能被本次写入补齐的起始地址 [addr - pat_len + 1 ..= addr + sz - 1]
            let start_lo = addr.saturating_sub((pat_len - 1) as u64);
            let start_hi = addr.wrapping_add((sz - 1) as u64);
            let mut candidate = start_lo;
            while candidate <= start_hi {
                let mut matched = true;
                for (k, &pb) in pattern.iter().enumerate() {
                    if mem.get(&candidate.wrapping_add(k as u64)).copied() != Some(pb) {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    let seq = rec.seq_low32;
                    let pc = rec.pc;
                    if last_hit_addr_seq != Some((candidate, seq)) {
                        hits.push(MemPatternHit {
                            seq_low32: seq,
                            pc,
                            addr: candidate,
                            matched_len: pat_len,
                        });
                        last_hit_addr_seq = Some((candidate, seq));
                    }
                }
                match candidate.checked_add(1) {
                    Some(next) => candidate = next,
                    None => break,
                }
            }
        }
        hits
    }

    /// 构建基于 `BL` / `BLR` / `RET` 的时间轴调用树（自动忽略未落入 Trace 过滤范围的外部调用）
    pub fn build_calltree(&self) -> Vec<CallTreeNode> {
        struct ActiveFrame {
            node_idx: usize,
            return_addr: u64,
        }

        let mut nodes: Vec<CallTreeNode> = Vec::new();
        let mut stack: Vec<ActiveFrame> = Vec::new();
        let total = self.idx_count;
        if total == 0 {
            return nodes;
        }

        // 根节点代表整个 Trace 入口函数
        let root_pc = read_packed::<TraceRecord>(&self.idx_mmap, 0).pc;
        nodes.push(CallTreeNode {
            target_pc: root_pc,
            caller_pc: 0,
            start_idx: 0,
            end_idx: total - 1,
            depth: 0,
        });

        for idx in 0..total.saturating_sub(1) {
            let cur = read_packed::<TraceRecord>(&self.idx_mmap, idx);
            let next = read_packed::<TraceRecord>(&self.idx_mmap, idx + 1);
            let pc = cur.pc;
            let op = cur.opcode;
            let next_pc = next.pc;

            // 若当前 PC 已回到调用栈上某帧的 return_addr（例如经 .plt 调外部 HLE 返回，未经过模块内 RET）
            if let Some(pos) = stack.iter().rposition(|f| f.return_addr == pc) {
                while stack.len() > pos {
                    if let Some(frame) = stack.pop() {
                        nodes[frame.node_idx].end_idx = idx.saturating_sub(1);
                    }
                }
            }

            let is_bl = (op & 0xFC00_0000) == 0x9400_0000;
            let is_blr = (op & 0xFFFF_FC1F) == 0xD63F_0000;
            let is_ret = (op & 0xFFFF_FC1F) == 0xD65F_0000;

            if (is_bl || is_blr) && next_pc != pc.wrapping_add(4) {
                let depth = stack.len() + 1;
                let node_idx = nodes.len();
                nodes.push(CallTreeNode {
                    target_pc: next_pc,
                    caller_pc: pc,
                    start_idx: idx + 1,
                    end_idx: total - 1,
                    depth,
                });
                stack.push(ActiveFrame {
                    node_idx,
                    return_addr: pc.wrapping_add(4),
                });
            } else if is_ret {
                if let Some(pos) = stack.iter().rposition(|f| f.return_addr == next_pc) {
                    while stack.len() > pos {
                        if let Some(frame) = stack.pop() {
                            nodes[frame.node_idx].end_idx = idx;
                        }
                    }
                }
            }
        }

        nodes
    }

    /// 自动扫描 Trace 中出现的常见密码学算法常量（MD5/SHA1/SHA256/SM3/SM4/AES/ChaCha/CRC32/TEA/MurmurHash3）
    pub fn scan_crypto(&self) -> Vec<CryptoHitGroup> {
        const SIGNATURES: &[(&str, u32)] = &[
            // MD5 IV & round constants
            ("MD5", 0x6745_2301),
            ("MD5", 0xefcd_ab89),
            ("MD5", 0x98ba_dcfe),
            ("MD5", 0x1032_5476),
            ("MD5", 0xd76a_a478),
            ("MD5", 0xe8c7_b756),
            // SHA-1 unique H4 & round constants
            ("SHA-1", 0xc3d2_e1f0),
            ("SHA-1", 0x5a82_7999),
            ("SHA-1", 0x6ed9_eba1),
            ("SHA-1", 0x8f1b_bcdc),
            ("SHA-1", 0xca62_c1d6),
            // SHA-256 IV & K0
            ("SHA-256", 0x6a09_e667),
            ("SHA-256", 0xbb67_ae85),
            ("SHA-256", 0x3c6e_f372),
            ("SHA-256", 0xa54f_f53a),
            ("SHA-256", 0x428a_2f98),
            // SM3 IV & Tj
            ("SM3", 0x7380_166f),
            ("SM3", 0x4914_b2b9),
            ("SM3", 0x1724_42d7),
            ("SM3", 0xda8a_0600),
            ("SM3", 0x79cc_4519),
            ("SM3", 0x7a87_9d8a),
            // SM4 FK
            ("SM4", 0xa3b1_bac6),
            ("SM4", 0x56aa_3350),
            ("SM4", 0x677d_9197),
            ("SM4", 0xb270_22dc),
            // AES S-box / T-table words
            ("AES", 0x637c_777b),
            ("AES", 0x7b77_7c63),
            ("AES", 0xc663_63a5),
            ("AES", 0xa563_63c6),
            // ChaCha20 / Salsa20 "expand 32-byte k"
            ("ChaCha20/Salsa20", 0x6170_7865),
            ("ChaCha20/Salsa20", 0x3320_646e),
            ("ChaCha20/Salsa20", 0x7962_2d32),
            ("ChaCha20/Salsa20", 0x6b20_6574),
            // CRC32
            ("CRC32", 0xedb8_8320),
            ("CRC32", 0x04c1_1db7),
            // TEA / XTEA / XXTEA
            ("TEA/XTEA", 0x9e37_79b9),
            ("TEA/XTEA", 0x61c8_8647),
            // MurmurHash3
            ("MurmurHash3", 0xcc9e_2d51),
            ("MurmurHash3", 0x1b87_3593),
            ("MurmurHash3", 0x85eb_ca6b),
        ];

        let mut const_map: HashMap<u32, Vec<&'static str>> = HashMap::new();
        for &(algo, val) in SIGNATURES {
            const_map.entry(val).or_default().push(algo);
        }

        // algo -> Vec<(idx, pc, constant)>
        let mut raw_hits: BTreeMap<&'static str, Vec<(usize, u64, u32)>> = BTreeMap::new();

        for i in 0..self.idx_count {
            let rec = read_packed::<TraceRecord>(&self.idx_mmap, i);
            let reg_id = rec.primary_reg_id;
            if reg_id != 0xFF {
                let val = rec.primary_reg_val;
                if val <= u32::MAX as u64 {
                    let v32 = val as u32;
                    if let Some(algos) = const_map.get(&v32) {
                        let (attr_idx, attr_rec) = self.attribute_pre_exec(i, rec);
                        let pc = attr_rec.pc;
                        for &algo in algos {
                            raw_hits.entry(algo).or_default().push((attr_idx, pc, v32));
                        }
                    }
                }
            }
        }

        if let Some(mmap) = self.ext_mmap.as_ref() {
            let mut seq_to_idx: Option<HashMap<u32, usize>> = None;
            for i in 0..self.ext_count {
                let ext = read_packed::<ExtRecord>(mmap, i);
                let val = ext.value;
                if val <= u32::MAX as u64 {
                    let v32 = val as u32;
                    if let Some(algos) = const_map.get(&v32) {
                        let seq = ext.seq_low32;
                        let map = seq_to_idx.get_or_insert_with(|| self.build_seq_index_map());
                        if let Some(&idx) = map.get(&seq) {
                            let (attr_idx, pc) = if ext.kind == ExtKind::RegDeltaExtra as u8 {
                                if let Some(raw_rec) = self.get(idx) {
                                    let (ai, ar) = self.attribute_pre_exec(idx, raw_rec);
                                    (ai, ar.pc)
                                } else {
                                    (idx, ext.pc)
                                }
                            } else {
                                (idx, ext.pc)
                            };
                            for &algo in algos {
                                raw_hits.entry(algo).or_default().push((attr_idx, pc, v32));
                            }
                        }
                    }
                }
            }
        }

        // 将同一算法在 2500 条指令窗口内的命中聚合成一次调用实例
        const WINDOW_GAP: usize = 2500;
        let mut groups = Vec::new();
        for (algo, mut events) in raw_hits {
            events.sort_by_key(|&(idx, _, _)| idx);
            let mut cur_start = 0usize;
            let mut cur_end = 0usize;
            let mut cur_pc = 0u64;
            let mut cur_hits = 0usize;
            let mut cur_consts: BTreeSet<u32> = BTreeSet::new();

            for (idx, pc, c) in events {
                if cur_hits == 0 {
                    cur_start = idx;
                    cur_end = idx;
                    cur_pc = pc;
                    cur_hits = 1;
                    cur_consts.insert(c);
                } else if idx.saturating_sub(cur_end) <= WINDOW_GAP {
                    cur_end = idx;
                    cur_hits += 1;
                    cur_consts.insert(c);
                } else {
                    if cur_consts.len() >= 2 || algo == "CRC32" {
                        groups.push(CryptoHitGroup {
                            algorithm: algo,
                            start_idx: cur_start,
                            end_idx: cur_end,
                            first_pc: cur_pc,
                            hit_count: cur_hits,
                            distinct_constants: cur_consts.iter().copied().collect(),
                        });
                    }
                    cur_start = idx;
                    cur_end = idx;
                    cur_pc = pc;
                    cur_hits = 1;
                    cur_consts.clear();
                    cur_consts.insert(c);
                }
            }
            if cur_hits > 0 && (cur_consts.len() >= 2 || algo == "CRC32") {
                groups.push(CryptoHitGroup {
                    algorithm: algo,
                    start_idx: cur_start,
                    end_idx: cur_end,
                    first_pc: cur_pc,
                    hit_count: cur_hits,
                    distinct_constants: cur_consts.iter().copied().collect(),
                });
            }
        }

        // 如果某窗口同时命中 SHA-1 与 MD5（因为共享前 4 个 IV），保留 SHA-1 并过滤掉重叠的 MD5 误报
        let sha1_ranges: Vec<(usize, usize)> = groups
            .iter()
            .filter(|g| g.algorithm == "SHA-1")
            .map(|g| (g.start_idx.saturating_sub(500), g.end_idx.saturating_add(500)))
            .collect();
        groups.retain(|g| {
            if g.algorithm != "MD5" {
                return true;
            }
            !sha1_ranges
                .iter()
                .any(|&(s, e)| g.start_idx >= s && g.end_idx <= e)
        });

        groups.sort_by_key(|g| g.start_idx);
        groups
    }

    fn attribute_pre_exec(&self, raw_idx: usize, raw_rec: TraceRecord) -> (usize, TraceRecord) {
        if raw_idx > 0 {
            if let Some(prev) = self.get(raw_idx - 1) {
                if raw_rec.seq_low32 == prev.seq_low32.wrapping_add(1) {
                    return (raw_idx - 1, prev);
                }
            }
        }
        (raw_idx, raw_rec)
    }

    fn build_seq_index_map(&self) -> HashMap<u32, usize> {
        let mut map = HashMap::with_capacity(self.idx_count);
        for i in 0..self.idx_count {
            let seq = read_packed::<TraceRecord>(&self.idx_mmap, i).seq_low32;
            map.insert(seq, i);
        }
        map
    }

    /// 导出 IDAPython 覆盖率染色脚本
    pub fn export_ida_python(&self, runtime_base: u64) -> String {
        let offsets = self.collect_relative_offsets(runtime_base);
        let mut script = String::from(
            "# Auto-generated by runidbg-arm64-emu-tracer runidbg-cli\n\
             import ida_nalt, idc\n\
             base = ida_nalt.get_imagebase()\n\
             offsets = [\n",
        );
        for off in &offsets {
            script.push_str(&format!("    0x{off:x},\n"));
        }
        script.push_str(
            "]\n\
             for off in offsets:\n\
                 idc.set_color(base + off, idc.CIC_ITEM, 0xCCFFCC)\n\
             print(f'[runidbg-arm64-emu-tracer] Highlighted {len(offsets)} instructions.')\n",
        );
        script
    }

    /// 导出 Binary Ninja 覆盖率高亮脚本
    pub fn export_binja_python(&self, runtime_base: u64) -> String {
        let offsets = self.collect_relative_offsets(runtime_base);
        let mut script = String::from(
            "# Auto-generated by runidbg-arm64-emu-tracer runidbg-cli\n\
             from binaryninja import HighlightStandardColor\n\
             base = bv.start\n\
             offsets = [\n",
        );
        for off in &offsets {
            script.push_str(&format!("    0x{off:x},\n"));
        }
        script.push_str(
            "]\n\
             for off in offsets:\n\
                 ea = base + off\n\
                 for f in bv.get_functions_containing(ea):\n\
                     f.set_user_instr_highlight(ea, HighlightStandardColor.GreenHighlightColor)\n\
             print(f'[runidbg-arm64-emu-tracer] Highlighted {len(offsets)} instructions.')\n",
        );
        script
    }

    fn collect_relative_offsets(&self, runtime_base: u64) -> BTreeSet<u64> {
        let mut offsets = BTreeSet::new();
        for i in 0..self.idx_count {
            let pc = read_packed::<TraceRecord>(&self.idx_mmap, i).pc;
            if pc >= runtime_base {
                offsets.insert(pc - runtime_base);
            }
        }
        offsets
    }
}

#[inline]
fn read_packed<T: Copy>(mmap: &Mmap, index: usize) -> T {
    let offset = index * size_of::<T>();
    // SAFETY: 调用方保证 index * size_of::<T>() + size_of::<T>() <= mmap.len()
    unsafe { ptr::read_unaligned(mmap.as_ptr().add(offset) as *const T) }
}
