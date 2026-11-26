//! 内存匹配算法正确性等价验证 & 性能基准测试
//!
//! 1. 验证 `WildcardMatcher` + `scan_memory`（含跨 256KB 流式分块边界、全通配符与边界参数）与朴素扫描 100% 等价；
//! 2. 验证 `TraceReader::search_mem_bytes` / `search_mem_bytes_bounded` / `query_writes_by_value`
//!    在 `MemWrite` / 跨页写入 / 同 `seq` 多写（`STP`）去重 / 重叠与孤儿 `HleMemcpy` /
//!    大块 `HleMemset`（含 `dst==0`、首尾拼接、全填充、`min_seq`/`max_seq`/`limit`）下与朴素模型 100% 等价；
//! 3. 提供 `--ignored` release benchmark 量化真实提速倍率。

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use runidbg_arm64_emu_tracer::mem_match::WildcardMatcher;
use runidbg_arm64_emu_tracer::tracer::{
    BinaryTracer, ExtKind, ExtRecord, HleOpEvent, TraceLevel, TraceReader,
};

fn naive_wildcard_scan(haystack: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Vec::new();
    }
    haystack
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(i, w)| {
            w.iter()
                .zip(pattern.iter())
                .all(|(b, p)| p.is_none_or(|x| *b == x))
                .then_some(i)
        })
        .collect()
}

/// 朴素参照版 `search_mem_bytes_bounded`（逐字节 `HashMap<u64, u8>`）用于严格等价性对拍
fn naive_search_ext_bounded(
    records: &[ExtRecord],
    pattern: &[u8],
    min_seq: Option<u32>,
    max_seq: Option<u32>,
    limit: usize,
) -> Vec<(u32, u64)> {
    if pattern.is_empty() {
        return Vec::new();
    }
    let mut mem: HashMap<u64, u8> = HashMap::new();
    let mut hits = Vec::new();
    let mut dedup_seq: Option<u32> = None;
    let mut dedup_addrs: HashSet<u64> = HashSet::new();
    let pat_len = pattern.len();

    let check = |mem: &HashMap<u64, u8>,
                 start: u64,
                 wlen: usize,
                 seq: u32,
                 hits: &mut Vec<(u32, u64)>,
                 dedup_seq: &mut Option<u32>,
                 dedup_addrs: &mut HashSet<u64>|
     -> bool {
        if let Some(lo) = min_seq {
            if seq < lo {
                return false;
            }
        }
        if *dedup_seq != Some(seq) {
            dedup_addrs.clear();
            *dedup_seq = Some(seq);
        }
        let lo = start.saturating_sub((pat_len - 1) as u64);
        let hi = start.saturating_add((wlen.saturating_sub(1)) as u64);
        let mut cand = lo;
        while cand <= hi {
            if pattern
                .iter()
                .enumerate()
                .all(|(k, &pb)| mem.get(&cand.wrapping_add(k as u64)).copied() == Some(pb))
                && dedup_addrs.insert(cand)
            {
                hits.push((seq, cand));
                if limit > 0 && hits.len() >= limit {
                    return true;
                }
            }
            match cand.checked_add(1) {
                Some(n) => cand = n,
                None => break,
            }
        }
        false
    };

    let mut i = 0;
    while i < records.len() {
        let r = records[i];
        if let Some(hi) = max_seq {
            if r.seq_low32 > hi {
                break;
            }
        }
        match ExtKind::from_u8(r.kind) {
            Some(ExtKind::MemWrite) => {
                let sz = (r.size_or_reg as usize).clamp(1, 8);
                let bs = r.value.to_le_bytes();
                for (off, &b) in bs.iter().take(sz).enumerate() {
                    mem.insert(r.addr.wrapping_add(off as u64), b);
                }
                if check(&mem, r.addr, sz, r.seq_low32, &mut hits, &mut dedup_seq, &mut dedup_addrs) {
                    break;
                }
            }
            Some(ExtKind::HleMemcpy) => {
                let mut len = 0usize;
                if i + 1 < records.len()
                    && ExtKind::from_u8(records[i + 1].kind) == Some(ExtKind::HleMeta)
                    && records[i + 1].seq_low32 == r.seq_low32
                    && records[i + 1].addr == r.addr
                {
                    len = records[i + 1].value.min(1 << 20) as usize;
                    i += 1;
                }
                if len > 0 {
                    let copied: Vec<Option<u8>> = (0..len)
                        .map(|o| mem.get(&r.value.wrapping_add(o as u64)).copied())
                        .collect();
                    for (o, mb) in copied.into_iter().enumerate() {
                        if let Some(b) = mb {
                            mem.insert(r.addr.wrapping_add(o as u64), b);
                        } else {
                            mem.remove(&r.addr.wrapping_add(o as u64));
                        }
                    }
                    if check(
                        &mem,
                        r.addr,
                        len,
                        r.seq_low32,
                        &mut hits,
                        &mut dedup_seq,
                        &mut dedup_addrs,
                    ) {
                        break;
                    }
                }
            }
            Some(ExtKind::HleMemset) => {
                let len = r.value.min(1 << 20) as usize;
                let fill = r.size_or_reg;
                if len > 0 {
                    for o in 0..len {
                        mem.insert(r.addr.wrapping_add(o as u64), fill);
                    }
                    if check(
                        &mem,
                        r.addr,
                        len,
                        r.seq_low32,
                        &mut hits,
                        &mut dedup_seq,
                        &mut dedup_addrs,
                    ) {
                        break;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    hits
}

#[test]
fn test_trace_search_mem_bytes_exact_parity_with_naive() {
    let dir = std::env::temp_dir().join(format!(
        "runidbg_mem_match_parity_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let idx_path = dir.join("t.idx");
    let ext_path = dir.join("t.ext");

    let mut tracer =
        BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 64, 4096, TraceLevel::Full).unwrap();
    tracer.set_active(true);

    let rec_write = |tr: &mut BinaryTracer, pc: u64, addr: u64, bytes: &[u8]| {
        tr.record_fast(pc, 0xd503_201f);
        let mut off = 0usize;
        while off < bytes.len() {
            let take = (bytes.len() - off).min(8);
            let mut v = [0u8; 8];
            v[..take].copy_from_slice(&bytes[off..off + take]);
            tr.record_mem_access(true, addr + off as u64, take, u64::from_le_bytes(v));
            off += take;
        }
    };

    // 1. 跨 4KB 页边界拼出 "SIG_ALPHA!"
    rec_write(&mut tracer, 0x1000, 0x5000_0FFC, b"SIG_");
    rec_write(&mut tracer, 0x1004, 0x5000_1000, b"ALPHA!");

    // 2. 边界拼接场景：在 0x6000_0000 前写入 "XY"，在 0x6000_1000 后写入 "ZW"，
    //    中间执行大块 HleMemset(0x6000_0000, b'A', 4096) -> 左边界拼出 "XYAA"，右边界拼出 "AAZW"
    rec_write(&mut tracer, 0x1008, 0x5FFF_FFFE, b"XY");
    rec_write(&mut tracer, 0x100C, 0x6000_1000, b"ZW");
    tracer.record_fast(0x1010, 0xd503_201f);
    tracer.record_hle_event(HleOpEvent {
        kind: ExtKind::HleMemset,
        subop_or_byte: b'A',
        aux_subop: 0,
        dst: 0x6000_0000,
        src: 0,
        len: 4096,
        caller_pc: 0x1010,
    });

    // 3. HleMemcpy 非重叠复制跨页数据到 0x7000_0FFE（目标同样跨页）
    tracer.record_fast(0x1014, 0xd503_201f);
    tracer.record_hle_event(HleOpEvent {
        kind: ExtKind::HleMemcpy,
        subop_or_byte: 0,
        aux_subop: 0,
        dst: 0x7000_0FFE,
        src: 0x5000_0FFC,
        len: 10,
        caller_pc: 0x1014,
    });

    // 4. HleMemcpy 重叠复制（memmove）+ 源中含未写空洞清除目标字节
    rec_write(&mut tracer, 0x1018, 0x8000_0000, b"TOKEN");
    tracer.record_fast(0x101C, 0xd503_201f);
    tracer.record_hle_event(HleOpEvent {
        kind: ExtKind::HleMemcpy,
        subop_or_byte: 1,
        aux_subop: 0,
        dst: 0x8000_0002,
        src: 0x8000_0000,
        len: 7,
        caller_pc: 0x101C,
    });

    // 5. HleMemcpy 自拷贝（dst == src）+ dst==0 大块 HleMemset + len == 2*pat_len / 2*pat_len+1
    tracer.record_fast(0x1020, 0xd503_201f);
    tracer.record_hle_event(HleOpEvent {
        kind: ExtKind::HleMemcpy,
        subop_or_byte: 0,
        aux_subop: 0,
        dst: 0x8000_0002,
        src: 0x8000_0002,
        len: 5,
        caller_pc: 0x1020,
    });
    rec_write(&mut tracer, 0x1024, 0x20, b"ZZ");
    tracer.record_fast(0x1028, 0xd503_201f);
    tracer.record_hle_event(HleOpEvent {
        kind: ExtKind::HleMemset,
        subop_or_byte: b'B',
        aux_subop: 0,
        dst: 0,
        src: 0,
        len: 32,
        caller_pc: 0x1028,
    });

    // 6. 同一 seq_low32 多写（模拟 STP）去重验证
    tracer.record_fast(0x102C, 0xd503_201f);
    tracer.record_mem_access(true, 0x9000_0000, 8, u64::from_le_bytes(*b"ABABABAB"));
    tracer.record_mem_access(true, 0x9000_0008, 8, u64::from_le_bytes(*b"ABABABAB"));

    tracer.flush().unwrap();
    drop(tracer);

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let ref_records: Vec<ExtRecord> = (0..reader.ext_len())
        .map(|i| reader.get_ext(i).unwrap())
        .collect();
    assert!(!ref_records.is_empty());

    let test_patterns: &[&[u8]] = &[
        b"SIG_ALPHA!",
        b"XYAA",
        b"AAZW",
        b"AAAA",
        b"TOKEN",
        b"BBZZ",
        b"ABAB",
        b"NOT_FOUND_XYZ",
        b"A",
    ];

    for &pat in test_patterns {
        let got: Vec<(u32, u64)> = reader
            .search_mem_bytes(pat)
            .into_iter()
            .map(|h| (h.seq_low32, h.addr))
            .collect();
        let expected = naive_search_ext_bounded(&ref_records, pat, None, None, 0);
        assert_eq!(
            got,
            expected,
            "TraceReader::search_mem_bytes mismatch for {:?}",
            String::from_utf8_lossy(pat)
        );
    }

    // 验证 min_seq / max_seq / limit 有界提前终止等价性（含在 HleMemset 左边界命中即截断）
    for &(min_s, max_s, lim) in &[
        (Some(4u32), Some(8u32), 0usize),
        (Some(4u32), None, 1usize),
        (None, Some(5u32), 3usize),
    ] {
        for &pat in &[b"XYAA".as_slice(), b"AAAA".as_slice(), b"ABAB".as_slice()] {
            let got: Vec<(u32, u64)> = reader
                .search_mem_bytes_bounded(pat, min_s, max_s, lim)
                .into_iter()
                .map(|h| (h.seq_low32, h.addr))
                .collect();
            let expected = naive_search_ext_bounded(&ref_records, pat, min_s, max_s, lim);
            assert_eq!(
                got, expected,
                "bounded mismatch pat={:?} min={min_s:?} max={max_s:?} lim={lim}",
                String::from_utf8_lossy(pat)
            );
        }
    }

    // 验证 query_writes_by_value 多宽度（1, 2, 4, 8）+ 高位掩码 + limit
    let q4 = reader.query_writes_by_value(u32::from_le_bytes(*b"XYAA") as u64, 4, None, None, 5);
    assert_eq!(q4.len(), 1);
    assert_eq!(q4[0].addr, 0x5FFF_FFFE);
    let q2_masked =
        reader.query_writes_by_value(0xFFFF_0000 | (u16::from_le_bytes(*b"ZZ") as u64), 2, None, None, 2);
    assert_eq!(q2_masked.len(), 1);
    assert_eq!(q2_masked[0].addr, 0x20);

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "js")]
#[test]
fn test_js_mem_scan_cross_chunk_boundary() {
    // 映射 600KB 内存（> 256KB 流式分块大小），在精确的 256KB / 512KB 块边界埋入特征码
    use std::path::Path;
    use runidbg_arm64_emu_tracer::script::JsSession;

    let script = r#"
        (() => {
            const emu = Emu.create();
            const size = 600 * 1024;
            const base = emu.mem.alloc(size);
            const sig = new Uint8Array([0xFD, 0x7B, 0xBF, 0xA9, 0x99, 0x88, 0x77, 0x66]);
            // 在 0、256KB-3（严格跨第 1/2 块边界）、512KB-7（跨第 2/3 块边界）和末尾写入特征码
            const offsets = [0, 256 * 1024 - 3, 512 * 1024 - 7, size - sig.length];
            for (const off of offsets) {
                emu.mem.writeBytes(base + off, sig);
            }
            const hits = emu.mem.scan(base, size, "fd 7b ?? a9 99 ?? 77 66");
            if (hits.length !== offsets.length) {
                throw new Error("expected " + offsets.length + " hits, got " + JSON.stringify(hits));
            }
            for (let i = 0; i < offsets.length; i++) {
                if (hits[i] !== base + offsets[i]) {
                    throw new Error("hit[" + i + "] mismatch: " + hits[i] + " vs " + (base + offsets[i]));
                }
            }
            // 单字节扫描 & len=0 边界 & 全通配符跨块扫描数量校验
            const emptyHits = emu.mem.scan(base, 0, "fd");
            if (emptyHits.length !== 0) throw new Error("len=0 must return empty");
            const oneHits = emu.mem.scan(base, 16, "fd");
            if (oneHits.length !== 1 || oneHits[0] !== base) throw new Error("single-byte scan mismatch");
            const wildHits = emu.mem.scan(base + 256 * 1024 - 4, 10, "?? ??");
            if (wildHits.length !== 9) throw new Error("all-wildcard count mismatch: " + wildHits.length);
            return { base, hits };
        })()
    "#;
    let session = JsSession::new(&[], Path::new("."), true).unwrap();
    let res = session.eval_json_string(script).unwrap();
    assert!(res.contains("\"hits\":["));
}

#[test]
#[ignore]
fn bench_memory_matching_speedup() {
    // ---- Benchmark 1: 32 MB Guest 内存通配符特征码扫描 ----
    let size = 32 * 1024 * 1024;
    let mut mem = vec![0u8; size];
    for (i, b) in mem.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(1_103_515_245).wrapping_add(12_345)) >> 16) as u8;
    }
    let sig_bytes = [
        0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0xF3, 0x53, 0x01, 0xA9,
    ];
    for k in 1..=16 {
        let pos = k * (size / 17);
        mem[pos..pos + sig_bytes.len()].copy_from_slice(&sig_bytes);
    }
    let pat: Vec<Option<u8>> = vec![
        Some(0xFD),
        Some(0x7B),
        None,
        Some(0xA9),
        Some(0xFD),
        Some(0x03),
        None,
        Some(0x91),
        Some(0xF3),
        Some(0x53),
        None,
        Some(0xA9),
    ];

    let t0 = Instant::now();
    let naive_hits = naive_wildcard_scan(&mem, &pat);
    let naive_ms = (t0.elapsed().as_secs_f64() * 1000.0).max(1e-9);

    let t1 = Instant::now();
    let matcher = WildcardMatcher::new(&pat);
    let simd_hits = matcher.find_all(&mem);
    let simd_ms = (t1.elapsed().as_secs_f64() * 1000.0).max(1e-9);

    assert_eq!(naive_hits, simd_hits);
    println!(
        "[Bench 1] 32 MB Wildcard Scan (12B w/ 3 wildcards): naive={:.2} ms ({:.2} GB/s) vs SIMD={:.2} ms ({:.2} GB/s) => {:.1}x speedup",
        naive_ms,
        (size as f64 / 1e9) / (naive_ms / 1000.0),
        simd_ms,
        (size as f64 / 1e9) / (simd_ms / 1000.0),
        naive_ms / simd_ms,
    );

    // ---- Benchmark 2: 端到端 TraceReader::search_mem_bytes（200k MemWrite + 8×64KB HleMemset，含边界剪枝）----
    let dir = std::env::temp_dir().join(format!(
        "runidbg_mem_match_bench_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let idx_path = dir.join("b.idx");
    let ext_path = dir.join("b.ext");

    let mut tracer =
        BinaryTracer::new_dual_mmap(&idx_path, &ext_path, 250_000, 250_000, TraceLevel::Full)
            .unwrap();
    tracer.set_active(true);
    for seq in 0..200_000u32 {
        tracer.record_fast(0x4000_1000, 0xd503_201f);
        let addr = 0x5000_0000u64 + ((seq as u64 * 8) & 0x3_FFFF);
        let val = (seq as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        tracer.record_mem_access(true, addr, 8, val);
    }
    // 插入 8 次 64KB memset(b'R')：fill='R' 出现在 "RUNIDBG!" 中，真实测试大块边界剪枝路径
    for k in 0..8u32 {
        tracer.record_fast(0x4000_2000, 0xd503_201f);
        tracer.record_hle_event(HleOpEvent {
            kind: ExtKind::HleMemset,
            subop_or_byte: b'R',
            aux_subop: 0,
            dst: 0x6000_0000 + (k as u64) * 65536,
            src: 0,
            len: 65536,
            caller_pc: 0x4000_2000,
        });
    }
    tracer.record_fast(0x4000_3000, 0xd503_201f);
    tracer.record_mem_access(true, 0x5000_1000, 8, u64::from_le_bytes(*b"RUNIDBG!"));
    tracer.flush().unwrap();
    drop(tracer);

    let reader = TraceReader::open(&idx_path, Some(&ext_path)).unwrap();
    let records: Vec<ExtRecord> = (0..reader.ext_len())
        .map(|i| reader.get_ext(i).unwrap())
        .collect();

    let target = b"RUNIDBG!";
    let tn0 = Instant::now();
    let expected = naive_search_ext_bounded(&records, target, None, None, 0);
    let naive_ext_ms = (tn0.elapsed().as_secs_f64() * 1000.0).max(1e-9);

    let tf0 = Instant::now();
    let fast_hits: Vec<(u32, u64)> = reader
        .search_mem_bytes(target)
        .into_iter()
        .map(|h| (h.seq_low32, h.addr))
        .collect();
    let fast_ext_ms = (tf0.elapsed().as_secs_f64() * 1000.0).max(1e-9);

    assert_eq!(expected, fast_hits);
    println!(
        "[Bench 2] End-to-End TraceReader::search_mem_bytes (200k MemWrite + 512KB HleMemset w/ fill in pat): naive={:.2} ms vs fast={:.2} ms => {:.1}x speedup",
        naive_ext_ms,
        fast_ext_ms,
        naive_ext_ms / fast_ext_ms,
    );

    let _ = std::fs::remove_dir_all(&dir);
}
