//! 高性能零依赖内存特征码匹配与页块影子内存原语
//!
//! - [`WildcardMatcher`]：支持通配符（`Option<u8>`）与纯精确字节串（`from_exact`）的 SIMD 加速扫描器。
//!   - 预处理选取 1–2 个低频稀缺字节作为锚点，避开 `0x00`/`0xFF` 等高频字节；
//!   - `aarch64` 走 NEON（16 字节并行 + `vshrn_n_u16` 位掩码直出）；
//!   - `x86_64` 运行时探测 AVX2（32 字节并行）并回退 SSE2（16 字节并行）；
//!   - 其余架构走零依赖 SWAR `u64`（8 字节并行）；
//!   - 剩余固定字节按 8 字节 `(val64, mask64)` 块打包校验，过滤率 > 99.99%。
//! - [`PagedShadowMem`]：4KB 页块 + 64×u64 有效位图 + FxHash + 热页缓存影子内存，
//!   替代离线 Trace 字节流匹配中的逐字节 `HashMap<u64, u8>`。

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::ops::ControlFlow;

// ============================================================================
// 1. 稀缺字节锚点 + SIMD 加速特征码匹配器
// ============================================================================

/// 8 字节打包掩码块：校验 `u64::from_le_bytes(haystack[pos + off .. pos + off + 8]) & mask == val`
#[derive(Debug, Clone, Copy)]
struct PackedChunk8 {
    off: usize,
    val: u64,
    mask: u64,
}

#[derive(Debug, Clone)]
enum MatchPlan {
    Empty,
    /// 全通配符（每个合法位置都命中）
    AllWildcards,
    /// 仅 1 个固定字节
    OneAnchor { off1: usize, b1: u8 },
    /// >= 2 个固定字节：双稀缺字节 SIMD 滤波 + 打包块/尾部验证
    TwoAnchors {
        off1: usize,
        b1: u8,
        off2: usize,
        b2: u8,
        chunks: Vec<PackedChunk8>,
        tail: Vec<(usize, u8)>,
    },
}

/// 预编译的内存字节特征码扫描器（支持精确字节串与 `??` 通配符）
#[derive(Debug, Clone)]
pub struct WildcardMatcher {
    pat_len: usize,
    plan: MatchPlan,
    /// 256-bit 字节出现集合（仅在精确模式无通配符时用于 O(1) 剪枝）
    byte_bitmap: [u64; 4],
    /// 若精确模式所有字节相同，则为 `Some(b)`，用于大块 `memset` 数学剪枝
    all_same_exact: Option<u8>,
}

/// 字节稀缺度评分（越小越稀缺，越优先选作 SIMD 滤波锚点）
#[inline]
const fn byte_rarity_score(b: u8) -> u8 {
    match b {
        0x00 => 255,
        0xFF => 240,
        // ARM64 高频编码字节与小整数常见字节
        0x01 | 0x02 | 0x04 | 0x08 | 0x1F | 0x20 | 0x52 | 0x91 | 0xA9 | 0xAA | 0xB4 | 0xD5
        | 0xE0 | 0xF9 | 0xFD => 180,
        // 常见 ASCII 字符（空格/数字/小写字母）略高频于任意二进制字节
        b'0'..=b'9' | b'a'..=b'z' => 90,
        _ => 10,
    }
}

impl WildcardMatcher {
    /// 从通配符字节序列编译扫描计划
    pub fn new(pattern: &[Option<u8>]) -> Self {
        let pat_len = pattern.len();
        if pat_len == 0 {
            return Self {
                pat_len: 0,
                plan: MatchPlan::Empty,
                byte_bitmap: [0; 4],
                all_same_exact: None,
            };
        }

        let mut fixed: Vec<(usize, u8)> = Vec::with_capacity(pat_len);
        let mut byte_bitmap = [0u64; 4];
        let mut all_exact = true;
        let mut first_exact: Option<u8> = None;
        let mut same_exact = true;

        for (i, &p) in pattern.iter().enumerate() {
            if let Some(b) = p {
                fixed.push((i, b));
                byte_bitmap[(b >> 6) as usize] |= 1u64 << (b & 63);
                match first_exact {
                    None => first_exact = Some(b),
                    Some(fb) if fb != b => same_exact = false,
                    _ => {}
                }
            } else {
                all_exact = false;
                same_exact = false;
            }
        }

        if !all_exact {
            // 通配符可匹配任意字节，令位图全 1 保证公开 API `contains_byte`/`contains_any_byte` 剪枝绝对安全
            byte_bitmap = [u64::MAX; 4];
        }

        let all_same_exact = if all_exact && same_exact {
            first_exact
        } else {
            None
        };

        let plan = match fixed.len() {
            0 => MatchPlan::AllWildcards,
            1 => MatchPlan::OneAnchor {
                off1: fixed[0].0,
                b1: fixed[0].1,
            },
            _ => {
                // 选出最稀缺的第 1 锚点
                let mut best1_idx = 0usize;
                let mut best1_score = byte_rarity_score(fixed[0].1);
                for (idx, &(_, b)) in fixed.iter().enumerate().skip(1) {
                    let s = byte_rarity_score(b);
                    if s < best1_score {
                        best1_score = s;
                        best1_idx = idx;
                    }
                }
                let (off1, b1) = fixed[best1_idx];

                // 选出最稀缺且尽量与 b1 不同、间距较大的第 2 锚点
                let mut best2_idx = if best1_idx == 0 { 1 } else { 0 };
                let mut best2_key = (u16::MAX, 0usize);
                for (idx, &(off, b)) in fixed.iter().enumerate() {
                    if idx == best1_idx {
                        continue;
                    }
                    let penalty: u16 = if b == b1 { 60 } else { 0 };
                    let score = u16::from(byte_rarity_score(b)) + penalty;
                    let dist = off.abs_diff(off1);
                    if score < best2_key.0 || (score == best2_key.0 && dist > best2_key.1) {
                        best2_key = (score, dist);
                        best2_idx = idx;
                    }
                }
                let (off2, b2) = fixed[best2_idx];

                // 收集剩余固定字节并按 8 字节打包成 Masked u64 块
                let mut rest: Vec<(usize, u8)> = Vec::with_capacity(fixed.len() - 2);
                for (idx, &item) in fixed.iter().enumerate() {
                    if idx != best1_idx && idx != best2_idx {
                        rest.push(item);
                    }
                }

                let mut chunks: Vec<PackedChunk8> = Vec::new();
                let mut tail: Vec<(usize, u8)> = Vec::new();

                if pat_len >= 8 && rest.len() >= 3 {
                    let mut ri = 0usize;
                    while ri < rest.len() {
                        let start_off = rest[ri].0;
                        // 仅当 start_off + 8 <= pat_len 且窗口内覆盖 >= 3 个固定字节时打包为 u64 块
                        if start_off + 8 <= pat_len {
                            let mut end_ri = ri;
                            while end_ri < rest.len() && rest[end_ri].0 < start_off + 8 {
                                end_ri += 1;
                            }
                            if end_ri - ri >= 3 {
                                let mut val = 0u64;
                                let mut mask = 0u64;
                                for &(o, b) in &rest[ri..end_ri] {
                                    let shift = (o - start_off) * 8;
                                    val |= u64::from(b) << shift;
                                    mask |= 0xFFu64 << shift;
                                }
                                chunks.push(PackedChunk8 {
                                    off: start_off,
                                    val,
                                    mask,
                                });
                                ri = end_ri;
                                continue;
                            }
                        }
                        tail.push(rest[ri]);
                        ri += 1;
                    }
                } else {
                    tail = rest;
                }

                MatchPlan::TwoAnchors {
                    off1,
                    b1,
                    off2,
                    b2,
                    chunks,
                    tail,
                }
            }
        };

        Self {
            pat_len,
            plan,
            byte_bitmap,
            all_same_exact,
        }
    }

    /// 从精确字节串编译扫描计划
    pub fn from_exact(pattern: &[u8]) -> Self {
        let wrapped: Vec<Option<u8>> = pattern.iter().copied().map(Some).collect();
        Self::new(&wrapped)
    }

    #[inline]
    pub fn pat_len(&self) -> usize {
        self.pat_len
    }

    /// 判断某个字节是否可能出现在目标 pattern 中（精确模式走 O(1) 256-bit 位图；含通配符时恒返回 `true`）
    #[inline]
    pub fn contains_byte(&self, b: u8) -> bool {
        (self.byte_bitmap[(b >> 6) as usize] & (1u64 << (b & 63))) != 0
    }

    /// 判断 `bytes` 中是否至少有一个字节可能出现在目标 pattern 中（含通配符时恒返回 `true`）
    #[inline]
    pub fn contains_any_byte(&self, bytes: &[u8]) -> bool {
        bytes.iter().any(|&b| self.contains_byte(b))
    }

    /// 若精确 pattern 全部由同一个字节 `b` 组成，返回 `Some(b)`
    #[inline]
    pub fn all_same_exact(&self) -> Option<u8> {
        self.all_same_exact
    }

    /// 扫描 `haystack`，返回所有命中偏移（升序）
    pub fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let _ = self.for_each_match(haystack, |pos| {
            out.push(pos);
            ControlFlow::Continue(())
        });
        out
    }

    /// 扫描 `haystack`，按升序对每个命中偏移调用 `on_match`（返回 `ControlFlow::Break` 可提前终止）
    pub fn for_each_match<F>(&self, haystack: &[u8], mut on_match: F) -> ControlFlow<()>
    where
        F: FnMut(usize) -> ControlFlow<()>,
    {
        if self.pat_len == 0 || haystack.len() < self.pat_len {
            return ControlFlow::Continue(());
        }
        let limit = haystack.len() - self.pat_len + 1;

        match &self.plan {
            MatchPlan::Empty => ControlFlow::Continue(()),
            MatchPlan::AllWildcards => {
                for pos in 0..limit {
                    on_match(pos)?;
                }
                ControlFlow::Continue(())
            }
            MatchPlan::OneAnchor { off1, b1 } => {
                scan_one_anchor(haystack, limit, *off1, *b1, on_match)
            }
            MatchPlan::TwoAnchors {
                off1,
                b1,
                off2,
                b2,
                chunks,
                tail,
            } => scan_two_anchors(haystack, limit, *off1, *b1, *off2, *b2, |pos| {
                if verify_rest(haystack, pos, chunks, tail) {
                    on_match(pos)
                } else {
                    ControlFlow::Continue(())
                }
            }),
        }
    }
}

#[inline(always)]
fn verify_rest(
    haystack: &[u8],
    pos: usize,
    chunks: &[PackedChunk8],
    tail: &[(usize, u8)],
) -> bool {
    for c in chunks {
        let start = pos + c.off;
        // 调用方已保证 pos + pat_len <= haystack.len() 且 c.off + 8 <= pat_len
        let word = u64::from_le_bytes(haystack[start..start + 8].try_into().unwrap());
        if (word & c.mask) != c.val {
            return false;
        }
    }
    for &(o, b) in tail {
        if haystack[pos + o] != b {
            return false;
        }
    }
    true
}

// ============================================================================
// 2. 跨架构 SIMD / SWAR 单锚点与双锚点扫描内核
// ============================================================================

#[inline]
#[allow(unused_mut)]
fn scan_one_anchor<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    #[cfg(all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "neon"
    ))]
    {
        return unsafe { scan_one_anchor_neon(haystack, limit, off1, b1, on_cand) };
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return unsafe { scan_one_anchor_avx2(haystack, limit, off1, b1, on_cand) };
        }
        #[cfg(target_feature = "sse2")]
        {
            return unsafe { scan_one_anchor_sse2(haystack, limit, off1, b1, on_cand) };
        }
    }

    #[allow(unreachable_code)]
    scan_one_anchor_swar(haystack, limit, off1, b1, &mut on_cand)
}

#[inline]
#[allow(unused_mut)]
fn scan_two_anchors<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    off2: usize,
    b2: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    #[cfg(all(
        target_arch = "aarch64",
        target_endian = "little",
        target_feature = "neon"
    ))]
    {
        return unsafe { scan_two_anchors_neon(haystack, limit, off1, b1, off2, b2, on_cand) };
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return unsafe { scan_two_anchors_avx2(haystack, limit, off1, b1, off2, b2, on_cand) };
        }
        #[cfg(target_feature = "sse2")]
        {
            return unsafe { scan_two_anchors_sse2(haystack, limit, off1, b1, off2, b2, on_cand) };
        }
    }

    #[allow(unreachable_code)]
    scan_two_anchors_swar(haystack, limit, off1, b1, off2, b2, &mut on_cand)
}

// ---- ARM64 NEON (16 bytes / iter) ----

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon"
))]
#[inline]
unsafe fn neon_emit_matches<F>(
    m: std::arch::aarch64::uint8x16_t,
    pos: usize,
    on_cand: &mut F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    use std::arch::aarch64::*;
    // 将 16 个 0x00/0xFF lane 压缩为 64-bit nibble 掩码（每 lane 占 4 bit）
    let narrowed = vshrn_n_u16::<4>(vreinterpretq_u16_u8(m));
    let mut bits = vget_lane_u64::<0>(vreinterpret_u64_u8(narrowed));
    while bits != 0 {
        let lane = (bits.trailing_zeros() >> 2) as usize;
        on_cand(pos + lane)?;
        bits &= !(0xFu64 << (lane * 4));
    }
    ControlFlow::Continue(())
}

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon"
))]
unsafe fn scan_one_anchor_neon<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    use std::arch::aarch64::*;
    let ptr = haystack.as_ptr();
    let splat1 = vdupq_n_u8(b1);
    let mut pos = 0usize;
    while pos + 16 <= limit {
        let v1 = vld1q_u8(ptr.add(pos + off1));
        let m = vceqq_u8(v1, splat1);
        if vmaxvq_u8(m) != 0 {
            neon_emit_matches(m, pos, &mut on_cand)?;
        }
        pos += 16;
    }
    while pos < limit {
        if *ptr.add(pos + off1) == b1 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_feature = "neon"
))]
unsafe fn scan_two_anchors_neon<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    off2: usize,
    b2: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    use std::arch::aarch64::*;
    let ptr = haystack.as_ptr();
    let splat1 = vdupq_n_u8(b1);
    let splat2 = vdupq_n_u8(b2);
    let mut pos = 0usize;
    while pos + 16 <= limit {
        let v1 = vld1q_u8(ptr.add(pos + off1));
        let v2 = vld1q_u8(ptr.add(pos + off2));
        let m = vandq_u8(vceqq_u8(v1, splat1), vceqq_u8(v2, splat2));
        if vmaxvq_u8(m) != 0 {
            neon_emit_matches(m, pos, &mut on_cand)?;
        }
        pos += 16;
    }
    while pos < limit {
        if *ptr.add(pos + off1) == b1 && *ptr.add(pos + off2) == b2 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

// ---- x86_64 AVX2 (32 bytes / iter) & SSE2 (16 bytes / iter) ----

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_one_anchor_avx2<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    use std::arch::x86_64::*;
    let ptr = haystack.as_ptr();
    let splat1 = _mm256_set1_epi8(b1 as i8);
    let mut pos = 0usize;
    while pos + 32 <= limit {
        let v1 = _mm256_loadu_si256(ptr.add(pos + off1) as *const __m256i);
        let mut mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, splat1)) as u32;
        while mask != 0 {
            let lane = mask.trailing_zeros() as usize;
            on_cand(pos + lane)?;
            mask &= mask - 1;
        }
        pos += 32;
    }
    while pos < limit {
        if *ptr.add(pos + off1) == b1 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_two_anchors_avx2<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    off2: usize,
    b2: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    use std::arch::x86_64::*;
    let ptr = haystack.as_ptr();
    let splat1 = _mm256_set1_epi8(b1 as i8);
    let splat2 = _mm256_set1_epi8(b2 as i8);
    let mut pos = 0usize;
    while pos + 32 <= limit {
        let v1 = _mm256_loadu_si256(ptr.add(pos + off1) as *const __m256i);
        let v2 = _mm256_loadu_si256(ptr.add(pos + off2) as *const __m256i);
        let m = _mm256_and_si256(
            _mm256_cmpeq_epi8(v1, splat1),
            _mm256_cmpeq_epi8(v2, splat2),
        );
        let mut mask = _mm256_movemask_epi8(m) as u32;
        while mask != 0 {
            let lane = mask.trailing_zeros() as usize;
            on_cand(pos + lane)?;
            mask &= mask - 1;
        }
        pos += 32;
    }
    while pos < limit {
        if *ptr.add(pos + off1) == b1 && *ptr.add(pos + off2) == b2 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
unsafe fn scan_one_anchor_sse2<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    use std::arch::x86_64::*;
    let ptr = haystack.as_ptr();
    let splat1 = _mm_set1_epi8(b1 as i8);
    let mut pos = 0usize;
    while pos + 16 <= limit {
        let v1 = _mm_loadu_si128(ptr.add(pos + off1) as *const __m128i);
        let mut mask = _mm_movemask_epi8(_mm_cmpeq_epi8(v1, splat1)) as u32;
        while mask != 0 {
            let lane = mask.trailing_zeros() as usize;
            on_cand(pos + lane)?;
            mask &= mask - 1;
        }
        pos += 16;
    }
    while pos < limit {
        if *ptr.add(pos + off1) == b1 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
unsafe fn scan_two_anchors_sse2<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    off2: usize,
    b2: u8,
    mut on_cand: F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    use std::arch::x86_64::*;
    let ptr = haystack.as_ptr();
    let splat1 = _mm_set1_epi8(b1 as i8);
    let splat2 = _mm_set1_epi8(b2 as i8);
    let mut pos = 0usize;
    while pos + 16 <= limit {
        let v1 = _mm_loadu_si128(ptr.add(pos + off1) as *const __m128i);
        let v2 = _mm_loadu_si128(ptr.add(pos + off2) as *const __m128i);
        let m = _mm_and_si128(_mm_cmpeq_epi8(v1, splat1), _mm_cmpeq_epi8(v2, splat2));
        let mut mask = _mm_movemask_epi8(m) as u32;
        while mask != 0 {
            let lane = mask.trailing_zeros() as usize;
            on_cand(pos + lane)?;
            mask &= mask - 1;
        }
        pos += 16;
    }
    while pos < limit {
        if *ptr.add(pos + off1) == b1 && *ptr.add(pos + off2) == b2 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

// ---- 通用 SWAR u64 (8 bytes / iter, 零 unsafe, 无跨 lane 借位干扰) ----

#[inline]
fn swar_eq_mask(word: u64, splat: u64) -> u64 {
    // 无借位按 lane 精确判零：((b & 0x7F) + 0x7F) <= 0xFE 绝不向相邻高字节进位，
    // 当且仅当某字节 b == 0 时该字节最高位 bit 7 为 1（0x80）。
    const LO7: u64 = 0x7F7F_7F7F_7F7F_7F7F;
    const HI: u64 = 0x8080_8080_8080_8080;
    let x = word ^ splat;
    !((x & LO7).wrapping_add(LO7) | x) & HI
}

pub(crate) fn scan_one_anchor_swar<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    on_cand: &mut F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    let splat1 = u64::from_ne_bytes([b1; 8]);
    let mut pos = 0usize;
    while pos + 8 <= limit {
        let w1 = u64::from_le_bytes(haystack[pos + off1..pos + off1 + 8].try_into().unwrap());
        let mut mask = swar_eq_mask(w1, splat1);
        while mask != 0 {
            let lane = (mask.trailing_zeros() >> 3) as usize;
            on_cand(pos + lane)?;
            mask &= mask - 1;
        }
        pos += 8;
    }
    while pos < limit {
        if haystack[pos + off1] == b1 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

pub(crate) fn scan_two_anchors_swar<F>(
    haystack: &[u8],
    limit: usize,
    off1: usize,
    b1: u8,
    off2: usize,
    b2: u8,
    on_cand: &mut F,
) -> ControlFlow<()>
where
    F: FnMut(usize) -> ControlFlow<()>,
{
    let splat1 = u64::from_ne_bytes([b1; 8]);
    let splat2 = u64::from_ne_bytes([b2; 8]);
    let mut pos = 0usize;
    while pos + 8 <= limit {
        let w1 = u64::from_le_bytes(haystack[pos + off1..pos + off1 + 8].try_into().unwrap());
        let w2 = u64::from_le_bytes(haystack[pos + off2..pos + off2 + 8].try_into().unwrap());
        let mut mask = swar_eq_mask(w1, splat1) & swar_eq_mask(w2, splat2);
        while mask != 0 {
            let lane = (mask.trailing_zeros() >> 3) as usize;
            on_cand(pos + lane)?;
            mask &= mask - 1;
        }
        pos += 8;
    }
    while pos < limit {
        if haystack[pos + off1] == b1 && haystack[pos + off2] == b2 {
            on_cand(pos)?;
        }
        pos += 1;
    }
    ControlFlow::Continue(())
}

// ============================================================================
// 3. 轻量零依赖 FxHash + 4KB 页块影子内存（离线 Trace 字节流增量匹配）
// ============================================================================

#[derive(Default)]
struct FxHasher {
    hash: u64,
}

impl FxHasher {
    const K: u64 = 0x517c_c1b7_2722_0a95;

    #[inline]
    fn add_u64(&mut self, i: u64) {
        self.hash = (self.hash.rotate_left(5) ^ i).wrapping_mul(Self::K);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.add_u64(u64::from(b));
        }
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add_u64(i);
    }
}

type FxHashMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

const SHADOW_PAGE_SHIFT: u32 = 12;
const SHADOW_PAGE_SIZE: usize = 1 << SHADOW_PAGE_SHIFT; // 4096
const SHADOW_PAGE_MASK: usize = SHADOW_PAGE_SIZE - 1;

/// 4KB 影子内存页（含 64×u64 精确有效字节位图）
struct ShadowPage {
    data: [u8; SHADOW_PAGE_SIZE],
    valid: [u64; SHADOW_PAGE_SIZE / 64],
    valid_count: u16,
}

impl ShadowPage {
    fn new_empty() -> Box<Self> {
        Box::new(Self {
            data: [0u8; SHADOW_PAGE_SIZE],
            valid: [0u64; SHADOW_PAGE_SIZE / 64],
            valid_count: 0,
        })
    }

    #[inline]
    fn get_byte(&self, off: usize) -> Option<u8> {
        if (self.valid[off >> 6] & (1u64 << (off & 63))) != 0 {
            Some(self.data[off])
        } else {
            None
        }
    }

    #[inline]
    fn set_byte(&mut self, off: usize, val: u8) {
        self.data[off] = val;
        let bit = 1u64 << (off & 63);
        let word = &mut self.valid[off >> 6];
        if (*word & bit) == 0 {
            *word |= bit;
            self.valid_count += 1;
        }
    }

    #[inline]
    fn clear_byte(&mut self, off: usize) {
        let bit = 1u64 << (off & 63);
        let word = &mut self.valid[off >> 6];
        if (*word & bit) != 0 {
            *word &= !bit;
            self.valid_count -= 1;
        }
    }

    /// 批量置位 `[start, end)` 的有效位图并准确维护 `valid_count`
    fn set_valid_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        if start == 0 && end == SHADOW_PAGE_SIZE {
            self.valid.fill(u64::MAX);
            self.valid_count = SHADOW_PAGE_SIZE as u16;
            return;
        }
        let first_w = start >> 6;
        let last_w = (end - 1) >> 6;
        let first_bit = start & 63;
        let last_bit = (end - 1) & 63;

        if first_w == last_w {
            let width = end - start;
            let mask = if width == 64 {
                u64::MAX
            } else {
                ((1u64 << width) - 1) << first_bit
            };
            let old = self.valid[first_w];
            let nw = old | mask;
            self.valid[first_w] = nw;
            self.valid_count += (nw.count_ones() - old.count_ones()) as u16;
            return;
        }

        let mut added = 0u32;
        let head_mask = u64::MAX << first_bit;
        let old_h = self.valid[first_w];
        let new_h = old_h | head_mask;
        self.valid[first_w] = new_h;
        added += new_h.count_ones() - old_h.count_ones();

        for w in &mut self.valid[first_w + 1..last_w] {
            added += 64 - w.count_ones();
            *w = u64::MAX;
        }

        let tail_mask = if last_bit == 63 {
            u64::MAX
        } else {
            (1u64 << (last_bit + 1)) - 1
        };
        let old_t = self.valid[last_w];
        let new_t = old_t | tail_mask;
        self.valid[last_w] = new_t;
        added += new_t.count_ones() - old_t.count_ones();

        self.valid_count += added as u16;
    }

    /// 批量清除 `[start, end)` 的有效位图并准确维护 `valid_count`
    fn clear_valid_range(&mut self, start: usize, end: usize) {
        if start >= end || self.valid_count == 0 {
            return;
        }
        if start == 0 && end == SHADOW_PAGE_SIZE {
            self.valid.fill(0);
            self.valid_count = 0;
            return;
        }
        let first_w = start >> 6;
        let last_w = (end - 1) >> 6;
        let first_bit = start & 63;
        let last_bit = (end - 1) & 63;

        if first_w == last_w {
            let width = end - start;
            let mask = if width == 64 {
                u64::MAX
            } else {
                ((1u64 << width) - 1) << first_bit
            };
            let old = self.valid[first_w];
            let nw = old & !mask;
            self.valid[first_w] = nw;
            self.valid_count -= (old.count_ones() - nw.count_ones()) as u16;
            return;
        }

        let mut removed = 0u32;
        let head_mask = u64::MAX << first_bit;
        let old_h = self.valid[first_w];
        let new_h = old_h & !head_mask;
        self.valid[first_w] = new_h;
        removed += old_h.count_ones() - new_h.count_ones();

        for w in &mut self.valid[first_w + 1..last_w] {
            removed += w.count_ones();
            *w = 0;
        }

        let tail_mask = if last_bit == 63 {
            u64::MAX
        } else {
            (1u64 << (last_bit + 1)) - 1
        };
        let old_t = self.valid[last_w];
        let new_t = old_t & !tail_mask;
        self.valid[last_w] = new_t;
        removed += old_t.count_ones() - new_t.count_ones();

        self.valid_count -= removed as u16;
    }

    /// 检查 `[start, start + len)` 是否全部有效（要求 `start + len <= 4096`）
    #[inline]
    fn is_valid_range(&self, start: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        if self.valid_count == SHADOW_PAGE_SIZE as u16 {
            return true;
        }
        if (self.valid_count as usize) < len {
            return false;
        }
        let end = start + len;
        let first_w = start >> 6;
        let last_w = (end - 1) >> 6;
        let first_bit = start & 63;
        let last_bit = (end - 1) & 63;

        if first_w == last_w {
            let mask = if len == 64 {
                u64::MAX
            } else {
                ((1u64 << len) - 1) << first_bit
            };
            return (self.valid[first_w] & mask) == mask;
        }

        let head_mask = u64::MAX << first_bit;
        if (self.valid[first_w] & head_mask) != head_mask {
            return false;
        }
        for &w in &self.valid[first_w + 1..last_w] {
            if w != u64::MAX {
                return false;
            }
        }
        let tail_mask = if last_bit == 63 {
            u64::MAX
        } else {
            (1u64 << (last_bit + 1)) - 1
        };
        (self.valid[last_w] & tail_mask) == tail_mask
    }
}

/// 4KB 页块影子内存（供离线 Trace `.ext` 字节流增量匹配使用）
pub struct PagedShadowMem {
    pages: Vec<Box<ShadowPage>>,
    page_map: FxHashMap<u64, usize>,
    last_page: Option<(u64, usize)>,
    /// 复用 `HleMemcpy` 临时缓冲，避免重复分配
    scratch_bytes: Vec<u8>,
    scratch_valid: Vec<u8>,
}

impl Default for PagedShadowMem {
    fn default() -> Self {
        Self::new()
    }
}

impl PagedShadowMem {
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            page_map: FxHashMap::default(),
            last_page: None,
            scratch_bytes: Vec::new(),
            scratch_valid: Vec::new(),
        }
    }

    #[inline]
    fn find_page_idx(&self, page_id: u64) -> Option<usize> {
        if let Some((last_id, idx)) = self.last_page {
            if last_id == page_id {
                return Some(idx);
            }
        }
        self.page_map.get(&page_id).copied()
    }

    #[inline]
    fn get_or_create_page_idx(&mut self, page_id: u64) -> usize {
        if let Some((last_id, idx)) = self.last_page {
            if last_id == page_id {
                return idx;
            }
        }
        let idx = if let Some(&existing) = self.page_map.get(&page_id) {
            existing
        } else {
            let idx = self.pages.len();
            self.pages.push(ShadowPage::new_empty());
            self.page_map.insert(page_id, idx);
            idx
        };
        self.last_page = Some((page_id, idx));
        idx
    }

    #[inline]
    pub fn get_byte(&self, addr: u64) -> Option<u8> {
        let idx = self.find_page_idx(addr >> SHADOW_PAGE_SHIFT)?;
        self.pages[idx].get_byte((addr as usize) & SHADOW_PAGE_MASK)
    }

    #[inline]
    pub fn set_byte(&mut self, addr: u64, val: u8) {
        let idx = self.get_or_create_page_idx(addr >> SHADOW_PAGE_SHIFT);
        self.pages[idx].set_byte((addr as usize) & SHADOW_PAGE_MASK, val);
    }

    #[inline]
    pub fn clear_byte(&mut self, addr: u64) {
        if let Some(idx) = self.find_page_idx(addr >> SHADOW_PAGE_SHIFT) {
            self.pages[idx].clear_byte((addr as usize) & SHADOW_PAGE_MASK);
        }
    }

    /// 连续写入 `bytes` 到 `addr`（自动处理跨页与地址回绕）
    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if addr.checked_add(bytes.len() as u64).is_none() {
            for (off, &b) in bytes.iter().enumerate() {
                self.set_byte(addr.wrapping_add(off as u64), b);
            }
            return;
        }
        let mut cur_addr = addr;
        let mut src_off = 0usize;
        while src_off < bytes.len() {
            let page_id = cur_addr >> SHADOW_PAGE_SHIFT;
            let page_off = (cur_addr as usize) & SHADOW_PAGE_MASK;
            let take = (SHADOW_PAGE_SIZE - page_off).min(bytes.len() - src_off);
            let idx = self.get_or_create_page_idx(page_id);
            let page = &mut self.pages[idx];
            page.data[page_off..page_off + take]
                .copy_from_slice(&bytes[src_off..src_off + take]);
            page.set_valid_range(page_off, page_off + take);
            cur_addr += take as u64;
            src_off += take;
        }
    }

    /// 连续填充 `len` 字节的 `fill` 到 `dst`（整页直填，极速处理大块 `HleMemset`）
    pub fn fill_bytes(&mut self, dst: u64, fill: u8, len: usize) {
        if len == 0 {
            return;
        }
        if dst.checked_add(len as u64).is_none() {
            for off in 0..len {
                self.set_byte(dst.wrapping_add(off as u64), fill);
            }
            return;
        }
        let mut cur_addr = dst;
        let mut rem = len;
        while rem > 0 {
            let page_id = cur_addr >> SHADOW_PAGE_SHIFT;
            let page_off = (cur_addr as usize) & SHADOW_PAGE_MASK;
            let take = (SHADOW_PAGE_SIZE - page_off).min(rem);
            let idx = self.get_or_create_page_idx(page_id);
            let page = &mut self.pages[idx];
            page.data[page_off..page_off + take].fill(fill);
            page.set_valid_range(page_off, page_off + take);
            cur_addr += take as u64;
            rem -= take;
        }
    }

    /// 语义精确的 `memcpy`/`memmove`（支持源/目标重叠，未写入的源字节会清除目标对应有效位）
    pub fn copy_range(&mut self, dst: u64, src: u64, len: usize) {
        if len == 0 || dst == src {
            return;
        }
        // 地址回绕极端情况走安全逐字节
        let (Some(src_end), Some(dst_end)) = (
            src.checked_add(len as u64),
            dst.checked_add(len as u64),
        ) else {
            self.scratch_bytes.clear();
            self.scratch_valid.clear();
            self.scratch_bytes.reserve(len);
            self.scratch_valid.reserve(len);
            for off in 0..len {
                match self.get_byte(src.wrapping_add(off as u64)) {
                    Some(b) => {
                        self.scratch_bytes.push(b);
                        self.scratch_valid.push(1);
                    }
                    None => {
                        self.scratch_bytes.push(0);
                        self.scratch_valid.push(0);
                    }
                }
            }
            for off in 0..len {
                if self.scratch_valid[off] != 0 {
                    self.set_byte(dst.wrapping_add(off as u64), self.scratch_bytes[off]);
                } else {
                    self.clear_byte(dst.wrapping_add(off as u64));
                }
            }
            return;
        };

        let overlaps = src < dst_end && dst < src_end;
        if !overlaps {
            // 非重叠快路径：按页段直接搬运，源页不存在时直接批量清除目标有效位（零分配）
            let mut cur_src = src;
            let mut cur_dst = dst;
            let mut rem = len;
            while rem > 0 {
                let s_pid = cur_src >> SHADOW_PAGE_SHIFT;
                let s_off = (cur_src as usize) & SHADOW_PAGE_MASK;
                let d_pid = cur_dst >> SHADOW_PAGE_SHIFT;
                let d_off = (cur_dst as usize) & SHADOW_PAGE_MASK;
                let take = (SHADOW_PAGE_SIZE - s_off)
                    .min(SHADOW_PAGE_SIZE - d_off)
                    .min(rem);

                match self.find_page_idx(s_pid) {
                    None => {
                        if let Some(d_idx) = self.find_page_idx(d_pid) {
                            self.pages[d_idx].clear_valid_range(d_off, d_off + take);
                        }
                    }
                    Some(s_idx) if self.pages[s_idx].valid_count == 0 => {
                        if let Some(d_idx) = self.find_page_idx(d_pid) {
                            self.pages[d_idx].clear_valid_range(d_off, d_off + take);
                        }
                    }
                    Some(s_idx) => {
                        if self.pages[s_idx].is_valid_range(s_off, take) {
                            // 整段源字节全部有效：零栈缓冲直接整块拷贝
                            let d_idx = self.get_or_create_page_idx(d_pid);
                            if s_idx == d_idx {
                                let p = &mut self.pages[d_idx];
                                p.data.copy_within(s_off..s_off + take, d_off);
                                p.set_valid_range(d_off, d_off + take);
                            } else if s_idx < d_idx {
                                let (left, right) = self.pages.split_at_mut(d_idx);
                                let sp = &left[s_idx];
                                let dp = &mut right[0];
                                dp.data[d_off..d_off + take]
                                    .copy_from_slice(&sp.data[s_off..s_off + take]);
                                dp.set_valid_range(d_off, d_off + take);
                            } else {
                                let (left, right) = self.pages.split_at_mut(s_idx);
                                let dp = &mut left[d_idx];
                                let sp = &right[0];
                                dp.data[d_off..d_off + take]
                                    .copy_from_slice(&sp.data[s_off..s_off + take]);
                                dp.set_valid_range(d_off, d_off + take);
                            }
                        } else {
                            // 稀疏混合有效/无效段：使用复用 scratch（仅需 `take` 字节，避免栈上 8KB 清零）
                            let mut any_valid = false;
                            if s_pid == d_pid {
                                self.scratch_bytes.resize(take, 0);
                                self.scratch_valid.resize(take, 0);
                                let sp = &self.pages[s_idx];
                                for k in 0..take {
                                    if let Some(b) = sp.get_byte(s_off + k) {
                                        self.scratch_bytes[k] = b;
                                        self.scratch_valid[k] = 1;
                                        any_valid = true;
                                    } else {
                                        self.scratch_valid[k] = 0;
                                    }
                                }
                                if any_valid {
                                    let dp = &mut self.pages[s_idx];
                                    for k in 0..take {
                                        if self.scratch_valid[k] != 0 {
                                            dp.set_byte(d_off + k, self.scratch_bytes[k]);
                                        } else {
                                            dp.clear_byte(d_off + k);
                                        }
                                    }
                                } else {
                                    self.pages[s_idx].clear_valid_range(d_off, d_off + take);
                                }
                            } else {
                                {
                                    let sp = &self.pages[s_idx];
                                    for k in 0..take {
                                        if sp.get_byte(s_off + k).is_some() {
                                            any_valid = true;
                                            break;
                                        }
                                    }
                                }
                                if any_valid {
                                    let d_idx = self.get_or_create_page_idx(d_pid);
                                    let (sp, dp) = if s_idx < d_idx {
                                        let (left, right) = self.pages.split_at_mut(d_idx);
                                        (&*left[s_idx], &mut *right[0])
                                    } else {
                                        let (left, right) = self.pages.split_at_mut(s_idx);
                                        (&*right[0], &mut *left[d_idx])
                                    };
                                    for k in 0..take {
                                        if let Some(b) = sp.get_byte(s_off + k) {
                                            dp.set_byte(d_off + k, b);
                                        } else {
                                            dp.clear_byte(d_off + k);
                                        }
                                    }
                                } else if let Some(d_idx) = self.find_page_idx(d_pid) {
                                    self.pages[d_idx].clear_valid_range(d_off, d_off + take);
                                }
                            }
                        }
                    }
                }
                cur_src += take as u64;
                cur_dst += take as u64;
                rem -= take;
            }
            return;
        }

        // 重叠区域（memmove 语义）：先读入复用 scratch 再写回
        self.scratch_bytes.resize(len, 0);
        self.scratch_valid.resize(len, 0);
        {
            let mut cur_src = src;
            let mut dst_off = 0usize;
            while dst_off < len {
                let s_pid = cur_src >> SHADOW_PAGE_SHIFT;
                let s_off = (cur_src as usize) & SHADOW_PAGE_MASK;
                let take = (SHADOW_PAGE_SIZE - s_off).min(len - dst_off);
                if let Some(s_idx) = self.find_page_idx(s_pid) {
                    let sp = &self.pages[s_idx];
                    if sp.is_valid_range(s_off, take) {
                        self.scratch_bytes[dst_off..dst_off + take]
                            .copy_from_slice(&sp.data[s_off..s_off + take]);
                        self.scratch_valid[dst_off..dst_off + take].fill(1);
                    } else {
                        for k in 0..take {
                            if let Some(b) = sp.get_byte(s_off + k) {
                                self.scratch_bytes[dst_off + k] = b;
                                self.scratch_valid[dst_off + k] = 1;
                            } else {
                                self.scratch_valid[dst_off + k] = 0;
                            }
                        }
                    }
                } else {
                    self.scratch_valid[dst_off..dst_off + take].fill(0);
                }
                cur_src += take as u64;
                dst_off += take;
            }
        }
        {
            let mut cur_dst = dst;
            let mut src_off = 0usize;
            while src_off < len {
                let d_pid = cur_dst >> SHADOW_PAGE_SHIFT;
                let d_off = (cur_dst as usize) & SHADOW_PAGE_MASK;
                let take = (SHADOW_PAGE_SIZE - d_off).min(len - src_off);
                let any_valid = self.scratch_valid[src_off..src_off + take]
                    .iter()
                    .any(|&v| v != 0);
                if any_valid {
                    let d_idx = self.get_or_create_page_idx(d_pid);
                    let dp = &mut self.pages[d_idx];
                    for k in 0..take {
                        if self.scratch_valid[src_off + k] != 0 {
                            dp.set_byte(d_off + k, self.scratch_bytes[src_off + k]);
                        } else {
                            dp.clear_byte(d_off + k);
                        }
                    }
                } else if let Some(d_idx) = self.find_page_idx(d_pid) {
                    self.pages[d_idx].clear_valid_range(d_off, d_off + take);
                }
                cur_dst += take as u64;
                src_off += take;
            }
        }
    }

    /// 精确检查单个地址 `candidate` 处是否匹配 `pattern`
    #[inline]
    fn match_at(&self, candidate: u64, pattern: &[u8]) -> bool {
        let pat_len = pattern.len();
        let page_id = candidate >> SHADOW_PAGE_SHIFT;
        let page_off = (candidate as usize) & SHADOW_PAGE_MASK;
        if page_off + pat_len <= SHADOW_PAGE_SIZE {
            let Some(idx) = self.find_page_idx(page_id) else {
                return false;
            };
            let page = &self.pages[idx];
            return &page.data[page_off..page_off + pat_len] == pattern
                && page.is_valid_range(page_off, pat_len);
        }
        for (k, &pb) in pattern.iter().enumerate() {
            if self.get_byte(candidate.wrapping_add(k as u64)) != Some(pb) {
                return false;
            }
        }
        true
    }

    /// 在候选起始地址区间 `[start_lo ..= start_hi]` 内按升序搜索所有精确匹配 `pattern` 的地址。
    /// `matcher` 必须由 `WildcardMatcher::from_exact(pattern)` 构建（长度须与 `pattern` 一致）。
    /// 页内连续段直接使用 [`WildcardMatcher`] 的 SIMD 内核扫描，跨页边界无缝衔接。
    pub fn scan_candidates<F>(
        &self,
        start_lo: u64,
        start_hi: u64,
        pattern: &[u8],
        matcher: &WildcardMatcher,
        mut on_match: F,
    ) -> ControlFlow<()>
    where
        F: FnMut(u64) -> ControlFlow<()>,
    {
        let pat_len = pattern.len();
        if pat_len == 0 || start_lo > start_hi {
            return ControlFlow::Continue(());
        }
        assert_eq!(
            matcher.pat_len(),
            pat_len,
            "WildcardMatcher::pat_len() must match pattern.len()"
        );

        // 若逼近 u64::MAX 发生地址回绕，走安全逐候选回退
        if start_hi.checked_add(pat_len as u64).is_none() {
            let mut cand = start_lo;
            loop {
                if self.match_at(cand, pattern) {
                    on_match(cand)?;
                }
                if cand == start_hi {
                    break;
                }
                cand += 1;
            }
            return ControlFlow::Continue(());
        }

        let pat_len_u64 = pat_len as u64;
        let mut cur = start_lo;
        while cur <= start_hi {
            let page_id = cur >> SHADOW_PAGE_SHIFT;
            let page_base = page_id << SHADOW_PAGE_SHIFT;
            let page_end = page_base.saturating_add(SHADOW_PAGE_SIZE as u64);
            let page_cand_end = start_hi.min(page_end - 1);

            if let Some(idx) = self.find_page_idx(page_id) {
                let page = &self.pages[idx];
                if page.valid_count > 0 {
                    // 1) 完全落在本页内的候选区间（使用 SIMD 加速扫描连续页切片）
                    if pat_len <= SHADOW_PAGE_SIZE {
                        let max_inner = page_end - pat_len_u64;
                        if cur <= max_inner {
                            let inner_hi = page_cand_end.min(max_inner);
                            if (page.valid_count as usize) >= pat_len {
                                let off_lo = (cur - page_base) as usize;
                                let off_hi_excl = (inner_hi - page_base) as usize + pat_len;
                                let slice = &page.data[off_lo..off_hi_excl];
                                matcher.for_each_match(slice, |rel| {
                                    let p_off = off_lo + rel;
                                    if page.is_valid_range(p_off, pat_len) {
                                        on_match(cur + rel as u64)
                                    } else {
                                        ControlFlow::Continue(())
                                    }
                                })?;
                            }
                            cur = inner_hi + 1;
                        }
                    }

                    // 2) 跨越本页末尾边界的候选区间（最多 pat_len - 1 个候选地址）
                    if cur <= page_cand_end {
                        // 仅当下一页也存在时跨页候选才可能完整有效
                        if self.find_page_idx(page_id + 1).is_some() {
                            let mut cand = cur;
                            while cand <= page_cand_end {
                                if self.match_at(cand, pattern) {
                                    on_match(cand)?;
                                }
                                cand += 1;
                            }
                        }
                    }
                }
            }

            if page_cand_end == start_hi {
                break;
            }
            cur = page_end;
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_wildcard_matcher_parity_against_naive() {
        // 覆盖各类边界长度、对齐偏移、全零/高频字节、全通配符、单固定字节、多打包块
        let mut buf = vec![0u8; 4096 + 37];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(131) ^ (i >> 3)) & 0xFF) as u8;
        }
        // 在关键 SIMD 边界附近（0, 1, 15, 16, 17, 31, 32, 33, 末尾）手工埋点
        let sig = [0xFD, 0x7B, 0x01, 0xA9, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        for &pos in &[0usize, 1, 14, 15, 16, 30, 31, 32, 63, 64, 1000, buf.len() - sig.len()] {
            buf[pos..pos + sig.len()].copy_from_slice(&sig);
        }

        let patterns: Vec<Vec<Option<u8>>> = vec![
            vec![None, None, None],
            vec![Some(0xFD)],
            vec![None, Some(0x7B), None],
            vec![Some(0xFD), Some(0x7B), None, Some(0xA9)],
            vec![
                Some(0xFD),
                Some(0x7B),
                None,
                Some(0xA9),
                Some(0x33),
                None,
                Some(0x55),
                Some(0x66),
                Some(0x77),
                None,
                Some(0x99),
            ],
            vec![Some(0x00), Some(0x00), Some(0x00)],
            vec![Some(0x33), Some(0x33)],
            sig.iter().copied().map(Some).collect(),
        ];

        for pat in &patterns {
            let matcher = WildcardMatcher::new(pat);
            let got = matcher.find_all(&buf);
            let expected = naive_wildcard_scan(&buf, pat);
            assert_eq!(got, expected, "mismatch for pattern {pat:?}");
        }

        // 同时验证 SWAR 路径与朴素结果一致
        let mut swar_hits = Vec::new();
        let _ = scan_two_anchors_swar(
            &buf,
            buf.len() - 4 + 1,
            0,
            0xFD,
            3,
            0xA9,
            &mut |pos| {
                if buf[pos + 1] == 0x7B {
                    swar_hits.push(pos);
                }
                ControlFlow::Continue(())
            },
        );
        let expected_swar =
            naive_wildcard_scan(&buf, &[Some(0xFD), Some(0x7B), None, Some(0xA9)]);
        assert_eq!(swar_hits, expected_swar);
    }

    #[test]
    fn test_paged_shadow_mem_cross_page_and_overlap_copy() {
        let mut mem = PagedShadowMem::new();
        // 跨 4KB 页边界写入 "HELLO_WORLD"
        let base = 0x1000_0FFC_u64;
        mem.write_bytes(base, b"HELLO_WORLD");
        let pat = b"LO_WO";
        let matcher = WildcardMatcher::from_exact(pat);

        let mut hits = Vec::new();
        let _ = mem.scan_candidates(base - 10, base + 20, pat, &matcher, |addr| {
            hits.push(addr);
            ControlFlow::Continue(())
        });
        assert_eq!(hits, vec![base + 3]);

        // 测试 memmove 重叠复制 + 稀疏无效字节传播
        mem.write_bytes(0x2000, b"ABCDEFGH");
        mem.clear_byte(0x2002); // 使 'C' 无效
        mem.copy_range(0x2004, 0x2000, 8); // 重叠向后复制
        assert_eq!(mem.get_byte(0x2004), Some(b'A'));
        assert_eq!(mem.get_byte(0x2005), Some(b'B'));
        assert_eq!(mem.get_byte(0x2006), None); // 无效位正确传播
        assert_eq!(mem.get_byte(0x2007), Some(b'D'));
        assert_eq!(mem.get_byte(0x200B), Some(b'H'));

        // 大块 memset 跨多页
        mem.fill_bytes(0x5000, 0xAA, 10_000);
        let pat_aa = b"\xAA\xAA\xAA\xAA";
        let m_aa = WildcardMatcher::from_exact(pat_aa);
        let mut cnt = 0usize;
        let _ = mem.scan_candidates(0x5000, 0x5000 + 10_000 - 4, pat_aa, &m_aa, |_| {
            cnt += 1;
            ControlFlow::Continue(())
        });
        assert_eq!(cnt, 10_000 - 3);
    }

    #[test]
    fn test_swar_carry_free_and_wildcard_bitmap_soundness() {
        // P0 回归：匹配字节后紧跟 `b ^ 1`（原 Mycroft 减法会发生跨 lane 借位误报）
        let hay = [0x10u8, 0x11, 0x11, 0x22, 0x10, 0x11, 0x10, 0x10, 0x11, 0x33];
        let mut hits1 = Vec::new();
        let _ = scan_one_anchor_swar(&hay, hay.len(), 0, 0x10, &mut |p| {
            hits1.push(p);
            ControlFlow::Continue(())
        });
        assert_eq!(hits1, vec![0, 4, 6, 7]);

        let mut hits2 = Vec::new();
        let _ = scan_two_anchors_swar(&hay, hay.len() - 1, 0, 0x10, 1, 0x11, &mut |p| {
            hits2.push(p);
            ControlFlow::Continue(())
        });
        assert_eq!(hits2, vec![0, 4, 7]);

        // 通配符 matcher 的 contains_byte 必须恒为 true，避免误剪枝
        let wm = WildcardMatcher::new(&[Some(0xAA), None, Some(0xBB)]);
        assert!(wm.contains_byte(0x00));
        assert!(wm.contains_byte(0x55));
        assert!(wm.contains_any_byte(&[0x12]));
    }

    #[test]
    fn test_shadow_page_bitmap_boundaries_and_multipage_pattern() {
        // 覆盖 64-bit word 边界与 valid_count 一致性
        let ranges = [
            (0, 1),
            (0, 64),
            (63, 64),
            (63, 65),
            (64, 128),
            (0, 4095),
            (1, 4096),
            (0, 4096),
            (4095, 4096),
        ];
        for (s, e) in ranges {
            let mut p = ShadowPage::new_empty();
            p.set_valid_range(s, e);
            let ones: u16 = p.valid.iter().map(|w| w.count_ones() as u16).sum();
            assert_eq!(p.valid_count, ones);
            assert_eq!(p.valid_count as usize, e - s);
            assert!(p.is_valid_range(s, e - s));
            p.clear_valid_range(s, e);
            assert_eq!(p.valid_count, 0);
            assert!(p.valid.iter().all(|&w| w == 0));
        }

        // 跨越 3 个 4KB 页的超长特征码（5000B）+ 同页非重叠拷贝 + 反向重叠拷贝 + u64::MAX 回绕
        let mut mem = PagedShadowMem::new();
        let big_pat: Vec<u8> = (0..5000usize).map(|i| ((i * 37) & 0xFF) as u8).collect();
        let start = 0x1000_0F00u64;
        mem.write_bytes(start, &big_pat);
        let matcher = WildcardMatcher::from_exact(&big_pat);
        let mut hits = Vec::new();
        let _ = mem.scan_candidates(start - 16, start + 16, &big_pat, &matcher, |a| {
            hits.push(a);
            ControlFlow::Continue(())
        });
        assert_eq!(hits, vec![start]);

        // 同页非重叠拷贝与反向重叠拷贝
        mem.write_bytes(0x3000, b"12345678");
        mem.copy_range(0x3100, 0x3000, 8);
        assert_eq!((0..8).map(|i| mem.get_byte(0x3100 + i).unwrap()).collect::<Vec<_>>(), b"12345678");
        mem.copy_range(0x3100, 0x3102, 6); // dst < src 重叠
        assert_eq!((0..6).map(|i| mem.get_byte(0x3100 + i).unwrap()).collect::<Vec<_>>(), b"345678");

        // u64::MAX 回绕写入与匹配
        let wrap_addr = u64::MAX - 2;
        mem.write_bytes(wrap_addr, b"WXYZ");
        let wm = WildcardMatcher::from_exact(b"WXYZ");
        let mut wrap_hits = Vec::new();
        let _ = mem.scan_candidates(wrap_addr, u64::MAX, b"WXYZ", &wm, |a| {
            wrap_hits.push(a);
            ControlFlow::Continue(())
        });
        assert_eq!(wrap_hits, vec![wrap_addr]);

        // 最后一个 4KB 页且不回绕边界：start_hi = u64::MAX - pat_len（覆盖 page_end 饱和路径）
        let last_page_addr = u64::MAX - 8;
        mem.write_bytes(last_page_addr, b"LASTPAGE");
        let lm = WildcardMatcher::from_exact(b"LASTPAGE");
        let mut last_hits = Vec::new();
        let _ = mem.scan_candidates(
            last_page_addr - 4,
            u64::MAX - 8,
            b"LASTPAGE",
            &lm,
            |a| {
                last_hits.push(a);
                ControlFlow::Continue(())
            },
        );
        assert_eq!(last_hits, vec![last_page_addr]);
    }

    #[test]
    fn test_early_break_mid_vector_simd_and_swar() {
        // 单个 SIMD/SWAR 向量内全命中，验证 ControlFlow::Break(()) 在第 2 次命中时立即中断
        let buf = [0xAAu8; 64];
        let m1 = WildcardMatcher::from_exact(&[0xAA]);
        let mut seen = Vec::new();
        let cf = m1.for_each_match(&buf, |p| {
            seen.push(p);
            if seen.len() >= 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert!(cf.is_break());
        assert_eq!(seen, vec![0, 1]);

        let m2 = WildcardMatcher::from_exact(&[0xAA, 0xAA]);
        let mut seen2 = Vec::new();
        let cf2 = m2.for_each_match(&buf, |p| {
            seen2.push(p);
            if seen2.len() >= 3 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert!(cf2.is_break());
        assert_eq!(seen2, vec![0, 1, 2]);

        let mut swar_seen = Vec::new();
        let cf3 = scan_one_anchor_swar(&buf, buf.len(), 0, 0xAA, &mut |p| {
            swar_seen.push(p);
            if swar_seen.len() >= 2 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert!(cf3.is_break());
        assert_eq!(swar_seen, vec![0, 1]);
    }
}
