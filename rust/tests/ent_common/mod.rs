//! Shared helpers of the entropy-coding differential tests (owner: worker
//! "entropy").
#![allow(dead_code)]

use brotli::enc::encoder_dict::SharedEncoderDictionary;
use brotli::enc::params::{BrotliDistanceParams, BrotliEncoderParams, BrotliHasherParams};

/// xorshift64* PRNG.
#[derive(Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xD1B54A32D192ED03 | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    /// Uniform in `[0, n)` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    pub fn range(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        lo + self.below(hi_inclusive - lo + 1)
    }
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
}

const WORDS: &[&str] = &[
    "the", "of", "and", "to", "in", "a", "is", "that", "for", "it", "as", "was", "with", "be", "by", "on", "not",
    "he", "this", "are", "or", "his", "from", "at", "which", "but", "have", "an", "had", "they", "you", "were",
    "their", "one", "all", "we", "can", "her", "has", "there", "been", "if", "more", "when", "will", "would",
    "who", "so", "no", "brotli", "compression", "entropy", "Huffman", "histogram", "<div class=\"x\">", "</div>",
    "\n", "\r\n", "    ", "{", "}", "();", "€", "ünïcödé", "日本語", "текст", "0123", "4567", "89",
];

/// Number of data kinds of `gen_data`.
pub const NUM_DATA_KINDS: u64 = 11;

/// Generates test data of kind `kind` (0..NUM_DATA_KINDS) and length `len`.
pub fn gen_data(rng: &mut Rng, kind: u32, len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len + 64);
    match kind {
        // Random bytes.
        0 => {
            while v.len() < len {
                v.push(rng.next_u32() as u8);
            }
        }
        // Text-like.
        1 => {
            while v.len() < len {
                let w = WORDS[rng.below(WORDS.len() as u64) as usize];
                v.extend_from_slice(w.as_bytes());
                if rng.chance(3, 4) {
                    v.push(b' ');
                } else if rng.chance(1, 2) {
                    v.extend_from_slice(b", ");
                } else {
                    v.extend_from_slice(b".\n");
                }
            }
        }
        // Repetitive with mutations.
        2 => {
            let plen = rng.range(1, 300) as usize;
            let pattern: Vec<u8> = (0..plen).map(|_| rng.next_u32() as u8).collect();
            while v.len() < len {
                let mut chunk = pattern.clone();
                for c in chunk.iter_mut() {
                    if rng.chance(1, 50) {
                        *c = rng.next_u32() as u8;
                    }
                }
                v.extend_from_slice(&chunk);
            }
        }
        // Small alphabet random.
        3 => {
            let alpha = rng.range(1, 6) as u8;
            let base = rng.next_u32() as u8;
            while v.len() < len {
                v.push(base.wrapping_add((rng.next_u32() % alpha as u32) as u8));
            }
        }
        // Binary structured (little-endian counters / floats).
        4 => {
            let mut x: u32 = rng.next_u32();
            let step = rng.range(1, 1000) as u32;
            while v.len() < len {
                x = x.wrapping_add(step);
                if rng.chance(1, 8) {
                    v.extend_from_slice(&(x as f32).to_le_bytes());
                } else {
                    v.extend_from_slice(&x.to_le_bytes());
                }
            }
        }
        // Runs of a single byte.
        5 => {
            while v.len() < len {
                let b = rng.next_u32() as u8;
                let run = rng.range(1, 5000) as usize;
                v.extend(std::iter::repeat(b).take(run));
            }
        }
        // Text with embedded base64 data URIs.
        6 => {
            const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut prev: Vec<u8> = Vec::new();
            while v.len() < len {
                let r = rng.below(10);
                if r < 4 {
                    v.extend_from_slice(b"<img src=\"data:image/png;base64,");
                    if !prev.is_empty() && rng.chance(1, 3) {
                        v.extend_from_slice(&prev.clone());
                    } else {
                        let n = rng.range(1, 6000) as usize;
                        let s: Vec<u8> = (0..n).map(|_| B64[rng.below(64) as usize]).collect();
                        v.extend_from_slice(&s);
                        prev = s;
                    }
                    let pad = rng.below(3) as usize;
                    v.extend(std::iter::repeat(b'=').take(pad));
                    v.extend_from_slice(b"\">\n");
                } else {
                    let w = WORDS[rng.below(WORDS.len() as u64) as usize];
                    v.extend_from_slice(w.as_bytes());
                    v.push(b' ');
                }
            }
        }
        // Mixture of the above in chunks.
        7 => {
            while v.len() < len {
                let k = rng.below(7) as u32;
                let n = rng.range(1, 20000) as usize;
                let chunk = gen_data(rng, k, n);
                v.extend_from_slice(&chunk);
            }
        }
        // All zeros.
        8 => {
            v.resize(len, 0);
        }
        // Segments with very different statistics (many block types).
        10 => {
            while v.len() < len {
                let n = rng.range(200, 4000) as usize;
                let alpha: Vec<u8> = (0..rng.range(1, 24)).map(|_| rng.next_u32() as u8).collect();
                for _ in 0..n {
                    v.push(alpha[rng.below(alpha.len() as u64) as usize]);
                }
            }
        }
        // Copies of earlier data at various distances (LZ-friendly).
        _ => {
            while v.len() < len {
                if v.len() > 16 && rng.chance(2, 3) {
                    let dist = rng.range(1, v.len().min(1 << 20) as u64) as usize;
                    let n = rng.range(2, 300) as usize;
                    let start = v.len() - dist;
                    for i in 0..n {
                        let b = v[start + i];
                        v.push(b);
                    }
                } else {
                    let n = rng.range(1, 20) as usize;
                    for _ in 0..n {
                        v.push(rng.next_u32() as u8);
                    }
                }
            }
        }
    }
    v.truncate(len);
    v
}

/// A `BrotliEncoderParams` with the fields used by the entropy modules.
pub fn make_params(quality: i32, large_window: bool, disable_lcm: bool, dist: BrotliDistanceParams) -> BrotliEncoderParams {
    BrotliEncoderParams {
        mode: 0,
        quality,
        lgwin: 22,
        lgblock: 0,
        stream_offset: 0,
        size_hint: 0,
        disable_literal_context_modeling: disable_lcm,
        large_window,
        hasher: BrotliHasherParams::default(),
        dist,
        dictionary: SharedEncoderDictionary::new(),
        base64_mode: 0,
        max_base64_regions: 16,
        min_base64_region_len: 2048,
        simd_hasher: 0,
        hasher_opt: false,
    }
}

/// Time / iteration budget of the randomized loops: `ENT_SECONDS` (default
/// `default_secs`).
pub fn budget_secs(default_secs: f64) -> f64 {
    std::env::var("ENT_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(default_secs)
}

pub fn base_seed() -> u64 {
    std::env::var("ENT_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5EED)
}
