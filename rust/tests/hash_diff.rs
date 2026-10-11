//! Differential tests of the matching side of the encoder (hashers, backward
//! references, Zopfli, static dictionary) against the C reference, via the
//! shims in `tests/c_shims/hash_shim.c`.
//!
//! OWNER: worker "hashers".
//!
//! Every session replicates encode.c around the matching code (parameter
//! setup, ring buffer writes, InitOrStitchToPreviousBlock,
//! ExtendLastCommand, backward references / Zopfli, metablock ends,
//! position wrapping) on both sides and compares commands, distance cache,
//! last_insert_len, num_literals, base64 regions and dictionary statistics
//! after every block.
//!
//! Environment knobs:
//! * `HASH_FUZZ_SECS`: duration of the randomized loop in
//!   `randomized_sessions` (default 20).
//! * `HASH_FUZZ_SEED`: base seed of the randomized loop.
//!
//! Ignored helpers: `bench_qualities`, `bench_min` (timings),
//! `work_single_side` (one side only, for `/usr/bin/time -l` instruction /
//! cycle counts), `huge_window_sessions` (lgwin 27 / 30 multi-block).
#![cfg(feature = "c-reference")]
#![allow(clippy::too_many_arguments)]

mod cref;

use std::ffi::c_void;

use brotli::common::alloc::Allocator;
use brotli::enc::backward_references::brotli_create_backward_references;
use brotli::enc::backward_references_hq::{
    brotli_create_hq_zopfli_backward_references, brotli_create_zopfli_backward_references,
};
use brotli::enc::command::{get_length_code, Command};
use brotli::enc::compound_dictionary::{create_prepared_dictionary, PreparedDictionary};
use brotli::enc::encoder_dict::{SharedEncoderDictionary, DEFAULT_ENCODER_DICTIONARY};
use brotli::enc::hash::{get_matching_tag_mask, hasher_size, init_or_stitch_to_previous_block, Hasher};
use brotli::enc::params::{Base64Region, BrotliDistanceParams, BrotliEncoderParams, BrotliHasherParams};
use brotli::enc::quality::{choose_hasher, compute_lg_block, sanitize_params};
use brotli::enc::ringbuffer::RingBuffer;
use brotli::enc::static_dict::{brotli_find_all_static_dictionary_matches, K_INVALID_MATCH};
use brotli::common::context::{brotli_context_lut, ContextType};

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct HsParamsOut {
    quality: i32,
    lgwin: i32,
    lgblock: i32,
    large_window: i32,
    stream_offset: usize,
    dist: BrotliDistanceParams,
}

extern "C" {
    fn hashshim_create(
        quality: i32,
        lgwin: i32,
        lgblock: i32,
        mode: i32,
        size_hint: usize,
        large_window: i32,
        stream_offset: usize,
        base64_mode: i32,
        max_base64_regions: usize,
        min_base64_region_len: usize,
        simd_hasher: i32,
        hasher_opt: i32,
        npostfix: i32,
        ndirect: i32,
        initial_pos: u64,
        zero_alloc: i32,
    ) -> *mut c_void;
    fn hashshim_get_params(s: *const c_void, out: *mut HsParamsOut);
    fn hashshim_attach(s: *mut c_void, data: *const u8, size: usize) -> i32;
    fn hashshim_destroy(s: *mut c_void);
    fn hashshim_process(s: *mut c_void, input: *const u8, n: usize, is_last: i32) -> i32;
    fn hashshim_flush(s: *mut c_void, restore_dist_cache: i32);
    fn hashshim_update_last_processed_pos(s: *mut c_void) -> i32;
    fn hashshim_num_commands(s: *const c_void) -> usize;
    fn hashshim_commands(s: *const c_void) -> *const Command;
    fn hashshim_num_literals(s: *const c_void) -> usize;
    fn hashshim_last_insert_len(s: *const c_void) -> usize;
    fn hashshim_dist_cache(s: *const c_void) -> *const i32;
    fn hashshim_hasher_type(s: *const c_void) -> i32;
    fn hashshim_num_base64_regions(s: *const c_void) -> usize;
    fn hashshim_base64_regions(s: *const c_void) -> *const Base64Region;
    fn hashshim_dict_num_lookups(s: *const c_void) -> usize;
    fn hashshim_dict_num_matches(s: *const c_void) -> usize;
    fn hashshim_hasher_size(
        quality: i32,
        lgwin: i32,
        size_hint: usize,
        simd_hasher: i32,
        hasher_opt: i32,
        one_shot: i32,
        input_size: usize,
        out: *mut usize,
    ) -> i32;
    fn hashshim_matching_tag_mask(chunk_count: usize, tag: u8, tag_bucket: *const u8, head: usize) -> u64;
    fn hashshim_static_dict_matches(data: *const u8, min_length: usize, max_length: usize, matches: *mut u32) -> i32;
}

/* ------------------------------- RNG / data ------------------------------ */

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0x1234567))
    }
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
}

fn dictionary_words() -> Vec<Vec<u8>> {
    let d = &brotli::common::dictionary::BROTLI_DICTIONARY;
    let data = d.data();
    let mut words = Vec::new();
    for len in 4..=24usize {
        let bits = d.size_bits_by_length[len];
        if bits == 0 {
            continue;
        }
        let n = 1usize << bits;
        let off = d.offsets_by_length[len] as usize;
        for i in (0..n).step_by(7) {
            words.push(data[off + i * len..off + (i + 1) * len].to_vec());
        }
    }
    words
}

fn gen_text(rng: &mut Rng, len: usize, words: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let suffixes: [&[u8]; 16] = [
        b" ", b" ", b" ", b", ", b". ", b"\n", b" the ", b" of ", b"ing ", b"=\"", b"\">", b"'", b"(", b". The ",
        b" and ", b"ed ",
    ];
    let local: Vec<Vec<u8>> = (0..64).map(|_| words[rng.below(words.len() as u64) as usize].clone()).collect();
    while out.len() < len {
        let w = if rng.chance(1, 2) { &local[rng.below(64) as usize] } else { &words[rng.below(words.len() as u64) as usize] };
        match rng.below(10) {
            0 => {
                let mut c = w.clone();
                c[0] = c[0].to_ascii_uppercase();
                out.extend_from_slice(&c);
            }
            1 => out.extend(w.iter().map(|c| c.to_ascii_uppercase())),
            2 => {
                out.extend_from_slice(&w[..w.len() - 1 - rng.below(3).min(w.len() as u64 - 2) as usize]);
            }
            _ => out.extend_from_slice(w),
        }
        out.extend_from_slice(suffixes[rng.below(16) as usize]);
    }
    out.truncate(len);
    out
}

fn gen_base64(rng: &mut Rng, len: usize) -> Vec<u8> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(len + 256);
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    while out.len() < len {
        match rng.below(6) {
            0 | 1 => {
                out.extend_from_slice(b"<img src=\"data:image/png;base64,");
                let blob = if !blobs.is_empty() && rng.chance(1, 3) {
                    blobs[rng.below(blobs.len() as u64) as usize].clone()
                } else {
                    let hi = if rng.chance(1, 4) { 6000 } else { 400 };
                    let n = rng.range(0, hi) as usize;
                    let mut b: Vec<u8> = (0..n).map(|_| ALPHA[rng.below(64) as usize]).collect();
                    for _ in 0..rng.below(3) {
                        b.push(b'=');
                    }
                    if rng.chance(1, 8) {
                        b.push(b'=');
                        b.push(ALPHA[rng.below(64) as usize]);
                    }
                    blobs.push(b.clone());
                    b
                };
                out.extend_from_slice(&blob);
                out.extend_from_slice(b"\">");
            }
            2 => out.extend_from_slice(b";base64"),
            3 => out.extend_from_slice(b";base64,;base64,"),
            _ => {
                let n = rng.range(1, 200) as usize;
                for _ in 0..n {
                    out.push(b"abc <>;=\n"[rng.below(9) as usize]);
                }
            }
        }
    }
    out.truncate(len);
    out
}

fn gen_data(rng: &mut Rng, len: usize, words: &[Vec<u8>]) -> Vec<u8> {
    match rng.below(9) {
        0 => (0..len).map(|_| rng.next() as u8).collect(),
        1 => gen_text(rng, len, words),
        2 => {
            // Highly repetitive with mutations.
            let plen = rng.range(1, 40) as usize;
            let pat: Vec<u8> = (0..plen).map(|_| rng.next() as u8).collect();
            let mut v: Vec<u8> = (0..len).map(|i| pat[i % plen]).collect();
            for _ in 0..rng.below(len as u64 / 50 + 1) {
                let i = rng.below(len as u64) as usize;
                v[i] = rng.next() as u8;
            }
            v
        }
        3 => gen_base64(rng, len),
        4 => {
            // Binary structured.
            let mut v = Vec::with_capacity(len + 8);
            let mut x = rng.next() as u32;
            while v.len() < len {
                x = x.wrapping_add(rng.below(5) as u32);
                v.extend_from_slice(&x.to_le_bytes());
            }
            v.truncate(len);
            v
        }
        5 => {
            // Small alphabet.
            let k = rng.range(1, 4);
            (0..len).map(|_| b'a' + rng.below(k) as u8).collect()
        }
        6 => {
            // Long copies of earlier chunks (long matches, > MAX_ZOPFLI_LEN).
            let mut v: Vec<u8> = Vec::with_capacity(len);
            while v.len() < len {
                if v.len() > 100 && rng.chance(1, 2) {
                    let start = rng.below(v.len() as u64) as usize;
                    let n = rng.range(1, 3000) as usize;
                    for i in 0..n {
                        let c = v[start + (i % (v.len() - start))];
                        v.push(c);
                    }
                } else {
                    let n = rng.range(1, 500) as usize;
                    for _ in 0..n {
                        v.push(rng.next() as u8);
                    }
                }
            }
            v.truncate(len);
            v
        }
        7 => {
            let mut v = gen_text(rng, len, words);
            let b = gen_base64(rng, len);
            for i in 0..len {
                if (i / 1000) % 2 == 1 {
                    v[i] = b[i];
                }
            }
            v
        }
        _ => {
            // Zeros with sparse noise.
            let mut v = vec![0u8; len];
            for _ in 0..rng.below(len as u64 / 10 + 1) {
                let i = rng.below(len as u64) as usize;
                v[i] = rng.next() as u8;
            }
            v
        }
    }
}

/* ------------------------------- Sessions -------------------------------- */

use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics: nanoseconds spent in C / Rust processing, per hasher type
/// session counts, and counts of special paths.
static C_NANOS: AtomicU64 = AtomicU64::new(0);
static R_NANOS: AtomicU64 = AtomicU64::new(0);
#[allow(clippy::declare_interior_mutable_const)]
const ATOMIC_ZERO: AtomicU64 = AtomicU64::new(0);
static TYPE_COUNTS: [AtomicU64; 70] = [ATOMIC_ZERO; 70];
static WRAPS: AtomicU64 = AtomicU64::new(0);
static B64_SESSIONS: AtomicU64 = AtomicU64::new(0);
static COMPOUND_SESSIONS: AtomicU64 = AtomicU64::new(0);

fn print_stats() {
    let mut types = Vec::new();
    for (i, c) in TYPE_COUNTS.iter().enumerate() {
        let v = c.load(Ordering::Relaxed);
        if v != 0 {
            types.push(format!("H{}:{}", i, v));
        }
    }
    eprintln!(
        "stats: C {:.3}s, Rust {:.3}s; types [{}]; wraps {}; sessions with base64 regions {}; with compound dict {}",
        C_NANOS.load(Ordering::Relaxed) as f64 * 1e-9,
        R_NANOS.load(Ordering::Relaxed) as f64 * 1e-9,
        types.join(" "),
        WRAPS.load(Ordering::Relaxed),
        B64_SESSIONS.load(Ordering::Relaxed),
        COMPOUND_SESSIONS.load(Ordering::Relaxed),
    );
}

#[derive(Clone, Debug)]
struct Config {
    quality: i32,
    lgwin: i32,
    lgblock: i32,
    mode: i32,
    size_hint: usize,
    large_window: bool,
    stream_offset: usize,
    base64_mode: i32,
    max_base64_regions: usize,
    min_base64_region_len: usize,
    simd_hasher: i32,
    hasher_opt: bool,
    npostfix: i32,
    ndirect: i32,
    initial_pos: u64,
    /// C allocator: 0 = malloc, 1 = calloc, 2 = poisoned malloc.
    zero_alloc: i32,
    /// Compound dictionary chunks (as ranges of the input, or random).
    dicts: Vec<Vec<u8>>,
}

struct CSess(*mut c_void);

impl Drop for CSess {
    fn drop(&mut self) {
        unsafe { hashshim_destroy(self.0) }
    }
}

struct RSess {
    m: Allocator,
    params: BrotliEncoderParams,
    rb: RingBuffer,
    hasher: Hasher,
    dist_cache: [i32; 16],
    saved_dist_cache: [i32; 4],
    last_insert_len: usize,
    commands: Vec<Command>,
    num_commands: usize,
    num_literals: usize,
    input_pos: u64,
    last_processed_pos: u64,
    // Keep the prepared dictionaries (and their sources) alive.
    _prepared: Vec<Box<PreparedDictionary>>,
    _sources: Vec<Vec<u8>>,
}

fn wrap_position(position: u64) -> u32 {
    let mut result = position as u32;
    let gb = position >> 30;
    if gb > 2 {
        // Wrap every 2GiB; The first 3GB are continuous.
        result = (result & ((1u32 << 30) - 1)) | ((((gb - 1) & 1) as u32) + 1) << 30;
    }
    result
}

impl RSess {
    fn new(cfg: &Config, cp: &HsParamsOut) -> RSess {
        let params = BrotliEncoderParams {
            mode: cfg.mode as u32,
            quality: cp.quality,
            lgwin: cp.lgwin,
            lgblock: cp.lgblock,
            stream_offset: cp.stream_offset,
            size_hint: cfg.size_hint,
            disable_literal_context_modeling: false,
            large_window: cp.large_window != 0,
            hasher: BrotliHasherParams::default(),
            dist: cp.dist,
            dictionary: SharedEncoderDictionary::new(),
            base64_mode: cfg.base64_mode,
            max_base64_regions: cfg.max_base64_regions,
            min_base64_region_len: cfg.min_base64_region_len,
            simd_hasher: cfg.simd_hasher as u32,
            hasher_opt: cfg.hasher_opt,
        };
        let mut rb = RingBuffer::new();
        rb.setup(&params);
        let mut dist_cache = [0i32; 16];
        dist_cache[..4].copy_from_slice(&[4, 11, 15, 16]);
        if cp.stream_offset != 0 {
            dist_cache[..4].copy_from_slice(&[-16, -16, -16, -16]);
        }
        let mut saved = [0i32; 4];
        saved.copy_from_slice(&dist_cache[..4]);
        if cfg.initial_pos != 0 {
            rb.pos_ = if cfg.initial_pos < (1u64 << 31) {
                cfg.initial_pos as u32
            } else {
                (cfg.initial_pos as u32 & 0x7FFFFFFF) | 0x80000000
            };
        }
        let mut s = RSess {
            m: Allocator::default(),
            params,
            rb,
            hasher: Hasher::new(),
            dist_cache,
            saved_dist_cache: saved,
            last_insert_len: 0,
            commands: Vec::new(),
            num_commands: 0,
            num_literals: 0,
            input_pos: cfg.initial_pos,
            last_processed_pos: cfg.initial_pos,
            _prepared: Vec::new(),
            _sources: Vec::new(),
        };
        for d in &cfg.dicts {
            let src = d.clone();
            if let Some(p) = create_prepared_dictionary(&s.m, &src) {
                let p = Box::new(p);
                let ok = unsafe { s.params.dictionary.compound.attach(&p) };
                if ok {
                    s._prepared.push(p);
                    s._sources.push(src);
                }
            }
        }
        s
    }

    fn extend_last_command(&mut self, bytes: &mut u32, wrapped_last_processed_pos: &mut u32) {
        let data = self.rb.buffer();
        let mask = self.rb.mask_;
        let params = &self.params;
        let last_command = &mut self.commands[self.num_commands - 1];
        let max_backward_distance: u64 = (1u64 << params.lgwin) - 16;
        let last_copy_len: u64 = (last_command.copy_len_ & 0x1FFFFFF) as u64;
        let last_processed_pos: u64 = self.last_processed_pos - last_copy_len;
        let max_distance: u64 =
            if last_processed_pos < max_backward_distance { last_processed_pos } else { max_backward_distance };
        let cmd_dist: u64 = self.dist_cache[0] as i64 as u64;
        let distance_code: u32 = last_command.restore_distance_code(&params.dist);
        let dict = &params.dictionary.compound;
        let compound_dictionary_size = dict.total_size;
        if distance_code < 16 || (distance_code - 15) as u64 == cmd_dist {
            if cmd_dist <= max_distance {
                while *bytes != 0
                    && data[(*wrapped_last_processed_pos & mask) as usize]
                        == data[((*wrapped_last_processed_pos as u64).wrapping_sub(cmd_dist) as u32 & mask) as usize]
                {
                    last_command.copy_len_ += 1;
                    *bytes -= 1;
                    *wrapped_last_processed_pos += 1;
                }
            } else if (cmd_dist - max_distance - 1) < compound_dictionary_size as u64
                && last_copy_len < cmd_dist - max_distance
            {
                let address =
                    compound_dictionary_size - (cmd_dist - max_distance) as usize + last_copy_len as usize;
                let mut br_index = 0usize;
                while address >= dict.chunk_offsets[br_index + 1] {
                    br_index += 1;
                }
                let mut br_offset = address - dict.chunk_offsets[br_index];
                let mut chunk = dict.chunk_source(br_index);
                let mut chunk_length = dict.chunk_offsets[br_index + 1] - dict.chunk_offsets[br_index];
                while *bytes != 0 && data[(*wrapped_last_processed_pos & mask) as usize] == chunk[br_offset] {
                    last_command.copy_len_ += 1;
                    *bytes -= 1;
                    *wrapped_last_processed_pos += 1;
                    br_offset += 1;
                    if br_offset == chunk_length {
                        br_index += 1;
                        br_offset = 0;
                        if br_index != dict.num_chunks {
                            chunk = dict.chunk_source(br_index);
                            chunk_length = dict.chunk_offsets[br_index + 1] - dict.chunk_offsets[br_index];
                        } else {
                            break;
                        }
                    }
                }
            }
            // The copy length is at most the metablock size, and thus
            // expressible.
            last_command.cmd_prefix_ = get_length_code(
                last_command.insert_len_ as usize,
                ((last_command.copy_len_ & 0x1FFFFFF) as i32 + (last_command.copy_len_ >> 25) as i32) as usize,
                (last_command.dist_prefix_ & 0x3FF) == 0,
            );
        }
    }

    fn process(&mut self, input: &[u8], is_last: bool) {
        let n = input.len();
        if n > 0 {
            self.rb.write(&self.m, input);
            self.input_pos += n as u64;
            if self.rb.pos_ <= self.rb.mask_ {
                let p = self.rb.pos_ as usize;
                self.rb.buffer_mut()[p..p + 7].fill(0);
            }
        }
        let delta = self.input_pos - self.last_processed_pos;
        let mut bytes = delta as u32;
        let mut wrapped_last_processed_pos = wrap_position(self.last_processed_pos);
        if !self.rb.is_allocated() {
            return;
        }
        let mask = self.rb.mask_ as usize;
        {
            let newsize = self.num_commands + bytes as usize / 2 + 1;
            if newsize > self.commands.len() {
                let newsize = newsize + bytes as usize / 4 + 16;
                self.commands.resize(newsize, Command::default());
            }
        }
        init_or_stitch_to_previous_block(
            &self.m,
            &mut self.hasher,
            self.rb.buffer(),
            mask,
            &mut self.params,
            wrapped_last_processed_pos as usize,
            bytes as usize,
            is_last,
        );
        if self.num_commands != 0 && self.last_insert_len == 0 {
            self.extend_last_command(&mut bytes, &mut wrapped_last_processed_pos);
        }
        let lut = brotli_context_lut(ContextType::Utf8);
        let data = self.rb.buffer();
        let commands = &mut self.commands[self.num_commands..];
        if self.params.quality == 10 {
            brotli_create_zopfli_backward_references(
                &self.m,
                bytes as usize,
                wrapped_last_processed_pos as usize,
                data,
                mask,
                lut,
                &self.params,
                &mut self.hasher,
                &mut self.dist_cache,
                &mut self.last_insert_len,
                commands,
                &mut self.num_commands,
                &mut self.num_literals,
            );
        } else if self.params.quality == 11 {
            brotli_create_hq_zopfli_backward_references(
                &self.m,
                bytes as usize,
                wrapped_last_processed_pos as usize,
                data,
                mask,
                lut,
                &self.params,
                &mut self.hasher,
                &mut self.dist_cache,
                &mut self.last_insert_len,
                commands,
                &mut self.num_commands,
                &mut self.num_literals,
            );
        } else {
            brotli_create_backward_references(
                bytes as usize,
                wrapped_last_processed_pos as usize,
                data,
                mask,
                lut,
                &self.params,
                &mut self.hasher,
                &mut self.dist_cache,
                &mut self.last_insert_len,
                commands,
                &mut self.num_commands,
                &mut self.num_literals,
            );
        }
    }

    fn flush(&mut self, restore: bool) {
        if self.last_insert_len > 0 {
            self.commands[self.num_commands] = Command::new_insert(self.last_insert_len);
            self.num_commands += 1;
            self.num_literals += self.last_insert_len;
            self.last_insert_len = 0;
        }
        if restore {
            self.dist_cache[..4].copy_from_slice(&self.saved_dist_cache);
        }
        self.hasher.common.num_base64_regions = 0;
        self.num_commands = 0;
        self.num_literals = 0;
        self.saved_dist_cache.copy_from_slice(&self.dist_cache[..4]);
    }

    fn update_last_processed_pos(&mut self) -> bool {
        let a = wrap_position(self.last_processed_pos);
        let b = wrap_position(self.input_pos);
        self.last_processed_pos = self.input_pos;
        if b < a {
            self.hasher.reset();
            true
        } else {
            false
        }
    }
}

fn compare(c: &CSess, r: &RSess, what: &str) -> Result<(), String> {
    unsafe {
        let s = c.0;
        let nc = hashshim_num_commands(s);
        if nc != r.num_commands {
            return Err(format!("{}: num_commands C={} R={}", what, nc, r.num_commands));
        }
        if nc > 0 {
            let cc = std::slice::from_raw_parts(hashshim_commands(s), nc);
            for i in 0..nc {
                if cc[i] != r.commands[i] {
                    return Err(format!("{}: command {} differs: C={:?} R={:?}", what, i, cc[i], r.commands[i]));
                }
            }
        }
        let nl = hashshim_num_literals(s);
        if nl != r.num_literals {
            return Err(format!("{}: num_literals C={} R={}", what, nl, r.num_literals));
        }
        let li = hashshim_last_insert_len(s);
        if li != r.last_insert_len {
            return Err(format!("{}: last_insert_len C={} R={}", what, li, r.last_insert_len));
        }
        let dc = std::slice::from_raw_parts(hashshim_dist_cache(s), 16);
        if dc != &r.dist_cache[..] {
            return Err(format!("{}: dist_cache C={:?} R={:?}", what, dc, r.dist_cache));
        }
        let ht = hashshim_hasher_type(s);
        if ht != r.params.hasher.type_ {
            return Err(format!("{}: hasher type C={} R={}", what, ht, r.params.hasher.type_));
        }
        let nb = hashshim_num_base64_regions(s);
        if nb != r.hasher.common.num_base64_regions {
            return Err(format!("{}: num_base64_regions C={} R={}", what, nb, r.hasher.common.num_base64_regions));
        }
        if nb > 0 {
            let cb = std::slice::from_raw_parts(hashshim_base64_regions(s), nb);
            if cb != &r.hasher.common.base64_regions[..nb] {
                return Err(format!("{}: base64 regions differ", what));
            }
        }
        let a = hashshim_dict_num_lookups(s);
        let b = hashshim_dict_num_matches(s);
        if a != r.hasher.common.dict_num_lookups || b != r.hasher.common.dict_num_matches {
            return Err(format!(
                "{}: dict stats C=({}, {}) R=({}, {})",
                what, a, b, r.hasher.common.dict_num_lookups, r.hasher.common.dict_num_matches
            ));
        }
    }
    Ok(())
}

/// Runs one session on both sides; `blocks` are the block lengths, and
/// `flushes[i]` tells whether to end the metablock after block i.
fn run_session(cfg: &Config, input: &[u8], rng: &mut Rng) -> Result<(usize, usize), String> {
    let c = unsafe {
        CSess(hashshim_create(
            cfg.quality,
            cfg.lgwin,
            cfg.lgblock,
            cfg.mode,
            cfg.size_hint,
            cfg.large_window as i32,
            cfg.stream_offset,
            cfg.base64_mode,
            cfg.max_base64_regions,
            cfg.min_base64_region_len,
            cfg.simd_hasher,
            cfg.hasher_opt as i32,
            cfg.npostfix,
            cfg.ndirect,
            cfg.initial_pos,
            cfg.zero_alloc,
        ))
    };
    let mut cp = HsParamsOut::default();
    unsafe { hashshim_get_params(c.0, &mut cp) };
    let mut r = RSess::new(cfg, &cp);
    let mut attached = 0;
    for d in &cfg.dicts {
        let ok = unsafe { hashshim_attach(c.0, d.as_ptr(), d.len()) };
        attached += ok as usize;
    }
    if attached != r._prepared.len() {
        return Err(format!("attach mismatch C={} R={}", attached, r._prepared.len()));
    }
    let block_size = 1usize << cp.lgblock;
    let mut pos = 0usize;
    let mut total_commands = 0usize;
    let mut calls = 0usize;
    let mut saw_b64 = false;
    loop {
        let remaining = input.len() - pos;
        let n = if rng.chance(1, 3) {
            remaining.min(block_size)
        } else {
            remaining.min(rng.range(0, block_size as u64) as usize)
        };
        let is_last = pos + n == input.len() && (rng.chance(3, 4) || n == 0);
        let chunk = &input[pos..pos + n];
        pos += n;
        if n == 0 && !is_last && !rng.chance(1, 4) {
            continue;
        }
        let t0 = std::time::Instant::now();
        let ok = unsafe { hashshim_process(c.0, chunk.as_ptr(), n, is_last as i32) };
        let t1 = std::time::Instant::now();
        if ok == 0 {
            return Err("hs_process failed".into());
        }
        r.process(chunk, is_last);
        let t2 = std::time::Instant::now();
        C_NANOS.fetch_add((t1 - t0).as_nanos() as u64, Ordering::Relaxed);
        R_NANOS.fetch_add((t2 - t1).as_nanos() as u64, Ordering::Relaxed);
        if r.hasher.common.num_base64_regions > 0 {
            saw_b64 = true;
        }
        calls += 1;
        compare(&c, &r, &format!("after block {} (pos {}, n {})", calls, pos, n))?;
        total_commands += r.num_commands;
        let flush = is_last || rng.chance(1, 3);
        if flush {
            let restore = rng.chance(1, 6);
            unsafe { hashshim_flush(c.0, restore as i32) };
            r.flush(restore);
            compare(&c, &r, &format!("after flush {}", calls))?;
        }
        let wc = unsafe { hashshim_update_last_processed_pos(c.0) } != 0;
        let wr = r.update_last_processed_pos();
        if wc != wr {
            return Err("wrap mismatch".into());
        }
        if wc {
            WRAPS.fetch_add(1, Ordering::Relaxed);
        }
        if is_last {
            break;
        }
    }
    let t = r.params.hasher.type_;
    if (0..70).contains(&t) && calls > 0 {
        TYPE_COUNTS[t as usize].fetch_add(1, Ordering::Relaxed);
    }
    if saw_b64 {
        B64_SESSIONS.fetch_add(1, Ordering::Relaxed);
    }
    if !r._prepared.is_empty() {
        COMPOUND_SESSIONS.fetch_add(1, Ordering::Relaxed);
    }
    Ok((calls, total_commands))
}

fn random_config(rng: &mut Rng, input: &[u8], max_len: usize) -> Config {
    let quality = rng.range(2, 11) as i32;
    let large = rng.chance(1, 6);
    let lgwin = if large { rng.range(25, 30) as i32 } else { rng.range(10, 24) as i32 };
    let lgblock = if rng.chance(1, 2) { 0 } else { rng.range(16, 24) as i32 };
    let size_hint = match rng.below(4) {
        0 => 0,
        1 => rng.below(1 << 22) as usize,
        2 => (1 << 20) + rng.below(1 << 22) as usize,
        _ => max_len,
    };
    let stream_offset = match rng.below(10) {
        0 | 1 => rng.range(1, 1 << 20) as usize,
        2 => rng.range(1, 1 << 31) as usize,
        _ => 0,
    };
    let base64_mode = rng.chance(1, 3) as i32;
    let max_base64_regions = if rng.chance(1, 5) { 0 } else { rng.range(1, 16) as usize };
    let min_base64_region_len = match rng.below(3) {
        0 => 2048,
        1 => rng.below(64) as usize,
        _ => rng.below(1000) as usize,
    };
    let mut dicts = Vec::new();
    if rng.chance(1, 4) {
        let many = rng.chance(1, 8);
        let count = if many { rng.range(4, 16) } else { rng.range(1, 3) };
        for _ in 0..count {
            let len = if many {
                rng.range(0, 3000) as usize
            } else if rng.chance(1, 20) {
                rng.range(2 << 20, 3 << 20) as usize
            } else {
                rng.range(0, 80_000) as usize
            };
            let d: Vec<u8> = if !input.is_empty() && rng.chance(2, 3) {
                let start = rng.below(input.len() as u64) as usize;
                let mut v: Vec<u8> = input[start..(start + len).min(input.len())].to_vec();
                if rng.chance(1, 2) {
                    for _ in 0..rng.below(v.len() as u64 / 20 + 1) {
                        let i = rng.below(v.len() as u64) as usize;
                        v[i] = rng.next() as u8;
                    }
                }
                v
            } else {
                (0..len).map(|_| rng.next() as u8).collect()
            };
            dicts.push(d);
        }
    }
    let initial_pos = if !large && lgwin <= 24 && rng.chance(1, 8) {
        match rng.below(5) {
            0 => (3u64 << 30) - rng.below(1 << 21),
            1 => (1u64 << 31) - rng.below(1 << 21),
            2 => (5u64 << 30) - rng.below(1 << 21),
            3 => (1u64 << 32) - rng.below(1 << 21),
            _ => rng.range(1, 1 << 24),
        }
    } else {
        0
    };
    Config {
        quality,
        lgwin,
        lgblock,
        mode: rng.below(3) as i32,
        size_hint,
        large_window: large,
        stream_offset,
        base64_mode,
        max_base64_regions,
        min_base64_region_len,
        simd_hasher: rng.below(3) as i32,
        hasher_opt: rng.chance(1, 2),
        npostfix: if rng.chance(1, 2) { 0 } else { rng.range(0, 4) as i32 },
        ndirect: if rng.chance(1, 2) { 0 } else { (rng.range(0, 15) << rng.range(0, 3)) as i32 },
        initial_pos,
        zero_alloc: if initial_pos != 0 { 1 } else { rng.below(3) as i32 },
        dicts,
    }
}

fn input_len(rng: &mut Rng, quality: i32, big: bool) -> usize {
    let cap = if quality >= 10 { 300_000 } else { 1_500_000 };
    match rng.below(6) {
        0 => rng.below(64) as usize,
        1 => rng.below(2000) as usize,
        2 => rng.below(70_000) as usize,
        3 if big => rng.below(cap as u64) as usize,
        _ => rng.below(200_000.min(cap) as u64) as usize,
    }
}

fn run_random(seed: u64, words: &[Vec<u8>], big: bool) -> Result<(usize, usize), String> {
    let mut rng = Rng::new(seed);
    let q_probe = rng.range(2, 11) as i32;
    let len = input_len(&mut rng, q_probe, big);
    let input = gen_data(&mut rng, len, words);
    let mut cfg = random_config(&mut rng, &input, len);
    cfg.quality = q_probe;
    if cfg.large_window && cfg.lgwin > 26 && input.len() >= (1 << 16) {
        // The Rust ring buffer zero-fills its (up to 2 GiB) allocation;
        // keep the very large windows to single-block inputs.
        cfg.lgwin = 26;
    }
    run_session(&cfg, &input, &mut rng).map_err(|e| format!("seed {}: {:?} len {}: {}", seed, cfg_summary(&cfg), len, e))
}

fn cfg_summary(cfg: &Config) -> String {
    format!(
        "q{} w{} b{} mode{} hint{} lw{} so{} b64({},{},{}) simd{} opt{} np{} nd{} ipos{} dicts{:?}",
        cfg.quality,
        cfg.lgwin,
        cfg.lgblock,
        cfg.mode,
        cfg.size_hint,
        cfg.large_window,
        cfg.stream_offset,
        cfg.base64_mode,
        cfg.max_base64_regions,
        cfg.min_base64_region_len,
        cfg.simd_hasher,
        cfg.hasher_opt,
        cfg.npostfix,
        cfg.ndirect,
        cfg.initial_pos,
        cfg.dicts.iter().map(|d| d.len()).collect::<Vec<_>>()
    )
}

/* --------------------------------- Tests --------------------------------- */

#[test]
fn hasher_size_matches_c() {
    let mut rng = Rng::new(7);
    let sizes = [0usize, 1, 100, 1000, 65535, 65536, 1 << 20, (1 << 20) + 1, 5 << 20, 100 << 20];
    for quality in 0..=11 {
        for lgwin in 10..=30 {
            for &size_hint in sizes.iter() {
                for simd in 0..3 {
                    for opt in 0..2 {
                        for one_shot in 0..2 {
                            let input_size = if rng.chance(1, 2) { size_hint } else { rng.below(1 << 26) as usize };
                            let mut c_out = [0usize; 4];
                            let ct = unsafe {
                                hashshim_hasher_size(quality, lgwin, size_hint, simd, opt, one_shot, input_size, c_out.as_mut_ptr())
                            };
                            let mut params = BrotliEncoderParams {
                                mode: 0,
                                quality,
                                lgwin,
                                lgblock: 0,
                                stream_offset: 0,
                                size_hint,
                                disable_literal_context_modeling: false,
                                large_window: lgwin > 24,
                                hasher: BrotliHasherParams::default(),
                                dist: BrotliDistanceParams::default(),
                                dictionary: SharedEncoderDictionary::new(),
                                base64_mode: 0,
                                max_base64_regions: 16,
                                min_base64_region_len: 2048,
                                simd_hasher: simd as u32,
                                hasher_opt: opt != 0,
                            };
                            sanitize_params(&mut params);
                            params.lgblock = compute_lg_block(&params);
                            let mut hp = params.hasher;
                            choose_hasher(&params, &mut hp);
                            params.hasher = hp;
                            assert_eq!(ct, params.hasher.type_, "type q{} w{} hint{}", quality, lgwin, size_hint);
                            let mut r_out = [0usize; 4];
                            hasher_size(&params, one_shot != 0, input_size, &mut r_out);
                            assert_eq!(c_out, r_out, "q{} w{} hint{} simd{} opt{} one_shot{} in{} type{}", quality, lgwin, size_hint, simd, opt, one_shot, input_size, ct);
                        }
                    }
                }
            }
        }
    }
    // Every hasher type directly.
    for t in [2, 3, 4, 5, 6, 10, 35, 40, 41, 42, 54, 55, 58, 59, 65, 68, 0, 1, 7] {
        let mut params = BrotliEncoderParams {
            mode: 0,
            quality: 9,
            lgwin: 22,
            lgblock: 0,
            stream_offset: 0,
            size_hint: 0,
            disable_literal_context_modeling: false,
            large_window: false,
            hasher: BrotliHasherParams { type_: t, bucket_bits: 15, block_bits: 6, num_last_distances_to_check: 16 },
            dist: BrotliDistanceParams::default(),
            dictionary: SharedEncoderDictionary::new(),
            base64_mode: 0,
            max_base64_regions: 16,
            min_base64_region_len: 2048,
            simd_hasher: 0,
            hasher_opt: false,
        };
        let mut out = [0usize; 4];
        hasher_size(&params, false, 1000, &mut out);
        let simd = t == 58 || t == 59 || t == 68;
        if t == 0 || t == 1 || t == 7 || (simd && !brotli::enc::quality::HAVE_SIMD_HASHERS) {
            // No such hasher (the SIMD hashers only exist on 64-bit targets,
            // like BROTLI_MAX_SIMD_QUALITY in C).
            assert_eq!(out, [0; 4]);
        } else {
            assert!(out[0] > 0, "type {}", t);
        }
        params.lgwin = 10;
        hasher_size(&params, true, 10, &mut out);
    }
}

#[test]
fn matching_tag_mask_matches_c() {
    let mut rng = Rng::new(11);
    let mut bucket = [0u8; 64 + 8];
    for _ in 0..200_000 {
        let chunk_count = [1usize, 2, 4][rng.below(3) as usize];
        let tag = if rng.chance(1, 2) { rng.below(4) as u8 } else { rng.next() as u8 };
        for b in bucket.iter_mut() {
            *b = if rng.chance(1, 2) { rng.below(4) as u8 } else { rng.next() as u8 };
        }
        let head = rng.below(64) as usize & (chunk_count * 16 - 1);
        let c = unsafe { hashshim_matching_tag_mask(chunk_count, tag, bucket.as_ptr(), head) };
        let r = get_matching_tag_mask(chunk_count, tag, &bucket, head);
        assert_eq!(c, r);
        // Semantics check against a naive implementation.
        let w = 16 * chunk_count;
        let mut naive = 0u64;
        for k in 0..w {
            if bucket[(head + k) % w] == tag {
                naive |= 1 << k;
            }
        }
        assert_eq!(r, naive);
    }
}

#[test]
fn static_dictionary_matches_c() {
    let words = dictionary_words();
    let mut rng = Rng::new(3);
    for iter in 0..20_000 {
        let text = if iter % 3 == 0 { gen_data(&mut rng, 64, &words) } else { gen_text(&mut rng, 64, &words) };
        let mut buf = text.clone();
        buf.extend_from_slice(&[0u8; 8]);
        for start in (0..32).step_by(1 + (iter % 5)) {
            let data = &buf[start..];
            let max_length = rng.range(1, 64 - start as u64) as usize;
            let min_length = rng.range(0, 10) as usize;
            let mut cm = [K_INVALID_MATCH; 38];
            let mut rm = [K_INVALID_MATCH; 38];
            let cf = unsafe { hashshim_static_dict_matches(data.as_ptr(), min_length, max_length, cm.as_mut_ptr()) };
            let rf = brotli_find_all_static_dictionary_matches(&DEFAULT_ENCODER_DICTIONARY, data, min_length, max_length, &mut rm);
            assert_eq!(cf != 0, rf, "found flag, iter {}", iter);
            assert_eq!(cm, rm, "iter {} start {}", iter, start);
        }
    }
}

/// Deterministic matrix: every quality / hasher type with a few inputs.
#[test]
fn matrix_sessions() {
    let words = dictionary_words();
    let mut rng = Rng::new(1);
    let inputs: Vec<Vec<u8>> = vec![
        gen_text(&mut rng, 300_000, &words),
        gen_base64(&mut rng, 100_000),
        (0..200_000u32).map(|i| ((i * 7) % 251) as u8 ^ (i >> 9) as u8).collect(),
        (0..50_000).map(|_| rng.next() as u8).collect(),
        vec![b'a'; 70_000],
        gen_text(&mut rng, 1000, &words),
        Vec::new(),
        vec![1, 2, 3],
    ];
    let mut n = 0;
    for quality in 2..=11 {
        for &(lgwin, size_hint, simd, opt, large) in &[
            (22, 0usize, 0, false, false),
            (16, 0, 0, false, false),
            (20, 2 << 20, 0, false, false),
            (22, 0, 1, false, false),
            (22, 0, 1, true, false),
            (22, 2 << 20, 1, false, false),
            (22, 0, 2, false, false),
            (26, 2 << 20, 0, false, true),
            (26, 0, 0, false, true),
            (12, 0, 0, false, false),
        ] {
            for (k, input) in inputs.iter().enumerate() {
                if quality >= 10 && input.len() > 100_000 && k % 2 == 1 {
                    continue;
                }
                let cfg = Config {
                    quality,
                    lgwin,
                    lgblock: 0,
                    mode: (k % 3) as i32,
                    size_hint,
                    large_window: large,
                    stream_offset: if k == 2 { 12345 } else { 0 },
                    base64_mode: (k % 2) as i32,
                    max_base64_regions: 16,
                    min_base64_region_len: if k == 1 { 100 } else { 2048 },
                    simd_hasher: simd,
                    hasher_opt: opt,
                    npostfix: 1,
                    ndirect: 4,
                    initial_pos: 0,
                    zero_alloc: 2,
                    dicts: if k == 0 { vec![inputs[0][1000..30000].to_vec()] } else { Vec::new() },
                };
                let mut srng = Rng::new(n as u64);
                let t0 = std::time::Instant::now();
                let res = run_session(&cfg, input, &mut srng);
                if std::env::var("HASH_VERBOSE").is_ok() {
                    eprintln!("{} input {} ({} bytes): {:?} in {:?}", cfg_summary(&cfg), k, input.len(), res.as_ref().map(|_| ()), t0.elapsed());
                }
                if let Err(e) = res {
                    panic!("{} input {}: {}", cfg_summary(&cfg), k, e);
                }
                n += 1;
            }
        }
    }
    print_stats();
}

#[test]
fn randomized_sessions() {
    let words = dictionary_words();
    let secs: u64 = std::env::var("HASH_FUZZ_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let base: u64 = std::env::var("HASH_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1000);
    let start = std::time::Instant::now();
    let mut iters = 0u64;
    let mut calls = 0usize;
    let mut cmds = 0usize;
    while start.elapsed().as_secs() < secs || iters < 20 {
        let seed = base + iters;
        match run_random(seed, &words, iters % 4 == 0) {
            Ok((c, n)) => {
                calls += c;
                cmds += n;
            }
            Err(e) => panic!("{}", e),
        }
        iters += 1;
    }
    eprintln!("randomized_sessions: {} sessions, {} blocks, {} commands clean", iters, calls, cmds);
    print_stats();
}

#[test]
fn c_reference_linked() {
    // Keep the cref module (and thus the C library) linked.
    let data = b"hello hello hello hello";
    assert!(cref::compress(5, 22, 0, data).is_some());
}

/// Speed comparison per quality (run with `--ignored --nocapture`).
#[test]
#[ignore]
fn bench_qualities() {
    let words = dictionary_words();
    let mut rng = Rng::new(99);
    let text = gen_text(&mut rng, 4 << 20, &words);
    let bin: Vec<u8> = gen_data(&mut Rng::new(5), 4 << 20, &words);
    for (name, input) in [("text", &text), ("mixed", &bin)] {
        for quality in 2..=11 {
            for &(lgwin, hint, simd) in &[(22, 0usize, 0), (22, 8usize << 20, 0), (16, 0, 0), (22, 0, 1), (26, 8 << 20, 0)] {
                let len = if quality >= 10 { input.len() / 4 } else { input.len() };
                let cfg = Config {
                    quality,
                    lgwin,
                    lgblock: 0,
                    mode: 0,
                    size_hint: hint,
                    large_window: lgwin > 24,
                    stream_offset: 0,
                    base64_mode: 0,
                    max_base64_regions: 16,
                    min_base64_region_len: 2048,
                    simd_hasher: simd,
                    hasher_opt: false,
                    npostfix: 0,
                    ndirect: 0,
                    initial_pos: 0,
                    zero_alloc: 2,
                    dicts: Vec::new(),
                };
                let c0 = C_NANOS.load(Ordering::Relaxed);
                let r0 = R_NANOS.load(Ordering::Relaxed);
                let mut srng = Rng::new(1);
                run_session(&cfg, &input[..len], &mut srng).unwrap();
                let c = (C_NANOS.load(Ordering::Relaxed) - c0) as f64 * 1e-6;
                let r = (R_NANOS.load(Ordering::Relaxed) - r0) as f64 * 1e-6;
                eprintln!("{} q{} w{} hint{} simd{}: C {:.1}ms R {:.1}ms ratio {:.2}", name, quality, lgwin, hint, simd, c, r, r / c);
            }
        }
    }
}

/// Interleaved C / Rust timing (min over repetitions) per configuration
/// (run with `--ignored --nocapture`; `HASH_BENCH_REPS`).
#[test]
#[ignore]
fn bench_min() {
    let words = dictionary_words();
    let reps = std::env::var("HASH_BENCH_REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    let text = gen_text(&mut Rng::new(99), 2 << 20, &words);
    let mixed = gen_data(&mut Rng::new(5), 2 << 20, &words);
    let only: Option<i32> = std::env::var("HASH_BENCH_Q").ok().and_then(|s| s.parse().ok());
    for (name, input) in [("text", &text), ("mixed", &mixed)] {
        for quality in 2..=11 {
            if only.map(|q| q != quality).unwrap_or(false) {
                continue;
            }
            for &(lgwin, hint, simd) in &[(22, 0usize, 0), (22, 8usize << 20, 0), (16, 0, 0), (22, 0, 1), (26, 8 << 20, 0)] {
                if quality >= 10 && (lgwin != 22 || hint != 0 || simd != 0) {
                    continue;
                }
                let len = if quality >= 10 { input.len() / 4 } else { input.len() };
                let data = &input[..len];
                let block = 1usize << 16;
                let mut best_c = f64::MAX;
                let mut best_r = f64::MAX;
                let mut ht = 0;
                for _ in 0..reps {
                    let c = unsafe { CSess(hashshim_create(quality, lgwin, 0, 0, hint, (lgwin > 24) as i32, 0, 0, 16, 2048, simd, 0, 0, 0, 0, 0)) };
                    let mut cp = HsParamsOut::default();
                    unsafe { hashshim_get_params(c.0, &mut cp) };
                    let block = block.min(1 << cp.lgblock);
                    let t = std::time::Instant::now();
                    for (i, chunk) in data.chunks(block).enumerate() {
                        let last = (i + 1) * block >= data.len();
                        unsafe { hashshim_process(c.0, chunk.as_ptr(), chunk.len(), last as i32) };
                        unsafe { hashshim_flush(c.0, 0) };
                        unsafe { hashshim_update_last_processed_pos(c.0) };
                    }
                    best_c = best_c.min(t.elapsed().as_secs_f64());
                    let cfg = Config {
                        quality, lgwin, lgblock: 0, mode: 0, size_hint: hint, large_window: lgwin > 24,
                        stream_offset: 0, base64_mode: 0, max_base64_regions: 16, min_base64_region_len: 2048,
                        simd_hasher: simd, hasher_opt: false, npostfix: 0, ndirect: 0, initial_pos: 0,
                        zero_alloc: 2, dicts: Vec::new(),
                    };
                    let mut r = RSess::new(&cfg, &cp);
                    let t = std::time::Instant::now();
                    for (i, chunk) in data.chunks(block).enumerate() {
                        let last = (i + 1) * block >= data.len();
                        r.process(chunk, last);
                        r.flush(false);
                        r.update_last_processed_pos();
                    }
                    best_r = best_r.min(t.elapsed().as_secs_f64());
                    ht = r.params.hasher.type_;
                }
                eprintln!(
                    "{:5} q{:2} w{} hint{:8} simd{} H{:2}: C {:7.2}ms R {:7.2}ms ratio {:.2}",
                    name, quality, lgwin, hint, simd, ht, best_c * 1e3, best_r * 1e3, best_r / best_c
                );
            }
        }
    }
}

/// Single-side workload for `/usr/bin/time -l` (instructions / cycles):
/// `HASH_WORK_SIDE` (c|r), `HASH_WORK_Q`, `HASH_WORK_W`, `HASH_WORK_HINT`,
/// `HASH_WORK_SIMD`, `HASH_WORK_DATA` (text|mixed), `HASH_WORK_REPS`.
#[test]
#[ignore]
fn work_single_side() {
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let words = dictionary_words();
    let quality = env("HASH_WORK_Q", 5) as i32;
    let lgwin = env("HASH_WORK_W", 22) as i32;
    let hint = env("HASH_WORK_HINT", 0) as usize;
    let simd = env("HASH_WORK_SIMD", 0) as i32;
    let reps = env("HASH_WORK_REPS", 3);
    let side_c = std::env::var("HASH_WORK_SIDE").map(|s| s == "c").unwrap_or(false);
    let data = if std::env::var("HASH_WORK_DATA").map(|s| s == "text").unwrap_or(false) {
        gen_text(&mut Rng::new(99), 2 << 20, &words)
    } else {
        gen_data(&mut Rng::new(5), 2 << 20, &words)
    };
    let data = if quality >= 10 { &data[..data.len() / 4] } else { &data[..] };
    let block = 1usize << 16;
    for _ in 0..reps {
        let c = unsafe { CSess(hashshim_create(quality, lgwin, 0, 0, hint, (lgwin > 24) as i32, 0, 0, 16, 2048, simd, 0, 0, 0, 0, 0)) };
        let mut cp = HsParamsOut::default();
        unsafe { hashshim_get_params(c.0, &mut cp) };
        let block = block.min(1 << cp.lgblock);
        if side_c {
            for (i, chunk) in data.chunks(block).enumerate() {
                let last = (i + 1) * block >= data.len();
                unsafe { hashshim_process(c.0, chunk.as_ptr(), chunk.len(), last as i32) };
                unsafe { hashshim_flush(c.0, 0) };
                unsafe { hashshim_update_last_processed_pos(c.0) };
            }
        } else {
            let cfg = Config {
                quality, lgwin, lgblock: 0, mode: 0, size_hint: hint, large_window: lgwin > 24,
                stream_offset: 0, base64_mode: 0, max_base64_regions: 16, min_base64_region_len: 2048,
                simd_hasher: simd, hasher_opt: false, npostfix: 0, ndirect: 0, initial_pos: 0,
                zero_alloc: 2, dicts: Vec::new(),
            };
            let mut r = RSess::new(&cfg, &cp);
            for (i, chunk) in data.chunks(block).enumerate() {
                let last = (i + 1) * block >= data.len();
                r.process(chunk, last);
                r.flush(false);
                r.update_last_processed_pos();
            }
        }
    }
}

fn base_config(quality: i32, lgwin: i32) -> Config {
    Config {
        quality,
        lgwin,
        lgblock: 0,
        mode: 0,
        size_hint: 0,
        large_window: lgwin > 24,
        stream_offset: 0,
        base64_mode: 0,
        max_base64_regions: 16,
        min_base64_region_len: 2048,
        simd_hasher: 0,
        hasher_opt: false,
        npostfix: 0,
        ndirect: 0,
        initial_pos: 0,
        zero_alloc: 2,
        dicts: Vec::new(),
    }
}

/// Base64 region detection / deduplication with every non-Zopfli hasher.
#[test]
fn base64_sessions() {
    let mut n = 0u64;
    for quality in 2..=11 {
        for &(lgwin, hint, simd, opt) in &[
            (22, 0usize, 0, false),
            (16, 0, 0, false),
            (22, 2 << 20, 0, false),
            (22, 0, 1, true),
            (22, 0, 1, false),
            (22, 2 << 20, 1, false),
            (26, 2 << 20, 0, false),
            (26, 0, 0, false),
        ] {
            for min_len in [0usize, 1, 16, 300, 2048] {
                for max_regions in [1usize, 3, 16, 1 << 26] {
                    n += 1;
                    let mut rng = Rng::new(n);
                    let len = if quality >= 10 { 30_000 } else { rng.range(1000, 200_000) as usize };
                    let input = gen_base64(&mut rng, len);
                    let mut cfg = base_config(quality, lgwin);
                    cfg.size_hint = hint;
                    cfg.simd_hasher = simd;
                    cfg.hasher_opt = opt;
                    cfg.base64_mode = 1;
                    cfg.min_base64_region_len = min_len;
                    cfg.max_base64_regions = max_regions;
                    // calloc: C allocates `max_regions` entries.
                    cfg.zero_alloc = if max_regions > 1000 { 1 } else { 2 };
                    if rng.chance(1, 3) {
                        cfg.dicts.push(input[..len / 3].to_vec());
                    }
                    if let Err(e) = run_session(&cfg, &input, &mut rng) {
                        panic!("{}: {}", cfg_summary(&cfg), e);
                    }
                }
            }
        }
    }
    print_stats();
}

/// Position wrapping (WrapPosition / HasherReset) near 2, 3, 4 and 5 GiB.
#[test]
fn wrap_sessions() {
    let words = dictionary_words();
    let mut n = 0u64;
    for quality in 2..=11 {
        for &(lgwin, hint, simd, opt) in &[(22, 0usize, 0, false), (16, 0, 0, false), (22, 2 << 20, 0, false), (22, 0, 1, true), (20, 0, 0, false)] {
            for &base in &[1u64 << 31, 3u64 << 30, 1u64 << 32, 5u64 << 30, 7u64 << 30] {
                n += 1;
                let mut rng = Rng::new(n * 77);
                let len = if quality >= 10 { 200_000 } else { 600_000 };
                let input = gen_data(&mut rng, len, &words);
                let mut cfg = base_config(quality, lgwin);
                cfg.size_hint = hint;
                cfg.simd_hasher = simd;
                cfg.hasher_opt = opt;
                cfg.initial_pos = base - rng.range(1, len as u64 - 1);
                cfg.zero_alloc = 1;
                cfg.stream_offset = if rng.chance(1, 3) { 1000 } else { 0 };
                if rng.chance(1, 3) {
                    cfg.dicts.push(input[len / 2..len / 2 + 20000].to_vec());
                }
                if let Err(e) = run_session(&cfg, &input, &mut rng) {
                    panic!("{}: {}", cfg_summary(&cfg), e);
                }
            }
        }
    }
    print_stats();
    assert!(WRAPS.load(Ordering::Relaxed) > 0);
}

/// Multi-megabyte inputs (several metablocks, ring buffer wrapping).
#[test]
fn large_sessions() {
    let words = dictionary_words();
    let mut n = 0u64;
    for quality in 2..=11 {
        for &(lgwin, hint) in &[(18, 0usize), (22, 8 << 20), (24, 0)] {
            n += 1;
            let mut rng = Rng::new(n * 1313);
            let len = if quality >= 10 { 2 << 20 } else { 6 << 20 };
            let mut input = gen_text(&mut rng, len, &words);
            let other = gen_data(&mut rng, len, &words);
            for i in 0..len {
                if (i >> 18) % 3 == 1 {
                    input[i] = other[i];
                }
            }
            let mut cfg = base_config(quality, lgwin);
            cfg.size_hint = hint;
            cfg.lgblock = [0, 16, 20][(n % 3) as usize];
            if let Err(e) = run_session(&cfg, &input, &mut rng) {
                panic!("{}: {}", cfg_summary(&cfg), e);
            }
        }
    }
    print_stats();
}

/// Multi-block sessions with the largest windows (needs several GiB of
/// address space; the Rust ring buffer zero-fills up to 2 GiB).
#[test]
#[ignore]
fn huge_window_sessions() {
    let words = dictionary_words();
    for quality in 2..=11 {
        for lgwin in [27, 30] {
            let mut rng = Rng::new(quality as u64 * 100 + lgwin as u64);
            let len = if quality >= 10 { 300_000 } else { 1_000_000 };
            let input = gen_data(&mut rng, len, &words);
            let mut cfg = base_config(quality, lgwin);
            cfg.size_hint = if quality % 2 == 0 { 8 << 20 } else { 0 };
            cfg.zero_alloc = 0;
            let t = std::time::Instant::now();
            if let Err(e) = run_session(&cfg, &input, &mut rng) {
                panic!("{}: {}", cfg_summary(&cfg), e);
            }
            eprintln!("{} ok in {:?}", cfg_summary(&cfg), t.elapsed());
        }
    }
}
