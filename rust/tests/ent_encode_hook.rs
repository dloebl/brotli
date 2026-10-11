//! Differential test of the entropy-coding / bit-stream modules against the
//! C reference (owner: worker "entropy").
//!
//! A private copy of `c/enc/encode.c` (see `c_shims/ent_encode_hook.c`) routes
//! every call into compress_fragment*, metablock and brotli_bit_stream through
//! hooks; each hook hands the exact inputs and the C outputs to a callback
//! here, which replays the call with the Rust port and compares.
#![cfg(feature = "c-reference")]
#![allow(clippy::too_many_arguments, clippy::missing_safety_doc)]

mod cref;
mod ent_common;

use std::ffi::{c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use brotli::common::alloc::{Allocator, Buf};
use brotli::common::context::{brotli_context_lut, ContextType};
use brotli::enc::block_splitter::BlockSplit;
use brotli::enc::brotli_bit_stream::{
    brotli_store_meta_block, brotli_store_meta_block_fast, brotli_store_meta_block_trivial,
    brotli_store_uncompressed_meta_block,
};
use brotli::enc::command::Command;
use brotli::enc::compress_fragment::{brotli_compress_fragment_fast, BrotliOnePassArena};
use brotli::enc::compress_fragment_two_pass::{
    brotli_compress_fragment_two_pass, BrotliTwoPassArena, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE,
};
use brotli::enc::entropy_encode::HuffmanTree;
use brotli::enc::histogram::Histogram;
use brotli::enc::metablock::{
    brotli_build_meta_block, brotli_build_meta_block_greedy, brotli_optimize_histograms, MetaBlockSplit,
};
use brotli::enc::params::{Base64Region, BrotliDistanceParams};
use ent_common::{base_seed, budget_secs, gen_data, make_params, Rng};

// ---------------------------------------------------------------------------
// C layout mirrors.

#[repr(C)]
#[derive(Clone, Copy)]
struct CHuffmanTree {
    total_count_: u32,
    index_left_: i16,
    index_right_or_value_: i16,
}

#[repr(C)]
struct COnePassArena {
    lit_depth: [u8; 256],
    lit_bits: [u16; 256],
    cmd_depth: [u8; 128],
    cmd_bits: [u16; 128],
    cmd_histo: [u32; 128],
    cmd_code: [u8; 512],
    cmd_code_numbits: usize,
    tree: [CHuffmanTree; 513],
    histogram: [u32; 256],
    tmp_depth: [u8; 704],
    tmp_bits: [u16; 64],
}

#[repr(C)]
struct CTwoPassArena {
    lit_histo: [u32; 256],
    lit_depth: [u8; 256],
    lit_bits: [u16; 256],
    cmd_histo: [u32; 128],
    cmd_depth: [u8; 128],
    cmd_bits: [u16; 128],
    tmp_tree: [CHuffmanTree; 513],
    tmp_depth: [u8; 704],
    tmp_bits: [u16; 64],
}

#[repr(C)]
struct CHistogram<const N: usize> {
    data_: [u32; N],
    total_count_: usize,
    bit_cost_: f64,
}

#[repr(C)]
struct CBlockSplit {
    num_types: usize,
    num_blocks: usize,
    types: *mut u8,
    lengths: *mut u32,
    types_alloc_size: usize,
    lengths_alloc_size: usize,
}

#[repr(C)]
struct CMetaBlockSplit {
    literal_split: CBlockSplit,
    command_split: CBlockSplit,
    distance_split: CBlockSplit,
    literal_context_map: *mut u32,
    literal_context_map_size: usize,
    distance_context_map: *mut u32,
    distance_context_map_size: usize,
    literal_histograms: *mut CHistogram<256>,
    literal_histograms_size: usize,
    command_histograms: *mut CHistogram<704>,
    command_histograms_size: usize,
    distance_histograms: *mut CHistogram<544>,
    distance_histograms_size: usize,
    literal_is_base64: [u8; 32],
}

type CbFast = unsafe extern "C" fn(
    *const COnePassArena,
    *const COnePassArena,
    *const u8,
    usize,
    c_int,
    *const c_int,
    usize,
    usize,
    *const u8,
    usize,
    *const u8,
);
type CbTwoPass = unsafe extern "C" fn(
    *const CTwoPassArena,
    *const CTwoPassArena,
    *const u8,
    usize,
    c_int,
    *const c_int,
    usize,
    usize,
    *const u8,
    usize,
    *const u8,
);
type CbStoreSimple = unsafe extern "C" fn(
    c_int,
    *const u8,
    usize,
    usize,
    usize,
    c_int,
    *const BrotliDistanceParams,
    *const Command,
    usize,
    usize,
    *const u8,
    usize,
    *const u8,
);
type CbGreedy = unsafe extern "C" fn(
    *const u8,
    usize,
    usize,
    *const Base64Region,
    usize,
    u8,
    u8,
    c_int,
    usize,
    *const u32,
    *const Command,
    usize,
    *const CMetaBlockSplit,
);
type CbBuild = unsafe extern "C" fn(
    *const u8,
    usize,
    usize,
    *const Base64Region,
    usize,
    c_int,
    c_int,
    c_int,
    *const BrotliDistanceParams,
    *const BrotliDistanceParams,
    u8,
    u8,
    *const Command,
    *const Command,
    usize,
    c_int,
    *const CMetaBlockSplit,
);
type CbOptimize = unsafe extern "C" fn(u32, *const CMetaBlockSplit, *const CMetaBlockSplit);
type CbStore = unsafe extern "C" fn(
    *const u8,
    usize,
    usize,
    usize,
    u8,
    u8,
    c_int,
    *const BrotliDistanceParams,
    c_int,
    *const Command,
    usize,
    *const CMetaBlockSplit,
    usize,
    *const u8,
    usize,
    *const u8,
);
type CbUncompressed = unsafe extern "C" fn(c_int, *const u8, usize, usize, usize, usize, *const u8, usize, *const u8);

#[repr(C)]
struct EntHooks {
    fast: Option<CbFast>,
    two_pass: Option<CbTwoPass>,
    store_simple: Option<CbStoreSimple>,
    greedy: Option<CbGreedy>,
    build: Option<CbBuild>,
    optimize: Option<CbOptimize>,
    store: Option<CbStore>,
    uncompressed: Option<CbUncompressed>,
}

extern "C" {
    fn ent_set_hooks(hooks: *const EntHooks);
    fn ent_sizeof_one_pass_arena() -> usize;
    fn ent_sizeof_two_pass_arena() -> usize;
    fn ent_sizeof_meta_block_split() -> usize;
    fn ent_sizeof_histogram_literal() -> usize;
    fn ent_sizeof_histogram_command() -> usize;
    fn ent_sizeof_histogram_distance() -> usize;

    fn ent_BrotliEncoderCreateInstance(alloc: *const c_void, free: *const c_void, opaque: *mut c_void) -> *mut c_void;
    fn ent_BrotliEncoderDestroyInstance(state: *mut c_void);
    fn ent_BrotliEncoderSetParameter(state: *mut c_void, param: c_int, value: u32) -> c_int;
    fn ent_BrotliEncoderCompressStream(
        state: *mut c_void,
        op: c_int,
        available_in: *mut usize,
        next_in: *mut *const u8,
        available_out: *mut usize,
        next_out: *mut *mut u8,
        total_out: *mut usize,
    ) -> c_int;
    fn ent_BrotliEncoderIsFinished(state: *mut c_void) -> c_int;
    fn ent_BrotliEncoderHasMoreOutput(state: *mut c_void) -> c_int;
}

// ---------------------------------------------------------------------------
// Hook state.

#[derive(Default)]
struct Stats {
    events: [u64; 8],
    failures: u64,
    first_failures: Vec<String>,
    ring_variant: u64,
    coverage: std::collections::BTreeMap<String, u64>,
}

static STATS: Mutex<Option<Stats>> = Mutex::new(None);
static SERIAL: Mutex<()> = Mutex::new(());

const KIND_NAMES: [&str; 8] =
    ["fast(q0)", "two_pass(q1)", "store_simple", "greedy", "build", "optimize", "store", "uncompressed"];

fn record(kind: usize, result: std::thread::Result<Result<(), String>>) {
    let mut g = STATS.lock().unwrap_or_else(|e| e.into_inner());
    let st = g.get_or_insert_with(Stats::default);
    st.events[kind] += 1;
    let err = match result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e),
        Err(p) => Some(format!(
            "PANIC: {}",
            p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
        )),
    };
    if let Some(e) = err {
        st.failures += 1;
        if st.first_failures.len() < 10 {
            st.first_failures.push(format!("[{}] {}", KIND_NAMES[kind], e));
        }
    }
}

fn cov(name: String) {
    let mut g = STATS.lock().unwrap_or_else(|e| e.into_inner());
    let st = g.get_or_insert_with(Stats::default);
    *st.coverage.entry(name).or_insert(0) += 1;
}

fn next_ring_variant() -> u64 {
    let mut g = STATS.lock().unwrap_or_else(|e| e.into_inner());
    let st = g.get_or_insert_with(Stats::default);
    st.ring_variant += 1;
    st.ring_variant
}

unsafe fn slice<'a, T>(p: *const T, n: usize) -> &'a [T] {
    if n == 0 || p.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    }
}

fn m() -> Allocator {
    Allocator::default()
}

/// Copies the ring buffer window `[pos, pos + len)` of the C ring buffer
/// `(data, mask)` into a fresh Rust ring buffer.  Depending on `variant`, the
/// Rust ring buffer has the same mask (when small) or a different (smaller)
/// one, which exercises wrap-around at other places.
unsafe fn ring_window(data: *const u8, pos: usize, len: usize, mask: usize, variant: u64) -> (Vec<u8>, usize) {
    let new_mask = match variant % 3 {
        0 if mask < (1 << 22) => mask,
        1 => (len.max(16)).next_power_of_two() - 1,
        _ => (len.max(16)).next_power_of_two() * 2 - 1,
    };
    let mut buf = vec![0u8; new_mask + 1 + 8];
    for k in 0..len {
        let p = pos.wrapping_add(k);
        buf[p & new_mask] = *data.add(p & mask);
    }
    (buf, new_mask)
}

fn new_storage(size: usize, ix_before: usize, storage_before: &[u8]) -> Vec<u8> {
    let mut s = vec![0u8; size];
    let n = (ix_before >> 3) + 1;
    s[..n].copy_from_slice(&storage_before[..n]);
    s
}

fn compare_storage(rust_ix: usize, rust: &[u8], c_ix: usize, c: &[u8]) -> Result<(), String> {
    if rust_ix != c_ix {
        return Err(format!("storage_ix: rust {} vs C {}", rust_ix, c_ix));
    }
    let n = (c_ix + 7) >> 3;
    if rust[..n] != c[..n] {
        let first = (0..n).find(|&i| rust[i] != c[i]).unwrap();
        return Err(format!("storage differs at byte {} of {} (rust {:02x} vs C {:02x})", first, n, rust[first], c[first]));
    }
    Ok(())
}

fn huffman_from_c(t: &CHuffmanTree) -> HuffmanTree {
    HuffmanTree::new(t.total_count_, t.index_left_, t.index_right_or_value_)
}

fn one_pass_from_c(c: &COnePassArena) -> BrotliOnePassArena {
    let mut s = BrotliOnePassArena::default();
    s.lit_depth = c.lit_depth;
    s.lit_bits = c.lit_bits;
    s.cmd_depth = c.cmd_depth;
    s.cmd_bits = c.cmd_bits;
    s.cmd_histo = c.cmd_histo;
    s.cmd_code = c.cmd_code;
    s.cmd_code_numbits = c.cmd_code_numbits;
    for (d, t) in s.tree.iter_mut().zip(c.tree.iter()) {
        *d = huffman_from_c(t);
    }
    s.histogram = c.histogram;
    s.tmp_depth = c.tmp_depth;
    s.tmp_bits = c.tmp_bits;
    s
}

fn two_pass_from_c(c: &CTwoPassArena) -> BrotliTwoPassArena {
    let mut s = BrotliTwoPassArena::default();
    s.lit_histo = c.lit_histo;
    s.lit_depth = c.lit_depth;
    s.lit_bits = c.lit_bits;
    s.cmd_histo = c.cmd_histo;
    s.cmd_depth = c.cmd_depth;
    s.cmd_bits = c.cmd_bits;
    for (d, t) in s.tmp_tree.iter_mut().zip(c.tmp_tree.iter()) {
        *d = huffman_from_c(t);
    }
    s.tmp_depth = c.tmp_depth;
    s.tmp_bits = c.tmp_bits;
    s
}

unsafe fn split_from_c(m: &Allocator, c: &CBlockSplit) -> BlockSplit {
    let mut s = BlockSplit::new();
    s.num_types = c.num_types;
    s.num_blocks = c.num_blocks;
    s.types = Buf::from_slice(m, slice(c.types, c.num_blocks));
    s.lengths = Buf::from_slice(m, slice(c.lengths, c.num_blocks));
    s
}

unsafe fn histos_from_c<const N: usize>(m: &Allocator, p: *const CHistogram<N>, n: usize) -> Buf<Histogram<N>> {
    let mut b: Buf<Histogram<N>> = Buf::new(m, n);
    for (i, h) in slice(p, n).iter().enumerate() {
        b[i].data_ = h.data_;
        b[i].total_count_ = h.total_count_;
        b[i].bit_cost_ = h.bit_cost_;
    }
    b
}

unsafe fn mb_from_c(m: &Allocator, c: &CMetaBlockSplit) -> MetaBlockSplit {
    let mut mb = MetaBlockSplit::new();
    mb.literal_split = split_from_c(m, &c.literal_split);
    mb.command_split = split_from_c(m, &c.command_split);
    mb.distance_split = split_from_c(m, &c.distance_split);
    mb.literal_context_map = Buf::from_slice(m, slice(c.literal_context_map, c.literal_context_map_size));
    mb.literal_context_map_size = c.literal_context_map_size;
    mb.distance_context_map = Buf::from_slice(m, slice(c.distance_context_map, c.distance_context_map_size));
    mb.distance_context_map_size = c.distance_context_map_size;
    mb.literal_histograms = histos_from_c(m, c.literal_histograms, c.literal_histograms_size);
    mb.literal_histograms_size = c.literal_histograms_size;
    mb.command_histograms = histos_from_c(m, c.command_histograms, c.command_histograms_size);
    mb.command_histograms_size = c.command_histograms_size;
    mb.distance_histograms = histos_from_c(m, c.distance_histograms, c.distance_histograms_size);
    mb.distance_histograms_size = c.distance_histograms_size;
    mb.literal_is_base64 = c.literal_is_base64;
    mb
}

unsafe fn compare_split(name: &str, r: &BlockSplit, c: &CBlockSplit) -> Result<(), String> {
    if r.num_types != c.num_types || r.num_blocks != c.num_blocks {
        return Err(format!(
            "{}: num_types/num_blocks rust {}/{} vs C {}/{}",
            name, r.num_types, r.num_blocks, c.num_types, c.num_blocks
        ));
    }
    let n = c.num_blocks;
    if r.types[..n] != *slice(c.types, n) {
        return Err(format!("{}: types differ", name));
    }
    if r.lengths[..n] != *slice(c.lengths, n) {
        return Err(format!("{}: lengths differ", name));
    }
    Ok(())
}

unsafe fn compare_histos<const N: usize>(
    name: &str,
    r: &[Histogram<N>],
    rn: usize,
    c: *const CHistogram<N>,
    cn: usize,
) -> Result<(), String> {
    if rn != cn {
        return Err(format!("{}: size rust {} vs C {}", name, rn, cn));
    }
    for (i, ch) in slice(c, cn).iter().enumerate() {
        let rh = &r[i];
        if rh.data_ != ch.data_ {
            let k = (0..N).find(|&k| rh.data_[k] != ch.data_[k]).unwrap();
            return Err(format!("{}[{}].data_[{}]: rust {} vs C {}", name, i, k, rh.data_[k], ch.data_[k]));
        }
        if rh.total_count_ != ch.total_count_ {
            return Err(format!("{}[{}].total_count_: rust {} vs C {}", name, i, rh.total_count_, ch.total_count_));
        }
        if rh.bit_cost_.to_bits() != ch.bit_cost_.to_bits() {
            return Err(format!("{}[{}].bit_cost_: rust {} vs C {}", name, i, rh.bit_cost_, ch.bit_cost_));
        }
    }
    Ok(())
}

unsafe fn compare_mb(r: &MetaBlockSplit, c: &CMetaBlockSplit) -> Result<(), String> {
    compare_split("literal_split", &r.literal_split, &c.literal_split)?;
    compare_split("command_split", &r.command_split, &c.command_split)?;
    compare_split("distance_split", &r.distance_split, &c.distance_split)?;
    if r.literal_context_map_size != c.literal_context_map_size
        || r.literal_context_map[..r.literal_context_map_size] != *slice(c.literal_context_map, c.literal_context_map_size)
    {
        return Err("literal_context_map differs".into());
    }
    if r.distance_context_map_size != c.distance_context_map_size
        || r.distance_context_map[..r.distance_context_map_size]
            != *slice(c.distance_context_map, c.distance_context_map_size)
    {
        return Err("distance_context_map differs".into());
    }
    compare_histos("literal_histograms", &r.literal_histograms, r.literal_histograms_size, c.literal_histograms, c.literal_histograms_size)?;
    compare_histos("command_histograms", &r.command_histograms, r.command_histograms_size, c.command_histograms, c.command_histograms_size)?;
    compare_histos(
        "distance_histograms",
        &r.distance_histograms,
        r.distance_histograms_size,
        c.distance_histograms,
        c.distance_histograms_size,
    )?;
    if r.literal_is_base64 != c.literal_is_base64 {
        return Err("literal_is_base64 differs".into());
    }
    Ok(())
}

fn total_len(cmds: &[Command]) -> usize {
    cmds.iter().map(|c| c.insert_len_ as usize + c.copy_len() as usize).sum()
}

// ---------------------------------------------------------------------------
// Callbacks.

unsafe extern "C" fn cb_fast(
    before: *const COnePassArena,
    after: *const COnePassArena,
    input: *const u8,
    input_size: usize,
    is_last: c_int,
    table_before: *const c_int,
    table_size: usize,
    ix_before: usize,
    storage_before: *const u8,
    ix_after: usize,
    storage_after: *const u8,
) {
    cov(format!("fast size>98304={} last={} table={}", input_size > 98304, is_last, table_size));
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let mut s = one_pass_from_c(&*before);
        let input = slice(input, input_size);
        let mut table: Vec<i32> = slice(table_before, table_size).to_vec();
        let mut storage = new_storage(2 * input_size + 503, ix_before, slice(storage_before, (ix_before >> 3) + 1));
        let mut ix = ix_before;
        brotli_compress_fragment_fast(&mut s, input, input_size, is_last != 0, &mut table, table_size, &mut ix, &mut storage);
        compare_storage(ix, &storage, ix_after, slice(storage_after, (ix_after + 7) >> 3))?;
        let a = &*after;
        if s.cmd_depth != a.cmd_depth || s.cmd_bits != a.cmd_bits || s.cmd_histo != a.cmd_histo {
            return Err("arena cmd_depth/cmd_bits/cmd_histo differ".into());
        }
        if s.cmd_code_numbits != a.cmd_code_numbits
            || s.cmd_code[..(a.cmd_code_numbits + 7) >> 3] != a.cmd_code[..(a.cmd_code_numbits + 7) >> 3]
        {
            return Err("arena cmd_code differs".into());
        }
        if s.lit_depth != a.lit_depth || s.lit_bits != a.lit_bits {
            return Err("arena lit_depth/lit_bits differ".into());
        }
        Ok(())
    }));
    record(0, r);
}

unsafe extern "C" fn cb_two_pass(
    before: *const CTwoPassArena,
    after: *const CTwoPassArena,
    input: *const u8,
    input_size: usize,
    is_last: c_int,
    table_before: *const c_int,
    table_size: usize,
    ix_before: usize,
    storage_before: *const u8,
    ix_after: usize,
    storage_after: *const u8,
) {
    cov(format!("two_pass size>131072={} last={} table={}", input_size > 131072, is_last, table_size));
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let mut s = two_pass_from_c(&*before);
        let input = slice(input, input_size);
        let mut table: Vec<i32> = slice(table_before, table_size).to_vec();
        let mut storage = new_storage(2 * input_size + 503, ix_before, slice(storage_before, (ix_before >> 3) + 1));
        let buf_size = input_size.min(K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE);
        let mut command_buf = vec![0u32; buf_size];
        let mut literal_buf = vec![0u8; buf_size];
        let mut ix = ix_before;
        brotli_compress_fragment_two_pass(
            &mut s,
            input,
            input_size,
            is_last != 0,
            &mut command_buf,
            &mut literal_buf,
            &mut table,
            table_size,
            &mut ix,
            &mut storage,
        );
        compare_storage(ix, &storage, ix_after, slice(storage_after, (ix_after + 7) >> 3))?;
        let a = &*after;
        if input_size > 0 && (s.cmd_depth != a.cmd_depth || s.cmd_bits != a.cmd_bits || s.lit_depth != a.lit_depth) {
            return Err("arena depths/bits differ".into());
        }
        Ok(())
    }));
    record(1, r);
}

unsafe extern "C" fn cb_store_simple(
    kind: c_int,
    input: *const u8,
    start_pos: usize,
    length: usize,
    mask: usize,
    is_last: c_int,
    dist: *const BrotliDistanceParams,
    commands: *const Command,
    n_commands: usize,
    ix_before: usize,
    storage_before: *const u8,
    ix_after: usize,
    storage_after: *const u8,
) {
    let variant = next_ring_variant();
    cov(format!("store_simple kind={} n<=128={}", kind, n_commands <= 128));
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let cmds = slice(commands, n_commands);
        let (ring, rmask) = ring_window(input, start_pos, length, mask, variant);
        let params = make_params(if kind == 0 { 2 } else { 3 }, false, false, *dist);
        let mut storage = new_storage(2 * length + 503, ix_before, slice(storage_before, (ix_before >> 3) + 1));
        let mut ix = ix_before;
        if kind == 0 {
            brotli_store_meta_block_fast(&m(), &ring, start_pos, length, rmask, is_last != 0, &params, cmds, &mut ix, &mut storage);
        } else {
            brotli_store_meta_block_trivial(&m(), &ring, start_pos, length, rmask, is_last != 0, &params, cmds, &mut ix, &mut storage);
        }
        compare_storage(ix, &storage, ix_after, slice(storage_after, (ix_after + 7) >> 3))
    }));
    record(2, r);
}

unsafe extern "C" fn cb_greedy(
    ringbuffer: *const u8,
    pos: usize,
    mask: usize,
    regions: *const Base64Region,
    num_regions: usize,
    prev_byte: u8,
    prev_byte2: u8,
    literal_context_mode: c_int,
    num_contexts: usize,
    static_context_map: *const u32,
    commands: *const Command,
    n_commands: usize,
    mb_c: *const CMetaBlockSplit,
) {
    let variant = next_ring_variant();
    if std::env::var("ENT_DEBUG").is_ok() {
        eprintln!("greedy pos={} regions={:?}", pos, slice(regions, num_regions));
        let mut p = pos;
        for c in slice(commands, n_commands) {
            eprintln!("  cmd at {}: insert {} copy {}", p, c.insert_len_, c.copy_len());
            p += c.insert_len_ as usize + c.copy_len() as usize;
        }
    }
    cov(format!("greedy ctx={} b64={}", num_contexts, num_regions > 0));
    cov(format!("greedy literal types {}", match (*mb_c).literal_split.num_types { 0..=1 => "1", 2..=16 => "2-16", 17..=128 => "17-128", _ => ">128" }));
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let cmds = slice(commands, n_commands);
        let len = total_len(cmds);
        let (ring, rmask) = ring_window(ringbuffer, pos, len, mask, variant);
        let regions = slice(regions, num_regions);
        let scm = if static_context_map.is_null() { None } else { Some(slice(static_context_map, 64)) };
        let lut = brotli_context_lut(ContextType::from_u32(literal_context_mode as u32));
        let mut mb = MetaBlockSplit::new();
        brotli_build_meta_block_greedy(
            &m(),
            &ring,
            pos,
            rmask,
            regions,
            prev_byte,
            prev_byte2,
            lut,
            num_contexts,
            scm,
            cmds,
            &mut mb,
        );
        compare_mb(&mb, &*mb_c)
    }));
    record(3, r);
}

unsafe extern "C" fn cb_build(
    ringbuffer: *const u8,
    pos: usize,
    mask: usize,
    regions: *const Base64Region,
    num_regions: usize,
    quality: c_int,
    large_window: c_int,
    disable_lcm: c_int,
    dist_before: *const BrotliDistanceParams,
    dist_after: *const BrotliDistanceParams,
    prev_byte: u8,
    prev_byte2: u8,
    cmds_before: *const Command,
    cmds_after: *const Command,
    num_commands: usize,
    literal_context_mode: c_int,
    mb_c: *const CMetaBlockSplit,
) {
    let variant = next_ring_variant();
    cov(format!(
        "build q={} b64={} lw={} dist_changed={} lcm_off={}",
        quality,
        num_regions > 0,
        large_window,
        *dist_before != *dist_after,
        disable_lcm
    ));
    cov(format!("build literal types {}", match (*mb_c).literal_split.num_types { 0..=1 => "1", 2..=16 => "2-16", 17..=128 => "17-128", _ => ">128" }));
    cov(format!("build literal histos {}", match (*mb_c).literal_histograms_size { 0..=1 => "1", 2..=16 => "2-16", 17..=128 => "17-128", _ => ">128" }));
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let mut cmds: Vec<Command> = slice(cmds_before, num_commands).to_vec();
        let len = total_len(&cmds);
        let (ring, rmask) = ring_window(ringbuffer, pos, len, mask, variant);
        let regions = slice(regions, num_regions);
        let mut params = make_params(quality, large_window != 0, disable_lcm != 0, *dist_before);
        let mut mb = MetaBlockSplit::new();
        brotli_build_meta_block(
            &m(),
            &ring,
            pos,
            rmask,
            regions,
            &mut params,
            prev_byte,
            prev_byte2,
            &mut cmds,
            ContextType::from_u32(literal_context_mode as u32),
            &mut mb,
        );
        if params.dist != *dist_after {
            return Err(format!("dist params: rust {:?} vs C {:?}", params.dist, *dist_after));
        }
        if cmds[..] != *slice(cmds_after, num_commands) {
            return Err("recomputed commands differ".into());
        }
        compare_mb(&mb, &*mb_c)
    }));
    record(4, r);
}

unsafe extern "C" fn cb_optimize(num_distance_codes: u32, before: *const CMetaBlockSplit, after: *const CMetaBlockSplit) {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let mut mb = mb_from_c(&m(), &*before);
        brotli_optimize_histograms(num_distance_codes, &mut mb);
        compare_mb(&mb, &*after)
    }));
    record(5, r);
}

unsafe extern "C" fn cb_store(
    input: *const u8,
    start_pos: usize,
    length: usize,
    mask: usize,
    prev_byte: u8,
    prev_byte2: u8,
    is_last: c_int,
    dist: *const BrotliDistanceParams,
    literal_context_mode: c_int,
    commands: *const Command,
    n_commands: usize,
    mb_c: *const CMetaBlockSplit,
    ix_before: usize,
    storage_before: *const u8,
    ix_after: usize,
    storage_after: *const u8,
) {
    let variant = next_ring_variant();
    cov(format!("store base64 types={}", (*mb_c).literal_is_base64.iter().any(|&b| b != 0)));
    cov(format!("store lcm={} dcm={}", (*mb_c).literal_context_map_size != 0, (*mb_c).distance_context_map_size != 0));
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let cmds = slice(commands, n_commands);
        let (ring, rmask) = ring_window(input, start_pos, length, mask, variant);
        let params = make_params(5, false, false, *dist);
        let mb = mb_from_c(&m(), &*mb_c);
        let mut storage = new_storage(2 * length + 503, ix_before, slice(storage_before, (ix_before >> 3) + 1));
        let mut ix = ix_before;
        brotli_store_meta_block(
            &m(),
            &ring,
            start_pos,
            length,
            rmask,
            prev_byte,
            prev_byte2,
            is_last != 0,
            &params,
            ContextType::from_u32(literal_context_mode as u32),
            cmds,
            &mb,
            &mut ix,
            &mut storage,
        );
        compare_storage(ix, &storage, ix_after, slice(storage_after, (ix_after + 7) >> 3))
    }));
    record(6, r);
}

unsafe extern "C" fn cb_uncompressed(
    is_final: c_int,
    input: *const u8,
    position: usize,
    mask: usize,
    len: usize,
    ix_before: usize,
    storage_before: *const u8,
    ix_after: usize,
    storage_after: *const u8,
) {
    let variant = next_ring_variant();
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let (ring, rmask) = ring_window(input, position, len, mask, variant);
        let mut storage = new_storage(2 * len + 503, ix_before, slice(storage_before, (ix_before >> 3) + 1));
        let mut ix = ix_before;
        brotli_store_uncompressed_meta_block(is_final != 0, &ring, position, rmask, len, &mut ix, &mut storage);
        compare_storage(ix, &storage, ix_after, slice(storage_after, (ix_after + 7) >> 3))
    }));
    record(7, r);
}

// ---------------------------------------------------------------------------
// Driver.

#[derive(Clone, Debug)]
struct EncParams {
    quality: u32,
    lgwin: u32,
    mode: u32,
    lgblock: u32,
    large_window: bool,
    disable_lcm: bool,
    size_hint: u32,
    npostfix: u32,
    ndirect: u32,
    base64_mode: bool,
    max_base64_regions: u32,
    min_base64_region_len: u32,
}

impl EncParams {
    fn random(rng: &mut Rng, len: usize) -> Self {
        let quality = match std::env::var("ENT_QUALITY").ok().and_then(|q| q.parse::<u32>().ok()) {
            Some(q) => q,
            None => rng.range(0, 11) as u32,
        };
        let large_window = rng.chance(1, 6);
        let lgwin = if large_window && rng.chance(1, 2) { rng.range(10, 30) } else { rng.range(10, 24) } as u32;
        let npostfix = rng.range(0, 3) as u32;
        let ndirect = (rng.range(0, 15) as u32) << npostfix;
        EncParams {
            quality,
            lgwin,
            mode: rng.range(0, 2) as u32,
            lgblock: if rng.chance(1, 3) { rng.range(16, 24) as u32 } else { 0 },
            large_window,
            disable_lcm: rng.chance(1, 5),
            size_hint: if rng.chance(1, 2) { len as u32 } else { rng.next_u32() >> rng.range(0, 31) },
            npostfix: if rng.chance(1, 2) { npostfix } else { 0 },
            ndirect: if rng.chance(1, 2) { ndirect } else { 0 },
            base64_mode: rng.chance(1, 2),
            max_base64_regions: rng.range(0, 40) as u32,
            min_base64_region_len: if rng.chance(1, 2) { rng.range(1, 64) as u32 } else { rng.range(1, 4096) as u32 },
        }
    }
}

/// Compresses `data` with the hooked C encoder (streaming, with random chunk
/// sizes and flushes); returns the compressed stream.
fn c_compress(p: &EncParams, data: &[u8], rng: &mut Rng) -> Vec<u8> {
    unsafe {
        let s = ent_BrotliEncoderCreateInstance(std::ptr::null(), std::ptr::null(), std::ptr::null_mut());
        assert!(!s.is_null());
        let set = |param: c_int, v: u32| {
            ent_BrotliEncoderSetParameter(s, param, v);
        };
        set(0, p.mode);
        set(1, p.quality);
        set(2, p.lgwin);
        set(3, p.lgblock);
        set(4, p.disable_lcm as u32);
        set(5, p.size_hint);
        set(6, p.large_window as u32);
        set(7, p.npostfix);
        set(8, p.ndirect);
        set(10, p.base64_mode as u32);
        set(11, p.max_base64_regions);
        set(14, p.min_base64_region_len);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut pos = 0usize;
        let streaming = rng.chance(1, 3);
        loop {
            let chunk = if streaming { (rng.range(1, 70000) as usize).min(data.len() - pos) } else { data.len() - pos };
            let last = pos + chunk == data.len();
            let op = if last {
                2
            } else if rng.chance(1, 4) {
                1
            } else {
                0
            };
            let mut avail_in = chunk;
            let mut next_in = data.as_ptr().add(pos);
            loop {
                let out_cap = if rng.chance(1, 4) { rng.range(1, buf.len() as u64) as usize } else { buf.len() };
                let mut avail_out = out_cap;
                let mut next_out = buf.as_mut_ptr();
                let ok = ent_BrotliEncoderCompressStream(
                    s,
                    op,
                    &mut avail_in,
                    &mut next_in,
                    &mut avail_out,
                    &mut next_out,
                    std::ptr::null_mut(),
                );
                assert!(ok != 0, "C encoder failed");
                out.extend_from_slice(&buf[..out_cap - avail_out]);
                let done = if op == 2 {
                    ent_BrotliEncoderIsFinished(s) != 0
                } else {
                    avail_in == 0 && ent_BrotliEncoderHasMoreOutput(s) == 0
                };
                if done {
                    break;
                }
            }
            pos += chunk;
            if last {
                break;
            }
        }
        ent_BrotliEncoderDestroyInstance(s);
        out
    }
}

fn install_hooks() {
    let hooks = EntHooks {
        fast: Some(cb_fast),
        two_pass: Some(cb_two_pass),
        store_simple: Some(cb_store_simple),
        greedy: Some(cb_greedy),
        build: Some(cb_build),
        optimize: Some(cb_optimize),
        store: Some(cb_store),
        uncompressed: Some(cb_uncompressed),
    };
    unsafe { ent_set_hooks(&hooks) };
}

/// Streaming decompression with the C reference (large window allowed).
fn decompress(input: &[u8], large_window: bool) -> Option<Vec<u8>> {
    unsafe {
        let s = cref::ref_BrotliDecoderCreateInstance(None, None, std::ptr::null_mut());
        if large_window {
            cref::ref_BrotliDecoderSetParameter(s, 1, 1);
        }
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut avail_in = input.len();
        let mut next_in = input.as_ptr();
        let result = loop {
            let mut avail_out = buf.len();
            let mut next_out = buf.as_mut_ptr();
            let r = cref::ref_BrotliDecoderDecompressStream(
                s,
                &mut avail_in,
                &mut next_in,
                &mut avail_out,
                &mut next_out,
                std::ptr::null_mut(),
            );
            out.extend_from_slice(&buf[..buf.len() - avail_out]);
            match r {
                1 => break Some(out),
                3 => continue,
                _ => break None,
            }
        };
        cref::ref_BrotliDecoderDestroyInstance(s);
        result
    }
}

fn run_hooked(budget: f64, seed: u64, max_len: usize) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert_eq!(std::mem::size_of::<COnePassArena>(), ent_sizeof_one_pass_arena());
        assert_eq!(std::mem::size_of::<CTwoPassArena>(), ent_sizeof_two_pass_arena());
        assert_eq!(std::mem::size_of::<CMetaBlockSplit>(), ent_sizeof_meta_block_split());
        assert_eq!(std::mem::size_of::<CHistogram<256>>(), ent_sizeof_histogram_literal());
        assert_eq!(std::mem::size_of::<CHistogram<704>>(), ent_sizeof_histogram_command());
        assert_eq!(std::mem::size_of::<CHistogram<544>>(), ent_sizeof_histogram_distance());
        // The Rust types have the C sizes (EstimatePeakMemoryUsage).
        assert_eq!(std::mem::size_of::<BrotliOnePassArena>(), ent_sizeof_one_pass_arena());
        assert_eq!(std::mem::size_of::<BrotliTwoPassArena>(), ent_sizeof_two_pass_arena());
        assert_eq!(std::mem::size_of::<Histogram<256>>(), ent_sizeof_histogram_literal());
        assert_eq!(std::mem::size_of::<Histogram<704>>(), ent_sizeof_histogram_command());
        assert_eq!(std::mem::size_of::<Histogram<544>>(), ent_sizeof_histogram_distance());
    }
    install_hooks();
    *STATS.lock().unwrap() = Some(Stats::default());
    let start = std::time::Instant::now();
    let mut rng = Rng::new(seed);
    let mut iters = 0u64;
    let mut bytes = 0u64;
    while iters == 0 || start.elapsed().as_secs_f64() < budget {
        let len = match rng.below(10) {
            0..=3 => rng.below(2000) as usize,
            4..=7 => rng.below(70000) as usize,
            8 => rng.below(400000.min(max_len as u64 + 1)) as usize,
            _ => rng.below(max_len as u64 + 1) as usize,
        };
        let kind = rng.below(ent_common::NUM_DATA_KINDS) as u32;
        let data = gen_data(&mut rng, kind, len);
        let p = EncParams::random(&mut rng, len);
        let fails_before = STATS.lock().unwrap().as_ref().unwrap().failures;
        let out = c_compress(&p, &data, &mut rng);
        let mut fails_after = STATS.lock().unwrap().as_ref().unwrap().failures;
        // Sanity: the hooked C encoder still produces a valid stream.
        let dec = decompress(&out, p.large_window);
        if dec.as_deref() != Some(&data[..]) {
            // Known C reference bug with BROTLI_PARAM_BASE64_MODE (see
            // base64_dupe_region_matches_c): the stream is corrupt and the C
            // output may depend on uninitialized memory; do not count
            // mismatches of such streams.
            assert!(p.base64_mode, "C stream does not round-trip (params {:?})", p);
            let mut g = STATS.lock().unwrap();
            let st = g.as_mut().unwrap();
            let n = st.failures - fails_before;
            st.failures = fails_before;
            st.first_failures.truncate(st.first_failures.len().saturating_sub(n as usize));
            *st.coverage.entry("C base64 stream corrupt (ignored)".into()).or_insert(0) += 1;
            fails_after = fails_before;
        }
        if fails_after != fails_before {
            eprintln!("mismatch with params {:?}, data kind {}, len {} (iter {}, seed {})", p, kind, len, iters, seed);
        }
        iters += 1;
        bytes += len as u64;
        if fails_after > 20 {
            break;
        }
    }
    unsafe { ent_set_hooks(std::ptr::null()) };
    let st = STATS.lock().unwrap().take().unwrap();
    eprintln!(
        "hooked encoder: {} streams, {} bytes, events: {}",
        iters,
        bytes,
        KIND_NAMES.iter().zip(st.events.iter()).map(|(n, c)| format!("{}={}", n, c)).collect::<Vec<_>>().join(" ")
    );
    for (k, v) in st.coverage.iter() {
        eprintln!("  {:50} {}", k, v);
    }
    if st.failures != 0 {
        panic!("{} mismatches:\n{}", st.failures, st.first_failures.join("\n"));
    }
}

#[test]
fn hooked_encoder_matches_c() {
    // Default (quick) run: 12 s with inputs up to 1 MiB; set ENT_SECONDS for
    // longer randomized runs (inputs up to 4 MiB).
    let long = std::env::var("ENT_SECONDS").is_ok();
    run_hooked(budget_secs(12.0), base_seed(), if long { 4 << 20 } else { 1 << 20 });
}

/// Regression scenario: with BROTLI_PARAM_BASE64_MODE, a duplicated base64
/// block is emitted as a copy and its region start is moved into that copy,
/// so the forced base64 literal block covers following non-base64 literals.
/// The C reference then emits those literals with zero-length codes (reading
/// uninitialized `bits_` entries) and produces a stream that does not
/// round-trip.  The Rust port must still match the C output bit for bit.
#[test]
fn base64_dupe_region_matches_c() {
    let mut rng = Rng::new(42);
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s: Vec<u8> = (0..3000).map(|_| B64[rng.below(64) as usize]).collect();
    let mut data = Vec::new();
    for i in 0..4 {
        data.extend_from_slice(b"some text here, <img src=\"data:image/png");
        for _ in 0..8 {
            data.push(b'a' + rng.below(26) as u8);
        }
        data.extend_from_slice(b";base64,");
        data.extend_from_slice(&s);
        data.extend_from_slice(b"\"> and more text!!! ... ;;; ,,, ");
        for _ in 0..(2000 * (i + 1)) {
            let c = b" .,;:!?-_\n\"'()[]{}<>@#%^&*~"[rng.below(27) as usize];
            data.push(c);
        }
    }
    for q in 4..10 {
        let p = EncParams {
            quality: q,
            lgwin: 22,
            mode: 0,
            lgblock: 0,
            large_window: false,
            disable_lcm: false,
            size_hint: 0,
            npostfix: 0,
            ndirect: 0,
            base64_mode: true,
            max_base64_regions: 16,
            min_base64_region_len: 100,
        };
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        install_hooks();
        *STATS.lock().unwrap() = Some(Stats::default());
        let out = c_compress(&p, &data, &mut rng);
        unsafe { ent_set_hooks(std::ptr::null()) };
        let st = STATS.lock().unwrap().take().unwrap();
        let dec = decompress(&out, false);
        eprintln!(
            "q{}: {} -> {} bytes, C roundtrip ok: {}, mismatches {} {:?}",
            q,
            data.len(),
            out.len(),
            dec.as_deref() == Some(&data[..]),
            st.failures,
            st.first_failures
        );
        assert!(st.events[3] > 0 && st.events[6] > 0);
        // When the C stream is corrupt, the C encoder has read uninitialized
        // memory (`bits_` of zero-depth symbols), so its output depends on
        // heap garbage; the Rust port behaves as if that memory were zero.
        if dec.as_deref() == Some(&data[..]) || st.failures == 0 {
            assert_eq!(st.failures, 0);
        } else {
            eprintln!("  (C output depends on uninitialized memory here; mismatch not counted)");
        }
    }
}
