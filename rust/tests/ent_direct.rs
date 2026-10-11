//! Direct differential tests of the entropy-coding / bit-stream functions
//! against the C reference, with synthetic (also adversarial) inputs
//! (owner: worker "entropy").
#![cfg(feature = "c-reference")]
#![allow(clippy::too_many_arguments)]

mod cref;
mod ent_common;

use std::ffi::c_int;

use brotli::common::alloc::{Allocator, Buf};
use brotli::common::context::{brotli_context_lut, ContextType};
use brotli::enc::bit_cost::{brotli_bits_entropy, brotli_population_cost};
use brotli::enc::block_splitter::{brotli_split_block, BlockSplit};
use brotli::enc::brotli_bit_stream::{
    brotli_build_and_store_huffman_tree_fast, brotli_store_huffman_tree, brotli_store_meta_block,
    brotli_store_meta_block_fast, brotli_store_meta_block_trivial, brotli_store_uncompressed_meta_block,
};
use brotli::enc::cluster::brotli_cluster_histograms;
use brotli::enc::command::Command;
use brotli::enc::compress_fragment::{brotli_compress_fragment_fast, init_command_prefix_codes, BrotliOnePassArena};
use brotli::enc::compress_fragment_two_pass::{
    brotli_compress_fragment_two_pass, BrotliTwoPassArena, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE,
};
use brotli::enc::entropy_encode::{
    brotli_convert_bit_depths_to_symbols, brotli_create_huffman_tree, brotli_optimize_huffman_counts_for_rle,
    brotli_write_huffman_tree, HuffmanTree,
};
use brotli::enc::histogram::Histogram;
use brotli::enc::metablock::{
    brotli_build_meta_block, brotli_build_meta_block_greedy, brotli_init_distance_params, brotli_optimize_histograms,
    MetaBlockSplit,
};
use brotli::enc::params::{Base64Region, BrotliDistanceParams};
use ent_common::{base_seed, budget_secs, gen_data, make_params, Rng, NUM_DATA_KINDS};

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(C)]
struct COpaque {
    _p: [u8; 0],
}

extern "C" {
    fn ent_c_create_huffman_tree(data: *const u32, length: usize, tree_limit: c_int, depth: *mut u8);
    fn ent_c_optimize_huffman_counts_for_rle(length: usize, counts: *mut u32, good_for_rle: *mut u8);
    fn ent_c_write_huffman_tree(depth: *const u8, length: usize, tree_size: *mut usize, tree: *mut u8, extra: *mut u8);
    fn ent_c_convert_bit_depths_to_symbols(depth: *const u8, len: usize, bits: *mut u16);
    fn ent_c_bits_entropy(population: *const u32, size: usize) -> f64;
    fn ent_c_population_cost_literal(h: *const CHistogram<256>) -> f64;
    fn ent_c_population_cost_command(h: *const CHistogram<704>) -> f64;
    fn ent_c_population_cost_distance(h: *const CHistogram<544>) -> f64;
    fn ent_c_cluster_histograms_literal(
        input: *const CHistogram<256>,
        in_size: usize,
        max_histograms: usize,
        out: *mut CHistogram<256>,
        out_size: *mut usize,
        symbols: *mut u32,
    );
    fn ent_c_cluster_histograms_command(
        input: *const CHistogram<704>,
        in_size: usize,
        max_histograms: usize,
        out: *mut CHistogram<704>,
        out_size: *mut usize,
        symbols: *mut u32,
    );
    fn ent_c_cluster_histograms_distance(
        input: *const CHistogram<544>,
        in_size: usize,
        max_histograms: usize,
        out: *mut CHistogram<544>,
        out_size: *mut usize,
        symbols: *mut u32,
    );
    fn ent_c_store_huffman_tree(depths: *const u8, num: usize, storage_ix: *mut usize, storage: *mut u8);
    fn ent_c_build_and_store_huffman_tree_fast(
        histogram: *const u32,
        histogram_total: usize,
        max_bits: usize,
        depth: *mut u8,
        bits: *mut u16,
        storage_ix: *mut usize,
        storage: *mut u8,
    );
    fn ent_c_store_uncompressed_meta_block(
        is_final: c_int,
        input: *const u8,
        position: usize,
        mask: usize,
        len: usize,
        storage_ix: *mut usize,
        storage: *mut u8,
    );
    fn ent_c_init_command(
        dist: *const BrotliDistanceParams,
        insertlen: usize,
        copylen: usize,
        copylen_code_delta: c_int,
        distance_code: usize,
        out: *mut Command,
    );
    fn ent_c_init_insert_command(insertlen: usize, out: *mut Command);
    fn ent_c_init_distance_params(dist: *mut BrotliDistanceParams, npostfix: u32, ndirect: u32, large_window: c_int);
    fn ent_c_new_mb() -> *mut CMetaBlockSplit;
    fn ent_c_destroy_mb(mb: *mut CMetaBlockSplit);
    fn ent_c_split_block(
        cmds: *const Command,
        num_commands: usize,
        data: *const u8,
        pos: usize,
        mask: usize,
        quality: c_int,
        mb: *mut CMetaBlockSplit,
    );
    fn ent_c_build_meta_block_greedy(
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
        mb: *mut CMetaBlockSplit,
    );
    fn ent_c_build_meta_block(
        ringbuffer: *const u8,
        pos: usize,
        mask: usize,
        regions: *const Base64Region,
        num_regions: usize,
        quality: c_int,
        large_window: c_int,
        disable_lcm: c_int,
        dist: *mut BrotliDistanceParams,
        prev_byte: u8,
        prev_byte2: u8,
        cmds: *mut Command,
        num_commands: usize,
        literal_context_mode: c_int,
        mb: *mut CMetaBlockSplit,
    );
    fn ent_c_optimize_histograms(num_distance_codes: u32, mb: *mut CMetaBlockSplit);
    fn ent_c_store_meta_block(
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
        mb: *const CMetaBlockSplit,
        storage_ix: *mut usize,
        storage: *mut u8,
    );
    fn ent_c_store_meta_block_simple(
        kind: c_int,
        input: *const u8,
        start_pos: usize,
        length: usize,
        mask: usize,
        is_last: c_int,
        dist: *const BrotliDistanceParams,
        commands: *const Command,
        n_commands: usize,
        storage_ix: *mut usize,
        storage: *mut u8,
    );
    fn ent_c_new_one_pass_arena() -> *mut COpaque;
    fn ent_c_new_two_pass_arena() -> *mut COpaque;
    fn ent_c_free(p: *mut COpaque);
    fn ent_c_compress_fragment_fast(
        s: *mut COpaque,
        input: *const u8,
        input_size: usize,
        is_last: c_int,
        table: *mut c_int,
        table_size: usize,
        storage_ix: *mut usize,
        storage: *mut u8,
    );
    fn ent_c_compress_fragment_two_pass(
        s: *mut COpaque,
        input: *const u8,
        input_size: usize,
        is_last: c_int,
        command_buf: *mut u32,
        literal_buf: *mut u8,
        table: *mut c_int,
        table_size: usize,
        storage_ix: *mut usize,
        storage: *mut u8,
    );
    fn ent_c_static_context_map(which: c_int) -> *const u32;
}

fn m() -> Allocator {
    Allocator::default()
}

unsafe fn slice<'a, T>(p: *const T, n: usize) -> &'a [T] {
    if n == 0 || p.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    }
}

fn deadline(default_secs: f64) -> (std::time::Instant, f64) {
    (std::time::Instant::now(), budget_secs(default_secs))
}

fn running(start: &(std::time::Instant, f64), iter: u64) -> bool {
    iter < 20 || start.0.elapsed().as_secs_f64() < start.1
}

/// A random histogram-like count vector of length `n`.
fn random_counts(rng: &mut Rng, n: usize, huge: bool) -> Vec<u32> {
    let mut v = vec![0u32; n];
    let density = rng.range(1, 100);
    let max = match rng.below(4) {
        0 => 3,
        1 => 100,
        2 => 100000,
        _ => {
            if huge {
                u32::MAX / (n as u32).max(1)
            } else {
                1 << 20
            }
        }
    };
    let style = rng.below(3);
    for (i, c) in v.iter_mut().enumerate() {
        if rng.below(100) < density {
            *c = match style {
                0 => rng.range(1, max as u64) as u32,
                1 => ((max as u64 >> (i % 20).min(31)) as u32).max(1),
                _ => {
                    if rng.chance(1, 2) {
                        rng.range(1, 4) as u32
                    } else {
                        rng.range(1, max as u64) as u32
                    }
                }
            };
        }
    }
    if rng.chance(1, 5) {
        // Runs of equal values.
        let mut i = 0;
        while i < n {
            let run = rng.range(1, 40) as usize;
            let val = if rng.chance(1, 3) { 0 } else { rng.range(1, max as u64) as u32 };
            for c in v.iter_mut().skip(i).take(run) {
                *c = val;
            }
            i += run;
        }
    }
    v
}

#[test]
fn entropy_encode_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 1);
    let dl = deadline(3.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        let n = match rng.below(4) {
            0 => rng.range(1, 30) as usize,
            1 => 256,
            2 => 704,
            _ => rng.range(1, 704) as usize,
        };
        // BrotliCreateHuffmanTree / BrotliConvertBitDepthsToSymbols.
        let mut counts = random_counts(&mut rng, n, false);
        if counts.iter().all(|&c| c == 0) {
            counts[rng.below(n as u64) as usize] = 1;
        }
        let tree_limit = [15, 14, 7, 5, 15, 15][rng.below(6) as usize];
        if tree_limit < 15 && counts.iter().filter(|&&c| c != 0).count() > (1 << tree_limit) {
            continue;
        }
        let mut depth_c = vec![0u8; n];
        let mut depth_r = vec![0u8; n];
        unsafe { ent_c_create_huffman_tree(counts.as_ptr(), n, tree_limit, depth_c.as_mut_ptr()) };
        let mut tree = vec![HuffmanTree::default(); 2 * n + 1];
        brotli_create_huffman_tree(&counts, n, tree_limit, &mut tree, &mut depth_r);
        assert_eq!(depth_r, depth_c, "create_huffman_tree n={} limit={}", n, tree_limit);

        let mut bits_c = vec![0x5555u16; n];
        let mut bits_r = vec![0x5555u16; n];
        unsafe { ent_c_convert_bit_depths_to_symbols(depth_c.as_ptr(), n, bits_c.as_mut_ptr()) };
        brotli_convert_bit_depths_to_symbols(&depth_r, n, &mut bits_r);
        assert_eq!(bits_r, bits_c);

        // BrotliWriteHuffmanTree (on the depths and on random depth vectors).
        let mut depths_in = depth_c.clone();
        if rng.chance(1, 2) {
            let mut i = 0;
            while i < n {
                let run = rng.range(1, 30) as usize;
                let v = if rng.chance(1, 3) { 0 } else { rng.range(1, 15) as u8 };
                for d in depths_in.iter_mut().skip(i).take(run) {
                    *d = v;
                }
                i += run;
            }
        }
        let mut ts_c = 0usize;
        let mut ts_r = 0usize;
        let mut tree_c = vec![0u8; 704];
        let mut tree_r = vec![0u8; 704];
        let mut ex_c = vec![0u8; 704];
        let mut ex_r = vec![0u8; 704];
        unsafe { ent_c_write_huffman_tree(depths_in.as_ptr(), n, &mut ts_c, tree_c.as_mut_ptr(), ex_c.as_mut_ptr()) };
        brotli_write_huffman_tree(&depths_in, n, &mut ts_r, &mut tree_r, &mut ex_r);
        assert_eq!(ts_r, ts_c);
        assert_eq!(tree_r[..ts_r], tree_c[..ts_c]);
        assert_eq!(ex_r[..ts_r], ex_c[..ts_c]);

        // BrotliOptimizeHuffmanCountsForRle (also with huge counts).
        let mut counts2_c = random_counts(&mut rng, n, true);
        let mut counts2_r = counts2_c.clone();
        let mut good_c = vec![7u8; n];
        let mut good_r = vec![7u8; n];
        unsafe { ent_c_optimize_huffman_counts_for_rle(n, counts2_c.as_mut_ptr(), good_c.as_mut_ptr()) };
        brotli_optimize_huffman_counts_for_rle(n, &mut counts2_r, &mut good_r);
        assert_eq!(counts2_r, counts2_c, "optimize_huffman_counts_for_rle n={}", n);
        assert_eq!(good_r, good_c);
    }
    eprintln!("entropy_encode: {} iterations", iter);
}

fn to_c_histo<const N: usize>(counts: &[u32]) -> CHistogram<N> {
    let mut h = CHistogram { data_: [0u32; N], total_count_: 0, bit_cost_: f64::INFINITY };
    h.data_.copy_from_slice(counts);
    h.total_count_ = counts.iter().map(|&c| c as usize).sum();
    h
}

fn to_r_histo<const N: usize>(c: &CHistogram<N>) -> Histogram<N> {
    Histogram { data_: c.data_, total_count_: c.total_count_, bit_cost_: c.bit_cost_ }
}

#[test]
fn bit_cost_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 2);
    let dl = deadline(2.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        let n = rng.range(1, 704) as usize;
        let huge = rng.chance(1, 4);
        let counts = random_counts(&mut rng, n, huge);
        let a = unsafe { ent_c_bits_entropy(counts.as_ptr(), n) };
        let b = brotli_bits_entropy(&counts, n);
        assert_eq!(a.to_bits(), b.to_bits(), "bits_entropy");

        let mut small = |len: usize| -> Vec<u32> {
            let mut v = random_counts(&mut rng, len, false);
            if rng.chance(1, 3) {
                // Few non-zero symbols (special cases 1..4).
                let k = rng.range(0, 5) as usize;
                v.iter_mut().for_each(|x| *x = 0);
                for _ in 0..k {
                    let i = rng.below(len as u64) as usize;
                    v[i] = rng.range(1, 1 << 20) as u32;
                }
            }
            v
        };
        let l = small(256);
        let hl = to_c_histo::<256>(&l);
        assert_eq!(unsafe { ent_c_population_cost_literal(&hl) }.to_bits(), brotli_population_cost(&to_r_histo(&hl)).to_bits());
        let c = small(704);
        let hc = to_c_histo::<704>(&c);
        assert_eq!(unsafe { ent_c_population_cost_command(&hc) }.to_bits(), brotli_population_cost(&to_r_histo(&hc)).to_bits());
        let d = small(544);
        let hd = to_c_histo::<544>(&d);
        assert_eq!(unsafe { ent_c_population_cost_distance(&hd) }.to_bits(), brotli_population_cost(&to_r_histo(&hd)).to_bits());
    }
    eprintln!("bit_cost: {} iterations", iter);
}

fn cluster_case<const N: usize>(
    rng: &mut Rng,
    cfun: unsafe extern "C" fn(*const CHistogram<N>, usize, usize, *mut CHistogram<N>, *mut usize, *mut u32),
) {
    let in_size = match rng.below(4) {
        0 => rng.range(1, 8) as usize,
        1 => rng.range(1, 70) as usize,
        2 => rng.range(60, 300) as usize,
        _ => rng.range(1, 1200) as usize,
    };
    let max_histograms = if rng.chance(1, 2) { 256 } else { rng.range(1, 300) as usize };
    // A few "prototype" distributions, each histogram is a noisy copy.
    let protos: Vec<Vec<u32>> = (0..rng.range(1, 10)).map(|_| random_counts(rng, N, false)).collect();
    let mut input: Vec<CHistogram<N>> = Vec::with_capacity(in_size);
    for _ in 0..in_size {
        let p = &protos[rng.below(protos.len() as u64) as usize];
        let mut v: Vec<u32> = p
            .iter()
            .map(|&x| if rng.chance(1, 4) { (x as u64 * rng.range(0, 3) / 2) as u32 } else { x })
            .collect();
        if rng.chance(1, 10) {
            v.iter_mut().for_each(|x| *x = 0);
        }
        input.push(to_c_histo::<N>(&v));
    }
    let mut out_c = vec![CHistogram { data_: [0u32; N], total_count_: 0, bit_cost_: 0.0 }; in_size];
    let mut sym_c = vec![0u32; in_size];
    let mut out_size_c = 0usize;
    unsafe { cfun(input.as_ptr(), in_size, max_histograms, out_c.as_mut_ptr(), &mut out_size_c, sym_c.as_mut_ptr()) };

    let input_r: Vec<Histogram<N>> = input.iter().map(to_r_histo).collect();
    let mut out_r: Buf<Histogram<N>> = Buf::new(&m(), in_size);
    let mut sym_r = vec![0u32; in_size];
    let mut out_size_r = 0usize;
    brotli_cluster_histograms(&m(), &input_r, in_size, max_histograms, &mut out_r, &mut out_size_r, &mut sym_r);
    assert_eq!(out_size_r, out_size_c, "cluster out_size (N={}, in_size={})", N, in_size);
    assert_eq!(sym_r, sym_c, "cluster symbols");
    for i in 0..out_size_c {
        assert_eq!(out_r[i].data_, out_c[i].data_);
        assert_eq!(out_r[i].total_count_, out_c[i].total_count_);
        assert_eq!(out_r[i].bit_cost_.to_bits(), out_c[i].bit_cost_.to_bits());
    }
}

#[test]
fn cluster_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 3);
    let dl = deadline(4.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        match rng.below(3) {
            0 => cluster_case::<256>(&mut rng, ent_c_cluster_histograms_literal),
            1 => cluster_case::<704>(&mut rng, ent_c_cluster_histograms_command),
            _ => cluster_case::<544>(&mut rng, ent_c_cluster_histograms_distance),
        }
    }
    eprintln!("cluster: {} iterations", iter);
}

fn random_storage_prefix(rng: &mut Rng, size: usize) -> (Vec<u8>, usize) {
    let mut s = vec![0u8; size];
    let ix = rng.range(0, 14) as usize;
    let mut bits = rng.next_u64() & ((1u64 << ix) - 1);
    for b in s.iter_mut().take((ix >> 3) + 1) {
        *b = bits as u8;
        bits >>= 8;
    }
    (s, ix)
}

#[test]
fn huffman_tree_storage_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 4);
    let dl = deadline(2.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        let n = match rng.below(3) {
            0 => 256,
            1 => 704,
            _ => rng.range(2, 704) as usize,
        };
        let mut counts = random_counts(&mut rng, n, false);
        let nz = counts.iter().filter(|&&c| c != 0).count();
        if nz < 2 {
            counts[0] = 1;
            counts[n - 1] = 3;
        }
        // BrotliStoreHuffmanTree with depths of a real Huffman code.
        let mut depth = vec![0u8; n];
        unsafe { ent_c_create_huffman_tree(counts.as_ptr(), n, 15, depth.as_mut_ptr()) };
        let (mut st_c, ix0) = random_storage_prefix(&mut rng, 4096);
        let mut st_r = st_c.clone();
        let mut ix_c = ix0;
        let mut ix_r = ix0;
        unsafe { ent_c_store_huffman_tree(depth.as_ptr(), n, &mut ix_c, st_c.as_mut_ptr()) };
        let mut tree = vec![HuffmanTree::default(); 2 * 704 + 1];
        brotli_store_huffman_tree(&depth, n, &mut tree, &mut ix_r, &mut st_r);
        assert_eq!(ix_r, ix_c);
        assert_eq!(st_r[..(ix_c + 7) / 8], st_c[..(ix_c + 7) / 8]);

        // BrotliBuildAndStoreHuffmanTreeFast.
        let total: usize = counts.iter().map(|&c| c as usize).sum();
        let max_bits = {
            let mut b = 0;
            let mut x = n - 1;
            while x != 0 {
                x >>= 1;
                b += 1;
            }
            b + rng.below(2) as usize
        };
        let (mut st_c, ix0) = random_storage_prefix(&mut rng, 4096);
        let mut st_r = st_c.clone();
        let mut ix_c = ix0;
        let mut ix_r = ix0;
        let mut d_c = vec![0x77u8; n];
        let mut d_r = vec![0x77u8; n];
        let mut b_c = vec![0x7777u16; n];
        let mut b_r = vec![0x7777u16; n];
        unsafe {
            ent_c_build_and_store_huffman_tree_fast(
                counts.as_ptr(),
                total,
                max_bits,
                d_c.as_mut_ptr(),
                b_c.as_mut_ptr(),
                &mut ix_c,
                st_c.as_mut_ptr(),
            )
        };
        brotli_build_and_store_huffman_tree_fast(&mut tree, &counts, total, max_bits, &mut d_r, &mut b_r, &mut ix_r, &mut st_r);
        assert_eq!(ix_r, ix_c);
        assert_eq!(st_r[..(ix_c + 7) / 8], st_c[..(ix_c + 7) / 8]);
        assert_eq!(d_r, d_c);
        assert_eq!(b_r, b_c);
    }
    eprintln!("huffman tree storage: {} iterations", iter);
}

/// q0 / q1 on consecutive blocks with the arena carried across calls (like
/// encode.c), random table sizes and initial bit positions.
#[test]
fn compress_fragment_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 5);
    let dl = deadline(6.0);
    let mut iter = 0u64;
    let mut bytes = 0usize;
    while running(&dl, iter) {
        iter += 1;
        let two_pass = rng.chance(1, 2);
        let c_arena = unsafe { if two_pass { ent_c_new_two_pass_arena() } else { ent_c_new_one_pass_arena() } };
        let mut r1 = BrotliOnePassArena::default();
        init_command_prefix_codes(&mut r1);
        let mut r2 = BrotliTwoPassArena::default();
        let nblocks = rng.range(1, 6);
        let kind = rng.below(NUM_DATA_KINDS) as u32;
        for b in 0..nblocks {
            let is_last = b + 1 == nblocks;
            let len = match rng.below(6) {
                0 => rng.below(40) as usize,
                1..=3 => rng.below(70000) as usize,
                4 => rng.below(300000) as usize,
                _ => rng.below(1 << 20) as usize + 1,
            };
            let len = if len == 0 && !is_last { 1 } else { len };
            let k = if rng.chance(1, 4) { rng.below(NUM_DATA_KINDS) as u32 } else { kind };
            let data = gen_data(&mut rng, k, len);
            bytes += len;
            let table_bits = if two_pass { rng.range(8, 17) } else { [9u64, 11, 13, 15][rng.below(4) as usize] };
            let table_size = 1usize << table_bits;
            let mut table_c = vec![0i32; table_size];
            let mut table_r = vec![0i32; table_size];
            let size = 2 * len + 503;
            let (mut st_c, ix0) = random_storage_prefix(&mut rng, size);
            let ix0 = ix0 & 7;
            let mut st_r = st_c.clone();
            let mut ix_c = ix0;
            let mut ix_r = ix0;
            if two_pass {
                let buf_size = len.min(K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE);
                let mut cb_c = vec![0u32; buf_size.max(1)];
                let mut lb_c = vec![0u8; buf_size.max(1)];
                let mut cb_r = vec![0u32; buf_size];
                let mut lb_r = vec![0u8; buf_size];
                unsafe {
                    ent_c_compress_fragment_two_pass(
                        c_arena,
                        data.as_ptr(),
                        len,
                        is_last as c_int,
                        cb_c.as_mut_ptr(),
                        lb_c.as_mut_ptr(),
                        table_c.as_mut_ptr(),
                        table_size,
                        &mut ix_c,
                        st_c.as_mut_ptr(),
                    )
                };
                brotli_compress_fragment_two_pass(
                    &mut r2,
                    &data,
                    len,
                    is_last,
                    &mut cb_r,
                    &mut lb_r,
                    &mut table_r,
                    table_size,
                    &mut ix_r,
                    &mut st_r,
                );
            } else {
                unsafe {
                    ent_c_compress_fragment_fast(
                        c_arena,
                        data.as_ptr(),
                        len,
                        is_last as c_int,
                        table_c.as_mut_ptr(),
                        table_size,
                        &mut ix_c,
                        st_c.as_mut_ptr(),
                    )
                };
                brotli_compress_fragment_fast(&mut r1, &data, len, is_last, &mut table_r, table_size, &mut ix_r, &mut st_r);
            }
            assert_eq!(ix_r, ix_c, "storage_ix (two_pass={}, len={}, block {})", two_pass, len, b);
            assert!(st_r[..(ix_c + 7) / 8] == st_c[..(ix_c + 7) / 8], "storage (two_pass={}, len={})", two_pass, len);
            assert!(table_r == table_c, "hash table");
        }
        unsafe { ent_c_free(c_arena) };
    }
    eprintln!("compress_fragment: {} iterations, {} bytes", iter, bytes);
}

#[test]
fn uncompressed_meta_block_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 6);
    for _ in 0..300 {
        let len = rng.range(1, 70000) as usize;
        let mask = (len.next_power_of_two() << rng.below(2)) - 1;
        let ring: Vec<u8> = (0..=mask).map(|_| rng.next_u32() as u8).collect();
        let pos = rng.next_u64() as usize;
        let size = 2 * len + 503;
        let (mut st_c, ix0) = random_storage_prefix(&mut rng, size);
        let mut st_r = st_c.clone();
        let mut ix_c = ix0;
        let mut ix_r = ix0;
        let fin = rng.chance(1, 2);
        unsafe { ent_c_store_uncompressed_meta_block(fin as c_int, ring.as_ptr(), pos, mask, len, &mut ix_c, st_c.as_mut_ptr()) };
        brotli_store_uncompressed_meta_block(fin, &ring, pos, mask, len, &mut ix_r, &mut st_r);
        assert_eq!(ix_r, ix_c);
        assert!(st_r[..(ix_c + 7) / 8] == st_c[..(ix_c + 7) / 8]);
    }
}

/// Synthetic metablock: ring buffer, position, mask and commands covering
/// `len` bytes.
struct SynthBlock {
    ring: Vec<u8>,
    mask: usize,
    pos: usize,
    len: usize,
    cmds: Vec<Command>,
    dist: BrotliDistanceParams,
    large_window: bool,
}

fn synth_block(rng: &mut Rng, max_len: usize) -> SynthBlock {
    synth_block_ex(rng, max_len, false)
}

/// `base64`: data made of base64 characters only (the hasher only records
/// base64 regions over base64 characters; literals of forced base64 blocks
/// that are not base64 characters make the C reference read uninitialized
/// memory).
fn synth_block_ex(rng: &mut Rng, max_len: usize, base64: bool) -> SynthBlock {
    let len = match rng.below(5) {
        0 => rng.range(1, 200) as usize,
        1 | 2 => rng.range(1, 20000) as usize,
        3 => rng.range(1, 200000) as usize,
        _ => rng.range(1, max_len as u64) as usize,
    };
    let k = rng.below(NUM_DATA_KINDS) as u32;
    let mut data = gen_data(rng, k, len);
    if base64 {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for b in data.iter_mut() {
            *b = B64[(*b & 63) as usize];
        }
    }
    let mask = (len.max(4).next_power_of_two() << rng.below(2)) - 1;
    let mut ring = vec![0u8; mask + 1];
    let pos = if rng.chance(1, 2) { rng.below(1 << 30) as usize } else { rng.next_u64() as usize >> 8 };
    for (k, &b) in data.iter().enumerate() {
        ring[pos.wrapping_add(k) & mask] = b;
    }
    let large_window = rng.chance(1, 5);
    let npostfix = if rng.chance(1, 2) { 0 } else { rng.range(0, 3) as u32 };
    let ndirect = if rng.chance(1, 2) { 0 } else { (rng.range(0, 15) as u32) << npostfix };
    let mut dist = BrotliDistanceParams::default();
    unsafe { ent_c_init_distance_params(&mut dist, npostfix, ndirect, large_window as c_int) };
    let max_distance = dist.max_distance.min(if large_window { 1 << 30 } else { (1 << 24) - 16 });
    // Commands.
    let style = rng.below(4);
    let mut cmds = Vec::new();
    let mut remaining = len;
    let mut last_dist_code: Option<usize> = None;
    while remaining > 0 {
        let insert = match style {
            0 => rng.below(20) as usize,
            1 => rng.below(300) as usize,
            2 => {
                if rng.chance(1, 10) {
                    rng.below(30000) as usize
                } else {
                    rng.below(5) as usize
                }
            }
            _ => rng.below(3000) as usize,
        }
        .min(remaining);
        let left = remaining - insert;
        if left < 2 || rng.chance(1, 50) {
            let mut c = Command::default();
            unsafe { ent_c_init_insert_command(remaining, &mut c) };
            cmds.push(c);
            break;
        }
        let copy = (match rng.below(4) {
            0 => rng.range(2, 10),
            1 => rng.range(2, 100),
            2 => rng.range(2, 3000),
            _ => rng.range(2, 70000),
        } as usize)
            .min(left);
        let delta: i32 = if rng.chance(1, 8) && copy > 4 { rng.range(0, 6) as i32 - 2 } else { 0 };
        let distance_code = match rng.below(5) {
            0 => rng.below(16) as usize,
            1 => last_dist_code.unwrap_or(0),
            _ => {
                let d = match rng.below(3) {
                    0 => rng.range(1, 64),
                    1 => rng.range(1, 70000),
                    _ => rng.range(1, max_distance as u64),
                } as usize;
                d + 15
            }
        };
        last_dist_code = Some(distance_code);
        let mut c = Command::default();
        unsafe { ent_c_init_command(&dist, insert, copy, delta, distance_code, &mut c) };
        cmds.push(c);
        remaining -= insert + copy;
    }
    SynthBlock { ring, mask, pos, len, cmds, dist, large_window }
}

fn random_regions(rng: &mut Rng, b: &SynthBlock, num_literals: usize) -> Vec<Base64Region> {
    let n = rng.range(1, 20) as usize;
    let mut v = Vec::new();
    let mut p = b.pos;
    for _ in 0..n {
        // Positions are ring positions (like the hasher records them).
        let start = if rng.chance(1, 5) {
            b.pos.wrapping_add(rng.below(b.len as u64 + 10) as usize)
        } else {
            p += rng.below((b.len / n.max(1)).max(1) as u64) as usize;
            p
        };
        let length = rng.range(1, (num_literals.max(1) as u64).min(20000)) as usize;
        p += length;
        v.push(Base64Region { start_literal_pos: start, length, last_start_pos: start });
    }
    v
}

unsafe fn compare_split(name: &str, r: &BlockSplit, c: &CBlockSplit) {
    assert_eq!((r.num_types, r.num_blocks), (c.num_types, c.num_blocks), "{}: num_types/num_blocks", name);
    assert!(r.types[..c.num_blocks] == *slice(c.types, c.num_blocks), "{}: types", name);
    assert!(r.lengths[..c.num_blocks] == *slice(c.lengths, c.num_blocks), "{}: lengths", name);
}

unsafe fn compare_histos<const N: usize>(name: &str, r: &[Histogram<N>], rn: usize, c: *const CHistogram<N>, cn: usize) {
    assert_eq!(rn, cn, "{}: size", name);
    for (i, ch) in slice(c, cn).iter().enumerate() {
        assert!(r[i].data_ == ch.data_, "{}[{}].data_", name, i);
        assert_eq!(r[i].total_count_, ch.total_count_, "{}[{}].total_count_", name, i);
        assert_eq!(r[i].bit_cost_.to_bits(), ch.bit_cost_.to_bits(), "{}[{}].bit_cost_", name, i);
    }
}

unsafe fn compare_mb(r: &MetaBlockSplit, c: &CMetaBlockSplit) {
    compare_split("literal_split", &r.literal_split, &c.literal_split);
    compare_split("command_split", &r.command_split, &c.command_split);
    compare_split("distance_split", &r.distance_split, &c.distance_split);
    assert_eq!(r.literal_context_map_size, c.literal_context_map_size);
    assert!(r.literal_context_map[..r.literal_context_map_size] == *slice(c.literal_context_map, c.literal_context_map_size));
    assert_eq!(r.distance_context_map_size, c.distance_context_map_size);
    assert!(r.distance_context_map[..r.distance_context_map_size] == *slice(c.distance_context_map, c.distance_context_map_size));
    compare_histos("literal", &r.literal_histograms, r.literal_histograms_size, c.literal_histograms, c.literal_histograms_size);
    compare_histos("command", &r.command_histograms, r.command_histograms_size, c.command_histograms, c.command_histograms_size);
    compare_histos("distance", &r.distance_histograms, r.distance_histograms_size, c.distance_histograms, c.distance_histograms_size);
    assert_eq!(r.literal_is_base64, c.literal_is_base64);
}

/// Stores `mb` (C and Rust copies) with C and Rust and compares.
unsafe fn check_store(
    rng: &mut Rng,
    b: &SynthBlock,
    cmds: &[Command],
    dist: &BrotliDistanceParams,
    mode: ContextType,
    prev_byte: u8,
    prev_byte2: u8,
    mb_r: &MetaBlockSplit,
    mb_c: *const CMetaBlockSplit,
) {
    let size = 2 * b.len + 503;
    let (mut st_c, ix0) = random_storage_prefix(rng, size);
    let mut st_r = st_c.clone();
    let mut ix_c = ix0;
    let mut ix_r = ix0;
    let is_last = rng.chance(1, 2);
    ent_c_store_meta_block(
        b.ring.as_ptr(),
        b.pos,
        b.len,
        b.mask,
        prev_byte,
        prev_byte2,
        is_last as c_int,
        dist,
        mode as c_int,
        cmds.as_ptr(),
        cmds.len(),
        mb_c,
        &mut ix_c,
        st_c.as_mut_ptr(),
    );
    let params = make_params(5, b.large_window, false, *dist);
    brotli_store_meta_block(
        &m(),
        &b.ring,
        b.pos,
        b.len,
        b.mask,
        prev_byte,
        prev_byte2,
        is_last,
        &params,
        mode,
        cmds,
        mb_r,
        &mut ix_r,
        &mut st_r,
    );
    assert_eq!(ix_r, ix_c, "store_meta_block storage_ix");
    if st_r[..(ix_c + 7) / 8] != st_c[..(ix_c + 7) / 8] {
        let first = (0..(ix_c + 7) / 8).find(|&i| st_r[i] != st_c[i]).unwrap();
        panic!(
            "store_meta_block storage differs at byte {} of {}; b64 types {:?}, lit types {}, lit histos {}, cm {}",
            first,
            (ix_c + 7) / 8,
            mb_r.literal_is_base64,
            mb_r.literal_split.num_types,
            mb_r.literal_histograms_size,
            mb_r.literal_context_map_size
        );
    }
}

#[test]
fn metablock_greedy_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 7);
    let dl = deadline(6.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        let use_b64 = rng.chance(1, 2);
        let b = synth_block_ex(&mut rng, 1 << 21, use_b64);
        let num_literals: usize = b.cmds.iter().map(|c| c.insert_len_ as usize).sum();
        // (Base64 regions always cover literals in the encoder.)
        let regions = if use_b64 && num_literals > 0 { random_regions(&mut rng, &b, num_literals) } else { Vec::new() };
        let num_contexts = [1usize, 1, 2, 3, 13][rng.below(5) as usize];
        let scm_ptr = unsafe { ent_c_static_context_map(num_contexts as c_int) };
        let scm = unsafe { if scm_ptr.is_null() { None } else { Some(slice(scm_ptr, 64)) } };
        let mode = ContextType::from_u32(rng.below(4) as u32);
        let prev_byte = rng.next_u32() as u8;
        let prev_byte2 = rng.next_u32() as u8;
        unsafe {
            let mb_c = ent_c_new_mb();
            ent_c_build_meta_block_greedy(
                b.ring.as_ptr(),
                b.pos,
                b.mask,
                regions.as_ptr(),
                regions.len(),
                prev_byte,
                prev_byte2,
                mode as c_int,
                num_contexts,
                scm_ptr,
                b.cmds.as_ptr(),
                b.cmds.len(),
                mb_c,
            );
            let mut mb_r = MetaBlockSplit::new();
            brotli_build_meta_block_greedy(
                &m(),
                &b.ring,
                b.pos,
                b.mask,
                &regions,
                prev_byte,
                prev_byte2,
                brotli_context_lut(mode),
                num_contexts,
                scm,
                &b.cmds,
                &mut mb_r,
            );
            compare_mb(&mb_r, &*mb_c);
            if rng.chance(1, 2) {
                let ndc = b.dist.alphabet_size_limit;
                ent_c_optimize_histograms(ndc, mb_c);
                brotli_optimize_histograms(ndc, &mut mb_r);
                compare_mb(&mb_r, &*mb_c);
            }
            check_store(&mut rng, &b, &b.cmds, &b.dist, mode, prev_byte, prev_byte2, &mb_r, mb_c);
            ent_c_destroy_mb(mb_c);
        }
    }
    eprintln!("metablock greedy: {} iterations", iter);
}

#[test]
fn metablock_hq_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 8);
    let dl = deadline(8.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        let use_b64 = rng.chance(1, 2);
        let b = synth_block_ex(&mut rng, 1 << 19, use_b64);
        let num_literals: usize = b.cmds.iter().map(|c| c.insert_len_ as usize).sum();
        // (Base64 regions always cover literals in the encoder.)
        let regions = if use_b64 && num_literals > 0 { random_regions(&mut rng, &b, num_literals) } else { Vec::new() };
        let quality = if rng.chance(1, 2) { 10 } else { 11 };
        let disable_lcm = rng.chance(1, 4);
        let mode = ContextType::from_u32(rng.below(4) as u32);
        let prev_byte = rng.next_u32() as u8;
        let prev_byte2 = rng.next_u32() as u8;
        unsafe {
            let mb_c = ent_c_new_mb();
            let mut cmds_c = b.cmds.clone();
            let mut dist_c = b.dist;
            ent_c_build_meta_block(
                b.ring.as_ptr(),
                b.pos,
                b.mask,
                regions.as_ptr(),
                regions.len(),
                quality,
                b.large_window as c_int,
                disable_lcm as c_int,
                &mut dist_c,
                prev_byte,
                prev_byte2,
                cmds_c.as_mut_ptr(),
                cmds_c.len(),
                mode as c_int,
                mb_c,
            );
            let mut cmds_r = b.cmds.clone();
            let mut params = make_params(quality, b.large_window, disable_lcm, b.dist);
            let mut mb_r = MetaBlockSplit::new();
            brotli_build_meta_block(
                &m(),
                &b.ring,
                b.pos,
                b.mask,
                &regions,
                &mut params,
                prev_byte,
                prev_byte2,
                &mut cmds_r,
                mode,
                &mut mb_r,
            );
            if std::env::var("ENT_DEBUG").is_ok() {
                for (name, sp) in [("lit", &mb_r.literal_split), ("cmd", &mb_r.command_split), ("dist", &mb_r.distance_split)] {
                    if sp.lengths[..sp.num_blocks].iter().any(|&l| l == 0) {
                        eprintln!("{} split has zero-length block: types {:?} lengths {:?} regions {:?} nlit {}", name, &sp.types[..sp.num_blocks], &sp.lengths[..sp.num_blocks], regions, num_literals);
                    }
                }
            }
            assert_eq!(params.dist, dist_c, "distance params");
            assert!(cmds_r == cmds_c, "recomputed commands");
            compare_mb(&mb_r, &*mb_c);
            ent_c_optimize_histograms(dist_c.alphabet_size_limit, mb_c);
            brotli_optimize_histograms(dist_c.alphabet_size_limit, &mut mb_r);
            compare_mb(&mb_r, &*mb_c);
            check_store(&mut rng, &b, &cmds_r, &dist_c, mode, prev_byte, prev_byte2, &mb_r, mb_c);
            ent_c_destroy_mb(mb_c);
        }
    }
    eprintln!("metablock hq: {} iterations", iter);
}

#[test]
fn split_block_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 9);
    let dl = deadline(3.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        let b = synth_block(&mut rng, 1 << 18);
        let quality = rng.range(4, 11) as i32;
        unsafe {
            let mb_c = ent_c_new_mb();
            ent_c_split_block(b.cmds.as_ptr(), b.cmds.len(), b.ring.as_ptr(), b.pos, b.mask, quality, mb_c);
            let params = make_params(quality, false, false, b.dist);
            let mut mb_r = MetaBlockSplit::new();
            brotli_split_block(
                &m(),
                &b.cmds,
                &b.ring,
                b.pos,
                b.mask,
                &params,
                &mut mb_r.literal_split,
                &mut mb_r.command_split,
                &mut mb_r.distance_split,
            );
            compare_split("literal_split", &mb_r.literal_split, &(*mb_c).literal_split);
            compare_split("command_split", &mb_r.command_split, &(*mb_c).command_split);
            compare_split("distance_split", &mb_r.distance_split, &(*mb_c).distance_split);
            ent_c_destroy_mb(mb_c);
        }
    }
    eprintln!("split_block: {} iterations", iter);
}

#[test]
fn store_meta_block_simple_matches_c() {
    let mut rng = Rng::new(base_seed() ^ 10);
    let dl = deadline(2.0);
    let mut iter = 0u64;
    while running(&dl, iter) {
        iter += 1;
        let mut b = synth_block(&mut rng, 1 << 18);
        let kind = rng.below(2) as c_int;
        // q2/q3 use npostfix = ndirect = 0 and no large window.
        let mut dist = BrotliDistanceParams::default();
        brotli_init_distance_params(&mut dist, 0, 0, false);
        if rng.chance(1, 2) {
            // Re-encode the distances with default params, capped to the
            // 64-symbol static distance code range of q2.
            for c in b.cmds.iter_mut() {
                if c.copy_len() != 0 && c.cmd_prefix_ >= 128 {
                    let d = c.restore_distance_code(&b.dist).min(if kind == 0 { 1 << 20 } else { 1 << 23 });
                    let insert = c.insert_len_ as usize;
                    let copy = c.copy_len() as usize;
                    let delta = c.copy_len_code() as i32 - copy as i32;
                    unsafe { ent_c_init_command(&dist, insert, copy, delta, d as usize, c) };
                }
            }
            b.dist = dist;
        } else {
            let mut d2 = BrotliDistanceParams::default();
            unsafe { ent_c_init_distance_params(&mut d2, 0, 0, 0) };
            assert_eq!(d2, dist);
            if b.dist != dist {
                continue;
            }
        }
        let size = 2 * b.len + 503;
        let (mut st_c, ix0) = random_storage_prefix(&mut rng, size);
        let mut st_r = st_c.clone();
        let mut ix_c = ix0;
        let mut ix_r = ix0;
        let is_last = rng.chance(1, 2);
        unsafe {
            ent_c_store_meta_block_simple(
                kind,
                b.ring.as_ptr(),
                b.pos,
                b.len,
                b.mask,
                is_last as c_int,
                &b.dist,
                b.cmds.as_ptr(),
                b.cmds.len(),
                &mut ix_c,
                st_c.as_mut_ptr(),
            )
        };
        let params = make_params(if kind == 0 { 2 } else { 3 }, false, false, b.dist);
        if kind == 0 {
            brotli_store_meta_block_fast(&m(), &b.ring, b.pos, b.len, b.mask, is_last, &params, &b.cmds, &mut ix_r, &mut st_r);
        } else {
            brotli_store_meta_block_trivial(&m(), &b.ring, b.pos, b.len, b.mask, is_last, &params, &b.cmds, &mut ix_r, &mut st_r);
        }
        assert_eq!(ix_r, ix_c);
        assert!(st_r[..(ix_c + 7) / 8] == st_c[..(ix_c + 7) / 8]);
    }
    eprintln!("store_meta_block simple: {} iterations", iter);
}

/// Rough performance comparison with the C reference (run with
/// `cargo test --release --features c-reference --test ent_direct bench -- --ignored --nocapture`).
#[test]
#[ignore]
fn bench_vs_c() {
    use std::time::Instant;
    let mut rng = Rng::new(77);
    let mut data = Vec::new();
    for k in [1u32, 7, 9, 1, 4, 6] {
        data.extend_from_slice(&gen_data(&mut rng, k, 1 << 20));
    }
    // q0 / q1.
    for two_pass in [false, true] {
        let mut t_c = 0.0;
        let mut t_r = 0.0;
        for chunk in data.chunks(1 << 18) {
            let len = chunk.len();
            let table_size = if two_pass { 1 << 17 } else { 1 << 15 };
            let mut st_c = vec![0u8; 2 * len + 503];
            let mut st_r = st_c.clone();
            let mut table = vec![0i32; table_size];
            let (mut ix_c, mut ix_r) = (0usize, 0usize);
            let mut cb = vec![0u32; len.min(1 << 17)];
            let mut lb = vec![0u8; len.min(1 << 17)];
            unsafe {
                let a = if two_pass { ent_c_new_two_pass_arena() } else { ent_c_new_one_pass_arena() };
                let t = Instant::now();
                if two_pass {
                    ent_c_compress_fragment_two_pass(a, chunk.as_ptr(), len, 1, cb.as_mut_ptr(), lb.as_mut_ptr(), table.as_mut_ptr(), table_size, &mut ix_c, st_c.as_mut_ptr());
                } else {
                    ent_c_compress_fragment_fast(a, chunk.as_ptr(), len, 1, table.as_mut_ptr(), table_size, &mut ix_c, st_c.as_mut_ptr());
                }
                t_c += t.elapsed().as_secs_f64();
                ent_c_free(a);
            }
            table.iter_mut().for_each(|x| *x = 0);
            let t = Instant::now();
            if two_pass {
                let mut s = BrotliTwoPassArena::default();
                brotli_compress_fragment_two_pass(&mut s, chunk, len, true, &mut cb, &mut lb, &mut table, table_size, &mut ix_r, &mut st_r);
            } else {
                let mut s = BrotliOnePassArena::default();
                init_command_prefix_codes(&mut s);
                brotli_compress_fragment_fast(&mut s, chunk, len, true, &mut table, table_size, &mut ix_r, &mut st_r);
            }
            t_r += t.elapsed().as_secs_f64();
            assert_eq!(ix_c, ix_r);
        }
        eprintln!("compress_fragment two_pass={}: C {:.3}s, Rust {:.3}s", two_pass, t_c, t_r);
    }
    // Metablock chains on synthetic blocks.
    for hq in [false, true] {
        let mut t_c = 0.0;
        let mut t_r = 0.0;
        let mut rng = Rng::new(99);
        for _ in 0..(if hq { 6 } else { 30 }) {
            let mut b = synth_block_ex(&mut rng, 1 << 20, false);
            while b.len < (1 << 18) {
                b = synth_block_ex(&mut rng, 1 << 20, false);
            }
            let mode = ContextType::Utf8;
            let scm = unsafe { ent_c_static_context_map(13) };
            unsafe {
                let mb_c = ent_c_new_mb();
                let mut cmds_c = b.cmds.clone();
                let mut dist_c = b.dist;
                let mut st_c = vec![0u8; 2 * b.len + 503];
                let mut ix_c = 0usize;
                let t = Instant::now();
                if hq {
                    ent_c_build_meta_block(b.ring.as_ptr(), b.pos, b.mask, std::ptr::null(), 0, 11, b.large_window as c_int, 0, &mut dist_c, 0, 0, cmds_c.as_mut_ptr(), cmds_c.len(), mode as c_int, mb_c);
                } else {
                    ent_c_build_meta_block_greedy(b.ring.as_ptr(), b.pos, b.mask, std::ptr::null(), 0, 0, 0, mode as c_int, 13, scm, cmds_c.as_ptr(), cmds_c.len(), mb_c);
                }
                ent_c_optimize_histograms(dist_c.alphabet_size_limit, mb_c);
                ent_c_store_meta_block(b.ring.as_ptr(), b.pos, b.len, b.mask, 0, 0, 1, &dist_c, mode as c_int, cmds_c.as_ptr(), cmds_c.len(), mb_c, &mut ix_c, st_c.as_mut_ptr());
                t_c += t.elapsed().as_secs_f64();
                ent_c_destroy_mb(mb_c);

                let mut cmds_r = b.cmds.clone();
                let mut params = make_params(11, b.large_window, false, b.dist);
                let mut mb_r = MetaBlockSplit::new();
                let mut st_r = vec![0u8; 2 * b.len + 503];
                let mut ix_r = 0usize;
                let t = Instant::now();
                if hq {
                    brotli_build_meta_block(&m(), &b.ring, b.pos, b.mask, &[], &mut params, 0, 0, &mut cmds_r, mode, &mut mb_r);
                } else {
                    brotli_build_meta_block_greedy(&m(), &b.ring, b.pos, b.mask, &[], 0, 0, brotli_context_lut(mode), 13, Some(slice(scm, 64)), &cmds_r, &mut mb_r);
                }
                brotli_optimize_histograms(params.dist.alphabet_size_limit, &mut mb_r);
                brotli_store_meta_block(&m(), &b.ring, b.pos, b.len, b.mask, 0, 0, true, &params, mode, &cmds_r, &mb_r, &mut ix_r, &mut st_r);
                t_r += t.elapsed().as_secs_f64();
                assert_eq!(ix_c, ix_r);
            }
        }
        eprintln!("metablock chain hq={}: C {:.3}s, Rust {:.3}s", hq, t_c, t_r);
    }
}
