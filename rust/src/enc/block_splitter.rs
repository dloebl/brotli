//! Port of `c/enc/block_splitter.h` / `block_splitter.c` /
//! `block_splitter_inc.h`.
//!
//! OWNER: worker "entropy".
//!
//! The C template (instantiated for Literal / Command / Distance with data
//! type `uint8_t` / `uint16_t` / `uint16_t`) maps to functions generic over
//! the symbol type and the histogram alphabet size `N`.

use super::bit_cost::brotli_population_cost;
use super::cluster::{brotli_histogram_bit_cost_distance, brotli_histogram_combine, HistogramPair};
use super::command::Command;
use super::fast_log::fast_log2;
use super::histogram::{clear_histograms, Histogram, BROTLI_NUM_HISTOGRAM_DISTANCE_SYMBOLS};
use super::memory::{Buf, MemoryManager};
use super::params::BrotliEncoderParams;
use super::quality::HQ_ZOPFLIFICATION_QUALITY;
use crate::common::constants::{BROTLI_MAX_NUMBER_OF_BLOCK_TYPES, BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS};

/// `BlockSplit`.  `types.len()` / `lengths.len()` are the allocated
/// capacities (C: `types_alloc_size` / `lengths_alloc_size`).
#[derive(Default)]
pub struct BlockSplit {
    /// Amount of distinct types
    pub num_types: usize,
    /// Amount of values in types and length
    pub num_blocks: usize,
    pub types: Buf<u8>,
    pub lengths: Buf<u32>,
}

impl BlockSplit {
    /// `BrotliInitBlockSplit`.
    pub fn new() -> Self {
        BlockSplit::default()
    }
}

const K_MAX_LITERAL_HISTOGRAMS: usize = 100;
const K_MAX_COMMAND_HISTOGRAMS: usize = 50;
const K_LITERAL_BLOCK_SWITCH_COST: f64 = 28.1;
const K_COMMAND_BLOCK_SWITCH_COST: f64 = 13.5;
const K_DISTANCE_BLOCK_SWITCH_COST: f64 = 14.6;
const K_LITERAL_STRIDE_LENGTH: usize = 70;
const K_COMMAND_STRIDE_LENGTH: usize = 40;
const K_DISTANCE_STRIDE_LENGTH: usize = 40;
const K_SYMBOLS_PER_LITERAL_HISTOGRAM: usize = 544;
const K_SYMBOLS_PER_COMMAND_HISTOGRAM: usize = 530;
const K_SYMBOLS_PER_DISTANCE_HISTOGRAM: usize = 544;
const K_MIN_LENGTH_FOR_BLOCK_SPLITTING: usize = 128;
const K_ITER_MUL_FOR_REFINING: usize = 2;
const K_MIN_ITERS_FOR_REFINING: usize = 100;

const HISTOGRAMS_PER_BATCH: usize = 64;
const CLUSTERS_PER_BATCH: usize = 16;

/// Symbol type of a block splitter instantiation (`DataType`).
pub(crate) trait SymbolData: Copy {
    fn idx(self) -> usize;
}
impl SymbolData for u8 {
    #[inline(always)]
    fn idx(self) -> usize {
        self as usize
    }
}
impl SymbolData for u16 {
    #[inline(always)]
    fn idx(self) -> usize {
        self as usize
    }
}

/// `HistogramAddVector`.
#[inline]
fn histogram_add_vector<T: SymbolData, const N: usize>(h: &mut Histogram<N>, p: &[T]) {
    h.total_count_ = h.total_count_.wrapping_add(p.len());
    for &v in p {
        h.data_[v.idx()] = h.data_[v.idx()].wrapping_add(1);
    }
}

fn count_literals(cmds: &[Command]) -> usize {
    // Count how many we have.
    let mut total_length: usize = 0;
    for c in cmds {
        total_length += c.insert_len_ as usize;
    }
    total_length
}

fn copy_literals_to_byte_array(cmds: &[Command], data: &[u8], offset: usize, mask: usize, literals: &mut [u8]) {
    let mut pos: usize = 0;
    let mut from_pos = offset & mask;
    for c in cmds {
        let mut insert_len = c.insert_len_ as usize;
        if from_pos + insert_len > mask {
            let head_size = mask + 1 - from_pos;
            literals[pos..pos + head_size].copy_from_slice(&data[from_pos..from_pos + head_size]);
            from_pos = 0;
            pos += head_size;
            insert_len -= head_size;
        }
        if insert_len > 0 {
            literals[pos..pos + insert_len].copy_from_slice(&data[from_pos..from_pos + insert_len]);
            pos += insert_len;
        }
        from_pos = (from_pos + insert_len + c.copy_len() as usize) & mask;
    }
}

#[inline(always)]
fn my_rand(seed: &mut u32) -> u32 {
    // Initial seed should be 7. In this case, loop length is (1 << 29).
    *seed = seed.wrapping_mul(16807);
    *seed
}

#[inline(always)]
fn bit_cost(count: usize) -> f64 {
    if count == 0 {
        -2.0
    } else {
        fast_log2(count)
    }
}

fn initial_entropy_codes<T: SymbolData, const N: usize>(
    data: &[T],
    length: usize,
    stride: usize,
    num_histograms: usize,
    histograms: &mut [Histogram<N>],
) {
    let mut seed: u32 = 7;
    let block_length = length / num_histograms;
    clear_histograms(&mut histograms[..num_histograms]);
    for i in 0..num_histograms {
        let mut pos = length * i / num_histograms;
        if i != 0 {
            pos += my_rand(&mut seed) as usize % block_length;
        }
        if pos + stride >= length {
            pos = length - stride - 1;
        }
        histogram_add_vector(&mut histograms[i], &data[pos..pos + stride]);
    }
}

fn random_sample<T: SymbolData, const N: usize>(
    seed: &mut u32,
    data: &[T],
    length: usize,
    mut stride: usize,
    sample: &mut Histogram<N>,
) {
    let mut pos: usize = 0;
    if stride >= length {
        stride = length;
    } else {
        pos = my_rand(seed) as usize % (length - stride + 1);
    }
    histogram_add_vector(sample, &data[pos..pos + stride]);
}

fn refine_entropy_codes<T: SymbolData, const N: usize>(
    data: &[T],
    length: usize,
    stride: usize,
    num_histograms: usize,
    histograms: &mut [Histogram<N>],
    tmp: &mut Histogram<N>,
) {
    let mut iters = K_ITER_MUL_FOR_REFINING * length / stride + K_MIN_ITERS_FOR_REFINING;
    let mut seed: u32 = 7;
    iters = ((iters + num_histograms - 1) / num_histograms) * num_histograms;
    for iter in 0..iters {
        tmp.clear();
        random_sample(&mut seed, data, length, stride, tmp);
        histograms[iter % num_histograms].add_histogram(tmp);
    }
}

/// Assigns a block id from the range `[0, num_histograms)` to each data
/// element in `data[0..length)` and fills in `block_id[0..length)` with the
/// assigned values. Returns the number of blocks, i.e. one plus the number
/// of block switches.
#[allow(clippy::too_many_arguments)]
fn find_blocks<T: SymbolData, const N: usize>(
    data: &[T],
    length: usize,
    block_switch_bitcost: f64,
    num_histograms: usize,
    histograms: &[Histogram<N>],
    insert_cost: &mut [f64],
    cost: &mut [f64],
    switch_signal: &mut [u8],
    block_id: &mut [u8],
) -> usize {
    let alphabet_size = N;
    let bitmap_len = (num_histograms + 7) >> 3;
    let mut num_blocks: usize = 1;
    debug_assert!(num_histograms <= 256);

    // Trivial case: single histogram -> single block type.
    if num_histograms <= 1 {
        for b in block_id[..length].iter_mut() {
            *b = 0;
        }
        return 1;
    }

    // Fill bitcost for each symbol of all histograms.
    // Non-existing symbol cost: 2 + log2(total_count).
    // Regular symbol cost: -log2(symbol_count / total_count).
    for c in insert_cost[..alphabet_size * num_histograms].iter_mut() {
        *c = 0.0;
    }
    for i in 0..num_histograms {
        insert_cost[i] = fast_log2(histograms[i].total_count_ as u32 as usize);
    }
    let mut i = alphabet_size;
    while i != 0 {
        // Reverse order to use the 0-th row as a temporary storage.
        i -= 1;
        for j in 0..num_histograms {
            insert_cost[i * num_histograms + j] = insert_cost[j] - bit_cost(histograms[j].data_[i] as usize);
        }
    }

    // After each iteration of this loop, cost[k] will contain the difference
    // between the minimum cost of arriving at the current byte position using
    // entropy code k, and the minimum cost of arriving at the current byte
    // position. This difference is capped at the block switch cost, and if it
    // reaches block switch cost, it means that when we trace back from the
    // last position, we need to switch here.
    for c in cost[..num_histograms].iter_mut() {
        *c = 0.0;
    }
    for s in switch_signal[..length * bitmap_len].iter_mut() {
        *s = 0;
    }
    const PROLOGUE_LENGTH: usize = 2000;
    const MULTIPLIER: f64 = 0.07 / 2000.0;
    for byte_ix in 0..length {
        let ix = byte_ix * bitmap_len;
        let symbol = data[byte_ix].idx();
        let insert_cost_ix = symbol * num_histograms;
        let mut min_cost: f64 = 1e99;
        let mut block_switch_cost = block_switch_bitcost;
        let costs = &mut cost[..num_histograms];
        let ins = &insert_cost[insert_cost_ix..insert_cost_ix + num_histograms];
        for k in 0..num_histograms {
            // We are coding the symbol with entropy code k.
            costs[k] += ins[k];
            if costs[k] < min_cost {
                min_cost = costs[k];
                block_id[byte_ix] = k as u8;
            }
        }
        // More blocks for the beginning.
        if byte_ix < PROLOGUE_LENGTH {
            block_switch_cost *= 0.77 + MULTIPLIER * byte_ix as f64;
        }
        for k in 0..num_histograms {
            costs[k] -= min_cost;
            if costs[k] >= block_switch_cost {
                let mask = (1u32 << (k & 7)) as u8;
                costs[k] = block_switch_cost;
                debug_assert!((k >> 3) < bitmap_len);
                switch_signal[ix + (k >> 3)] |= mask;
            }
        }
    }

    let mut byte_ix = length - 1;
    {
        // Trace back from the last position and switch at the marked places.
        let mut ix = byte_ix * bitmap_len;
        let mut cur_id = block_id[byte_ix];
        while byte_ix > 0 {
            let mask = (1u32 << (cur_id & 7)) as u8;
            debug_assert!(((cur_id as usize) >> 3) < bitmap_len);
            byte_ix -= 1;
            ix -= bitmap_len;
            if switch_signal[ix + (cur_id >> 3) as usize] & mask != 0 && cur_id != block_id[byte_ix] {
                cur_id = block_id[byte_ix];
                num_blocks += 1;
            }
            block_id[byte_ix] = cur_id;
        }
    }
    num_blocks
}

fn remap_block_ids(block_ids: &mut [u8], length: usize, new_id: &mut [u16], num_histograms: usize) -> usize {
    const K_INVALID_ID: u16 = 256;
    let mut next_id: u16 = 0;
    for v in new_id[..num_histograms].iter_mut() {
        *v = K_INVALID_ID;
    }
    for &b in block_ids[..length].iter() {
        debug_assert!((b as usize) < num_histograms);
        if new_id[b as usize] == K_INVALID_ID {
            new_id[b as usize] = next_id;
            next_id += 1;
        }
    }
    for b in block_ids[..length].iter_mut() {
        *b = new_id[*b as usize] as u8;
        debug_assert!((*b as usize) < num_histograms);
    }
    debug_assert!(next_id as usize <= num_histograms);
    next_id as usize
}

fn build_block_histograms<T: SymbolData, const N: usize>(
    data: &[T],
    length: usize,
    block_ids: &[u8],
    num_histograms: usize,
    histograms: &mut [Histogram<N>],
) {
    clear_histograms(&mut histograms[..num_histograms]);
    for i in 0..length {
        histograms[block_ids[i] as usize].add(data[i].idx());
    }
}

/// Given the initial partitioning build partitioning with limited number
/// of histograms (and block types).
fn cluster_blocks<T: SymbolData, const N: usize>(
    m: &MemoryManager,
    data: &[T],
    length: usize,
    num_blocks: usize,
    block_ids: &[u8],
    split: &mut BlockSplit,
) {
    let mut histogram_symbols: Buf<u32> = Buf::new(m, num_blocks);
    let mut u32buf: Buf<u32> = Buf::new(m, num_blocks + 4 * HISTOGRAMS_PER_BATCH);
    let expected_num_clusters = CLUSTERS_PER_BATCH * (num_blocks + HISTOGRAMS_PER_BATCH - 1) / HISTOGRAMS_PER_BATCH;
    let mut all_histograms_size: usize = 0;
    let mut all_histograms: Buf<Histogram<N>> = Buf::new(m, expected_num_clusters);
    let mut cluster_size_size: usize = 0;
    let mut cluster_size: Buf<u32> = Buf::new(m, expected_num_clusters);
    let mut num_clusters: usize = 0;
    let mut histograms: Buf<Histogram<N>> = Buf::new(m, core::cmp::min(num_blocks, HISTOGRAMS_PER_BATCH));
    let mut max_num_pairs: usize = HISTOGRAMS_PER_BATCH * HISTOGRAMS_PER_BATCH / 2;
    let pairs_capacity: usize = max_num_pairs + 1;
    let mut pairs: Buf<HistogramPair> = Buf::new(m, pairs_capacity);
    let mut pos: usize = 0;
    const K_INVALID_INDEX: u32 = u32::MAX;
    // TODO(eustas): move to arena?
    let mut tmp: Buf<Histogram<N>> = Buf::new(m, 2);

    // (C: memset(u32, 0, ...); Buf is zero-initialized.)
    let (sizes, rest) = u32buf.split_at_mut(HISTOGRAMS_PER_BATCH);
    let (new_clusters, rest) = rest.split_at_mut(HISTOGRAMS_PER_BATCH);
    let (symbols, rest) = rest.split_at_mut(HISTOGRAMS_PER_BATCH);
    let (remap, block_lengths) = rest.split_at_mut(HISTOGRAMS_PER_BATCH);

    // Calculate block lengths (convert repeating values -> series length).
    {
        let mut block_idx: usize = 0;
        for i in 0..length {
            debug_assert!(block_idx < num_blocks);
            block_lengths[block_idx] += 1;
            if i + 1 == length || block_ids[i] != block_ids[i + 1] {
                block_idx += 1;
            }
        }
        debug_assert!(block_idx == num_blocks);
    }

    // Pre-cluster blocks (cluster batches).
    let mut i: usize = 0;
    while i < num_blocks {
        let num_to_combine = core::cmp::min(num_blocks - i, HISTOGRAMS_PER_BATCH);
        for j in 0..num_to_combine {
            let block_length = block_lengths[i + j] as usize;
            let h = &mut histograms[j];
            h.clear();
            for _ in 0..block_length {
                h.add(data[pos].idx());
                pos += 1;
            }
            h.bit_cost_ = brotli_population_cost(h);
            new_clusters[j] = j as u32;
            symbols[j] = j as u32;
            sizes[j] = 1;
        }
        let num_new_clusters = brotli_histogram_combine(
            &mut histograms,
            &mut tmp[0],
            sizes,
            symbols,
            new_clusters,
            &mut pairs,
            num_to_combine,
            num_to_combine,
            HISTOGRAMS_PER_BATCH,
            max_num_pairs,
        );
        all_histograms.ensure_capacity(m, all_histograms_size + num_new_clusters);
        cluster_size.ensure_capacity(m, cluster_size_size + num_new_clusters);
        for j in 0..num_new_clusters {
            let nc = new_clusters[j] as usize;
            all_histograms[all_histograms_size] = histograms[nc];
            all_histograms_size += 1;
            cluster_size[cluster_size_size] = sizes[nc];
            cluster_size_size += 1;
            remap[nc] = j as u32;
        }
        for j in 0..num_to_combine {
            histogram_symbols[i + j] = (num_clusters as u32).wrapping_add(remap[symbols[j] as usize]);
        }
        num_clusters += num_new_clusters;
        debug_assert!(num_clusters == cluster_size_size);
        debug_assert!(num_clusters == all_histograms_size);
        i += HISTOGRAMS_PER_BATCH;
    }
    drop(histograms);

    // Final clustering.
    max_num_pairs = core::cmp::min(64 * num_clusters, (num_clusters / 2) * num_clusters);
    if pairs_capacity < max_num_pairs + 1 {
        pairs.free();
        pairs = Buf::new(m, max_num_pairs + 1);
    }
    let mut clusters: Buf<u32> = Buf::new(m, num_clusters);
    for (i, c) in clusters.iter_mut().enumerate() {
        *c = i as u32;
    }
    let num_final_clusters = brotli_histogram_combine(
        &mut all_histograms,
        &mut tmp[0],
        &mut cluster_size,
        &mut histogram_symbols,
        &mut clusters,
        &mut pairs,
        num_clusters,
        num_blocks,
        BROTLI_MAX_NUMBER_OF_BLOCK_TYPES as usize,
        max_num_pairs,
    );
    drop(pairs);
    drop(cluster_size);

    // Assign blocks to final histograms.
    let mut new_index: Buf<u32> = Buf::new(m, num_clusters);
    for v in new_index.iter_mut() {
        *v = K_INVALID_INDEX;
    }
    pos = 0;
    {
        let mut next_index: u32 = 0;
        let (t0, t1) = tmp.split_at_mut(1);
        let cur = &mut t0[0];
        let scratch = &mut t1[0];
        for i in 0..num_blocks {
            cur.clear();
            for _ in 0..block_lengths[i] {
                cur.add(data[pos].idx());
                pos += 1;
            }
            // Among equally good histograms prefer last used.
            // TODO(eustas): should we give a block-switch discount here?
            let mut best_out = if i == 0 { histogram_symbols[0] } else { histogram_symbols[i - 1] };
            let mut best_bits = brotli_histogram_bit_cost_distance(cur, &all_histograms[best_out as usize], scratch);
            for &c in clusters[..num_final_clusters].iter() {
                let cur_bits = brotli_histogram_bit_cost_distance(cur, &all_histograms[c as usize], scratch);
                if cur_bits < best_bits {
                    best_bits = cur_bits;
                    best_out = c;
                }
            }
            histogram_symbols[i] = best_out;
            if new_index[best_out as usize] == K_INVALID_INDEX {
                new_index[best_out as usize] = next_index;
                next_index += 1;
            }
        }
    }
    drop(tmp);
    drop(clusters);
    drop(all_histograms);
    split.types.ensure_capacity(m, num_blocks);
    split.lengths.ensure_capacity(m, num_blocks);

    // Rewrite final assignment to block-split. There might be less blocks
    // than |num_blocks| due to clustering.
    {
        let mut cur_length: u32 = 0;
        let mut block_idx: usize = 0;
        let mut max_type: u8 = 0;
        for i in 0..num_blocks {
            cur_length = cur_length.wrapping_add(block_lengths[i]);
            if i + 1 == num_blocks || histogram_symbols[i] != histogram_symbols[i + 1] {
                let id = new_index[histogram_symbols[i] as usize] as u8;
                split.types[block_idx] = id;
                split.lengths[block_idx] = cur_length;
                max_type = core::cmp::max(max_type, id);
                cur_length = 0;
                block_idx += 1;
            }
        }
        split.num_blocks = block_idx;
        split.num_types = max_type as usize + 1;
    }
}

/// Create BlockSplit (partitioning) given the limits, estimates and "effort"
/// parameters.
///
/// NB: max_histograms is often less than number of histograms allowed by
///     format; this is done intentionally, to save some "space" for
///     context-aware clustering (here entropy is estimated for context-free
///     symbols).
#[allow(clippy::too_many_arguments)]
fn split_byte_vector<T: SymbolData, const N: usize>(
    m: &MemoryManager,
    data: &[T],
    length: usize,
    symbols_per_histogram: usize,
    max_histograms: usize,
    sampling_stride_length: usize,
    block_switch_cost: f64,
    params: &BrotliEncoderParams,
    split: &mut BlockSplit,
) {
    let data_size = N;
    // Calculate number of histograms; initial estimate is one histogram per
    // specified amount of symbols; however, this value is capped.
    let mut num_histograms = length / symbols_per_histogram + 1;
    if num_histograms > max_histograms {
        num_histograms = max_histograms;
    }

    // Corner case: no input.
    if length == 0 {
        split.num_types = 1;
        return;
    }

    if length < K_MIN_LENGTH_FOR_BLOCK_SPLITTING {
        split.types.ensure_capacity(m, split.num_blocks + 1);
        split.lengths.ensure_capacity(m, split.num_blocks + 1);
        split.num_types = 1;
        split.types[split.num_blocks] = 0;
        split.lengths[split.num_blocks] = length as u32;
        split.num_blocks += 1;
        return;
    }
    let mut histograms: Buf<Histogram<N>> = Buf::new(m, num_histograms + 1);
    // Find good entropy codes.
    initial_entropy_codes(data, length, sampling_stride_length, num_histograms, &mut histograms);
    {
        let (h, t) = histograms.split_at_mut(num_histograms);
        refine_entropy_codes(data, length, sampling_stride_length, num_histograms, h, &mut t[0]);
    }
    {
        // Find a good path through literals with the good entropy codes.
        let mut block_ids: Buf<u8> = Buf::new(m, length);
        let mut num_blocks: usize = 0;
        let bitmaplen = (num_histograms + 7) >> 3;
        let mut insert_cost: Buf<f64> = Buf::new(m, data_size * num_histograms);
        let mut cost: Buf<f64> = Buf::new(m, num_histograms);
        let mut switch_signal: Buf<u8> = Buf::new(m, length * bitmaplen);
        let mut new_id: Buf<u16> = Buf::new(m, num_histograms);
        let iters = if params.quality < HQ_ZOPFLIFICATION_QUALITY { 3 } else { 10 };
        for _ in 0..iters {
            num_blocks = find_blocks(
                data,
                length,
                block_switch_cost,
                num_histograms,
                &histograms,
                &mut insert_cost,
                &mut cost,
                &mut switch_signal,
                &mut block_ids,
            );
            num_histograms = remap_block_ids(&mut block_ids, length, &mut new_id, num_histograms);
            build_block_histograms(data, length, &block_ids, num_histograms, &mut histograms);
        }
        drop(insert_cost);
        drop(cost);
        drop(switch_signal);
        drop(new_id);
        drop(histograms);
        cluster_blocks::<T, N>(m, data, length, num_blocks, &block_ids, split);
    }
}

/// `BrotliSplitBlock`: extracts literals, command distance and prefix codes,
/// then applies SplitByteVector to create partitioning.
#[allow(clippy::too_many_arguments)]
pub fn brotli_split_block(
    m: &MemoryManager,
    cmds: &[Command],
    data: &[u8],
    pos: usize,
    mask: usize,
    params: &BrotliEncoderParams,
    literal_split: &mut BlockSplit,
    insert_and_copy_split: &mut BlockSplit,
    dist_split: &mut BlockSplit,
) {
    let num_commands = cmds.len();
    {
        let literals_count = count_literals(cmds);
        let mut literals: Buf<u8> = Buf::new(m, literals_count);
        // Create a continuous array of literals.
        copy_literals_to_byte_array(cmds, data, pos, mask, &mut literals);
        // Create the block split on the array of literals.
        // Literal histograms can have alphabet size up to 256.
        // Though, to accommodate context modeling, less than half of maximum
        // size is allowed.
        split_byte_vector::<u8, BROTLI_NUM_LITERAL_SYMBOLS>(
            m,
            &literals,
            literals_count,
            K_SYMBOLS_PER_LITERAL_HISTOGRAM,
            K_MAX_LITERAL_HISTOGRAMS,
            K_LITERAL_STRIDE_LENGTH,
            K_LITERAL_BLOCK_SWITCH_COST,
            params,
            literal_split,
        );
        // NB: this might be a good place for injecting extra splitting without
        //     increasing encoder complexity; however, output partition would be
        //     less optimal than one produced with forced splitting inside
        //     SplitByteVector (FindBlocks / ClusterBlocks).
    }

    {
        // Compute prefix codes for commands.
        let mut insert_and_copy_codes: Buf<u16> = Buf::new(m, num_commands);
        for (dst, c) in insert_and_copy_codes.iter_mut().zip(cmds.iter()) {
            *dst = c.cmd_prefix_;
        }
        // Create the block split on the array of command prefixes.
        split_byte_vector::<u16, BROTLI_NUM_COMMAND_SYMBOLS>(
            m,
            &insert_and_copy_codes,
            num_commands,
            K_SYMBOLS_PER_COMMAND_HISTOGRAM,
            K_MAX_COMMAND_HISTOGRAMS,
            K_COMMAND_STRIDE_LENGTH,
            K_COMMAND_BLOCK_SWITCH_COST,
            params,
            insert_and_copy_split,
        );
        // TODO(eustas): reuse for distances?
    }

    {
        // Create a continuous array of distance prefixes.
        let mut distance_prefixes: Buf<u16> = Buf::new(m, num_commands);
        let mut j: usize = 0;
        for c in cmds {
            if c.copy_len() != 0 && c.cmd_prefix_ >= 128 {
                distance_prefixes[j] = c.dist_prefix_ & 0x3FF;
                j += 1;
            }
        }
        // Create the block split on the array of distance prefixes.
        split_byte_vector::<u16, BROTLI_NUM_HISTOGRAM_DISTANCE_SYMBOLS>(
            m,
            &distance_prefixes[..j],
            j,
            K_SYMBOLS_PER_DISTANCE_HISTOGRAM,
            K_MAX_COMMAND_HISTOGRAMS,
            K_DISTANCE_STRIDE_LENGTH,
            K_DISTANCE_BLOCK_SWITCH_COST,
            params,
            dist_split,
        );
    }
}
