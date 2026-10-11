//! Port of `c/enc/metablock.h` / `metablock.c` / `metablock_inc.h`:
//! algorithms for distributing the literals and commands of a metablock
//! between block types and contexts.
//!
//! OWNER: worker "entropy".

use super::bit_cost::{brotli_bits_entropy, brotli_population_cost};
use super::block_splitter::{brotli_split_block, BlockSplit};
use super::cluster::brotli_cluster_histograms;
use super::command::Command;
use super::entropy_encode::brotli_optimize_huffman_counts_for_rle;
use super::histogram::{
    brotli_build_histograms_with_context, clear_histograms, Histogram, HistogramCommand, HistogramDistance,
    HistogramLiteral,
};
use super::memory::{Buf, MemoryManager};
use super::params::{Base64Region, BrotliDistanceParams, BrotliEncoderParams};
use super::prefix::prefix_encode_copy_distance;
use crate::common::constants::{
    brotli_calculate_distance_code_limit, brotli_distance_alphabet_size, BROTLI_DISTANCE_CONTEXT_BITS,
    BROTLI_LARGE_MAX_DISTANCE_BITS, BROTLI_LITERAL_CONTEXT_BITS, BROTLI_MAX_ALLOWED_DISTANCE, BROTLI_MAX_DISTANCE_BITS,
    BROTLI_MAX_NPOSTFIX, BROTLI_MAX_NUMBER_OF_BLOCK_TYPES, BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS,
};
use crate::common::context::{brotli_context, ContextLut, ContextType};

pub const BROTLI_MAX_STATIC_CONTEXTS: usize = 13;

/// `MetaBlockSplit`.  Sizes of the `Buf`s are the allocated capacities; the
/// `*_size` fields hold the number of used entries (as in C).
pub struct MetaBlockSplit {
    pub literal_split: BlockSplit,
    pub command_split: BlockSplit,
    pub distance_split: BlockSplit,
    pub literal_context_map: Buf<u32>,
    pub literal_context_map_size: usize,
    pub distance_context_map: Buf<u32>,
    pub distance_context_map_size: usize,
    pub literal_histograms: Buf<HistogramLiteral>,
    pub literal_histograms_size: usize,
    pub command_histograms: Buf<HistogramCommand>,
    pub command_histograms_size: usize,
    pub distance_histograms: Buf<HistogramDistance>,
    pub distance_histograms_size: usize,
    pub literal_is_base64: [u8; 32],
}

impl Default for MetaBlockSplit {
    fn default() -> Self {
        Self::new()
    }
}

impl MetaBlockSplit {
    /// `InitMetaBlockSplit`.  (`DestroyMetaBlockSplit` == drop.)
    pub fn new() -> Self {
        MetaBlockSplit {
            literal_split: BlockSplit::new(),
            command_split: BlockSplit::new(),
            distance_split: BlockSplit::new(),
            literal_context_map: Buf::empty(),
            literal_context_map_size: 0,
            distance_context_map: Buf::empty(),
            distance_context_map_size: 0,
            literal_histograms: Buf::empty(),
            literal_histograms_size: 0,
            command_histograms: Buf::empty(),
            command_histograms_size: 0,
            distance_histograms: Buf::empty(),
            distance_histograms_size: 0,
            literal_is_base64: [0; 32],
        }
    }
}

const MAX_LOCAL_BASE64_REGIONS: usize = 256;

/// `ForceBase64LiteralSplits`.
fn force_base64_literal_splits(
    m: &MemoryManager,
    split: &mut BlockSplit,
    base64_regions: &[Base64Region],
    last_flush_pos: usize,
    literal_is_base64: &mut [u8; 32],
) {
    let num_base64_regions = base64_regions.len();
    // Each base64 region can split an existing block into at most 3 blocks
    // (adding 2 new blocks). In the worst case, every base64 region splits
    // a different block, increasing the number of blocks by 2 *
    // num_base64_regions. We add 1 extra block as a safety margin.
    let new_alloc_size = split.num_blocks + num_base64_regions * 2 + 1;
    let mut new_types: Buf<u8> = Buf::new(m, new_alloc_size);
    let mut new_lengths: Buf<u32> = Buf::new(m, new_alloc_size);
    let mut new_num_blocks: usize = 0;
    let mut curr_offset: usize = 0;

    *literal_is_base64 = [0; 32];
    let base64_type_id = split.num_types as u8;
    literal_is_base64[(base64_type_id >> 3) as usize] |= (1u32 << (base64_type_id & 7)) as u8;

    for block_idx in 0..split.num_blocks {
        let mut block_len = split.lengths[block_idx];
        let block_type = split.types[block_idx];
        let mut block_start = curr_offset;
        let block_end = curr_offset.wrapping_add(block_len as usize);

        let mut intersected = false;
        for region in base64_regions.iter() {
            let b64_start = region.start_literal_pos.wrapping_sub(last_flush_pos);
            let b64_end = b64_start.wrapping_add(region.length);

            if b64_start < block_end && b64_end > block_start {
                if b64_start > block_start {
                    new_types[new_num_blocks] = block_type;
                    new_lengths[new_num_blocks] = (b64_start - block_start) as u32;
                    new_num_blocks += 1;
                }
                let intersect_start = core::cmp::max(block_start, b64_start);
                let intersect_end = core::cmp::min(block_end, b64_end);
                new_types[new_num_blocks] = base64_type_id;
                new_lengths[new_num_blocks] = intersect_end.wrapping_sub(intersect_start) as u32;
                new_num_blocks += 1;

                if b64_end < block_end {
                    block_start = b64_end;
                    block_len = (block_end - b64_end) as u32;
                    continue;
                } else {
                    block_len = 0;
                    intersected = true;
                    break;
                }
            }
        }

        if !intersected && block_len > 0 {
            new_types[new_num_blocks] = block_type;
            new_lengths[new_num_blocks] = block_len;
            new_num_blocks += 1;
        }
        curr_offset = block_end;
    }

    split.types = new_types;
    split.lengths = new_lengths;
    split.num_blocks = new_num_blocks;
    split.num_types += 1;
}

/// `AppendBase64Histogram`.
fn append_base64_histogram(m: &MemoryManager, mb: &mut MetaBlockSplit) {
    let base64_type_id = mb.literal_split.num_types - 1;
    let b64_histo_id = mb.literal_histograms_size;
    let new_context_map_size = mb.literal_split.num_types << BROTLI_LITERAL_CONTEXT_BITS;
    let mut new_histos: Buf<HistogramLiteral> = Buf::new(m, mb.literal_histograms_size + 1);
    let mut new_context_map: Buf<u32> = Buf::new(m, new_context_map_size);
    new_histos[..mb.literal_histograms_size].copy_from_slice(&mb.literal_histograms[..mb.literal_histograms_size]);
    mb.literal_histograms = new_histos;
    mb.literal_histograms[b64_histo_id].clear();
    mb.literal_histograms_size += 1;

    if !mb.literal_context_map.is_empty() {
        new_context_map[..mb.literal_context_map_size]
            .copy_from_slice(&mb.literal_context_map[..mb.literal_context_map_size]);
    } else {
        // If context map was NULL (num_contexts == 1), initialize preceding
        // types.
        for t in 0..base64_type_id {
            for i in 0..64 {
                new_context_map[(t << 6) + i] = t as u32;
            }
        }
    }
    mb.literal_context_map = new_context_map;
    mb.literal_context_map_size = new_context_map_size;
    for i in 0..64 {
        mb.literal_context_map[(base64_type_id << 6) + i] = b64_histo_id as u32;
    }
}

/// `MapBase64RegionsToLiteralPositions`.
fn map_base64_regions_to_literal_positions(
    commands: &[Command],
    last_flush_pos: usize,
    in_regions: &[Base64Region],
    out_regions: &mut [Base64Region],
) {
    for (r, region) in in_regions.iter().enumerate() {
        let target_ring_pos = region.start_literal_pos;
        let mut curr_ring_pos = last_flush_pos;
        let mut curr_lit_pos: usize = 0;
        for cmd in commands.iter() {
            let insert_len = cmd.insert_len_ as usize;
            if curr_ring_pos.wrapping_add(insert_len) >= target_ring_pos {
                let offset = target_ring_pos.saturating_sub(curr_ring_pos);
                curr_lit_pos = curr_lit_pos.wrapping_add(offset);
                break;
            }
            curr_lit_pos = curr_lit_pos.wrapping_add(insert_len);
            curr_ring_pos = curr_ring_pos.wrapping_add(insert_len + cmd.copy_len() as usize);
        }
        out_regions[r].start_literal_pos = curr_lit_pos;
        out_regions[r].length = region.length;
    }
}

/// `BrotliInitDistanceParams`.
pub fn brotli_init_distance_params(params: &mut BrotliDistanceParams, npostfix: u32, ndirect: u32, large_window: bool) {
    params.distance_postfix_bits = npostfix;
    params.num_direct_distance_codes = ndirect;

    let mut alphabet_size_max = brotli_distance_alphabet_size(npostfix, ndirect, BROTLI_MAX_DISTANCE_BITS);
    let mut alphabet_size_limit = alphabet_size_max;
    let mut max_distance: u32 = ndirect
        .wrapping_add(1u32 << (BROTLI_MAX_DISTANCE_BITS + npostfix + 2))
        .wrapping_sub(1u32 << (npostfix + 2));

    if large_window {
        let limit = brotli_calculate_distance_code_limit(BROTLI_MAX_ALLOWED_DISTANCE as u32, npostfix, ndirect);
        alphabet_size_max = brotli_distance_alphabet_size(npostfix, ndirect, BROTLI_LARGE_MAX_DISTANCE_BITS);
        alphabet_size_limit = limit.max_alphabet_size;
        max_distance = limit.max_distance;
    }

    params.alphabet_size_max = alphabet_size_max;
    params.alphabet_size_limit = alphabet_size_limit;
    params.max_distance = max_distance as usize;
}

fn recompute_distance_prefixes(cmds: &mut [Command], orig_params: &BrotliDistanceParams, new_params: &BrotliDistanceParams) {
    if orig_params.distance_postfix_bits == new_params.distance_postfix_bits
        && orig_params.num_direct_distance_codes == new_params.num_direct_distance_codes
    {
        return;
    }

    for cmd in cmds.iter_mut() {
        if cmd.copy_len() != 0 && cmd.cmd_prefix_ >= 128 {
            let (prefix, extra) = prefix_encode_copy_distance(
                cmd.restore_distance_code(orig_params) as usize,
                new_params.num_direct_distance_codes as usize,
                new_params.distance_postfix_bits as usize,
            );
            cmd.dist_prefix_ = prefix;
            cmd.dist_extra_ = extra;
        }
    }
}

fn compute_distance_cost(
    cmds: &[Command],
    orig_params: &BrotliDistanceParams,
    new_params: &BrotliDistanceParams,
    cost: &mut f64,
    tmp: &mut HistogramDistance,
) -> bool {
    let mut equal_params = false;
    let mut extra_bits: f64 = 0.0;
    tmp.clear();

    if orig_params.distance_postfix_bits == new_params.distance_postfix_bits
        && orig_params.num_direct_distance_codes == new_params.num_direct_distance_codes
    {
        equal_params = true;
    }

    for cmd in cmds.iter() {
        if cmd.copy_len() != 0 && cmd.cmd_prefix_ >= 128 {
            let dist_prefix: u16 = if equal_params {
                cmd.dist_prefix_
            } else {
                let distance = cmd.restore_distance_code(orig_params);
                if distance as usize > new_params.max_distance {
                    return false;
                }
                let (prefix, _extra) = prefix_encode_copy_distance(
                    distance as usize,
                    new_params.num_direct_distance_codes as usize,
                    new_params.distance_postfix_bits as usize,
                );
                prefix
            };
            tmp.add((dist_prefix & 0x3FF) as usize);
            extra_bits += (dist_prefix >> 10) as f64;
        }
    }

    *cost = brotli_population_cost(tmp) + extra_bits;
    true
}

/// `BrotliBuildMetaBlock`: uses the slow shortest-path block splitter and
/// does context clustering.  `ringbuffer` is the ring buffer (`buffer_`),
/// addressed with `& mask`.  `cmds` are the commands of the metablock.
///
/// The distance parameters are dynamically selected based on the commands
/// which get recomputed under the new distance parameters. The new distance
/// parameters are stored into `params`.
#[allow(clippy::too_many_arguments)]
pub fn brotli_build_meta_block(
    m: &MemoryManager,
    ringbuffer: &[u8],
    pos: usize,
    mask: usize,
    base64_regions: &[Base64Region],
    params: &mut BrotliEncoderParams,
    prev_byte: u8,
    prev_byte2: u8,
    cmds: &mut [Command],
    literal_context_mode: ContextType,
    mb: &mut MetaBlockSplit,
) {
    // Histogram ids need to fit in one byte.
    const K_MAX_NUMBER_OF_HISTOGRAMS: usize = 256;
    let mut literal_context_multiplier: usize = 1;
    let mut ndirect_msb: u32 = 0;
    let mut check_orig = true;
    let mut best_dist_cost: f64 = 1e99;
    let orig_params = params.dist;
    let mut new_params = params.dist;
    let mut tmp: Buf<HistogramDistance> = Buf::new(m, 1);

    for npostfix in 0..=BROTLI_MAX_NPOSTFIX {
        while ndirect_msb < 16 {
            let ndirect = ndirect_msb << npostfix;
            brotli_init_distance_params(&mut new_params, npostfix, ndirect, params.large_window);
            if npostfix == orig_params.distance_postfix_bits && ndirect == orig_params.num_direct_distance_codes {
                check_orig = false;
            }
            let mut dist_cost: f64 = 0.0;
            let skip = !compute_distance_cost(cmds, &orig_params, &new_params, &mut dist_cost, &mut tmp[0]);
            if skip || dist_cost > best_dist_cost {
                break;
            }
            best_dist_cost = dist_cost;
            params.dist = new_params;
            ndirect_msb += 1;
        }
        // C: if (ndirect_msb > 0) ndirect_msb--;
        ndirect_msb = ndirect_msb.saturating_sub(1);
        ndirect_msb /= 2;
    }
    if check_orig {
        let mut dist_cost: f64 = 0.0;
        compute_distance_cost(cmds, &orig_params, &orig_params, &mut dist_cost, &mut tmp[0]);
        if dist_cost < best_dist_cost {
            // NB: currently unused; uncomment when more param tuning is added.
            // best_dist_cost = dist_cost;
            params.dist = orig_params;
        }
    }
    drop(tmp);
    let new_dist = params.dist;
    recompute_distance_prefixes(cmds, &orig_params, &new_dist);

    brotli_split_block(
        m,
        cmds,
        ringbuffer,
        pos,
        mask,
        params,
        &mut mb.literal_split,
        &mut mb.command_split,
        &mut mb.distance_split,
    );

    let mut literal_context_modes: Buf<ContextType> = Buf::empty();
    if !params.disable_literal_context_modeling {
        literal_context_multiplier = 1 << BROTLI_LITERAL_CONTEXT_BITS;
        literal_context_modes = Buf::new(m, mb.literal_split.num_types);
        for mode in literal_context_modes.iter_mut() {
            *mode = literal_context_mode;
        }
    }

    let literal_histograms_size = mb.literal_split.num_types * literal_context_multiplier;
    let mut literal_histograms: Buf<HistogramLiteral> = Buf::new(m, literal_histograms_size);
    clear_histograms(&mut literal_histograms);

    let distance_histograms_size = mb.distance_split.num_types << BROTLI_DISTANCE_CONTEXT_BITS;
    let mut distance_histograms: Buf<HistogramDistance> = Buf::new(m, distance_histograms_size);
    clear_histograms(&mut distance_histograms);

    debug_assert!(mb.command_histograms.is_empty());
    mb.command_histograms_size = mb.command_split.num_types;
    mb.command_histograms = Buf::new(m, mb.command_histograms_size);
    clear_histograms(&mut mb.command_histograms);

    brotli_build_histograms_with_context(
        cmds,
        &mb.literal_split,
        &mb.command_split,
        &mb.distance_split,
        ringbuffer,
        pos,
        mask,
        prev_byte,
        prev_byte2,
        if params.disable_literal_context_modeling { None } else { Some(&literal_context_modes[..]) },
        &mut literal_histograms,
        &mut mb.command_histograms,
        &mut distance_histograms,
    );
    drop(literal_context_modes);

    debug_assert!(mb.literal_context_map.is_empty());
    mb.literal_context_map_size = mb.literal_split.num_types << BROTLI_LITERAL_CONTEXT_BITS;
    mb.literal_context_map = Buf::new(m, mb.literal_context_map_size);

    debug_assert!(mb.literal_histograms.is_empty());
    mb.literal_histograms_size = mb.literal_context_map_size;
    mb.literal_histograms = Buf::new(m, mb.literal_histograms_size);

    brotli_cluster_histograms(
        m,
        &literal_histograms,
        literal_histograms_size,
        K_MAX_NUMBER_OF_HISTOGRAMS,
        &mut mb.literal_histograms,
        &mut mb.literal_histograms_size,
        &mut mb.literal_context_map,
    );
    drop(literal_histograms);

    if params.disable_literal_context_modeling {
        // Distribute assignment to all contexts.
        let mut i = mb.literal_split.num_types;
        while i != 0 {
            i -= 1;
            for j in 0..(1usize << BROTLI_LITERAL_CONTEXT_BITS) {
                mb.literal_context_map[(i << BROTLI_LITERAL_CONTEXT_BITS) + j] = mb.literal_context_map[i];
            }
        }
    }

    if !base64_regions.is_empty() && mb.literal_split.num_types < 256 && mb.literal_histograms_size < 256 {
        let mut local_b64 = [Base64Region::default(); MAX_LOCAL_BASE64_REGIONS];
        let safe_num_b64 = core::cmp::min(base64_regions.len(), MAX_LOCAL_BASE64_REGIONS);
        map_base64_regions_to_literal_positions(cmds, pos, &base64_regions[..safe_num_b64], &mut local_b64);
        force_base64_literal_splits(m, &mut mb.literal_split, &local_b64[..safe_num_b64], 0, &mut mb.literal_is_base64);
        append_base64_histogram(m, mb);
    }

    debug_assert!(mb.distance_context_map.is_empty());
    mb.distance_context_map_size = mb.distance_split.num_types << BROTLI_DISTANCE_CONTEXT_BITS;
    mb.distance_context_map = Buf::new(m, mb.distance_context_map_size);

    debug_assert!(mb.distance_histograms.is_empty());
    mb.distance_histograms_size = mb.distance_context_map_size;
    mb.distance_histograms = Buf::new(m, mb.distance_histograms_size);

    brotli_cluster_histograms(
        m,
        &distance_histograms,
        mb.distance_context_map_size,
        K_MAX_NUMBER_OF_HISTOGRAMS,
        &mut mb.distance_histograms,
        &mut mb.distance_histograms_size,
        &mut mb.distance_context_map,
    );
    drop(distance_histograms);
}

/// Greedy block splitter for one block category (literal, command or
/// distance) (`BlockSplitter{Literal,Command,Distance}`, template
/// `metablock_inc.h`).
struct BlockSplitter<const N: usize> {
    /// Alphabet size of particular block category.
    alphabet_size_: usize,
    /// We collect at least this many symbols for each block.
    min_block_size_: usize,
    /// We merge histograms A and B if
    ///   entropy(A+B) < entropy(A) + entropy(B) + split_threshold_,
    /// where A is the current histogram and B is the histogram of the last or
    /// the second last block type.
    split_threshold_: f64,

    num_blocks_: usize,

    /// Temporary storage for BlockSplitterFinishBlock.
    combined_histo: Buf<Histogram<N>>,

    /// The number of symbols that we want to collect before deciding on
    /// whether or not to merge the block with a previous one or emit a new
    /// block.
    target_block_size_: usize,
    /// The number of symbols in the current histogram.
    block_size_: usize,
    /// Offset of the current histogram.
    curr_histogram_ix_: usize,
    /// Offset of the histograms of the previous two block types.
    last_histogram_ix_: [usize; 2],
    /// Entropy of the previous two block types.
    last_entropy_: [f64; 2],
    /// The number of times we merged the current block with the last one.
    merge_last_count_: usize,
}

impl<const N: usize> BlockSplitter<N> {
    /// `InitBlockSplitter`.
    #[allow(clippy::too_many_arguments)]
    fn new(
        m: &MemoryManager,
        alphabet_size: usize,
        min_block_size: usize,
        split_threshold: f64,
        num_symbols: usize,
        split: &mut BlockSplit,
        histograms: &mut Buf<Histogram<N>>,
        histograms_size: &mut usize,
    ) -> Self {
        let max_num_blocks = num_symbols / min_block_size + 1;
        // We have to allocate one more histogram than the maximum number of
        // block types for the current histogram when the meta-block is too
        // big.
        let max_num_types = core::cmp::min(max_num_blocks, BROTLI_MAX_NUMBER_OF_BLOCK_TYPES as usize + 1);
        split.types.ensure_capacity(m, max_num_blocks);
        split.lengths.ensure_capacity(m, max_num_blocks);
        split.num_blocks = max_num_blocks;
        debug_assert!(histograms.is_empty());
        *histograms_size = max_num_types;
        *histograms = Buf::new(m, *histograms_size);
        // Clear only current histogram.
        histograms[0].clear();
        BlockSplitter {
            alphabet_size_: alphabet_size,
            min_block_size_: min_block_size,
            split_threshold_: split_threshold,
            num_blocks_: 0,
            combined_histo: Buf::new(m, 2),
            target_block_size_: min_block_size,
            block_size_: 0,
            curr_histogram_ix_: 0,
            last_histogram_ix_: [0, 0],
            last_entropy_: [0.0, 0.0],
            merge_last_count_: 0,
        }
    }

    /// `BlockSplitterFinishBlock`: does either of three things:
    ///   (1) emits the current block with a new block type;
    ///   (2) emits the current block with the type of the second last block;
    ///   (3) merges the current block with the last block.
    fn finish_block(
        &mut self,
        is_final: bool,
        split: &mut BlockSplit,
        histograms: &mut [Histogram<N>],
        histograms_size: &mut usize,
    ) {
        self.block_size_ = core::cmp::max(self.block_size_, self.min_block_size_);
        if self.num_blocks_ == 0 {
            // Create first block.
            split.lengths[0] = self.block_size_ as u32;
            split.types[0] = 0;
            self.last_entropy_[0] = brotli_bits_entropy(&histograms[0].data_, self.alphabet_size_);
            self.last_entropy_[1] = self.last_entropy_[0];
            self.num_blocks_ += 1;
            split.num_types += 1;
            self.curr_histogram_ix_ += 1;
            if self.curr_histogram_ix_ < *histograms_size {
                histograms[self.curr_histogram_ix_].clear();
            }
            self.block_size_ = 0;
        } else if self.block_size_ > 0 {
            let curr = self.curr_histogram_ix_;
            let entropy = brotli_bits_entropy(&histograms[curr].data_, self.alphabet_size_);
            let mut combined_entropy = [0.0f64; 2];
            let mut diff = [0.0f64; 2];
            for j in 0..2 {
                let last_histogram_ix = self.last_histogram_ix_[j];
                self.combined_histo[j] = histograms[curr];
                self.combined_histo[j].add_histogram(&histograms[last_histogram_ix]);
                combined_entropy[j] = brotli_bits_entropy(&self.combined_histo[j].data_, self.alphabet_size_);
                diff[j] = combined_entropy[j] - entropy - self.last_entropy_[j];
            }

            if split.num_types < BROTLI_MAX_NUMBER_OF_BLOCK_TYPES as usize
                && diff[0] > self.split_threshold_
                && diff[1] > self.split_threshold_
            {
                // Create new block.
                split.lengths[self.num_blocks_] = self.block_size_ as u32;
                split.types[self.num_blocks_] = split.num_types as u8;
                self.last_histogram_ix_[1] = self.last_histogram_ix_[0];
                self.last_histogram_ix_[0] = split.num_types as u8 as usize;
                self.last_entropy_[1] = self.last_entropy_[0];
                self.last_entropy_[0] = entropy;
                self.num_blocks_ += 1;
                split.num_types += 1;
                self.curr_histogram_ix_ += 1;
                if self.curr_histogram_ix_ < *histograms_size {
                    histograms[self.curr_histogram_ix_].clear();
                }
                self.block_size_ = 0;
                self.merge_last_count_ = 0;
                self.target_block_size_ = self.min_block_size_;
            } else if diff[1] < diff[0] - 20.0 {
                // Combine this block with second last block.
                split.lengths[self.num_blocks_] = self.block_size_ as u32;
                split.types[self.num_blocks_] = split.types[self.num_blocks_ - 2];
                self.last_histogram_ix_.swap(0, 1);
                histograms[self.last_histogram_ix_[0]] = self.combined_histo[1];
                self.last_entropy_[1] = self.last_entropy_[0];
                self.last_entropy_[0] = combined_entropy[1];
                self.num_blocks_ += 1;
                self.block_size_ = 0;
                histograms[curr].clear();
                self.merge_last_count_ = 0;
                self.target_block_size_ = self.min_block_size_;
            } else {
                // Combine this block with last block.
                split.lengths[self.num_blocks_ - 1] =
                    split.lengths[self.num_blocks_ - 1].wrapping_add(self.block_size_ as u32);
                histograms[self.last_histogram_ix_[0]] = self.combined_histo[0];
                self.last_entropy_[0] = combined_entropy[0];
                if split.num_types == 1 {
                    self.last_entropy_[1] = self.last_entropy_[0];
                }
                self.block_size_ = 0;
                histograms[curr].clear();
                self.merge_last_count_ += 1;
                if self.merge_last_count_ > 1 {
                    self.target_block_size_ += self.min_block_size_;
                }
            }
        }
        if is_final {
            *histograms_size = split.num_types;
            split.num_blocks = self.num_blocks_;
        }
    }

    /// `BlockSplitterAddSymbol`: adds the next symbol to the current
    /// histogram. When the current histogram reaches the target size, decides
    /// on merging the block.
    #[inline(always)]
    fn add_symbol(
        &mut self,
        symbol: usize,
        split: &mut BlockSplit,
        histograms: &mut [Histogram<N>],
        histograms_size: &mut usize,
    ) {
        histograms[self.curr_histogram_ix_].add(symbol);
        self.block_size_ += 1;
        if self.block_size_ == self.target_block_size_ {
            self.finish_block(false, split, histograms, histograms_size);
        }
    }
}

/// Greedy block splitter for one block category (literal, command or
/// distance). Gathers histograms for all context buckets.
struct ContextBlockSplitter {
    /// Alphabet size of particular block category.
    alphabet_size_: usize,
    num_contexts_: usize,
    max_block_types_: usize,
    /// We collect at least this many symbols for each block.
    min_block_size_: usize,
    /// We merge histograms A and B if
    ///   entropy(A+B) < entropy(A) + entropy(B) + split_threshold_,
    /// where A is the current histogram and B is the histogram of the last or
    /// the second last block type.
    split_threshold_: f64,

    num_blocks_: usize,

    /// The number of symbols that we want to collect before deciding on
    /// whether or not to merge the block with a previous one or emit a new
    /// block.
    target_block_size_: usize,
    /// The number of symbols in the current histogram.
    block_size_: usize,
    /// Offset of the current histogram.
    curr_histogram_ix_: usize,
    /// Offset of the histograms of the previous two block types.
    last_histogram_ix_: [usize; 2],
    /// Entropy of the previous two block types.
    last_entropy_: [f64; 2 * BROTLI_MAX_STATIC_CONTEXTS],
    /// The number of times we merged the current block with the last one.
    merge_last_count_: usize,
}

impl ContextBlockSplitter {
    /// `InitContextBlockSplitter`.
    #[allow(clippy::too_many_arguments)]
    fn new(
        m: &MemoryManager,
        alphabet_size: usize,
        num_contexts: usize,
        min_block_size: usize,
        split_threshold: f64,
        num_symbols: usize,
        split: &mut BlockSplit,
        histograms: &mut Buf<HistogramLiteral>,
        histograms_size: &mut usize,
    ) -> Self {
        let max_num_blocks = num_symbols / min_block_size + 1;
        debug_assert!(num_contexts <= BROTLI_MAX_STATIC_CONTEXTS);
        let max_block_types = BROTLI_MAX_NUMBER_OF_BLOCK_TYPES as usize / num_contexts;

        // We have to allocate one more histogram than the maximum number of
        // block types for the current histogram when the meta-block is too
        // big.
        let max_num_types = core::cmp::min(max_num_blocks, max_block_types + 1);
        split.types.ensure_capacity(m, max_num_blocks);
        split.lengths.ensure_capacity(m, max_num_blocks);
        split.num_blocks = max_num_blocks;
        debug_assert!(histograms.is_empty());
        *histograms_size = max_num_types * num_contexts;
        *histograms = Buf::new(m, *histograms_size);
        // Clear only current histogram.
        clear_histograms(&mut histograms[..num_contexts]);
        ContextBlockSplitter {
            alphabet_size_: alphabet_size,
            num_contexts_: num_contexts,
            max_block_types_: max_block_types,
            min_block_size_: min_block_size,
            split_threshold_: split_threshold,
            num_blocks_: 0,
            target_block_size_: min_block_size,
            block_size_: 0,
            curr_histogram_ix_: 0,
            last_histogram_ix_: [0, 0],
            last_entropy_: [0.0; 2 * BROTLI_MAX_STATIC_CONTEXTS],
            merge_last_count_: 0,
        }
    }

    /// `ContextBlockSplitterFinishBlock`: does either of three things:
    ///   (1) emits the current block with a new block type;
    ///   (2) emits the current block with the type of the second last block;
    ///   (3) merges the current block with the last block.
    fn finish_block(
        &mut self,
        m: &MemoryManager,
        is_final: bool,
        split: &mut BlockSplit,
        histograms: &mut [HistogramLiteral],
        histograms_size: &mut usize,
    ) {
        let num_contexts = self.num_contexts_;
        let last_entropy = &mut self.last_entropy_;

        if self.block_size_ < self.min_block_size_ {
            self.block_size_ = self.min_block_size_;
        }
        if self.num_blocks_ == 0 {
            // Create first block.
            split.lengths[0] = self.block_size_ as u32;
            split.types[0] = 0;

            for i in 0..num_contexts {
                last_entropy[i] = brotli_bits_entropy(&histograms[i].data_, self.alphabet_size_);
                last_entropy[num_contexts + i] = last_entropy[i];
            }
            self.num_blocks_ += 1;
            split.num_types += 1;
            self.curr_histogram_ix_ += num_contexts;
            if self.curr_histogram_ix_ < *histograms_size {
                clear_histograms(&mut histograms[self.curr_histogram_ix_..self.curr_histogram_ix_ + num_contexts]);
            }
            self.block_size_ = 0;
        } else if self.block_size_ > 0 {
            // Try merging the set of histograms for the current block type
            // with the respective set of histograms for the last and second
            // last block types. Decide over the split based on the total
            // reduction of entropy across all contexts.
            let mut entropy = [0.0f64; BROTLI_MAX_STATIC_CONTEXTS];
            let mut combined_histo: Buf<HistogramLiteral> = Buf::new(m, 2 * num_contexts);
            let mut combined_entropy = [0.0f64; 2 * BROTLI_MAX_STATIC_CONTEXTS];
            let mut diff = [0.0f64; 2];
            for i in 0..num_contexts {
                let curr_histo_ix = self.curr_histogram_ix_ + i;
                entropy[i] = brotli_bits_entropy(&histograms[curr_histo_ix].data_, self.alphabet_size_);
                for j in 0..2 {
                    let jx = j * num_contexts + i;
                    let last_histogram_ix = self.last_histogram_ix_[j] + i;
                    combined_histo[jx] = histograms[curr_histo_ix];
                    combined_histo[jx].add_histogram(&histograms[last_histogram_ix]);
                    combined_entropy[jx] = brotli_bits_entropy(&combined_histo[jx].data_, self.alphabet_size_);
                    diff[j] += combined_entropy[jx] - entropy[i] - last_entropy[jx];
                }
            }

            if split.num_types < self.max_block_types_ && diff[0] > self.split_threshold_ && diff[1] > self.split_threshold_ {
                // Create new block.
                split.lengths[self.num_blocks_] = self.block_size_ as u32;
                split.types[self.num_blocks_] = split.num_types as u8;
                self.last_histogram_ix_[1] = self.last_histogram_ix_[0];
                self.last_histogram_ix_[0] = split.num_types * num_contexts;
                for i in 0..num_contexts {
                    last_entropy[num_contexts + i] = last_entropy[i];
                    last_entropy[i] = entropy[i];
                }
                self.num_blocks_ += 1;
                split.num_types += 1;
                self.curr_histogram_ix_ += num_contexts;
                if self.curr_histogram_ix_ < *histograms_size {
                    clear_histograms(&mut histograms[self.curr_histogram_ix_..self.curr_histogram_ix_ + num_contexts]);
                }
                self.block_size_ = 0;
                self.merge_last_count_ = 0;
                self.target_block_size_ = self.min_block_size_;
            } else if diff[1] < diff[0] - 20.0 {
                // Combine this block with second last block.
                split.lengths[self.num_blocks_] = self.block_size_ as u32;
                split.types[self.num_blocks_] = split.types[self.num_blocks_ - 2];
                self.last_histogram_ix_.swap(0, 1);
                for i in 0..num_contexts {
                    histograms[self.last_histogram_ix_[0] + i] = combined_histo[num_contexts + i];
                    last_entropy[num_contexts + i] = last_entropy[i];
                    last_entropy[i] = combined_entropy[num_contexts + i];
                    histograms[self.curr_histogram_ix_ + i].clear();
                }
                self.num_blocks_ += 1;
                self.block_size_ = 0;
                self.merge_last_count_ = 0;
                self.target_block_size_ = self.min_block_size_;
            } else {
                // Combine this block with last block.
                split.lengths[self.num_blocks_ - 1] =
                    split.lengths[self.num_blocks_ - 1].wrapping_add(self.block_size_ as u32);
                for i in 0..num_contexts {
                    histograms[self.last_histogram_ix_[0] + i] = combined_histo[i];
                    last_entropy[i] = combined_entropy[i];
                    if split.num_types == 1 {
                        last_entropy[num_contexts + i] = last_entropy[i];
                    }
                    histograms[self.curr_histogram_ix_ + i].clear();
                }
                self.block_size_ = 0;
                self.merge_last_count_ += 1;
                if self.merge_last_count_ > 1 {
                    self.target_block_size_ += self.min_block_size_;
                }
            }
        }
        if is_final {
            *histograms_size = split.num_types * num_contexts;
            split.num_blocks = self.num_blocks_;
        }
    }

    /// `ContextBlockSplitterAddSymbol`: adds the next symbol to the current
    /// block type and context. When the current block reaches the target
    /// size, decides on merging the block.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn add_symbol(
        &mut self,
        m: &MemoryManager,
        symbol: usize,
        context: usize,
        split: &mut BlockSplit,
        histograms: &mut [HistogramLiteral],
        histograms_size: &mut usize,
    ) {
        histograms[self.curr_histogram_ix_ + context].add(symbol);
        self.block_size_ += 1;
        if self.block_size_ == self.target_block_size_ {
            self.finish_block(m, false, split, histograms, histograms_size);
        }
    }
}

fn map_static_contexts(m: &MemoryManager, num_contexts: usize, static_context_map: &[u32], mb: &mut MetaBlockSplit) {
    debug_assert!(mb.literal_context_map.is_empty());
    mb.literal_context_map_size = mb.literal_split.num_types << BROTLI_LITERAL_CONTEXT_BITS;
    mb.literal_context_map = Buf::new(m, mb.literal_context_map_size);

    for i in 0..mb.literal_split.num_types {
        let offset = (i * num_contexts) as u32;
        for j in 0..(1usize << BROTLI_LITERAL_CONTEXT_BITS) {
            mb.literal_context_map[(i << BROTLI_LITERAL_CONTEXT_BITS) + j] = offset.wrapping_add(static_context_map[j]);
        }
    }
}

enum LiteralBlocks {
    Plain(BlockSplitter<BROTLI_NUM_LITERAL_SYMBOLS>),
    Ctx(ContextBlockSplitter),
}

#[allow(clippy::too_many_arguments)]
fn brotli_build_meta_block_greedy_internal(
    m: &MemoryManager,
    ringbuffer: &[u8],
    mut pos: usize,
    mask: usize,
    base64_regions: &[Base64Region],
    mut prev_byte: u8,
    mut prev_byte2: u8,
    literal_context_lut: ContextLut,
    num_contexts: usize,
    static_context_map: Option<&[u32]>,
    commands: &[Command],
    mb: &mut MetaBlockSplit,
) {
    let start_pos = pos;
    let n_commands = commands.len();
    let mut num_literals: usize = 0;
    for c in commands.iter() {
        num_literals += c.insert_len_ as usize;
    }

    let mut lit_blocks = if num_contexts == 1 {
        LiteralBlocks::Plain(BlockSplitter::new(
            m,
            256,
            512,
            400.0,
            num_literals,
            &mut mb.literal_split,
            &mut mb.literal_histograms,
            &mut mb.literal_histograms_size,
        ))
    } else {
        LiteralBlocks::Ctx(ContextBlockSplitter::new(
            m,
            256,
            num_contexts,
            512,
            400.0,
            num_literals,
            &mut mb.literal_split,
            &mut mb.literal_histograms,
            &mut mb.literal_histograms_size,
        ))
    };
    let mut cmd_blocks: BlockSplitter<BROTLI_NUM_COMMAND_SYMBOLS> = BlockSplitter::new(
        m,
        BROTLI_NUM_COMMAND_SYMBOLS,
        1024,
        500.0,
        n_commands,
        &mut mb.command_split,
        &mut mb.command_histograms,
        &mut mb.command_histograms_size,
    );
    let mut dist_blocks: BlockSplitter<{ super::histogram::BROTLI_NUM_HISTOGRAM_DISTANCE_SYMBOLS }> = BlockSplitter::new(
        m,
        64,
        512,
        100.0,
        n_commands,
        &mut mb.distance_split,
        &mut mb.distance_histograms,
        &mut mb.distance_histograms_size,
    );

    for cmd in commands.iter() {
        cmd_blocks.add_symbol(
            cmd.cmd_prefix_ as usize,
            &mut mb.command_split,
            &mut mb.command_histograms,
            &mut mb.command_histograms_size,
        );
        let mut j = cmd.insert_len_ as usize;
        while j != 0 {
            let literal = ringbuffer[pos & mask];
            match &mut lit_blocks {
                LiteralBlocks::Plain(b) => {
                    b.add_symbol(
                        literal as usize,
                        &mut mb.literal_split,
                        &mut mb.literal_histograms,
                        &mut mb.literal_histograms_size,
                    );
                }
                LiteralBlocks::Ctx(b) => {
                    let context = brotli_context(prev_byte, prev_byte2, literal_context_lut) as usize;
                    let scm = static_context_map.unwrap_or(&[]);
                    b.add_symbol(
                        m,
                        literal as usize,
                        scm[context] as usize,
                        &mut mb.literal_split,
                        &mut mb.literal_histograms,
                        &mut mb.literal_histograms_size,
                    );
                }
            }
            prev_byte2 = prev_byte;
            prev_byte = literal;
            pos = pos.wrapping_add(1);
            j -= 1;
        }
        let copy_len = cmd.copy_len() as usize;
        pos = pos.wrapping_add(copy_len);
        if copy_len != 0 {
            prev_byte2 = ringbuffer[pos.wrapping_sub(2) & mask];
            prev_byte = ringbuffer[pos.wrapping_sub(1) & mask];
            if cmd.cmd_prefix_ >= 128 {
                dist_blocks.add_symbol(
                    (cmd.dist_prefix_ & 0x3FF) as usize,
                    &mut mb.distance_split,
                    &mut mb.distance_histograms,
                    &mut mb.distance_histograms_size,
                );
            }
        }
    }

    match &mut lit_blocks {
        LiteralBlocks::Plain(b) => {
            b.finish_block(true, &mut mb.literal_split, &mut mb.literal_histograms, &mut mb.literal_histograms_size);
        }
        LiteralBlocks::Ctx(b) => {
            b.finish_block(m, true, &mut mb.literal_split, &mut mb.literal_histograms, &mut mb.literal_histograms_size);
        }
    }
    drop(lit_blocks);

    if !base64_regions.is_empty()
        && mb.literal_split.num_types < 256
        && mb.literal_histograms_size + num_contexts <= 256
    {
        let mut local_b64 = [Base64Region::default(); MAX_LOCAL_BASE64_REGIONS];
        let safe_num_b64 = core::cmp::min(base64_regions.len(), MAX_LOCAL_BASE64_REGIONS);
        map_base64_regions_to_literal_positions(commands, start_pos, &base64_regions[..safe_num_b64], &mut local_b64);
        force_base64_literal_splits(m, &mut mb.literal_split, &local_b64[..safe_num_b64], 0, &mut mb.literal_is_base64);
        {
            let num_b64_histos = num_contexts;
            let b64_histo_id = mb.literal_histograms_size;
            let mut new_histos: Buf<HistogramLiteral> = Buf::new(m, mb.literal_histograms_size + num_b64_histos);
            new_histos[..mb.literal_histograms_size].copy_from_slice(&mb.literal_histograms[..mb.literal_histograms_size]);
            mb.literal_histograms = new_histos;
            for i in 0..num_b64_histos {
                mb.literal_histograms[b64_histo_id + i].clear();
            }
            mb.literal_histograms_size += num_b64_histos;
        }
    }

    cmd_blocks.finish_block(true, &mut mb.command_split, &mut mb.command_histograms, &mut mb.command_histograms_size);
    dist_blocks.finish_block(true, &mut mb.distance_split, &mut mb.distance_histograms, &mut mb.distance_histograms_size);

    if num_contexts > 1 {
        map_static_contexts(m, num_contexts, static_context_map.unwrap_or(&[]), mb);
    }
}

/// `BrotliBuildMetaBlockGreedy`: uses a fast greedy block splitter that tries
/// to merge current block with the last or the second last block and uses a
/// static context clustering which is the same for all block types.
/// `static_context_map` is `None` for C `NULL` (then `num_contexts == 1`).
#[allow(clippy::too_many_arguments)]
pub fn brotli_build_meta_block_greedy(
    m: &MemoryManager,
    ringbuffer: &[u8],
    pos: usize,
    mask: usize,
    base64_regions: &[Base64Region],
    prev_byte: u8,
    prev_byte2: u8,
    literal_context_lut: ContextLut,
    num_contexts: usize,
    static_context_map: Option<&[u32]>,
    commands: &[Command],
    mb: &mut MetaBlockSplit,
) {
    if num_contexts == 1 {
        brotli_build_meta_block_greedy_internal(
            m,
            ringbuffer,
            pos,
            mask,
            base64_regions,
            prev_byte,
            prev_byte2,
            literal_context_lut,
            1,
            None,
            commands,
            mb,
        );
    } else {
        brotli_build_meta_block_greedy_internal(
            m,
            ringbuffer,
            pos,
            mask,
            base64_regions,
            prev_byte,
            prev_byte2,
            literal_context_lut,
            num_contexts,
            static_context_map,
            commands,
            mb,
        );
    }
}

/// `BrotliOptimizeHistograms`.
pub fn brotli_optimize_histograms(num_distance_codes: u32, mb: &mut MetaBlockSplit) {
    let mut good_for_rle = [0u8; BROTLI_NUM_COMMAND_SYMBOLS];
    for h in mb.literal_histograms[..mb.literal_histograms_size].iter_mut() {
        brotli_optimize_huffman_counts_for_rle(256, &mut h.data_, &mut good_for_rle);
    }
    for h in mb.command_histograms[..mb.command_histograms_size].iter_mut() {
        brotli_optimize_huffman_counts_for_rle(BROTLI_NUM_COMMAND_SYMBOLS, &mut h.data_, &mut good_for_rle);
    }
    for h in mb.distance_histograms[..mb.distance_histograms_size].iter_mut() {
        brotli_optimize_huffman_counts_for_rle(num_distance_codes as usize, &mut h.data_, &mut good_for_rle);
    }
}
