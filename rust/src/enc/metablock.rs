//! Port of `c/enc/metablock.h` / `metablock.c` / `metablock_inc.h`:
//! algorithms for distributing the literals and commands of a metablock
//! between block types and contexts.
//!
//! OWNER: worker "entropy".

use super::block_splitter::BlockSplit;
use super::command::Command;
use super::histogram::{HistogramCommand, HistogramDistance, HistogramLiteral};
use super::memory::{Buf, MemoryManager};
use super::params::{Base64Region, BrotliDistanceParams, BrotliEncoderParams};
use crate::common::context::{ContextLut, ContextType};

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

/// `BrotliInitDistanceParams`.
pub fn brotli_init_distance_params(params: &mut BrotliDistanceParams, npostfix: u32, ndirect: u32, large_window: bool) {
    let _ = (params, npostfix, ndirect, large_window);
    todo!("metablock::brotli_init_distance_params")
}

/// `BrotliBuildMetaBlock`: uses the slow shortest-path block splitter and
/// does context clustering.  `ringbuffer` is the ring buffer (`buffer_`),
/// addressed with `& mask`.  `cmds` are the commands of the metablock.
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
    let _ = (m, ringbuffer, pos, mask, base64_regions, params, prev_byte, prev_byte2, cmds, literal_context_mode, mb);
    todo!("metablock::brotli_build_meta_block")
}

/// `BrotliBuildMetaBlockGreedy`: uses a fast greedy block splitter that tries
/// to merge current block with the last or the second last block and uses a
/// static context clustering which is the same for all block types.
/// `static_context_map` is `None` for C `NULL` (then `num_contexts == 1`).
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
    let _ = (m, ringbuffer, pos, mask, base64_regions, prev_byte, prev_byte2, literal_context_lut, num_contexts, static_context_map, commands, mb);
    todo!("metablock::brotli_build_meta_block_greedy")
}

/// `BrotliOptimizeHistograms`.
pub fn brotli_optimize_histograms(num_distance_codes: u32, mb: &mut MetaBlockSplit) {
    let _ = (num_distance_codes, mb);
    todo!("metablock::brotli_optimize_histograms")
}
