//! Port of `c/enc/brotli_bit_stream.h` / `brotli_bit_stream.c` /
//! `block_encoder_inc.h`: functions to convert brotli-related data
//! structures into the brotli bit stream.
//!
//! All `storage` slices are the output buffer; `storage_ix` is the bit
//! position.  `input` is the ring buffer addressed with `& mask`.
//!
//! OWNER: worker "entropy".

use super::command::Command;
use super::entropy_encode::HuffmanTree;
use super::memory::MemoryManager;
use super::metablock::MetaBlockSplit;
use super::params::BrotliEncoderParams;
use crate::common::context::ContextType;

/// `BrotliStoreHuffmanTree`.
pub fn brotli_store_huffman_tree(depths: &[u8], num: usize, tree: &mut [HuffmanTree], storage_ix: &mut usize, storage: &mut [u8]) {
    let _ = (depths, num, tree, storage_ix, storage);
    todo!("brotli_bit_stream::brotli_store_huffman_tree")
}

/// `BrotliBuildAndStoreHuffmanTreeFast`.
pub fn brotli_build_and_store_huffman_tree_fast(
    tree: &mut [HuffmanTree],
    histogram: &[u32],
    histogram_total: usize,
    max_bits: usize,
    depth: &mut [u8],
    bits: &mut [u16],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let _ = (tree, histogram, histogram_total, max_bits, depth, bits, storage_ix, storage);
    todo!("brotli_bit_stream::brotli_build_and_store_huffman_tree_fast")
}

/// `BrotliStoreMetaBlock`.
pub fn brotli_store_meta_block(
    m: &MemoryManager,
    input: &[u8],
    start_pos: usize,
    length: usize,
    mask: usize,
    prev_byte: u8,
    prev_byte2: u8,
    is_last: bool,
    params: &BrotliEncoderParams,
    literal_context_mode: ContextType,
    commands: &[Command],
    mb: &MetaBlockSplit,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let _ = (m, input, start_pos, length, mask, prev_byte, prev_byte2, is_last, params, literal_context_mode, commands, mb, storage_ix, storage);
    todo!("brotli_bit_stream::brotli_store_meta_block")
}

/// `BrotliStoreMetaBlockTrivial`: stores the meta-block without doing any
/// block splitting, just collects one histogram per block category and uses
/// that for entropy coding.
pub fn brotli_store_meta_block_trivial(
    m: &MemoryManager,
    input: &[u8],
    start_pos: usize,
    length: usize,
    mask: usize,
    is_last: bool,
    params: &BrotliEncoderParams,
    commands: &[Command],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let _ = (m, input, start_pos, length, mask, is_last, params, commands, storage_ix, storage);
    todo!("brotli_bit_stream::brotli_store_meta_block_trivial")
}

/// `BrotliStoreMetaBlockFast`: same as above, but uses static prefix codes
/// for histograms with few symbols, and uses fast heuristics instead.
pub fn brotli_store_meta_block_fast(
    m: &MemoryManager,
    input: &[u8],
    start_pos: usize,
    length: usize,
    mask: usize,
    is_last: bool,
    params: &BrotliEncoderParams,
    commands: &[Command],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let _ = (m, input, start_pos, length, mask, is_last, params, commands, storage_ix, storage);
    todo!("brotli_bit_stream::brotli_store_meta_block_fast")
}

/// `BrotliStoreUncompressedMetaBlock`: this is for storing uncompressed
/// blocks (simple raw storage of bytes-as-bytes).
pub fn brotli_store_uncompressed_meta_block(
    is_final_block: bool,
    input: &[u8],
    position: usize,
    mask: usize,
    len: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let _ = (is_final_block, input, position, mask, len, storage_ix, storage);
    todo!("brotli_bit_stream::brotli_store_uncompressed_meta_block")
}
