//! Port of `c/enc/compress_fragment.h` / `compress_fragment.c`: function for
//! fast encoding of an input fragment, independently from the input history
//! (quality 0).
//!
//! OWNER: worker "entropy".

use super::entropy_encode::HuffmanTree;
use crate::common::constants::{BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS};

/// `BrotliOnePassArena`.
#[derive(Clone)]
pub struct BrotliOnePassArena {
    pub lit_depth: [u8; 256],
    pub lit_bits: [u16; 256],
    /// Command and distance prefix codes (each 64 symbols, stored
    /// back-to-back) used for the next block.
    pub cmd_depth: [u8; 128],
    pub cmd_bits: [u16; 128],
    pub cmd_histo: [u32; 128],
    /// The compressed form of the command and distance prefix codes for the
    /// next block.
    pub cmd_code: [u8; 512],
    pub cmd_code_numbits: usize,
    pub tree: [HuffmanTree; 2 * BROTLI_NUM_LITERAL_SYMBOLS + 1],
    pub histogram: [u32; 256],
    pub tmp_depth: [u8; BROTLI_NUM_COMMAND_SYMBOLS],
    pub tmp_bits: [u16; 64],
}

impl Default for BrotliOnePassArena {
    fn default() -> Self {
        BrotliOnePassArena {
            lit_depth: [0; 256],
            lit_bits: [0; 256],
            cmd_depth: [0; 128],
            cmd_bits: [0; 128],
            cmd_histo: [0; 128],
            cmd_code: [0; 512],
            cmd_code_numbits: 0,
            tree: [HuffmanTree::default(); 2 * BROTLI_NUM_LITERAL_SYMBOLS + 1],
            histogram: [0; 256],
            tmp_depth: [0; BROTLI_NUM_COMMAND_SYMBOLS],
            tmp_bits: [0; 64],
        }
    }
}

/// `BrotliCompressFragmentFast`.
///
/// Compresses `input[..input_size]` into a complete meta-block (the C
/// version reads only within `input_size`).  `table` is a hash table of
/// `table_size` entries (power of two, odd log2 in `[9, 15]`), zeroed by the
/// caller.  Output is written to `storage` at bit position `*storage_ix`.
pub fn brotli_compress_fragment_fast(
    s: &mut BrotliOnePassArena,
    input: &[u8],
    input_size: usize,
    is_last: bool,
    table: &mut [i32],
    table_size: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let _ = (s, input, input_size, is_last, table, table_size, storage_ix, storage);
    todo!("compress_fragment::brotli_compress_fragment_fast")
}
