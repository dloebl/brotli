//! Port of `c/enc/compress_fragment_two_pass.h` /
//! `compress_fragment_two_pass.c`: function for fast encoding of an input
//! fragment, independently from the input history (quality 1).
//!
//! OWNER: worker "entropy".

use super::entropy_encode::HuffmanTree;
use crate::common::constants::{BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS};

/// `kCompressFragmentTwoPassBlockSize`.
pub const K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE: usize = 1 << 17;

/// `BrotliTwoPassArena`.
#[derive(Clone)]
pub struct BrotliTwoPassArena {
    pub lit_histo: [u32; 256],
    pub lit_depth: [u8; 256],
    pub lit_bits: [u16; 256],
    pub cmd_histo: [u32; 128],
    pub cmd_depth: [u8; 128],
    pub cmd_bits: [u16; 128],
    /// BuildAndStoreCommandPrefixCode
    pub tmp_tree: [HuffmanTree; 2 * BROTLI_NUM_LITERAL_SYMBOLS + 1],
    pub tmp_depth: [u8; BROTLI_NUM_COMMAND_SYMBOLS],
    pub tmp_bits: [u16; 64],
}

impl Default for BrotliTwoPassArena {
    fn default() -> Self {
        BrotliTwoPassArena {
            lit_histo: [0; 256],
            lit_depth: [0; 256],
            lit_bits: [0; 256],
            cmd_histo: [0; 128],
            cmd_depth: [0; 128],
            cmd_bits: [0; 128],
            tmp_tree: [HuffmanTree::default(); 2 * BROTLI_NUM_LITERAL_SYMBOLS + 1],
            tmp_depth: [0; BROTLI_NUM_COMMAND_SYMBOLS],
            tmp_bits: [0; 64],
        }
    }
}

/// `BrotliCompressFragmentTwoPass`.
///
/// Compresses `input[..input_size]`.  `command_buf` and `literal_buf` are
/// scratch buffers of at least `min(input_size,
/// K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE)` entries.  `table` is a hash
/// table of `table_size` entries (power of two), zeroed by the caller.
pub fn brotli_compress_fragment_two_pass(
    s: &mut BrotliTwoPassArena,
    input: &[u8],
    input_size: usize,
    is_last: bool,
    command_buf: &mut [u32],
    literal_buf: &mut [u8],
    table: &mut [i32],
    table_size: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let _ = (s, input, input_size, is_last, command_buf, literal_buf, table, table_size, storage_ix, storage);
    todo!("compress_fragment_two_pass::brotli_compress_fragment_two_pass")
}
