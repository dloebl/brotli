//! Port of `c/enc/entropy_encode_static.h`: static entropy codes used for
//! faster meta-block encoding.
//!
//! OWNER: worker "entropy".

mod tables;

use super::write_bits::brotli_write_bits;

pub use tables::{
    K_CODE_LENGTH_BITS, K_CODE_LENGTH_DEPTH, K_NON_ZERO_REPS_BITS, K_NON_ZERO_REPS_DEPTH, K_STATIC_COMMAND_CODE_BITS,
    K_STATIC_COMMAND_CODE_DEPTH, K_STATIC_DISTANCE_CODE_BITS, K_STATIC_DISTANCE_CODE_DEPTH, K_ZERO_REPS_BITS,
    K_ZERO_REPS_DEPTH,
};

/// `kCmdHistoSeed` (file-static in `compress_fragment.c`).
pub(crate) use tables::K_CMD_HISTO_SEED;

/// `StoreStaticCodeLengthCode`.
#[inline]
pub fn store_static_code_length_code(storage_ix: &mut usize, storage: &mut [u8]) {
    brotli_write_bits(40, (0x0000FFu64 << 32) | 0x55555554u64, storage_ix, storage);
}

/// `StoreStaticCommandHuffmanTree`.
#[inline]
pub fn store_static_command_huffman_tree(storage_ix: &mut usize, storage: &mut [u8]) {
    brotli_write_bits(56, (0x926244u64 << 32) | 0x16307003u64, storage_ix, storage);
    brotli_write_bits(3, 0x00000000, storage_ix, storage);
}

/// `StoreStaticDistanceHuffmanTree`.
#[inline]
pub fn store_static_distance_huffman_tree(storage_ix: &mut usize, storage: &mut [u8]) {
    brotli_write_bits(28, 0x0369DC03, storage_ix, storage);
}
