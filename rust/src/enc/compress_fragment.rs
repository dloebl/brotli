//! Port of `c/enc/compress_fragment.h` / `compress_fragment.c`: function for
//! fast encoding of an input fragment, independently from the input history
//! (quality 0).
//!
//! This function uses one-pass processing: when we find a backward match, we
//! immediately emit the corresponding command and literal codes to the bit
//! stream.
//!
//! Adapted from the CompressFragment() function in
//! https://github.com/google/snappy/blob/master/snappy.cc
//!
//! OWNER: worker "entropy".

use super::brotli_bit_stream::{brotli_build_and_store_huffman_tree_fast, brotli_store_huffman_tree};
use super::entropy_encode::{brotli_convert_bit_depths_to_symbols, brotli_create_huffman_tree, HuffmanTree};
use super::entropy_encode_static::K_CMD_HISTO_SEED;
use super::fast_log::{fast_log2, log2_floor_non_zero};
use super::find_match_length::find_match_length_with_limit;
use super::write_bits::brotli_write_bits;
use crate::common::constants::{brotli_max_backward_limit, BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS, BROTLI_WINDOW_GAP};

/// `BrotliOnePassArena` (`#[repr(C)]`: same size as the C struct, which
/// matters for `BrotliEncoderEstimatePeakMemoryUsage`).
#[repr(C)]
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

// Tables of `InitCommandPrefixCodes` (encode.c), extracted from the C source.
const K_DEFAULT_COMMAND_DEPTHS: [u8; 128] = [
    0, 4, 4, 5, 6, 6, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8,
    0, 0, 0, 4, 4, 4, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7,
    7, 7, 10, 10, 10, 10, 10, 10, 0, 4, 4, 5, 5, 5, 6, 6,
    7, 8, 8, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4,
    4, 4, 4, 5, 5, 5, 5, 5, 5, 6, 6, 7, 7, 7, 8, 10,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 0, 0, 0, 0,
];
const K_DEFAULT_COMMAND_BITS: [u16; 128] = [
    0, 0, 8, 9, 3, 35, 7, 71, 39, 103, 23, 47, 175, 111, 239, 31,
    0, 0, 0, 4, 12, 2, 10, 6, 13, 29, 11, 43, 27, 59, 87, 55,
    15, 79, 319, 831, 191, 703, 447, 959, 0, 14, 1, 25, 5, 21, 19, 51,
    119, 159, 95, 223, 479, 991, 63, 575, 127, 639, 383, 895, 255, 767, 511, 1023,
    14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    27, 59, 7, 39, 23, 55, 30, 1, 17, 9, 25, 5, 0, 8, 4, 12,
    2, 10, 6, 21, 13, 29, 3, 19, 11, 15, 47, 31, 95, 63, 127, 255,
    767, 2815, 1791, 3839, 511, 2559, 1535, 3583, 1023, 3071, 2047, 4095, 0, 0, 0, 0,
];
const K_DEFAULT_COMMAND_CODE: [u8; 57] = [
    0xff, 0x77, 0xd5, 0xbf, 0xe7, 0xde, 0xea, 0x9e, 0x51, 0x5d, 0xde, 0xc6, 0x70, 0x57, 0xbc, 0x58,
    0x58, 0x58, 0xd8, 0xd8, 0x58, 0xd5, 0xcb, 0x8c, 0xea, 0xe0, 0xc3, 0x87, 0x1f, 0x83, 0xc1, 0x60,
    0x1c, 0x67, 0xb2, 0xaa, 0x06, 0x83, 0xc1, 0x60, 0x30, 0x18, 0xcc, 0xa1, 0xce, 0x88, 0x54, 0x94,
    0x46, 0xe1, 0xb0, 0xd0, 0x4e, 0xb2, 0xf7, 0x04, 0x00,
];
const K_DEFAULT_COMMAND_CODE_NUM_BITS: usize = 448;

/// `InitCommandPrefixCodes` (static in `encode.c`): initializes the command
/// and distance prefix codes of the one-pass arena for the first block
/// (provided here for the encoder; not part of `compress_fragment.c`).
pub fn init_command_prefix_codes(s: &mut BrotliOnePassArena) {
    s.cmd_depth.copy_from_slice(&K_DEFAULT_COMMAND_DEPTHS);
    s.cmd_bits.copy_from_slice(&K_DEFAULT_COMMAND_BITS);

    // Initialize the pre-compressed form of the command and distance prefix
    // codes.
    s.cmd_code[..K_DEFAULT_COMMAND_CODE.len()].copy_from_slice(&K_DEFAULT_COMMAND_CODE);
    s.cmd_code_numbits = K_DEFAULT_COMMAND_CODE_NUM_BITS;
}

/// `MAX_DISTANCE`.
const MAX_DISTANCE: isize = brotli_max_backward_limit(18) as isize;

/// `kHashMul32` (hash_base.h).
pub(crate) const K_HASH_MUL32: u32 = 0x1E35A7BD;

#[inline(always)]
pub(crate) fn load64le(p: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(p[i..i + 8].try_into().unwrap())
}

#[inline(always)]
pub(crate) fn load32le(p: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(p[i..i + 4].try_into().unwrap())
}

#[inline(always)]
fn hash(p: &[u8], i: usize, shift: usize) -> u32 {
    let h = (load64le(p, i) << 24).wrapping_mul(K_HASH_MUL32 as u64);
    (h >> shift) as u32
}

#[inline(always)]
fn hash_bytes_at_offset(v: u64, offset: i32, shift: usize) -> u32 {
    debug_assert!(offset >= 0);
    debug_assert!(offset <= 3);
    let h = ((v >> (8 * offset)) << 24).wrapping_mul(K_HASH_MUL32 as u64);
    (h >> shift) as u32
}

#[inline(always)]
fn is_match(p: &[u8], p1: usize, p2: usize) -> bool {
    load32le(p, p1) == load32le(p, p2) && p[p1 + 4] == p[p2 + 4]
}

/// Builds a literal prefix code into "depths" and "bits" based on the
/// statistics of the "input" string and stores it into the bit stream.
/// Note that the prefix code here is built from the pre-LZ77 input, therefore
/// we can only approximate the statistics of the actual literal stream.
/// Moreover, for long inputs we build a histogram from a sample of the input
/// and thus have to assign a non-zero depth for each literal.
/// Returns estimated compression ratio millibytes/char for encoding given
/// input with generated code.
fn build_and_store_literal_prefix_code(
    s: &mut BrotliOnePassArena,
    input: &[u8],
    input_size: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) -> usize {
    let mut histogram_total: usize;
    s.histogram = [0; 256];

    if input_size < (1 << 15) {
        for &b in input[..input_size].iter() {
            s.histogram[b as usize] += 1;
        }
        histogram_total = input_size;
        for h in s.histogram.iter_mut() {
            // We weigh the first 11 samples with weight 3 to account for the
            // balancing effect of the LZ77 phase on the histogram.
            let adjust = 2 * core::cmp::min(*h, 11u32);
            *h += adjust;
            histogram_total += adjust as usize;
        }
    } else {
        const K_SAMPLE_RATE: usize = 29;
        let mut i = 0;
        while i < input_size {
            s.histogram[input[i] as usize] += 1;
            i += K_SAMPLE_RATE;
        }
        histogram_total = (input_size + K_SAMPLE_RATE - 1) / K_SAMPLE_RATE;
        for h in s.histogram.iter_mut() {
            // We add 1 to each population count to avoid 0 bit depths (since
            // this is only a sample and we don't know if the symbol appears or
            // not), and we weigh the first 11 samples with weight 3 to account
            // for the balancing effect of the LZ77 phase on the histogram (more
            // frequent symbols are more likely to be in backward references
            // instead as literals).
            let adjust = 1 + 2 * core::cmp::min(*h, 11u32);
            *h += adjust;
            histogram_total += adjust as usize;
        }
    }
    brotli_build_and_store_huffman_tree_fast(
        &mut s.tree,
        &s.histogram,
        histogram_total,
        /* max_bits = */ 8,
        &mut s.lit_depth,
        &mut s.lit_bits,
        storage_ix,
        storage,
    );
    {
        let mut literal_ratio: usize = 0;
        for i in 0..256 {
            if s.histogram[i] != 0 {
                literal_ratio = literal_ratio.wrapping_add(s.histogram[i].wrapping_mul(s.lit_depth[i] as u32) as usize);
            }
        }
        // Estimated encoding ratio, millibytes per symbol.
        literal_ratio.wrapping_mul(125) / histogram_total
    }
}

/// Builds a command and distance prefix code (each 64 symbols) into "depth"
/// and "bits" based on "histogram" and stores it into the bit stream.
fn build_and_store_command_prefix_code(s: &mut BrotliOnePassArena, storage_ix: &mut usize, storage: &mut [u8]) {
    let histogram = &s.cmd_histo;
    let depth = &mut s.cmd_depth;
    let bits = &mut s.cmd_bits;
    let tmp_depth = &mut s.tmp_depth;
    let tmp_bits = &mut s.tmp_bits;
    // TODO(eustas): do only once on initialization.
    *tmp_depth = [0; BROTLI_NUM_COMMAND_SYMBOLS];

    brotli_create_huffman_tree(&histogram[..], 64, 15, &mut s.tree, &mut depth[..]);
    brotli_create_huffman_tree(&histogram[64..], 64, 14, &mut s.tree, &mut depth[64..]);
    // We have to jump through a few hoops here in order to compute
    // the command bits because the symbols are in a different order than in
    // the full alphabet. This looks complicated, but having the symbols
    // in this order in the command bits saves a few branches in the Emit*
    // functions.
    tmp_depth[0..24].copy_from_slice(&depth[0..24]);
    tmp_depth[24..32].copy_from_slice(&depth[40..48]);
    tmp_depth[32..40].copy_from_slice(&depth[24..32]);
    tmp_depth[40..48].copy_from_slice(&depth[48..56]);
    tmp_depth[48..56].copy_from_slice(&depth[32..40]);
    tmp_depth[56..64].copy_from_slice(&depth[56..64]);
    brotli_convert_bit_depths_to_symbols(&tmp_depth[..], 64, &mut tmp_bits[..]);
    bits[0..24].copy_from_slice(&tmp_bits[0..24]);
    bits[24..32].copy_from_slice(&tmp_bits[32..40]);
    bits[32..40].copy_from_slice(&tmp_bits[48..56]);
    bits[40..48].copy_from_slice(&tmp_bits[24..32]);
    bits[48..56].copy_from_slice(&tmp_bits[40..48]);
    bits[56..64].copy_from_slice(&tmp_bits[56..64]);
    brotli_convert_bit_depths_to_symbols(&depth[64..], 64, &mut bits[64..]);
    {
        // Create the bit length array for the full command alphabet.
        for d in tmp_depth[..64].iter_mut() {
            *d = 0; // only 64 first values were used
        }
        tmp_depth[0..8].copy_from_slice(&depth[0..8]);
        tmp_depth[64..72].copy_from_slice(&depth[8..16]);
        tmp_depth[128..136].copy_from_slice(&depth[16..24]);
        tmp_depth[192..200].copy_from_slice(&depth[24..32]);
        tmp_depth[384..392].copy_from_slice(&depth[32..40]);
        for i in 0..8 {
            tmp_depth[128 + 8 * i] = depth[40 + i];
            tmp_depth[256 + 8 * i] = depth[48 + i];
            tmp_depth[448 + 8 * i] = depth[56 + i];
        }
        // TODO(eustas): could/should full-length machinery be avoided?
        brotli_store_huffman_tree(&tmp_depth[..], BROTLI_NUM_COMMAND_SYMBOLS, &mut s.tree, storage_ix, storage);
    }
    brotli_store_huffman_tree(&depth[64..], 64, &mut s.tree, storage_ix, storage);
}

/// REQUIRES: insertlen < 6210
#[inline(always)]
fn emit_insert_len(
    insertlen: usize,
    depth: &[u8; 128],
    bits: &[u16; 128],
    histo: &mut [u32; 128],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    if insertlen < 6 {
        let code = insertlen + 40;
        brotli_write_bits(depth[code] as usize, bits[code] as u64, storage_ix, storage);
        histo[code] += 1;
    } else if insertlen < 130 {
        let tail = insertlen - 2;
        let nbits = log2_floor_non_zero(tail) - 1;
        let prefix = tail >> nbits;
        let inscode = ((nbits as usize) << 1) + prefix + 42;
        brotli_write_bits(depth[inscode] as usize, bits[inscode] as u64, storage_ix, storage);
        brotli_write_bits(nbits as usize, (tail - (prefix << nbits)) as u64, storage_ix, storage);
        histo[inscode] += 1;
    } else if insertlen < 2114 {
        let tail = insertlen - 66;
        let nbits = log2_floor_non_zero(tail);
        let code = nbits as usize + 50;
        brotli_write_bits(depth[code] as usize, bits[code] as u64, storage_ix, storage);
        brotli_write_bits(nbits as usize, (tail - (1usize << nbits)) as u64, storage_ix, storage);
        histo[code] += 1;
    } else {
        brotli_write_bits(depth[61] as usize, bits[61] as u64, storage_ix, storage);
        brotli_write_bits(12, (insertlen - 2114) as u64, storage_ix, storage);
        histo[61] += 1;
    }
}

#[inline(always)]
fn emit_long_insert_len(
    insertlen: usize,
    depth: &[u8; 128],
    bits: &[u16; 128],
    histo: &mut [u32; 128],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    if insertlen < 22594 {
        brotli_write_bits(depth[62] as usize, bits[62] as u64, storage_ix, storage);
        brotli_write_bits(14, (insertlen - 6210) as u64, storage_ix, storage);
        histo[62] += 1;
    } else {
        brotli_write_bits(depth[63] as usize, bits[63] as u64, storage_ix, storage);
        brotli_write_bits(24, (insertlen - 22594) as u64, storage_ix, storage);
        histo[63] += 1;
    }
}

#[inline(always)]
fn emit_copy_len(
    copylen: usize,
    depth: &[u8; 128],
    bits: &[u16; 128],
    histo: &mut [u32; 128],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    if copylen < 10 {
        brotli_write_bits(depth[copylen + 14] as usize, bits[copylen + 14] as u64, storage_ix, storage);
        histo[copylen + 14] += 1;
    } else if copylen < 134 {
        let tail = copylen - 6;
        let nbits = log2_floor_non_zero(tail) - 1;
        let prefix = tail >> nbits;
        let code = ((nbits as usize) << 1) + prefix + 20;
        brotli_write_bits(depth[code] as usize, bits[code] as u64, storage_ix, storage);
        brotli_write_bits(nbits as usize, (tail - (prefix << nbits)) as u64, storage_ix, storage);
        histo[code] += 1;
    } else if copylen < 2118 {
        let tail = copylen - 70;
        let nbits = log2_floor_non_zero(tail);
        let code = nbits as usize + 28;
        brotli_write_bits(depth[code] as usize, bits[code] as u64, storage_ix, storage);
        brotli_write_bits(nbits as usize, (tail - (1usize << nbits)) as u64, storage_ix, storage);
        histo[code] += 1;
    } else {
        brotli_write_bits(depth[39] as usize, bits[39] as u64, storage_ix, storage);
        brotli_write_bits(24, (copylen - 2118) as u64, storage_ix, storage);
        histo[39] += 1;
    }
}

#[inline(always)]
fn emit_copy_len_last_distance(
    copylen: usize,
    depth: &[u8; 128],
    bits: &[u16; 128],
    histo: &mut [u32; 128],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    if copylen < 12 {
        brotli_write_bits(depth[copylen - 4] as usize, bits[copylen - 4] as u64, storage_ix, storage);
        histo[copylen - 4] += 1;
    } else if copylen < 72 {
        let tail = copylen - 8;
        let nbits = log2_floor_non_zero(tail) - 1;
        let prefix = tail >> nbits;
        let code = ((nbits as usize) << 1) + prefix + 4;
        brotli_write_bits(depth[code] as usize, bits[code] as u64, storage_ix, storage);
        brotli_write_bits(nbits as usize, (tail - (prefix << nbits)) as u64, storage_ix, storage);
        histo[code] += 1;
    } else if copylen < 136 {
        let tail = copylen - 8;
        let code = (tail >> 5) + 30;
        brotli_write_bits(depth[code] as usize, bits[code] as u64, storage_ix, storage);
        brotli_write_bits(5, (tail & 31) as u64, storage_ix, storage);
        brotli_write_bits(depth[64] as usize, bits[64] as u64, storage_ix, storage);
        histo[code] += 1;
        histo[64] += 1;
    } else if copylen < 2120 {
        let tail = copylen - 72;
        let nbits = log2_floor_non_zero(tail);
        let code = nbits as usize + 28;
        brotli_write_bits(depth[code] as usize, bits[code] as u64, storage_ix, storage);
        brotli_write_bits(nbits as usize, (tail - (1usize << nbits)) as u64, storage_ix, storage);
        brotli_write_bits(depth[64] as usize, bits[64] as u64, storage_ix, storage);
        histo[code] += 1;
        histo[64] += 1;
    } else {
        brotli_write_bits(depth[39] as usize, bits[39] as u64, storage_ix, storage);
        brotli_write_bits(24, (copylen - 2120) as u64, storage_ix, storage);
        brotli_write_bits(depth[64] as usize, bits[64] as u64, storage_ix, storage);
        histo[39] += 1;
        histo[64] += 1;
    }
}

#[inline(always)]
fn emit_distance(
    distance: usize,
    depth: &[u8; 128],
    bits: &[u16; 128],
    histo: &mut [u32; 128],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let d = distance + 3;
    let nbits = log2_floor_non_zero(d) - 1;
    let prefix = (d >> nbits) & 1;
    let offset = (2 + prefix) << nbits;
    let distcode = 2 * (nbits as usize - 1) + prefix + 80;
    brotli_write_bits(depth[distcode] as usize, bits[distcode] as u64, storage_ix, storage);
    brotli_write_bits(nbits as usize, (d - offset) as u64, storage_ix, storage);
    histo[distcode] += 1;
}

#[inline(always)]
fn emit_literals(input: &[u8], depth: &[u8; 256], bits: &[u16; 256], storage_ix: &mut usize, storage: &mut [u8]) {
    for &lit in input.iter() {
        brotli_write_bits(depth[lit as usize] as usize, bits[lit as usize] as u64, storage_ix, storage);
    }
}

/// `BrotliStoreMetaBlockHeader` (static in compress_fragment.c and
/// compress_fragment_two_pass.c).
/// REQUIRES: len <= 1 << 24.
pub(crate) fn brotli_store_meta_block_header(len: usize, is_uncompressed: bool, storage_ix: &mut usize, storage: &mut [u8]) {
    let mut nibbles: usize = 6;
    // ISLAST
    brotli_write_bits(1, 0, storage_ix, storage);
    if len <= (1usize << 16) {
        nibbles = 4;
    } else if len <= (1usize << 20) {
        nibbles = 5;
    }
    brotli_write_bits(2, (nibbles - 4) as u64, storage_ix, storage);
    brotli_write_bits(nibbles * 4, len.wrapping_sub(1) as u64, storage_ix, storage);
    // ISUNCOMPRESSED
    brotli_write_bits(1, is_uncompressed as u64, storage_ix, storage);
}

fn update_bits(mut n_bits: usize, mut bits: u32, mut pos: usize, array: &mut [u8]) {
    while n_bits > 0 {
        let byte_pos = pos >> 3;
        let n_unchanged_bits = pos & 7;
        let n_changed_bits = core::cmp::min(n_bits, 8 - n_unchanged_bits);
        let total_bits = n_unchanged_bits + n_changed_bits;
        let mask: u32 = (!((1u32 << total_bits) - 1)) | ((1u32 << n_unchanged_bits) - 1);
        let unchanged_bits = array[byte_pos] as u32 & mask;
        let changed_bits = bits & ((1u32 << n_changed_bits) - 1);
        array[byte_pos] = ((changed_bits << n_unchanged_bits) | unchanged_bits) as u8;
        n_bits -= n_changed_bits;
        bits >>= n_changed_bits;
        pos += n_changed_bits;
    }
}

/// `RewindBitPosition` (static in compress_fragment.c and
/// compress_fragment_two_pass.c).
pub(crate) fn rewind_bit_position(new_storage_ix: usize, storage_ix: &mut usize, storage: &mut [u8]) {
    let bitpos = new_storage_ix & 7;
    let mask = (1u32 << bitpos) - 1;
    storage[new_storage_ix >> 3] &= mask as u8;
    *storage_ix = new_storage_ix;
}

fn should_merge_block(s: &mut BrotliOnePassArena, data: &[u8], len: usize) -> bool {
    const K_SAMPLE_RATE: usize = 43;
    s.histogram = [0; 256];
    let mut i = 0;
    while i < len {
        s.histogram[data[i] as usize] += 1;
        i += K_SAMPLE_RATE;
    }
    {
        let total = (len + K_SAMPLE_RATE - 1) / K_SAMPLE_RATE;
        let mut r = (fast_log2(total) + 0.5) * (total as f64) + 200.0;
        for i in 0..256 {
            r -= (s.histogram[i] as f64) * (s.lit_depth[i] as f64 + fast_log2(s.histogram[i] as usize));
        }
        r >= 0.0
    }
}

/// Acceptable loss for uncompressible speedup is 2%
const MIN_RATIO: usize = 980;

#[inline(always)]
fn should_use_uncompressed_mode(metablock_start: usize, next_emit: usize, insertlen: usize, literal_ratio: usize) -> bool {
    let compressed = next_emit - metablock_start;
    if compressed * 50 > insertlen {
        false
    } else {
        literal_ratio > MIN_RATIO
    }
}

/// `(*storage_ix + 7u) & ~7u` (the mask is a 32-bit unsigned int,
/// zero-extended to size_t).
#[inline(always)]
pub(crate) fn round_up_to_byte(storage_ix: usize) -> usize {
    storage_ix.wrapping_add(7) & (!7u32 as usize)
}

fn emit_uncompressed_meta_block(
    input: &[u8],
    begin: usize,
    end: usize,
    storage_ix_start: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let len = end - begin;
    rewind_bit_position(storage_ix_start, storage_ix, storage);
    brotli_store_meta_block_header(len, true, storage_ix, storage);
    *storage_ix = round_up_to_byte(*storage_ix);
    let dst = *storage_ix >> 3;
    storage[dst..dst + len].copy_from_slice(&input[begin..end]);
    *storage_ix += len << 3;
    storage[*storage_ix >> 3] = 0;
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn brotli_compress_fragment_fast_impl<const TABLE_BITS: usize>(
    s: &mut BrotliOnePassArena,
    input_base: &[u8],
    mut input_size: usize,
    is_last: bool,
    table: &mut [i32],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    // All positions are offsets from the start of the input ("base_ip").
    // "input" is the start of the current block.
    let mut input: usize = 0;

    // "next_emit" is a pointer to the first byte that is not covered by a
    // previous copy. Bytes between "next_emit" and the start of the next copy
    // or the end of the input will be emitted as literal bytes.
    let mut next_emit: usize = input;

    const K_FIRST_BLOCK_SIZE: usize = 3 << 15;
    const K_MERGE_BLOCK_SIZE: usize = 1 << 16;

    const K_INPUT_MARGIN_BYTES: usize = BROTLI_WINDOW_GAP;
    const K_MIN_MATCH_LEN: usize = 5;

    let mut metablock_start: usize = input;
    let mut block_size = core::cmp::min(input_size, K_FIRST_BLOCK_SIZE);
    let mut total_block_size = block_size;
    // Save the bit position of the MLEN field of the meta-block header, so
    // that we can update it later if we decide to extend this meta-block.
    let mut mlen_storage_ix = *storage_ix + 3;

    let mut literal_ratio: usize;

    let shift: usize = 64 - TABLE_BITS;

    brotli_store_meta_block_header(block_size, false, storage_ix, storage);
    // No block splits, no contexts.
    brotli_write_bits(13, 0, storage_ix, storage);

    literal_ratio = build_and_store_literal_prefix_code(s, &input_base[input..], block_size, storage_ix, storage);

    {
        // Store the pre-compressed command and distance prefix codes.
        let mut i = 0;
        while i + 7 < s.cmd_code_numbits {
            brotli_write_bits(8, s.cmd_code[i >> 3] as u64, storage_ix, storage);
            i += 8;
        }
    }
    brotli_write_bits(s.cmd_code_numbits & 7, s.cmd_code[s.cmd_code_numbits >> 3] as u64, storage_ix, storage);

    'emit_commands: loop {
        // Initialize the command and distance histograms. We will gather
        // statistics of command and distance codes during the processing
        // of this block and use it to update the command and distance
        // prefix codes for the next block.
        s.cmd_histo.copy_from_slice(&K_CMD_HISTO_SEED);

        // "ip" is the input pointer.
        let mut ip: usize = input;
        let mut last_distance: i32 = -1;
        let ip_end: usize = input + block_size;

        // true: goto next_block; false: goto emit_remainder.
        let goto_next_block: bool = 'body: {
            if block_size >= K_INPUT_MARGIN_BYTES {
                // For the last block, we need to keep a 16 bytes margin so that
                // we can be sure that all distances are at most window size -
                // 16. For all other blocks, we only need to keep a margin of 5
                // bytes so that we don't go over the block size with a copy.
                let len_limit = core::cmp::min(block_size - K_MIN_MATCH_LEN, input_size - K_INPUT_MARGIN_BYTES);
                let ip_limit = input + len_limit;

                ip += 1;
                let mut next_hash = hash(input_base, ip, shift);
                loop {
                    // Step 1: Scan forward in the input looking for a
                    // 5-byte-long match. If we get close to exhausting the
                    // input then goto emit_remainder.
                    //
                    // Heuristic match skipping: If 32 bytes are scanned with no
                    // matches found, start looking only at every other byte. If
                    // 32 more bytes are scanned, look at every third byte, etc..
                    // When a match is found, immediately go back to looking at
                    // every byte. This is a small loss (~5% performance, ~0.1%
                    // density) for compressible data due to more bookkeeping,
                    // but for non-compressible data (such as JPEG) it's a huge
                    // win since the compressor quickly "realizes" the data is
                    // incompressible and doesn't bother looking for matches
                    // everywhere.
                    //
                    // The "skip" variable keeps track of how many bytes there
                    // are since the last match; dividing it by 32 (i.e.
                    // right-shifting by five) gives the number of bytes to move
                    // ahead for each iteration.
                    let mut skip: u32 = 32;

                    let mut next_ip: usize = ip;
                    let mut candidate: usize;
                    debug_assert!(next_emit < ip);
                    // trawl:
                    loop {
                        loop {
                            let hash_ = next_hash as usize;
                            let bytes_between_hash_lookups = (skip >> 5) as usize;
                            skip = skip.wrapping_add(1);
                            debug_assert!(next_hash == hash(input_base, next_ip, shift));
                            ip = next_ip;
                            next_ip = ip + bytes_between_hash_lookups;
                            if next_ip > ip_limit {
                                break 'body false;
                            }
                            next_hash = hash(input_base, next_ip, shift);
                            candidate = (ip as isize - last_distance as isize) as usize;
                            if is_match(input_base, ip, candidate) && candidate < ip {
                                table[hash_] = ip as i32;
                                break;
                            }
                            candidate = table[hash_] as usize;
                            debug_assert!(candidate < ip);

                            table[hash_] = ip as i32;
                            if is_match(input_base, ip, candidate) {
                                break;
                            }
                        }

                        // Check copy distance. If candidate is not feasible,
                        // continue search. Checking is done outside of hot loop
                        // to reduce overhead.
                        if ip as isize - candidate as isize > MAX_DISTANCE {
                            continue; // goto trawl
                        }
                        break;
                    }

                    // Step 2: Emit the found match together with the literal
                    // bytes from "next_emit" to the bit stream, and then see if
                    // we can find a next match immediately afterwards. Repeat
                    // until we find no match for the input without emitting
                    // some literal bytes.

                    {
                        // We have a 5-byte match at ip, and we need to emit
                        // bytes in [next_emit, ip).
                        let base = ip;
                        let matched = 5 + find_match_length_with_limit(
                            &input_base[candidate + 5..],
                            &input_base[ip + 5..],
                            ip_end - ip - 5,
                        );
                        let distance = (base - candidate) as i32; // > 0
                        let insert = base - next_emit;
                        ip += matched;
                        if insert < 6210 {
                            emit_insert_len(insert, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);
                        } else if should_use_uncompressed_mode(metablock_start, next_emit, insert, literal_ratio) {
                            emit_uncompressed_meta_block(
                                input_base,
                                metablock_start,
                                base,
                                mlen_storage_ix - 3,
                                storage_ix,
                                storage,
                            );
                            input_size -= base - input;
                            input = base;
                            next_emit = input;
                            break 'body true;
                        } else {
                            emit_long_insert_len(insert, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);
                        }
                        emit_literals(&input_base[next_emit..next_emit + insert], &s.lit_depth, &s.lit_bits, storage_ix, storage);
                        if distance == last_distance {
                            brotli_write_bits(s.cmd_depth[64] as usize, s.cmd_bits[64] as u64, storage_ix, storage);
                            s.cmd_histo[64] += 1;
                        } else {
                            emit_distance(distance as usize, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);
                            last_distance = distance;
                        }
                        emit_copy_len_last_distance(matched, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);

                        next_emit = ip;
                        if ip >= ip_limit {
                            break 'body false;
                        }
                        // We could immediately start working at ip now, but to
                        // improve compression we first update "table" with the
                        // hashes of some positions within the last copy.
                        {
                            let input_bytes = load64le(input_base, ip - 3);
                            let mut prev_hash = hash_bytes_at_offset(input_bytes, 0, shift) as usize;
                            let cur_hash = hash_bytes_at_offset(input_bytes, 3, shift) as usize;
                            table[prev_hash] = (ip - 3) as i32;
                            prev_hash = hash_bytes_at_offset(input_bytes, 1, shift) as usize;
                            table[prev_hash] = (ip - 2) as i32;
                            prev_hash = hash_bytes_at_offset(input_bytes, 2, shift) as usize;
                            table[prev_hash] = (ip - 1) as i32;

                            candidate = table[cur_hash] as usize;
                            table[cur_hash] = ip as i32;
                        }
                    }

                    while is_match(input_base, ip, candidate) {
                        // We have a 5-byte match at ip, and no need to emit any
                        // literal bytes prior to ip.
                        let base = ip;
                        let matched = 5 + find_match_length_with_limit(
                            &input_base[candidate + 5..],
                            &input_base[ip + 5..],
                            ip_end - ip - 5,
                        );
                        if ip as isize - candidate as isize > MAX_DISTANCE {
                            break;
                        }
                        ip += matched;
                        last_distance = (base - candidate) as i32; // > 0
                        emit_copy_len(matched, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);
                        emit_distance(last_distance as usize, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);

                        next_emit = ip;
                        if ip >= ip_limit {
                            break 'body false;
                        }
                        // We could immediately start working at ip now, but to
                        // improve compression we first update "table" with the
                        // hashes of some positions within the last copy.
                        {
                            let input_bytes = load64le(input_base, ip - 3);
                            let mut prev_hash = hash_bytes_at_offset(input_bytes, 0, shift) as usize;
                            let cur_hash = hash_bytes_at_offset(input_bytes, 3, shift) as usize;
                            table[prev_hash] = (ip - 3) as i32;
                            prev_hash = hash_bytes_at_offset(input_bytes, 1, shift) as usize;
                            table[prev_hash] = (ip - 2) as i32;
                            prev_hash = hash_bytes_at_offset(input_bytes, 2, shift) as usize;
                            table[prev_hash] = (ip - 1) as i32;

                            candidate = table[cur_hash] as usize;
                            table[cur_hash] = ip as i32;
                        }
                    }

                    ip += 1;
                    next_hash = hash(input_base, ip, shift);
                }
            }
            false
        };

        if !goto_next_block {
            // emit_remainder:
            debug_assert!(next_emit <= ip_end);
            input += block_size;
            input_size -= block_size;
            block_size = core::cmp::min(input_size, K_MERGE_BLOCK_SIZE);

            // Decide if we want to continue this meta-block instead of emitting
            // the last insert-only command.
            if input_size > 0
                && total_block_size + block_size <= (1 << 20)
                && should_merge_block(s, &input_base[input..], block_size)
            {
                debug_assert!(total_block_size > (1 << 16));
                // Update the size of the current meta-block and continue
                // emitting commands. We can do this because the current size
                // and the new size both have 5 nibbles.
                total_block_size += block_size;
                update_bits(20, (total_block_size - 1) as u32, mlen_storage_ix, storage);
                continue 'emit_commands;
            }

            // Emit the remaining bytes as literals.
            if next_emit < ip_end {
                let insert = ip_end - next_emit;
                if insert < 6210 {
                    emit_insert_len(insert, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);
                    emit_literals(&input_base[next_emit..next_emit + insert], &s.lit_depth, &s.lit_bits, storage_ix, storage);
                } else if should_use_uncompressed_mode(metablock_start, next_emit, insert, literal_ratio) {
                    emit_uncompressed_meta_block(input_base, metablock_start, ip_end, mlen_storage_ix - 3, storage_ix, storage);
                } else {
                    emit_long_insert_len(insert, &s.cmd_depth, &s.cmd_bits, &mut s.cmd_histo, storage_ix, storage);
                    emit_literals(&input_base[next_emit..next_emit + insert], &s.lit_depth, &s.lit_bits, storage_ix, storage);
                }
            }
            next_emit = ip_end;
        }

        // next_block:
        // If we have more data, write a new meta-block header and prefix codes
        // and then continue emitting commands.
        if input_size > 0 {
            metablock_start = input;
            block_size = core::cmp::min(input_size, K_FIRST_BLOCK_SIZE);
            total_block_size = block_size;
            // Save the bit position of the MLEN field of the meta-block header,
            // so that we can update it later if we decide to extend this
            // meta-block.
            mlen_storage_ix = *storage_ix + 3;
            brotli_store_meta_block_header(block_size, false, storage_ix, storage);
            // No block splits, no contexts.
            brotli_write_bits(13, 0, storage_ix, storage);
            literal_ratio = build_and_store_literal_prefix_code(s, &input_base[input..], block_size, storage_ix, storage);
            build_and_store_command_prefix_code(s, storage_ix, storage);
            continue 'emit_commands;
        }
        break;
    }
    let _ = next_emit;

    if !is_last {
        // If this is not the last block, update the command and distance
        // prefix codes for the next block and store the compressed forms.
        s.cmd_code[0] = 0;
        s.cmd_code_numbits = 0;
        let mut cmd_code = s.cmd_code;
        let mut cmd_code_numbits = s.cmd_code_numbits;
        build_and_store_command_prefix_code(s, &mut cmd_code_numbits, &mut cmd_code);
        s.cmd_code = cmd_code;
        s.cmd_code_numbits = cmd_code_numbits;
    }
}

/// `BrotliCompressFragmentFast`.
///
/// Compresses `input[..input_size]` into a complete meta-block (the C
/// version reads only within `input_size`).  `table` is a hash table of
/// `table_size` entries (power of two, odd log2 in `[9, 15]`), zeroed by the
/// caller.  Output is written to `storage` at bit position `*storage_ix`.
///
/// If `is_last` is true, emits an additional empty last meta-block.
///
/// `s.cmd_depth` and `s.cmd_bits` contain the command and distance prefix
/// codes used for the encoding of this input fragment.  If `is_last` is
/// false, they are updated to reflect the statistics of this input fragment,
/// to be used for the encoding of the next fragment.
///
/// REQUIRES: `input_size` is greater than zero, or `is_last` is true.
/// REQUIRES: `input_size` is less or equal to maximal metablock size (1 << 24).
/// REQUIRES: All elements in `table[0..table_size-1]` are initialized to zero.
/// REQUIRES: `table_size` is an odd (9, 11, 13, 15) power of two.
/// OUTPUT: maximal copy distance <= `input_size`
/// OUTPUT: maximal copy distance <= BROTLI_MAX_BACKWARD_LIMIT(18)
#[allow(clippy::too_many_arguments)]
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
    let initial_storage_ix = *storage_ix;
    let table_bits = log2_floor_non_zero(table_size) as usize;

    if input_size == 0 {
        debug_assert!(is_last);
        brotli_write_bits(1, 1, storage_ix, storage); // islast
        brotli_write_bits(1, 1, storage_ix, storage); // isempty
        *storage_ix = round_up_to_byte(*storage_ix);
        return;
    }

    let input = &input[..input_size];
    match table_bits {
        9 => brotli_compress_fragment_fast_impl::<9>(s, input, input_size, is_last, table, storage_ix, storage),
        11 => brotli_compress_fragment_fast_impl::<11>(s, input, input_size, is_last, table, storage_ix, storage),
        13 => brotli_compress_fragment_fast_impl::<13>(s, input, input_size, is_last, table, storage_ix, storage),
        15 => brotli_compress_fragment_fast_impl::<15>(s, input, input_size, is_last, table, storage_ix, storage),
        _ => debug_assert!(false, "unsupported table size"),
    }

    // If output is larger than single uncompressed block, rewrite it.
    if (*storage_ix).wrapping_sub(initial_storage_ix) > 31 + (input_size << 3) {
        emit_uncompressed_meta_block(input, 0, input_size, initial_storage_ix, storage_ix, storage);
    }

    if is_last {
        brotli_write_bits(1, 1, storage_ix, storage); // islast
        brotli_write_bits(1, 1, storage_ix, storage); // isempty
        *storage_ix = round_up_to_byte(*storage_ix);
    }
}
