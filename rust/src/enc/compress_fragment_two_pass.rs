//! Port of `c/enc/compress_fragment_two_pass.h` /
//! `compress_fragment_two_pass.c`: function for fast encoding of an input
//! fragment, independently from the input history (quality 1).
//!
//! This function uses two-pass processing: in the first pass we save the
//! found backward matches and literal bytes into a buffer, and in the second
//! pass we emit them into the bit stream using prefix codes built based on
//! the actual command and literal byte histograms.
//!
//! OWNER: worker "entropy".

use super::bit_cost::brotli_bits_entropy;
use super::brotli_bit_stream::{brotli_build_and_store_huffman_tree_fast, brotli_store_huffman_tree};
use super::compress_fragment::{
    brotli_store_meta_block_header, load32le, load64le, rewind_bit_position, round_up_to_byte, K_HASH_MUL32,
};
use super::entropy_encode::{brotli_convert_bit_depths_to_symbols, brotli_create_huffman_tree, HuffmanTree};
use super::fast_log::log2_floor_non_zero;
use super::find_match_length::find_match_length_with_limit;
use super::write_bits::brotli_write_bits;
use crate::common::constants::{brotli_max_backward_limit, BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS, BROTLI_WINDOW_GAP};

/// `kCompressFragmentTwoPassBlockSize`.
pub const K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE: usize = 1 << 17;

/// `BrotliTwoPassArena` (`#[repr(C)]`: same size as the C struct, which
/// matters for `BrotliEncoderEstimatePeakMemoryUsage`).
#[repr(C)]
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

/// `MAX_DISTANCE`.
const MAX_DISTANCE: isize = brotli_max_backward_limit(18) as isize;

#[inline(always)]
fn hash(p: &[u8], i: usize, shift: usize, length: usize) -> u32 {
    let h = (load64le(p, i) << ((8 - length) * 8)).wrapping_mul(K_HASH_MUL32 as u64);
    (h >> shift) as u32
}

#[inline(always)]
fn hash_bytes_at_offset(v: u64, offset: usize, shift: usize, length: usize) -> u32 {
    debug_assert!(offset <= 8 - length);
    let h = ((v >> (8 * offset)) << ((8 - length) * 8)).wrapping_mul(K_HASH_MUL32 as u64);
    (h >> shift) as u32
}

#[inline(always)]
fn is_match(p: &[u8], p1: usize, p2: usize, length: usize) -> bool {
    if load32le(p, p1) == load32le(p, p2) {
        if length == 4 {
            return true;
        }
        return p[p1 + 4] == p[p2 + 4] && p[p1 + 5] == p[p2 + 5];
    }
    false
}

/// Builds a command and distance prefix code (each 64 symbols) into "depth"
/// and "bits" based on "histogram" and stores it into the bit stream.
fn build_and_store_command_prefix_code(s: &mut BrotliTwoPassArena, storage_ix: &mut usize, storage: &mut [u8]) {
    // Tree size for building a tree over 64 symbols is 2 * 64 + 1.
    // TODO(eustas): initialize once.
    s.tmp_depth = [0; BROTLI_NUM_COMMAND_SYMBOLS];
    brotli_create_huffman_tree(&s.cmd_histo, 64, 15, &mut s.tmp_tree, &mut s.cmd_depth);
    brotli_create_huffman_tree(&s.cmd_histo[64..], 64, 14, &mut s.tmp_tree, &mut s.cmd_depth[64..]);
    // We have to jump through a few hoops here in order to compute
    // the command bits because the symbols are in a different order than in
    // the full alphabet. This looks complicated, but having the symbols
    // in this order in the command bits saves a few branches in the Emit*
    // functions.
    s.tmp_depth[0..24].copy_from_slice(&s.cmd_depth[24..48]);
    s.tmp_depth[24..32].copy_from_slice(&s.cmd_depth[0..8]);
    s.tmp_depth[32..40].copy_from_slice(&s.cmd_depth[48..56]);
    s.tmp_depth[40..48].copy_from_slice(&s.cmd_depth[8..16]);
    s.tmp_depth[48..56].copy_from_slice(&s.cmd_depth[56..64]);
    s.tmp_depth[56..64].copy_from_slice(&s.cmd_depth[16..24]);
    brotli_convert_bit_depths_to_symbols(&s.tmp_depth, 64, &mut s.tmp_bits);
    s.cmd_bits[0..8].copy_from_slice(&s.tmp_bits[24..32]);
    s.cmd_bits[8..16].copy_from_slice(&s.tmp_bits[40..48]);
    s.cmd_bits[16..24].copy_from_slice(&s.tmp_bits[56..64]);
    s.cmd_bits[24..48].copy_from_slice(&s.tmp_bits[0..24]);
    s.cmd_bits[48..56].copy_from_slice(&s.tmp_bits[32..40]);
    s.cmd_bits[56..64].copy_from_slice(&s.tmp_bits[48..56]);
    brotli_convert_bit_depths_to_symbols(&s.cmd_depth[64..], 64, &mut s.cmd_bits[64..]);
    {
        // Create the bit length array for the full command alphabet.
        for d in s.tmp_depth[..64].iter_mut() {
            *d = 0; // only 64 first values were used
        }
        s.tmp_depth[0..8].copy_from_slice(&s.cmd_depth[24..32]);
        s.tmp_depth[64..72].copy_from_slice(&s.cmd_depth[32..40]);
        s.tmp_depth[128..136].copy_from_slice(&s.cmd_depth[40..48]);
        s.tmp_depth[192..200].copy_from_slice(&s.cmd_depth[48..56]);
        s.tmp_depth[384..392].copy_from_slice(&s.cmd_depth[56..64]);
        for i in 0..8 {
            s.tmp_depth[128 + 8 * i] = s.cmd_depth[i];
            s.tmp_depth[256 + 8 * i] = s.cmd_depth[8 + i];
            s.tmp_depth[448 + 8 * i] = s.cmd_depth[16 + i];
        }
        brotli_store_huffman_tree(&s.tmp_depth, BROTLI_NUM_COMMAND_SYMBOLS, &mut s.tmp_tree, storage_ix, storage);
    }
    brotli_store_huffman_tree(&s.cmd_depth[64..], 64, &mut s.tmp_tree, storage_ix, storage);
}

/// Output of the first pass: commands and literals buffers with their fill
/// levels (the C version advances `*commands` / `*literals` pointers).
struct CommandSink<'a> {
    commands: &'a mut [u32],
    num_commands: usize,
    literals: &'a mut [u8],
    num_literals: usize,
}

impl<'a> CommandSink<'a> {
    #[inline(always)]
    fn push(&mut self, v: u32) {
        self.commands[self.num_commands] = v;
        self.num_commands += 1;
    }

    #[inline(always)]
    fn push_literals(&mut self, src: &[u8]) {
        self.literals[self.num_literals..self.num_literals + src.len()].copy_from_slice(src);
        self.num_literals += src.len();
    }
}

#[inline(always)]
fn emit_insert_len(insertlen: u32, out: &mut CommandSink) {
    if insertlen < 6 {
        out.push(insertlen);
    } else if insertlen < 130 {
        let tail = insertlen - 2;
        let nbits = log2_floor_non_zero(tail as usize) - 1;
        let prefix = tail >> nbits;
        let inscode = (nbits << 1) + prefix + 2;
        let extra = tail - (prefix << nbits);
        out.push(inscode | (extra << 8));
    } else if insertlen < 2114 {
        let tail = insertlen - 66;
        let nbits = log2_floor_non_zero(tail as usize);
        let code = nbits + 10;
        let extra = tail - (1u32 << nbits);
        out.push(code | (extra << 8));
    } else if insertlen < 6210 {
        let extra = insertlen - 2114;
        out.push(21 | (extra << 8));
    } else if insertlen < 22594 {
        let extra = insertlen - 6210;
        out.push(22 | (extra << 8));
    } else {
        let extra = insertlen - 22594;
        out.push(23 | (extra << 8));
    }
}

#[inline(always)]
fn emit_copy_len(copylen: usize, out: &mut CommandSink) {
    if copylen < 10 {
        out.push((copylen + 38) as u32);
    } else if copylen < 134 {
        let tail = copylen - 6;
        let nbits = log2_floor_non_zero(tail) as usize - 1;
        let prefix = tail >> nbits;
        let code = (nbits << 1) + prefix + 44;
        let extra = tail - (prefix << nbits);
        out.push((code | (extra << 8)) as u32);
    } else if copylen < 2118 {
        let tail = copylen - 70;
        let nbits = log2_floor_non_zero(tail) as usize;
        let code = nbits + 52;
        let extra = tail - (1usize << nbits);
        out.push((code | (extra << 8)) as u32);
    } else {
        let extra = copylen - 2118;
        out.push((63 | (extra << 8)) as u32);
    }
}

#[inline(always)]
fn emit_copy_len_last_distance(copylen: usize, out: &mut CommandSink) {
    if copylen < 12 {
        out.push((copylen + 20) as u32);
    } else if copylen < 72 {
        let tail = copylen - 8;
        let nbits = log2_floor_non_zero(tail) as usize - 1;
        let prefix = tail >> nbits;
        let code = (nbits << 1) + prefix + 28;
        let extra = tail - (prefix << nbits);
        out.push((code | (extra << 8)) as u32);
    } else if copylen < 136 {
        let tail = copylen - 8;
        let code = (tail >> 5) + 54;
        let extra = tail & 31;
        out.push((code | (extra << 8)) as u32);
        out.push(64);
    } else if copylen < 2120 {
        let tail = copylen - 72;
        let nbits = log2_floor_non_zero(tail) as usize;
        let code = nbits + 52;
        let extra = tail - (1usize << nbits);
        out.push((code | (extra << 8)) as u32);
        out.push(64);
    } else {
        let extra = copylen - 2120;
        out.push((63 | (extra << 8)) as u32);
        out.push(64);
    }
}

#[inline(always)]
fn emit_distance(distance: u32, out: &mut CommandSink) {
    let d = distance + 3;
    let nbits = log2_floor_non_zero(d as usize) - 1;
    let prefix = (d >> nbits) & 1;
    let offset = (2 + prefix) << nbits;
    let distcode = 2 * (nbits - 1) + prefix + 80;
    let extra = d - offset;
    out.push(distcode | (extra << 8));
}

/// Updates "table" with the hashes of some positions within the last copy
/// and returns the next candidate (the "We could immediately start working at
/// ip now, but to improve compression..." blocks of `CreateCommands`).
/// `third_offset` is the hash offset used for position `ip - 1` in the
/// `min_match == 4` case (0 in the first block of the C code, 2 in the
/// second one).
#[inline(always)]
fn update_table_after_copy(
    input: &[u8],
    ip: usize,
    table: &mut [i32],
    shift: usize,
    min_match: usize,
    third_offset: usize,
) -> usize {
    let cur_hash: usize;
    if min_match == 4 {
        let input_bytes = load64le(input, ip - 3);
        cur_hash = hash_bytes_at_offset(input_bytes, 3, shift, min_match) as usize;
        let mut prev_hash = hash_bytes_at_offset(input_bytes, 0, shift, min_match) as usize;
        table[prev_hash] = (ip - 3) as i32;
        prev_hash = hash_bytes_at_offset(input_bytes, 1, shift, min_match) as usize;
        table[prev_hash] = (ip - 2) as i32;
        prev_hash = hash_bytes_at_offset(input_bytes, third_offset, shift, min_match) as usize;
        table[prev_hash] = (ip - 1) as i32;
    } else {
        let mut input_bytes = load64le(input, ip - 5);
        let mut prev_hash = hash_bytes_at_offset(input_bytes, 0, shift, min_match) as usize;
        table[prev_hash] = (ip - 5) as i32;
        prev_hash = hash_bytes_at_offset(input_bytes, 1, shift, min_match) as usize;
        table[prev_hash] = (ip - 4) as i32;
        prev_hash = hash_bytes_at_offset(input_bytes, 2, shift, min_match) as usize;
        table[prev_hash] = (ip - 3) as i32;
        input_bytes = load64le(input, ip - 2);
        cur_hash = hash_bytes_at_offset(input_bytes, 2, shift, min_match) as usize;
        prev_hash = hash_bytes_at_offset(input_bytes, 0, shift, min_match) as usize;
        table[prev_hash] = (ip - 2) as i32;
        prev_hash = hash_bytes_at_offset(input_bytes, 1, shift, min_match) as usize;
        table[prev_hash] = (ip - 1) as i32;
    }

    let candidate = table[cur_hash] as usize;
    table[cur_hash] = ip as i32;
    candidate
}

/// `CreateCommands`.  All positions are offsets into `input_base` (the
/// "base_ip" of C); `input` is the start of the current block.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn create_commands(
    input_base: &[u8],
    input: usize,
    block_size: usize,
    input_size: usize,
    table: &mut [i32],
    table_bits: usize,
    min_match: usize,
    out: &mut CommandSink,
) {
    // "ip" is the input pointer.
    let mut ip: usize = input;
    let shift: usize = 64 - table_bits;
    let ip_end: usize = input + block_size;
    // "next_emit" is a pointer to the first byte that is not covered by a
    // previous copy. Bytes between "next_emit" and the start of the next copy
    // or the end of the input will be emitted as literal bytes.
    let mut next_emit: usize = input;

    let mut last_distance: i32 = -1;
    const K_INPUT_MARGIN_BYTES: usize = BROTLI_WINDOW_GAP;

    'emit_remainder: {
        if block_size >= K_INPUT_MARGIN_BYTES {
            // For the last block, we need to keep a 16 bytes margin so that we
            // can be sure that all distances are at most window size - 16.
            // For all other blocks, we only need to keep a margin of 5 bytes so
            // that we don't go over the block size with a copy.
            let len_limit = core::cmp::min(block_size - min_match, input_size - K_INPUT_MARGIN_BYTES);
            let ip_limit = input + len_limit;

            ip += 1;
            let mut next_hash = hash(input_base, ip, shift, min_match);
            loop {
                // Step 1: Scan forward in the input looking for a 6-byte-long
                // match. If we get close to exhausting the input then goto
                // emit_remainder.
                //
                // Heuristic match skipping: If 32 bytes are scanned with no
                // matches found, start looking only at every other byte. If 32
                // more bytes are scanned, look at every third byte, etc.. When a
                // match is found, immediately go back to looking at every byte.
                // This is a small loss (~5% performance, ~0.1% density) for
                // compressible data due to more bookkeeping, but for
                // non-compressible data (such as JPEG) it's a huge win since the
                // compressor quickly "realizes" the data is incompressible and
                // doesn't bother looking for matches everywhere.
                //
                // The "skip" variable keeps track of how many bytes there are
                // since the last match; dividing it by 32 (ie. right-shifting by
                // five) gives the number of bytes to move ahead for each
                // iteration.
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
                        ip = next_ip;
                        debug_assert!(hash_ as u32 == hash(input_base, ip, shift, min_match));
                        next_ip = ip + bytes_between_hash_lookups;
                        if next_ip > ip_limit {
                            break 'emit_remainder;
                        }
                        next_hash = hash(input_base, next_ip, shift, min_match);
                        candidate = (ip as isize - last_distance as isize) as usize;
                        if is_match(input_base, ip, candidate, min_match) && candidate < ip {
                            table[hash_] = ip as i32;
                            break;
                        }
                        candidate = table[hash_] as usize;
                        debug_assert!(candidate < ip);

                        table[hash_] = ip as i32;
                        if is_match(input_base, ip, candidate, min_match) {
                            break;
                        }
                    }

                    // Check copy distance. If candidate is not feasible,
                    // continue search. Checking is done outside of hot loop to
                    // reduce overhead.
                    if ip as isize - candidate as isize > MAX_DISTANCE {
                        continue; // goto trawl
                    }
                    break;
                }

                // Step 2: Emit the found match together with the literal bytes
                // from "next_emit", and then see if we can find a next match
                // immediately afterwards. Repeat until we find no match for the
                // input without emitting some literal bytes.

                {
                    // We have a 6-byte match at ip, and we need to emit bytes in
                    // [next_emit, ip).
                    let base = ip;
                    let matched = min_match
                        + find_match_length_with_limit(
                            &input_base[candidate + min_match..],
                            &input_base[ip + min_match..],
                            ip_end - ip - min_match,
                        );
                    let distance = (base - candidate) as i32; // > 0
                    let insert = (base - next_emit) as i32;
                    ip += matched;
                    emit_insert_len(insert as u32, out);
                    out.push_literals(&input_base[next_emit..next_emit + insert as usize]);
                    if distance == last_distance {
                        out.push(64);
                    } else {
                        emit_distance(distance as u32, out);
                        last_distance = distance;
                    }
                    emit_copy_len_last_distance(matched, out);

                    next_emit = ip;
                    if ip >= ip_limit {
                        break 'emit_remainder;
                    }
                    candidate = update_table_after_copy(input_base, ip, table, shift, min_match, 0);
                }

                while ip as isize - candidate as isize <= MAX_DISTANCE && is_match(input_base, ip, candidate, min_match) {
                    // We have a 6-byte match at ip, and no need to emit any
                    // literal bytes prior to ip.
                    let base = ip;
                    let matched = min_match
                        + find_match_length_with_limit(
                            &input_base[candidate + min_match..],
                            &input_base[ip + min_match..],
                            ip_end - ip - min_match,
                        );
                    ip += matched;
                    last_distance = (base - candidate) as i32; // > 0
                    emit_copy_len(matched, out);
                    emit_distance(last_distance as u32, out);

                    next_emit = ip;
                    if ip >= ip_limit {
                        break 'emit_remainder;
                    }
                    candidate = update_table_after_copy(input_base, ip, table, shift, min_match, 2);
                }

                ip += 1;
                next_hash = hash(input_base, ip, shift, min_match);
            }
        }
    }

    // emit_remainder:
    debug_assert!(next_emit <= ip_end);
    // Emit the remaining bytes as literals.
    if next_emit < ip_end {
        let insert = (ip_end - next_emit) as u32;
        emit_insert_len(insert, out);
        out.push_literals(&input_base[next_emit..ip_end]);
    }
}

fn store_commands(
    s: &mut BrotliTwoPassArena,
    literals: &[u8],
    num_literals: usize,
    commands: &[u32],
    num_commands: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    const K_NUM_EXTRA_BITS: [u32; 128] = [
        0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2,
        3, 3, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
        14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24,
    ];
    const K_INSERT_OFFSET: [u32; 24] =
        [0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594];

    s.lit_histo = [0; 256];
    // TODO(eustas): is that necessary?
    s.cmd_depth = [0; 128];
    // TODO(eustas): is that necessary?
    s.cmd_bits = [0; 128];
    s.cmd_histo = [0; 128];
    for &l in literals[..num_literals].iter() {
        s.lit_histo[l as usize] += 1;
    }
    brotli_build_and_store_huffman_tree_fast(
        &mut s.tmp_tree,
        &s.lit_histo,
        num_literals,
        /* max_bits = */ 8,
        &mut s.lit_depth,
        &mut s.lit_bits,
        storage_ix,
        storage,
    );

    for &c in commands[..num_commands].iter() {
        let code = (c & 0xFF) as usize;
        debug_assert!(code < 128);
        s.cmd_histo[code] += 1;
    }
    s.cmd_histo[1] += 1;
    s.cmd_histo[2] += 1;
    s.cmd_histo[64] += 1;
    s.cmd_histo[84] += 1;
    build_and_store_command_prefix_code(s, storage_ix, storage);

    let mut lit_pos: usize = 0;
    for &cmd in commands[..num_commands].iter() {
        let code = (cmd & 0xFF) as usize;
        let extra = cmd >> 8;
        debug_assert!(code < 128);
        brotli_write_bits(s.cmd_depth[code] as usize, s.cmd_bits[code] as u64, storage_ix, storage);
        brotli_write_bits(K_NUM_EXTRA_BITS[code] as usize, extra as u64, storage_ix, storage);
        if code < 24 {
            let insert = K_INSERT_OFFSET[code].wrapping_add(extra);
            for _ in 0..insert {
                let lit = literals[lit_pos] as usize;
                brotli_write_bits(s.lit_depth[lit] as usize, s.lit_bits[lit] as u64, storage_ix, storage);
                lit_pos += 1;
            }
        }
    }
}

/// Acceptable loss for uncompressible speedup is 2%
const MIN_RATIO: f64 = 0.98;
const SAMPLE_RATE: usize = 43;

fn should_compress(s: &mut BrotliTwoPassArena, input: &[u8], input_size: usize, num_literals: usize) -> bool {
    let corpus_size = input_size as f64;
    if (num_literals as f64) < MIN_RATIO * corpus_size {
        true
    } else {
        let max_total_bit_cost = corpus_size * 8.0 * MIN_RATIO / SAMPLE_RATE as f64;
        s.lit_histo = [0; 256];
        let mut i = 0;
        while i < input_size {
            s.lit_histo[input[i] as usize] += 1;
            i += SAMPLE_RATE;
        }
        brotli_bits_entropy(&s.lit_histo, 256) < max_total_bit_cost
    }
}

fn emit_uncompressed_meta_block(input: &[u8], input_size: usize, storage_ix: &mut usize, storage: &mut [u8]) {
    brotli_store_meta_block_header(input_size, true, storage_ix, storage);
    *storage_ix = round_up_to_byte(*storage_ix);
    let dst = *storage_ix >> 3;
    storage[dst..dst + input_size].copy_from_slice(&input[..input_size]);
    *storage_ix += input_size << 3;
    storage[*storage_ix >> 3] = 0;
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn brotli_compress_fragment_two_pass_impl<const TABLE_BITS: usize>(
    s: &mut BrotliTwoPassArena,
    input_base: &[u8],
    mut input_size: usize,
    command_buf: &mut [u32],
    literal_buf: &mut [u8],
    table: &mut [i32],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let min_match: usize = if TABLE_BITS <= 15 { 4 } else { 6 };
    // Save the start of the first block for position and distance
    // computations (positions are offsets from the start of `input_base`).
    let mut input: usize = 0;

    while input_size > 0 {
        let block_size = core::cmp::min(input_size, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE);
        let mut sink = CommandSink { commands: &mut *command_buf, num_commands: 0, literals: &mut *literal_buf, num_literals: 0 };
        create_commands(input_base, input, block_size, input_size, table, TABLE_BITS, min_match, &mut sink);
        let num_literals = sink.num_literals;
        let num_commands = sink.num_commands;
        if should_compress(s, &input_base[input..], block_size, num_literals) {
            brotli_store_meta_block_header(block_size, false, storage_ix, storage);
            // No block splits, no contexts.
            brotli_write_bits(13, 0, storage_ix, storage);
            store_commands(s, literal_buf, num_literals, command_buf, num_commands, storage_ix, storage);
        } else {
            // Since we did not find many backward references and the entropy
            // of the data is close to 8 bits, we can simply emit an
            // uncompressed block. This makes compression speed of
            // uncompressible data about 3x faster.
            emit_uncompressed_meta_block(&input_base[input..], block_size, storage_ix, storage);
        }
        input += block_size;
        input_size -= block_size;
    }
}

/// `BrotliCompressFragmentTwoPass`.
///
/// Compresses `input[..input_size]`.  `command_buf` and `literal_buf` are
/// scratch buffers of at least `min(input_size,
/// K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE)` entries.  `table` is a hash
/// table of `table_size` entries (power of two), zeroed by the caller.
///
/// If `is_last` is true, emits an additional empty last meta-block.
///
/// REQUIRES: `input_size` is greater than zero, or `is_last` is true.
/// REQUIRES: `input_size` is less or equal to maximal metablock size (1 << 24).
/// REQUIRES: All elements in `table[0..table_size-1]` are initialized to zero.
/// REQUIRES: `table_size` is a power of two
/// OUTPUT: maximal copy distance <= `input_size`
/// OUTPUT: maximal copy distance <= BROTLI_MAX_BACKWARD_LIMIT(18)
#[allow(clippy::too_many_arguments)]
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
    let initial_storage_ix = *storage_ix;
    let table_bits = log2_floor_non_zero(table_size) as usize;
    let input = &input[..input_size];
    macro_rules! case {
        ($b:literal) => {
            brotli_compress_fragment_two_pass_impl::<$b>(
                s,
                input,
                input_size,
                command_buf,
                literal_buf,
                table,
                storage_ix,
                storage,
            )
        };
    }
    match table_bits {
        8 => case!(8),
        9 => case!(9),
        10 => case!(10),
        11 => case!(11),
        12 => case!(12),
        13 => case!(13),
        14 => case!(14),
        15 => case!(15),
        16 => case!(16),
        17 => case!(17),
        _ => debug_assert!(false, "unsupported table size"),
    }

    // If output is larger than single uncompressed block, rewrite it.
    if (*storage_ix).wrapping_sub(initial_storage_ix) > 31 + (input_size << 3) {
        rewind_bit_position(initial_storage_ix, storage_ix, storage);
        emit_uncompressed_meta_block(input, input_size, storage_ix, storage);
    }

    if is_last {
        brotli_write_bits(1, 1, storage_ix, storage); // islast
        brotli_write_bits(1, 1, storage_ix, storage); // isempty
        *storage_ix = round_up_to_byte(*storage_ix);
    }
}
