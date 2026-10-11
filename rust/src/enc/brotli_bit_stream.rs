//! Port of `c/enc/brotli_bit_stream.h` / `brotli_bit_stream.c` /
//! `block_encoder_inc.h`: functions to convert brotli-related data
//! structures into the brotli bit stream.
//!
//! All `storage` slices are the output buffer; `storage_ix` is the bit
//! position.  `input` is the ring buffer addressed with `& mask`.
//!
//! As in C, the functions here operate under assumption that there is enough
//! space in the storage (slice indexing panics otherwise).
//!
//! OWNER: worker "entropy".

use super::command::{
    get_copy_base, get_copy_extra, get_copy_length_code, get_insert_base, get_insert_extra, get_insert_length_code,
    Command,
};
use super::entropy_encode::{
    brotli_convert_bit_depths_to_symbols, brotli_create_huffman_tree, brotli_set_depth, brotli_write_huffman_tree,
    sort_huffman_tree_items, HuffmanTree,
};
use super::entropy_encode_static::{
    store_static_code_length_code, store_static_command_huffman_tree, store_static_distance_huffman_tree,
    K_CODE_LENGTH_BITS, K_CODE_LENGTH_DEPTH, K_NON_ZERO_REPS_BITS, K_NON_ZERO_REPS_DEPTH, K_STATIC_COMMAND_CODE_BITS,
    K_STATIC_COMMAND_CODE_DEPTH, K_STATIC_DISTANCE_CODE_BITS, K_STATIC_DISTANCE_CODE_DEPTH, K_ZERO_REPS_BITS,
    K_ZERO_REPS_DEPTH,
};
use super::fast_log::log2_floor_non_zero;
use super::histogram::{Histogram, HistogramCommand, HistogramDistance, HistogramLiteral};
use super::memory::{Boxed, Buf, MemoryManager};
use super::metablock::MetaBlockSplit;
use super::params::{BrotliEncoderParams, K_IS_BASE64};
use super::write_bits::{brotli_write_bits, brotli_write_bits_prepare_storage};
use crate::common::constants::{
    brotli_distance_alphabet_size, BROTLI_CODE_LENGTH_CODES, BROTLI_DISTANCE_CONTEXT_BITS, BROTLI_LARGE_MAX_DISTANCE_BITS,
    BROTLI_LITERAL_CONTEXT_BITS, BROTLI_MAX_BLOCK_TYPE_SYMBOLS, BROTLI_MAX_CONTEXT_MAP_SYMBOLS,
    BROTLI_NUM_BLOCK_LEN_SYMBOLS, BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS,
    BROTLI_REPEAT_PREVIOUS_CODE_LENGTH, BROTLI_REPEAT_ZERO_CODE_LENGTH, K_BROTLI_PREFIX_CODE_RANGES,
};
use crate::common::context::{brotli_context, brotli_context_lut, ContextType};

const MAX_HUFFMAN_TREE_SIZE: usize = 2 * BROTLI_NUM_COMMAND_SYMBOLS + 1;
/// The maximum size of Huffman dictionary for distances assuming that
/// NPOSTFIX = 0 and NDIRECT = 0.
const MAX_SIMPLE_DISTANCE_ALPHABET_SIZE: usize = brotli_distance_alphabet_size(0, 0, BROTLI_LARGE_MAX_DISTANCE_BITS) as usize;
// MAX_SIMPLE_DISTANCE_ALPHABET_SIZE == 140
const _: () = assert!(MAX_SIMPLE_DISTANCE_ALPHABET_SIZE == 140);

const MAX_BLOCK_TYPE_SYMBOLS: usize = BROTLI_MAX_BLOCK_TYPE_SYMBOLS as usize;
const MAX_CONTEXT_MAP_SYMBOLS: usize = BROTLI_MAX_CONTEXT_MAP_SYMBOLS as usize;

#[inline]
fn block_length_prefix_code(len: u32) -> u32 {
    let mut code: u32 = if len >= 177 {
        if len >= 753 {
            20
        } else {
            14
        }
    } else if len >= 41 {
        7
    } else {
        0
    };
    while code < (BROTLI_NUM_BLOCK_LEN_SYMBOLS - 1) as u32 && len >= K_BROTLI_PREFIX_CODE_RANGES[code as usize + 1].offset as u32 {
        code += 1;
    }
    code
}

/// `GetBlockLengthPrefixCode`: returns `(code, n_extra, extra)`.
#[inline]
fn get_block_length_prefix_code(len: u32) -> (usize, u32, u32) {
    let code = block_length_prefix_code(len) as usize;
    let n_extra = K_BROTLI_PREFIX_CODE_RANGES[code].nbits as u32;
    let extra = len.wrapping_sub(K_BROTLI_PREFIX_CODE_RANGES[code].offset as u32);
    (code, n_extra, extra)
}

#[derive(Clone, Copy)]
struct BlockTypeCodeCalculator {
    last_type: usize,
    second_last_type: usize,
}

impl BlockTypeCodeCalculator {
    /// `InitBlockTypeCodeCalculator`.
    fn new() -> Self {
        BlockTypeCodeCalculator { last_type: 1, second_last_type: 0 }
    }
}

#[inline]
fn next_block_type_code(calculator: &mut BlockTypeCodeCalculator, type_: u8) -> usize {
    let t = type_ as usize;
    let type_code = if t == calculator.last_type.wrapping_add(1) {
        1
    } else if t == calculator.second_last_type {
        0
    } else {
        t + 2
    };
    calculator.second_last_type = calculator.last_type;
    calculator.last_type = t;
    type_code
}

/// `BrotliEncodeMlen`: returns `(bits, numbits, nibblesbits)`;
/// `nibblesbits` represents the 2 bits to encode MNIBBLES (0-3).
/// REQUIRES: length > 0
/// REQUIRES: length <= (1 << 24)
#[inline]
fn brotli_encode_mlen(length: usize) -> (u64, usize, u64) {
    let lg: usize = if length == 1 { 1 } else { log2_floor_non_zero((length - 1) as u32 as usize) as usize + 1 };
    let mnibbles: usize = (if lg < 16 { 16 } else { lg + 3 }) / 4;
    debug_assert!(length > 0);
    debug_assert!(length <= (1 << 24));
    debug_assert!(lg <= 24);
    ((length as u64).wrapping_sub(1), mnibbles * 4, (mnibbles as u64).wrapping_sub(4))
}

#[inline]
fn store_command_extra(cmd: &Command, storage_ix: &mut usize, storage: &mut [u8]) {
    let copylen_code = cmd.copy_len_code();
    let inscode = get_insert_length_code(cmd.insert_len_ as usize);
    let copycode = get_copy_length_code(copylen_code as usize);
    let insnumextra = get_insert_extra(inscode);
    let insextraval = cmd.insert_len_.wrapping_sub(get_insert_base(inscode)) as u64;
    let copyextraval = copylen_code.wrapping_sub(get_copy_base(copycode)) as u64;
    let bits = (copyextraval << insnumextra) | insextraval;
    brotli_write_bits((insnumextra + get_copy_extra(copycode)) as usize, bits, storage_ix, storage);
}

/// Data structure that stores almost everything that is needed to encode
/// each block switch command.
#[derive(Clone, Copy)]
struct BlockSplitCode {
    type_code_calculator: BlockTypeCodeCalculator,
    type_depths: [u8; MAX_BLOCK_TYPE_SYMBOLS],
    type_bits: [u16; MAX_BLOCK_TYPE_SYMBOLS],
    length_depths: [u8; BROTLI_NUM_BLOCK_LEN_SYMBOLS],
    length_bits: [u16; BROTLI_NUM_BLOCK_LEN_SYMBOLS],
}

impl BlockSplitCode {
    fn new() -> Self {
        BlockSplitCode {
            type_code_calculator: BlockTypeCodeCalculator::new(),
            type_depths: [0; MAX_BLOCK_TYPE_SYMBOLS],
            type_bits: [0; MAX_BLOCK_TYPE_SYMBOLS],
            length_depths: [0; BROTLI_NUM_BLOCK_LEN_SYMBOLS],
            length_bits: [0; BROTLI_NUM_BLOCK_LEN_SYMBOLS],
        }
    }
}

/// Stores a number between 0 and 255.
fn store_var_len_uint8(n: usize, storage_ix: &mut usize, storage: &mut [u8]) {
    if n == 0 {
        brotli_write_bits(1, 0, storage_ix, storage);
    } else {
        let nbits = log2_floor_non_zero(n) as usize;
        brotli_write_bits(1, 1, storage_ix, storage);
        brotli_write_bits(3, nbits as u64, storage_ix, storage);
        brotli_write_bits(nbits, n.wrapping_sub(1usize << nbits) as u64, storage_ix, storage);
    }
}

/// Stores the compressed meta-block header.
/// REQUIRES: length > 0
/// REQUIRES: length <= (1 << 24)
fn store_compressed_meta_block_header(is_final_block: bool, length: usize, storage_ix: &mut usize, storage: &mut [u8]) {
    // Write ISLAST bit.
    brotli_write_bits(1, is_final_block as u64, storage_ix, storage);
    // Write ISEMPTY bit.
    if is_final_block {
        brotli_write_bits(1, 0, storage_ix, storage);
    }

    let (lenbits, nlenbits, nibblesbits) = brotli_encode_mlen(length);
    brotli_write_bits(2, nibblesbits, storage_ix, storage);
    brotli_write_bits(nlenbits, lenbits, storage_ix, storage);

    if !is_final_block {
        // Write ISUNCOMPRESSED bit.
        brotli_write_bits(1, 0, storage_ix, storage);
    }
}

/// Stores the uncompressed meta-block header.
/// REQUIRES: length > 0
/// REQUIRES: length <= (1 << 24)
fn brotli_store_uncompressed_meta_block_header(length: usize, storage_ix: &mut usize, storage: &mut [u8]) {
    // Write ISLAST bit.
    // Uncompressed block cannot be the last one, so set to 0.
    brotli_write_bits(1, 0, storage_ix, storage);
    let (lenbits, nlenbits, nibblesbits) = brotli_encode_mlen(length);
    brotli_write_bits(2, nibblesbits, storage_ix, storage);
    brotli_write_bits(nlenbits, lenbits, storage_ix, storage);
    // Write ISUNCOMPRESSED bit.
    brotli_write_bits(1, 1, storage_ix, storage);
}

fn brotli_store_huffman_tree_of_huffman_tree_to_bit_mask(
    num_codes: i32,
    code_length_bitdepth: &[u8],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    const K_STORAGE_ORDER: [u8; BROTLI_CODE_LENGTH_CODES] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    // The bit lengths of the Huffman code over the code length alphabet
    // are compressed with the following static Huffman code:
    //   Symbol   Code
    //   ------   ----
    //   0          00
    //   1        1110
    //   2         110
    //   3          01
    //   4          10
    //   5        1111
    const K_HUFFMAN_BIT_LENGTH_HUFFMAN_CODE_SYMBOLS: [u8; 6] = [0, 7, 3, 2, 1, 15];
    const K_HUFFMAN_BIT_LENGTH_HUFFMAN_CODE_BIT_LENGTHS: [u8; 6] = [2, 4, 3, 2, 2, 4];

    let mut skip_some: usize = 0; // skips none.

    // Throw away trailing zeros:
    let mut codes_to_store: usize = BROTLI_CODE_LENGTH_CODES;
    if num_codes > 1 {
        while codes_to_store > 0 {
            if code_length_bitdepth[K_STORAGE_ORDER[codes_to_store - 1] as usize] != 0 {
                break;
            }
            codes_to_store -= 1;
        }
    }
    if code_length_bitdepth[K_STORAGE_ORDER[0] as usize] == 0 && code_length_bitdepth[K_STORAGE_ORDER[1] as usize] == 0 {
        skip_some = 2; // skips two.
        if code_length_bitdepth[K_STORAGE_ORDER[2] as usize] == 0 {
            skip_some = 3; // skips three.
        }
    }
    brotli_write_bits(2, skip_some as u64, storage_ix, storage);
    for i in skip_some..codes_to_store {
        let l = code_length_bitdepth[K_STORAGE_ORDER[i] as usize] as usize;
        brotli_write_bits(
            K_HUFFMAN_BIT_LENGTH_HUFFMAN_CODE_BIT_LENGTHS[l] as usize,
            K_HUFFMAN_BIT_LENGTH_HUFFMAN_CODE_SYMBOLS[l] as u64,
            storage_ix,
            storage,
        );
    }
}

fn brotli_store_huffman_tree_to_bit_mask(
    huffman_tree_size: usize,
    huffman_tree: &[u8],
    huffman_tree_extra_bits: &[u8],
    code_length_bitdepth: &[u8],
    code_length_bitdepth_symbols: &[u16],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    for i in 0..huffman_tree_size {
        let ix = huffman_tree[i] as usize;
        brotli_write_bits(code_length_bitdepth[ix] as usize, code_length_bitdepth_symbols[ix] as u64, storage_ix, storage);
        // Extra bits
        if ix == BROTLI_REPEAT_PREVIOUS_CODE_LENGTH as usize {
            brotli_write_bits(2, huffman_tree_extra_bits[i] as u64, storage_ix, storage);
        } else if ix == BROTLI_REPEAT_ZERO_CODE_LENGTH as usize {
            brotli_write_bits(3, huffman_tree_extra_bits[i] as u64, storage_ix, storage);
        }
    }
}

fn store_simple_huffman_tree(
    depths: &[u8],
    symbols: &mut [usize; 4],
    num_symbols: usize,
    max_bits: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    // value of 1 indicates a simple Huffman code
    brotli_write_bits(2, 1, storage_ix, storage);
    brotli_write_bits(2, (num_symbols - 1) as u64, storage_ix, storage); // NSYM - 1

    // Sort
    for i in 0..num_symbols {
        for j in (i + 1)..num_symbols {
            if depths[symbols[j]] < depths[symbols[i]] {
                symbols.swap(j, i);
            }
        }
    }

    if num_symbols == 2 {
        brotli_write_bits(max_bits, symbols[0] as u64, storage_ix, storage);
        brotli_write_bits(max_bits, symbols[1] as u64, storage_ix, storage);
    } else if num_symbols == 3 {
        brotli_write_bits(max_bits, symbols[0] as u64, storage_ix, storage);
        brotli_write_bits(max_bits, symbols[1] as u64, storage_ix, storage);
        brotli_write_bits(max_bits, symbols[2] as u64, storage_ix, storage);
    } else {
        brotli_write_bits(max_bits, symbols[0] as u64, storage_ix, storage);
        brotli_write_bits(max_bits, symbols[1] as u64, storage_ix, storage);
        brotli_write_bits(max_bits, symbols[2] as u64, storage_ix, storage);
        brotli_write_bits(max_bits, symbols[3] as u64, storage_ix, storage);
        // tree-select
        brotli_write_bits(1, if depths[symbols[0]] == 1 { 1 } else { 0 }, storage_ix, storage);
    }
}

/// `BrotliStoreHuffmanTree`.  `num` = alphabet size, `depths` = symbol
/// depths.
pub fn brotli_store_huffman_tree(depths: &[u8], num: usize, tree: &mut [HuffmanTree], storage_ix: &mut usize, storage: &mut [u8]) {
    // Write the Huffman tree into the brotli-representation.
    // The command alphabet is the largest, so this allocation will fit all
    // alphabets.
    let mut huffman_tree = [0u8; BROTLI_NUM_COMMAND_SYMBOLS];
    let mut huffman_tree_extra_bits = [0u8; BROTLI_NUM_COMMAND_SYMBOLS];
    let mut huffman_tree_size: usize = 0;
    let mut code_length_bitdepth = [0u8; BROTLI_CODE_LENGTH_CODES];
    let mut code_length_bitdepth_symbols = [0u16; BROTLI_CODE_LENGTH_CODES];
    let mut huffman_tree_histogram = [0u32; BROTLI_CODE_LENGTH_CODES];
    let mut num_codes: i32 = 0;
    let mut code: usize = 0;

    debug_assert!(num <= BROTLI_NUM_COMMAND_SYMBOLS);

    brotli_write_huffman_tree(depths, num, &mut huffman_tree_size, &mut huffman_tree, &mut huffman_tree_extra_bits);

    // Calculate the statistics of the Huffman tree in brotli-representation.
    for &t in huffman_tree[..huffman_tree_size].iter() {
        huffman_tree_histogram[t as usize] += 1;
    }

    for (i, &h) in huffman_tree_histogram.iter().enumerate() {
        if h != 0 {
            if num_codes == 0 {
                code = i;
                num_codes = 1;
            } else if num_codes == 1 {
                num_codes = 2;
                break;
            }
        }
    }

    // Calculate another Huffman tree to use for compressing both the
    // earlier Huffman tree with.
    brotli_create_huffman_tree(&huffman_tree_histogram, BROTLI_CODE_LENGTH_CODES, 5, tree, &mut code_length_bitdepth);
    brotli_convert_bit_depths_to_symbols(&code_length_bitdepth, BROTLI_CODE_LENGTH_CODES, &mut code_length_bitdepth_symbols);

    // Now, we have all the data, let's start storing it
    brotli_store_huffman_tree_of_huffman_tree_to_bit_mask(num_codes, &code_length_bitdepth, storage_ix, storage);

    if num_codes == 1 {
        code_length_bitdepth[code] = 0;
    }

    // Store the real Huffman tree now.
    brotli_store_huffman_tree_to_bit_mask(
        huffman_tree_size,
        &huffman_tree,
        &huffman_tree_extra_bits,
        &code_length_bitdepth,
        &code_length_bitdepth_symbols,
        storage_ix,
        storage,
    );
}

/// `BuildAndStoreHuffmanTree`: builds a Huffman tree from
/// `histogram[0:length]` into `depth[0:length]` and `bits[0:length]` and
/// stores the encoded tree to the bit stream.
#[allow(clippy::too_many_arguments)]
fn build_and_store_huffman_tree(
    histogram: &[u32],
    histogram_length: usize,
    alphabet_size: usize,
    tree: &mut [HuffmanTree],
    depth: &mut [u8],
    bits: &mut [u16],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let mut count: usize = 0;
    let mut s4 = [0usize; 4];
    let mut max_bits: usize = 0;
    for (i, &h) in histogram[..histogram_length].iter().enumerate() {
        if h != 0 {
            if count < 4 {
                s4[count] = i;
            } else if count > 4 {
                break;
            }
            count += 1;
        }
    }

    {
        let mut max_bits_counter = alphabet_size.wrapping_sub(1);
        while max_bits_counter != 0 {
            max_bits_counter >>= 1;
            max_bits += 1;
        }
    }

    if count <= 1 {
        brotli_write_bits(4, 1, storage_ix, storage);
        brotli_write_bits(max_bits, s4[0] as u64, storage_ix, storage);
        depth[s4[0]] = 0;
        bits[s4[0]] = 0;
        return;
    }

    for d in depth[..histogram_length].iter_mut() {
        *d = 0;
    }
    brotli_create_huffman_tree(histogram, histogram_length, 15, tree, depth);
    brotli_convert_bit_depths_to_symbols(depth, histogram_length, bits);

    if count <= 4 {
        store_simple_huffman_tree(depth, &mut s4, count, max_bits, storage_ix, storage);
    } else {
        brotli_store_huffman_tree(depth, histogram_length, tree, storage_ix, storage);
    }
}

#[inline]
fn sort_huffman_tree_fast(v0: &HuffmanTree, v1: &HuffmanTree) -> bool {
    v0.total_count_ < v1.total_count_
}

/// `BrotliBuildAndStoreHuffmanTreeFast`.
#[allow(clippy::too_many_arguments)]
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
    let mut count: usize = 0;
    let mut symbols = [0usize; 4];
    let mut length: usize = 0;
    let mut total = histogram_total;
    while total != 0 {
        if histogram[length] != 0 {
            if count < 4 {
                symbols[count] = length;
            }
            count += 1;
            total = total.wrapping_sub(histogram[length] as usize);
        }
        length += 1;
    }

    if count <= 1 {
        brotli_write_bits(4, 1, storage_ix, storage);
        brotli_write_bits(max_bits, symbols[0] as u64, storage_ix, storage);
        depth[symbols[0]] = 0;
        bits[symbols[0]] = 0;
        return;
    }

    for d in depth[..length].iter_mut() {
        *d = 0;
    }
    {
        let sentinel = HuffmanTree::new(u32::MAX, -1, -1);
        let mut count_limit: u32 = 1;
        loop {
            let mut node: usize = 0;
            let mut l = length;
            while l != 0 {
                l -= 1;
                if histogram[l] != 0 {
                    if histogram[l] >= count_limit {
                        tree[node] = HuffmanTree::new(histogram[l], -1, l as i16);
                    } else {
                        tree[node] = HuffmanTree::new(count_limit, -1, l as i16);
                    }
                    node += 1;
                }
            }
            {
                let n = node as i32;
                let mut i: i32 = 0; // Points to the next leaf node.
                let mut j: i32 = n + 1; // Points to the next non-leaf node.

                sort_huffman_tree_items(tree, n as usize, sort_huffman_tree_fast);
                // The nodes are:
                // [0, n): the sorted leaf nodes that we start with.
                // [n]: we add a sentinel here.
                // [n + 1, 2n): new parent nodes are added here, starting from
                //              (n+1). These are naturally in ascending order.
                // [2n]: we add a sentinel at the end as well.
                // There will be (2n+1) elements at the end.
                tree[node] = sentinel;
                node += 1;
                tree[node] = sentinel;
                node += 1;

                let mut k = n - 1;
                while k > 0 {
                    let left: i32;
                    let right: i32;
                    if tree[i as usize].total_count_ <= tree[j as usize].total_count_ {
                        left = i;
                        i += 1;
                    } else {
                        left = j;
                        j += 1;
                    }
                    if tree[i as usize].total_count_ <= tree[j as usize].total_count_ {
                        right = i;
                        i += 1;
                    } else {
                        right = j;
                        j += 1;
                    }
                    // The sentinel node becomes the parent node.
                    tree[node - 1].total_count_ =
                        tree[left as usize].total_count_.wrapping_add(tree[right as usize].total_count_);
                    tree[node - 1].index_left_ = left as i16;
                    tree[node - 1].index_right_or_value_ = right as i16;
                    // Add back the last sentinel node.
                    tree[node] = sentinel;
                    node += 1;
                    k -= 1;
                }
                if brotli_set_depth(2 * n - 1, tree, depth, 14) {
                    // We need to pack the Huffman tree in 14 bits. If this was
                    // not successful, add fake entities to the lowest values
                    // and retry.
                    break;
                }
            }
            count_limit = count_limit.wrapping_mul(2);
        }
    }
    brotli_convert_bit_depths_to_symbols(depth, length, bits);
    if count <= 4 {
        // value of 1 indicates a simple Huffman code
        brotli_write_bits(2, 1, storage_ix, storage);
        brotli_write_bits(2, (count - 1) as u64, storage_ix, storage); // NSYM - 1

        // Sort
        for i in 0..count {
            for j in (i + 1)..count {
                if depth[symbols[j]] < depth[symbols[i]] {
                    symbols.swap(j, i);
                }
            }
        }

        if count == 2 {
            brotli_write_bits(max_bits, symbols[0] as u64, storage_ix, storage);
            brotli_write_bits(max_bits, symbols[1] as u64, storage_ix, storage);
        } else if count == 3 {
            brotli_write_bits(max_bits, symbols[0] as u64, storage_ix, storage);
            brotli_write_bits(max_bits, symbols[1] as u64, storage_ix, storage);
            brotli_write_bits(max_bits, symbols[2] as u64, storage_ix, storage);
        } else {
            brotli_write_bits(max_bits, symbols[0] as u64, storage_ix, storage);
            brotli_write_bits(max_bits, symbols[1] as u64, storage_ix, storage);
            brotli_write_bits(max_bits, symbols[2] as u64, storage_ix, storage);
            brotli_write_bits(max_bits, symbols[3] as u64, storage_ix, storage);
            // tree-select
            brotli_write_bits(1, if depth[symbols[0]] == 1 { 1 } else { 0 }, storage_ix, storage);
        }
    } else {
        let mut previous_value: u8 = 8;
        // Complex Huffman Tree
        store_static_code_length_code(storage_ix, storage);

        // Actual RLE coding.
        let mut i: usize = 0;
        while i < length {
            let value = depth[i];
            let mut reps: usize = 1;
            let mut k = i + 1;
            while k < length && depth[k] == value {
                reps += 1;
                k += 1;
            }
            i += reps;
            if value == 0 {
                brotli_write_bits(K_ZERO_REPS_DEPTH[reps] as usize, K_ZERO_REPS_BITS[reps], storage_ix, storage);
            } else {
                if previous_value != value {
                    brotli_write_bits(
                        K_CODE_LENGTH_DEPTH[value as usize] as usize,
                        K_CODE_LENGTH_BITS[value as usize] as u64,
                        storage_ix,
                        storage,
                    );
                    reps -= 1;
                }
                if reps < 3 {
                    while reps != 0 {
                        reps -= 1;
                        brotli_write_bits(
                            K_CODE_LENGTH_DEPTH[value as usize] as usize,
                            K_CODE_LENGTH_BITS[value as usize] as u64,
                            storage_ix,
                            storage,
                        );
                    }
                } else {
                    reps -= 3;
                    brotli_write_bits(K_NON_ZERO_REPS_DEPTH[reps] as usize, K_NON_ZERO_REPS_BITS[reps], storage_ix, storage);
                }
                previous_value = value;
            }
        }
    }
}

#[inline]
fn index_of(v: &[u8], v_size: usize, value: u8) -> usize {
    let mut i = 0;
    while i < v_size {
        if v[i] == value {
            return i;
        }
        i += 1;
    }
    i
}

#[inline]
fn move_to_front(v: &mut [u8], index: usize) {
    let value = v[index];
    let mut i = index;
    while i != 0 {
        v[i] = v[i - 1];
        i -= 1;
    }
    v[0] = value;
}

fn move_to_front_transform(v_in: &[u32], v_size: usize, v_out: &mut [u32]) {
    let mut mtf = [0u8; 256];
    if v_size == 0 {
        return;
    }
    let mut max_value = v_in[0];
    for &v in v_in[1..v_size].iter() {
        if v > max_value {
            max_value = v;
        }
    }
    debug_assert!(max_value < 256);
    for (i, e) in mtf[..=max_value as usize].iter_mut().enumerate() {
        *e = i as u8;
    }
    {
        let mtf_size = max_value as usize + 1;
        for i in 0..v_size {
            let index = index_of(&mtf, mtf_size, v_in[i] as u8);
            debug_assert!(index < mtf_size);
            v_out[i] = index as u32;
            move_to_front(&mut mtf, index);
        }
    }
}

/// Finds runs of zeros in `v[0..in_size)` and replaces them with a prefix
/// code of the run length plus extra bits (lower 9 bits is the prefix code
/// and the rest are the extra bits). Non-zero values in `v[]` are shifted by
/// `*max_length_prefix`. Will not create prefix codes bigger than the
/// initial value of `*max_run_length_prefix`. The prefix code of run length
/// L is simply Log2Floor(L) and the number of extra bits is the same as the
/// prefix code.
fn run_length_code_zeros(in_size: usize, v: &mut [u32], out_size: &mut usize, max_run_length_prefix: &mut u32) {
    let mut max_reps: u32 = 0;
    let mut i: usize = 0;
    while i < in_size {
        let mut reps: u32 = 0;
        while i < in_size && v[i] != 0 {
            i += 1;
        }
        while i < in_size && v[i] == 0 {
            reps += 1;
            i += 1;
        }
        max_reps = core::cmp::max(reps, max_reps);
    }
    let mut max_prefix: u32 = if max_reps > 0 { log2_floor_non_zero(max_reps as usize) } else { 0 };
    max_prefix = core::cmp::min(max_prefix, *max_run_length_prefix);
    *max_run_length_prefix = max_prefix;
    *out_size = 0;
    i = 0;
    while i < in_size {
        debug_assert!(*out_size <= i);
        if v[i] != 0 {
            v[*out_size] = v[i].wrapping_add(*max_run_length_prefix);
            i += 1;
            *out_size += 1;
        } else {
            let mut reps: u32 = 1;
            let mut k = i + 1;
            while k < in_size && v[k] == 0 {
                reps += 1;
                k += 1;
            }
            i += reps as usize;
            while reps != 0 {
                if reps < (2u32 << max_prefix) {
                    let run_length_prefix = log2_floor_non_zero(reps as usize);
                    let extra_bits = reps - (1u32 << run_length_prefix);
                    v[*out_size] = run_length_prefix + (extra_bits << 9);
                    *out_size += 1;
                    break;
                } else {
                    let extra_bits = (1u32 << max_prefix) - 1;
                    v[*out_size] = max_prefix + (extra_bits << 9);
                    reps -= (2u32 << max_prefix) - 1;
                    *out_size += 1;
                }
            }
        }
    }
}

const SYMBOL_BITS: u32 = 9;

struct EncodeContextMapArena {
    histogram: [u32; MAX_CONTEXT_MAP_SYMBOLS],
    depths: [u8; MAX_CONTEXT_MAP_SYMBOLS],
    bits: [u16; MAX_CONTEXT_MAP_SYMBOLS],
}

impl EncodeContextMapArena {
    fn new() -> Self {
        EncodeContextMapArena {
            histogram: [0; MAX_CONTEXT_MAP_SYMBOLS],
            depths: [0; MAX_CONTEXT_MAP_SYMBOLS],
            bits: [0; MAX_CONTEXT_MAP_SYMBOLS],
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_context_map(
    m: &MemoryManager,
    arena: &mut EncodeContextMapArena,
    context_map: &[u32],
    context_map_size: usize,
    num_clusters: usize,
    tree: &mut [HuffmanTree],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let mut max_run_length_prefix: u32 = 6;
    let mut num_rle_symbols: usize = 0;
    const K_SYMBOL_MASK: u32 = (1u32 << SYMBOL_BITS) - 1;

    store_var_len_uint8(num_clusters.wrapping_sub(1), storage_ix, storage);

    if num_clusters == 1 {
        return;
    }

    let mut rle_symbols: Buf<u32> = Buf::new(m, context_map_size);
    move_to_front_transform(context_map, context_map_size, &mut rle_symbols);
    run_length_code_zeros(context_map_size, &mut rle_symbols, &mut num_rle_symbols, &mut max_run_length_prefix);
    arena.histogram = [0; MAX_CONTEXT_MAP_SYMBOLS];
    for &s in rle_symbols[..num_rle_symbols].iter() {
        arena.histogram[(s & K_SYMBOL_MASK) as usize] += 1;
    }
    {
        let use_rle = max_run_length_prefix > 0;
        brotli_write_bits(1, use_rle as u64, storage_ix, storage);
        if use_rle {
            brotli_write_bits(4, (max_run_length_prefix - 1) as u64, storage_ix, storage);
        }
    }
    build_and_store_huffman_tree(
        &arena.histogram,
        num_clusters + max_run_length_prefix as usize,
        num_clusters + max_run_length_prefix as usize,
        tree,
        &mut arena.depths,
        &mut arena.bits,
        storage_ix,
        storage,
    );
    for &s in rle_symbols[..num_rle_symbols].iter() {
        let rle_symbol = s & K_SYMBOL_MASK;
        let extra_bits_val = s >> SYMBOL_BITS;
        brotli_write_bits(
            arena.depths[rle_symbol as usize] as usize,
            arena.bits[rle_symbol as usize] as u64,
            storage_ix,
            storage,
        );
        if rle_symbol > 0 && rle_symbol <= max_run_length_prefix {
            brotli_write_bits(rle_symbol as usize, extra_bits_val as u64, storage_ix, storage);
        }
    }
    brotli_write_bits(1, 1, storage_ix, storage); // use move-to-front
}

/// Stores the block switch command with index block_ix to the bit stream.
#[inline]
fn store_block_switch(
    code: &mut BlockSplitCode,
    block_len: u32,
    block_type: u8,
    is_first_block: bool,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let typecode = next_block_type_code(&mut code.type_code_calculator, block_type);
    if !is_first_block {
        brotli_write_bits(code.type_depths[typecode] as usize, code.type_bits[typecode] as u64, storage_ix, storage);
    }
    let (lencode, len_nextra, len_extra) = get_block_length_prefix_code(block_len);

    brotli_write_bits(code.length_depths[lencode] as usize, code.length_bits[lencode] as u64, storage_ix, storage);
    brotli_write_bits(len_nextra as usize, len_extra as u64, storage_ix, storage);
}

/// Builds a BlockSplitCode data structure from the block split given by the
/// vector of block types and block lengths and stores it to the bit stream.
#[allow(clippy::too_many_arguments)]
fn build_and_store_block_split_code(
    types: &[u8],
    lengths: &[u32],
    num_blocks: usize,
    num_types: usize,
    tree: &mut [HuffmanTree],
    code: &mut BlockSplitCode,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let mut type_histo = [0u32; MAX_BLOCK_TYPE_SYMBOLS];
    let mut length_histo = [0u32; BROTLI_NUM_BLOCK_LEN_SYMBOLS];
    let mut type_code_calculator = BlockTypeCodeCalculator::new();
    for i in 0..num_blocks {
        let type_code = next_block_type_code(&mut type_code_calculator, types[i]);
        if i != 0 {
            type_histo[type_code] += 1;
        }
        length_histo[block_length_prefix_code(lengths[i]) as usize] += 1;
    }
    store_var_len_uint8(num_types.wrapping_sub(1), storage_ix, storage);
    if num_types > 1 {
        // TODO(eustas): else? could StoreBlockSwitch occur?
        build_and_store_huffman_tree(
            &type_histo,
            num_types + 2,
            num_types + 2,
            tree,
            &mut code.type_depths,
            &mut code.type_bits,
            storage_ix,
            storage,
        );
        build_and_store_huffman_tree(
            &length_histo,
            BROTLI_NUM_BLOCK_LEN_SYMBOLS,
            BROTLI_NUM_BLOCK_LEN_SYMBOLS,
            tree,
            &mut code.length_depths,
            &mut code.length_bits,
            storage_ix,
            storage,
        );
        store_block_switch(code, lengths[0], types[0], true, storage_ix, storage);
    }
}

/// Stores a context map where the histogram type is always the block type.
fn store_trivial_context_map(
    arena: &mut EncodeContextMapArena,
    num_types: usize,
    context_bits: usize,
    tree: &mut [HuffmanTree],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    store_var_len_uint8(num_types.wrapping_sub(1), storage_ix, storage);
    if num_types > 1 {
        let repeat_code = context_bits - 1;
        let repeat_bits = ((1u32 << repeat_code) - 1) as usize;
        let alphabet_size = num_types + repeat_code;
        for h in arena.histogram[..alphabet_size].iter_mut() {
            *h = 0;
        }
        // Write RLEMAX.
        brotli_write_bits(1, 1, storage_ix, storage);
        brotli_write_bits(4, (repeat_code - 1) as u64, storage_ix, storage);
        arena.histogram[repeat_code] = num_types as u32;
        arena.histogram[0] = 1;
        for h in arena.histogram[context_bits..alphabet_size].iter_mut() {
            *h = 1;
        }
        build_and_store_huffman_tree(
            &arena.histogram,
            alphabet_size,
            alphabet_size,
            tree,
            &mut arena.depths,
            &mut arena.bits,
            storage_ix,
            storage,
        );
        for i in 0..num_types {
            let code = if i == 0 { 0 } else { i + context_bits - 1 };
            brotli_write_bits(arena.depths[code] as usize, arena.bits[code] as u64, storage_ix, storage);
            brotli_write_bits(arena.depths[repeat_code] as usize, arena.bits[repeat_code] as u64, storage_ix, storage);
            brotli_write_bits(repeat_code, repeat_bits as u64, storage_ix, storage);
        }
        // Write IMTF (inverse-move-to-front) bit.
        brotli_write_bits(1, 1, storage_ix, storage);
    }
}

/// Manages the encoding of one block category (literal, command or
/// distance).
struct BlockEncoder<'a> {
    histogram_length_: usize,
    num_block_types_: usize,
    block_types_: &'a [u8],
    block_lengths_: &'a [u32],
    num_blocks_: usize,
    block_split_code_: BlockSplitCode,
    block_ix_: usize,
    block_len_: usize,
    entropy_ix_: usize,
    depths_: Buf<u8>,
    bits_: Buf<u16>,
}

impl<'a> BlockEncoder<'a> {
    /// `InitBlockEncoder`.
    fn new(
        histogram_length: usize,
        num_block_types: usize,
        block_types: &'a [u8],
        block_lengths: &'a [u32],
        num_blocks: usize,
    ) -> Self {
        BlockEncoder {
            histogram_length_: histogram_length,
            num_block_types_: num_block_types,
            block_types_: block_types,
            block_lengths_: block_lengths,
            num_blocks_: num_blocks,
            block_split_code_: BlockSplitCode::new(),
            block_ix_: 0,
            block_len_: if num_blocks == 0 { 0 } else { block_lengths[0] as usize },
            entropy_ix_: 0,
            depths_: Buf::empty(),
            bits_: Buf::empty(),
        }
    }

    /// `BuildAndStoreBlockSwitchEntropyCodes`: creates entropy codes of block
    /// lengths and block types and stores them to the bit stream.
    fn build_and_store_block_switch_entropy_codes(&mut self, tree: &mut [HuffmanTree], storage_ix: &mut usize, storage: &mut [u8]) {
        build_and_store_block_split_code(
            self.block_types_,
            self.block_lengths_,
            self.num_blocks_,
            self.num_block_types_,
            tree,
            &mut self.block_split_code_,
            storage_ix,
            storage,
        );
    }

    /// `StoreSymbol`: stores the next symbol with the entropy code of the
    /// current block type. Updates the block type and block length at block
    /// boundaries.
    #[inline(always)]
    fn store_symbol(&mut self, symbol: usize, storage_ix: &mut usize, storage: &mut [u8]) {
        if self.block_len_ == 0 {
            self.block_ix_ += 1;
            let block_ix = self.block_ix_;
            let block_len = self.block_lengths_[block_ix];
            let block_type = self.block_types_[block_ix];
            self.block_len_ = block_len as usize;
            self.entropy_ix_ = block_type as usize * self.histogram_length_;
            store_block_switch(&mut self.block_split_code_, block_len, block_type, false, storage_ix, storage);
        }
        self.block_len_ = self.block_len_.wrapping_sub(1);
        {
            let ix = self.entropy_ix_ + symbol;
            brotli_write_bits(self.depths_[ix] as usize, self.bits_[ix] as u64, storage_ix, storage);
        }
    }

    /// `StoreSymbolWithContext`: stores the next symbol with the entropy code
    /// of the current block type and context value. Updates the block type
    /// and block length at block boundaries.
    #[inline(always)]
    fn store_symbol_with_context(
        &mut self,
        symbol: usize,
        context: usize,
        context_map: &[u32],
        storage_ix: &mut usize,
        storage: &mut [u8],
        context_bits: usize,
    ) {
        if self.block_len_ == 0 {
            self.block_ix_ += 1;
            let block_ix = self.block_ix_;
            let block_len = self.block_lengths_[block_ix];
            let block_type = self.block_types_[block_ix];
            self.block_len_ = block_len as usize;
            self.entropy_ix_ = (block_type as usize) << context_bits;
            store_block_switch(&mut self.block_split_code_, block_len, block_type, false, storage_ix, storage);
        }
        self.block_len_ = self.block_len_.wrapping_sub(1);
        {
            let histo_ix = context_map[self.entropy_ix_ + context] as usize;
            let ix = histo_ix * self.histogram_length_ + symbol;
            brotli_write_bits(self.depths_[ix] as usize, self.bits_[ix] as u64, storage_ix, storage);
        }
    }

    /// `BuildAndStoreEntropyCodes{Literal,Command,Distance}` (template
    /// `block_encoder_inc.h`).  `is_base64_histogram` is `None` for C
    /// `NULL`.
    #[allow(clippy::too_many_arguments)]
    fn build_and_store_entropy_codes<const N: usize>(
        &mut self,
        m: &MemoryManager,
        histograms: &[Histogram<N>],
        histograms_size: usize,
        alphabet_size: usize,
        tree: &mut [HuffmanTree],
        is_base64_histogram: Option<&[u8; 256]>,
        storage_ix: &mut usize,
        storage: &mut [u8],
    ) {
        let table_size = histograms_size * self.histogram_length_;
        self.depths_ = Buf::new(m, table_size);
        self.bits_ = Buf::new(m, table_size);

        for i in 0..histograms_size {
            let ix = i * self.histogram_length_;
            let b64 = match is_base64_histogram {
                Some(b) => self.histogram_length_ == 256 && i < 256 && b[i] != 0,
                None => false,
            };
            if b64 {
                let mut all_base64 = true;
                for k in 0..256 {
                    if histograms[i].data_[k] > 0 && K_IS_BASE64[k] == 0 {
                        all_base64 = false;
                        break;
                    }
                }
                if all_base64 {
                    let depths = &mut self.depths_[ix..ix + 256];
                    for (k, d) in depths.iter_mut().enumerate() {
                        *d = if K_IS_BASE64[k] != 0 { 6 } else { 0 };
                    }
                    brotli_convert_bit_depths_to_symbols(&self.depths_[ix..ix + 256], 256, &mut self.bits_[ix..]);
                    brotli_store_huffman_tree(&self.depths_[ix..ix + 256], 256, tree, storage_ix, storage);
                    continue;
                }
            }
            build_and_store_huffman_tree(
                &histograms[i].data_,
                self.histogram_length_,
                alphabet_size,
                tree,
                &mut self.depths_[ix..],
                &mut self.bits_[ix..],
                storage_ix,
                storage,
            );
        }
    }
}

/// `JumpToByteBoundary`.
#[inline]
fn jump_to_byte_boundary(storage_ix: &mut usize, storage: &mut [u8]) {
    // C: `(*storage_ix + 7u) & ~7u` (the mask is a 32-bit unsigned int,
    // zero-extended to size_t).
    *storage_ix = storage_ix.wrapping_add(7) & (!7u32 as usize);
    storage[*storage_ix >> 3] = 0;
}

/// `BrotliStoreMetaBlock`.
#[allow(clippy::too_many_arguments)]
pub fn brotli_store_meta_block(
    m: &MemoryManager,
    input: &[u8],
    start_pos: usize,
    length: usize,
    mask: usize,
    mut prev_byte: u8,
    mut prev_byte2: u8,
    is_last: bool,
    params: &BrotliEncoderParams,
    literal_context_mode: ContextType,
    commands: &[Command],
    mb: &MetaBlockSplit,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let mut pos = start_pos;
    let num_distance_symbols = params.dist.alphabet_size_max;
    let num_effective_distance_symbols = params.dist.alphabet_size_limit;
    let literal_context_lut = brotli_context_lut(literal_context_mode);
    let dist = &params.dist;
    debug_assert!(num_effective_distance_symbols as usize <= super::histogram::BROTLI_NUM_HISTOGRAM_DISTANCE_SYMBOLS);

    store_compressed_meta_block_header(is_last, length, storage_ix, storage);

    let mut tree: Buf<HuffmanTree> = Buf::new(m, MAX_HUFFMAN_TREE_SIZE);
    let mut context_map_arena: Boxed<EncodeContextMapArena> = Boxed::new(m, EncodeContextMapArena::new());
    let mut literal_enc = BlockEncoder::new(
        BROTLI_NUM_LITERAL_SYMBOLS,
        mb.literal_split.num_types,
        &mb.literal_split.types,
        &mb.literal_split.lengths,
        mb.literal_split.num_blocks,
    );
    let mut command_enc = BlockEncoder::new(
        BROTLI_NUM_COMMAND_SYMBOLS,
        mb.command_split.num_types,
        &mb.command_split.types,
        &mb.command_split.lengths,
        mb.command_split.num_blocks,
    );
    let mut distance_enc = BlockEncoder::new(
        num_effective_distance_symbols as usize,
        mb.distance_split.num_types,
        &mb.distance_split.types,
        &mb.distance_split.lengths,
        mb.distance_split.num_blocks,
    );

    literal_enc.build_and_store_block_switch_entropy_codes(&mut tree, storage_ix, storage);
    command_enc.build_and_store_block_switch_entropy_codes(&mut tree, storage_ix, storage);
    distance_enc.build_and_store_block_switch_entropy_codes(&mut tree, storage_ix, storage);

    brotli_write_bits(2, dist.distance_postfix_bits as u64, storage_ix, storage);
    brotli_write_bits(4, (dist.num_direct_distance_codes >> dist.distance_postfix_bits) as u64, storage_ix, storage);
    for _ in 0..mb.literal_split.num_types {
        brotli_write_bits(2, literal_context_mode as u64, storage_ix, storage);
    }

    if mb.literal_context_map_size == 0 {
        store_trivial_context_map(
            &mut context_map_arena,
            mb.literal_histograms_size,
            BROTLI_LITERAL_CONTEXT_BITS as usize,
            &mut tree,
            storage_ix,
            storage,
        );
    } else {
        encode_context_map(
            m,
            &mut context_map_arena,
            &mb.literal_context_map,
            mb.literal_context_map_size,
            mb.literal_histograms_size,
            &mut tree,
            storage_ix,
            storage,
        );
    }

    if mb.distance_context_map_size == 0 {
        store_trivial_context_map(
            &mut context_map_arena,
            mb.distance_histograms_size,
            BROTLI_DISTANCE_CONTEXT_BITS as usize,
            &mut tree,
            storage_ix,
            storage,
        );
    } else {
        encode_context_map(
            m,
            &mut context_map_arena,
            &mb.distance_context_map,
            mb.distance_context_map_size,
            mb.distance_histograms_size,
            &mut tree,
            storage_ix,
            storage,
        );
    }

    {
        let mut is_base64_histogram = [0u8; 256];
        let max_type_id = core::cmp::min(mb.literal_split.num_types, 256);
        for type_id in 0..max_type_id {
            if mb.literal_is_base64[type_id >> 3] as u32 & (1u32 << (type_id & 7)) != 0 {
                if !mb.literal_context_map.is_empty() {
                    for j in 0..(1usize << BROTLI_LITERAL_CONTEXT_BITS) {
                        let b64_histo_id = mb.literal_context_map[(type_id << BROTLI_LITERAL_CONTEXT_BITS) + j];
                        if b64_histo_id < 256 {
                            is_base64_histogram[b64_histo_id as usize] = 1;
                        }
                    }
                } else {
                    let b64_histo_id = type_id as u32;
                    if b64_histo_id < 256 {
                        is_base64_histogram[b64_histo_id as usize] = 1;
                    }
                }
            }
        }

        literal_enc.build_and_store_entropy_codes(
            m,
            &mb.literal_histograms,
            mb.literal_histograms_size,
            BROTLI_NUM_LITERAL_SYMBOLS,
            &mut tree,
            Some(&is_base64_histogram),
            storage_ix,
            storage,
        );
    }
    command_enc.build_and_store_entropy_codes(
        m,
        &mb.command_histograms,
        mb.command_histograms_size,
        BROTLI_NUM_COMMAND_SYMBOLS,
        &mut tree,
        None,
        storage_ix,
        storage,
    );
    distance_enc.build_and_store_entropy_codes(
        m,
        &mb.distance_histograms,
        mb.distance_histograms_size,
        num_distance_symbols as usize,
        &mut tree,
        None,
        storage_ix,
        storage,
    );
    drop(tree);

    for cmd in commands.iter() {
        let cmd_code = cmd.cmd_prefix_ as usize;
        command_enc.store_symbol(cmd_code, storage_ix, storage);
        store_command_extra(cmd, storage_ix, storage);
        if mb.literal_context_map_size == 0 {
            for _ in 0..cmd.insert_len_ {
                literal_enc.store_symbol(input[pos & mask] as usize, storage_ix, storage);
                pos = pos.wrapping_add(1);
            }
        } else {
            for _ in 0..cmd.insert_len_ {
                let context = brotli_context(prev_byte, prev_byte2, literal_context_lut) as usize;
                let literal = input[pos & mask];
                literal_enc.store_symbol_with_context(
                    literal as usize,
                    context,
                    &mb.literal_context_map,
                    storage_ix,
                    storage,
                    BROTLI_LITERAL_CONTEXT_BITS as usize,
                );
                prev_byte2 = prev_byte;
                prev_byte = literal;
                pos = pos.wrapping_add(1);
            }
        }
        let copy_len = cmd.copy_len() as usize;
        pos = pos.wrapping_add(copy_len);
        if copy_len != 0 {
            prev_byte2 = input[pos.wrapping_sub(2) & mask];
            prev_byte = input[pos.wrapping_sub(1) & mask];
            if cmd.cmd_prefix_ >= 128 {
                let dist_code = (cmd.dist_prefix_ & 0x3FF) as usize;
                let distnumextra = (cmd.dist_prefix_ >> 10) as u32;
                let distextra = cmd.dist_extra_ as u64;
                if mb.distance_context_map_size == 0 {
                    distance_enc.store_symbol(dist_code, storage_ix, storage);
                } else {
                    let context = cmd.distance_context() as usize;
                    distance_enc.store_symbol_with_context(
                        dist_code,
                        context,
                        &mb.distance_context_map,
                        storage_ix,
                        storage,
                        BROTLI_DISTANCE_CONTEXT_BITS as usize,
                    );
                }
                brotli_write_bits(distnumextra as usize, distextra, storage_ix, storage);
            }
        }
    }
    drop(distance_enc);
    drop(command_enc);
    drop(literal_enc);
    drop(context_map_arena);
    if is_last {
        jump_to_byte_boundary(storage_ix, storage);
    }
}

fn build_histograms(
    input: &[u8],
    start_pos: usize,
    mask: usize,
    commands: &[Command],
    lit_histo: &mut HistogramLiteral,
    cmd_histo: &mut HistogramCommand,
    dist_histo: &mut HistogramDistance,
) {
    let mut pos = start_pos;
    for cmd in commands.iter() {
        cmd_histo.add(cmd.cmd_prefix_ as usize);
        for _ in 0..cmd.insert_len_ {
            lit_histo.add(input[pos & mask] as usize);
            pos = pos.wrapping_add(1);
        }
        pos = pos.wrapping_add(cmd.copy_len() as usize);
        if cmd.copy_len() != 0 && cmd.cmd_prefix_ >= 128 {
            dist_histo.add((cmd.dist_prefix_ & 0x3FF) as usize);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn store_data_with_huffman_codes(
    input: &[u8],
    start_pos: usize,
    mask: usize,
    commands: &[Command],
    lit_depth: &[u8],
    lit_bits: &[u16],
    cmd_depth: &[u8],
    cmd_bits: &[u16],
    dist_depth: &[u8],
    dist_bits: &[u16],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let mut pos = start_pos;
    for cmd in commands.iter() {
        let cmd_code = cmd.cmd_prefix_ as usize;
        brotli_write_bits(cmd_depth[cmd_code] as usize, cmd_bits[cmd_code] as u64, storage_ix, storage);
        store_command_extra(cmd, storage_ix, storage);
        for _ in 0..cmd.insert_len_ {
            let literal = input[pos & mask] as usize;
            brotli_write_bits(lit_depth[literal] as usize, lit_bits[literal] as u64, storage_ix, storage);
            pos = pos.wrapping_add(1);
        }
        pos = pos.wrapping_add(cmd.copy_len() as usize);
        if cmd.copy_len() != 0 && cmd.cmd_prefix_ >= 128 {
            let dist_code = (cmd.dist_prefix_ & 0x3FF) as usize;
            let distnumextra = (cmd.dist_prefix_ >> 10) as u32;
            let distextra = cmd.dist_extra_;
            brotli_write_bits(dist_depth[dist_code] as usize, dist_bits[dist_code] as u64, storage_ix, storage);
            brotli_write_bits(distnumextra as usize, distextra as u64, storage_ix, storage);
        }
    }
}

// TODO(eustas): pull alloc/dealloc to caller?
struct MetablockArena {
    lit_histo: HistogramLiteral,
    cmd_histo: HistogramCommand,
    dist_histo: HistogramDistance,
    // TODO(eustas): merge bits and depth?
    lit_depth: [u8; BROTLI_NUM_LITERAL_SYMBOLS],
    lit_bits: [u16; BROTLI_NUM_LITERAL_SYMBOLS],
    cmd_depth: [u8; BROTLI_NUM_COMMAND_SYMBOLS],
    cmd_bits: [u16; BROTLI_NUM_COMMAND_SYMBOLS],
    dist_depth: [u8; MAX_SIMPLE_DISTANCE_ALPHABET_SIZE],
    dist_bits: [u16; MAX_SIMPLE_DISTANCE_ALPHABET_SIZE],
    tree: [HuffmanTree; MAX_HUFFMAN_TREE_SIZE],
}

impl MetablockArena {
    fn new(m: &MemoryManager) -> Boxed<MetablockArena> {
        Boxed::new(
            m,
            MetablockArena {
                lit_histo: Histogram::default(),
                cmd_histo: Histogram::default(),
                dist_histo: Histogram::default(),
                lit_depth: [0; BROTLI_NUM_LITERAL_SYMBOLS],
                lit_bits: [0; BROTLI_NUM_LITERAL_SYMBOLS],
                cmd_depth: [0; BROTLI_NUM_COMMAND_SYMBOLS],
                cmd_bits: [0; BROTLI_NUM_COMMAND_SYMBOLS],
                dist_depth: [0; MAX_SIMPLE_DISTANCE_ALPHABET_SIZE],
                dist_bits: [0; MAX_SIMPLE_DISTANCE_ALPHABET_SIZE],
                tree: [HuffmanTree::default(); MAX_HUFFMAN_TREE_SIZE],
            },
        )
    }
}

/// `BrotliStoreMetaBlockTrivial`: stores the meta-block without doing any
/// block splitting, just collects one histogram per block category and uses
/// that for entropy coding.
#[allow(clippy::too_many_arguments)]
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
    let mut arena = MetablockArena::new(m);
    let a = &mut *arena;
    let num_distance_symbols = params.dist.alphabet_size_max;

    store_compressed_meta_block_header(is_last, length, storage_ix, storage);

    a.lit_histo.clear();
    a.cmd_histo.clear();
    a.dist_histo.clear();

    build_histograms(input, start_pos, mask, commands, &mut a.lit_histo, &mut a.cmd_histo, &mut a.dist_histo);

    brotli_write_bits(13, 0, storage_ix, storage);

    build_and_store_huffman_tree(
        &a.lit_histo.data_,
        BROTLI_NUM_LITERAL_SYMBOLS,
        BROTLI_NUM_LITERAL_SYMBOLS,
        &mut a.tree,
        &mut a.lit_depth,
        &mut a.lit_bits,
        storage_ix,
        storage,
    );
    build_and_store_huffman_tree(
        &a.cmd_histo.data_,
        BROTLI_NUM_COMMAND_SYMBOLS,
        BROTLI_NUM_COMMAND_SYMBOLS,
        &mut a.tree,
        &mut a.cmd_depth,
        &mut a.cmd_bits,
        storage_ix,
        storage,
    );
    build_and_store_huffman_tree(
        &a.dist_histo.data_,
        MAX_SIMPLE_DISTANCE_ALPHABET_SIZE,
        num_distance_symbols as usize,
        &mut a.tree,
        &mut a.dist_depth,
        &mut a.dist_bits,
        storage_ix,
        storage,
    );
    store_data_with_huffman_codes(
        input,
        start_pos,
        mask,
        commands,
        &a.lit_depth,
        &a.lit_bits,
        &a.cmd_depth,
        &a.cmd_bits,
        &a.dist_depth,
        &a.dist_bits,
        storage_ix,
        storage,
    );
    drop(arena);
    if is_last {
        jump_to_byte_boundary(storage_ix, storage);
    }
}

/// `BrotliStoreMetaBlockFast`: same as above, but uses static prefix codes
/// for histograms with few symbols, and uses fast heuristics instead.
#[allow(clippy::too_many_arguments)]
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
    let mut arena = MetablockArena::new(m);
    let a = &mut *arena;
    let num_distance_symbols = params.dist.alphabet_size_max;
    let distance_alphabet_bits = log2_floor_non_zero(num_distance_symbols.wrapping_sub(1) as usize) + 1;
    let n_commands = commands.len();

    store_compressed_meta_block_header(is_last, length, storage_ix, storage);

    brotli_write_bits(13, 0, storage_ix, storage);

    if n_commands <= 128 {
        let mut histogram = [0u32; BROTLI_NUM_LITERAL_SYMBOLS];
        let mut pos = start_pos;
        let mut num_literals: usize = 0;
        for cmd in commands.iter() {
            for _ in 0..cmd.insert_len_ {
                histogram[input[pos & mask] as usize] += 1;
                pos = pos.wrapping_add(1);
            }
            num_literals += cmd.insert_len_ as usize;
            pos = pos.wrapping_add(cmd.copy_len() as usize);
        }
        brotli_build_and_store_huffman_tree_fast(
            &mut a.tree,
            &histogram,
            num_literals,
            /* max_bits = */ 8,
            &mut a.lit_depth,
            &mut a.lit_bits,
            storage_ix,
            storage,
        );
        store_static_command_huffman_tree(storage_ix, storage);
        store_static_distance_huffman_tree(storage_ix, storage);
        store_data_with_huffman_codes(
            input,
            start_pos,
            mask,
            commands,
            &a.lit_depth,
            &a.lit_bits,
            &K_STATIC_COMMAND_CODE_DEPTH,
            &K_STATIC_COMMAND_CODE_BITS,
            &K_STATIC_DISTANCE_CODE_DEPTH,
            &K_STATIC_DISTANCE_CODE_BITS,
            storage_ix,
            storage,
        );
    } else {
        a.lit_histo.clear();
        a.cmd_histo.clear();
        a.dist_histo.clear();
        build_histograms(input, start_pos, mask, commands, &mut a.lit_histo, &mut a.cmd_histo, &mut a.dist_histo);
        brotli_build_and_store_huffman_tree_fast(
            &mut a.tree,
            &a.lit_histo.data_,
            a.lit_histo.total_count_,
            /* max_bits = */ 8,
            &mut a.lit_depth,
            &mut a.lit_bits,
            storage_ix,
            storage,
        );
        brotli_build_and_store_huffman_tree_fast(
            &mut a.tree,
            &a.cmd_histo.data_,
            a.cmd_histo.total_count_,
            /* max_bits = */ 10,
            &mut a.cmd_depth,
            &mut a.cmd_bits,
            storage_ix,
            storage,
        );
        brotli_build_and_store_huffman_tree_fast(
            &mut a.tree,
            &a.dist_histo.data_,
            a.dist_histo.total_count_,
            /* max_bits = */ distance_alphabet_bits as usize,
            &mut a.dist_depth,
            &mut a.dist_bits,
            storage_ix,
            storage,
        );
        store_data_with_huffman_codes(
            input,
            start_pos,
            mask,
            commands,
            &a.lit_depth,
            &a.lit_bits,
            &a.cmd_depth,
            &a.cmd_bits,
            &a.dist_depth,
            &a.dist_bits,
            storage_ix,
            storage,
        );
    }

    drop(arena);

    if is_last {
        jump_to_byte_boundary(storage_ix, storage);
    }
}

/// `BrotliStoreUncompressedMetaBlock`: this is for storing uncompressed
/// blocks (simple raw storage of bytes-as-bytes).
pub fn brotli_store_uncompressed_meta_block(
    is_final_block: bool,
    input: &[u8],
    position: usize,
    mask: usize,
    mut len: usize,
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let mut masked_pos = position & mask;
    brotli_store_uncompressed_meta_block_header(len, storage_ix, storage);
    jump_to_byte_boundary(storage_ix, storage);

    if masked_pos + len > mask + 1 {
        let len1 = mask + 1 - masked_pos;
        let dst = *storage_ix >> 3;
        storage[dst..dst + len1].copy_from_slice(&input[masked_pos..masked_pos + len1]);
        *storage_ix += len1 << 3;
        len -= len1;
        masked_pos = 0;
    }
    let dst = *storage_ix >> 3;
    storage[dst..dst + len].copy_from_slice(&input[masked_pos..masked_pos + len]);
    *storage_ix += len << 3;

    // We need to clear the next 4 bytes to continue to be
    // compatible with BrotliWriteBits.
    brotli_write_bits_prepare_storage(*storage_ix, storage);

    // Since the uncompressed block itself may not be the final block, add an
    // empty one after this.
    if is_final_block {
        brotli_write_bits(1, 1, storage_ix, storage); // islast
        brotli_write_bits(1, 1, storage_ix, storage); // isempty
        jump_to_byte_boundary(storage_ix, storage);
    }
}
