//! Port of `c/enc/entropy_encode.h` / `entropy_encode.c`: entropy encoding
//! (Huffman) utilities.
//!
//! OWNER: worker "entropy".

use crate::common::constants::{
    BROTLI_INITIAL_REPEATED_CODE_LENGTH, BROTLI_REPEAT_PREVIOUS_CODE_LENGTH, BROTLI_REPEAT_ZERO_CODE_LENGTH,
};

/// A node of a Huffman tree (layout of the C struct).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HuffmanTree {
    pub total_count_: u32,
    pub index_left_: i16,
    pub index_right_or_value_: i16,
}

impl HuffmanTree {
    /// `InitHuffmanTree`.
    #[inline]
    pub fn new(count: u32, left: i16, right: i16) -> Self {
        HuffmanTree { total_count_: count, index_left_: left, index_right_or_value_: right }
    }
}

/// `kBrotliShellGaps`.
pub const K_BROTLI_SHELL_GAPS: [usize; 6] = [132, 57, 23, 10, 4, 1];

/// `BrotliSetDepth`: returns true if assignment of depths succeeded.
pub fn brotli_set_depth(p0: i32, pool: &[HuffmanTree], depth: &mut [u8], max_depth: i32) -> bool {
    let mut stack = [0i32; 16];
    let mut level: i32 = 0;
    let mut p = p0;
    debug_assert!(max_depth <= 15);
    stack[0] = -1;
    loop {
        let node = pool[p as usize];
        if node.index_left_ >= 0 {
            level += 1;
            if level > max_depth {
                return false;
            }
            stack[level as usize] = node.index_right_or_value_ as i32;
            p = node.index_left_ as i32;
            continue;
        } else {
            depth[node.index_right_or_value_ as usize] = level as u8;
        }
        while level >= 0 && stack[level as usize] == -1 {
            level -= 1;
        }
        if level < 0 {
            return true;
        }
        p = stack[level as usize];
        stack[level as usize] = -1;
    }
}

/// `SortHuffmanTreeItems`: input size optimized Shell sort (insertion sort
/// for small inputs).  Must be kept exactly as in C (not stable in general,
/// tie-breaking depends on the algorithm).
#[inline]
pub fn sort_huffman_tree_items<F: Fn(&HuffmanTree, &HuffmanTree) -> bool>(items: &mut [HuffmanTree], n: usize, comparator: F) {
    if n < 13 {
        // Insertion sort.
        for i in 1..n {
            let tmp = items[i];
            let mut k = i;
            let mut j = i - 1;
            while comparator(&tmp, &items[j]) {
                items[k] = items[j];
                k = j;
                if j == 0 {
                    break;
                }
                j -= 1;
            }
            items[k] = tmp;
        }
    } else {
        // Shell sort.
        let mut g = if n < 57 { 2 } else { 0 };
        while g < 6 {
            let gap = K_BROTLI_SHELL_GAPS[g];
            let mut i = gap;
            while i < n {
                let mut j = i;
                let tmp = items[i];
                while j >= gap && comparator(&tmp, &items[j - gap]) {
                    items[j] = items[j - gap];
                    j -= gap;
                }
                items[j] = tmp;
                i += 1;
            }
            g += 1;
        }
    }
}

/// Sort the root nodes, least popular first.
#[inline]
fn sort_huffman_tree(v0: &HuffmanTree, v1: &HuffmanTree) -> bool {
    if v0.total_count_ != v1.total_count_ {
        return v0.total_count_ < v1.total_count_;
    }
    v0.index_right_or_value_ > v1.index_right_or_value_
}

/// `BrotliCreateHuffmanTree`.
///
/// This function will create a Huffman tree.
///
/// The catch here is that the tree cannot be arbitrarily deep.
/// Brotli specifies a maximum depth of 15 bits for "code trees"
/// and 7 bits for "code length code trees."
///
/// count_limit is the value that is to be faked as the minimum value
/// and this minimum value is raised until the tree matches the
/// maximum length requirement.
///
/// The `(data, length)` contains the population counts; `tree` has to be at
/// least `2 * length + 1` long; `depth` receives the bit depths.
pub fn brotli_create_huffman_tree(data: &[u32], length: usize, tree_limit: i32, tree: &mut [HuffmanTree], depth: &mut [u8]) {
    let sentinel = HuffmanTree::new(u32::MAX, -1, -1);
    // For block sizes below 64 kB, we never need to do a second iteration
    // of this loop. Probably all of our block sizes will be smaller than
    // that, so this loop is mostly of academic interest. If we actually
    // would need this, we would be better off with the Katajainen algorithm.
    let mut count_limit: u32 = 1;
    loop {
        let mut n: usize = 0;
        let mut i = length;
        while i != 0 {
            i -= 1;
            if data[i] != 0 {
                let count = core::cmp::max(data[i], count_limit);
                tree[n] = HuffmanTree::new(count, -1, i as i16);
                n += 1;
            }
        }

        if n == 1 {
            depth[tree[0].index_right_or_value_ as usize] = 1; // Only one element.
            break;
        }
        if n == 0 {
            // Undefined behavior in C (never happens for valid callers).
            debug_assert!(false, "brotli_create_huffman_tree: empty histogram");
            return;
        }

        sort_huffman_tree_items(tree, n, sort_huffman_tree);

        // The nodes are:
        // [0, n): the sorted leaf nodes that we start with.
        // [n]: we add a sentinel here.
        // [n + 1, 2n): new parent nodes are added here, starting from
        //              (n+1). These are naturally in ascending order.
        // [2n]: we add a sentinel at the end as well.
        // There will be (2n+1) elements at the end.
        tree[n] = sentinel;
        tree[n + 1] = sentinel;

        let mut i = 0usize; // Points to the next leaf node.
        let mut j = n + 1; // Points to the next non-leaf node.
        let mut k = n - 1;
        while k != 0 {
            let left;
            let right;
            if tree[i].total_count_ <= tree[j].total_count_ {
                left = i;
                i += 1;
            } else {
                left = j;
                j += 1;
            }
            if tree[i].total_count_ <= tree[j].total_count_ {
                right = i;
                i += 1;
            } else {
                right = j;
                j += 1;
            }

            {
                // The sentinel node becomes the parent node.
                let j_end = 2 * n - k;
                tree[j_end].total_count_ = tree[left].total_count_.wrapping_add(tree[right].total_count_);
                tree[j_end].index_left_ = left as i16;
                tree[j_end].index_right_or_value_ = right as i16;

                // Add back the last sentinel node.
                tree[j_end + 1] = sentinel;
            }
            k -= 1;
        }
        if brotli_set_depth((2 * n - 1) as i32, tree, depth, tree_limit) {
            // We need to pack the Huffman tree in tree_limit bits. If this was
            // not successful, add fake entities to the lowest values and retry.
            break;
        }
        count_limit = count_limit.wrapping_mul(2);
    }
}

fn reverse(v: &mut [u8], mut start: usize, mut end: usize) {
    end = end.wrapping_sub(1);
    while start < end {
        v.swap(start, end);
        start += 1;
        end -= 1;
    }
}

fn brotli_write_huffman_tree_repetitions(
    previous_value: u8,
    value: u8,
    mut repetitions: usize,
    tree_size: &mut usize,
    tree: &mut [u8],
    extra_bits_data: &mut [u8],
) {
    debug_assert!(repetitions > 0);
    if previous_value != value {
        tree[*tree_size] = value;
        extra_bits_data[*tree_size] = 0;
        *tree_size += 1;
        repetitions -= 1;
    }
    if repetitions == 7 {
        tree[*tree_size] = value;
        extra_bits_data[*tree_size] = 0;
        *tree_size += 1;
        repetitions -= 1;
    }
    if repetitions < 3 {
        for _ in 0..repetitions {
            tree[*tree_size] = value;
            extra_bits_data[*tree_size] = 0;
            *tree_size += 1;
        }
    } else {
        let start = *tree_size;
        repetitions -= 3;
        loop {
            tree[*tree_size] = BROTLI_REPEAT_PREVIOUS_CODE_LENGTH as u8;
            extra_bits_data[*tree_size] = (repetitions & 0x3) as u8;
            *tree_size += 1;
            repetitions >>= 2;
            if repetitions == 0 {
                break;
            }
            repetitions -= 1;
        }
        reverse(tree, start, *tree_size);
        reverse(extra_bits_data, start, *tree_size);
    }
}

fn brotli_write_huffman_tree_repetitions_zeros(
    mut repetitions: usize,
    tree_size: &mut usize,
    tree: &mut [u8],
    extra_bits_data: &mut [u8],
) {
    if repetitions == 11 {
        tree[*tree_size] = 0;
        extra_bits_data[*tree_size] = 0;
        *tree_size += 1;
        repetitions -= 1;
    }
    if repetitions < 3 {
        for _ in 0..repetitions {
            tree[*tree_size] = 0;
            extra_bits_data[*tree_size] = 0;
            *tree_size += 1;
        }
    } else {
        let start = *tree_size;
        repetitions -= 3;
        loop {
            tree[*tree_size] = BROTLI_REPEAT_ZERO_CODE_LENGTH as u8;
            extra_bits_data[*tree_size] = (repetitions & 0x7) as u8;
            *tree_size += 1;
            repetitions >>= 3;
            if repetitions == 0 {
                break;
            }
            repetitions -= 1;
        }
        reverse(tree, start, *tree_size);
        reverse(extra_bits_data, start, *tree_size);
    }
}

/// `BrotliOptimizeHuffmanCountsForRle`.
///
/// Change the population counts in a way that the consequent
/// Huffman tree compression, especially its RLE-part will be more
/// likely to compress this data more efficiently.
///
/// `length` contains the size of the histogram, `counts` contains the
/// population counts, `good_for_rle` is a buffer of at least `length` size.
pub fn brotli_optimize_huffman_counts_for_rle(mut length: usize, counts: &mut [u32], good_for_rle: &mut [u8]) {
    let mut nonzero_count: usize = 0;
    let streak_limit: usize = 1240;
    // Let's make the Huffman code more compatible with RLE encoding.
    for &c in counts[..length].iter() {
        if c != 0 {
            nonzero_count += 1;
        }
    }
    if nonzero_count < 16 {
        return;
    }
    while length != 0 && counts[length - 1] == 0 {
        length -= 1;
    }
    if length == 0 {
        return; // All zeros.
    }
    // Now counts[0..length - 1] does not have trailing zeros.
    {
        let mut nonzeros: usize = 0;
        let mut smallest_nonzero: u32 = 1 << 30;
        for &c in counts[..length].iter() {
            if c != 0 {
                nonzeros += 1;
                if smallest_nonzero > c {
                    smallest_nonzero = c;
                }
            }
        }
        if nonzeros < 5 {
            // Small histogram will model it well.
            return;
        }
        if smallest_nonzero < 4 {
            let zeros = length - nonzeros;
            if zeros < 6 {
                for i in 1..length - 1 {
                    if counts[i - 1] != 0 && counts[i] == 0 && counts[i + 1] != 0 {
                        counts[i] = 1;
                    }
                }
            }
        }
        if nonzeros < 28 {
            return;
        }
    }
    // 2) Let's mark all population counts that already can be encoded
    // with an RLE code.
    for g in good_for_rle[..length].iter_mut() {
        *g = 0;
    }
    {
        // Let's not spoil any of the existing good RLE codes.
        // Mark any seq of 0's that is longer as 5 as a good_for_rle.
        // Mark any seq of non-0's that is longer as 7 as a good_for_rle.
        let mut symbol = counts[0];
        let mut step: usize = 0;
        for i in 0..=length {
            if i == length || counts[i] != symbol {
                if (symbol == 0 && step >= 5) || (symbol != 0 && step >= 7) {
                    for k in 0..step {
                        good_for_rle[i - k - 1] = 1;
                    }
                }
                step = 1;
                if i != length {
                    symbol = counts[i];
                }
            } else {
                step += 1;
            }
        }
    }
    // 3) Let's replace those population counts that lead to more RLE codes.
    // Math here is in 24.8 fixed point representation.
    let mut stride: usize = 0;
    let mut limit: usize =
        (256u32.wrapping_mul(counts[0].wrapping_add(counts[1]).wrapping_add(counts[2])) / 3).wrapping_add(420) as usize;
    let mut sum: usize = 0;
    for i in 0..=length {
        if i == length
            || good_for_rle[i] != 0
            || (i != 0 && good_for_rle[i - 1] != 0)
            || (256u32.wrapping_mul(counts[i]) as usize).wrapping_sub(limit).wrapping_add(streak_limit) >= 2 * streak_limit
        {
            if stride >= 4 || (stride >= 3 && sum == 0) {
                // The stride must end, collapse what we have, if we have enough (4).
                let mut count = (sum + stride / 2) / stride;
                if count == 0 {
                    count = 1;
                }
                if sum == 0 {
                    // Don't make an all zeros stride to be upgraded to ones.
                    count = 0;
                }
                for k in 0..stride {
                    // We don't want to change value at counts[i],
                    // that is already belonging to the next stride. Thus - 1.
                    counts[i - k - 1] = count as u32;
                }
            }
            stride = 0;
            sum = 0;
            if i < length.wrapping_sub(2) {
                // All interesting strides have a count of at least 4,
                // at least when non-zeros.
                limit = (256u32.wrapping_mul(counts[i].wrapping_add(counts[i + 1]).wrapping_add(counts[i + 2])) / 3)
                    .wrapping_add(420) as usize;
            } else if i < length {
                limit = 256u32.wrapping_mul(counts[i]) as usize;
            } else {
                limit = 0;
            }
        }
        stride += 1;
        if i != length {
            sum = sum.wrapping_add(counts[i] as usize);
            if stride >= 4 {
                limit = (256usize.wrapping_mul(sum).wrapping_add(stride / 2)) / stride;
            }
            if stride == 4 {
                limit = limit.wrapping_add(120);
            }
        }
    }
}

fn decide_over_rle_use(depth: &[u8], length: usize) -> (bool, bool) {
    let mut total_reps_zero: usize = 0;
    let mut total_reps_non_zero: usize = 0;
    let mut count_reps_zero: usize = 1;
    let mut count_reps_non_zero: usize = 1;
    let mut i = 0usize;
    while i < length {
        let value = depth[i];
        let mut reps: usize = 1;
        let mut k = i + 1;
        while k < length && depth[k] == value {
            reps += 1;
            k += 1;
        }
        if reps >= 3 && value == 0 {
            total_reps_zero += reps;
            count_reps_zero += 1;
        }
        if reps >= 4 && value != 0 {
            total_reps_non_zero += reps;
            count_reps_non_zero += 1;
        }
        i += reps;
    }
    (total_reps_non_zero > count_reps_non_zero * 2, total_reps_zero > count_reps_zero * 2)
}

/// `BrotliWriteHuffmanTree`: write a Huffman tree from bit depths into the
/// bit-stream representation of a Huffman tree. The generated Huffman tree
/// is to be compressed once more using a Huffman tree.
pub fn brotli_write_huffman_tree(depth: &[u8], length: usize, tree_size: &mut usize, tree: &mut [u8], extra_bits_data: &mut [u8]) {
    let mut previous_value: u8 = BROTLI_INITIAL_REPEATED_CODE_LENGTH as u8;
    let mut use_rle_for_non_zero = false;
    let mut use_rle_for_zero = false;

    // Throw away trailing zeros.
    let mut new_length = length;
    for i in 0..length {
        if depth[length - i - 1] == 0 {
            new_length -= 1;
        } else {
            break;
        }
    }

    // First gather statistics on if it is a good idea to do RLE.
    if length > 50 {
        // Find RLE coding for longer codes.
        // Shorter codes seem not to benefit from RLE.
        let (a, b) = decide_over_rle_use(depth, new_length);
        use_rle_for_non_zero = a;
        use_rle_for_zero = b;
    }

    // Actual RLE coding.
    let mut i = 0usize;
    while i < new_length {
        let value = depth[i];
        let mut reps: usize = 1;
        if (value != 0 && use_rle_for_non_zero) || (value == 0 && use_rle_for_zero) {
            let mut k = i + 1;
            while k < new_length && depth[k] == value {
                reps += 1;
                k += 1;
            }
        }
        if value == 0 {
            brotli_write_huffman_tree_repetitions_zeros(reps, tree_size, tree, extra_bits_data);
        } else {
            brotli_write_huffman_tree_repetitions(previous_value, value, reps, tree_size, tree, extra_bits_data);
            previous_value = value;
        }
        i += reps;
    }
}

#[inline]
fn brotli_reverse_bits(num_bits: usize, mut bits: u16) -> u16 {
    // Pre-reversed 4-bit values.
    const K_LUT: [usize; 16] = [0x00, 0x08, 0x04, 0x0C, 0x02, 0x0A, 0x06, 0x0E, 0x01, 0x09, 0x05, 0x0D, 0x03, 0x0B, 0x07, 0x0F];
    let mut retval = K_LUT[(bits & 0x0F) as usize];
    let mut i = 4;
    while i < num_bits {
        retval <<= 4;
        bits >>= 4;
        retval |= K_LUT[(bits & 0x0F) as usize];
        i += 4;
    }
    retval >>= 0usize.wrapping_sub(num_bits) & 0x03;
    retval as u16
}

/// 0..15 are values for bits
const MAX_HUFFMAN_BITS: usize = 16;

/// `BrotliConvertBitDepthsToSymbols`: get the actual bit values for a tree
/// of bit depths.
pub fn brotli_convert_bit_depths_to_symbols(depth: &[u8], len: usize, bits: &mut [u16]) {
    // In Brotli, all bit depths are [1..15]
    // 0 bit depth means that the symbol does not exist.
    let mut bl_count = [0u16; MAX_HUFFMAN_BITS];
    let mut next_code = [0u16; MAX_HUFFMAN_BITS];
    let mut code: i32 = 0;
    for &d in depth[..len].iter() {
        bl_count[d as usize] = bl_count[d as usize].wrapping_add(1);
    }
    bl_count[0] = 0;
    next_code[0] = 0;
    for i in 1..MAX_HUFFMAN_BITS {
        code = (code + bl_count[i - 1] as i32) << 1;
        next_code[i] = code as u16;
    }
    for i in 0..len {
        let d = depth[i] as usize;
        if d != 0 {
            bits[i] = brotli_reverse_bits(d, next_code[d]);
            next_code[d] = next_code[d].wrapping_add(1);
        }
    }
}
