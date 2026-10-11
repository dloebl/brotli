//! Port of `c/enc/hash_to_binary_tree_inc.h` (H10).
//!
//! A (forgetful) hash table where each hash bucket contains a binary tree of
//! sequences whose first 4 bytes share the same hash code.
//! Each sequence is MAX_TREE_COMP_LENGTH long and is identified by its
//! starting position in the input data. The binary tree is sorted by the
//! lexicographic order of the sequences, and it is also a max-heap with
//! respect to the starting positions.

use super::lazy::LazyPrefix;
use super::{find_match_length, load32, BackwardMatch, HasherCommon, HasherCore, K_HASH_MUL32};
use crate::common::constants::BROTLI_WINDOW_GAP;
use crate::enc::encoder_dict::BrotliEncoderDictionary;
use crate::enc::memory::{Buf, MemoryManager};
use crate::enc::params::BrotliEncoderParams;
use crate::enc::quality::HQ_ZOPFLIFICATION_QUALITY;
use crate::enc::static_dict::{brotli_find_all_static_dictionary_matches, BROTLI_MAX_STATIC_DICTIONARY_MATCH_LEN, K_INVALID_MATCH};

const BUCKET_BITS: u32 = 17;
const BUCKET_SIZE: usize = 1 << BUCKET_BITS;
const MAX_TREE_SEARCH_DEPTH: usize = 64;
const MAX_TREE_COMP_LENGTH: usize = 128;

/// `MAX_TREE_COMP_LENGTH` of H10 (== `StoreLookaheadH10()`).
pub const MAX_TREE_COMP_LENGTH_H10: usize = MAX_TREE_COMP_LENGTH;
/// `MAX_NUM_MATCHES_H10` == 64 + MAX_TREE_SEARCH_DEPTH.
pub const MAX_NUM_MATCHES_H10: usize = 128;

/// `H10`.
pub struct HashToBinaryTree {
    /// The window size minus 1
    window_mask: usize,
    /// Hash table that maps the 4-byte hashes of the sequence to the last
    /// position where this hash was found, which is the root of the binary
    /// tree of sequences that share this hash bucket.
    /// `uint32_t[BUCKET_SIZE]`
    buckets: Buf<u32>,
    /// A position used to mark a non-existent sequence, i.e. a tree is empty
    /// if its root is at invalid_pos_ and a node is a leaf if both its
    /// children are at invalid_pos_.
    invalid_pos: u32,
    /// The union of the binary trees of each hash bucket. The root of the
    /// tree corresponding to a hash is a sequence starting at buckets_[hash]
    /// and the left and right children of a sequence starting at pos are
    /// forest_[2 * pos] and forest_[2 * pos + 1].
    /// `uint32_t[2 * num_nodes]`; a slot is initialized before it becomes
    /// reachable (C never reads unwritten slots).
    forest: LazyPrefix<u32>,
}

impl HashToBinaryTree {
    #[inline(always)]
    fn hash_bytes(data: &[u8], i: usize) -> usize {
        let h = load32(data, i).wrapping_mul(K_HASH_MUL32);
        // The higher bits contain more mixture from the multiplication,
        // so we take our results from there.
        (h >> (32 - BUCKET_BITS)) as usize
    }

    #[inline(always)]
    fn left_child_index(&self, pos: usize) -> usize {
        2 * (pos & self.window_mask)
    }

    #[inline(always)]
    fn right_child_index(&self, pos: usize) -> usize {
        2 * (pos & self.window_mask) + 1
    }

    /// `StoreAndFindMatches`: stores the hash of the next 4 bytes and in a
    /// single tree-traversal, the hash bucket's binary tree is searched for
    /// matches and is re-rooted at the current position.
    ///
    /// If less than MAX_TREE_COMP_LENGTH data is available, the hash bucket
    /// of the current position is searched for matches, but the state of
    /// the hash table is not changed, since we can not know the final
    /// sorting order of the current (incomplete) sequence.
    ///
    /// This function must be called with increasing cur_ix positions.
    ///
    /// Found matches are written to `matches` (if any); returns their
    /// number.
    #[inline(always)]
    fn store_and_find_matches(
        &mut self,
        data: &[u8],
        cur_ix: usize,
        ring_buffer_mask: usize,
        max_length: usize,
        max_backward: usize,
        best_len: &mut usize,
        mut matches: Option<&mut [BackwardMatch]>,
    ) -> usize {
        let cur_ix_masked = cur_ix & ring_buffer_mask;
        let max_comp_len = if max_length < MAX_TREE_COMP_LENGTH { max_length } else { MAX_TREE_COMP_LENGTH };
        let should_reroot_tree = max_length >= MAX_TREE_COMP_LENGTH;
        let key = Self::hash_bytes(data, cur_ix_masked);
        let window_mask = self.window_mask;
        let invalid_pos = self.invalid_pos;
        let mut prev_ix = self.buckets[key] as usize;
        // The forest index of the rightmost node of the left subtree of the
        // new root, updated as we traverse and re-root the tree of the hash
        // bucket.
        let mut node_left = self.left_child_index(cur_ix);
        // The forest index of the leftmost node of the right subtree of the
        // new root, updated as we traverse and re-root the tree of the hash
        // bucket.
        let mut node_right = self.right_child_index(cur_ix);
        // The match length of the rightmost node of the left subtree of the
        // new root, updated as we traverse and re-root the tree of the hash
        // bucket.
        let mut best_len_left = 0usize;
        // The match length of the leftmost node of the right subtree of the
        // new root, updated as we traverse and re-root the tree of the hash
        // bucket.
        let mut best_len_right = 0usize;
        let mut num_found = 0usize;
        if should_reroot_tree {
            self.buckets[key] = cur_ix as u32;
            self.forest.ensure(node_right + 1);
        }
        let forest = self.forest.as_mut_slice();
        let mut depth_remaining = MAX_TREE_SEARCH_DEPTH;
        loop {
            let backward = cur_ix.wrapping_sub(prev_ix);
            let prev_ix_masked = prev_ix & ring_buffer_mask;
            if backward == 0 || backward > max_backward || depth_remaining == 0 {
                if should_reroot_tree {
                    forest[node_left] = invalid_pos;
                    forest[node_right] = invalid_pos;
                }
                break;
            }
            {
                let cur_len = if best_len_left < best_len_right { best_len_left } else { best_len_right };
                debug_assert!(cur_len <= MAX_TREE_COMP_LENGTH);
                let len = cur_len
                    + find_match_length(
                        &data[cur_ix_masked + cur_len..],
                        &data[prev_ix_masked + cur_len..],
                        max_length - cur_len,
                    );
                if let Some(m) = matches.as_deref_mut() {
                    if len > *best_len {
                        *best_len = len;
                        m[num_found] = BackwardMatch::new(backward, len);
                        num_found += 1;
                    }
                }
                if len >= max_comp_len {
                    if should_reroot_tree {
                        forest[node_left] = forest[2 * (prev_ix & window_mask)];
                        forest[node_right] = forest[2 * (prev_ix & window_mask) + 1];
                    }
                    break;
                }
                if data[cur_ix_masked + len] > data[prev_ix_masked + len] {
                    best_len_left = len;
                    if should_reroot_tree {
                        forest[node_left] = prev_ix as u32;
                    }
                    node_left = 2 * (prev_ix & window_mask) + 1;
                    prev_ix = forest[node_left] as usize;
                } else {
                    best_len_right = len;
                    if should_reroot_tree {
                        forest[node_right] = prev_ix as u32;
                    }
                    node_right = 2 * (prev_ix & window_mask);
                    prev_ix = forest[node_right] as usize;
                }
            }
            depth_remaining -= 1;
        }
        num_found
    }

    /// `FindAllMatches`: finds all backward matches of
    /// &data[cur_ix & ring_buffer_mask] up to the length of max_length and
    /// stores the position cur_ix in the hash table.
    ///
    /// Returns the number of matches found, and stores the found matches in
    /// matches[0] to matches[num_matches - 1]. The matches will be sorted by
    /// strictly increasing length and (non-strictly) increasing distance.
    pub fn find_all_matches(
        &mut self,
        dictionary: &BrotliEncoderDictionary,
        data: &[u8],
        ring_buffer_mask: usize,
        cur_ix: usize,
        max_length: usize,
        max_backward: usize,
        dictionary_distance: usize,
        params: &BrotliEncoderParams,
        matches: &mut [BackwardMatch],
    ) -> usize {
        let mut n = 0usize;
        let cur_ix_masked = cur_ix & ring_buffer_mask;
        let mut best_len = 1usize;
        let short_match_max_backward: usize = if params.quality != HQ_ZOPFLIFICATION_QUALITY { 16 } else { 64 };
        let mut stop = cur_ix.wrapping_sub(short_match_max_backward);
        let mut dict_matches = [K_INVALID_MATCH; BROTLI_MAX_STATIC_DICTIONARY_MATCH_LEN + 1];
        if cur_ix < short_match_max_backward {
            stop = 0;
        }
        let mut i = cur_ix.wrapping_sub(1);
        while i > stop && best_len <= 2 {
            let mut prev_ix = i;
            let backward = cur_ix.wrapping_sub(prev_ix);
            if backward > max_backward {
                break;
            }
            prev_ix &= ring_buffer_mask;
            if data[cur_ix_masked] != data[prev_ix] || data[cur_ix_masked + 1] != data[prev_ix + 1] {
                i = i.wrapping_sub(1);
                continue;
            }
            {
                let len = find_match_length(&data[prev_ix..], &data[cur_ix_masked..], max_length);
                if len > best_len {
                    best_len = len;
                    matches[n] = BackwardMatch::new(backward, len);
                    n += 1;
                }
            }
            i = i.wrapping_sub(1);
        }
        if best_len < max_length {
            n += self.store_and_find_matches(
                data,
                cur_ix,
                ring_buffer_mask,
                max_length,
                max_backward,
                &mut best_len,
                Some(&mut matches[n..]),
            );
        }
        {
            let minlen = if best_len + 1 > 4 { best_len + 1 } else { 4 };
            if brotli_find_all_static_dictionary_matches(dictionary, &data[cur_ix_masked..], minlen, max_length, &mut dict_matches) {
                let maxlen = if max_length < BROTLI_MAX_STATIC_DICTIONARY_MATCH_LEN {
                    max_length
                } else {
                    BROTLI_MAX_STATIC_DICTIONARY_MATCH_LEN
                };
                let mut l = minlen;
                while l <= maxlen {
                    let dict_id = dict_matches[l];
                    if dict_id < K_INVALID_MATCH {
                        let distance = dictionary_distance.wrapping_add((dict_id >> 5) as usize).wrapping_add(1);
                        if distance <= params.dist.max_distance {
                            matches[n] = BackwardMatch::new_dictionary(distance, l, (dict_id & 31) as usize);
                            n += 1;
                        }
                    }
                    l += 1;
                }
            }
        }
        n
    }
}

impl HasherCore for HashToBinaryTree {
    const HASH_TYPE_LENGTH: usize = 4;
    const STORE_LOOKAHEAD: usize = MAX_TREE_COMP_LENGTH;

    fn hash_mem_alloc_in_bytes(params: &BrotliEncoderParams, one_shot: bool, input_size: usize, alloc_size: &mut [usize; 4]) {
        let mut num_nodes = 1usize << params.lgwin;
        if one_shot && input_size < num_nodes {
            num_nodes = input_size;
        }
        alloc_size[0] = core::mem::size_of::<u32>() * BUCKET_SIZE;
        alloc_size[1] = 2 * core::mem::size_of::<u32>() * num_nodes;
    }

    fn new(m: &MemoryManager, _common: &HasherCommon, params: &BrotliEncoderParams, one_shot: bool, input_size: usize) -> Self {
        let mut num_nodes = 1usize << params.lgwin;
        if one_shot && input_size < num_nodes {
            num_nodes = input_size;
        }
        let window_mask = ((1u32 << params.lgwin).wrapping_sub(1)) as usize;
        let invalid_pos = 0usize.wrapping_sub(window_mask) as u32;
        HashToBinaryTree {
            window_mask,
            buckets: Buf::new(m, BUCKET_SIZE),
            invalid_pos,
            forest: LazyPrefix::new(m, 2 * num_nodes, invalid_pos),
        }
    }

    fn prepare(&mut self, _one_shot: bool, _input_size: usize, _data: &[u8]) {
        let invalid_pos = self.invalid_pos;
        self.buckets.fill(invalid_pos);
    }

    /// Stores the hash of the next 4 bytes and re-roots the binary tree at
    /// the current sequence, without returning any matches.
    /// REQUIRES: ix + MAX_TREE_COMP_LENGTH <= end-of-current-block
    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        // Maximum distance is window size - 16, see section 9.1. of the spec.
        let max_backward = self.window_mask.wrapping_sub(BROTLI_WINDOW_GAP).wrapping_add(1);
        let mut unused = 0usize;
        self.store_and_find_matches(data, ix, mask, MAX_TREE_COMP_LENGTH, max_backward, &mut unused, None);
    }

    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let mut i = ix_start;
        let mut j = ix_start;
        if ix_start + 63 <= ix_end {
            i = ix_end - 63;
        }
        if ix_start + 512 <= i {
            while j < i {
                self.store(data, mask, j);
                j += 8;
            }
        }
        while i < ix_end {
            self.store(data, mask, i);
            i += 1;
        }
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        if num_bytes >= Self::HASH_TYPE_LENGTH - 1 && position >= MAX_TREE_COMP_LENGTH {
            // Store the last `MAX_TREE_COMP_LENGTH - 1` positions in the
            // hasher.  These could not be calculated before, since they
            // require knowledge of both the previous and the current block.
            let i_start = position - MAX_TREE_COMP_LENGTH + 1;
            let i_end = if position < i_start + num_bytes { position } else { i_start + num_bytes };
            for i in i_start..i_end {
                // Maximum distance is window size - 16, see section 9.1. of
                // the spec.  Furthermore, we have to make sure that we don't
                // look further back from the start of the next block than
                // the window size, otherwise we could access already
                // overwritten areas of the ring-buffer.
                let gap = if BROTLI_WINDOW_GAP - 1 > position - i { BROTLI_WINDOW_GAP - 1 } else { position - i };
                let max_backward = self.window_mask.wrapping_sub(gap);
                // We know that i + MAX_TREE_COMP_LENGTH <= position +
                // num_bytes, i.e. the end of the current block and that we
                // have at least MAX_TREE_COMP_LENGTH tail in the ring-buffer.
                let mut unused = 0usize;
                self.store_and_find_matches(ringbuffer, i, ringbuffer_mask, MAX_TREE_COMP_LENGTH, max_backward, &mut unused, None);
            }
        }
    }
}
