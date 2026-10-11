//! Port of `c/enc/hash_longest_match_inc.h` (H5) and
//! `c/enc/hash_longest_match64_inc.h` (H6).
//!
//! A (forgetful) hash table to the data seen by the compressor, to help
//! create backward references to previous data.
//!
//! This is a hash map of fixed size (bucket_size_) to a ring buffer of fixed
//! size (block_size_). The ring buffer contains the last block_size_ index
//! positions of the given hash key in the compressed data.

use super::{
    backward_reference_penalty_using_last_distance, backward_reference_score,
    backward_reference_score_using_last_distance, find_match_length_at, load32, load64, prepare_distance_cache,
    search_in_static_dictionary, stitch_three, HasherCommon, HasherCore, HasherImpl, HasherSearchResult, K_HASH_MUL32,
    K_HASH_MUL64,
};
use crate::enc::encoder_dict::BrotliEncoderDictionary;
use crate::enc::memory::{Buf, MemoryManager};
use crate::enc::params::BrotliEncoderParams;

/// `HashMemAllocInBytes` of H5 / H6.
fn alloc_sizes(params: &BrotliEncoderParams, alloc_size: &mut [usize; 4]) {
    let bucket_size = 1usize << params.hasher.bucket_bits;
    let block_size = 1usize << params.hasher.block_bits;
    alloc_size[0] = core::mem::size_of::<u16>() * bucket_size;
    alloc_size[1] = core::mem::size_of::<u32>() * bucket_size * block_size;
}

/// `FN(Store)` of H5 / H6 for a precomputed `key`.
#[inline(always)]
fn store_key(num: &mut [u16], buckets: &mut [u32], block_mask: u32, block_bits: u32, key: usize, ix: usize) {
    let n = num[key];
    let minor_ix = (n as u32 & block_mask) as usize;
    let offset = minor_ix + (key << block_bits);
    num[key] = n.wrapping_add(1);
    buckets[offset] = ix as u32;
}

/// The "Try last distance first" loop shared by H5, H6 (and H58, H68):
/// returns the updated `(best_score, best_len)`.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) fn check_last_distances(
    num_last_distances_to_check: i32,
    data: &[u8],
    ring_buffer_mask: usize,
    distance_cache: &[i32],
    cur_ix: usize,
    cur_ix_masked: usize,
    max_length: usize,
    max_backward: usize,
    mut best_score: usize,
    mut best_len: usize,
    out: &mut HasherSearchResult,
) -> (usize, usize) {
    let n = num_last_distances_to_check as usize;
    for (i, &d) in distance_cache[..n].iter().enumerate() {
        let backward = d as usize;
        let mut prev_ix = cur_ix.wrapping_sub(backward);
        if prev_ix >= cur_ix {
            continue;
        }
        if backward > max_backward {
            continue;
        }
        prev_ix &= ring_buffer_mask;

        if cur_ix_masked + best_len > ring_buffer_mask {
            break;
        }
        if prev_ix + best_len > ring_buffer_mask || data[cur_ix_masked + best_len] != data[prev_ix + best_len] {
            continue;
        }
        {
            let len = find_match_length_at(data, prev_ix, cur_ix_masked, max_length);
            if len >= 3 || (len == 2 && i < 2) {
                // Comparing for >= 2 does not change the semantics, but just
                // saves for a few unnecessary binary logarithms in backward
                // reference score, since we are not interested in such short
                // matches.
                let mut score = backward_reference_score_using_last_distance(len);
                if best_score < score {
                    if i != 0 {
                        score = score.wrapping_sub(backward_reference_penalty_using_last_distance(i));
                    }
                    if best_score < score {
                        best_score = score;
                        best_len = len;
                        out.len = best_len;
                        out.distance = backward;
                        out.score = best_score;
                    }
                }
            }
        }
    }
    (best_score, best_len)
}

/// `H5`: `hash_longest_match_inc.h`.
pub struct HashLongestMatch {
    /// Number of hash buckets.
    bucket_size: usize,
    // Only block_size_ (== 1 << block_bits) newest backward references are
    // kept, and the older are forgotten.
    /// Left-shift for computing hash bucket index from hash value.
    hash_shift: i32,
    /// Mask for accessing entries in a block (in a ring-buffer manner).
    block_mask: u32,
    num_last_distances_to_check: i32,
    /// Number of entries in a particular bucket.  `uint16_t[bucket_size]`
    num: Buf<u16>,
    block_bits: u32,
    /// Buckets containing block_size_ of backward references.
    /// `uint32_t[bucket_size * block_size]`
    buckets: Buf<u32>,
}

impl HashLongestMatch {
    /// `HashBytes` is the function that chooses the bucket to place the
    /// address in.
    #[inline(always)]
    fn hash_bytes(data: &[u8], i: usize, shift: i32) -> usize {
        let h = load32(data, i).wrapping_mul(K_HASH_MUL32);
        // The higher bits contain more mixture from the multiplication,
        // so we take our results from there.
        (h >> shift) as usize
    }
}

impl HasherCore for HashLongestMatch {
    const HASH_TYPE_LENGTH: usize = 4;
    const STORE_LOOKAHEAD: usize = 4;

    fn hash_mem_alloc_in_bytes(params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize, alloc_size: &mut [usize; 4]) {
        alloc_sizes(params, alloc_size);
    }

    fn new(m: &MemoryManager, common: &HasherCommon, _params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize) -> Self {
        let hp = &common.params;
        let bucket_size = 1usize << hp.bucket_bits;
        let block_size = 1usize << hp.block_bits;
        HashLongestMatch {
            hash_shift: 32 - hp.bucket_bits,
            bucket_size,
            block_mask: (block_size - 1) as u32,
            num: Buf::new_zeroed(m, bucket_size),
            block_bits: hp.block_bits as u32,
            buckets: Buf::new_zeroed(m, bucket_size * block_size),
            num_last_distances_to_check: hp.num_last_distances_to_check,
        }
    }

    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]) {
        // Partial preparation is 100 times slower (per socket).
        let partial_prepare_threshold = self.bucket_size >> 6;
        if one_shot && input_size <= partial_prepare_threshold {
            for i in 0..input_size {
                let key = Self::hash_bytes(data, i, self.hash_shift);
                self.num[key] = 0;
            }
        } else {
            self.num.fill(0);
        }
    }

    /// Look at 4 bytes at &data[ix & mask].  Compute a hash from these, and
    /// store the value of ix at that position.
    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        let key = Self::hash_bytes(data, ix & mask, self.hash_shift);
        store_key(&mut self.num, &mut self.buckets, self.block_mask, self.block_bits, key, ix);
    }

    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let num = &mut self.num[..];
        let buckets = &mut self.buckets[..];
        for i in ix_start..ix_end {
            let key = Self::hash_bytes(data, i & mask, self.hash_shift);
            store_key(num, buckets, self.block_mask, self.block_bits, key, i);
        }
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        stitch_three(self, num_bytes, position, ringbuffer, ringbuffer_mask);
    }
}

impl HasherImpl for HashLongestMatch {
    #[inline(always)]
    fn prepare_distance_cache(&self, distance_cache: &mut [i32]) {
        prepare_distance_cache(distance_cache, self.num_last_distances_to_check);
    }

    /// Find a longest backward match of &data[cur_ix] up to the length of
    /// max_length and stores the position cur_ix in the hash table.
    ///
    /// REQUIRES: FN(PrepareDistanceCache) must be invoked for current
    /// distance cache values; if this method is invoked repeatedly with the
    /// same distance cache values, it is enough to invoke
    /// FN(PrepareDistanceCache) once.
    ///
    /// Does not look for matches longer than max_length.
    /// Does not look for matches further away than max_backward.
    /// Writes the best match into |out|.
    /// |out|->score is updated only if a better match is found.
    #[inline(always)]
    fn find_longest_match(
        &mut self,
        common: &mut HasherCommon,
        dictionary: &BrotliEncoderDictionary,
        data: &[u8],
        ring_buffer_mask: usize,
        distance_cache: &[i32],
        cur_ix: usize,
        max_length: usize,
        max_backward: usize,
        dictionary_distance: usize,
        max_distance: usize,
        out: &mut HasherSearchResult,
    ) {
        let cur_ix_masked = cur_ix & ring_buffer_mask;
        // Don't accept a short copy from far away.
        let min_score = out.score;
        let best_score = out.score;
        let best_len = out.len;
        // Precalculate the hash key and prefetch the bucket.
        let key = Self::hash_bytes(data, cur_ix_masked, self.hash_shift);
        out.len = 0;
        out.len_code_delta = 0;

        // Try last distance first.
        let (mut best_score, mut best_len) = check_last_distances(
            self.num_last_distances_to_check,
            data,
            ring_buffer_mask,
            distance_cache,
            cur_ix,
            cur_ix_masked,
            max_length,
            max_backward,
            best_score,
            best_len,
            out,
        );
        // we require matches of len >4, so increase best_len to 3, so we can
        // compare 4 bytes all the time.
        if best_len < 3 {
            best_len = 3;
        }
        {
            // block_size == 1 << block_bits, block_mask == block_size - 1
            // (spelled out so that the index bounds checks fold away).
            let block_size = 1usize << self.block_bits;
            let block_mask = block_size - 1;
            let nk = self.num[key] as usize;
            let down = nk.saturating_sub(block_size);
            let block_start = key << self.block_bits;
            let bucket = &mut self.buckets[block_start..block_start + block_size];
            let mut i = nk;
            while i > down {
                i -= 1;
                let mut prev_ix = bucket[i & block_mask] as usize;
                let backward = cur_ix.wrapping_sub(prev_ix);
                if backward > max_backward {
                    break;
                }
                prev_ix &= ring_buffer_mask;
                if cur_ix_masked + best_len > ring_buffer_mask {
                    break;
                }
                if prev_ix + best_len > ring_buffer_mask
                    // compare 4 bytes ending at best_len + 1
                    || load32(data, cur_ix_masked + best_len - 3) != load32(data, prev_ix + best_len - 3)
                {
                    continue;
                }
                {
                    let len = find_match_length_at(data, prev_ix, cur_ix_masked, max_length);
                    if len >= 4 {
                        // Comparing for >= 3 does not change the semantics,
                        // but just saves for a few unnecessary binary
                        // logarithms in backward reference score, since we
                        // are not interested in such short matches.
                        let score = backward_reference_score(len, backward);
                        if best_score < score {
                            best_score = score;
                            best_len = len;
                            out.len = best_len;
                            out.distance = backward;
                            out.score = best_score;
                        }
                    }
                }
            }
            bucket[nk & block_mask] = cur_ix as u32;
            self.num[key] = (nk as u16).wrapping_add(1);
        }
        if min_score == out.score {
            search_in_static_dictionary(
                dictionary,
                common,
                &data[cur_ix_masked..],
                max_length,
                dictionary_distance,
                max_distance,
                out,
                false,
            );
        }
    }
}

/// `H6`: `hash_longest_match64_inc.h`.
pub struct HashLongestMatch64 {
    /// Number of hash buckets.
    bucket_size: usize,
    // Only block_size_ (== 1 << block_bits) newest backward references are
    // kept, and the older are forgotten.
    /// Hash multiplier tuned to match length.
    hash_mul: u64,
    /// Mask for accessing entries in a block (in a ring-buffer manner).
    block_mask: u32,
    num_last_distances_to_check: i32,
    /// Number of entries in a particular bucket.  `uint16_t[bucket_size]`
    num: Buf<u16>,
    block_bits: u32,
    /// Buckets containing block_size_ of backward references.
    /// `uint32_t[bucket_size * block_size]`
    buckets: Buf<u32>,
}

impl HashLongestMatch64 {
    /// `HashBytes` is the function that chooses the bucket to place the
    /// address in.
    #[inline(always)]
    fn hash_bytes(data: &[u8], i: usize, hash_mul: u64) -> usize {
        let h = load64(data, i).wrapping_mul(hash_mul);
        // The higher bits contain more mixture from the multiplication,
        // so we take our results from there.
        (h >> (64 - 15)) as usize
    }
}

impl HasherCore for HashLongestMatch64 {
    const HASH_TYPE_LENGTH: usize = 8;
    const STORE_LOOKAHEAD: usize = 8;

    fn hash_mem_alloc_in_bytes(params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize, alloc_size: &mut [usize; 4]) {
        alloc_sizes(params, alloc_size);
    }

    fn new(m: &MemoryManager, common: &HasherCommon, _params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize) -> Self {
        let hp = &common.params;
        debug_assert!(hp.bucket_bits == 15);
        let bucket_size = 1usize << hp.bucket_bits;
        let block_size = 1usize << hp.block_bits;
        HashLongestMatch64 {
            hash_mul: K_HASH_MUL64 << (64 - 5 * 8),
            bucket_size,
            block_mask: (block_size - 1) as u32,
            num_last_distances_to_check: hp.num_last_distances_to_check,
            num: Buf::new_zeroed(m, bucket_size),
            block_bits: hp.block_bits as u32,
            buckets: Buf::new_zeroed(m, bucket_size * block_size),
        }
    }

    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]) {
        // Partial preparation is 100 times slower (per socket).
        let partial_prepare_threshold = self.bucket_size >> 6;
        if one_shot && input_size <= partial_prepare_threshold {
            for i in 0..input_size {
                let key = Self::hash_bytes(data, i, self.hash_mul);
                self.num[key] = 0;
            }
        } else {
            self.num.fill(0);
        }
    }

    /// Look at 4 bytes at &data[ix & mask].  Compute a hash from these, and
    /// store the value of ix at that position.
    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        let key = Self::hash_bytes(data, ix & mask, self.hash_mul);
        store_key(&mut self.num, &mut self.buckets, self.block_mask, self.block_bits, key, ix);
    }

    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let num = &mut self.num[..];
        let buckets = &mut self.buckets[..];
        for i in ix_start..ix_end {
            let key = Self::hash_bytes(data, i & mask, self.hash_mul);
            store_key(num, buckets, self.block_mask, self.block_bits, key, i);
        }
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        stitch_three(self, num_bytes, position, ringbuffer, ringbuffer_mask);
    }
}

impl HasherImpl for HashLongestMatch64 {
    #[inline(always)]
    fn prepare_distance_cache(&self, distance_cache: &mut [i32]) {
        prepare_distance_cache(distance_cache, self.num_last_distances_to_check);
    }

    /// See [`HashLongestMatch::find_longest_match`].
    #[inline(always)]
    fn find_longest_match(
        &mut self,
        common: &mut HasherCommon,
        dictionary: &BrotliEncoderDictionary,
        data: &[u8],
        ring_buffer_mask: usize,
        distance_cache: &[i32],
        cur_ix: usize,
        max_length: usize,
        max_backward: usize,
        dictionary_distance: usize,
        max_distance: usize,
        out: &mut HasherSearchResult,
    ) {
        let cur_ix_masked = cur_ix & ring_buffer_mask;
        // Don't accept a short copy from far away.
        let min_score = out.score;
        let best_score = out.score;
        let best_len = out.len;
        // Precalculate the hash key and prefetch the bucket.
        let key = Self::hash_bytes(data, cur_ix_masked, self.hash_mul);
        out.len = 0;
        out.len_code_delta = 0;

        // Try last distance first.
        let (mut best_score, mut best_len) = check_last_distances(
            self.num_last_distances_to_check,
            data,
            ring_buffer_mask,
            distance_cache,
            cur_ix,
            cur_ix_masked,
            max_length,
            max_backward,
            best_score,
            best_len,
            out,
        );
        // we require matches of len >4, so increase best_len to 3, so we can
        // compare 4 bytes all the time.
        if best_len < 3 {
            best_len = 3;
        }
        {
            // block_size == 1 << block_bits, block_mask == block_size - 1
            // (spelled out so that the index bounds checks fold away).
            let block_size = 1usize << self.block_bits;
            let block_mask = block_size - 1;
            let nk = self.num[key] as usize;
            let down = nk.saturating_sub(block_size);
            let first4 = load32(data, cur_ix_masked);
            let max_length_m4 = max_length.wrapping_sub(4);
            let block_start = key << self.block_bits;
            let bucket = &mut self.buckets[block_start..block_start + block_size];
            let mut i = nk;
            while i > down {
                i -= 1;
                let mut prev_ix = bucket[i & block_mask] as usize;
                let backward = cur_ix.wrapping_sub(prev_ix);
                if backward > max_backward {
                    break;
                }
                prev_ix &= ring_buffer_mask;
                if cur_ix_masked + best_len > ring_buffer_mask {
                    break;
                }
                if prev_ix + best_len > ring_buffer_mask
                    // compare 4 bytes ending at best_len + 1
                    || load32(data, cur_ix_masked + best_len - 3) != load32(data, prev_ix + best_len - 3)
                {
                    continue;
                }
                let current4 = load32(data, prev_ix);
                if first4 != current4 {
                    continue;
                }
                {
                    let len = find_match_length_at(data, prev_ix + 4, cur_ix_masked + 4, max_length_m4) + 4;
                    let score = backward_reference_score(len, backward);
                    if best_score < score {
                        best_score = score;
                        best_len = len;
                        out.len = best_len;
                        out.distance = backward;
                        out.score = best_score;
                    }
                }
            }
            bucket[nk & block_mask] = cur_ix as u32;
            self.num[key] = (nk as u16).wrapping_add(1);
        }
        if min_score == out.score {
            search_in_static_dictionary(
                dictionary,
                common,
                &data[cur_ix_masked..],
                max_length,
                dictionary_distance,
                max_distance,
                out,
                false,
            );
        }
    }
}
