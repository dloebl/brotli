//! Port of `c/enc/hash_longest_match_quickly_inc.h` (H2, H3, H4, H54).
//!
//! A (forgetful) hash table to the data seen by the compressor, to help
//! create backward references to previous data.
//!
//! This is a hash map of fixed size (BUCKET_SIZE).

use super::{
    backward_reference_score, backward_reference_score_using_last_distance, find_match_length_at, load64,
    search_in_static_dictionary, stitch_three, HasherCommon, HasherCore, HasherImpl, HasherSearchResult, K_HASH_MUL64,
};
use crate::enc::encoder_dict::BrotliEncoderDictionary;
use crate::enc::memory::{Buf, MemoryManager};
use crate::enc::params::BrotliEncoderParams;

/// `HashLongestMatchQuickly` with template parameters `BUCKET_BITS`,
/// `BUCKET_SWEEP_BITS`, `HASH_LEN`, `USE_DICTIONARY`.
pub struct HashLongestMatchQuickly<const BUCKET_BITS: u32, const BUCKET_SWEEP_BITS: u32, const HASH_LEN: u32, const USE_DICTIONARY: bool> {
    /// `uint32_t[BUCKET_SIZE]`
    buckets: Buf<u32>,
}

impl<const BUCKET_BITS: u32, const BUCKET_SWEEP_BITS: u32, const HASH_LEN: u32, const USE_DICTIONARY: bool>
    HashLongestMatchQuickly<BUCKET_BITS, BUCKET_SWEEP_BITS, HASH_LEN, USE_DICTIONARY>
{
    const BUCKET_SIZE: usize = 1 << BUCKET_BITS;
    const BUCKET_MASK: usize = Self::BUCKET_SIZE - 1;
    const BUCKET_SWEEP: usize = 1 << BUCKET_SWEEP_BITS;
    const BUCKET_SWEEP_MASK: usize = (Self::BUCKET_SWEEP - 1) << 3;

    /// `HashBytes` is the function that chooses the bucket to place the
    /// address in.  The HashLongestMatch and HashLongestMatchQuickly classes
    /// have separate, different implementations of hashing.
    #[inline(always)]
    fn hash_bytes(data: &[u8], i: usize) -> usize {
        let h = (load64(data, i) << (64 - 8 * HASH_LEN)).wrapping_mul(K_HASH_MUL64);
        // The higher bits contain more mixture from the multiplication,
        // so we take our results from there.
        (h >> (64 - BUCKET_BITS)) as u32 as usize
    }

    /// `FN(Store)` on the bucket slice.
    #[inline(always)]
    fn store_to(buckets: &mut [u32], data: &[u8], mask: usize, ix: usize) {
        let key = Self::hash_bytes(data, ix & mask);
        if Self::BUCKET_SWEEP == 1 {
            buckets[key] = ix as u32;
        } else {
            // Wiggle the value with the bucket sweep range.
            let off = (ix as u32 as usize) & Self::BUCKET_SWEEP_MASK;
            buckets[(key + off) & Self::BUCKET_MASK] = ix as u32;
        }
    }
}

impl<const BUCKET_BITS: u32, const BUCKET_SWEEP_BITS: u32, const HASH_LEN: u32, const USE_DICTIONARY: bool> HasherCore
    for HashLongestMatchQuickly<BUCKET_BITS, BUCKET_SWEEP_BITS, HASH_LEN, USE_DICTIONARY>
{
    const HASH_TYPE_LENGTH: usize = 8;
    const STORE_LOOKAHEAD: usize = 8;

    fn hash_mem_alloc_in_bytes(_params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize, alloc_size: &mut [usize; 4]) {
        alloc_size[0] = core::mem::size_of::<u32>() * Self::BUCKET_SIZE;
    }

    fn new(m: &MemoryManager, _common: &HasherCommon, _params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize) -> Self {
        HashLongestMatchQuickly { buckets: Buf::new(m, Self::BUCKET_SIZE) }
    }

    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]) {
        let buckets = &mut self.buckets[..];
        // Partial preparation is 100 times slower (per socket).
        let partial_prepare_threshold = Self::BUCKET_SIZE >> 5;
        if one_shot && input_size <= partial_prepare_threshold {
            for i in 0..input_size {
                let key = Self::hash_bytes(data, i);
                if Self::BUCKET_SWEEP == 1 {
                    buckets[key] = 0;
                } else {
                    for j in 0..Self::BUCKET_SWEEP {
                        buckets[(key + (j << 3)) & Self::BUCKET_MASK] = 0;
                    }
                }
            }
        } else {
            // It is not strictly necessary to fill this buffer here, but not
            // filling will make the results of the compression stochastic
            // (but correct). This is because random data would cause the
            // system to find accidentally good backward references here and
            // there.
            buckets.fill(0);
        }
    }

    /// Look at 5 bytes at &data[ix & mask].  Compute a hash from these, and
    /// store the value somewhere within [ix .. ix+3].
    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        Self::store_to(&mut self.buckets[..Self::BUCKET_SIZE], data, mask, ix);
    }

    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let buckets = &mut self.buckets[..Self::BUCKET_SIZE];
        for i in ix_start..ix_end {
            Self::store_to(buckets, data, mask, i);
        }
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        stitch_three(self, num_bytes, position, ringbuffer, ringbuffer_mask);
    }
}

impl<const BUCKET_BITS: u32, const BUCKET_SWEEP_BITS: u32, const HASH_LEN: u32, const USE_DICTIONARY: bool> HasherImpl
    for HashLongestMatchQuickly<BUCKET_BITS, BUCKET_SWEEP_BITS, HASH_LEN, USE_DICTIONARY>
{
    #[inline(always)]
    fn prepare_distance_cache(&self, _distance_cache: &mut [i32]) {}

    /// Find a longest backward match of &data[cur_ix & ring_buffer_mask] up
    /// to the length of max_length and stores the position cur_ix in the
    /// hash table.
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
        let buckets = &mut self.buckets[..Self::BUCKET_SIZE];
        let best_len_in = out.len;
        let cur_ix_masked = cur_ix & ring_buffer_mask;
        // TODO: compare 4 bytes at once (and set the minimum best len to 4)
        let mut compare_char = data[cur_ix_masked + best_len_in];
        let key = Self::hash_bytes(data, cur_ix_masked);
        let mut key_out = 0usize;
        let min_score = out.score;
        let mut best_score = out.score;
        let mut best_len = best_len_in;
        let cached_backward = distance_cache[0] as usize;
        let mut prev_ix = cur_ix.wrapping_sub(cached_backward);
        let mask32 = ring_buffer_mask as u32 as usize;

        out.len_code_delta = 0;
        if prev_ix < cur_ix && cached_backward <= max_backward {
            prev_ix &= mask32;
            if compare_char == data[prev_ix + best_len] {
                let len = find_match_length_at(data, prev_ix, cur_ix_masked, max_length);
                if len >= 4 {
                    let score = backward_reference_score_using_last_distance(len);
                    if best_score < score {
                        out.len = len;
                        out.distance = cached_backward;
                        out.score = score;
                        if Self::BUCKET_SWEEP == 1 {
                            buckets[key] = cur_ix as u32;
                            return;
                        } else {
                            best_len = len;
                            best_score = score;
                            compare_char = data[cur_ix_masked + len];
                        }
                    }
                }
            }
        }
        if Self::BUCKET_SWEEP == 1 {
            // Only one to look for, don't bother to prepare for a loop.
            prev_ix = buckets[key] as usize;
            buckets[key] = cur_ix as u32;
            let backward = cur_ix.wrapping_sub(prev_ix);
            prev_ix &= mask32;
            if compare_char != data[prev_ix + best_len_in] {
                return;
            }
            if backward == 0 || backward > max_backward {
                return;
            }
            let len = find_match_length_at(data, prev_ix, cur_ix_masked, max_length);
            if len >= 4 {
                let score = backward_reference_score(len, backward);
                if best_score < score {
                    out.len = len;
                    out.distance = backward;
                    out.score = score;
                    return;
                }
            }
        } else {
            let mut keys = [0usize; 4];
            for i in 0..Self::BUCKET_SWEEP {
                keys[i] = (key + (i << 3)) & Self::BUCKET_MASK;
            }
            key_out = keys[(cur_ix & Self::BUCKET_SWEEP_MASK) >> 3];
            for i in 0..Self::BUCKET_SWEEP {
                prev_ix = buckets[keys[i]] as usize;
                let backward = cur_ix.wrapping_sub(prev_ix);
                prev_ix &= mask32;
                if compare_char != data[prev_ix + best_len] {
                    continue;
                }
                if backward == 0 || backward > max_backward {
                    continue;
                }
                let len = find_match_length_at(data, prev_ix, cur_ix_masked, max_length);
                if len >= 4 {
                    let score = backward_reference_score(len, backward);
                    if best_score < score {
                        best_len = len;
                        out.len = len;
                        compare_char = data[cur_ix_masked + len];
                        best_score = score;
                        out.score = score;
                        out.distance = backward;
                    }
                }
            }
        }
        if USE_DICTIONARY && min_score == out.score {
            search_in_static_dictionary(
                dictionary,
                common,
                &data[cur_ix_masked..],
                max_length,
                dictionary_distance,
                max_distance,
                out,
                true,
            );
        }
        if Self::BUCKET_SWEEP != 1 {
            buckets[key_out] = cur_ix as u32;
        }
    }
}
