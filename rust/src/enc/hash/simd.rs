//! Port of `c/enc/hash_longest_match_simd_inc.h` (H58),
//! `c/enc/hash_longest_match_simd_opt_inc.h` (H59),
//! `c/enc/hash_longest_match64_simd_inc.h` (H68) and
//! `c/enc/matching_tag_mask.h`.
//!
//! A (forgetful) hash table to the data seen by the compressor, to help
//! create backward references to previous data.  This is a hash map of
//! fixed size (bucket_size_) to a ring buffer of fixed size (block_size_).
//! The ring buffer contains the last block_size_ index positions of the
//! given hash key in the compressed data; an 8-bit tag per entry allows to
//! check all candidates of a bucket at once.

use super::longest_match::check_last_distances;
use super::{
    backward_reference_penalty_using_last_distance, backward_reference_score,
    backward_reference_score_using_last_distance, find_match_length_at, load16, load32, load64, prepare_distance_cache,
    search_in_static_dictionary, stitch_three, HasherCommon, HasherCore, HasherImpl, HasherSearchResult, K_HASH_MUL32,
    K_HASH_MUL64,
};
use crate::enc::encoder_dict::BrotliEncoderDictionary;
use crate::enc::memory::{Buf, MemoryManager};
use crate::enc::params::BrotliEncoderParams;

const TAG_HASH_BITS: u32 = 8;
const TAG_HASH_MASK: usize = (1 << TAG_HASH_BITS) - 1;

/// `GetMatchingTagMask` (portable code path, which computes the same as
/// the SSE2 one): bit `k` of the result is set iff
/// `tag_bucket[(head + k) % (16 * chunk_count)] == tag`.
#[inline(always)]
pub fn get_matching_tag_mask(chunk_count: usize, tag: u8, tag_bucket: &[u8], head: usize) -> u64 {
    const X01: u64 = u64::MAX / 0xFF;
    const X80: u64 = X01 << 7;
    const EXTRACT_MAGIC: u64 = (u64::MAX / 0x7F) >> 8;
    let splat_char = (tag as u64).wrapping_mul(X01);
    let mut matches: u64 = 0;
    let mut i = (chunk_count * 16) as isize - 8;
    loop {
        let mut chunk = load64(tag_bucket, i as usize);
        chunk ^= splat_char;
        chunk = ((chunk | X80).wrapping_sub(X01) | chunk) & X80;
        matches <<= 8;
        matches |= chunk.wrapping_mul(EXTRACT_MAGIC) >> 56;
        i -= 8;
        if i < 0 {
            break;
        }
    }
    matches = !matches;
    if chunk_count == 1 {
        return (matches as u16).rotate_right((head & 0x0F) as u32) as u64;
    }
    if chunk_count == 2 {
        return (matches as u32).rotate_right((head & 0x1F) as u32) as u64;
    }
    matches.rotate_right((head & 0x3F) as u32)
}

/// Mask off any matches from uninitialized tags.
#[inline(always)]
fn valid_tags_mask(block_size: usize, num_key: u16) -> u64 {
    let n: u16 = 65535u16.wrapping_sub(num_key);
    let block_has_unused_slots: u64 = (block_size > n as usize) as u64;
    (block_has_unused_slots << (n & (64 - 1))).wrapping_sub(1)
}

/// `HashMemAllocInBytes` of H58 / H59 / H68.
fn alloc_sizes(params: &BrotliEncoderParams, alloc_size: &mut [usize; 4]) {
    let bucket_size = 1usize << params.hasher.bucket_bits;
    let block_size = 1usize << params.hasher.block_bits;
    alloc_size[0] = core::mem::size_of::<u16>() * bucket_size;
    alloc_size[1] = core::mem::size_of::<u8>() * bucket_size * block_size;
    alloc_size[2] = core::mem::size_of::<u32>() * bucket_size * block_size;
}

/// Shared table state of the tag hashers.
struct TagTables {
    /// Number of hash buckets.
    bucket_size: usize,
    // Only block_size_ (== 1 << block_bits) newest backward references are
    // kept, and the older are forgotten.
    /// Mask for accessing entries in a block (in a ring-buffer manner).
    block_mask: u32,
    num_last_distances_to_check: i32,
    block_bits: u32,
    /// Number of entries in a particular bucket (counting down from 65535).
    /// `uint16_t[bucket_size]`
    num: Buf<u16>,
    /// `uint8_t[bucket_size * block_size]`
    tags: Buf<u8>,
    /// Buckets containing block_size_ of backward references.
    /// `uint32_t[bucket_size * block_size]`
    buckets: Buf<u32>,
}

impl TagTables {
    fn new(m: &MemoryManager, common: &HasherCommon) -> Self {
        let hp = &common.params;
        let bucket_size = 1usize << hp.bucket_bits;
        let block_size = 1usize << hp.block_bits;
        TagTables {
            bucket_size,
            block_mask: (block_size - 1) as u32,
            num_last_distances_to_check: hp.num_last_distances_to_check,
            block_bits: hp.block_bits as u32,
            num: Buf::new(m, bucket_size),
            tags: Buf::new(m, bucket_size * block_size),
            buckets: Buf::new(m, bucket_size * block_size),
        }
    }

    #[inline(always)]
    fn prepare(&mut self, one_shot: bool, input_size: usize, hash: impl Fn(usize) -> usize) {
        // Partial preparation is 100 times slower (per socket).
        let partial_prepare_threshold = self.bucket_size >> 6;
        if one_shot && input_size <= partial_prepare_threshold {
            for i in 0..input_size {
                let key = hash(i) >> TAG_HASH_BITS;
                self.num[key] = 65535;
            }
        } else {
            // Set all the bytes of num to 255, which makes each uint16_t
            // 65535.
            self.num.fill(65535);
        }
    }

    #[inline(always)]
    fn store(&mut self, hash: usize, ix: usize) {
        Self::store_to(&mut self.num, &mut self.tags, &mut self.buckets, self.block_mask, self.block_bits, hash, ix);
    }

    #[inline(always)]
    fn store_to(num: &mut [u16], tags: &mut [u8], buckets: &mut [u32], block_mask: u32, block_bits: u32, hash: usize, ix: usize) {
        let key = hash >> TAG_HASH_BITS;
        let tag = (hash & TAG_HASH_MASK) as u8;
        let n = num[key];
        let minor_ix = (n as u32 & block_mask) as usize;
        let offset = minor_ix + (key << block_bits);
        num[key] = n.wrapping_sub(1);
        buckets[offset] = ix as u32;
        tags[offset] = tag;
    }

    #[inline(always)]
    fn store_range(&mut self, ix_start: usize, ix_end: usize, hash: impl Fn(usize) -> usize) {
        let num = &mut self.num[..];
        let tags = &mut self.tags[..];
        let buckets = &mut self.buckets[..];
        for i in ix_start..ix_end {
            Self::store_to(num, tags, buckets, self.block_mask, self.block_bits, hash(i), i);
        }
    }
}

/// `H58` (`OPT == false`, `hash_longest_match_simd_inc.h`) and `H59`
/// (`OPT == true`, `hash_longest_match_simd_opt_inc.h`).
pub struct HashLongestMatchSimd<const OPT: bool> {
    /// Left-shift for computing hash bucket index from hash value.
    hash_shift: i32,
    t: TagTables,
}

impl<const OPT: bool> HashLongestMatchSimd<OPT> {
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

impl<const OPT: bool> HasherCore for HashLongestMatchSimd<OPT> {
    const HASH_TYPE_LENGTH: usize = 4;
    const STORE_LOOKAHEAD: usize = 4;

    fn hash_mem_alloc_in_bytes(params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize, alloc_size: &mut [usize; 4]) {
        alloc_sizes(params, alloc_size);
    }

    fn new(m: &MemoryManager, common: &HasherCommon, _params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize) -> Self {
        HashLongestMatchSimd { hash_shift: 32 - common.params.bucket_bits - TAG_HASH_BITS as i32, t: TagTables::new(m, common) }
    }

    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]) {
        let shift = self.hash_shift;
        self.t.prepare(one_shot, input_size, |i| Self::hash_bytes(data, i, shift));
    }

    /// Look at 4 bytes at &data[ix & mask].  Compute a hash from these, and
    /// store the value of ix at that position.
    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        let hash = Self::hash_bytes(data, ix & mask, self.hash_shift);
        self.t.store(hash, ix);
    }

    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let shift = self.hash_shift;
        self.t.store_range(ix_start, ix_end, |i| Self::hash_bytes(data, i & mask, shift));
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        stitch_three(self, num_bytes, position, ringbuffer, ringbuffer_mask);
    }
}

impl<const OPT: bool> HasherImpl for HashLongestMatchSimd<OPT> {
    #[inline(always)]
    fn prepare_distance_cache(&self, distance_cache: &mut [i32]) {
        prepare_distance_cache(distance_cache, self.t.num_last_distances_to_check);
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
        let mut best_score = out.score;
        let mut best_len = if OPT {
            // If we're still searching the static dictionary, we have to do
            // the full search to determine if we should check the static
            // dictionary.
            if common.dict_num_matches < (common.dict_num_lookups >> 7) {
                out.len
            } else {
                0
            }
        } else {
            out.len
        };
        // Precalculate the hash key and prefetch the bucket.
        let hash = Self::hash_bytes(data, cur_ix_masked, self.hash_shift);
        let key = hash >> TAG_HASH_BITS;
        out.len = 0;
        out.len_code_delta = 0;

        if OPT {
            if best_len < 1 {
                best_len = 1;
            }
            // Try last distance first.
            let n = self.t.num_last_distances_to_check as usize;
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

                if load16(data, cur_ix_masked + best_len - 1) != load16(data, prev_ix + best_len - 1) {
                    continue;
                }
                {
                    let len = find_match_length_at(data, prev_ix, cur_ix_masked, max_length);
                    if len >= 3 || (len == 2 && i < 2) {
                        // Comparing for >= 2 does not change the semantics,
                        // but just saves for a few unnecessary binary
                        // logarithms in backward reference score, since we
                        // are not interested in such short matches.
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
        } else {
            // Try last distance first.
            let r = check_last_distances(
                self.t.num_last_distances_to_check,
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
            best_score = r.0;
            best_len = r.1;
        }
        // we require matches of len >4, so increase best_len to 3, so we can
        // compare 4 bytes all the time.
        if best_len < 3 {
            best_len = 3;
        }
        {
            let t = &mut self.t;
            // block_size == 1 << block_bits, block_mask == block_size - 1
            // (spelled out so that the index bounds checks fold away).
            let block_size = 1usize << t.block_bits;
            let block_mask = block_size - 1;
            let tag = (hash & TAG_HASH_MASK) as u8;
            let nk = t.num[key];
            let head = (nk as usize + 1) & block_mask;
            let block_start = key << t.block_bits;
            let tag_bucket = &mut t.tags[block_start..block_start + block_size];
            let mut matches = get_matching_tag_mask(block_size / 16, tag, tag_bucket, head);
            matches &= valid_tags_mask(block_size, nk);
            let bucket = &mut t.buckets[block_start..block_start + block_size];
            while matches > 0 {
                let rb_index = (head + matches.trailing_zeros() as usize) & block_mask;
                matches &= matches - 1;
                let mut prev_ix = bucket[rb_index] as usize;
                let backward = cur_ix.wrapping_sub(prev_ix);
                if backward > max_backward {
                    break;
                }
                prev_ix &= ring_buffer_mask;
                if !OPT {
                    if cur_ix_masked + best_len > ring_buffer_mask {
                        break;
                    }
                    if prev_ix + best_len > ring_buffer_mask {
                        continue;
                    }
                }
                // compare 4 bytes ending at best_len + 1
                if load32(data, cur_ix_masked + best_len - 3) != load32(data, prev_ix + best_len - 3) {
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
            let slot = nk as usize & block_mask;
            bucket[slot] = cur_ix as u32;
            tag_bucket[slot] = tag;
            t.num[key] = nk.wrapping_sub(1);
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

/// `H68`: `hash_longest_match64_simd_inc.h`.
pub struct HashLongestMatch64Simd {
    /// Hash multiplier tuned to match length.
    hash_mul: u64,
    t: TagTables,
}

impl HashLongestMatch64Simd {
    /// `HashBytes` is the function that chooses the bucket to place the
    /// address in.
    #[inline(always)]
    fn hash_bytes(data: &[u8], i: usize, hash_mul: u64) -> usize {
        let h = load64(data, i).wrapping_mul(hash_mul);
        // The higher bits contain more mixture from the multiplication,
        // so we take our results from there.
        (h >> (64 - 15 - TAG_HASH_BITS)) as usize
    }
}

impl HasherCore for HashLongestMatch64Simd {
    const HASH_TYPE_LENGTH: usize = 8;
    const STORE_LOOKAHEAD: usize = 8;

    fn hash_mem_alloc_in_bytes(params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize, alloc_size: &mut [usize; 4]) {
        alloc_sizes(params, alloc_size);
    }

    fn new(m: &MemoryManager, common: &HasherCommon, _params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize) -> Self {
        debug_assert!(common.params.bucket_bits == 15);
        HashLongestMatch64Simd { hash_mul: K_HASH_MUL64 << (64 - 5 * 8), t: TagTables::new(m, common) }
    }

    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]) {
        let hash_mul = self.hash_mul;
        self.t.prepare(one_shot, input_size, |i| Self::hash_bytes(data, i, hash_mul));
    }

    /// Look at 4 bytes at &data[ix & mask].  Compute a hash from these, and
    /// store the value of ix at that position.
    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        let hash = Self::hash_bytes(data, ix & mask, self.hash_mul);
        self.t.store(hash, ix);
    }

    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let hash_mul = self.hash_mul;
        self.t.store_range(ix_start, ix_end, |i| Self::hash_bytes(data, i & mask, hash_mul));
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        stitch_three(self, num_bytes, position, ringbuffer, ringbuffer_mask);
    }
}

impl HasherImpl for HashLongestMatch64Simd {
    #[inline(always)]
    fn prepare_distance_cache(&self, distance_cache: &mut [i32]) {
        prepare_distance_cache(distance_cache, self.t.num_last_distances_to_check);
    }

    /// See [`HashLongestMatchSimd::find_longest_match`].
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
        let hash = Self::hash_bytes(data, cur_ix_masked, self.hash_mul);
        let key = hash >> TAG_HASH_BITS;
        out.len = 0;
        out.len_code_delta = 0;

        // Try last distance first.
        let (mut best_score, mut best_len) = check_last_distances(
            self.t.num_last_distances_to_check,
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
            let t = &mut self.t;
            // block_size == 1 << block_bits, block_mask == block_size - 1
            // (spelled out so that the index bounds checks fold away).
            let block_size = 1usize << t.block_bits;
            let block_mask = block_size - 1;
            let tag = (hash & TAG_HASH_MASK) as u8;
            let first4 = load32(data, cur_ix_masked);
            let max_length_m4 = max_length.wrapping_sub(4);
            let nk = t.num[key];
            let head = (nk as usize + 1) & block_mask;
            let block_start = key << t.block_bits;
            let tag_bucket = &mut t.tags[block_start..block_start + block_size];
            let mut matches = get_matching_tag_mask(block_size / 16, tag, tag_bucket, head);
            matches &= valid_tags_mask(block_size, nk);
            let bucket = &mut t.buckets[block_start..block_start + block_size];
            while matches > 0 {
                let rb_index = (head + matches.trailing_zeros() as usize) & block_mask;
                matches &= matches - 1;
                let mut prev_ix = bucket[rb_index] as usize;
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
            let slot = nk as usize & block_mask;
            bucket[slot] = cur_ix as u32;
            tag_bucket[slot] = tag;
            t.num[key] = nk.wrapping_sub(1);
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
