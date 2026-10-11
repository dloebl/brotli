//! Port of `c/enc/hash_forgetful_chain_inc.h` (H40, H41, H42).
//!
//! A (forgetful) hash table to the data seen by the compressor, to help
//! create backward references to previous data.
//!
//! Hashes are stored in chains which are bucketed to groups. Group of chains
//! share a storage "bank". When more than "bank size" chain nodes are added,
//! oldest nodes are replaced; this way several chains may share a tail.

use super::{
    backward_reference_penalty_using_last_distance, backward_reference_score,
    backward_reference_score_using_last_distance, find_match_length_at, load32, prepare_distance_cache,
    search_in_static_dictionary, stitch_three, HasherCommon, HasherCore, HasherImpl, HasherSearchResult, K_HASH_MUL32,
};
use crate::enc::encoder_dict::BrotliEncoderDictionary;
use crate::enc::memory::{Buf, MemoryManager};
use crate::enc::params::BrotliEncoderParams;

const CAPPED_CHAINS: bool = false;

/// `FN(Slot)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    delta: u16,
    next: u16,
}

/// `HashForgetfulChain` with template parameters `BUCKET_BITS`,
/// `NUM_BANKS`, `BANK_BITS`, `NUM_LAST_DISTANCES_TO_CHECK`.
pub struct HashForgetfulChain<const BUCKET_BITS: u32, const NUM_BANKS: usize, const BANK_BITS: u32, const NUM_LAST_DISTANCES_TO_CHECK: usize> {
    /// Up to 1KiB. Move to dynamic?
    free_slot_idx: [u16; NUM_BANKS],
    max_hops: usize,
    /// `uint32_t addr[BUCKET_SIZE]`
    addr: Buf<u32>,
    /// `uint16_t head[BUCKET_SIZE]`
    head: Buf<u16>,
    /// Truncated hash used for quick rejection of "distance cache"
    /// candidates.  `uint8_t tiny_hash[65536]`
    tiny_hash: Buf<u8>,
    /// `FN(Bank) banks[NUM_BANKS]`, flattened.
    banks: Buf<Slot>,
}

impl<const BUCKET_BITS: u32, const NUM_BANKS: usize, const BANK_BITS: u32, const NUM_LAST_DISTANCES_TO_CHECK: usize>
    HashForgetfulChain<BUCKET_BITS, NUM_BANKS, BANK_BITS, NUM_LAST_DISTANCES_TO_CHECK>
{
    const BANK_SIZE: usize = 1 << BANK_BITS;
    /// Number of hash buckets.
    const BUCKET_SIZE: usize = 1 << BUCKET_BITS;

    /// `HashBytes` is the function that chooses the bucket to place the
    /// address in.
    #[inline(always)]
    fn hash_bytes(data: &[u8], i: usize) -> usize {
        let h = load32(data, i).wrapping_mul(K_HASH_MUL32);
        // The higher bits contain more mixture from the multiplication,
        // so we take our results from there.
        (h >> (32 - BUCKET_BITS)) as usize
    }

    /// `FN(Store)` for a precomputed `key`.
    #[inline(always)]
    fn store_key(
        free_slot_idx: &mut [u16; NUM_BANKS],
        addr: &mut [u32],
        head: &mut [u16],
        tiny_hash: &mut [u8],
        banks: &mut [Slot],
        key: usize,
        ix: usize,
    ) {
        let bank = key & (NUM_BANKS - 1);
        let idx = (free_slot_idx[bank] as usize) & (Self::BANK_SIZE - 1);
        free_slot_idx[bank] = free_slot_idx[bank].wrapping_add(1);
        let mut delta = ix.wrapping_sub(addr[key] as usize);
        tiny_hash[ix as u16 as usize] = key as u8;
        if delta > 0xFFFF {
            delta = if CAPPED_CHAINS { 0 } else { 0xFFFF };
        }
        let s = &mut banks[bank * Self::BANK_SIZE + idx];
        s.delta = delta as u16;
        s.next = head[key];
        addr[key] = ix as u32;
        head[key] = idx as u16;
    }
}

impl<const BUCKET_BITS: u32, const NUM_BANKS: usize, const BANK_BITS: u32, const NUM_LAST_DISTANCES_TO_CHECK: usize> HasherCore
    for HashForgetfulChain<BUCKET_BITS, NUM_BANKS, BANK_BITS, NUM_LAST_DISTANCES_TO_CHECK>
{
    const HASH_TYPE_LENGTH: usize = 4;
    const STORE_LOOKAHEAD: usize = 4;

    fn hash_mem_alloc_in_bytes(_params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize, alloc_size: &mut [usize; 4]) {
        alloc_size[0] = core::mem::size_of::<u32>() * Self::BUCKET_SIZE + core::mem::size_of::<u16>() * Self::BUCKET_SIZE + 65536;
        alloc_size[1] = core::mem::size_of::<Slot>() * Self::BANK_SIZE * NUM_BANKS;
    }

    fn new(m: &MemoryManager, _common: &HasherCommon, params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize) -> Self {
        HashForgetfulChain {
            free_slot_idx: [0; NUM_BANKS],
            max_hops: (if params.quality > 6 { 7usize } else { 8usize }).wrapping_shl((params.quality - 4) as u32),
            addr: Buf::new(m, Self::BUCKET_SIZE),
            head: Buf::new(m, Self::BUCKET_SIZE),
            tiny_hash: Buf::new(m, 65536),
            banks: Buf::new(m, Self::BANK_SIZE * NUM_BANKS),
        }
    }

    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]) {
        // Partial preparation is 100 times slower (per socket).
        let partial_prepare_threshold = Self::BUCKET_SIZE >> 6;
        if one_shot && input_size <= partial_prepare_threshold {
            for i in 0..input_size {
                let bucket = Self::hash_bytes(data, i);
                // See InitEmpty comment.
                self.addr[bucket] = 0xCCCCCCCC;
                self.head[bucket] = 0xCCCC;
            }
        } else {
            // Fill |addr| array with 0xCCCCCCCC value. Because of wrapping,
            // position processed by hasher never reaches 3GB + 64M; this
            // makes all new chains to be terminated after the first node.
            self.addr.fill(0xCCCCCCCC);
            self.head.fill(0);
        }
        self.tiny_hash.fill(0);
        self.free_slot_idx = [0; NUM_BANKS];
    }

    /// Look at 4 bytes at &data[ix & mask]. Compute a hash from these, and
    /// prepend node to corresponding chain; also update tiny_hash for
    /// current position.
    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        let key = Self::hash_bytes(data, ix & mask);
        Self::store_key(
            &mut self.free_slot_idx,
            &mut self.addr[..Self::BUCKET_SIZE],
            &mut self.head[..Self::BUCKET_SIZE],
            &mut self.tiny_hash[..65536],
            &mut self.banks,
            key,
            ix,
        );
    }

    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let free_slot_idx = &mut self.free_slot_idx;
        let addr = &mut self.addr[..Self::BUCKET_SIZE];
        let head = &mut self.head[..Self::BUCKET_SIZE];
        let tiny_hash = &mut self.tiny_hash[..65536];
        let banks = &mut self.banks[..];
        for i in ix_start..ix_end {
            let key = Self::hash_bytes(data, i & mask);
            Self::store_key(free_slot_idx, addr, head, tiny_hash, banks, key, i);
        }
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        stitch_three(self, num_bytes, position, ringbuffer, ringbuffer_mask);
    }
}

impl<const BUCKET_BITS: u32, const NUM_BANKS: usize, const BANK_BITS: u32, const NUM_LAST_DISTANCES_TO_CHECK: usize> HasherImpl
    for HashForgetfulChain<BUCKET_BITS, NUM_BANKS, BANK_BITS, NUM_LAST_DISTANCES_TO_CHECK>
{
    #[inline(always)]
    fn prepare_distance_cache(&self, distance_cache: &mut [i32]) {
        prepare_distance_cache(distance_cache, NUM_LAST_DISTANCES_TO_CHECK as i32);
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
        let mut best_len = out.len;
        let key = Self::hash_bytes(data, cur_ix_masked);
        let tiny_hash = key as u8;
        out.len = 0;
        out.len_code_delta = 0;

        // Try last distance first.
        let tiny_hashes = &self.tiny_hash[..65536];
        let distance_cache = &distance_cache[..NUM_LAST_DISTANCES_TO_CHECK];
        for i in 0..NUM_LAST_DISTANCES_TO_CHECK {
            let backward = distance_cache[i] as usize;
            let mut prev_ix = cur_ix.wrapping_sub(backward);
            // For distance code 0 we want to consider 2-byte matches.
            if i > 0 && tiny_hashes[prev_ix as u16 as usize] != tiny_hash {
                continue;
            }
            if prev_ix >= cur_ix || backward > max_backward {
                continue;
            }
            prev_ix &= ring_buffer_mask;
            {
                let len = find_match_length_at(data, prev_ix, cur_ix_masked, max_length);
                if len >= 2 {
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
        // we require matches of len >4, so increase best_len to 3, so we can
        // compare 4 bytes all the time.
        if best_len < 3 {
            best_len = 3;
        }
        {
            let bank = key & (NUM_BANKS - 1);
            let bank_base = bank * Self::BANK_SIZE;
            let bank_slots = &self.banks[bank_base..bank_base + Self::BANK_SIZE];
            let mut backward: usize = 0;
            let mut hops = self.max_hops;
            let mut delta = cur_ix.wrapping_sub(self.addr[key] as usize);
            let mut slot = self.head[key] as usize;
            while hops > 0 {
                hops -= 1;
                let last = slot;
                backward = backward.wrapping_add(delta);
                if backward > max_backward || (CAPPED_CHAINS && delta == 0) {
                    break;
                }
                let prev_ix = cur_ix.wrapping_sub(backward) & ring_buffer_mask;
                let s = bank_slots[last];
                slot = s.next as usize;
                delta = s.delta as usize;
                if cur_ix_masked + best_len > ring_buffer_mask
                    || prev_ix + best_len > ring_buffer_mask
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
            self.store(data, ring_buffer_mask, cur_ix);
        }
        if out.score == min_score {
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
