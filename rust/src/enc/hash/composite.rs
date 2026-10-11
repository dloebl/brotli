//! Port of `c/enc/hash_composite_inc.h` (H35, H55, H65).
//!
//! Composite hasher: This hasher allows to combine two other hashers,
//! HASHER_A and HASHER_B.

use super::{HasherCommon, HasherCore, HasherImpl, HasherSearchResult};
use crate::enc::encoder_dict::BrotliEncoderDictionary;
use crate::enc::memory::MemoryManager;
use crate::enc::params::BrotliEncoderParams;

/// `HashComposite` of `A` (HASHER_A) and `B` (HASHER_B).
///
/// In C, the initialization of the sub-hashers is deferred to the first
/// `Prepare`, which `HasherSetup` invokes right after `Initialize`; doing
/// it in `new` is equivalent.
pub struct HashComposite<A, B> {
    ha: A,
    hb: B,
    /// `ha_common = *common` / `hb_common = *common` (by value: the
    /// sub-hashers keep their own static dictionary statistics).
    ha_common: HasherCommon,
    hb_common: HasherCommon,
}

impl<A: HasherImpl, B: HasherImpl> HasherCore for HashComposite<A, B> {
    const HASH_TYPE_LENGTH: usize =
        if A::HASH_TYPE_LENGTH > B::HASH_TYPE_LENGTH { A::HASH_TYPE_LENGTH } else { B::HASH_TYPE_LENGTH };
    const STORE_LOOKAHEAD: usize =
        if A::STORE_LOOKAHEAD > B::STORE_LOOKAHEAD { A::STORE_LOOKAHEAD } else { B::STORE_LOOKAHEAD };

    fn hash_mem_alloc_in_bytes(params: &BrotliEncoderParams, one_shot: bool, input_size: usize, alloc_size: &mut [usize; 4]) {
        let mut alloc_size_a = [0usize; 4];
        let mut alloc_size_b = [0usize; 4];
        A::hash_mem_alloc_in_bytes(params, one_shot, input_size, &mut alloc_size_a);
        B::hash_mem_alloc_in_bytes(params, one_shot, input_size, &mut alloc_size_b);
        // Should never happen.
        debug_assert!(alloc_size_a[2] == 0 && alloc_size_a[3] == 0);
        debug_assert!(alloc_size_b[2] == 0 && alloc_size_b[3] == 0);
        alloc_size[0] = alloc_size_a[0];
        alloc_size[1] = alloc_size_a[1];
        alloc_size[2] = alloc_size_b[0];
        alloc_size[3] = alloc_size_b[1];
    }

    fn new(m: &MemoryManager, common: &HasherCommon, params: &BrotliEncoderParams, one_shot: bool, input_size: usize) -> Self {
        let ha_common = common.copy_scalars();
        let hb_common = common.copy_scalars();
        let ha = A::new(m, &ha_common, params, one_shot, input_size);
        let hb = B::new(m, &hb_common, params, one_shot, input_size);
        HashComposite { ha, hb, ha_common, hb_common }
    }

    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]) {
        self.ha.prepare(one_shot, input_size, data);
        self.hb.prepare(one_shot, input_size, data);
    }

    #[inline(always)]
    fn store(&mut self, data: &[u8], mask: usize, ix: usize) {
        self.ha.store(data, mask, ix);
        self.hb.store(data, mask, ix);
    }

    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        self.ha.store_range(data, mask, ix_start, ix_end);
        self.hb.store_range(data, mask, ix_start, ix_end);
    }

    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ring_buffer_mask: usize) {
        self.ha.stitch_to_previous_block(num_bytes, position, ringbuffer, ring_buffer_mask);
        self.hb.stitch_to_previous_block(num_bytes, position, ringbuffer, ring_buffer_mask);
    }
}

impl<A: HasherImpl, B: HasherImpl> HasherImpl for HashComposite<A, B> {
    #[inline(always)]
    fn prepare_distance_cache(&self, distance_cache: &mut [i32]) {
        self.ha.prepare_distance_cache(distance_cache);
        self.hb.prepare_distance_cache(distance_cache);
    }

    #[inline(always)]
    fn find_longest_match(
        &mut self,
        _common: &mut HasherCommon,
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
        self.ha.find_longest_match(
            &mut self.ha_common,
            dictionary,
            data,
            ring_buffer_mask,
            distance_cache,
            cur_ix,
            max_length,
            max_backward,
            dictionary_distance,
            max_distance,
            out,
        );
        self.hb.find_longest_match(
            &mut self.hb_common,
            dictionary,
            data,
            ring_buffer_mask,
            distance_cache,
            cur_ix,
            max_length,
            max_backward,
            dictionary_distance,
            max_distance,
            out,
        );
    }
}
