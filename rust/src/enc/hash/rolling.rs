//! Port of `c/enc/hash_rolling_inc.h` (HROLLING, HROLLING_FAST).
//!
//! Rolling hash for long distance long string matches. Stores one position
//! per bucket, bucket key is computed over a long region.
//!
//! Template parameters: JUMP (skip bytes for speedup); CHUNKLEN, NUMBUCKETS
//! and MASK are the same for both instantiations.
//! NUMBUCKETS / (MASK + 1) = probability of storing and using hash code.

use super::lazy::LazyPrefix;
use super::{backward_reference_score, find_match_length_at, HasherCommon, HasherCore, HasherImpl, HasherSearchResult};
use crate::enc::encoder_dict::BrotliEncoderDictionary;
use crate::enc::memory::MemoryManager;
use crate::enc::params::BrotliEncoderParams;

const CHUNKLEN: usize = 32;
const NUMBUCKETS: usize = 16777216;
const MASK: u32 = ((NUMBUCKETS * 64) - 1) as u32;

const K_ROLLING_HASH_MUL32: u32 = 69069;
const K_INVALID_POS: u32 = 0xffffffff;

/// Computes a code from a single byte. A lookup table of 256 values could
/// be used, but simply adding 1 works about as good.
#[inline(always)]
fn hash_byte(byte: u8) -> u32 {
    byte as u32 + 1
}

#[inline(always)]
fn hash_rolling_function_initial(state: u32, add: u8, factor: u32) -> u32 {
    factor.wrapping_mul(state).wrapping_add(hash_byte(add))
}

#[inline(always)]
fn hash_rolling_function(state: u32, add: u8, rem: u8, factor: u32, factor_remove: u32) -> u32 {
    factor
        .wrapping_mul(state)
        .wrapping_add(hash_byte(add))
        .wrapping_sub(factor_remove.wrapping_mul(hash_byte(rem)))
}

/// `HashRolling` with template parameter `JUMP`.
pub struct HashRolling<const JUMP: usize> {
    state: u32,
    /// `uint32_t table[NUMBUCKETS]`
    table: LazyPrefix<u32>,
    next_ix: usize,
    factor: u32,
    factor_remove: u32,
}

impl<const JUMP: usize> HashRolling<JUMP> {
    #[inline(always)]
    fn table(&mut self) -> &mut [u32] {
        self.table.as_mut_slice()
    }
}

impl<const JUMP: usize> HasherCore for HashRolling<JUMP> {
    /// This hasher uses a longer forward length, but returning a higher
    /// value here will hurt compression by the main hasher when combined
    /// with a composite hasher. The hasher tests for forward itself instead.
    const HASH_TYPE_LENGTH: usize = 4;
    const STORE_LOOKAHEAD: usize = 4;

    fn hash_mem_alloc_in_bytes(_params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize, alloc_size: &mut [usize; 4]) {
        alloc_size[0] = NUMBUCKETS * core::mem::size_of::<u32>();
    }

    fn new(m: &MemoryManager, _common: &HasherCommon, _params: &BrotliEncoderParams, _one_shot: bool, _input_size: usize) -> Self {
        let factor = K_ROLLING_HASH_MUL32;
        // Compute the factor of the oldest byte to remove: factor**steps
        // modulo 0xffffffff (the multiplications rely on 32-bit overflow)
        let mut factor_remove: u32 = 1;
        let mut i = 0;
        while i < CHUNKLEN {
            factor_remove = factor_remove.wrapping_mul(factor);
            i += JUMP;
        }
        let mut table = LazyPrefix::new(m, NUMBUCKETS, K_INVALID_POS);
        table.ensure(NUMBUCKETS);
        HashRolling { state: 0, table, next_ix: 0, factor, factor_remove }
    }

    fn prepare(&mut self, _one_shot: bool, input_size: usize, data: &[u8]) {
        // Too small size, cannot use this hasher.
        if input_size < CHUNKLEN {
            return;
        }
        self.state = 0;
        let mut i = 0;
        while i < CHUNKLEN {
            self.state = hash_rolling_function_initial(self.state, data[i], self.factor);
            i += JUMP;
        }
    }

    #[inline(always)]
    fn store(&mut self, _data: &[u8], _mask: usize, _ix: usize) {}

    #[inline(always)]
    fn store_range(&mut self, _data: &[u8], _mask: usize, _ix_start: usize, _ix_end: usize) {}

    fn stitch_to_previous_block(&mut self, num_bytes: usize, mut position: usize, ringbuffer: &[u8], ring_buffer_mask: usize) {
        // In this case we must re-initialize the hasher from scratch from the
        // current position.
        let mut available = num_bytes;
        if (position & (JUMP - 1)) != 0 {
            let diff = JUMP - (position & (JUMP - 1));
            available = available.saturating_sub(diff);
            position += diff;
        }
        let position_masked = position & ring_buffer_mask;
        // wrapping around ringbuffer not handled.
        if available > ring_buffer_mask - position_masked {
            available = ring_buffer_mask - position_masked;
        }

        self.prepare(false, available, &ringbuffer[position & ring_buffer_mask..]);
        self.next_ix = position;
    }
}

impl<const JUMP: usize> HasherImpl for HashRolling<JUMP> {
    #[inline(always)]
    fn prepare_distance_cache(&self, _distance_cache: &mut [i32]) {}

    #[inline(always)]
    fn find_longest_match(
        &mut self,
        _common: &mut HasherCommon,
        _dictionary: &BrotliEncoderDictionary,
        data: &[u8],
        ring_buffer_mask: usize,
        _distance_cache: &[i32],
        cur_ix: usize,
        max_length: usize,
        max_backward: usize,
        _dictionary_distance: usize,
        _max_distance: usize,
        out: &mut HasherSearchResult,
    ) {
        let cur_ix_masked = cur_ix & ring_buffer_mask;

        if (cur_ix & (JUMP - 1)) != 0 {
            return;
        }

        // Not enough lookahead
        if max_length < CHUNKLEN {
            return;
        }

        let mut pos = self.next_ix;
        while pos <= cur_ix {
            let code = self.state & MASK;

            let rem = data[pos & ring_buffer_mask];
            let add = data[(pos + CHUNKLEN) & ring_buffer_mask];

            self.state = hash_rolling_function(self.state, add, rem, self.factor, self.factor_remove);

            if (code as usize) < NUMBUCKETS {
                let table = self.table();
                let found_ix = table[code as usize] as usize;
                table[code as usize] = pos as u32;
                if pos == cur_ix && found_ix != K_INVALID_POS as usize {
                    // The cast to 32-bit makes backward distances up to 4GB
                    // work even if cur_ix is above 4GB, despite using 32-bit
                    // values in the table.
                    let backward = cur_ix.wrapping_sub(found_ix) as u32 as usize;
                    if backward <= max_backward {
                        let found_ix_masked = found_ix & ring_buffer_mask;
                        let len = find_match_length_at(data, found_ix_masked, cur_ix_masked, max_length);
                        if len >= 4 && len > out.len {
                            let score = backward_reference_score(len, backward);
                            if score > out.score {
                                out.len = len;
                                out.distance = backward;
                                out.score = score;
                                out.len_code_delta = 0;
                            }
                        }
                    }
                }
            }
            pos += JUMP;
        }

        self.next_ix = cur_ix + JUMP;

        // NOTE: this hasher does not search in the dictionary. It is used as
        // backup-hasher, the main hasher already searches in it.
    }
}
