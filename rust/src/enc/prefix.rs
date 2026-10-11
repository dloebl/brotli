//! Port of `c/enc/prefix.h`.

use super::fast_log::log2_floor_non_zero;
use crate::common::constants::BROTLI_NUM_DISTANCE_SHORT_CODES;

/// `PrefixEncodeCopyDistance`.  Here `distance_code` is an intermediate code,
/// i.e. one of the special codes or the actual distance increased by
/// `BROTLI_NUM_DISTANCE_SHORT_CODES - 1`.  Returns `(code, extra_bits)`.
#[inline(always)]
pub fn prefix_encode_copy_distance(distance_code: usize, num_direct_codes: usize, postfix_bits: usize) -> (u16, u32) {
    let short = BROTLI_NUM_DISTANCE_SHORT_CODES as usize;
    if distance_code < short + num_direct_codes {
        (distance_code as u16, 0)
    } else {
        let dist: usize = (1usize << (postfix_bits + 2)) + (distance_code - short - num_direct_codes);
        let bucket: usize = log2_floor_non_zero(dist) as usize - 1;
        let postfix_mask: usize = (1usize << postfix_bits) - 1;
        let postfix = dist & postfix_mask;
        let prefix = (dist >> bucket) & 1;
        let offset = (2 + prefix) << bucket;
        let nbits = bucket - postfix_bits;
        let code = ((nbits << 10) | (short + num_direct_codes + ((2 * (nbits - 1) + prefix) << postfix_bits) + postfix)) as u16;
        let extra = ((dist - offset) >> postfix_bits) as u32;
        (code, extra)
    }
}
