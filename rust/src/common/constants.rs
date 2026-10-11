//! Port of `c/common/constants.h` / `constants.c`.

pub const BROTLI_CONTEXT_MAP_MAX_RLE: u32 = 16;
pub const BROTLI_MAX_NUMBER_OF_BLOCK_TYPES: u32 = 256;
pub const BROTLI_NUM_LITERAL_SYMBOLS: usize = 256;
pub const BROTLI_NUM_COMMAND_SYMBOLS: usize = 704;
pub const BROTLI_NUM_BLOCK_LEN_SYMBOLS: usize = 26;
pub const BROTLI_MAX_CONTEXT_MAP_SYMBOLS: u32 = BROTLI_MAX_NUMBER_OF_BLOCK_TYPES + BROTLI_CONTEXT_MAP_MAX_RLE;
pub const BROTLI_MAX_BLOCK_TYPE_SYMBOLS: u32 = BROTLI_MAX_NUMBER_OF_BLOCK_TYPES + 2;

pub const BROTLI_REPEAT_PREVIOUS_CODE_LENGTH: u32 = 16;
pub const BROTLI_REPEAT_ZERO_CODE_LENGTH: u32 = 17;
pub const BROTLI_CODE_LENGTH_CODES: usize = (BROTLI_REPEAT_ZERO_CODE_LENGTH + 1) as usize;
pub const BROTLI_INITIAL_REPEATED_CODE_LENGTH: u32 = 8;

pub const BROTLI_LARGE_MAX_DISTANCE_BITS: u32 = 62;
pub const BROTLI_LARGE_MIN_WBITS: u32 = 10;
pub const BROTLI_LARGE_MAX_WBITS: u32 = 30;

pub const BROTLI_NUM_DISTANCE_SHORT_CODES: u32 = 16;
pub const BROTLI_MAX_NPOSTFIX: u32 = 3;
pub const BROTLI_MAX_NDIRECT: u32 = 120;
pub const BROTLI_MAX_DISTANCE_BITS: u32 = 24;

/// `BROTLI_DISTANCE_ALPHABET_SIZE(NPOSTFIX, NDIRECT, MAXNBITS)`
#[inline]
pub const fn brotli_distance_alphabet_size(npostfix: u32, ndirect: u32, maxnbits: u32) -> u32 {
    BROTLI_NUM_DISTANCE_SHORT_CODES + ndirect + (maxnbits << (npostfix + 1))
}

/// `BROTLI_NUM_DISTANCE_SYMBOLS` (== 1128).
///
/// NB: the C macro passes NDIRECT/NPOSTFIX in swapped order, which is an
/// undefined shift in C; it is unused there.  We use the documented value.
pub const BROTLI_NUM_DISTANCE_SYMBOLS: usize =
    brotli_distance_alphabet_size(BROTLI_MAX_NPOSTFIX, BROTLI_MAX_NDIRECT, BROTLI_LARGE_MAX_DISTANCE_BITS) as usize;

pub const BROTLI_MAX_DISTANCE: usize = 0x3FFFFFC;
pub const BROTLI_MAX_ALLOWED_DISTANCE: usize = 0x7FFFFFFC;

pub const BROTLI_NUM_INS_COPY_CODES: usize = 24;

pub const BROTLI_LITERAL_CONTEXT_BITS: u32 = 6;
pub const BROTLI_DISTANCE_CONTEXT_BITS: u32 = 2;

pub const BROTLI_WINDOW_GAP: usize = 16;

/// `BROTLI_MAX_BACKWARD_LIMIT(W)`
#[inline]
pub const fn brotli_max_backward_limit(w: u32) -> usize {
    (1usize << w) - BROTLI_WINDOW_GAP
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrotliDistanceCodeLimit {
    pub max_alphabet_size: u32,
    pub max_distance: u32,
}

/// `BrotliCalculateDistanceCodeLimit`.
pub fn brotli_calculate_distance_code_limit(max_distance: u32, npostfix: u32, ndirect: u32) -> BrotliDistanceCodeLimit {
    if max_distance <= ndirect {
        return BrotliDistanceCodeLimit {
            max_alphabet_size: max_distance.wrapping_add(BROTLI_NUM_DISTANCE_SHORT_CODES),
            max_distance,
        };
    }
    let forbidden_distance = max_distance.wrapping_add(1);
    let mut offset = forbidden_distance.wrapping_sub(ndirect).wrapping_sub(1);
    let mut ndistbits: u32 = 0;
    let postfix = (1u32 << npostfix) - 1;
    offset = (offset >> npostfix) + 4;
    let mut tmp = offset / 2;
    while tmp != 0 {
        ndistbits += 1;
        tmp >>= 1;
    }
    ndistbits = ndistbits.wrapping_sub(1);
    let half = (offset >> ndistbits) & 1;
    let mut group = (ndistbits.wrapping_sub(1) << 1) | half;
    if group == 0 {
        return BrotliDistanceCodeLimit {
            max_alphabet_size: ndirect + BROTLI_NUM_DISTANCE_SHORT_CODES,
            max_distance: ndirect,
        };
    }
    group -= 1;
    ndistbits = (group >> 1) + 1;
    let extra = (1u32 << ndistbits) - 1;
    let mut start = (1u32 << (ndistbits + 1)) - 4;
    start += (group & 1) << ndistbits;
    BrotliDistanceCodeLimit {
        max_alphabet_size: ((group << npostfix) | postfix) + ndirect + BROTLI_NUM_DISTANCE_SHORT_CODES + 1,
        max_distance: ((start + extra) << npostfix).wrapping_add(postfix).wrapping_add(ndirect).wrapping_add(1),
    }
}

/// `BrotliPrefixCodeRange`: range of values `[offset, offset + 2^nbits)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BrotliPrefixCodeRange {
    pub offset: u16,
    pub nbits: u8,
}

const fn make_prefix_code_ranges() -> [BrotliPrefixCodeRange; BROTLI_NUM_BLOCK_LEN_SYMBOLS] {
    let src = &super::tables::PREFIX_CODE_RANGES;
    let mut out = [BrotliPrefixCodeRange { offset: 0, nbits: 0 }; BROTLI_NUM_BLOCK_LEN_SYMBOLS];
    let mut i = 0;
    while i < BROTLI_NUM_BLOCK_LEN_SYMBOLS {
        out[i] = BrotliPrefixCodeRange { offset: src[i].0, nbits: src[i].1 };
        i += 1;
    }
    out
}

/// `_kBrotliPrefixCodeRanges`: block length prefix code ranges.
pub static K_BROTLI_PREFIX_CODE_RANGES: [BrotliPrefixCodeRange; BROTLI_NUM_BLOCK_LEN_SYMBOLS] = make_prefix_code_ranges();

/// Public API constants from `<brotli/encode.h>`.
pub const BROTLI_MIN_WINDOW_BITS: i32 = 10;
pub const BROTLI_MAX_WINDOW_BITS: i32 = 24;
pub const BROTLI_LARGE_MAX_WINDOW_BITS: i32 = 30;
pub const BROTLI_MIN_INPUT_BLOCK_BITS: i32 = 16;
pub const BROTLI_MAX_INPUT_BLOCK_BITS: i32 = 24;
pub const BROTLI_MIN_QUALITY: i32 = 0;
pub const BROTLI_MAX_QUALITY: i32 = 11;
pub const BROTLI_DEFAULT_QUALITY: i32 = 11;
pub const BROTLI_DEFAULT_WINDOW: i32 = 22;

/// Public API constants from `<brotli/shared_dictionary.h>`.
pub const SHARED_BROTLI_MIN_DICTIONARY_WORD_LENGTH: usize = 4;
pub const SHARED_BROTLI_MAX_DICTIONARY_WORD_LENGTH: usize = 31;
pub const SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS: usize = 64;
pub const SHARED_BROTLI_MAX_COMPOUND_DICTS: usize = 15;

pub const BROTLI_UINT32_MAX: u32 = u32::MAX;
pub const BROTLI_SIZE_MAX: usize = usize::MAX;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distance_symbols() {
        assert_eq!(BROTLI_NUM_DISTANCE_SYMBOLS, 1128);
    }
}
