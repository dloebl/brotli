//! Port of `c/enc/static_dict.h` / `static_dict.c`: class to model the
//! static dictionary.
//!
//! OWNER: worker "hashers".

pub const BROTLI_MAX_STATIC_DICTIONARY_MATCH_LEN: usize = 37;
pub const K_INVALID_MATCH: u32 = 0xFFFFFFF;
