//! Port of `c/enc/static_dict_lut.h` and `c/enc/dictionary_hash.h`: lookup
//! tables for the static dictionary (embedded at compile time, i.e.
//! `BROTLI_STATIC_INIT_NONE`).

/// `DictWord`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DictWord {
    /// Highest bit is used to indicate end of bucket.
    pub len: u8,
    pub transform: u8,
    pub idx: u16,
}

pub const BROTLI_ENC_STATIC_DICT_LUT_NUM_BUCKETS: usize = 32768;
pub const BROTLI_ENC_STATIC_DICT_LUT_NUM_ITEMS: usize = 31705;
pub const BROTLI_ENC_NUM_HASH_BUCKETS: usize = 32768;

pub use super::static_dict_tables::{
    STATIC_DICTIONARY_BUCKETS as K_STATIC_DICTIONARY_BUCKETS,
    STATIC_DICTIONARY_HASH_LENGTHS as K_STATIC_DICTIONARY_HASH_LENGTHS,
    STATIC_DICTIONARY_HASH_WORDS as K_STATIC_DICTIONARY_HASH_WORDS,
    STATIC_DICTIONARY_WORDS as K_STATIC_DICTIONARY_WORDS,
};
