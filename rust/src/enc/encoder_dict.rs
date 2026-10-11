//! Port of `c/enc/encoder_dict.h` / `encoder_dict.c` (default,
//! non-experimental build).
//!
//! Dictionary hierarchy for Encoder:
//! - SharedEncoderDictionary
//!   - CompoundDictionary
//!     - PreparedDictionary [up to 15x] = prefix dictionary with precomputed
//!       hashes
//!   - ContextualEncoderDictionary
//!     - BrotliEncoderDictionary [up to 64x] = for each context, precomputed
//!       static dictionary with words + transforms
//!
//! In the default build only the RFC 7932 static dictionary is available as
//! (non-compound) dictionary, so all `BrotliEncoderDictionary` references
//! point to the static [`DEFAULT_ENCODER_DICTIONARY`].

use super::compound_dictionary::{CompoundDictionary, K_SHARED_DICTIONARY_MAGIC};
use super::static_dict_lut::{
    DictWord, K_STATIC_DICTIONARY_BUCKETS, K_STATIC_DICTIONARY_HASH_LENGTHS, K_STATIC_DICTIONARY_HASH_WORDS,
    K_STATIC_DICTIONARY_WORDS,
};
use crate::common::constants::{BROTLI_MAX_QUALITY, SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS};
use crate::common::dictionary::{BrotliDictionary, BROTLI_DICTIONARY};
use crate::common::transform::BROTLI_TRANSFORMS;

/// `kCutoffTransformsCount` (hash.h).
pub const K_CUTOFF_TRANSFORMS_COUNT: u32 = 10;
/// `kCutoffTransforms` (hash.h):
/// `0,  12,   27,    23,    42,    63,    56,    48,    59,    64`
/// `0+0, 4+8, 8+19, 12+11, 16+26, 20+43, 24+32, 28+20, 32+27, 36+28`
pub const K_CUTOFF_TRANSFORMS: u64 = (0x071B520Au64 << 32) | 0xDA2D3200u64;

/// `BrotliEncoderDictionary`.
#[derive(Debug)]
pub struct BrotliEncoderDictionary {
    pub words: &'static BrotliDictionary,
    pub num_transforms: u32,
    /// cut off for fast encoder
    pub cutoff_transforms_count: u32,
    pub cutoff_transforms: u64,
    /// from dictionary_hash.h, for fast encoder
    pub hash_table_words: &'static [u16],
    pub hash_table_lengths: &'static [u8],
    /// from static_dict_lut.h, for slow encoder
    pub buckets: &'static [u16],
    pub dict_words: &'static [DictWord],
    /// Heavy version (trie of all transformed words); only used with custom
    /// (experimental) dictionaries, always false in the default build.
    pub has_words_heavy: bool,
}

/// `InitEncoderDictionary`: RFC 7932 static dictionary / transforms.
pub static DEFAULT_ENCODER_DICTIONARY: BrotliEncoderDictionary = BrotliEncoderDictionary {
    words: &BROTLI_DICTIONARY,
    num_transforms: (crate::common::tables::TRANSFORMS_DATA.len() / 3) as u32,
    cutoff_transforms_count: K_CUTOFF_TRANSFORMS_COUNT,
    cutoff_transforms: K_CUTOFF_TRANSFORMS,
    hash_table_words: &K_STATIC_DICTIONARY_HASH_WORDS,
    hash_table_lengths: &K_STATIC_DICTIONARY_HASH_LENGTHS,
    buckets: &K_STATIC_DICTIONARY_BUCKETS,
    dict_words: &K_STATIC_DICTIONARY_WORDS,
    has_words_heavy: false,
};

// Silence "unused" for the transforms import in builds that do not need it.
#[allow(dead_code)]
fn _assert_transforms_count() -> u32 {
    BROTLI_TRANSFORMS.num_transforms
}

/// `ContextualEncoderDictionary`.
#[derive(Clone, Copy, Debug)]
pub struct ContextualEncoderDictionary {
    pub context_based: bool,
    pub num_dictionaries: u8,
    pub context_map: [u8; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
    pub dict: [&'static BrotliEncoderDictionary; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
}

/// `SharedEncoderDictionary`.
#[derive(Clone, Copy, Debug)]
pub struct SharedEncoderDictionary {
    /// Magic value to distinguish this struct from PreparedDictionary.
    pub magic: u32,
    /// LZ77 prefix, compound dictionary
    pub compound: CompoundDictionary,
    /// Custom static dictionary (optionally context-based)
    pub contextual: ContextualEncoderDictionary,
    /// The maximum quality the dictionary was computed for
    pub max_quality: i32,
}

impl SharedEncoderDictionary {
    /// `BrotliInitSharedEncoderDictionary`.
    pub fn new() -> Self {
        SharedEncoderDictionary {
            magic: K_SHARED_DICTIONARY_MAGIC,
            compound: CompoundDictionary::new(),
            contextual: ContextualEncoderDictionary {
                context_based: false,
                num_dictionaries: 1,
                context_map: [0; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
                dict: [&DEFAULT_ENCODER_DICTIONARY; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
            },
            max_quality: BROTLI_MAX_QUALITY,
        }
    }
}

impl Default for SharedEncoderDictionary {
    fn default() -> Self {
        Self::new()
    }
}
