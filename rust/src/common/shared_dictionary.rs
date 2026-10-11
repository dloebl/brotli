//! Port of `c/common/shared_dictionary.c` (default, non-experimental build).
//!
//! In the default build of the C library only raw LZ77 prefix dictionaries
//! ("compound" dictionaries) can be attached; serialized shared dictionaries
//! are rejected (`BROTLI_SHARED_DICTIONARY_SERIALIZED`: "DO NOT USE: methods
//! accepting this value will fail").

use super::constants::{SHARED_BROTLI_MAX_COMPOUND_DICTS, SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS};
use super::dictionary::{brotli_get_dictionary, BrotliDictionary};
use super::transform::{brotli_get_transforms, BrotliTransforms};

/// `BrotliSharedDictionaryType`.
pub const BROTLI_SHARED_DICTIONARY_RAW: u32 = 0;
pub const BROTLI_SHARED_DICTIONARY_SERIALIZED: u32 = 1;

/// Rust equivalent of `BrotliSharedDictionaryInternal`.
pub struct SharedDictionary {
    /// LZ77 prefixes (compound dictionary).
    pub num_prefix: u32,
    pub prefix_size: [usize; SHARED_BROTLI_MAX_COMPOUND_DICTS],
    /// Client-owned prefix data; must outlive the dictionary (C contract).
    pub prefix: [*const u8; SHARED_BROTLI_MAX_COMPOUND_DICTS],

    /// If set, the context map selects word and transform lists from 64
    /// contexts; otherwise only `words[0]` and `transforms[0]` are used.
    pub context_based: bool,
    pub context_map: [u8; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
    /// Amount of word_list+transform_list combinations.
    pub num_dictionaries: u8,
    pub words: [&'static BrotliDictionary; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
    pub transforms: [&'static BrotliTransforms; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
}

impl Default for SharedDictionary {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedDictionary {
    /// State right after `BrotliSharedDictionaryCreateInstance`.
    pub fn new() -> Self {
        SharedDictionary {
            num_prefix: 0,
            prefix_size: [0; SHARED_BROTLI_MAX_COMPOUND_DICTS],
            prefix: [core::ptr::null(); SHARED_BROTLI_MAX_COMPOUND_DICTS],
            context_based: false,
            context_map: [0; SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
            num_dictionaries: 1,
            words: [brotli_get_dictionary(); SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
            transforms: [brotli_get_transforms(); SHARED_BROTLI_NUM_DICTIONARY_CONTEXTS],
        }
    }

    /// `BrotliSharedDictionaryAttach`.
    ///
    /// # Safety
    /// For raw dictionaries `data` must point to `data_size` bytes that stay
    /// valid as long as the dictionary is used.
    pub unsafe fn attach(&mut self, dict_type: u32, data_size: usize, data: *const u8) -> bool {
        if dict_type == BROTLI_SHARED_DICTIONARY_RAW {
            if self.num_prefix as usize >= SHARED_BROTLI_MAX_COMPOUND_DICTS {
                return false;
            }
            self.prefix_size[self.num_prefix as usize] = data_size;
            self.prefix[self.num_prefix as usize] = data;
            self.num_prefix += 1;
            return true;
        }
        false
    }

    /// Prefix `i` as a slice.
    ///
    /// # Safety
    /// See [`SharedDictionary::attach`].
    pub unsafe fn prefix_slice(&self, i: usize) -> &[u8] {
        if self.prefix_size[i] == 0 || self.prefix[i].is_null() {
            &[]
        } else {
            core::slice::from_raw_parts(self.prefix[i], self.prefix_size[i])
        }
    }
}
