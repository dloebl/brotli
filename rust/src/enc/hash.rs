//! Port of `c/enc/hash.h` and all hasher templates (`hash_*_inc.h`,
//! `hash_base.h`, `matching_tag_mask.h`): a (forgetful) hash table to the
//! data seen by the compressor, to help create backward references to
//! previous data.
//!
//! OWNER: worker "hashers".  Hasher implementations may live in submodules
//! under `src/enc/hash/`.
//!
//! The C templates are mapped to generic structs implementing the
//! [`HasherImpl`] trait (one instantiation per C `HASHER()`):
//!
//! | C       | Rust                                                   |
//! |---------|--------------------------------------------------------|
//! | H2      | `HashLongestMatchQuickly<16, 0, 5, true>`              |
//! | H3      | `HashLongestMatchQuickly<16, 1, 5, false>`             |
//! | H4      | `HashLongestMatchQuickly<17, 2, 5, true>`              |
//! | H54     | `HashLongestMatchQuickly<20, 2, 7, false>`             |
//! | H5      | `HashLongestMatch`                                     |
//! | H6      | `HashLongestMatch64`                                   |
//! | H58/H59 | `HashLongestMatchSimd<false>` / `<true>`               |
//! | H68     | `HashLongestMatch64Simd`                               |
//! | H40-42  | `HashForgetfulChain<15, banks, bank bits, distances>`  |
//! | HROLLING(_FAST) | `HashRolling<1>` / `HashRolling<4>`            |
//! | H35/H55/H65 | `HashComposite<A, B>`                              |
//! | H10     | `HashToBinaryTree`                                     |

mod binary_tree;
mod composite;
mod forgetful_chain;
mod lazy;
mod longest_match;
mod quickly;
mod rolling;
mod simd;

pub use binary_tree::{HashToBinaryTree, MAX_NUM_MATCHES_H10, MAX_TREE_COMP_LENGTH_H10};
pub use composite::HashComposite;
pub use forgetful_chain::HashForgetfulChain;
pub use longest_match::{HashLongestMatch, HashLongestMatch64};
pub use quickly::HashLongestMatchQuickly;
pub use rolling::HashRolling;
pub use simd::{get_matching_tag_mask, HashLongestMatch64Simd, HashLongestMatchSimd};

use super::compound_dictionary::{CompoundDictionary, PreparedDictionary, K_PREPARED_DICTIONARY_HASH_MUL64_LONG};
use super::encoder_dict::BrotliEncoderDictionary;
use super::fast_log::log2_floor_non_zero;
use super::memory::{Buf, MemoryManager};
use super::params::{Base64Region, BrotliEncoderParams, BrotliHasherParams};
use super::quality::{choose_hasher, max_metablock_size, HAVE_SIMD_HASHERS};
use crate::common::constants::SHARED_BROTLI_MAX_COMPOUND_DICTS;

/// `H2`.
pub type H2 = HashLongestMatchQuickly<16, 0, 5, true>;
/// `H3`.
pub type H3 = HashLongestMatchQuickly<16, 1, 5, false>;
/// `H4`.
pub type H4 = HashLongestMatchQuickly<17, 2, 5, true>;
/// `H54`.
pub type H54 = HashLongestMatchQuickly<20, 2, 7, false>;
/// `H5`.
pub type H5 = HashLongestMatch;
/// `H6`.
pub type H6 = HashLongestMatch64;
/// `H58`.
pub type H58 = HashLongestMatchSimd<false>;
/// `H59`.
pub type H59 = HashLongestMatchSimd<true>;
/// `H68`.
pub type H68 = HashLongestMatch64Simd;
/// `H40`.
pub type H40 = HashForgetfulChain<15, 1, 16, 4>;
/// `H41`.
pub type H41 = HashForgetfulChain<15, 1, 16, 10>;
/// `H42`.
pub type H42 = HashForgetfulChain<15, 512, 9, 16>;
/// `HROLLING_FAST`.
pub type HRollingFast = HashRolling<4>;
/// `HROLLING`.
pub type HRolling = HashRolling<1>;
/// `H35`.
pub type H35 = HashComposite<H3, HRollingFast>;
/// `H55`.
pub type H55 = HashComposite<H54, HRollingFast>;
/// `H65`.
pub type H65 = HashComposite<H6, HRolling>;
/// `H10`.
pub type H10 = HashToBinaryTree;

/// `kHashMul32`.
pub const K_HASH_MUL32: u32 = 0x1E35A7BD;
/// `kHashMul64`.
pub const K_HASH_MUL64: u64 = (0x1FE35A7Bu64 << 32) | 0xD3579BD3u64;

/// `BROTLI_UNALIGNED_LOAD16LE` / `BrotliUnalignedRead16`.
#[inline(always)]
pub(crate) fn load16(data: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([data[i], data[i + 1]])
}

/// `BROTLI_UNALIGNED_LOAD32LE` / `BrotliUnalignedRead32`.
#[inline(always)]
pub(crate) fn load32(data: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(data[i..i + 4].try_into().unwrap())
}

/// `BROTLI_UNALIGNED_LOAD64LE` / `BrotliUnalignedRead64`.
#[inline(always)]
pub(crate) fn load64(data: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(data[i..i + 8].try_into().unwrap())
}

/// `FindMatchLengthWithLimit`: number of equal leading bytes of `s1` and
/// `s2`, at most `limit` (clamped to the slice lengths; in C reading past
/// them would be undefined behavior).
#[inline(always)]
pub(crate) fn find_match_length(s1: &[u8], s2: &[u8], limit: usize) -> usize {
    let limit = limit.min(s1.len()).min(s2.len());
    let a = &s1[..limit];
    let b = &s2[..limit];
    let mut matched = 0usize;
    let mut ca = a.chunks_exact(8);
    let mut cb = b.chunks_exact(8);
    for (x, y) in (&mut ca).zip(&mut cb) {
        let d = u64::from_le_bytes(x.try_into().unwrap()) ^ u64::from_le_bytes(y.try_into().unwrap());
        if d != 0 {
            return matched + (d.trailing_zeros() as usize >> 3);
        }
        matched += 8;
    }
    for (x, y) in ca.remainder().iter().zip(cb.remainder().iter()) {
        if x != y {
            return matched;
        }
        matched += 1;
    }
    matched
}

/// `FindMatchLengthWithLimit(&data[i1], &data[i2], limit)`.
#[inline(always)]
pub(crate) fn find_match_length_at(data: &[u8], i1: usize, i2: usize, limit: usize) -> usize {
    find_match_length(&data[i1..], &data[i2..], limit)
}

/// `Hash14`.
#[inline(always)]
pub fn hash14(data: &[u8]) -> u32 {
    let h = load32(data, 0).wrapping_mul(K_HASH_MUL32);
    // The higher bits contain more mixture from the multiplication,
    // so we take our results from there.
    h >> (32 - 14)
}

/// `Hash15`.
#[inline(always)]
pub fn hash15(data: &[u8]) -> u32 {
    let h = load32(data, 0).wrapping_mul(K_HASH_MUL32);
    h >> (32 - 15)
}

/// `HasherCommon`.
#[derive(Default)]
pub struct HasherCommon {
    /// False before the first invocation of HasherSetup (where "extra"
    /// memory is allocated).
    pub is_setup_: bool,
    pub dict_num_lookups: usize,
    pub dict_num_matches: usize,
    pub params: BrotliHasherParams,
    /// False if hasher needs to be "prepared" before use.
    pub is_prepared_: bool,
    pub base64_regions: Buf<Base64Region>,
    pub num_base64_regions: usize,
}

impl HasherCommon {
    /// By-value copy of the scalar part (`ha_common = *common` in the
    /// composite hasher; the base64 region pointer is never used by the
    /// sub-hashers).
    pub(crate) fn copy_scalars(&self) -> HasherCommon {
        HasherCommon {
            is_setup_: self.is_setup_,
            dict_num_lookups: self.dict_num_lookups,
            dict_num_matches: self.dict_num_matches,
            params: self.params,
            is_prepared_: self.is_prepared_,
            base64_regions: Buf::empty(),
            num_base64_regions: self.num_base64_regions,
        }
    }
}

/// `score_t`.
pub type Score = usize;

/// `HasherSearchResult`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HasherSearchResult {
    pub len: usize,
    pub distance: usize,
    pub score: Score,
    /// == len_code - len
    pub len_code_delta: i32,
}

/// `PrepareDistanceCache`.
#[inline(always)]
pub fn prepare_distance_cache(distance_cache: &mut [i32], num_distances: i32) {
    if num_distances > 4 {
        let last_distance = distance_cache[0];
        distance_cache[4] = last_distance.wrapping_sub(1);
        distance_cache[5] = last_distance.wrapping_add(1);
        distance_cache[6] = last_distance.wrapping_sub(2);
        distance_cache[7] = last_distance.wrapping_add(2);
        distance_cache[8] = last_distance.wrapping_sub(3);
        distance_cache[9] = last_distance.wrapping_add(3);
        if num_distances > 10 {
            let next_last_distance = distance_cache[1];
            distance_cache[10] = next_last_distance.wrapping_sub(1);
            distance_cache[11] = next_last_distance.wrapping_add(1);
            distance_cache[12] = next_last_distance.wrapping_sub(2);
            distance_cache[13] = next_last_distance.wrapping_add(2);
            distance_cache[14] = next_last_distance.wrapping_sub(3);
            distance_cache[15] = next_last_distance.wrapping_add(3);
        }
    }
}

pub const BROTLI_LITERAL_BYTE_SCORE: usize = 135;
pub const BROTLI_DISTANCE_BIT_PENALTY: usize = 30;
/// Score must be positive after applying maximal penalty.
pub const BROTLI_SCORE_BASE: usize = BROTLI_DISTANCE_BIT_PENALTY * 8 * core::mem::size_of::<usize>();

/// `BackwardReferenceScore`.
///
/// Usually, we always choose the longest backward reference. This function
/// allows for the exception of that rule.
///
/// If we choose a backward reference that is further away, it will usually
/// be coded with more bits. We approximate this by assuming log2(distance).
/// If the distance can be expressed in terms of the last four distances, we
/// use some heuristic constants to estimate the bits cost. For the first up
/// to four literals we use the bit cost of the literals from the literal
/// cost model, after that we use the average bit cost of the cost model.
///
/// This function is used to sometimes discard a longer backward reference
/// when it is not much longer and the bit cost for encoding it is more than
/// the saved literals.
///
/// backward_reference_offset MUST be positive.
#[inline(always)]
pub fn backward_reference_score(copy_length: usize, backward_reference_offset: usize) -> Score {
    (BROTLI_SCORE_BASE.wrapping_add(BROTLI_LITERAL_BYTE_SCORE.wrapping_mul(copy_length)))
        .wrapping_sub(BROTLI_DISTANCE_BIT_PENALTY * log2_floor_non_zero(backward_reference_offset) as usize)
}

/// `MinimumBetterLength`: returns the minimum length of a backward reference
/// that will improve on the provided score.  We conservatively assume that
/// the match will be a last distance match, the best case scenario for the
/// next match.
#[inline(always)]
pub fn minimum_better_length(score: Score) -> usize {
    score.wrapping_sub(BROTLI_SCORE_BASE + 15) / BROTLI_LITERAL_BYTE_SCORE
}

/// `BackwardReferenceScoreUsingLastDistance`.
#[inline(always)]
pub fn backward_reference_score_using_last_distance(copy_length: usize) -> Score {
    BROTLI_LITERAL_BYTE_SCORE.wrapping_mul(copy_length).wrapping_add(BROTLI_SCORE_BASE + 15)
}

/// `BackwardReferencePenaltyUsingLastDistance`.
#[inline(always)]
pub fn backward_reference_penalty_using_last_distance(distance_short_code: usize) -> Score {
    39 + ((0x1CA10 >> (distance_short_code & 0xE)) & 0xE)
}

/// `TestStaticDictionaryItem`.  `data` starts at the current position.
#[inline]
pub fn test_static_dictionary_item(
    dictionary: &BrotliEncoderDictionary,
    len: usize,
    word_idx: usize,
    data: &[u8],
    max_length: usize,
    max_backward: usize,
    max_distance: usize,
    out: &mut HasherSearchResult,
) -> bool {
    let words = dictionary.words;
    let offset = (words.offsets_by_length[len] as usize).wrapping_add(len.wrapping_mul(word_idx));
    if len > max_length {
        return false;
    }
    let matchlen = find_match_length(data, &words.data()[offset..], len);
    if matchlen + dictionary.cutoff_transforms_count as usize <= len || matchlen == 0 {
        return false;
    }
    let backward;
    {
        let cut = len - matchlen;
        let transform_id = (cut << 2).wrapping_add(((dictionary.cutoff_transforms >> (cut * 6)) & 0x3F) as usize);
        backward = max_backward
            .wrapping_add(1)
            .wrapping_add(word_idx)
            .wrapping_add(transform_id << words.size_bits_by_length[len]);
    }
    if backward > max_distance {
        return false;
    }
    let score = backward_reference_score(matchlen, backward);
    if score < out.score {
        return false;
    }
    out.len = matchlen;
    out.len_code_delta = len as i32 - matchlen as i32;
    out.distance = backward;
    out.score = score;
    true
}

/// `SearchInStaticDictionary`.  `data` starts at the current position.
#[inline]
pub fn search_in_static_dictionary(
    dictionary: &BrotliEncoderDictionary,
    common: &mut HasherCommon,
    data: &[u8],
    max_length: usize,
    max_backward: usize,
    max_distance: usize,
    out: &mut HasherSearchResult,
    shallow: bool,
) {
    if common.dict_num_matches < (common.dict_num_lookups >> 7) {
        return;
    }
    let mut key = (hash14(data) << 1) as usize;
    let n = if shallow { 1 } else { 2 };
    for _ in 0..n {
        common.dict_num_lookups = common.dict_num_lookups.wrapping_add(1);
        let len = dictionary.hash_table_lengths[key];
        if len != 0 {
            let item_matches = test_static_dictionary_item(
                dictionary,
                len as usize,
                dictionary.hash_table_words[key] as usize,
                data,
                max_length,
                max_backward,
                max_distance,
                out,
            );
            if item_matches {
                common.dict_num_matches = common.dict_num_matches.wrapping_add(1);
            }
        }
        key += 1;
    }
}

/// `BackwardMatch`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackwardMatch {
    pub distance: u32,
    pub length_and_code: u32,
}

impl BackwardMatch {
    /// `InitBackwardMatch`.
    #[inline(always)]
    pub fn new(dist: usize, len: usize) -> Self {
        BackwardMatch { distance: dist as u32, length_and_code: (len << 5) as u32 }
    }

    /// `InitDictionaryBackwardMatch`.
    #[inline(always)]
    pub fn new_dictionary(dist: usize, len: usize, len_code: usize) -> Self {
        BackwardMatch {
            distance: dist as u32,
            length_and_code: ((len << 5) | (if len == len_code { 0 } else { len_code })) as u32,
        }
    }

    /// `BackwardMatchLength`.
    #[inline(always)]
    pub fn length(&self) -> usize {
        (self.length_and_code >> 5) as usize
    }

    /// `BackwardMatchLengthCode`.
    #[inline(always)]
    pub fn length_code(&self) -> usize {
        let code = (self.length_and_code & 31) as usize;
        if code != 0 {
            code
        } else {
            self.length()
        }
    }
}

/// Interface of one hasher template instantiation (the `FN(...)` functions
/// of the C `hash_*_inc.h` templates) shared by all hashers.
pub trait HasherCore {
    /// `FN(HashTypeLength)`.
    const HASH_TYPE_LENGTH: usize;
    /// `FN(StoreLookahead)`.
    const STORE_LOOKAHEAD: usize;

    /// `FN(HashMemAllocInBytes)`.
    fn hash_mem_alloc_in_bytes(params: &BrotliEncoderParams, one_shot: bool, input_size: usize, alloc_size: &mut [usize; 4]);

    /// Allocation (`HasherSetup`) + `FN(Initialize)`.  `common` is the
    /// hasher's `HasherCommon` (already holding the chosen params).
    fn new(m: &MemoryManager, common: &HasherCommon, params: &BrotliEncoderParams, one_shot: bool, input_size: usize) -> Self;

    /// `FN(Prepare)`.
    fn prepare(&mut self, one_shot: bool, input_size: usize, data: &[u8]);

    /// `FN(Store)`.
    fn store(&mut self, data: &[u8], mask: usize, ix: usize);

    /// `FN(StoreRange)`.
    #[inline(always)]
    fn store_range(&mut self, data: &[u8], mask: usize, ix_start: usize, ix_end: usize) {
        let mut i = ix_start;
        while i < ix_end {
            self.store(data, mask, i);
            i += 1;
        }
    }

    /// `FN(StitchToPreviousBlock)`.
    fn stitch_to_previous_block(&mut self, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize);
}

/// The "generic" hashers (everything but H10): `FN(FindLongestMatch)` API.
pub trait HasherImpl: HasherCore {
    /// `FN(PrepareDistanceCache)`.
    fn prepare_distance_cache(&self, distance_cache: &mut [i32]);

    /// `FN(FindLongestMatch)`.  `common` is the `HasherCommon` the C hasher
    /// points to (dictionary search statistics).
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
    );
}

/// `StitchToPreviousBlock` helper shared by the hashers that store the
/// three last positions of the previous block.
#[inline(always)]
pub(crate) fn stitch_three<H: HasherCore>(h: &mut H, num_bytes: usize, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
    if num_bytes >= H::HASH_TYPE_LENGTH - 1 && position >= 3 {
        // Prepare the hashes for three last bytes of the last write.
        // These could not be calculated before, since they require knowledge
        // of both the previous and the current block.
        h.store(ringbuffer, ringbuffer_mask, position - 3);
        h.store(ringbuffer, ringbuffer_mask, position - 2);
        h.store(ringbuffer, ringbuffer_mask, position - 1);
    }
}

/// The type-specific part of `Hasher` (the C `privat` union).
#[allow(clippy::large_enum_variant)]
#[derive(Default)]
pub enum HasherPrivate {
    #[default]
    None,
    H2(H2),
    H3(H3),
    H4(H4),
    H5(H5),
    H6(H6),
    H40(H40),
    H41(H41),
    H42(H42),
    H54(H54),
    H58(H58),
    H59(H59),
    H68(H68),
    H35(H35),
    H55(H55),
    H65(H65),
    H10(H10),
}

/// `Hasher`: common part plus the type-specific state of the selected
/// hasher (H2, H3, H4, H5, H6, H35, H40, H41, H42, H54, H55, H58, H59, H65,
/// H68, H10).
pub struct Hasher {
    pub common: HasherCommon,
    /// Type specific state (C: `privat` union).
    pub privat: HasherPrivate,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// `HasherInit`.  (`DestroyHasher` == drop.)
    pub fn new() -> Self {
        Hasher { common: HasherCommon::default(), privat: HasherPrivate::None }
    }

    /// `HasherReset`.
    #[inline]
    pub fn reset(&mut self) {
        self.common.is_prepared_ = false;
    }
}

/// Calls `$body` with `$h` bound to the concrete hasher (`FOR_ALL_HASHERS`).
macro_rules! for_all_hashers {
    ($privat:expr, $h:ident => $body:expr, _ => $default:expr) => {
        match $privat {
            HasherPrivate::H2($h) => $body,
            HasherPrivate::H3($h) => $body,
            HasherPrivate::H4($h) => $body,
            HasherPrivate::H5($h) => $body,
            HasherPrivate::H6($h) => $body,
            HasherPrivate::H40($h) => $body,
            HasherPrivate::H41($h) => $body,
            HasherPrivate::H42($h) => $body,
            HasherPrivate::H54($h) => $body,
            HasherPrivate::H58($h) => $body,
            HasherPrivate::H59($h) => $body,
            HasherPrivate::H68($h) => $body,
            HasherPrivate::H35($h) => $body,
            HasherPrivate::H55($h) => $body,
            HasherPrivate::H65($h) => $body,
            HasherPrivate::H10($h) => $body,
            HasherPrivate::None => $default,
        }
    };
}

/// `HasherSize`: fills `alloc_size` with the byte sizes of the (up to 4)
/// allocations the C hasher of `params.hasher.type_` would make.
pub fn hasher_size(params: &BrotliEncoderParams, one_shot: bool, input_size: usize, alloc_size: &mut [usize; 4]) {
    match params.hasher.type_ {
        2 => H2::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        3 => H3::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        4 => H4::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        5 => H5::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        6 => H6::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        40 => H40::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        41 => H41::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        42 => H42::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        54 => H54::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        58 if HAVE_SIMD_HASHERS => H58::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        59 if HAVE_SIMD_HASHERS => H59::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        68 if HAVE_SIMD_HASHERS => H68::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        35 => H35::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        55 => H55::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        65 => H65::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        10 => H10::hash_mem_alloc_in_bytes(params, one_shot, input_size, alloc_size),
        _ => {}
    }
}

/// `HasherSetup`.
pub fn hasher_setup(
    m: &MemoryManager,
    hasher: &mut Hasher,
    params: &mut BrotliEncoderParams,
    data: &[u8],
    position: usize,
    input_size: usize,
    is_last: bool,
) {
    let one_shot = position == 0 && is_last;
    if !hasher.common.is_setup_ {
        let mut hparams = params.hasher;
        choose_hasher(params, &mut hparams);
        params.hasher = hparams;
        hasher.common.params = params.hasher;
        hasher.common.dict_num_lookups = 0;
        hasher.common.dict_num_matches = 0;
        if params.base64_mode != 0 && params.max_base64_regions > 0 {
            // C allocates `max_base64_regions` entries (any u32 value).  A
            // region consumes at least 9 bytes (";base64," plus one base64
            // character) and `num_base64_regions` is reset at every
            // metablock end, so no more than `max_metablock_size / 8 + 1`
            // entries can ever be used; capping the allocation avoids
            // committing gigabytes for huge parameter values.
            let cap = max_metablock_size(params) / 8 + 1;
            let n = if params.max_base64_regions < cap { params.max_base64_regions } else { cap };
            hasher.common.base64_regions = Buf::new(m, n);
        }
        let c = &hasher.common;
        let p: &BrotliEncoderParams = params;
        hasher.privat = match c.params.type_ {
            2 => HasherPrivate::H2(H2::new(m, c, p, one_shot, input_size)),
            3 => HasherPrivate::H3(H3::new(m, c, p, one_shot, input_size)),
            4 => HasherPrivate::H4(H4::new(m, c, p, one_shot, input_size)),
            5 => HasherPrivate::H5(H5::new(m, c, p, one_shot, input_size)),
            6 => HasherPrivate::H6(H6::new(m, c, p, one_shot, input_size)),
            40 => HasherPrivate::H40(H40::new(m, c, p, one_shot, input_size)),
            41 => HasherPrivate::H41(H41::new(m, c, p, one_shot, input_size)),
            42 => HasherPrivate::H42(H42::new(m, c, p, one_shot, input_size)),
            54 => HasherPrivate::H54(H54::new(m, c, p, one_shot, input_size)),
            58 if HAVE_SIMD_HASHERS => HasherPrivate::H58(H58::new(m, c, p, one_shot, input_size)),
            59 if HAVE_SIMD_HASHERS => HasherPrivate::H59(H59::new(m, c, p, one_shot, input_size)),
            68 if HAVE_SIMD_HASHERS => HasherPrivate::H68(H68::new(m, c, p, one_shot, input_size)),
            35 => HasherPrivate::H35(H35::new(m, c, p, one_shot, input_size)),
            55 => HasherPrivate::H55(H55::new(m, c, p, one_shot, input_size)),
            65 => HasherPrivate::H65(H65::new(m, c, p, one_shot, input_size)),
            10 => HasherPrivate::H10(H10::new(m, c, p, one_shot, input_size)),
            _ => HasherPrivate::None,
        };
        hasher.reset();
        hasher.common.is_setup_ = true;
    }

    if !hasher.common.is_prepared_ {
        for_all_hashers!(&mut hasher.privat, h => h.prepare(one_shot, input_size, data), _ => {});
        hasher.common.is_prepared_ = true;
    }
}

/// `InitOrStitchToPreviousBlock`.  `data` is the ring buffer (`buffer_`).
pub fn init_or_stitch_to_previous_block(
    m: &MemoryManager,
    hasher: &mut Hasher,
    data: &[u8],
    mask: usize,
    params: &mut BrotliEncoderParams,
    position: usize,
    input_size: usize,
    is_last: bool,
) {
    hasher_setup(m, hasher, params, data, position, input_size, is_last);
    for_all_hashers!(
        &mut hasher.privat,
        h => h.stitch_to_previous_block(input_size, position, data, mask),
        _ => {}
    );
}

/* ----------------------- Compound dictionary search ---------------------- */

/// `FindCompoundDictionaryMatch`.
///
/// NB: when seamless dictionary-ring-buffer copies are implemented, don't
/// forget to add proper guards for non-zero-BROTLI_PARAM_STREAM_OFFSET.
#[inline]
pub fn find_compound_dictionary_match(
    dict: &PreparedDictionary,
    data: &[u8],
    ring_buffer_mask: usize,
    distance_cache: &[i32],
    cur_ix: usize,
    max_length: usize,
    distance_offset: usize,
    max_distance: usize,
    out: &mut HasherSearchResult,
) {
    let cur_ix_masked = cur_ix & ring_buffer_mask;
    let h = (load64(data, cur_ix_masked) & dict.hash_mask()).wrapping_mul(K_PREPARED_DICTIONARY_HASH_MUL64_LONG);
    let key = (h >> dict.hash_shift()) as u32;
    let slot = key & dict.slot_mask();
    let head = dict.heads[key as usize] as u32;
    let chain = dict.slot_offsets[slot as usize].wrapping_add(head) as usize;
    let item: u32 = if head == 0xFFFF { 1 } else { 0 };
    find_compound_dictionary_match_impl::<false>(
        dict,
        chain,
        item,
        data,
        ring_buffer_mask,
        distance_cache,
        cur_ix,
        max_length,
        distance_offset,
        max_distance,
        out,
    );
}

/// Shared body of `FindCompoundDictionaryMatch` (`OPT == false`) and
/// `FindCompoundDictionaryMatchOpt` (`OPT == true`; it lacks the ring buffer
/// end check in the chain loop).
#[inline(always)]
fn find_compound_dictionary_match_impl<const OPT: bool>(
    dict: &PreparedDictionary,
    mut chain: usize,
    mut item: u32,
    data: &[u8],
    ring_buffer_mask: usize,
    distance_cache: &[i32],
    cur_ix: usize,
    max_length: usize,
    distance_offset: usize,
    max_distance: usize,
    out: &mut HasherSearchResult,
) {
    let source_size = dict.source_size as usize;
    let boundary = distance_offset.wrapping_sub(source_size);
    let source = dict.source();
    let items: &[u32] = &dict.items;
    let cur_ix_masked = cur_ix & ring_buffer_mask;
    let mut best_score = out.score;
    let mut best_len = out.len;

    for i in 0..4 {
        let distance = distance_cache[i] as usize;
        if distance <= boundary || distance > distance_offset {
            continue;
        }
        let offset = distance_offset - distance;
        let mut limit = source_size.wrapping_sub(offset);
        limit = if limit > max_length { max_length } else { limit };
        let len = find_match_length(&source[offset..], &data[cur_ix_masked..], limit);
        if len >= 2 {
            let mut score = backward_reference_score_using_last_distance(len);
            if best_score < score {
                if i != 0 {
                    score = score.wrapping_sub(backward_reference_penalty_using_last_distance(i));
                }
                if best_score < score {
                    best_score = score;
                    if len > best_len {
                        best_len = len;
                    }
                    out.len = len;
                    out.len_code_delta = 0;
                    out.distance = distance;
                    out.score = best_score;
                }
            }
        }
    }
    // we require matches of len >4, so increase best_len to 3, so we can
    // compare 4 bytes all the time.
    if best_len < 3 {
        best_len = 3;
    }
    while item == 0 {
        item = items[chain];
        chain += 1;
        let offset = (item & 0x7FFFFFFF) as usize;
        item &= 0x80000000;
        let distance = distance_offset.wrapping_sub(offset);
        let mut limit = source_size.wrapping_sub(offset);
        limit = if limit > max_length { max_length } else { limit };
        if distance > max_distance {
            continue;
        }
        if (!OPT && cur_ix_masked + best_len > ring_buffer_mask)
            || best_len >= limit
            // compare 4 bytes ending at best_len + 1
            || load32(data, cur_ix_masked + best_len - 3) != load32(source, offset + best_len - 3)
        {
            continue;
        }
        {
            let len = find_match_length(&source[offset..], &data[cur_ix_masked..], limit);
            if len >= 4 {
                let score = backward_reference_score(len, distance);
                if best_score < score {
                    best_score = score;
                    best_len = len;
                    out.len = best_len;
                    out.len_code_delta = 0;
                    out.distance = distance;
                    out.score = best_score;
                }
            }
        }
    }
}

/// `FindAllCompoundDictionaryMatches`.  Writes up to `match_limit` matches
/// to `matches` and returns their number.
///
/// NB: when seamless dictionary-ring-buffer copies are implemented, don't
/// forget to add proper guards for non-zero-BROTLI_PARAM_STREAM_OFFSET.
pub fn find_all_compound_dictionary_matches(
    dict: &PreparedDictionary,
    data: &[u8],
    ring_buffer_mask: usize,
    cur_ix: usize,
    min_length: usize,
    max_length: usize,
    distance_offset: usize,
    max_distance: usize,
    matches: &mut [BackwardMatch],
    match_limit: usize,
) -> usize {
    let source_size = dict.source_size as usize;
    let source = dict.source();
    let items: &[u32] = &dict.items;
    let cur_ix_masked = cur_ix & ring_buffer_mask;
    let mut best_len = min_length;
    let h = (load64(data, cur_ix_masked) & dict.hash_mask()).wrapping_mul(K_PREPARED_DICTIONARY_HASH_MUL64_LONG);
    let key = (h >> dict.hash_shift()) as u32;
    let slot = key & dict.slot_mask();
    let head = dict.heads[key as usize] as u32;
    let mut chain = dict.slot_offsets[slot as usize].wrapping_add(head) as usize;
    let mut item: u32 = if head == 0xFFFF { 1 } else { 0 };
    let mut found = 0usize;

    while item == 0 {
        item = items[chain];
        chain += 1;
        let offset = (item & 0x7FFFFFFF) as usize;
        item &= 0x80000000;
        let distance = distance_offset.wrapping_sub(offset);
        let mut limit = source_size.wrapping_sub(offset);
        limit = if limit > max_length { max_length } else { limit };
        if distance > max_distance {
            continue;
        }
        if cur_ix_masked + best_len > ring_buffer_mask
            || best_len >= limit
            || data[cur_ix_masked + best_len] != source[offset + best_len]
        {
            continue;
        }
        let len = find_match_length(&source[offset..], &data[cur_ix_masked..], limit);
        if len > best_len {
            best_len = len;
            matches[found] = BackwardMatch::new(distance, len);
            found += 1;
            if found == match_limit {
                break;
            }
        }
    }
    found
}

/// `LookupCompoundDictionaryMatch`.
#[inline]
pub fn lookup_compound_dictionary_match(
    addon: &CompoundDictionary,
    data: &[u8],
    ring_buffer_mask: usize,
    distance_cache: &[i32],
    cur_ix: usize,
    max_length: usize,
    max_ring_buffer_distance: usize,
    max_distance: usize,
    sr: &mut HasherSearchResult,
) {
    let base_offset = max_ring_buffer_distance.wrapping_add(1).wrapping_add(addon.total_size).wrapping_sub(1);
    for d in 0..addon.num_chunks {
        // Only one prepared dictionary type is currently supported.
        find_compound_dictionary_match(
            addon.chunk(d),
            data,
            ring_buffer_mask,
            distance_cache,
            cur_ix,
            max_length,
            base_offset.wrapping_sub(addon.chunk_offsets[d]),
            max_distance,
            sr,
        );
    }
}

/// `LookupAllCompoundDictionaryMatches`.
pub fn lookup_all_compound_dictionary_matches(
    addon: &CompoundDictionary,
    data: &[u8],
    ring_buffer_mask: usize,
    cur_ix: usize,
    mut min_length: usize,
    max_length: usize,
    max_ring_buffer_distance: usize,
    max_distance: usize,
    matches: &mut [BackwardMatch],
    match_limit: usize,
) -> usize {
    let base_offset = max_ring_buffer_distance.wrapping_add(1).wrapping_add(addon.total_size).wrapping_sub(1);
    let mut total_found = 0usize;
    for d in 0..addon.num_chunks {
        // Only one prepared dictionary type is currently supported.
        total_found += find_all_compound_dictionary_matches(
            addon.chunk(d),
            data,
            ring_buffer_mask,
            cur_ix,
            min_length,
            max_length,
            base_offset.wrapping_sub(addon.chunk_offsets[d]),
            max_distance,
            &mut matches[total_found..],
            match_limit - total_found,
        );
        if total_found == match_limit {
            break;
        }
        if total_found > 0 {
            min_length = matches[total_found - 1].length();
        }
    }
    total_found
}

/// `PreparedDictionaryProbe`: state handed between the prefetch and find
/// calls.  Avoids recalculating the hash and dependent variables.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreparedDictionaryProbe {
    /// Index into `items` (C: `chain` pointer).
    pub chain: usize,
    pub item: u32,
}

/// Probe state for every chunk of a compound dictionary.
pub type PreparedDictionaryProbes = [PreparedDictionaryProbe; SHARED_BROTLI_MAX_COMPOUND_DICTS + 1];

/// `PrefetchCompoundDictionaryMatchOpt` (the prefetch instructions
/// themselves are omitted; only the probe computation is kept).
#[inline]
pub fn prefetch_compound_dictionary_match_opt(
    addon: &CompoundDictionary,
    data: &[u8],
    ring_buffer_mask: usize,
    cur_ix: usize,
    probes: &mut PreparedDictionaryProbes,
) {
    let cur_ix_masked = cur_ix & ring_buffer_mask;
    let bytes = load64(data, cur_ix_masked);
    for d in 0..addon.num_chunks {
        let view = addon.chunk(d);
        let h = (bytes & view.hash_mask()).wrapping_mul(K_PREPARED_DICTIONARY_HASH_MUL64_LONG);
        let key = (h >> view.hash_shift()) as u32;
        let slot = key & view.slot_mask();
        let head = view.heads[key as usize] as u32;
        // Deliberately branchless - if head == 0xFFFF (no items), the chain
        // index is garbage, but it is never dereferenced.
        probes[d].chain = view.slot_offsets[slot as usize].wrapping_add(head) as usize;
        probes[d].item = if head == 0xFFFF { 1 } else { 0 };
    }
}

/// `LookupCompoundDictionaryMatchOpt`.
#[inline]
pub fn lookup_compound_dictionary_match_opt(
    addon: &CompoundDictionary,
    probes: &PreparedDictionaryProbes,
    data: &[u8],
    ring_buffer_mask: usize,
    distance_cache: &[i32],
    cur_ix: usize,
    max_length: usize,
    max_ring_buffer_distance: usize,
    max_distance: usize,
    sr: &mut HasherSearchResult,
) {
    let base_offset = max_ring_buffer_distance.wrapping_add(1).wrapping_add(addon.total_size).wrapping_sub(1);
    for d in 0..addon.num_chunks {
        // `FindCompoundDictionaryMatchOpt`.
        find_compound_dictionary_match_impl::<true>(
            addon.chunk(d),
            probes[d].chain,
            probes[d].item,
            data,
            ring_buffer_mask,
            distance_cache,
            cur_ix,
            max_length,
            base_offset.wrapping_sub(addon.chunk_offsets[d]),
            max_distance,
            sr,
        );
    }
}
