//! Port of `c/enc/hash.h` and all hasher templates (`hash_*_inc.h`,
//! `hash_base.h`, `matching_tag_mask.h`): a (forgetful) hash table to the
//! data seen by the compressor, to help create backward references to
//! previous data.
//!
//! OWNER: worker "hashers".  Hasher implementations may live in submodules
//! under `src/enc/hash/`.

use super::memory::{Buf, MemoryManager};
use super::params::{Base64Region, BrotliEncoderParams, BrotliHasherParams};

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

/// `Hasher`: common part plus the type-specific state of the selected
/// hasher (H2, H3, H4, H5, H6, H35, H40, H41, H42, H54, H55, H58, H59, H65,
/// H68, H10).
pub struct Hasher {
    pub common: HasherCommon,
    // Type specific state goes here (owned by the "hashers" worker).
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// `HasherInit`.  (`DestroyHasher` == drop.)
    pub fn new() -> Self {
        Hasher { common: HasherCommon::default() }
    }

    /// `HasherReset`.
    #[inline]
    pub fn reset(&mut self) {
        self.common.is_prepared_ = false;
    }
}

/// `HasherSize`: fills `alloc_size` with the byte sizes of the (up to 4)
/// allocations the C hasher of `params.hasher.type_` would make.
pub fn hasher_size(params: &BrotliEncoderParams, one_shot: bool, input_size: usize, alloc_size: &mut [usize; 4]) {
    let _ = (params, one_shot, input_size, alloc_size);
    todo!("hash::hasher_size")
}

/// `HasherSetup`.
pub fn hasher_setup(m: &MemoryManager, hasher: &mut Hasher, params: &mut BrotliEncoderParams, data: &[u8], position: usize, input_size: usize, is_last: bool) {
    let _ = (m, hasher, params, data, position, input_size, is_last);
    todo!("hash::hasher_setup")
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
    let _ = (m, hasher, data, mask, params, position, input_size, is_last);
    todo!("hash::init_or_stitch_to_previous_block")
}
