//! Port of `c/enc/params.h`: parameters for the Brotli encoder with chosen
//! quality levels.

use super::encoder_dict::SharedEncoderDictionary;

/// `BrotliEncoderMode` values.
pub const BROTLI_MODE_GENERIC: u32 = 0;
pub const BROTLI_MODE_TEXT: u32 = 1;
pub const BROTLI_MODE_FONT: u32 = 2;

/// `BrotliEncoderBase64Mode` values.
pub const BROTLI_BASE64_MODE_DISABLED: i32 = 0;
pub const BROTLI_BASE64_MODE_ENABLED: i32 = 1;
pub const BROTLI_DEFAULT_BASE64_MODE: i32 = BROTLI_BASE64_MODE_DISABLED;
pub const BROTLI_DEFAULT_MAX_BASE64_REGIONS: usize = 16;
pub const BROTLI_DEFAULT_MIN_BASE64_REGION_LEN: usize = 2048;

/// `BrotliEncoderSimdHasher` values.
pub const BROTLI_SIMD_HASHER_DEFAULT: u32 = 0;
pub const BROTLI_SIMD_HASHER_ENABLE: u32 = 1;
pub const BROTLI_SIMD_HASHER_DISABLE: u32 = 2;
pub const BROTLI_DEFAULT_SIMD_HASHER: u32 = BROTLI_SIMD_HASHER_DEFAULT;

/// `BrotliHasherParams`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrotliHasherParams {
    pub type_: i32,
    pub bucket_bits: i32,
    pub block_bits: i32,
    pub num_last_distances_to_check: i32,
}

/// `BrotliDistanceParams`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BrotliDistanceParams {
    pub distance_postfix_bits: u32,
    pub num_direct_distance_codes: u32,
    pub alphabet_size_max: u32,
    pub alphabet_size_limit: u32,
    pub max_distance: usize,
}

/// `BrotliEncoderParams`.
#[derive(Clone, Copy)]
pub struct BrotliEncoderParams {
    /// `BrotliEncoderMode` (raw value, like the C enum may hold any value).
    pub mode: u32,
    pub quality: i32,
    pub lgwin: i32,
    pub lgblock: i32,
    pub stream_offset: usize,
    pub size_hint: usize,
    pub disable_literal_context_modeling: bool,
    pub large_window: bool,
    pub hasher: BrotliHasherParams,
    pub dist: BrotliDistanceParams,
    pub dictionary: SharedEncoderDictionary,
    pub base64_mode: i32,
    pub max_base64_regions: usize,
    pub min_base64_region_len: usize,
    /// `BrotliEncoderSimdHasher` (validated to be <= 2).
    pub simd_hasher: u32,
    pub hasher_opt: bool,
}

/// `Base64Region` (declared in `hash.h` in C).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Base64Region {
    pub start_literal_pos: usize,
    pub length: usize,
}
/// `kIsBase64` (backward_references.c): 1 for base64 alphabet bytes
/// (`A-Z a-z 0-9 + /`).
pub static K_IS_BASE64: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
