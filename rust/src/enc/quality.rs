//! Port of `c/enc/quality.h`: constants and formulas that affect speed-ratio
//! trade-offs and thus define quality levels.

use super::params::{BrotliEncoderParams, BrotliHasherParams, BROTLI_SIMD_HASHER_DISABLE, BROTLI_SIMD_HASHER_ENABLE};
use crate::common::constants::{
    BROTLI_LARGE_MAX_WINDOW_BITS, BROTLI_MAX_INPUT_BLOCK_BITS, BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS,
    BROTLI_MIN_INPUT_BLOCK_BITS, BROTLI_MIN_QUALITY, BROTLI_MIN_WINDOW_BITS,
};

pub const FAST_ONE_PASS_COMPRESSION_QUALITY: i32 = 0;
pub const FAST_TWO_PASS_COMPRESSION_QUALITY: i32 = 1;
pub const ZOPFLIFICATION_QUALITY: i32 = 10;
pub const HQ_ZOPFLIFICATION_QUALITY: i32 = 11;

pub const MAX_QUALITY_FOR_STATIC_ENTROPY_CODES: i32 = 2;
pub const MIN_QUALITY_FOR_BLOCK_SPLIT: i32 = 4;
pub const MIN_QUALITY_FOR_NONZERO_DISTANCE_PARAMS: i32 = 4;
pub const MIN_QUALITY_FOR_OPTIMIZE_HISTOGRAMS: i32 = 4;
pub const MIN_QUALITY_FOR_EXTENSIVE_REFERENCE_SEARCH: i32 = 5;
pub const MIN_QUALITY_FOR_CONTEXT_MODELING: i32 = 5;
pub const MIN_QUALITY_FOR_HQ_CONTEXT_MODELING: i32 = 7;
pub const MIN_QUALITY_FOR_HQ_BLOCK_SPLITTING: i32 = 10;

/// For quality below MIN_QUALITY_FOR_BLOCK_SPLIT there is no block
/// splitting, so we buffer at most this much literals and commands.
pub const MAX_NUM_DELAYED_SYMBOLS: usize = 0x2FFF;

/// Returns hash-table size for quality levels 0 and 1.
#[inline]
pub fn max_hash_table_size(quality: i32) -> usize {
    if quality == FAST_ONE_PASS_COMPRESSION_QUALITY {
        1 << 15
    } else {
        1 << 17
    }
}

/// The maximum length for which the zopflification uses distinct distances.
pub const MAX_ZOPFLI_LEN_QUALITY_10: usize = 150;
pub const MAX_ZOPFLI_LEN_QUALITY_11: usize = 325;

/// Do not thoroughly search when a long copy is found.
pub const BROTLI_LONG_COPY_QUICK_STEP: usize = 16384;

#[inline]
pub fn max_zopfli_len(params: &BrotliEncoderParams) -> usize {
    if params.quality <= 10 {
        MAX_ZOPFLI_LEN_QUALITY_10
    } else {
        MAX_ZOPFLI_LEN_QUALITY_11
    }
}

/// Number of best candidates to evaluate to expand Zopfli chain.
#[inline]
pub fn max_zopfli_candidates(params: &BrotliEncoderParams) -> usize {
    if params.quality <= 10 {
        1
    } else {
        5
    }
}

/// `SanitizeParams`.
pub fn sanitize_params(params: &mut BrotliEncoderParams) {
    params.quality = BROTLI_MAX_QUALITY.min(BROTLI_MIN_QUALITY.max(params.quality));
    if params.quality <= MAX_QUALITY_FOR_STATIC_ENTROPY_CODES {
        params.large_window = false;
    }
    if params.lgwin < BROTLI_MIN_WINDOW_BITS {
        params.lgwin = BROTLI_MIN_WINDOW_BITS;
    } else {
        let max_lgwin = if params.large_window { BROTLI_LARGE_MAX_WINDOW_BITS } else { BROTLI_MAX_WINDOW_BITS };
        if params.lgwin > max_lgwin {
            params.lgwin = max_lgwin;
        }
    }
}

/// `ComputeLgBlock`: returns optimized lg_block value.
pub fn compute_lg_block(params: &BrotliEncoderParams) -> i32 {
    let mut lgblock = params.lgblock;
    if params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY || params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY {
        lgblock = params.lgwin;
    } else if params.quality < MIN_QUALITY_FOR_BLOCK_SPLIT {
        lgblock = 14;
    } else if lgblock == 0 {
        lgblock = 16;
        if params.quality >= 9 && params.lgwin > lgblock {
            lgblock = 18.min(params.lgwin);
        }
    } else {
        lgblock = BROTLI_MAX_INPUT_BLOCK_BITS.min(BROTLI_MIN_INPUT_BLOCK_BITS.max(lgblock));
    }
    lgblock
}

/// `ComputeRbBits`: log2 of the size of main ring buffer area.
#[inline]
pub fn compute_rb_bits(params: &BrotliEncoderParams) -> i32 {
    1 + params.lgwin.max(params.lgblock)
}

/// `MaxMetablockSize`.
#[inline]
pub fn max_metablock_size(params: &BrotliEncoderParams) -> usize {
    let bits = compute_rb_bits(params).min(BROTLI_MAX_INPUT_BLOCK_BITS);
    1usize << bits
}

/// `LiteralSpreeLengthForSparseSearch`.
#[inline]
pub fn literal_spree_length_for_sparse_search(params: &BrotliEncoderParams) -> usize {
    if params.quality < 9 {
        64
    } else {
        512
    }
}

/// `BROTLI_MAX_SIMD_QUALITY` / `BROTLI_MAX_RECOMMENDED_SIMD_QUALITY` from
/// `platform.h`: defined iff `BROTLI_TZCNT64` is available, i.e. on 64-bit
/// targets.  MSVC x64 recommends 7, everything else 6.
#[cfg(target_pointer_width = "64")]
pub const BROTLI_MAX_SIMD_QUALITY: Option<i32> = Some(7);
#[cfg(not(target_pointer_width = "64"))]
pub const BROTLI_MAX_SIMD_QUALITY: Option<i32> = None;

#[cfg(all(target_pointer_width = "64", target_env = "msvc", target_arch = "x86_64"))]
pub const BROTLI_MAX_RECOMMENDED_SIMD_QUALITY: i32 = 7;
#[cfg(not(all(target_pointer_width = "64", target_env = "msvc", target_arch = "x86_64")))]
pub const BROTLI_MAX_RECOMMENDED_SIMD_QUALITY: i32 = 6;

/// Whether the SIMD hashers (H58, H59, H68) are compiled in.
pub const HAVE_SIMD_HASHERS: bool = BROTLI_MAX_SIMD_QUALITY.is_some();

/// `ShouldUseSimdHasher`.
pub fn should_use_simd_hasher(params: &BrotliEncoderParams) -> bool {
    let max_simd = match BROTLI_MAX_SIMD_QUALITY {
        Some(q) => q,
        None => return false,
    };
    if params.simd_hasher == BROTLI_SIMD_HASHER_DISABLE {
        return false;
    }
    let mut max_quality = BROTLI_MAX_RECOMMENDED_SIMD_QUALITY;
    if params.simd_hasher == BROTLI_SIMD_HASHER_ENABLE {
        max_quality = max_simd;
    }
    params.quality <= max_quality
}

/// `ChooseHasher`.
pub fn choose_hasher(params: &BrotliEncoderParams, hparams: &mut BrotliHasherParams) {
    if params.quality > 9 {
        hparams.type_ = 10;
    } else if params.quality == 4 && params.size_hint >= (1 << 20) {
        hparams.type_ = 54;
    } else if params.quality < 5 {
        hparams.type_ = params.quality;
    } else if params.lgwin <= 16 {
        hparams.type_ = if params.quality < 7 {
            40
        } else if params.quality < 9 {
            41
        } else {
            42
        };
    } else if params.size_hint >= (1 << 20) && params.lgwin >= 19 {
        hparams.type_ = if HAVE_SIMD_HASHERS && should_use_simd_hasher(params) { 68 } else { 6 };
        hparams.block_bits = params.quality - 1;
        hparams.bucket_bits = 15;
        hparams.num_last_distances_to_check = if params.quality < 7 {
            4
        } else if params.quality < 9 {
            10
        } else {
            16
        };
    } else {
        hparams.type_ = if HAVE_SIMD_HASHERS && should_use_simd_hasher(params) {
            if params.hasher_opt {
                59
            } else {
                58
            }
        } else {
            5
        };
        hparams.block_bits = params.quality - 1;
        hparams.bucket_bits = if params.quality < 7 { 14 } else { 15 };
        hparams.num_last_distances_to_check = if params.quality < 7 {
            4
        } else if params.quality < 9 {
            10
        } else {
            16
        };
    }

    if params.lgwin > 24 {
        // Different hashers for large window brotli: not for qualities <= 2,
        // these are too fast for large window. Not for qualities >= 10: their
        // hasher already works well with large window. So the changes are:
        //   H3 --> H35: for quality 3.
        //   H54 --> H55: for quality 4 with size hint > 1MB
        //   H6/H68 --> H65: for qualities 5, 6, 7, 8, 9.
        if hparams.type_ == 3 {
            hparams.type_ = 35;
        }
        if hparams.type_ == 54 {
            hparams.type_ = 55;
        }
        if hparams.type_ == 6 || hparams.type_ == 68 {
            hparams.type_ = 65;
        }
    }
}
