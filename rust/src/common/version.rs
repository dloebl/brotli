//! Port of `c/common/version.h`.

pub const BROTLI_VERSION_MAJOR: u32 = 1;
pub const BROTLI_VERSION_MINOR: u32 = 2;
pub const BROTLI_VERSION_PATCH: u32 = 0;

/// `BROTLI_MAKE_HEX_VERSION(A, B, C)`
pub const fn brotli_make_hex_version(a: u32, b: u32, c: u32) -> u32 {
    (a << 24) | (b << 12) | c
}

/// `BROTLI_VERSION`: 0xMMMNNNPPP.
pub const BROTLI_VERSION: u32 = brotli_make_hex_version(BROTLI_VERSION_MAJOR, BROTLI_VERSION_MINOR, BROTLI_VERSION_PATCH);

/// ABI version information (libtool style).
pub const BROTLI_ABI_CURRENT: u32 = 3;
pub const BROTLI_ABI_REVISION: u32 = 0;
pub const BROTLI_ABI_AGE: u32 = 2;
