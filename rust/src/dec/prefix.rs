//! Port of `c/dec/prefix.h` / `prefix.c` / `prefix_inc.h`: lookup tables to
//! map prefix codes to value ranges.  This is used during decoding of the
//! block lengths, literal insertion lengths and copy lengths.
//!
//! The default C build uses `BROTLI_STATIC_INIT_NONE`: `kCmdLut` is a
//! compile-time table (generated into `tables.rs` from `prefix_inc.h`).

/// `CmdLutElement`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CmdLutElement {
    pub insert_len_extra_bits: u8,
    pub copy_len_extra_bits: u8,
    pub distance_code: i8,
    pub context: u8,
    pub insert_len_offset: u16,
    pub copy_len_offset: u16,
}

/// `kCmdLut`.
pub use super::tables::K_CMD_LUT;

/// `BrotliDecoderEnsureStaticInit` (static_init.c): with
/// `BROTLI_STATIC_INIT_NONE` there is nothing to initialize.
#[inline(always)]
pub fn brotli_decoder_ensure_static_init() -> bool {
    true
}
