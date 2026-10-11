//! Port of `c/common/context.h` / `context.c`: literal context modeling.

pub use super::tables::CONTEXT_LOOKUP_TABLE;

/// `ContextType`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ContextType {
    #[default]
    Lsb6 = 0,
    Msb6 = 1,
    Utf8 = 2,
    Signed = 3,
}

pub const CONTEXT_LSB6: ContextType = ContextType::Lsb6;
pub const CONTEXT_MSB6: ContextType = ContextType::Msb6;
pub const CONTEXT_UTF8: ContextType = ContextType::Utf8;
pub const CONTEXT_SIGNED: ContextType = ContextType::Signed;

impl ContextType {
    /// Converts the low 2 bits of `v` into a context type.
    #[inline]
    pub fn from_u32(v: u32) -> ContextType {
        match v & 3 {
            0 => ContextType::Lsb6,
            1 => ContextType::Msb6,
            2 => ContextType::Utf8,
            _ => ContextType::Signed,
        }
    }
}

/// `ContextLut`: a 512-entry slice of [`CONTEXT_LOOKUP_TABLE`]
/// (`[0..256)` indexed by p1, `[256..512)` indexed by p2).
pub type ContextLut = &'static [u8];

/// `BROTLI_CONTEXT_LUT(MODE)`.
#[inline]
pub fn brotli_context_lut(mode: ContextType) -> ContextLut {
    let off = (mode as usize) << 9;
    &CONTEXT_LOOKUP_TABLE[off..off + 512]
}

/// `BROTLI_CONTEXT(P1, P2, LUT)`.
#[inline(always)]
pub fn brotli_context(p1: u8, p2: u8, lut: ContextLut) -> u8 {
    lut[p1 as usize] | lut[256 + p2 as usize]
}
