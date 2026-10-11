//! Port of `c/enc/fast_log.h` / `fast_log.c`.

pub use crate::common::tables::LOG2_TABLE as K_BROTLI_LOG2_TABLE;

pub const BROTLI_LOG2_TABLE_SIZE: usize = 256;

/// `Log2FloorNonZero`: floor(log2(n)) for n > 0 (uses the low 32 bits, like
/// the C `BROTLI_BSR32` path).
#[inline(always)]
pub fn log2_floor_non_zero(n: usize) -> u32 {
    31 ^ (n as u32).leading_zeros()
}

pub const LOG_2_INV: f64 = 1.4426950408889634;

/// `FastLog2`: faster logarithm for small integers, with log2(0) == 0.
#[inline(always)]
pub fn fast_log2(v: usize) -> f64 {
    if v < BROTLI_LOG2_TABLE_SIZE {
        return K_BROTLI_LOG2_TABLE[v];
    }
    // SAFETY: plain libm call (the C library uses the same `log2`).
    unsafe { log2(v as f64) }
}

extern "C" {
    /// libm `log2` (bit-identical to what the C implementation uses).
    fn log2(x: f64) -> f64;
}
