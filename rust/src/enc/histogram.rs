//! Port of `c/enc/histogram.h` / `histogram_inc.h` / `histogram.c`.
//!
//! OWNER: worker "entropy" (may add functions; must keep the types below).

use crate::common::constants::{BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS};

pub const BROTLI_NUM_HISTOGRAM_DISTANCE_SYMBOLS: usize = 544;

/// A simple container for histograms of data in blocks
/// (`HistogramLiteral` / `HistogramCommand` / `HistogramDistance`).
#[derive(Clone, Copy, Debug)]
pub struct Histogram<const N: usize> {
    pub data_: [u32; N],
    pub total_count_: usize,
    pub bit_cost_: f64,
}

pub type HistogramLiteral = Histogram<BROTLI_NUM_LITERAL_SYMBOLS>;
pub type HistogramCommand = Histogram<BROTLI_NUM_COMMAND_SYMBOLS>;
pub type HistogramDistance = Histogram<BROTLI_NUM_HISTOGRAM_DISTANCE_SYMBOLS>;

impl<const N: usize> Default for Histogram<N> {
    /// Zero-initialized (like freshly allocated memory); call `clear()` for
    /// the `HistogramClear` state (`bit_cost_ = HUGE_VAL`).
    fn default() -> Self {
        Histogram { data_: [0; N], total_count_: 0, bit_cost_: 0.0 }
    }
}

impl<const N: usize> Histogram<N> {
    /// `HistogramClear`.
    #[inline]
    pub fn clear(&mut self) {
        self.data_ = [0; N];
        self.total_count_ = 0;
        self.bit_cost_ = f64::INFINITY;
    }

    /// A cleared histogram.
    #[inline]
    pub fn new() -> Self {
        let mut h = Self::default();
        h.clear();
        h
    }

    /// `HistogramAdd`.
    #[inline(always)]
    pub fn add(&mut self, val: usize) {
        self.data_[val] += 1;
        self.total_count_ += 1;
    }

    /// `HistogramAddVector` (for u8 data).
    #[inline]
    pub fn add_vector_u8(&mut self, p: &[u8]) {
        self.total_count_ += p.len();
        for &v in p {
            self.data_[v as usize] += 1;
        }
    }

    /// `HistogramAddVector` (for u16 data).
    #[inline]
    pub fn add_vector_u16(&mut self, p: &[u16]) {
        self.total_count_ += p.len();
        for &v in p {
            self.data_[v as usize] += 1;
        }
    }

    /// `HistogramAddHistogram`.
    #[inline]
    pub fn add_histogram(&mut self, v: &Self) {
        self.total_count_ += v.total_count_;
        for i in 0..N {
            self.data_[i] += v.data_[i];
        }
    }

    /// `HistogramDataSize`.
    #[inline]
    pub const fn data_size() -> usize {
        N
    }
}

/// `ClearHistograms`.
#[inline]
pub fn clear_histograms<const N: usize>(array: &mut [Histogram<N>]) {
    for h in array.iter_mut() {
        h.clear();
    }
}
