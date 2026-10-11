//! Port of `c/enc/histogram.h` / `histogram_inc.h` / `histogram.c`.
//!
//! OWNER: worker "entropy" (may add functions; must keep the types below).

use super::block_splitter::BlockSplit;
use super::command::Command;
use crate::common::constants::{
    BROTLI_DISTANCE_CONTEXT_BITS, BROTLI_LITERAL_CONTEXT_BITS, BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_LITERAL_SYMBOLS,
};
use crate::common::context::{brotli_context, brotli_context_lut, ContextType};

pub const BROTLI_NUM_HISTOGRAM_DISTANCE_SYMBOLS: usize = 544;

/// A simple container for histograms of data in blocks
/// (`HistogramLiteral` / `HistogramCommand` / `HistogramDistance`).
/// `#[repr(C)]`: same layout / size as the C structs (the size is used by
/// `BrotliEncoderEstimatePeakMemoryUsage`).
#[repr(C)]
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

/// `BlockSplitIterator`.
struct BlockSplitIterator<'a> {
    split_: &'a BlockSplit,
    idx_: usize,
    type_: usize,
    length_: usize,
}

impl<'a> BlockSplitIterator<'a> {
    /// `InitBlockSplitIterator`.
    fn new(split: &'a BlockSplit) -> Self {
        BlockSplitIterator {
            split_: split,
            idx_: 0,
            type_: 0,
            length_: if split.lengths.is_empty() { 0 } else { split.lengths[0] as usize },
        }
    }

    /// `BlockSplitIteratorNext`.
    #[inline(always)]
    fn next(&mut self) {
        if self.length_ == 0 {
            self.idx_ += 1;
            self.type_ = self.split_.types[self.idx_] as usize;
            self.length_ = self.split_.lengths[self.idx_] as usize;
        }
        self.length_ = self.length_.wrapping_sub(1);
    }
}

/// `BrotliBuildHistogramsWithContext`: build per-context histograms of
/// literals, commands and distance codes.  `context_modes` is `None` for C
/// `NULL`.  `ringbuffer` is addressed with `& mask`.
pub fn brotli_build_histograms_with_context(
    cmds: &[Command],
    literal_split: &BlockSplit,
    insert_and_copy_split: &BlockSplit,
    dist_split: &BlockSplit,
    ringbuffer: &[u8],
    start_pos: usize,
    mask: usize,
    mut prev_byte: u8,
    mut prev_byte2: u8,
    context_modes: Option<&[ContextType]>,
    literal_histograms: &mut [HistogramLiteral],
    insert_and_copy_histograms: &mut [HistogramCommand],
    copy_dist_histograms: &mut [HistogramDistance],
) {
    let mut pos = start_pos;
    let mut literal_it = BlockSplitIterator::new(literal_split);
    let mut insert_and_copy_it = BlockSplitIterator::new(insert_and_copy_split);
    let mut dist_it = BlockSplitIterator::new(dist_split);
    for cmd in cmds.iter() {
        insert_and_copy_it.next();
        insert_and_copy_histograms[insert_and_copy_it.type_].add(cmd.cmd_prefix_ as usize);
        let mut j = cmd.insert_len_ as usize;
        while j != 0 {
            literal_it.next();
            let mut context = literal_it.type_;
            if let Some(modes) = context_modes {
                let lut = brotli_context_lut(modes[context]);
                context = (context << BROTLI_LITERAL_CONTEXT_BITS) + brotli_context(prev_byte, prev_byte2, lut) as usize;
            }
            let lit = ringbuffer[pos & mask];
            literal_histograms[context].add(lit as usize);
            prev_byte2 = prev_byte;
            prev_byte = lit;
            pos = pos.wrapping_add(1);
            j -= 1;
        }
        let copy_len = cmd.copy_len() as usize;
        pos = pos.wrapping_add(copy_len);
        if copy_len != 0 {
            prev_byte2 = ringbuffer[pos.wrapping_sub(2) & mask];
            prev_byte = ringbuffer[pos.wrapping_sub(1) & mask];
            if cmd.cmd_prefix_ >= 128 {
                dist_it.next();
                let context = (dist_it.type_ << BROTLI_DISTANCE_CONTEXT_BITS) + cmd.distance_context() as usize;
                copy_dist_histograms[context].add((cmd.dist_prefix_ & 0x3FF) as usize);
            }
        }
    }
}
