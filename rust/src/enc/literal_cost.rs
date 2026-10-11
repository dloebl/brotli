//! Port of `c/enc/literal_cost.c`: literal cost model to allow backward
//! reference replacement to be efficient.

use super::fast_log::fast_log2;
use super::utf8_util::{brotli_is_mostly_utf8, K_MIN_UTF8_RATIO};

#[inline]
fn utf8_position(last: usize, c: usize, clamp: usize) -> usize {
    if c < 128 {
        0 // Next one is the 'Byte 1' again.
    } else if c >= 192 {
        // Next one is the 'Byte 2' of utf-8 encoding.
        1.min(clamp)
    } else {
        // Let's decide over the last byte if this ends the sequence.
        if last < 0xE0 {
            0 // Completed two or three byte coding.
        } else {
            // Next one is the 'Byte 3' of utf-8 encoding.
            2.min(clamp)
        }
    }
}

fn decide_multi_byte_stats_level(pos: usize, len: usize, mask: usize, data: &[u8]) -> usize {
    let mut counts = [0usize; 3];
    let mut max_utf8 = 1; // should be 2, but 1 compresses better.
    let mut last_c = 0usize;
    for i in 0..len {
        let c = data[(pos + i) & mask] as usize;
        counts[utf8_position(last_c, c, 2)] += 1;
        last_c = c;
    }
    if counts[2] < 500 {
        max_utf8 = 1;
    }
    if counts[1] + counts[2] < 25 {
        max_utf8 = 0;
    }
    max_utf8
}

fn estimate_bit_costs_for_literals_utf8(pos: usize, len: usize, mask: usize, data: &[u8], histogram: &mut [usize], cost: &mut [f32]) {
    // max_utf8 is 0 (normal ASCII single byte modeling),
    // 1 (for 2-byte UTF-8 modeling), or 2 (for 3-byte UTF-8 modeling).
    let max_utf8 = decide_multi_byte_stats_level(pos, len, mask, data);
    let window_half: usize = 495;
    let in_window = window_half.min(len);
    let mut in_window_utf8 = [0usize; 3];
    for h in histogram[..3 * 256].iter_mut() {
        *h = 0;
    }
    {
        // Bootstrap histograms.
        let mut last_c = 0usize;
        let mut utf8_pos = 0usize;
        for i in 0..in_window {
            let c = data[(pos + i) & mask] as usize;
            histogram[256 * utf8_pos + c] += 1;
            in_window_utf8[utf8_pos] += 1;
            utf8_pos = utf8_position(last_c, c, max_utf8);
            last_c = c;
        }
    }
    // Compute bit costs with sliding window.
    for i in 0..len {
        if i >= window_half {
            // Remove a byte in the past.
            let c = if i < window_half + 1 { 0 } else { data[(pos + i - window_half - 1) & mask] as usize };
            let last_c = if i < window_half + 2 { 0 } else { data[(pos + i - window_half - 2) & mask] as usize };
            let utf8_pos2 = utf8_position(last_c, c, max_utf8);
            histogram[256 * utf8_pos2 + data[(pos + i - window_half) & mask] as usize] -= 1;
            in_window_utf8[utf8_pos2] -= 1;
        }
        if i + window_half < len {
            // Add a byte in the future.
            let c = data[(pos + i + window_half - 1) & mask] as usize;
            let last_c = data[(pos + i + window_half - 2) & mask] as usize;
            let utf8_pos2 = utf8_position(last_c, c, max_utf8);
            histogram[256 * utf8_pos2 + data[(pos + i + window_half) & mask] as usize] += 1;
            in_window_utf8[utf8_pos2] += 1;
        }
        {
            let c = if i < 1 { 0 } else { data[(pos + i - 1) & mask] as usize };
            let last_c = if i < 2 { 0 } else { data[(pos + i - 2) & mask] as usize };
            let utf8_pos = utf8_position(last_c, c, max_utf8);
            let masked_pos = (pos + i) & mask;
            let mut histo = histogram[256 * utf8_pos + data[masked_pos] as usize];
            const PROLOGUE_LENGTH: usize = 2000;
            const MULTIPLIER: f64 = 0.35 / 2000.0;
            if histo == 0 {
                histo = 1;
            }
            let mut lit_cost = fast_log2(in_window_utf8[utf8_pos]) - fast_log2(histo);
            lit_cost += 0.02905;
            if lit_cost < 1.0 {
                lit_cost *= 0.5;
                lit_cost += 0.5;
            }
            // Make the first bytes more expensive -- seems to help, not sure
            // why.
            if i < PROLOGUE_LENGTH {
                lit_cost += 0.35 + MULTIPLIER * (i as f64);
            }
            cost[i] = lit_cost as f32;
        }
    }
}

/// `BrotliEstimateBitCostsForLiterals`.
///
/// Estimates how many bits the literals in the interval `[pos, pos + len)`
/// of the ring buffer `(data, mask)` will take entropy coded.  Writes `len`
/// values to `cost`.  `histogram` is scratch space of at least `3 * 256`
/// entries.
pub fn brotli_estimate_bit_costs_for_literals(pos: usize, len: usize, mask: usize, data: &[u8], histogram: &mut [usize], cost: &mut [f32]) {
    if brotli_is_mostly_utf8(data, pos, mask, len, K_MIN_UTF8_RATIO) {
        estimate_bit_costs_for_literals_utf8(pos, len, mask, data, histogram, cost);
    } else {
        let window_half: usize = 2000;
        let mut in_window = window_half.min(len);
        for h in histogram[..256].iter_mut() {
            *h = 0;
        }
        // Bootstrap histogram.
        for i in 0..in_window {
            histogram[data[(pos + i) & mask] as usize] += 1;
        }
        // Compute bit costs with sliding window.
        for i in 0..len {
            if i >= window_half {
                // Remove a byte in the past.
                histogram[data[(pos + i - window_half) & mask] as usize] -= 1;
                in_window -= 1;
            }
            if i + window_half < len {
                // Add a byte in the future.
                histogram[data[(pos + i + window_half) & mask] as usize] += 1;
                in_window += 1;
            }
            let mut histo = histogram[data[(pos + i) & mask] as usize];
            if histo == 0 {
                histo = 1;
            }
            let mut lit_cost = fast_log2(in_window) - fast_log2(histo);
            lit_cost += 0.029;
            if lit_cost < 1.0 {
                lit_cost *= 0.5;
                lit_cost += 0.5;
            }
            cost[i] = lit_cost as f32;
        }
    }
}
