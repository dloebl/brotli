//! Port of `c/enc/bit_cost.h` / `bit_cost.c` / `bit_cost_inc.h`: functions
//! to estimate the bit cost of Huffman trees.
//!
//! OWNER: worker "entropy".

use super::fast_log::fast_log2;
use super::histogram::{Histogram, HistogramCommand, HistogramDistance, HistogramLiteral};
use crate::common::constants::{BROTLI_CODE_LENGTH_CODES, BROTLI_REPEAT_ZERO_CODE_LENGTH};

/// `BrotliBitsEntropy`.  Uses the first `size` entries of `population`.
pub fn brotli_bits_entropy(population: &[u32], size: usize) -> f64 {
    let mut sum: usize = 0;
    let mut retval: f64 = 0.0;
    // The C code processes two elements per iteration (with a jump into the
    // middle of the loop for odd sizes); the order of the operations is
    // simply element by element.
    for &v in population[..size].iter() {
        let p = v as usize;
        sum = sum.wrapping_add(p);
        retval -= (p as f64) * fast_log2(p);
    }
    if sum != 0 {
        retval += (sum as f64) * fast_log2(sum);
    }

    if retval < sum as f64 {
        // At least one bit per literal is needed.
        retval = sum as f64;
    }

    retval
}

/// `BrotliPopulationCost{Literal,Command,Distance}` (template
/// `bit_cost_inc.h`).
pub fn brotli_population_cost<const N: usize>(histogram: &Histogram<N>) -> f64 {
    const K_ONE_SYMBOL_HISTOGRAM_COST: f64 = 12.0;
    const K_TWO_SYMBOL_HISTOGRAM_COST: f64 = 20.0;
    const K_THREE_SYMBOL_HISTOGRAM_COST: f64 = 28.0;
    const K_FOUR_SYMBOL_HISTOGRAM_COST: f64 = 37.0;
    let data_size = N;
    let mut count: i32 = 0;
    let mut s = [0usize; 5];
    let mut bits: f64 = 0.0;
    if histogram.total_count_ == 0 {
        return K_ONE_SYMBOL_HISTOGRAM_COST;
    }
    for i in 0..data_size {
        if histogram.data_[i] > 0 {
            s[count as usize] = i;
            count += 1;
            if count > 4 {
                break;
            }
        }
    }
    if count == 1 {
        return K_ONE_SYMBOL_HISTOGRAM_COST;
    }
    if count == 2 {
        return K_TWO_SYMBOL_HISTOGRAM_COST + histogram.total_count_ as f64;
    }
    if count == 3 {
        let histo0 = histogram.data_[s[0]];
        let histo1 = histogram.data_[s[1]];
        let histo2 = histogram.data_[s[2]];
        let histomax = core::cmp::max(histo0, core::cmp::max(histo1, histo2));
        // C: double + uint32_t - uint32_t, evaluated left to right in double.
        return K_THREE_SYMBOL_HISTOGRAM_COST + 2u32.wrapping_mul(histo0.wrapping_add(histo1).wrapping_add(histo2)) as f64
            - histomax as f64;
    }
    if count == 4 {
        let mut histo = [0u32; 4];
        for i in 0..4 {
            histo[i] = histogram.data_[s[i]];
        }
        // Sort
        for i in 0..4 {
            for j in (i + 1)..4 {
                if histo[j] > histo[i] {
                    histo.swap(j, i);
                }
            }
        }
        let h23 = histo[2].wrapping_add(histo[3]);
        let histomax = core::cmp::max(h23, histo[0]);
        return K_FOUR_SYMBOL_HISTOGRAM_COST + 3u32.wrapping_mul(h23) as f64
            + 2u32.wrapping_mul(histo[0].wrapping_add(histo[1])) as f64
            - histomax as f64;
    }

    {
        // In this loop we compute the entropy of the histogram and
        // simultaneously build a simplified histogram of the code length
        // codes where we use the zero repeat code 17, but we don't use the
        // non-zero repeat code 16.
        let mut max_depth: usize = 1;
        let mut depth_histo = [0u32; BROTLI_CODE_LENGTH_CODES];
        let log2total = fast_log2(histogram.total_count_);
        let mut i = 0usize;
        while i < data_size {
            if histogram.data_[i] > 0 {
                // Compute -log2(P(symbol)) = -log2(count(symbol)/total_count) =
                //                          = log2(total_count) - log2(count(symbol))
                let log2p = log2total - fast_log2(histogram.data_[i] as usize);
                // Approximate the bit depth by round(-log2(P(symbol)))
                let mut depth = (log2p + 0.5) as usize;
                bits += histogram.data_[i] as f64 * log2p;
                if depth > 15 {
                    depth = 15;
                }
                if depth > max_depth {
                    max_depth = depth;
                }
                depth_histo[depth] += 1;
                i += 1;
            } else {
                // Compute the run length of zeros and add the appropriate
                // number of 0 and 17 code length codes to the code length code
                // histogram.
                let mut reps: u32 = 1;
                let mut k = i + 1;
                while k < data_size && histogram.data_[k] == 0 {
                    reps += 1;
                    k += 1;
                }
                i += reps as usize;
                if i == data_size {
                    // Don't add any cost for the last zero run, since these
                    // are encoded only implicitly.
                    break;
                }
                if reps < 3 {
                    depth_histo[0] += reps;
                } else {
                    reps -= 2;
                    while reps > 0 {
                        depth_histo[BROTLI_REPEAT_ZERO_CODE_LENGTH as usize] += 1;
                        // Add the 3 extra bits for the 17 code length code.
                        bits += 3.0;
                        reps >>= 3;
                    }
                }
            }
        }
        // Add the estimated encoding cost of the code length code histogram.
        bits += (18 + 2 * max_depth) as f64;
        // Add the entropy of the code length code histogram.
        bits += brotli_bits_entropy(&depth_histo, BROTLI_CODE_LENGTH_CODES);
    }
    bits
}

/// `BrotliPopulationCostLiteral`.
#[inline]
pub fn brotli_population_cost_literal(histogram: &HistogramLiteral) -> f64 {
    brotli_population_cost(histogram)
}

/// `BrotliPopulationCostCommand`.
#[inline]
pub fn brotli_population_cost_command(histogram: &HistogramCommand) -> f64 {
    brotli_population_cost(histogram)
}

/// `BrotliPopulationCostDistance`.
#[inline]
pub fn brotli_population_cost_distance(histogram: &HistogramDistance) -> f64 {
    brotli_population_cost(histogram)
}
