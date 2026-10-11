//! Port of `c/enc/cluster.h` / `cluster.c` / `cluster_inc.h`: functions for
//! clustering similar histograms together.
//!
//! OWNER: worker "entropy".
//!
//! The C template (instantiated for Literal / Command / Distance) maps to
//! functions generic over the histogram alphabet size `N`.

use super::bit_cost::brotli_population_cost;
use super::fast_log::fast_log2;
use super::histogram::Histogram;
use super::memory::{Buf, MemoryManager};

/// `HistogramPair`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct HistogramPair {
    pub idx1: u32,
    pub idx2: u32,
    pub cost_combo: f64,
    pub cost_diff: f64,
}

#[inline]
fn histogram_pair_is_less(p1: &HistogramPair, p2: &HistogramPair) -> bool {
    if p1.cost_diff != p2.cost_diff {
        return p1.cost_diff > p2.cost_diff;
    }
    p1.idx2.wrapping_sub(p1.idx1) > p2.idx2.wrapping_sub(p2.idx1)
}

/// Returns entropy reduction of the context map when we combine two clusters.
#[inline]
fn cluster_cost_diff(size_a: usize, size_b: usize) -> f64 {
    let size_c = size_a + size_b;
    (size_a as f64) * fast_log2(size_a) + (size_b as f64) * fast_log2(size_b) - (size_c as f64) * fast_log2(size_c)
}

/// `BrotliCompareAndPushToQueue`: computes the bit cost reduction by
/// combining `out[idx1]` and `out[idx2]` and if it is below a threshold,
/// stores the pair `(idx1, idx2)` in the `pairs` queue.
pub fn brotli_compare_and_push_to_queue<const N: usize>(
    out: &[Histogram<N>],
    tmp: &mut Histogram<N>,
    cluster_size: &[u32],
    mut idx1: u32,
    mut idx2: u32,
    max_num_pairs: usize,
    pairs: &mut [HistogramPair],
    num_pairs: &mut usize,
) {
    let mut is_good_pair = false;
    let mut p = HistogramPair::default();
    if idx1 == idx2 {
        return;
    }
    if idx2 < idx1 {
        core::mem::swap(&mut idx1, &mut idx2);
    }
    p.idx1 = idx1;
    p.idx2 = idx2;
    p.cost_diff = 0.5 * cluster_cost_diff(cluster_size[idx1 as usize] as usize, cluster_size[idx2 as usize] as usize);
    p.cost_diff -= out[idx1 as usize].bit_cost_;
    p.cost_diff -= out[idx2 as usize].bit_cost_;

    if out[idx1 as usize].total_count_ == 0 {
        p.cost_combo = out[idx2 as usize].bit_cost_;
        is_good_pair = true;
    } else if out[idx2 as usize].total_count_ == 0 {
        p.cost_combo = out[idx1 as usize].bit_cost_;
        is_good_pair = true;
    } else {
        let threshold = if *num_pairs == 0 { 1e99 } else { f64_max(0.0, pairs[0].cost_diff) };
        *tmp = out[idx1 as usize];
        tmp.add_histogram(&out[idx2 as usize]);
        let cost_combo = brotli_population_cost(tmp);
        if cost_combo < threshold - p.cost_diff {
            p.cost_combo = cost_combo;
            is_good_pair = true;
        }
    }
    if is_good_pair {
        p.cost_diff += p.cost_combo;
        if *num_pairs > 0 && histogram_pair_is_less(&pairs[0], &p) {
            // Replace the top of the queue if needed.
            if *num_pairs < max_num_pairs {
                pairs[*num_pairs] = pairs[0];
                *num_pairs += 1;
            }
            pairs[0] = p;
        } else if *num_pairs < max_num_pairs {
            pairs[*num_pairs] = p;
            *num_pairs += 1;
        }
    }
}

/// `BROTLI_MAX(double, a, b)`: `((a) > (b) ? (a) : (b))`.
#[inline(always)]
fn f64_max(a: f64, b: f64) -> f64 {
    if a > b {
        a
    } else {
        b
    }
}

/// `BrotliHistogramCombine`.
pub fn brotli_histogram_combine<const N: usize>(
    out: &mut [Histogram<N>],
    tmp: &mut Histogram<N>,
    cluster_size: &mut [u32],
    symbols: &mut [u32],
    clusters: &mut [u32],
    pairs: &mut [HistogramPair],
    mut num_clusters: usize,
    symbols_size: usize,
    max_clusters: usize,
    max_num_pairs: usize,
) -> usize {
    let mut cost_diff_threshold: f64 = 0.0;
    let mut min_cluster_size: usize = 1;
    let mut num_pairs: usize = 0;

    {
        // We maintain a vector of histogram pairs, with the property that the
        // pair with the maximum bit cost reduction is the first.
        for idx1 in 0..num_clusters {
            for idx2 in (idx1 + 1)..num_clusters {
                brotli_compare_and_push_to_queue(
                    out,
                    tmp,
                    cluster_size,
                    clusters[idx1],
                    clusters[idx2],
                    max_num_pairs,
                    pairs,
                    &mut num_pairs,
                );
            }
        }
    }

    while num_clusters > min_cluster_size {
        if pairs[0].cost_diff >= cost_diff_threshold {
            cost_diff_threshold = 1e99;
            min_cluster_size = max_clusters;
            continue;
        }
        // Take the best pair from the top of heap.
        let best_idx1 = pairs[0].idx1;
        let best_idx2 = pairs[0].idx2;
        {
            let (b1, b2) = (best_idx1 as usize, best_idx2 as usize);
            let src = out[b2];
            out[b1].add_histogram(&src);
            out[b1].bit_cost_ = pairs[0].cost_combo;
            cluster_size[b1] = cluster_size[b1].wrapping_add(cluster_size[b2]);
        }
        for s in symbols[..symbols_size].iter_mut() {
            if *s == best_idx2 {
                *s = best_idx1;
            }
        }
        for i in 0..num_clusters {
            if clusters[i] == best_idx2 {
                clusters.copy_within(i + 1..num_clusters, i);
                break;
            }
        }
        num_clusters -= 1;
        {
            // Remove pairs intersecting the just combined best pair.
            let mut copy_to_idx: usize = 0;
            for i in 0..num_pairs {
                let p = pairs[i];
                if p.idx1 == best_idx1 || p.idx2 == best_idx1 || p.idx1 == best_idx2 || p.idx2 == best_idx2 {
                    // Remove invalid pair from the queue.
                    continue;
                }
                if histogram_pair_is_less(&pairs[0], &p) {
                    // Replace the top of the queue if needed.
                    let front = pairs[0];
                    pairs[0] = p;
                    pairs[copy_to_idx] = front;
                } else {
                    pairs[copy_to_idx] = p;
                }
                copy_to_idx += 1;
            }
            num_pairs = copy_to_idx;
        }

        // Push new pairs formed with the combined histogram to the heap.
        for i in 0..num_clusters {
            brotli_compare_and_push_to_queue(
                out,
                tmp,
                cluster_size,
                best_idx1,
                clusters[i],
                max_num_pairs,
                pairs,
                &mut num_pairs,
            );
        }
    }
    num_clusters
}

/// `BrotliHistogramBitCostDistance`: what is the bit cost of moving
/// histogram from cur_symbol to candidate.
pub fn brotli_histogram_bit_cost_distance<const N: usize>(
    histogram: &Histogram<N>,
    candidate: &Histogram<N>,
    tmp: &mut Histogram<N>,
) -> f64 {
    if histogram.total_count_ == 0 {
        0.0
    } else {
        *tmp = *histogram;
        tmp.add_histogram(candidate);
        brotli_population_cost(tmp) - candidate.bit_cost_
    }
}

/// `BrotliHistogramRemap`: find the best 'out' histogram for each of the
/// 'in' histograms.  When called, `clusters[0..num_clusters)` contains the
/// unique values from `symbols[0..in_size)`, but this property is not
/// preserved in this function.
/// Note: we assume that `out[]->bit_cost_` is already up-to-date.
pub fn brotli_histogram_remap<const N: usize>(
    in_: &[Histogram<N>],
    in_size: usize,
    clusters: &[u32],
    num_clusters: usize,
    out: &mut [Histogram<N>],
    tmp: &mut Histogram<N>,
    symbols: &mut [u32],
) {
    for i in 0..in_size {
        let mut best_out = if i == 0 { symbols[0] } else { symbols[i - 1] };
        let mut best_bits = brotli_histogram_bit_cost_distance(&in_[i], &out[best_out as usize], tmp);
        for &c in clusters[..num_clusters].iter() {
            let cur_bits = brotli_histogram_bit_cost_distance(&in_[i], &out[c as usize], tmp);
            if cur_bits < best_bits {
                best_bits = cur_bits;
                best_out = c;
            }
        }
        symbols[i] = best_out;
    }

    // Recompute each out based on raw and symbols.
    for &c in clusters[..num_clusters].iter() {
        out[c as usize].clear();
    }
    for i in 0..in_size {
        out[symbols[i] as usize].add_histogram(&in_[i]);
    }
}

/// `BrotliHistogramReindex`: reorders elements of the `out[0..length)` array
/// and changes values in `symbols[0..length)` array in the following way:
///
/// * when called, `symbols[]` contains indexes into `out[]`, and has N
///   unique values (possibly N < length)
/// * on return, `symbols'[i] = f(symbols[i])` and
///   `out'[symbols'[i]] = out[symbols[i]]`, for each `0 <= i < length`,
///   where f is a bijection between the range of `symbols[]` and `[0..N)`,
///   and the first occurrences of values in `symbols'[i]` come in
///   consecutive increasing order.
///
/// Returns N, the number of unique values in `symbols[]`.
pub fn brotli_histogram_reindex<const N: usize>(
    m: &MemoryManager,
    out: &mut [Histogram<N>],
    symbols: &mut [u32],
    length: usize,
) -> usize {
    const K_INVALID_INDEX: u32 = u32::MAX;
    let mut new_index: Buf<u32> = Buf::new(m, length);
    for v in new_index.iter_mut() {
        *v = K_INVALID_INDEX;
    }
    let mut next_index: u32 = 0;
    for i in 0..length {
        if new_index[symbols[i] as usize] == K_INVALID_INDEX {
            new_index[symbols[i] as usize] = next_index;
            next_index += 1;
        }
    }
    // TODO(eustas): by using idea of "cycle-sort" we can avoid allocation of
    // tmp and reduce the number of copying by the factor of 2.
    let mut tmp: Buf<Histogram<N>> = Buf::new(m, next_index as usize);
    next_index = 0;
    for i in 0..length {
        if new_index[symbols[i] as usize] == next_index {
            tmp[next_index as usize] = out[symbols[i] as usize];
            next_index += 1;
        }
        symbols[i] = new_index[symbols[i] as usize];
    }
    drop(new_index);
    for i in 0..next_index as usize {
        out[i] = tmp[i];
    }
    next_index as usize
}

/// `BrotliClusterHistograms{Literal,Command,Distance}`.
pub fn brotli_cluster_histograms<const N: usize>(
    m: &MemoryManager,
    in_: &[Histogram<N>],
    in_size: usize,
    max_histograms: usize,
    out: &mut [Histogram<N>],
    out_size: &mut usize,
    histogram_symbols: &mut [u32],
) {
    let mut cluster_size: Buf<u32> = Buf::new(m, in_size);
    let mut clusters: Buf<u32> = Buf::new(m, in_size);
    let mut num_clusters: usize = 0;
    const MAX_INPUT_HISTOGRAMS: usize = 64;
    let mut pairs_capacity: usize = MAX_INPUT_HISTOGRAMS * MAX_INPUT_HISTOGRAMS / 2;
    // For the first pass of clustering, we allow all pairs.
    let mut pairs: Buf<HistogramPair> = Buf::new(m, pairs_capacity + 1);
    // TODO(eustas): move to "persistent" arena?
    let mut tmp: Buf<Histogram<N>> = Buf::new(m, 1);

    for c in cluster_size.iter_mut() {
        *c = 1;
    }

    for i in 0..in_size {
        out[i] = in_[i];
        out[i].bit_cost_ = brotli_population_cost(&in_[i]);
        histogram_symbols[i] = i as u32;
    }

    let mut i = 0usize;
    while i < in_size {
        let num_to_combine = core::cmp::min(in_size - i, MAX_INPUT_HISTOGRAMS);
        for j in 0..num_to_combine {
            clusters[num_clusters + j] = (i + j) as u32;
        }
        let num_new_clusters = brotli_histogram_combine(
            out,
            &mut tmp[0],
            &mut cluster_size,
            &mut histogram_symbols[i..],
            &mut clusters[num_clusters..],
            &mut pairs,
            num_to_combine,
            num_to_combine,
            max_histograms,
            pairs_capacity,
        );
        num_clusters += num_new_clusters;
        i += MAX_INPUT_HISTOGRAMS;
    }

    {
        // For the second pass, we limit the total number of histogram pairs.
        // After this limit is reached, we only keep searching for the best
        // pair.
        let max_num_pairs = core::cmp::min(64 * num_clusters, (num_clusters / 2) * num_clusters);
        // BROTLI_ENSURE_CAPACITY(m, HistogramPair, pairs, pairs_capacity,
        //                        max_num_pairs + 1)
        if pairs_capacity < max_num_pairs + 1 {
            let mut new_size = if pairs_capacity == 0 { max_num_pairs + 1 } else { pairs_capacity };
            while new_size < max_num_pairs + 1 {
                new_size *= 2;
            }
            let mut new_pairs: Buf<HistogramPair> = Buf::new(m, new_size);
            if pairs_capacity != 0 {
                new_pairs[..pairs_capacity].copy_from_slice(&pairs[..pairs_capacity]);
            }
            pairs = new_pairs;
            pairs_capacity = new_size;
        }
        let _ = pairs_capacity;

        // Collapse similar histograms.
        num_clusters = brotli_histogram_combine(
            out,
            &mut tmp[0],
            &mut cluster_size,
            histogram_symbols,
            &mut clusters,
            &mut pairs,
            num_clusters,
            in_size,
            max_histograms,
            max_num_pairs,
        );
    }
    drop(pairs);
    drop(cluster_size);
    // Find the optimal map from original histograms to the final ones.
    brotli_histogram_remap(in_, in_size, &clusters, num_clusters, out, &mut tmp[0], histogram_symbols);
    drop(tmp);
    drop(clusters);
    // Convert the context map to a canonical form.
    *out_size = brotli_histogram_reindex(m, out, histogram_symbols, in_size);
}
