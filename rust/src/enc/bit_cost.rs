//! Port of `c/enc/bit_cost.h` / `bit_cost.c` / `bit_cost_inc.h`: functions
//! to estimate the bit cost of Huffman trees.
//!
//! OWNER: worker "entropy".

/// `BrotliBitsEntropy`.  Uses the first `size` entries of `population`.
pub fn brotli_bits_entropy(population: &[u32], size: usize) -> f64 {
    let _ = (population, size);
    todo!("bit_cost::brotli_bits_entropy")
}
