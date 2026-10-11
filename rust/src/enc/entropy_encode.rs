//! Port of `c/enc/entropy_encode.h` / `entropy_encode.c`: entropy encoding
//! (Huffman) utilities.
//!
//! OWNER: worker "entropy".

/// A node of a Huffman tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HuffmanTree {
    pub total_count_: u32,
    pub index_left_: i16,
    pub index_right_or_value_: i16,
}

impl HuffmanTree {
    /// `InitHuffmanTree`.
    #[inline]
    pub fn new(count: u32, left: i16, right: i16) -> Self {
        HuffmanTree { total_count_: count, index_left_: left, index_right_or_value_: right }
    }
}
