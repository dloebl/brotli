//! Port of `c/enc/block_splitter.h` / `block_splitter.c` /
//! `block_splitter_inc.h`.
//!
//! OWNER: worker "entropy".

use super::memory::Buf;

/// `BlockSplit`.  `types.len()` / `lengths.len()` are the allocated
/// capacities (C: `types_alloc_size` / `lengths_alloc_size`).
#[derive(Default)]
pub struct BlockSplit {
    /// Amount of distinct types
    pub num_types: usize,
    /// Amount of values in types and length
    pub num_blocks: usize,
    pub types: Buf<u8>,
    pub lengths: Buf<u32>,
}

impl BlockSplit {
    /// `BrotliInitBlockSplit`.
    pub fn new() -> Self {
        BlockSplit::default()
    }
}
