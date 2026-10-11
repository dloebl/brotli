//! Port of `c/enc/backward_references_hq.h` / `backward_references_hq.c`:
//! Zopfli-style backward references (qualities 10 and 11).
//!
//! OWNER: worker "hashers".

use super::command::Command;
use super::hash::Hasher;
use super::memory::MemoryManager;
use super::params::BrotliEncoderParams;
use crate::common::context::ContextLut;

/// `BrotliCreateZopfliBackwardReferences` (quality 10).  Same conventions as
/// `brotli_create_backward_references`.
pub fn brotli_create_zopfli_backward_references(
    m: &MemoryManager,
    num_bytes: usize,
    position: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    literal_context_lut: ContextLut,
    params: &BrotliEncoderParams,
    hasher: &mut Hasher,
    dist_cache: &mut [i32],
    last_insert_len: &mut usize,
    commands: &mut [Command],
    num_commands: &mut usize,
    num_literals: &mut usize,
) {
    let _ = (m, num_bytes, position, ringbuffer, ringbuffer_mask, literal_context_lut, params, hasher, dist_cache, last_insert_len, commands, num_commands, num_literals);
    todo!("backward_references_hq::brotli_create_zopfli_backward_references")
}

/// `BrotliCreateHqZopfliBackwardReferences` (quality 11).
pub fn brotli_create_hq_zopfli_backward_references(
    m: &MemoryManager,
    num_bytes: usize,
    position: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    literal_context_lut: ContextLut,
    params: &BrotliEncoderParams,
    hasher: &mut Hasher,
    dist_cache: &mut [i32],
    last_insert_len: &mut usize,
    commands: &mut [Command],
    num_commands: &mut usize,
    num_literals: &mut usize,
) {
    let _ = (m, num_bytes, position, ringbuffer, ringbuffer_mask, literal_context_lut, params, hasher, dist_cache, last_insert_len, commands, num_commands, num_literals);
    todo!("backward_references_hq::brotli_create_hq_zopfli_backward_references")
}
