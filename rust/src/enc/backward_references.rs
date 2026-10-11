//! Port of `c/enc/backward_references.h` / `backward_references.c` /
//! `backward_references_inc.h`: function to find backward reference copies.
//!
//! OWNER: worker "hashers".

use super::command::Command;
use super::hash::Hasher;
use super::params::BrotliEncoderParams;
use crate::common::context::ContextLut;

/// `BrotliCreateBackwardReferences`.
///
/// `ringbuffer` is the ring buffer (`buffer_`), `dist_cache` has 16 entries
/// (only the first 4 are state; the rest is scratch for
/// `PrepareDistanceCache`).  New commands are written to `commands[0..]`
/// and `*num_commands` is incremented by their number (like C, where
/// `commands` points to `&commands_[num_commands_]`).
pub fn brotli_create_backward_references(
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
    let _ = (num_bytes, position, ringbuffer, ringbuffer_mask, literal_context_lut, params, hasher, dist_cache, last_insert_len, commands, num_commands, num_literals);
    todo!("backward_references::brotli_create_backward_references")
}
