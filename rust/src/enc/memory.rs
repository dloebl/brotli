//! Port of `c/enc/memory.h` / `memory.c`.
//!
//! The encoder uses the `BROTLI_ENCODER_EXIT_ON_OOM` policy (the default of
//! the C library): allocation failures terminate the process.

pub use crate::common::alloc::{oom_exit, Allocator, Boxed, Buf};

/// `MemoryManager`: the client allocation callbacks.
pub type MemoryManager = Allocator;
