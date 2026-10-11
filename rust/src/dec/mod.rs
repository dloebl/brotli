//! Port of `c/dec`: the Brotli decoder.
//!
//! OWNER: worker "decoder".
//!
//! The Rust API mirrors the C API of `<brotli/decode.h>`:
//!
//! * [`Decoder`] owns a [`DecoderState`] allocated through the client
//!   allocator (like `BrotliDecoderCreateInstance`); it derefs to the state,
//!   which provides [`DecoderState::decompress_stream`],
//!   [`DecoderState::take_output`], [`DecoderState::has_more_output`],
//!   [`DecoderState::is_finished`], ...
//! * [`decompress`] is the one-shot `BrotliDecoderDecompress`.
//!
//! ```
//! use brotli::dec::{Decoder, BrotliDecoderResult};
//! let compressed = [0x8bu8, 0x00, 0x80, 0x68, 0x69, 0x03]; // "hi"
//! let mut d = Decoder::new().unwrap();
//! let mut out = [0u8; 16];
//! let (mut ip, mut op) = (0, 0);
//! let r = d.decompress_stream(&compressed, &mut ip, &mut out, &mut op, None);
//! assert_eq!(r, BrotliDecoderResult::Success);
//! assert_eq!(&out[..op], b"hi");
//! ```

pub mod bit_reader;
pub mod decode;
pub mod huffman;
pub mod prefix;
pub mod state;
#[doc(hidden)]
pub mod tables;

use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::common::alloc::{bootstrap_alloc, Allocator, BrotliAllocFunc, BrotliFreeFunc};

pub use decode::{
    decompress, decompress_raw, error_string, error_string_bytes, version, BrotliDecoderErrorCode,
    BrotliDecoderResult, BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION, BROTLI_DECODER_PARAM_LARGE_WINDOW,
};
pub use decode::*;
pub use state::{DecoderState, MetadataChunkFunc, MetadataStartFunc};

/// An owned decoder instance (`BrotliDecoderState*`), allocated through the
/// client allocator exactly like `BrotliDecoderCreateInstance` does.
pub struct Decoder {
    ptr: NonNull<DecoderState>,
}

impl Decoder {
    /// Creates a decoder using `malloc` / `free`.
    pub fn new() -> Option<Decoder> {
        // SAFETY: default allocator.
        unsafe { Self::create_instance(None, None, core::ptr::null_mut()) }
    }

    /// `BrotliDecoderCreateInstance`: `alloc_func` and `free_func` both
    /// `None` → malloc/free; both set → custom allocator; otherwise `None`.
    ///
    /// # Safety
    /// The callbacks must behave like malloc/free (and `opaque` must be
    /// valid for them).
    pub unsafe fn create_instance(
        alloc_func: BrotliAllocFunc,
        free_func: BrotliFreeFunc,
        opaque: *mut c_void,
    ) -> Option<Decoder> {
        if !decode::ensure_static_init() {
            return None;
        }
        let p = bootstrap_alloc(core::mem::size_of::<DecoderState>(), alloc_func, free_func, opaque)
            as *mut DecoderState;
        if p.is_null() {
            return None;
        }
        let alloc = Allocator::new(alloc_func, free_func, opaque);
        if (p as usize) % core::mem::align_of::<DecoderState>() != 0 {
            // A misaligned instance cannot hold the Rust state.
            alloc.free_raw(p as *mut c_void);
            return None;
        }
        match DecoderState::new(alloc) {
            Some(s) => {
                core::ptr::write(p, s);
                Some(Decoder { ptr: NonNull::new_unchecked(p) })
            }
            None => {
                alloc.free_raw(p as *mut c_void);
                None
            }
        }
    }

    /// Releases ownership; the pointer must be returned to
    /// [`Decoder::from_raw`] eventually.
    pub fn into_raw(self) -> *mut DecoderState {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Takes ownership of a pointer obtained from [`Decoder::into_raw`].
    ///
    /// # Safety
    /// `p` must come from [`Decoder::into_raw`] and not be used afterwards.
    pub unsafe fn from_raw(p: *mut DecoderState) -> Decoder {
        Decoder { ptr: NonNull::new_unchecked(p) }
    }
}

impl Drop for Decoder {
    /// `BrotliDecoderDestroyInstance`.
    fn drop(&mut self) {
        // SAFETY: `ptr` is a live, initialized state allocated with the
        // allocator stored inside it.
        unsafe {
            let p = self.ptr.as_ptr();
            let alloc = (*p).alloc;
            core::ptr::drop_in_place(p); // BrotliDecoderStateCleanup
            alloc.free_raw(p as *mut c_void);
        }
    }
}

impl Deref for Decoder {
    type Target = DecoderState;
    fn deref(&self) -> &DecoderState {
        // SAFETY: `ptr` is live and uniquely owned.
        unsafe { self.ptr.as_ref() }
    }
}

impl DerefMut for Decoder {
    fn deref_mut(&mut self) -> &mut DecoderState {
        // SAFETY: `ptr` is live and uniquely owned.
        unsafe { self.ptr.as_mut() }
    }
}
