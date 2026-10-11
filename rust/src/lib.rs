//! Brotli compression library implemented in Rust.
//!
//! This crate is a faithful port of the reference C implementation
//! (<https://github.com/google/brotli>).  It produces byte-identical output
//! and exports the very same C ABI (`BrotliEncoder*`, `BrotliDecoder*`,
//! `BrotliSharedDictionary*`, ...) declared by the public headers in
//! `c/include/brotli/`, so it can be used as a drop-in replacement for
//! `libbrotlicommon`, `libbrotlidec` and `libbrotlienc`.

#![cfg_attr(not(test), no_std)]
// Many doc comments are ported C comments using `a[i]`-style notation.
#![allow(rustdoc::broken_intra_doc_links, rustdoc::bare_urls)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::collapsible_if)]

pub mod common;
pub mod dec;
pub mod enc;
#[cfg(feature = "ffi")]
pub mod ffi;
