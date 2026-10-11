//! Bindings to the reference C implementation (feature `c-reference`); all
//! symbols carry the `ref_` prefix.  Include from integration tests with
//! `#[cfg(feature = "c-reference")] mod cref;`.
#![allow(dead_code, non_snake_case, clippy::missing_safety_doc)]

// Force linking of the `brotli` rlib, which bundles the C reference library.
extern crate brotli;

use std::ffi::{c_char, c_int, c_void};

pub type AllocFunc = Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>;
pub type FreeFunc = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;
pub type MetadataStartFunc = Option<unsafe extern "C" fn(*mut c_void, usize)>;
pub type MetadataChunkFunc = Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>;

extern "C" {
    // encode.h
    pub fn ref_BrotliEncoderSetParameter(state: *mut c_void, param: c_int, value: u32) -> c_int;
    pub fn ref_BrotliEncoderCreateInstance(alloc: AllocFunc, free: FreeFunc, opaque: *mut c_void) -> *mut c_void;
    pub fn ref_BrotliEncoderDestroyInstance(state: *mut c_void);
    pub fn ref_BrotliEncoderPrepareDictionary(
        dict_type: c_int,
        size: usize,
        data: *const u8,
        quality: c_int,
        alloc: AllocFunc,
        free: FreeFunc,
        opaque: *mut c_void,
    ) -> *mut c_void;
    pub fn ref_BrotliEncoderDestroyPreparedDictionary(dict: *mut c_void);
    pub fn ref_BrotliEncoderAttachPreparedDictionary(state: *mut c_void, dict: *const c_void) -> c_int;
    pub fn ref_BrotliEncoderMaxCompressedSize(input_size: usize) -> usize;
    pub fn ref_BrotliEncoderCompress(
        quality: c_int,
        lgwin: c_int,
        mode: c_int,
        input_size: usize,
        input: *const u8,
        encoded_size: *mut usize,
        encoded: *mut u8,
    ) -> c_int;
    pub fn ref_BrotliEncoderCompressStream(
        state: *mut c_void,
        op: c_int,
        available_in: *mut usize,
        next_in: *mut *const u8,
        available_out: *mut usize,
        next_out: *mut *mut u8,
        total_out: *mut usize,
    ) -> c_int;
    pub fn ref_BrotliEncoderIsFinished(state: *mut c_void) -> c_int;
    pub fn ref_BrotliEncoderHasMoreOutput(state: *mut c_void) -> c_int;
    pub fn ref_BrotliEncoderTakeOutput(state: *mut c_void, size: *mut usize) -> *const u8;
    pub fn ref_BrotliEncoderEstimatePeakMemoryUsage(quality: c_int, lgwin: c_int, input_size: usize) -> usize;
    pub fn ref_BrotliEncoderGetPreparedDictionarySize(dict: *const c_void) -> usize;
    pub fn ref_BrotliEncoderVersion() -> u32;

    // decode.h
    pub fn ref_BrotliDecoderSetParameter(state: *mut c_void, param: c_int, value: u32) -> c_int;
    pub fn ref_BrotliDecoderAttachDictionary(state: *mut c_void, dict_type: c_int, data_size: usize, data: *const u8) -> c_int;
    pub fn ref_BrotliDecoderCreateInstance(alloc: AllocFunc, free: FreeFunc, opaque: *mut c_void) -> *mut c_void;
    pub fn ref_BrotliDecoderDestroyInstance(state: *mut c_void);
    pub fn ref_BrotliDecoderDecompress(encoded_size: usize, encoded: *const u8, decoded_size: *mut usize, decoded: *mut u8) -> c_int;
    pub fn ref_BrotliDecoderDecompressStream(
        state: *mut c_void,
        available_in: *mut usize,
        next_in: *mut *const u8,
        available_out: *mut usize,
        next_out: *mut *mut u8,
        total_out: *mut usize,
    ) -> c_int;
    pub fn ref_BrotliDecoderHasMoreOutput(state: *const c_void) -> c_int;
    pub fn ref_BrotliDecoderTakeOutput(state: *mut c_void, size: *mut usize) -> *const u8;
    pub fn ref_BrotliDecoderIsUsed(state: *const c_void) -> c_int;
    pub fn ref_BrotliDecoderIsFinished(state: *const c_void) -> c_int;
    pub fn ref_BrotliDecoderGetErrorCode(state: *const c_void) -> c_int;
    pub fn ref_BrotliDecoderErrorString(code: c_int) -> *const c_char;
    pub fn ref_BrotliDecoderVersion() -> u32;
    pub fn ref_BrotliDecoderSetMetadataCallbacks(
        state: *mut c_void,
        start_func: MetadataStartFunc,
        chunk_func: MetadataChunkFunc,
        opaque: *mut c_void,
    );

    // shared_dictionary.h
    pub fn ref_BrotliSharedDictionaryCreateInstance(alloc: AllocFunc, free: FreeFunc, opaque: *mut c_void) -> *mut c_void;
    pub fn ref_BrotliSharedDictionaryDestroyInstance(dict: *mut c_void);
    pub fn ref_BrotliSharedDictionaryAttach(dict: *mut c_void, dict_type: c_int, data_size: usize, data: *const u8) -> c_int;

    // common (soft-private)
    pub static ref__kBrotliContextLookupTable: [u8; 2048];
    pub fn ref_BrotliGetDictionary() -> *const c_void;
    pub fn ref_BrotliGetTransforms() -> *const c_void;
    pub fn ref_BrotliTransformDictionaryWord(dst: *mut u8, word: *const u8, len: c_int, transforms: *const c_void, idx: c_int) -> c_int;
}

/// One-shot compression with the C reference.
pub fn compress(quality: i32, lgwin: i32, mode: i32, input: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; unsafe { ref_BrotliEncoderMaxCompressedSize(input.len()) }.max(1024) + 1024];
    let mut size = out.len();
    let ok = unsafe { ref_BrotliEncoderCompress(quality, lgwin, mode, input.len(), input.as_ptr(), &mut size, out.as_mut_ptr()) };
    if ok == 0 {
        return None;
    }
    out.truncate(size);
    Some(out)
}

/// Streaming decompression with the C reference; `None` on error.
pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let s = ref_BrotliDecoderCreateInstance(None, None, std::ptr::null_mut());
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut avail_in = input.len();
        let mut next_in = input.as_ptr();
        let result = loop {
            let mut avail_out = buf.len();
            let mut next_out = buf.as_mut_ptr();
            let r = ref_BrotliDecoderDecompressStream(s, &mut avail_in, &mut next_in, &mut avail_out, &mut next_out, std::ptr::null_mut());
            out.extend_from_slice(&buf[..buf.len() - avail_out]);
            match r {
                1 => break Some(out),
                3 => continue,
                _ => break None,
            }
        };
        ref_BrotliDecoderDestroyInstance(s);
        result
    }
}
