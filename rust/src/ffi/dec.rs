//! Exports of `libbrotlidec` (`<brotli/decode.h>`).
//!
//! OWNER: worker "decoder".

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_char, c_int, c_void};

use super::common::{to_brotli_bool, BrotliBool};
use crate::common::alloc::{BrotliAllocFunc, BrotliFreeFunc};
use crate::dec::{decompress_raw, error_string_bytes, version, Decoder, DecoderState, MetadataChunkFunc, MetadataStartFunc};

/// `BrotliDecoderState` (opaque to C).
pub type BrotliDecoderState = DecoderState;

/// `BrotliDecoderSetParameter`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderSetParameter(state: *mut BrotliDecoderState, param: c_int, value: u32) -> BrotliBool {
    to_brotli_bool((*state).set_parameter(param, value))
}

/// `BrotliDecoderAttachDictionary`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderAttachDictionary(
    state: *mut BrotliDecoderState,
    dict_type: c_int,
    data_size: usize,
    data: *const u8,
) -> BrotliBool {
    to_brotli_bool((*state).attach_dictionary(dict_type, data_size, data))
}

/// `BrotliDecoderCreateInstance`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderCreateInstance(
    alloc_func: BrotliAllocFunc,
    free_func: BrotliFreeFunc,
    opaque: *mut c_void,
) -> *mut BrotliDecoderState {
    match Decoder::create_instance(alloc_func, free_func, opaque) {
        Some(d) => d.into_raw(),
        None => core::ptr::null_mut(),
    }
}

/// `BrotliDecoderDestroyInstance`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderDestroyInstance(state: *mut BrotliDecoderState) {
    if state.is_null() {
        return;
    }
    drop(Decoder::from_raw(state));
}

/// `BrotliDecoderDecompress`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderDecompress(
    encoded_size: usize,
    encoded_buffer: *const u8,
    decoded_size: *mut usize,
    decoded_buffer: *mut u8,
) -> c_int {
    let encoded: &[u8] = if encoded_size == 0 { &[] } else { core::slice::from_raw_parts(encoded_buffer, encoded_size) };
    let capacity = *decoded_size;
    let decoded: Option<&mut [u8]> = if decoded_buffer.is_null() {
        None
    } else if capacity == 0 {
        Some(&mut [])
    } else {
        Some(core::slice::from_raw_parts_mut(decoded_buffer, capacity))
    };
    decompress_raw(encoded, &mut *decoded_size, decoded) as c_int
}

/// `BrotliDecoderDecompressStream`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderDecompressStream(
    state: *mut BrotliDecoderState,
    available_in: *mut usize,
    next_in: *mut *const u8,
    available_out: *mut usize,
    next_out: *mut *mut u8,
    total_out: *mut usize,
) -> c_int {
    let s = &mut *state;
    let avail_in = *available_in;
    let input: &[u8] = if avail_in == 0 { &[] } else { core::slice::from_raw_parts(*next_in, avail_in) };
    let mut avail_out = *available_out;
    let window: Option<&mut [u8]> = if next_out.is_null() || (*next_out).is_null() {
        None
    } else if avail_out == 0 {
        Some(&mut [])
    } else {
        Some(core::slice::from_raw_parts_mut(*next_out, avail_out))
    };
    let initial_out = avail_out;
    let mut in_pos = 0usize;
    let total = if total_out.is_null() { None } else { Some(&mut *total_out) };
    let r = s.decompress_stream_raw(input, &mut in_pos, &mut avail_out, window, total);
    if in_pos != 0 {
        *next_in = (*next_in).wrapping_add(in_pos);
        *available_in = avail_in.wrapping_sub(in_pos);
    }
    let written = initial_out - avail_out;
    if written != 0 {
        *next_out = (*next_out).add(written);
        *available_out = avail_out;
    }
    r as c_int
}

/// `BrotliDecoderHasMoreOutput`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderHasMoreOutput(state: *const BrotliDecoderState) -> BrotliBool {
    to_brotli_bool((*state).has_more_output())
}

/// `BrotliDecoderTakeOutput`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderTakeOutput(state: *mut BrotliDecoderState, size: *mut usize) -> *const u8 {
    match (*state).take_output(&mut *size) {
        Some(out) => out.as_ptr(),
        None => core::ptr::null(),
    }
}

/// `BrotliDecoderIsUsed`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderIsUsed(state: *const BrotliDecoderState) -> BrotliBool {
    to_brotli_bool((*state).is_used())
}

/// `BrotliDecoderIsFinished`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderIsFinished(state: *const BrotliDecoderState) -> BrotliBool {
    to_brotli_bool((*state).is_finished())
}

/// `BrotliDecoderGetErrorCode`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderGetErrorCode(state: *const BrotliDecoderState) -> c_int {
    (*state).get_error_code()
}

/// `BrotliDecoderErrorString`.
#[no_mangle]
pub extern "C" fn BrotliDecoderErrorString(c: c_int) -> *const c_char {
    error_string_bytes(c).as_ptr() as *const c_char
}

/// `BrotliDecoderVersion`.
#[no_mangle]
pub extern "C" fn BrotliDecoderVersion() -> u32 {
    version()
}

/// `BrotliDecoderSetMetadataCallbacks`.
#[no_mangle]
pub unsafe extern "C" fn BrotliDecoderSetMetadataCallbacks(
    state: *mut BrotliDecoderState,
    start_func: MetadataStartFunc,
    chunk_func: MetadataChunkFunc,
    opaque: *mut c_void,
) {
    (*state).set_metadata_callbacks(start_func, chunk_func, opaque);
}
