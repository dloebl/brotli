//! Exports of `libbrotlienc` (`<brotli/encode.h>`).

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_int, c_void};

use super::common::{to_brotli_bool, BrotliBool, BROTLI_FALSE};
use crate::common::alloc::{bootstrap_alloc, Allocator, BrotliAllocFunc, BrotliFreeFunc, Boxed};
use crate::common::shared_dictionary::BROTLI_SHARED_DICTIONARY_RAW;
use crate::enc::compound_dictionary::{
    create_prepared_dictionary, PreparedDictionary, K_LEAN_PREPARED_DICTIONARY_MAGIC, K_MANAGED_DICTIONARY_MAGIC,
    K_PREPARED_DICTIONARY_MAGIC,
};
use crate::enc::encode::{
    brotli_encoder_compress, brotli_encoder_estimate_peak_memory_usage, brotli_encoder_max_compressed_size,
    brotli_encoder_version, prepared_dictionary_size, BrotliEncoderState, ManagedDictionary, StreamIo,
    C_SIZEOF_MANAGED_DICTIONARY,
};

/// Opaque `BrotliEncoderState`.
pub type BrotliEncoderStateHandle = BrotliEncoderState;

#[inline]
unsafe fn slice_or_empty<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 || p.is_null() {
        &[]
    } else {
        core::slice::from_raw_parts(p, n)
    }
}

#[inline]
unsafe fn slice_or_empty_mut<'a>(p: *mut u8, n: usize) -> &'a mut [u8] {
    if n == 0 || p.is_null() {
        &mut []
    } else {
        core::slice::from_raw_parts_mut(p, n)
    }
}

/// `BrotliEncoderSetParameter`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderSetParameter(state: *mut BrotliEncoderState, param: c_int, value: u32) -> BrotliBool {
    to_brotli_bool((*state).set_parameter(param as u32, value))
}

/// `BrotliEncoderCreateInstance`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderCreateInstance(
    alloc_func: BrotliAllocFunc,
    free_func: BrotliFreeFunc,
    opaque: *mut c_void,
) -> *mut BrotliEncoderState {
    let p = bootstrap_alloc(core::mem::size_of::<BrotliEncoderState>(), alloc_func, free_func, opaque)
        as *mut BrotliEncoderState;
    if p.is_null() {
        return core::ptr::null_mut();
    }
    let m = Allocator::new(alloc_func, free_func, opaque);
    if (p as usize) % core::mem::align_of::<BrotliEncoderState>() != 0 {
        // A client allocator returning insufficiently aligned memory.
        m.free_raw(p as *mut c_void);
        return core::ptr::null_mut();
    }
    core::ptr::write(p, BrotliEncoderState::new(m));
    p
}

/// `BrotliEncoderDestroyInstance`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderDestroyInstance(state: *mut BrotliEncoderState) {
    if state.is_null() {
        return;
    }
    let m = (*state).memory_manager_;
    core::ptr::drop_in_place(state);
    m.free_raw(state as *mut c_void);
}

/// `BrotliEncoderPrepareDictionary`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderPrepareDictionary(
    dict_type: c_int,
    data_size: usize,
    data: *const u8,
    _quality: c_int,
    alloc_func: BrotliAllocFunc,
    free_func: BrotliFreeFunc,
    opaque: *mut c_void,
) -> *mut c_void {
    // Only raw dictionaries are supported by the (non-experimental) library.
    if dict_type as u32 != BROTLI_SHARED_DICTIONARY_RAW {
        return core::ptr::null_mut();
    }
    let p = bootstrap_alloc(core::mem::size_of::<ManagedDictionary>(), alloc_func, free_func, opaque)
        as *mut ManagedDictionary;
    if p.is_null() {
        return core::ptr::null_mut();
    }
    let m = Allocator::new(alloc_func, free_func, opaque);
    if (p as usize) % core::mem::align_of::<ManagedDictionary>() != 0 {
        m.free_raw(p as *mut c_void);
        return core::ptr::null_mut();
    }
    core::ptr::write(p, ManagedDictionary { magic: K_MANAGED_DICTIONARY_MAGIC, memory_manager_: m, dictionary: None });
    if data_size == 0 || !data.is_null() {
        let source = slice_or_empty(data, data_size);
        (*p).dictionary = create_prepared_dictionary(&m, source).map(|d| Boxed::new(&m, d));
    }
    if (*p).dictionary.is_none() {
        core::ptr::drop_in_place(p);
        m.free_raw(p as *mut c_void);
        return core::ptr::null_mut();
    }
    p as *mut c_void
}

/// `BrotliEncoderDestroyPreparedDictionary`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderDestroyPreparedDictionary(dictionary: *mut c_void) {
    if dictionary.is_null() {
        return;
    }
    // First field of dictionary structs.
    // Only managed dictionaries are eligible for destruction by this method.
    if *(dictionary as *const u32) != K_MANAGED_DICTIONARY_MAGIC {
        return;
    }
    let p = dictionary as *mut ManagedDictionary;
    let m = (*p).memory_manager_;
    core::ptr::drop_in_place(p);
    m.free_raw(p as *mut c_void);
}

/// Resolves a `BrotliEncoderPreparedDictionary*` to the prepared dictionary
/// it denotes (unwrapping managed dictionaries).  Returns the dictionary and
/// the managed-wrapper overhead.
unsafe fn resolve_prepared(dictionary: *const c_void) -> Option<(&'static PreparedDictionary, usize)> {
    if dictionary.is_null() {
        return None;
    }
    let magic = *(dictionary as *const u32);
    if magic == K_MANAGED_DICTIONARY_MAGIC {
        let managed = &*(dictionary as *const ManagedDictionary);
        let d: &PreparedDictionary = managed.dictionary.as_deref()?;
        if d.magic == K_PREPARED_DICTIONARY_MAGIC || d.magic == K_LEAN_PREPARED_DICTIONARY_MAGIC {
            return Some((&*(d as *const PreparedDictionary), C_SIZEOF_MANAGED_DICTIONARY));
        }
        return None;
    }
    if magic == K_PREPARED_DICTIONARY_MAGIC || magic == K_LEAN_PREPARED_DICTIONARY_MAGIC {
        return Some((&*(dictionary as *const PreparedDictionary), 0));
    }
    // kSharedDictionaryMagic instances can only be created by the
    // experimental serialized-dictionary API, which is not supported.
    None
}

/// `BrotliEncoderAttachPreparedDictionary`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderAttachPreparedDictionary(
    state: *mut BrotliEncoderState,
    dictionary: *const c_void,
) -> BrotliBool {
    match resolve_prepared(dictionary) {
        Some((prepared, _)) => to_brotli_bool((*state).attach_prepared_dictionary(prepared)),
        None => BROTLI_FALSE,
    }
}

/// `BrotliEncoderMaxCompressedSize`.
#[no_mangle]
pub extern "C" fn BrotliEncoderMaxCompressedSize(input_size: usize) -> usize {
    brotli_encoder_max_compressed_size(input_size)
}

/// `BrotliEncoderCompress`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderCompress(
    quality: c_int,
    lgwin: c_int,
    mode: c_int,
    input_size: usize,
    input_buffer: *const u8,
    encoded_size: *mut usize,
    encoded_buffer: *mut u8,
) -> BrotliBool {
    let input = slice_or_empty(input_buffer, input_size);
    let out = slice_or_empty_mut(encoded_buffer, *encoded_size);
    if out.is_empty() && *encoded_size != 0 {
        // NULL output buffer with non-zero capacity: C would crash.
        return BROTLI_FALSE;
    }
    to_brotli_bool(brotli_encoder_compress(quality, lgwin, mode as u32, input, &mut *encoded_size, out))
}

/// `BrotliEncoderCompressStream`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderCompressStream(
    state: *mut BrotliEncoderState,
    op: c_int,
    available_in: *mut usize,
    next_in: *mut *const u8,
    available_out: *mut usize,
    next_out: *mut *mut u8,
    total_out: *mut usize,
) -> BrotliBool {
    let s = &mut *state;
    let input = slice_or_empty(if *available_in != 0 { *next_in } else { core::ptr::null() }, *available_in);
    let output = slice_or_empty_mut(if *available_out != 0 { *next_out } else { core::ptr::null_mut() }, *available_out);
    let mut io = StreamIo { input, in_pos: 0, output, out_pos: 0 };
    let total = if total_out.is_null() { None } else { Some(&mut *total_out) };
    let result = s.compress_stream(op as u32, &mut io, total);
    let (in_pos, out_pos) = (io.in_pos, io.out_pos);
    if in_pos != 0 {
        *next_in = (*next_in).add(in_pos);
        *available_in -= in_pos;
    }
    if out_pos != 0 {
        *next_out = (*next_out).add(out_pos);
        *available_out -= out_pos;
    }
    to_brotli_bool(result)
}

/// `BrotliEncoderIsFinished`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderIsFinished(state: *mut BrotliEncoderState) -> BrotliBool {
    to_brotli_bool((*state).is_finished())
}

/// `BrotliEncoderHasMoreOutput`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderHasMoreOutput(state: *mut BrotliEncoderState) -> BrotliBool {
    to_brotli_bool((*state).has_more_output())
}

/// `BrotliEncoderTakeOutput`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderTakeOutput(state: *mut BrotliEncoderState, size: *mut usize) -> *const u8 {
    (*state).take_output_raw(&mut *size)
}

/// `BrotliEncoderEstimatePeakMemoryUsage`.
#[no_mangle]
pub extern "C" fn BrotliEncoderEstimatePeakMemoryUsage(quality: c_int, lgwin: c_int, input_size: usize) -> usize {
    brotli_encoder_estimate_peak_memory_usage(quality, lgwin, input_size)
}

/// `BrotliEncoderGetPreparedDictionarySize`.
#[no_mangle]
pub unsafe extern "C" fn BrotliEncoderGetPreparedDictionarySize(dictionary: *const c_void) -> usize {
    match resolve_prepared(dictionary) {
        Some((prepared, overhead)) => prepared_dictionary_size(prepared, overhead),
        None => 0,
    }
}

/// `BrotliEncoderVersion`.
#[no_mangle]
pub extern "C" fn BrotliEncoderVersion() -> u32 {
    brotli_encoder_version()
}
