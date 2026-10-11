//! Exports of `libbrotlicommon`: `<brotli/shared_dictionary.h>` plus the
//! "soft-private" symbols of `c/common/*.h` marked `BROTLI_COMMON_API`.

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_int, c_void};

use crate::common::alloc::{bootstrap_alloc, default_alloc_func, default_free_func, Allocator, BrotliAllocFunc, BrotliFreeFunc};
use crate::common::constants::{BrotliPrefixCodeRange, BROTLI_NUM_BLOCK_LEN_SYMBOLS, K_BROTLI_PREFIX_CODE_RANGES};
use crate::common::tables::CONTEXT_LOOKUP_TABLE_VALUE;
use crate::common::dictionary::{BrotliDictionary, BROTLI_DICTIONARY};
use crate::common::shared_dictionary::SharedDictionary;
use crate::common::transform::{transform_dictionary_word_raw, BrotliTransforms, BROTLI_TRANSFORMS};

/// `BROTLI_BOOL`
pub type BrotliBool = c_int;
pub const BROTLI_TRUE: BrotliBool = 1;
pub const BROTLI_FALSE: BrotliBool = 0;

#[inline]
pub fn to_brotli_bool(b: bool) -> BrotliBool {
    if b {
        BROTLI_TRUE
    } else {
        BROTLI_FALSE
    }
}

/// `_kBrotliContextLookupTable` (context.h).
#[no_mangle]
pub static _kBrotliContextLookupTable: [u8; 2048] = CONTEXT_LOOKUP_TABLE_VALUE;

/// `_kBrotliPrefixCodeRanges` (constants.h).
#[no_mangle]
pub static _kBrotliPrefixCodeRanges: [BrotliPrefixCodeRange; BROTLI_NUM_BLOCK_LEN_SYMBOLS] = K_BROTLI_PREFIX_CODE_RANGES;

/// `BrotliGetDictionary` (dictionary.h).
#[no_mangle]
pub extern "C" fn BrotliGetDictionary() -> *const BrotliDictionary {
    &BROTLI_DICTIONARY
}

/// `BrotliSetDictionaryData` (dictionary.h).  The dictionary is always
/// embedded (no `BROTLI_EXTERNAL_DICTIONARY_DATA`), so this is a no-op.
#[no_mangle]
pub extern "C" fn BrotliSetDictionaryData(_data: *const u8) {}

/// `BrotliGetTransforms` (transform.h).
#[no_mangle]
pub extern "C" fn BrotliGetTransforms() -> *const BrotliTransforms {
    &BROTLI_TRANSFORMS
}

/// `BrotliTransformDictionaryWord` (transform.h).
#[no_mangle]
pub unsafe extern "C" fn BrotliTransformDictionaryWord(
    dst: *mut u8,
    word: *const u8,
    len: c_int,
    transforms: *const BrotliTransforms,
    transform_idx: c_int,
) -> c_int {
    transform_dictionary_word_raw(dst, word, len, &*transforms, transform_idx)
}

/// `BrotliDefaultAllocFunc` (platform.h).
#[no_mangle]
pub unsafe extern "C" fn BrotliDefaultAllocFunc(opaque: *mut c_void, size: usize) -> *mut c_void {
    default_alloc_func(opaque, size)
}

/// `BrotliDefaultFreeFunc` (platform.h).
#[no_mangle]
pub unsafe extern "C" fn BrotliDefaultFreeFunc(opaque: *mut c_void, address: *mut c_void) {
    default_free_func(opaque, address)
}

/// Object behind the opaque `BrotliSharedDictionary*`.
pub struct SharedDictionaryInstance {
    pub alloc: Allocator,
    pub dict: SharedDictionary,
}

/// `BrotliSharedDictionaryCreateInstance`.
#[no_mangle]
pub unsafe extern "C" fn BrotliSharedDictionaryCreateInstance(
    alloc_func: BrotliAllocFunc,
    free_func: BrotliFreeFunc,
    opaque: *mut c_void,
) -> *mut c_void {
    let p = bootstrap_alloc(core::mem::size_of::<SharedDictionaryInstance>(), alloc_func, free_func, opaque)
        as *mut SharedDictionaryInstance;
    if p.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(p, SharedDictionaryInstance { alloc: Allocator::new(alloc_func, free_func, opaque), dict: SharedDictionary::new() });
    p as *mut c_void
}

/// `BrotliSharedDictionaryDestroyInstance`.
#[no_mangle]
pub unsafe extern "C" fn BrotliSharedDictionaryDestroyInstance(dict: *mut c_void) {
    if dict.is_null() {
        return;
    }
    let p = dict as *mut SharedDictionaryInstance;
    let alloc = (*p).alloc;
    core::ptr::drop_in_place(p);
    alloc.free_raw(p as *mut c_void);
}

/// `BrotliSharedDictionaryAttach`.
#[no_mangle]
pub unsafe extern "C" fn BrotliSharedDictionaryAttach(
    dict: *mut c_void,
    dict_type: c_int,
    data_size: usize,
    data: *const u8,
) -> BrotliBool {
    if dict.is_null() {
        return BROTLI_FALSE;
    }
    let p = dict as *mut SharedDictionaryInstance;
    to_brotli_bool((*p).dict.attach(dict_type as u32, data_size, data))
}
