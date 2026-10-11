//! Exhaustive differential test of the libbrotlicommon exports against the C
//! reference: BrotliGetDictionary / BrotliGetTransforms contents,
//! BrotliTransformDictionaryWord for every word and transform, the exported
//! lookup tables and the BrotliSharedDictionary API.
#![cfg(feature = "c-reference")]
mod cref;

use brotli::ffi::common as rs;
use std::ffi::c_void;

#[repr(C)]
struct Dict {
    size_bits_by_length: [u8; 32],
    offsets_by_length: [u32; 32],
    data_size: usize,
    data: *const u8,
}

#[repr(C)]
struct Transforms {
    prefix_suffix_size: u16,
    prefix_suffix: *const u8,
    prefix_suffix_map: *const u16,
    num_transforms: u32,
    transforms: *const u8,
    params: *const u8,
    cut_off_transforms: [i16; 10],
}

#[test]
fn dictionary_and_transforms_match() {
    unsafe {
        let a = &*(rs::BrotliGetDictionary() as *const Dict);
        let b = &*(cref::ref_BrotliGetDictionary() as *const Dict);
        assert_eq!(a.size_bits_by_length, b.size_bits_by_length);
        assert_eq!(a.offsets_by_length, b.offsets_by_length);
        assert_eq!(a.data_size, b.data_size);
        assert_eq!(std::slice::from_raw_parts(a.data, a.data_size), std::slice::from_raw_parts(b.data, b.data_size));

        let ta = &*(rs::BrotliGetTransforms() as *const Transforms);
        let tb = &*(cref::ref_BrotliGetTransforms() as *const Transforms);
        assert_eq!(ta.prefix_suffix_size, tb.prefix_suffix_size);
        assert_eq!(ta.num_transforms, tb.num_transforms);
        assert_eq!(ta.cut_off_transforms, tb.cut_off_transforms);
        assert_eq!(ta.params.is_null(), tb.params.is_null());
        assert_eq!(
            std::slice::from_raw_parts(ta.prefix_suffix, ta.prefix_suffix_size as usize),
            std::slice::from_raw_parts(tb.prefix_suffix, tb.prefix_suffix_size as usize)
        );
        assert_eq!(
            std::slice::from_raw_parts(ta.transforms, 3 * ta.num_transforms as usize),
            std::slice::from_raw_parts(tb.transforms, 3 * tb.num_transforms as usize)
        );
        assert_eq!(std::slice::from_raw_parts(ta.prefix_suffix_map, 50), std::slice::from_raw_parts(tb.prefix_suffix_map, 50));

        // Every word of every length, with every transform.
        let mut out_a = [0u8; 128];
        let mut out_b = [0u8; 128];
        let mut count = 0usize;
        for len in 4..=24usize {
            let bits = a.size_bits_by_length[len];
            if bits == 0 {
                continue;
            }
            for idx in 0..(1usize << bits) {
                let word = a.data.add(a.offsets_by_length[len] as usize + len * idx);
                for t in 0..ta.num_transforms as i32 {
                    out_a.fill(0xAA);
                    out_b.fill(0xAA);
                    let na = rs::BrotliTransformDictionaryWord(out_a.as_mut_ptr(), word, len as i32, rs::BrotliGetTransforms(), t);
                    let nb = cref::ref_BrotliTransformDictionaryWord(out_b.as_mut_ptr(), word, len as i32, cref::ref_BrotliGetTransforms(), t);
                    assert_eq!(na, nb);
                    assert_eq!(out_a, out_b, "len {} idx {} transform {}", len, idx, t);
                    count += 1;
                }
            }
        }
        assert!(count > 1_000_000);

        assert_eq!(rs::_kBrotliContextLookupTable, cref::ref__kBrotliContextLookupTable);
    }
}

#[test]
fn shared_dictionary_api_matches() {
    unsafe {
        let data = vec![7u8; 100];
        // Mixed NULL / non-NULL allocator functions must fail like in C.
        unsafe extern "C" fn my_alloc(_: *mut c_void, n: usize) -> *mut c_void {
            libc_malloc(n)
        }
        unsafe extern "C" fn my_free(_: *mut c_void, p: *mut c_void) {
            libc_free(p)
        }
        extern "C" {
            #[link_name = "malloc"]
            fn libc_malloc(n: usize) -> *mut c_void;
            #[link_name = "free"]
            fn libc_free(p: *mut c_void);
        }
        assert!(rs::BrotliSharedDictionaryCreateInstance(Some(my_alloc), None, std::ptr::null_mut()).is_null());
        assert!(cref::ref_BrotliSharedDictionaryCreateInstance(Some(my_alloc), None, std::ptr::null_mut()).is_null());
        assert!(rs::BrotliSharedDictionaryCreateInstance(None, Some(my_free), std::ptr::null_mut()).is_null());
        assert!(cref::ref_BrotliSharedDictionaryCreateInstance(None, Some(my_free), std::ptr::null_mut()).is_null());
        assert_eq!(rs::BrotliSharedDictionaryAttach(std::ptr::null_mut(), 0, 1, data.as_ptr()), 0);
        assert_eq!(cref::ref_BrotliSharedDictionaryAttach(std::ptr::null_mut(), 0, 1, data.as_ptr()), 0);
        for (alloc, free) in [(None, None), (Some(my_alloc as unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void), Some(my_free as unsafe extern "C" fn(*mut c_void, *mut c_void)))] {
            let a = rs::BrotliSharedDictionaryCreateInstance(alloc, free, std::ptr::null_mut());
            let b = cref::ref_BrotliSharedDictionaryCreateInstance(alloc, free, std::ptr::null_mut());
            assert!(!a.is_null() && !b.is_null());
            for i in 0..20 {
                let t = if i % 7 == 3 { 1 } else if i % 11 == 5 { 2 } else { 0 };
                assert_eq!(
                    rs::BrotliSharedDictionaryAttach(a, t, i, data.as_ptr()),
                    cref::ref_BrotliSharedDictionaryAttach(b, t, i, data.as_ptr()),
                    "attach #{} type {}", i, t
                );
            }
            rs::BrotliSharedDictionaryDestroyInstance(a);
            cref::ref_BrotliSharedDictionaryDestroyInstance(b);
        }
        rs::BrotliSharedDictionaryDestroyInstance(std::ptr::null_mut());
        // Default allocator exports.
        let p = rs::BrotliDefaultAllocFunc(std::ptr::null_mut(), 64);
        assert!(!p.is_null());
        rs::BrotliDefaultFreeFunc(std::ptr::null_mut(), p);
    }
}
