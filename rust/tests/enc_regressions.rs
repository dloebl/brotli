//! Regression tests for differences found by the differential fuzzers.
#![cfg(feature = "c-reference")]
mod cref;

use brotli::ffi::enc as rs;
use std::ffi::c_void;

type Stream = unsafe extern "C" fn(*mut c_void, i32, *mut usize, *mut *const u8, *mut usize, *mut *mut u8, *mut usize) -> i32;

unsafe fn call(f: Stream, s: *mut c_void, op: i32, input: &[u8], out: &mut [u8]) -> (i32, usize, Vec<u8>) {
    let mut ai = input.len();
    let mut ni = input.as_ptr();
    let mut ao = out.len();
    let mut no = out.as_mut_ptr();
    let r = f(s, op, &mut ai, &mut ni, &mut ao, &mut no, std::ptr::null_mut());
    (r, input.len() - ai, out[..out.len() - ao].to_vec())
}

/// q0/q1: after a metadata block was drained through the 16-byte tiny_buf_,
/// a flush needing padding used to write past tiny_buf_ in C (clobbering
/// remaining_metadata_bytes_ and breaking the stream).  Fixed in both.
#[test]
fn flush_padding_after_metadata_tiny_buf() {
    for q in [0u32, 1] {
        unsafe {
            let a = rs::BrotliEncoderCreateInstance(None, None, std::ptr::null_mut()) as *mut c_void;
            let b = cref::ref_BrotliEncoderCreateInstance(None, None, std::ptr::null_mut());
            let fa: Stream = std::mem::transmute(rs::BrotliEncoderCompressStream as *const ());
            let fb: Stream = std::mem::transmute(cref::ref_BrotliEncoderCompressStream as *const ());
            rs::BrotliEncoderSetParameter(a as *mut _, 1, q);
            cref::ref_BrotliEncoderSetParameter(b, 1, q);
            let meta = vec![b'M'; 3207];
            let data: Vec<u8> = (0..8205u32).map(|i| (i * 13 ^ (i >> 3)) as u8).collect();
            let mut out_a = vec![0u8; 1 << 18];
            let mut out_b = vec![0u8; 1 << 18];
            let mut stream = Vec::new();
            // Metadata: first with a small output buffer, then the rest.
            let (ra, ca, oa) = call(fa, a, 3, &meta, &mut out_a[..162]);
            let (rb, cb, ob) = call(fb, b, 3, &meta, &mut out_b[..162]);
            assert_eq!((ra, ca, &oa), (rb, cb, &ob));
            stream.extend_from_slice(&oa);
            let (ra, ca2, oa) = call(fa, a, 3, &meta[ca..], &mut out_a);
            let (rb, cb2, ob) = call(fb, b, 3, &meta[cb..], &mut out_b);
            assert_eq!((ra, ca2, &oa), (rb, cb2, &ob));
            stream.extend_from_slice(&oa);
            for op in [1, 2] {
                let input: &[u8] = if op == 1 { &data } else { &[] };
                let (ra, ca, oa) = call(fa, a, op, input, &mut out_a);
                let (rb, cb, ob) = call(fb, b, op, input, &mut out_b);
                assert_eq!((ra, ca, &oa), (rb, cb, &ob), "q{} op {}", q, op);
                assert_eq!(ra, 1, "q{} op {} must succeed", q, op);
                stream.extend_from_slice(&oa);
            }
            assert_eq!(rs::BrotliEncoderIsFinished(a as *mut _), 1);
            assert_eq!(cref::decompress(&stream).unwrap(), data);
            rs::BrotliEncoderDestroyInstance(a as *mut _);
            cref::ref_BrotliEncoderDestroyInstance(b);
        }
    }
}
