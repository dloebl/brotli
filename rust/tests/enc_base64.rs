//! Base64 mode: streams must always decode (regression for a bug inherited
//! from the C reference, where a duplicated base64 region made the forced
//! base64 literal block cover non-base64 literals).
#![cfg(feature = "c-reference")]
mod cref;

use brotli::ffi::enc as rs;

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

pub fn base64_test_data(seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s: Vec<u8> = (0..3000).map(|_| B64[rng.below(64) as usize]).collect();
    let mut data = Vec::new();
    for i in 0..4 {
        data.extend_from_slice(b"some text here, <img src=\"data:image/png");
        for _ in 0..8 {
            data.push(b'a' + rng.below(26) as u8);
        }
        data.extend_from_slice(b";base64,");
        data.extend_from_slice(&s);
        data.extend_from_slice(b"\"> and more text!!! ... ;;; ,,, ");
        for _ in 0..(2000 * (i + 1)) {
            data.push(b" .,;:!?-_\n\"'()[]{}<>@#%^&*~"[rng.below(27) as usize]);
        }
    }
    data
}

pub fn compress_rust(q: u32, data: &[u8], min_region: u32) -> Vec<u8> {
    unsafe {
        let s = rs::BrotliEncoderCreateInstance(None, None, std::ptr::null_mut());
        rs::BrotliEncoderSetParameter(s, 1, q);
        rs::BrotliEncoderSetParameter(s, 2, 22);
        rs::BrotliEncoderSetParameter(s, 10, 1); // BASE64_MODE
        rs::BrotliEncoderSetParameter(s, 11, 16); // MAX_BASE64_REGIONS
        rs::BrotliEncoderSetParameter(s, 14, min_region); // MIN_BASE64_REGION_LEN
        let mut out = vec![0u8; data.len() * 2 + 1024];
        let mut ai = data.len();
        let mut ni = data.as_ptr();
        let mut ao = out.len();
        let mut no = out.as_mut_ptr();
        assert_eq!(rs::BrotliEncoderCompressStream(s, 2, &mut ai, &mut ni, &mut ao, &mut no, std::ptr::null_mut()), 1);
        let n = out.len() - ao;
        out.truncate(n);
        rs::BrotliEncoderDestroyInstance(s);
        out
    }
}

pub fn compress_c(q: u32, data: &[u8], min_region: u32) -> Vec<u8> {
    unsafe {
        let s = cref::ref_BrotliEncoderCreateInstance(None, None, std::ptr::null_mut());
        cref::ref_BrotliEncoderSetParameter(s, 1, q);
        cref::ref_BrotliEncoderSetParameter(s, 2, 22);
        cref::ref_BrotliEncoderSetParameter(s, 10, 1);
        cref::ref_BrotliEncoderSetParameter(s, 11, 16);
        cref::ref_BrotliEncoderSetParameter(s, 14, min_region);
        let mut out = vec![0u8; data.len() * 2 + 1024];
        let mut ai = data.len();
        let mut ni = data.as_ptr();
        let mut ao = out.len();
        let mut no = out.as_mut_ptr();
        assert_eq!(cref::ref_BrotliEncoderCompressStream(s, 2, &mut ai, &mut ni, &mut ao, &mut no, std::ptr::null_mut()), 1);
        let n = out.len() - ao;
        out.truncate(n);
        cref::ref_BrotliEncoderDestroyInstance(s);
        out
    }
}

#[test]
fn base64_dupe_regions_roundtrip() {
    for seed in [42u64, 1, 2, 3] {
        let data = base64_test_data(seed);
        for q in 2..=11 {
            for min_region in [0u32, 100, 2048] {
                let c = compress_rust(q, &data, min_region);
                let r = compress_c(q, &data, min_region);
                assert!(c == r, "seed {} q{} min_region {}: Rust != C", seed, q, min_region);
                let d = cref::decompress(&c);
                assert!(d.as_deref() == Some(&data[..]), "seed {} q{} min_region {}: Rust base64 stream does not round-trip", seed, q, min_region);
            }
        }
    }
}
