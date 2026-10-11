//! Decoder throughput: Rust vs C reference.
//!
//!     cargo run --release --features c-reference --example dec_bench

#[cfg(all(feature = "c-reference", feature = "ffi"))]
#[path = "../tests/cref/mod.rs"]
mod cref;
#[cfg(all(feature = "c-reference", feature = "ffi"))]
#[path = "../tests/dec_harness/mod.rs"]
mod dec_harness;

#[cfg(all(feature = "c-reference", feature = "ffi"))]
fn main() {
    use dec_harness::*;
    let originals = testdata_originals();
    let mut big = Vec::new();
    for (n, d) in &originals {
        if n.ends_with(".txt") || n == "mapsdatazrh" || n == "compressed_file" {
            big.extend_from_slice(d);
        }
    }
    for (q, w) in [(1u32, 22u32), (5, 22), (9, 22), (11, 22)] {
        let enc = encode_stream(&big, &EncodeSpec { quality: q, lgwin: w, ..Default::default() }, &[]);
        let mut out = vec![0u8; big.len() + 100];
        let reps = 20;
        let t = std::time::Instant::now();
        for _ in 0..reps {
            let mut size = out.len();
            let r = unsafe { cref::ref_BrotliDecoderDecompress(enc.len(), enc.as_ptr(), &mut size, out.as_mut_ptr()) };
            assert_eq!(r, 1);
        }
        let tc = t.elapsed().as_secs_f64();
        let t = std::time::Instant::now();
        for _ in 0..reps {
            let (r, n) = brotli::dec::decompress(&enc, &mut out);
            assert_eq!(r, brotli::dec::BrotliDecoderResult::Success);
            assert_eq!(n, big.len());
        }
        let tr = t.elapsed().as_secs_f64();
        let mb = (big.len() * reps) as f64 / 1e6;
        println!("q{q:2} w{w}: C {:7.1} MB/s  Rust {:7.1} MB/s  (ratio {:.2})", mb / tc, mb / tr, tc / tr);
    }
}

#[cfg(not(all(feature = "c-reference", feature = "ffi")))]
fn main() {}
