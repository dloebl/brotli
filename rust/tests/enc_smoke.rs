//! Smoke test: Rust one-shot encoder output == C reference output.
#![cfg(feature = "c-reference")]
mod cref;

fn rust_compress(q: i32, lgwin: i32, mode: i32, input: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; brotli::enc::encode::brotli_encoder_max_compressed_size(input.len()).max(1024) + 1024];
    let mut size = out.len();
    if brotli::enc::encode::brotli_encoder_compress(q, lgwin, mode as u32, input, &mut size, &mut out) {
        out.truncate(size);
        Some(out)
    } else {
        None
    }
}

#[test]
fn one_shot_matches_c() {
    let mut inputs: Vec<Vec<u8>> = vec![Vec::new(), b"a".to_vec(), b"hello hello hello world".to_vec()];
    for name in ["alice29.txt", "asyoulik.txt", "plrabn12.txt", "x", "xyzzy", "64x", "ukkonooa", "random_org_10k.bin", "mapsdatazrh"] {
        if let Ok(d) = std::fs::read(format!("../tests/testdata/{}", name)) {
            inputs.push(d);
        }
    }
    let mut x: u32 = 1;
    inputs.push((0..300000).map(|_| { x = x.wrapping_mul(1103515245).wrapping_add(12345); (x >> 16) as u8 & 0x0F }).collect());
    for input in &inputs {
        for q in 0..=11 {
            for lgwin in [10, 16, 18, 22, 24] {
                let c = cref::compress(q, lgwin, 0, input).unwrap();
                let r = rust_compress(q, lgwin, 0, input).unwrap();
                assert!(c == r, "mismatch q={} lgwin={} len={} (c {} bytes, rust {} bytes)", q, lgwin, input.len(), c.len(), r.len());
            }
        }
    }
}
