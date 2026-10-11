//! Decompresses all `tests/testdata/*.compressed*` files with the Rust
//! decoder and compares them with the originals.

use brotli::dec::{decompress, BrotliDecoderResult, Decoder};
use std::path::PathBuf;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("testdata")
}

fn cases() -> Vec<(PathBuf, PathBuf)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(testdata()).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if let Some(idx) = name.find(".compressed") {
            let orig = testdata().join(&name[..idx]);
            v.push((p, orig));
        }
    }
    v.sort();
    assert!(v.len() > 30);
    v
}

fn stream_decode(data: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut d = Decoder::new().unwrap();
    let mut out = Vec::new();
    let mut ip = 0;
    let mut buf = vec![0u8; out_chunk];
    loop {
        let end = (ip + in_chunk).min(data.len());
        let mut lip = 0;
        let mut op = 0;
        let r = d.decompress_stream(&data[ip..end], &mut lip, &mut buf, &mut op, None);
        ip += lip;
        out.extend_from_slice(&buf[..op]);
        match r {
            BrotliDecoderResult::Success => return out,
            BrotliDecoderResult::NeedsMoreInput => assert!(ip < data.len(), "truncated"),
            BrotliDecoderResult::NeedsMoreOutput => {}
            BrotliDecoderResult::Error => panic!("error {}", d.get_error_code()),
        }
    }
}

#[test]
fn decompress_testdata_one_shot() {
    for (c, o) in cases() {
        let data = std::fs::read(&c).unwrap();
        let expected = std::fs::read(&o).unwrap();
        let mut out = vec![0u8; expected.len() + 16];
        let (r, n) = decompress(&data, &mut out);
        assert_eq!(r, BrotliDecoderResult::Success, "{}", c.display());
        assert_eq!(&out[..n], &expected[..], "{}", c.display());
    }
}

#[test]
fn decompress_testdata_streaming() {
    for (c, o) in cases() {
        let data = std::fs::read(&c).unwrap();
        let expected = std::fs::read(&o).unwrap();
        for (ic, oc) in [(1usize, 1usize), (3, 7), (64, 1 << 16), (1 << 20, 1 << 20), (5000, 100)] {
            if expected.len() > 200000 && (ic < 8 || oc < 8) {
                continue;
            }
            let out = stream_decode(&data, ic, oc);
            assert_eq!(out, expected, "{} {} {}", c.display(), ic, oc);
        }
    }
}
