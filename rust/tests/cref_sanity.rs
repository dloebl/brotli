//! Sanity check of the C reference bindings.
#![cfg(feature = "c-reference")]
mod cref;

#[test]
fn c_reference_roundtrip() {
    let data: Vec<u8> = (0..100000u32).map(|i| ((i * 7) % 251) as u8 ^ (i >> 9) as u8).collect();
    for q in [0, 1, 5, 9, 11] {
        let c = cref::compress(q, 22, 0, &data).unwrap();
        assert_eq!(cref::decompress(&c).unwrap(), data);
    }
}
