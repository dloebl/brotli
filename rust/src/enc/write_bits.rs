//! Port of `c/enc/write_bits.h`.

/// `BrotliWriteBits`: writes `n_bits` (<= 56) bits of `bits` at bit
/// position `*pos` of `array` (LSB first) and advances `*pos`.
///
/// Like the C version, the bytes following the current one are overwritten
/// (zero-initialized ahead); requires `array[*pos >> 3]` to be initialized.
#[inline(always)]
pub fn brotli_write_bits(n_bits: usize, bits: u64, pos: &mut usize, array: &mut [u8]) {
    debug_assert!(n_bits <= 56);
    debug_assert!(n_bits == 64 || (bits >> n_bits) == 0);
    let p = *pos >> 3;
    let v = (array[p] as u64) | (bits << (*pos & 7));
    if p + 8 <= array.len() {
        array[p..p + 8].copy_from_slice(&v.to_le_bytes());
    } else {
        // Near the end of the storage: write only the bytes that exist.
        let n = array.len() - p;
        array[p..].copy_from_slice(&v.to_le_bytes()[..n]);
    }
    *pos += n_bits;
}

/// `BrotliWriteBitsPrepareStorage`.
#[inline]
pub fn brotli_write_bits_prepare_storage(pos: usize, array: &mut [u8]) {
    debug_assert!((pos & 7) == 0);
    array[pos >> 3] = 0;
}
