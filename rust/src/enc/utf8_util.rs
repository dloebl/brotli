//! Port of `c/enc/utf8_util.c`.

pub const K_MIN_UTF8_RATIO: f64 = 0.75;

/// `BrotliParseAsUTF8`: returns `(symbol, bytes_read)`.
fn parse_as_utf8(input: &[u8], size: usize) -> (i32, usize) {
    let i0 = input[0] as i32;
    // ASCII
    if (i0 & 0x80) == 0 {
        if i0 > 0 {
            return (i0, 1);
        }
    }
    // 2-byte UTF8
    if size > 1 && (i0 & 0xE0) == 0xC0 && (input[1] & 0xC0) == 0x80 {
        let symbol = ((i0 & 0x1F) << 6) | (input[1] as i32 & 0x3F);
        if symbol > 0x7F {
            return (symbol, 2);
        }
    }
    // 3-byte UFT8
    if size > 2 && (i0 & 0xF0) == 0xE0 && (input[1] & 0xC0) == 0x80 && (input[2] & 0xC0) == 0x80 {
        let symbol = ((i0 & 0x0F) << 12) | ((input[1] as i32 & 0x3F) << 6) | (input[2] as i32 & 0x3F);
        if symbol > 0x7FF {
            return (symbol, 3);
        }
    }
    // 4-byte UFT8
    if size > 3
        && (i0 & 0xF8) == 0xF0
        && (input[1] & 0xC0) == 0x80
        && (input[2] & 0xC0) == 0x80
        && (input[3] & 0xC0) == 0x80
    {
        let symbol = ((i0 & 0x07) << 18)
            | ((input[1] as i32 & 0x3F) << 12)
            | ((input[2] as i32 & 0x3F) << 6)
            | (input[3] as i32 & 0x3F);
        if symbol > 0xFFFF && symbol <= 0x10FFFF {
            return (symbol, 4);
        }
    }
    // Not UTF8, emit a special symbol above the UTF8-code space
    (0x110000 | i0, 1)
}

/// `BrotliIsMostlyUTF8`: true if at least `min_fraction` of the data is
/// UTF8-encoded.  `data` is a ring buffer addressed with `(pos + i) & mask`.
pub fn brotli_is_mostly_utf8(data: &[u8], pos: usize, mask: usize, length: usize, min_fraction: f64) -> bool {
    let mut size_utf8: usize = 0;
    let mut i: usize = 0;
    let mut tmp = [0u8; 4];
    while i < length {
        let start = (pos + i) & mask;
        // The C code reads up to 4 bytes starting at the masked position
        // (without re-masking); bytes beyond `length - i` are not examined.
        let avail = (length - i).min(4);
        let n = avail.min(data.len() - start);
        tmp[..n].copy_from_slice(&data[start..start + n]);
        for b in tmp[n..].iter_mut() {
            *b = 0;
        }
        let (symbol, bytes_read) = parse_as_utf8(&tmp, length - i);
        i += bytes_read;
        if symbol < 0x110000 {
            size_utf8 += bytes_read;
        }
    }
    (size_utf8 as f64) > min_fraction * (length as f64)
}
