//! Port of `c/common/transform.h` / `transform.c`: RFC 7932 word transforms.

use super::tables::{TRANSFORMS_CUTOFF, TRANSFORMS_DATA, TRANSFORM_PREFIX_SUFFIX, TRANSFORM_PREFIX_SUFFIX_MAP};

pub const BROTLI_TRANSFORM_IDENTITY: u8 = 0;
pub const BROTLI_TRANSFORM_OMIT_LAST_1: u8 = 1;
pub const BROTLI_TRANSFORM_OMIT_LAST_2: u8 = 2;
pub const BROTLI_TRANSFORM_OMIT_LAST_3: u8 = 3;
pub const BROTLI_TRANSFORM_OMIT_LAST_4: u8 = 4;
pub const BROTLI_TRANSFORM_OMIT_LAST_5: u8 = 5;
pub const BROTLI_TRANSFORM_OMIT_LAST_6: u8 = 6;
pub const BROTLI_TRANSFORM_OMIT_LAST_7: u8 = 7;
pub const BROTLI_TRANSFORM_OMIT_LAST_8: u8 = 8;
pub const BROTLI_TRANSFORM_OMIT_LAST_9: u8 = 9;
pub const BROTLI_TRANSFORM_UPPERCASE_FIRST: u8 = 10;
pub const BROTLI_TRANSFORM_UPPERCASE_ALL: u8 = 11;
pub const BROTLI_TRANSFORM_OMIT_FIRST_1: u8 = 12;
pub const BROTLI_TRANSFORM_OMIT_FIRST_2: u8 = 13;
pub const BROTLI_TRANSFORM_OMIT_FIRST_3: u8 = 14;
pub const BROTLI_TRANSFORM_OMIT_FIRST_4: u8 = 15;
pub const BROTLI_TRANSFORM_OMIT_FIRST_5: u8 = 16;
pub const BROTLI_TRANSFORM_OMIT_FIRST_6: u8 = 17;
pub const BROTLI_TRANSFORM_OMIT_FIRST_7: u8 = 18;
pub const BROTLI_TRANSFORM_OMIT_FIRST_8: u8 = 19;
pub const BROTLI_TRANSFORM_OMIT_FIRST_9: u8 = 20;
pub const BROTLI_TRANSFORM_SHIFT_FIRST: u8 = 21;
pub const BROTLI_TRANSFORM_SHIFT_ALL: u8 = 22;
pub const BROTLI_NUM_TRANSFORM_TYPES: u8 = 23;

pub const BROTLI_TRANSFORMS_MAX_CUT_OFF: usize = BROTLI_TRANSFORM_OMIT_LAST_9 as usize;

/// `BrotliTransforms`; layout-compatible with the C struct (exported through
/// `BrotliGetTransforms`).
#[repr(C)]
#[derive(Debug)]
pub struct BrotliTransforms {
    pub prefix_suffix_size: u16,
    /// Last character must be null, so prefix_suffix_size must be at least 1.
    pub prefix_suffix: *const u8,
    pub prefix_suffix_map: *const u16,
    pub num_transforms: u32,
    /// Each entry is a [prefix_id, transform, suffix_id] triplet.
    pub transforms: *const u8,
    /// Shift parameters (2 bytes per transform); NULL iff no shift
    /// transforms are present.
    pub params: *const u8,
    /// Indices of transforms like ["", BROTLI_TRANSFORM_OMIT_LAST_#, ""];
    /// -1 if the cut-off transform does not exist.
    pub cut_off_transforms: [i16; BROTLI_TRANSFORMS_MAX_CUT_OFF + 1],
}

unsafe impl Sync for BrotliTransforms {}
unsafe impl Send for BrotliTransforms {}

pub static BROTLI_TRANSFORMS: BrotliTransforms = BrotliTransforms {
    prefix_suffix_size: TRANSFORM_PREFIX_SUFFIX.len() as u16,
    prefix_suffix: TRANSFORM_PREFIX_SUFFIX.as_ptr(),
    prefix_suffix_map: TRANSFORM_PREFIX_SUFFIX_MAP.as_ptr(),
    num_transforms: (TRANSFORMS_DATA.len() / 3) as u32,
    transforms: TRANSFORMS_DATA.as_ptr(),
    params: core::ptr::null(),
    cut_off_transforms: TRANSFORMS_CUTOFF,
};

/// `BrotliGetTransforms`.
#[inline]
pub fn brotli_get_transforms() -> &'static BrotliTransforms {
    &BROTLI_TRANSFORMS
}

impl BrotliTransforms {
    /// `BROTLI_TRANSFORM_PREFIX_ID(T, I)`
    #[inline]
    pub fn prefix_id(&self, i: usize) -> u8 {
        unsafe { *self.transforms.add(i * 3) }
    }
    /// `BROTLI_TRANSFORM_TYPE(T, I)`
    #[inline]
    pub fn transform_type(&self, i: usize) -> u8 {
        unsafe { *self.transforms.add(i * 3 + 1) }
    }
    /// `BROTLI_TRANSFORM_SUFFIX_ID(T, I)`
    #[inline]
    pub fn suffix_id(&self, i: usize) -> u8 {
        unsafe { *self.transforms.add(i * 3 + 2) }
    }
    /// Pointer to the length-prefixed prefix string of transform `i`.
    #[inline]
    pub fn prefix_ptr(&self, i: usize) -> *const u8 {
        unsafe { self.prefix_suffix.add(*self.prefix_suffix_map.add(self.prefix_id(i) as usize) as usize) }
    }
    /// Pointer to the length-prefixed suffix string of transform `i`.
    #[inline]
    pub fn suffix_ptr(&self, i: usize) -> *const u8 {
        unsafe { self.prefix_suffix.add(*self.prefix_suffix_map.add(self.suffix_id(i) as usize) as usize) }
    }
    /// Prefix string (without the length byte) of transform `i`.
    #[inline]
    pub fn prefix(&self, i: usize) -> &[u8] {
        unsafe {
            let p = self.prefix_ptr(i);
            core::slice::from_raw_parts(p.add(1), *p as usize)
        }
    }
    /// Suffix string (without the length byte) of transform `i`.
    #[inline]
    pub fn suffix(&self, i: usize) -> &[u8] {
        unsafe {
            let p = self.suffix_ptr(i);
            core::slice::from_raw_parts(p.add(1), *p as usize)
        }
    }
}

/// `ToUpperCase`: returns the number of bytes consumed (1..=3).
/// May touch up to 3 bytes starting at `p`.
#[inline]
unsafe fn to_upper_case(p: *mut u8) -> i32 {
    if *p < 0xC0 {
        if *p >= b'a' && *p <= b'z' {
            *p ^= 32;
        }
        return 1;
    }
    // An overly simplified uppercasing model for UTF-8.
    if *p < 0xE0 {
        *p.add(1) ^= 32;
        return 2;
    }
    // An arbitrary transform for three byte characters.
    *p.add(2) ^= 5;
    3
}

/// `Shift`.
unsafe fn shift(word: *mut u8, word_len: i32, parameter: u16) -> i32 {
    // Limited sign extension: scalar < (1 << 24).
    let mut scalar: u32 = (parameter as u32 & 0x7FFF).wrapping_add(0x1000000u32.wrapping_sub(parameter as u32 & 0x8000));
    let w0 = *word;
    if w0 < 0x80 {
        // 1-byte rune / 0sssssss / 7 bit scalar (ASCII).
        scalar = scalar.wrapping_add(w0 as u32);
        *word = (scalar & 0x7F) as u8;
        1
    } else if w0 < 0xC0 {
        // Continuation / 10AAAAAA.
        1
    } else if w0 < 0xE0 {
        // 2-byte rune / 110sssss AAssssss / 11 bit scalar.
        if word_len < 2 {
            return 1;
        }
        let w1 = *word.add(1);
        scalar = scalar.wrapping_add((w1 as u32 & 0x3F) | ((w0 as u32 & 0x1F) << 6));
        *word = (0xC0 | ((scalar >> 6) & 0x1F)) as u8;
        *word.add(1) = ((w1 as u32 & 0xC0) | (scalar & 0x3F)) as u8;
        2
    } else if w0 < 0xF0 {
        // 3-byte rune / 1110ssss AAssssss BBssssss / 16 bit scalar.
        if word_len < 3 {
            return word_len;
        }
        let w1 = *word.add(1);
        let w2 = *word.add(2);
        scalar = scalar.wrapping_add((w2 as u32 & 0x3F) | ((w1 as u32 & 0x3F) << 6) | ((w0 as u32 & 0x0F) << 12));
        *word = (0xE0 | ((scalar >> 12) & 0x0F)) as u8;
        *word.add(1) = ((w1 as u32 & 0xC0) | ((scalar >> 6) & 0x3F)) as u8;
        *word.add(2) = ((w2 as u32 & 0xC0) | (scalar & 0x3F)) as u8;
        3
    } else if w0 < 0xF8 {
        // 4-byte rune / 11110sss AAssssss BBssssss CCssssss / 21 bit scalar.
        if word_len < 4 {
            return word_len;
        }
        let w1 = *word.add(1);
        let w2 = *word.add(2);
        let w3 = *word.add(3);
        scalar = scalar.wrapping_add(
            (w3 as u32 & 0x3F) | ((w2 as u32 & 0x3F) << 6) | ((w1 as u32 & 0x3F) << 12) | ((w0 as u32 & 0x07) << 18),
        );
        *word = (0xF0 | ((scalar >> 18) & 0x07)) as u8;
        *word.add(1) = ((w1 as u32 & 0xC0) | ((scalar >> 12) & 0x3F)) as u8;
        *word.add(2) = ((w2 as u32 & 0xC0) | ((scalar >> 6) & 0x3F)) as u8;
        *word.add(3) = ((w3 as u32 & 0xC0) | (scalar & 0x3F)) as u8;
        4
    } else {
        1
    }
}

/// `BrotliTransformDictionaryWord` (raw-pointer version, exact C semantics).
///
/// # Safety
/// `dst` must have room for the transformed word plus 2 bytes of slack
/// (upper-casing may touch bytes past the end); `word` must be readable for
/// `len` bytes; `transform_idx` must be valid for `transforms`.
pub unsafe fn transform_dictionary_word_raw(
    dst: *mut u8,
    mut word: *const u8,
    mut len: i32,
    transforms: &BrotliTransforms,
    transform_idx: i32,
) -> i32 {
    let ti = transform_idx as usize;
    let mut idx: i32 = 0;
    let mut prefix = transforms.prefix_ptr(ti);
    let t = transforms.transform_type(ti);
    let mut suffix = transforms.suffix_ptr(ti);
    {
        let mut prefix_len = *prefix as i32;
        prefix = prefix.add(1);
        while prefix_len > 0 {
            prefix_len -= 1;
            *dst.offset(idx as isize) = *prefix;
            idx += 1;
            prefix = prefix.add(1);
        }
    }
    {
        let t = t as i32;
        let mut i: i32 = 0;
        if t <= BROTLI_TRANSFORM_OMIT_LAST_9 as i32 {
            len -= t;
        } else if t >= BROTLI_TRANSFORM_OMIT_FIRST_1 as i32 && t <= BROTLI_TRANSFORM_OMIT_FIRST_9 as i32 {
            let skip = t - (BROTLI_TRANSFORM_OMIT_FIRST_1 as i32 - 1);
            word = word.offset(skip as isize);
            len -= skip;
        }
        while i < len {
            *dst.offset(idx as isize) = *word.offset(i as isize);
            idx += 1;
            i += 1;
        }
        if t == BROTLI_TRANSFORM_UPPERCASE_FIRST as i32 {
            to_upper_case(dst.offset((idx - len) as isize));
        } else if t == BROTLI_TRANSFORM_UPPERCASE_ALL as i32 {
            let mut uppercase = dst.offset((idx - len) as isize);
            while len > 0 {
                let step = to_upper_case(uppercase);
                uppercase = uppercase.offset(step as isize);
                len -= step;
            }
        } else if t == BROTLI_TRANSFORM_SHIFT_FIRST as i32 {
            let param = (*transforms.params.add(ti * 2) as u16)
                .wrapping_add((*transforms.params.add(ti * 2 + 1) as u16) << 8);
            shift(dst.offset((idx - len) as isize), len, param);
        } else if t == BROTLI_TRANSFORM_SHIFT_ALL as i32 {
            let param = (*transforms.params.add(ti * 2) as u16)
                .wrapping_add((*transforms.params.add(ti * 2 + 1) as u16) << 8);
            let mut sh = dst.offset((idx - len) as isize);
            while len > 0 {
                let step = shift(sh, len, param);
                sh = sh.offset(step as isize);
                len -= step;
            }
        }
    }
    {
        let mut suffix_len = *suffix as i32;
        suffix = suffix.add(1);
        while suffix_len > 0 {
            suffix_len -= 1;
            *dst.offset(idx as isize) = *suffix;
            idx += 1;
            suffix = suffix.add(1);
        }
        idx
    }
}

/// Upper bound of bytes written/touched by [`transform_dictionary_word`]
/// for a word of length `len` with transform `transform_idx`.
#[inline]
pub fn transform_dictionary_word_max_len(len: usize, transforms: &BrotliTransforms, transform_idx: usize) -> usize {
    transforms.prefix(transform_idx).len() + len + transforms.suffix(transform_idx).len() + 3
}

/// Safe wrapper of `BrotliTransformDictionaryWord`.
///
/// Panics if `dst` is not large enough for the transformed word plus slack
/// (see [`transform_dictionary_word_max_len`]) or if `word` is too short.
pub fn transform_dictionary_word(dst: &mut [u8], word: &[u8], len: i32, transforms: &BrotliTransforms, transform_idx: i32) -> i32 {
    assert!(transform_idx >= 0 && (transform_idx as u32) < transforms.num_transforms);
    assert!(len >= 0 && word.len() >= len as usize);
    let need = transform_dictionary_word_max_len(len as usize, transforms, transform_idx as usize);
    assert!(dst.len() >= need);
    unsafe { transform_dictionary_word_raw(dst.as_mut_ptr(), word.as_ptr(), len, transforms, transform_idx) }
}
