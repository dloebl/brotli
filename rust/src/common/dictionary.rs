//! Port of `c/common/dictionary.h` / `dictionary.c`: the RFC 7932 static
//! dictionary.

/// Raw static dictionary data (122784 bytes), identical to
/// `kBrotliDictionaryData` of the C library.
pub static BROTLI_DICTIONARY_DATA: [u8; 122784] = *include_bytes!("dictionary.bin");

/// `BrotliDictionary`; layout-compatible with the C struct, because a
/// pointer to it is returned by the exported `BrotliGetDictionary`.
#[repr(C)]
#[derive(Debug)]
pub struct BrotliDictionary {
    /// Number of bits to encode index of dictionary word in a bucket.
    pub size_bits_by_length: [u8; 32],
    /// `offset[i + 1] == offset[i] + (bits[i] ? (i << bits[i]) : 0)`
    pub offsets_by_length: [u32; 32],
    /// `data_size == offsets_by_length[31]`
    pub data_size: usize,
    /// Dictionary words; length is `data_size`.
    pub data: *const u8,
}

// The dictionary is immutable static data.
unsafe impl Sync for BrotliDictionary {}
unsafe impl Send for BrotliDictionary {}

impl BrotliDictionary {
    /// The word data as a slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        if self.data.is_null() {
            return &[];
        }
        // SAFETY: `data` points to `data_size` readable bytes that live at
        // least as long as the dictionary itself.
        unsafe { core::slice::from_raw_parts(self.data, self.data_size) }
    }
}

pub static BROTLI_DICTIONARY: BrotliDictionary = BrotliDictionary {
    size_bits_by_length: [
        0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5, 0, 0, 0, 0, 0, 0, 0,
    ],
    offsets_by_length: [
        0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864, 104704,
        106752, 108928, 113536, 115968, 118528, 119872, 121280, 122016, 122784, 122784, 122784, 122784,
        122784, 122784, 122784,
    ],
    data_size: 122784,
    data: BROTLI_DICTIONARY_DATA.as_ptr(),
};

/// `BrotliGetDictionary`.
#[inline]
pub fn brotli_get_dictionary() -> &'static BrotliDictionary {
    &BROTLI_DICTIONARY
}

pub const BROTLI_MIN_DICTIONARY_WORD_LENGTH: usize = 4;
pub const BROTLI_MAX_DICTIONARY_WORD_LENGTH: usize = 24;
