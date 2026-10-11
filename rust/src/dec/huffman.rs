//! Port of `c/dec/huffman.h` / `huffman.c`: building Huffman decoding
//! tables.

use super::bit_reader::Reg;
use super::tables::K_REVERSE_BITS;
use crate::common::alloc::Buf;
use crate::common::constants::BROTLI_CODE_LENGTH_CODES;

pub const BROTLI_HUFFMAN_MAX_CODE_LENGTH: i32 = 15;

/// BROTLI_NUM_BLOCK_LEN_SYMBOLS == 26
pub const BROTLI_HUFFMAN_MAX_SIZE_26: usize = 396;
/// BROTLI_MAX_BLOCK_TYPE_SYMBOLS == 258
pub const BROTLI_HUFFMAN_MAX_SIZE_258: usize = 632;
/// BROTLI_MAX_CONTEXT_MAP_SYMBOLS == 272
pub const BROTLI_HUFFMAN_MAX_SIZE_272: usize = 646;

pub const BROTLI_HUFFMAN_MAX_CODE_LENGTH_CODE_LENGTH: i32 = 5;

const BROTLI_REVERSE_BITS_MAX: u32 = 8;
const BROTLI_REVERSE_BITS_LOWEST: Reg = (1 as Reg) << (BROTLI_REVERSE_BITS_MAX - 1);

/// `HuffmanCode`, in the packed 32-bit representation used by C with
/// `BROTLI_HUFFMAN_CODE_FAST_LOAD`: `(value << 16) | bits`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct HuffmanCode(pub u32);

impl HuffmanCode {
    /// `ConstructHuffmanCode`.
    #[inline(always)]
    pub fn new(bits: u8, value: u16) -> HuffmanCode {
        HuffmanCode(((value as u32) << 16) | bits as u32)
    }
    /// number of bits used for this symbol
    #[inline(always)]
    pub fn bits(self) -> Reg {
        (self.0 & 0xFF) as Reg
    }
    /// symbol value or table offset
    #[inline(always)]
    pub fn value(self) -> Reg {
        (self.0 >> 16) as Reg
    }
}

/// `BrotliReverseBits`: reverse of the 8 least significant bits.
#[inline(always)]
fn brotli_reverse_bits(num: Reg) -> usize {
    K_REVERSE_BITS[(num & 0xFF) as usize] as usize
}

/// `ReplicateValue`: stores `code` in `table[0], table[step], ...,
/// table[end - step]`.  Assumes that end is an integer multiple of step.
#[inline(always)]
fn replicate_value(table: &mut [HuffmanCode], step: i32, mut end: i32, code: HuffmanCode) {
    loop {
        end -= step;
        table[end as usize] = code;
        if end <= 0 {
            break;
        }
    }
}

/// `NextTableBitSize`: returns the table width of the next 2nd level table.
/// `count` is the histogram of bit lengths for the remaining symbols, `len`
/// is the code length of the next processed symbol.
#[inline(always)]
fn next_table_bit_size(count: &[u16; 16], mut len: i32, root_bits: i32) -> i32 {
    let mut left: i32 = 1 << (len - root_bits);
    while len < BROTLI_HUFFMAN_MAX_CODE_LENGTH {
        left -= count[len as usize] as i32;
        if left <= 0 {
            break;
        }
        len += 1;
        left <<= 1;
    }
    len - root_bits
}

/// `BrotliBuildCodeLengthsHuffmanTable`: builds a Huffman lookup table
/// assuming code lengths are in symbol order.
pub fn brotli_build_code_lengths_huffman_table(
    table: &mut [HuffmanCode],
    code_lengths: &[u8; BROTLI_CODE_LENGTH_CODES],
    count: &[u16; 16],
) {
    let mut sorted = [0i32; BROTLI_CODE_LENGTH_CODES]; // symbols sorted by code length
    // offsets in sorted table for each length
    let mut offset = [0i32; (BROTLI_HUFFMAN_MAX_CODE_LENGTH_CODE_LENGTH + 1) as usize];

    // Generate offsets into sorted symbol table by code length.
    let mut symbol: i32 = -1;
    let mut bits: i32 = 1;
    // BROTLI_HUFFMAN_MAX_CODE_LENGTH_CODE_LENGTH == 5
    for _ in 0..5 {
        symbol += count[bits as usize] as i32;
        offset[bits as usize] = symbol;
        bits += 1;
    }
    // Symbols with code length 0 are placed after all other symbols.
    offset[0] = BROTLI_CODE_LENGTH_CODES as i32 - 1;

    // Sort symbols by length, by symbol order within each length.
    symbol = BROTLI_CODE_LENGTH_CODES as i32;
    loop {
        for _ in 0..6 {
            symbol -= 1;
            let cl = code_lengths[symbol as usize] as usize;
            sorted[offset[cl] as usize] = symbol;
            offset[cl] -= 1;
        }
        if symbol == 0 {
            break;
        }
    }

    let table_size: i32 = 1 << BROTLI_HUFFMAN_MAX_CODE_LENGTH_CODE_LENGTH;

    // Special case: all symbols but one have 0 code length.
    if offset[0] == 0 {
        let code = HuffmanCode::new(0, sorted[0] as u16);
        for key in 0..table_size as usize {
            table[key] = code;
        }
        return;
    }

    // Fill in table.
    let mut key: Reg = 0;
    let mut key_step: Reg = BROTLI_REVERSE_BITS_LOWEST;
    symbol = 0;
    bits = 1;
    let mut step: i32 = 2;
    loop {
        let mut bits_count = count[bits as usize] as i32;
        while bits_count != 0 {
            let code = HuffmanCode::new(bits as u8, sorted[symbol as usize] as u16);
            symbol += 1;
            replicate_value(&mut table[brotli_reverse_bits(key)..], step, table_size, code);
            key += key_step;
            bits_count -= 1;
        }
        step <<= 1;
        key_step >>= 1;
        bits += 1;
        if bits > BROTLI_HUFFMAN_MAX_CODE_LENGTH_CODE_LENGTH {
            break;
        }
    }
}

/// `BrotliBuildHuffmanTable`: builds a Huffman lookup table assuming code
/// lengths are in symbol order.  Returns size of resulting table.
///
/// `symbol_lists` is addressed with negative indices in C; here
/// `symbol_lists[base + idx]` corresponds to C `symbol_lists[idx]`.
pub fn brotli_build_huffman_table(
    root_table: &mut [HuffmanCode],
    root_bits: i32,
    symbol_lists: &[u16],
    base: i32,
    count: &mut [u16; 16],
) -> u32 {
    let sl = |i: i32| -> i32 { symbol_lists[(base + i) as usize] as i32 };
    let mut max_length: i32 = -1;

    debug_assert!(root_bits as u32 <= BROTLI_REVERSE_BITS_MAX);
    debug_assert!((BROTLI_HUFFMAN_MAX_CODE_LENGTH - root_bits) as u32 <= BROTLI_REVERSE_BITS_MAX);

    while sl(max_length) == 0xFFFF {
        max_length -= 1;
    }
    max_length += BROTLI_HUFFMAN_MAX_CODE_LENGTH + 1;

    let mut table: usize = 0; // offset of the current table in root_table
    let mut table_bits: i32 = root_bits;
    let mut table_size: i32 = 1 << table_bits;
    let mut total_size: i32 = table_size;

    // Fill in the root table. Reduce the table size to if possible,
    // and create the repetitions by memcpy.
    if table_bits > max_length {
        table_bits = max_length;
        table_size = 1 << table_bits;
    }
    let mut key: Reg = 0;
    let mut key_step: Reg = BROTLI_REVERSE_BITS_LOWEST;
    let mut bits: i32 = 1;
    let mut step: i32 = 2;
    loop {
        let mut symbol = bits - (BROTLI_HUFFMAN_MAX_CODE_LENGTH + 1);
        let mut bits_count = count[bits as usize] as i32;
        while bits_count != 0 {
            symbol = sl(symbol);
            let code = HuffmanCode::new(bits as u8, symbol as u16);
            replicate_value(&mut root_table[table + brotli_reverse_bits(key)..], step, table_size, code);
            key += key_step;
            bits_count -= 1;
        }
        step <<= 1;
        key_step >>= 1;
        bits += 1;
        if bits > table_bits {
            break;
        }
    }

    // If root_bits != table_bits then replicate to fill the remaining slots.
    while total_size != table_size {
        let ts = table_size as usize;
        root_table.copy_within(table..table + ts, table + ts);
        table_size <<= 1;
    }

    // Fill in 2nd level tables and add pointers to root table.
    key_step = BROTLI_REVERSE_BITS_LOWEST >> (root_bits - 1);
    let mut sub_key: Reg = BROTLI_REVERSE_BITS_LOWEST << 1;
    let mut sub_key_step: Reg = BROTLI_REVERSE_BITS_LOWEST;
    let mut len = root_bits + 1;
    step = 2;
    while len <= max_length {
        let mut symbol = len - (BROTLI_HUFFMAN_MAX_CODE_LENGTH + 1);
        while count[len as usize] != 0 {
            if sub_key == (BROTLI_REVERSE_BITS_LOWEST << 1) {
                table += table_size as usize;
                table_bits = next_table_bit_size(count, len, root_bits);
                table_size = 1 << table_bits;
                total_size += table_size;
                sub_key = brotli_reverse_bits(key) as Reg;
                key += key_step;
                root_table[sub_key as usize] =
                    HuffmanCode::new((table_bits + root_bits) as u8, (table as Reg).wrapping_sub(sub_key) as u16);
                sub_key = 0;
            }
            symbol = sl(symbol);
            let code = HuffmanCode::new((len - root_bits) as u8, symbol as u16);
            replicate_value(&mut root_table[table + brotli_reverse_bits(sub_key)..], step, table_size, code);
            sub_key += sub_key_step;
            count[len as usize] -= 1;
        }
        step <<= 1;
        sub_key_step >>= 1;
        len += 1;
    }
    total_size as u32
}

/// `BrotliBuildSimpleHuffmanTable`: builds a simple Huffman table. The
/// `num_symbols` parameter is to be interpreted as follows: 0 means 1
/// symbol, 1 means 2 symbols, 2 means 3 symbols, 3 means 4 symbols with
/// lengths [2, 2, 2, 2], 4 means 4 symbols with lengths [1, 2, 3, 3].
pub fn brotli_build_simple_huffman_table(
    table: &mut [HuffmanCode],
    root_bits: i32,
    val: &mut [u16],
    num_symbols: u32,
) -> u32 {
    let mut table_size: u32 = 1;
    let goal_size: u32 = 1u32 << root_bits;
    match num_symbols {
        0 => {
            table[0] = HuffmanCode::new(0, val[0]);
        }
        1 => {
            if val[1] > val[0] {
                table[0] = HuffmanCode::new(1, val[0]);
                table[1] = HuffmanCode::new(1, val[1]);
            } else {
                table[0] = HuffmanCode::new(1, val[1]);
                table[1] = HuffmanCode::new(1, val[0]);
            }
            table_size = 2;
        }
        2 => {
            table[0] = HuffmanCode::new(1, val[0]);
            table[2] = HuffmanCode::new(1, val[0]);
            if val[2] > val[1] {
                table[1] = HuffmanCode::new(2, val[1]);
                table[3] = HuffmanCode::new(2, val[2]);
            } else {
                table[1] = HuffmanCode::new(2, val[2]);
                table[3] = HuffmanCode::new(2, val[1]);
            }
            table_size = 4;
        }
        3 => {
            for i in 0..3 {
                for k in i + 1..4 {
                    if val[k] < val[i] {
                        val.swap(k, i);
                    }
                }
            }
            table[0] = HuffmanCode::new(2, val[0]);
            table[2] = HuffmanCode::new(2, val[1]);
            table[1] = HuffmanCode::new(2, val[2]);
            table[3] = HuffmanCode::new(2, val[3]);
            table_size = 4;
        }
        4 => {
            if val[3] < val[2] {
                val.swap(3, 2);
            }
            table[0] = HuffmanCode::new(1, val[0]);
            table[1] = HuffmanCode::new(2, val[1]);
            table[2] = HuffmanCode::new(1, val[0]);
            table[3] = HuffmanCode::new(3, val[2]);
            table[4] = HuffmanCode::new(1, val[0]);
            table[5] = HuffmanCode::new(2, val[1]);
            table[6] = HuffmanCode::new(1, val[0]);
            table[7] = HuffmanCode::new(3, val[3]);
            table_size = 8;
        }
        _ => {}
    }
    while table_size != goal_size {
        let ts = table_size as usize;
        table.copy_within(0..ts, ts);
        table_size <<= 1;
    }
    goal_size
}

/// `HuffmanTreeGroup`: a collection of Huffman trees with the same alphabet
/// size.
///
/// C allocates `htrees` (pointer array) and `codes` in a single block; we do
/// the same single allocation (of the same byte size) and keep the tree
/// offsets in a fixed array instead of in the pointer slots.
pub struct HuffmanTreeGroup {
    /// The allocation: `[pointer slots (unused)][codes]`.
    pub mem: Buf<HuffmanCode>,
    /// Index in `mem` where `codes` begins.
    pub codes_start: usize,
    /// `htrees[i]`: index in `mem` of tree `i`.
    pub htrees: [u32; 256],
    pub alphabet_size_max: u16,
    /// alphabet_size_limit is needed due to simple codes, since
    /// log2(alphabet_size_max) could be greater than
    /// log2(alphabet_size_limit).
    pub alphabet_size_limit: u16,
    pub num_htrees: u16,
}

impl Default for HuffmanTreeGroup {
    fn default() -> Self {
        HuffmanTreeGroup {
            mem: Buf::empty(),
            codes_start: 0,
            htrees: [0; 256],
            alphabet_size_max: 0,
            alphabet_size_limit: 0,
            num_htrees: 0,
        }
    }
}
