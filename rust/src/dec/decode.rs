//! Port of `c/dec/decode.c`: the Brotli decoder state machine.

use core::ffi::c_void;

use super::bit_reader::{bit_mask, BitReader, BitReaderState, Reg};
use super::huffman::{
    brotli_build_code_lengths_huffman_table, brotli_build_huffman_table, brotli_build_simple_huffman_table,
    HuffmanCode, HuffmanTreeGroup, BROTLI_HUFFMAN_MAX_SIZE_26, BROTLI_HUFFMAN_MAX_SIZE_258,
};
use super::prefix::{brotli_decoder_ensure_static_init, K_CMD_LUT};
use super::state::*;
use super::tables::{
    K_CODE_LENGTH_CODE_ORDER, K_CODE_LENGTH_PREFIX_LENGTH, K_CODE_LENGTH_PREFIX_VALUE, K_ERROR_STRINGS,
    K_ERROR_STRING_INVALID, K_RING_BUFFER_WRITE_AHEAD_SLACK,
};
use crate::common::alloc::{Allocator, Boxed, Buf};
use crate::common::constants::{
    brotli_calculate_distance_code_limit, brotli_distance_alphabet_size, BROTLI_CODE_LENGTH_CODES,
    BROTLI_DISTANCE_CONTEXT_BITS, BROTLI_LARGE_MAX_DISTANCE_BITS, BROTLI_LARGE_MAX_WBITS, BROTLI_LARGE_MIN_WBITS,
    BROTLI_LITERAL_CONTEXT_BITS, BROTLI_MAX_ALLOWED_DISTANCE, BROTLI_MAX_DISTANCE_BITS, BROTLI_NUM_BLOCK_LEN_SYMBOLS,
    BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_DISTANCE_SHORT_CODES, BROTLI_NUM_LITERAL_SYMBOLS,
    BROTLI_REPEAT_PREVIOUS_CODE_LENGTH, BROTLI_WINDOW_GAP, K_BROTLI_PREFIX_CODE_RANGES,
    SHARED_BROTLI_MAX_COMPOUND_DICTS, SHARED_BROTLI_MAX_DICTIONARY_WORD_LENGTH,
    SHARED_BROTLI_MIN_DICTIONARY_WORD_LENGTH,
};
use crate::common::context::{brotli_context, brotli_context_lut, ContextType};
use crate::common::dictionary::BrotliDictionary;
use crate::common::transform::{transform_dictionary_word, BrotliTransforms};
use crate::common::version::BROTLI_VERSION;

/// `BrotliDecoderResult`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrotliDecoderResult {
    /// Decoding error, e.g. corrupted input or memory allocation problem.
    Error = 0,
    /// Decoding successfully completed.
    Success = 1,
    /// Partially done; should be called again with more input.
    NeedsMoreInput = 2,
    /// Partially done; should be called again with more output.
    NeedsMoreOutput = 3,
}

pub const BROTLI_DECODER_RESULT_ERROR: i32 = 0;
pub const BROTLI_DECODER_RESULT_SUCCESS: i32 = 1;
pub const BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: i32 = 2;
pub const BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: i32 = 3;

/// `BrotliDecoderErrorCode`.
pub type BrotliDecoderErrorCode = i32;
pub const BROTLI_DECODER_NO_ERROR: i32 = 0;
// Same as BrotliDecoderResult values
pub const BROTLI_DECODER_SUCCESS: i32 = 1;
pub const BROTLI_DECODER_NEEDS_MORE_INPUT: i32 = 2;
pub const BROTLI_DECODER_NEEDS_MORE_OUTPUT: i32 = 3;
// Errors caused by invalid input
pub const BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE: i32 = -1;
pub const BROTLI_DECODER_ERROR_FORMAT_RESERVED: i32 = -2;
pub const BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_META_NIBBLE: i32 = -3;
pub const BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET: i32 = -4;
pub const BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME: i32 = -5;
pub const BROTLI_DECODER_ERROR_FORMAT_CL_SPACE: i32 = -6;
pub const BROTLI_DECODER_ERROR_FORMAT_HUFFMAN_SPACE: i32 = -7;
pub const BROTLI_DECODER_ERROR_FORMAT_CONTEXT_MAP_REPEAT: i32 = -8;
pub const BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_1: i32 = -9;
pub const BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_2: i32 = -10;
pub const BROTLI_DECODER_ERROR_FORMAT_TRANSFORM: i32 = -11;
pub const BROTLI_DECODER_ERROR_FORMAT_DICTIONARY: i32 = -12;
pub const BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS: i32 = -13;
pub const BROTLI_DECODER_ERROR_FORMAT_PADDING_1: i32 = -14;
pub const BROTLI_DECODER_ERROR_FORMAT_PADDING_2: i32 = -15;
pub const BROTLI_DECODER_ERROR_FORMAT_DISTANCE: i32 = -16;
pub const BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH: i32 = -17;
pub const BROTLI_DECODER_ERROR_COMPOUND_DICTIONARY: i32 = -18;
pub const BROTLI_DECODER_ERROR_DICTIONARY_NOT_SET: i32 = -19;
pub const BROTLI_DECODER_ERROR_INVALID_ARGUMENTS: i32 = -20;
// Memory allocation problems
pub const BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES: i32 = -21;
// Literal, insert and distance trees together
pub const BROTLI_DECODER_ERROR_ALLOC_TREE_GROUPS: i32 = -22;
// -23..-24 codes are reserved for distinct tree groups
pub const BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MAP: i32 = -25;
pub const BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_1: i32 = -26;
pub const BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_2: i32 = -27;
// -28..-29 codes are reserved for dynamic ring-buffer allocation
pub const BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES: i32 = -30;
// "Impossible" states
pub const BROTLI_DECODER_ERROR_UNREACHABLE: i32 = -31;
/// `BROTLI_LAST_ERROR_CODE`
pub const BROTLI_LAST_ERROR_CODE: i32 = BROTLI_DECODER_ERROR_UNREACHABLE;

/// `BrotliDecoderParameter`.
pub const BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION: i32 = 0;
pub const BROTLI_DECODER_PARAM_LARGE_WINDOW: i32 = 1;

/// `SHARED_BROTLI_MAX_RAW_DICT_SIZE`: `1u << (23u + sizeof(size_t))`.
pub const SHARED_BROTLI_MAX_RAW_DICT_SIZE: u32 = 1u32 << (23 + core::mem::size_of::<usize>());

const HUFFMAN_TABLE_BITS: Reg = 8;
const HUFFMAN_TABLE_MASK: Reg = 0xFF;

const SUCCESS: i32 = BROTLI_DECODER_SUCCESS;
const NEEDS_MORE_INPUT: i32 = BROTLI_DECODER_NEEDS_MORE_INPUT;
const NEEDS_MORE_OUTPUT: i32 = BROTLI_DECODER_NEEDS_MORE_OUTPUT;

/// Offset of `block_len_trees` in `block_type_trees`.
const BLOCK_LEN_TREES_OFFSET: usize = 3 * BROTLI_HUFFMAN_MAX_SIZE_258;

/// Destination of `WriteRingBuffer` (C: `uint8_t** next_out`).
pub(crate) enum OutSink<'a> {
    /// `next_out == NULL`: nothing is copied.
    Null,
    /// `*next_out` points into the client buffer `buf` at `pos`.
    Buf { buf: &'a mut [u8], pos: usize },
    /// `*next_out == NULL` (BrotliDecoderTakeOutput): receives the offset
    /// of the output in the ring buffer.
    Take(Option<usize>),
}

/// `BrotliDecoderErrorString`: returns a NUL-terminated string.
pub fn error_string_bytes(c: BrotliDecoderErrorCode) -> &'static [u8] {
    if (-31..=3).contains(&c) {
        if let Some(s) = K_ERROR_STRINGS[(c + 31) as usize] {
            return s;
        }
    }
    K_ERROR_STRING_INVALID
}

/// `BrotliDecoderErrorString` (without the terminating NUL).
pub fn error_string(c: BrotliDecoderErrorCode) -> &'static str {
    let b = error_string_bytes(c);
    core::str::from_utf8(&b[..b.len() - 1]).unwrap_or("INVALID")
}

/// `BrotliDecoderVersion`.
pub fn version() -> u32 {
    BROTLI_VERSION
}

#[inline(always)]
fn result_from_code(e: i32) -> BrotliDecoderResult {
    match e {
        BROTLI_DECODER_SUCCESS => BrotliDecoderResult::Success,
        BROTLI_DECODER_NEEDS_MORE_INPUT => BrotliDecoderResult::NeedsMoreInput,
        BROTLI_DECODER_NEEDS_MORE_OUTPUT => BrotliDecoderResult::NeedsMoreOutput,
        _ => BrotliDecoderResult::Error,
    }
}

/// `DecodeVarLenUint8`: decodes a number in the range [0..255], by reading
/// 1 - 11 bits.
#[inline(never)]
fn decode_var_len_uint8(substate: &mut DecodeUint8State, br: &mut BitReader, inp: &[u8], value: &mut Reg) -> i32 {
    let mut bits: Reg = 0;
    let mut st = *substate;
    loop {
        match st {
            DecodeUint8State::None => {
                if !br.safe_read_bits(inp, 1, &mut bits) {
                    return NEEDS_MORE_INPUT;
                }
                if bits == 0 {
                    *value = 0;
                    return SUCCESS;
                }
                st = DecodeUint8State::Short;
            }
            DecodeUint8State::Short => {
                if !br.safe_read_bits(inp, 3, &mut bits) {
                    *substate = DecodeUint8State::Short;
                    return NEEDS_MORE_INPUT;
                }
                if bits == 0 {
                    *value = 1;
                    *substate = DecodeUint8State::None;
                    return SUCCESS;
                }
                // Use output value as a temporary storage. It MUST be persisted.
                *value = bits;
                st = DecodeUint8State::Long;
            }
            DecodeUint8State::Long => {
                if !br.safe_read_bits(inp, *value, &mut bits) {
                    *substate = DecodeUint8State::Long;
                    return NEEDS_MORE_INPUT;
                }
                *value = ((1 as Reg) << *value) + bits;
                *substate = DecodeUint8State::None;
                return SUCCESS;
            }
        }
    }
}

/// `DecodeSymbol`: decodes the Huffman code.  This method doesn't read data
/// from the bit reader, BUT drops the amount of bits that correspond to the
/// decoded symbol.  `bits` MUST contain at least 15 valid bits.
#[inline(always)]
fn decode_symbol(bits: Reg, table: &[HuffmanCode], br: &mut BitReader) -> Reg {
    let mut idx = (bits & HUFFMAN_TABLE_MASK) as usize;
    let mut e = table[idx];
    if e.bits() > HUFFMAN_TABLE_BITS {
        let nbits = e.bits() - HUFFMAN_TABLE_BITS;
        br.drop_bits(HUFFMAN_TABLE_BITS);
        idx += (e.value() + ((bits >> HUFFMAN_TABLE_BITS) & bit_mask(nbits))) as usize;
        e = table[idx];
    }
    br.drop_bits(e.bits());
    e.value()
}

/// `ReadSymbol`: reads and decodes the next Huffman code from bit-stream.
/// This method peeks 16 bits of input and drops 0 - 15 of them.
#[inline(always)]
fn read_symbol(table: &[HuffmanCode], br: &mut BitReader, inp: &[u8]) -> Reg {
    let bits = br.get_16_bits_unmasked(inp);
    decode_symbol(bits, table, br)
}

/// `SafeDecodeSymbol`: same as DecodeSymbol, but it is known that there is
/// less than 15 bits of input are currently available.
#[inline(never)]
fn safe_decode_symbol(table: &[HuffmanCode], br: &mut BitReader, result: &mut Reg) -> bool {
    let mut available_bits = br.get_available_bits();
    if available_bits == 0 {
        if table[0].bits() == 0 {
            *result = table[0].value();
            return true;
        }
        return false; // No valid bits at all.
    }
    let mut val = br.get_bits_unmasked();
    let mut idx = (val & HUFFMAN_TABLE_MASK) as usize;
    let mut e = table[idx];
    if e.bits() <= HUFFMAN_TABLE_BITS {
        if e.bits() <= available_bits {
            br.drop_bits(e.bits());
            *result = e.value();
            return true;
        } else {
            return false; // Not enough bits for the first level.
        }
    }
    if available_bits <= HUFFMAN_TABLE_BITS {
        return false; // Not enough bits to move to the second level.
    }

    // Speculatively drop HUFFMAN_TABLE_BITS.
    val = (val & bit_mask(e.bits())) >> HUFFMAN_TABLE_BITS;
    available_bits -= HUFFMAN_TABLE_BITS;
    idx += (e.value() + val) as usize;
    e = table[idx];
    if available_bits < e.bits() {
        return false; // Not enough bits for the second level.
    }

    br.drop_bits(HUFFMAN_TABLE_BITS + e.bits());
    *result = e.value();
    true
}

/// `SafeReadSymbol`.
#[inline(always)]
fn safe_read_symbol(table: &[HuffmanCode], br: &mut BitReader, inp: &[u8], result: &mut Reg) -> bool {
    let mut val: Reg = 0;
    if br.safe_get_bits(inp, 15, &mut val) {
        *result = decode_symbol(val, table, br);
        return true;
    }
    safe_decode_symbol(table, br, result)
}

/// `PreloadSymbol` (non-safe): makes a look-up in first level Huffman table.
/// Peeks 8 bits.
#[inline(always)]
fn preload_symbol(table: &[HuffmanCode], br: &mut BitReader, inp: &[u8], bits: &mut Reg, value: &mut Reg) {
    let e = table[br.get_bits_8(inp, HUFFMAN_TABLE_BITS) as usize];
    *bits = e.bits();
    *value = e.value();
}

/// `ReadPreloadedSymbol`: decodes the next Huffman code using data prepared
/// by PreloadSymbol.  Reads 0 - 15 bits. Also peeks 8 following bits.
#[inline(always)]
fn read_preloaded_symbol(table: &[HuffmanCode], br: &mut BitReader, inp: &[u8], bits: &mut Reg, value: &mut Reg) -> Reg {
    let mut result = *value;
    if *bits > HUFFMAN_TABLE_BITS {
        let val = br.get_16_bits_unmasked(inp);
        let mut ext = (val & HUFFMAN_TABLE_MASK) as usize + *value as usize;
        let mask = bit_mask(*bits - HUFFMAN_TABLE_BITS);
        br.drop_bits(HUFFMAN_TABLE_BITS);
        ext += ((val >> HUFFMAN_TABLE_BITS) & mask) as usize;
        let e = table[ext];
        br.drop_bits(e.bits());
        result = e.value();
    } else {
        br.drop_bits(*bits);
    }
    preload_symbol(table, br, inp, bits, value);
    result
}

/// `BrotliCopyPreloadedSymbolsToU8`: reads up to `limit` symbols from `br`
/// and copies them into the ring buffer, starting from `pos`.  Caller must
/// ensure that there is enough space for the write.  Returns the amount of
/// symbols actually copied.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn copy_preloaded_symbols_to_u8(
    table: &[HuffmanCode],
    br: &mut BitReader,
    inp: &[u8],
    bits: &mut Reg,
    value: &mut Reg,
    ringbuffer: &mut [u8],
    mut pos: i32,
    limit: i32,
) -> i32 {
    const K_MAXIMAL_OVERREAD: i64 = 4;
    let mut pos_limit = limit;
    // Calculate range where CheckInputAmount is always true.
    // Start with the number of bytes we can read.
    let mut new_lim: i64 = br.guard_in as i64 - br.next_in as i64;
    // Convert to bits, since symbols use variable number of bits.
    new_lim *= 8;
    // At most 15 bits per symbol, so this is safe.
    new_lim /= 15;
    if (new_lim - K_MAXIMAL_OVERREAD) <= limit as i64 {
        // Safe cast, since new_lim is already < num_steps
        pos_limit = (new_lim - K_MAXIMAL_OVERREAD) as i32;
    }
    if pos_limit < 0 {
        pos_limit = 0;
    }
    let mut copies = pos_limit;
    pos_limit += pos;
    // Fast path, caller made sure it is safe to write, we verified that is
    // is safe to read.
    while pos < pos_limit {
        debug_assert!(br.check_input_amount());
        ringbuffer[pos as usize] = read_preloaded_symbol(table, br, inp, bits, value) as u8;
        pos += 1;
    }
    // Do the remainder, caller made sure it is safe to write, we need to
    // verify that it is safe to read.
    while br.check_input_amount() && copies < limit {
        ringbuffer[pos as usize] = read_preloaded_symbol(table, br, inp, bits, value) as u8;
        pos += 1;
        copies += 1;
    }
    copies
}

/// `Log2Floor`.
#[inline(always)]
fn log2_floor(mut x: Reg) -> Reg {
    let mut result: Reg = 0;
    while x != 0 {
        x >>= 1;
        result += 1;
    }
    result
}

/// `ReadSimpleHuffmanSymbols`: reads (s->symbol + 1) symbols.  Totally 1..4
/// symbols are read, 1..11 bits each.  The list of symbols MUST NOT contain
/// duplicates.
fn read_simple_huffman_symbols(
    alphabet_size_max: Reg,
    alphabet_size_limit: Reg,
    br: &mut BitReader,
    h: &mut MetablockHeaderArena,
    inp: &[u8],
) -> i32 {
    // max_bits == 1..11; symbol == 0..3; 1..44 bits will be read.
    let max_bits = log2_floor(alphabet_size_max.wrapping_sub(1));
    let mut i = h.sub_loop_counter;
    let num_symbols = h.symbol;
    while i <= num_symbols {
        let mut v: Reg = 0;
        if !br.safe_read_bits(inp, max_bits, &mut v) {
            h.sub_loop_counter = i;
            h.substate_huffman = HuffmanState::SimpleRead;
            return NEEDS_MORE_INPUT;
        }
        if v >= alphabet_size_limit {
            return BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_ALPHABET;
        }
        h.symbols_lists_array[i as usize] = v as u16;
        i += 1;
    }

    for i in 0..num_symbols as usize {
        for k in i + 1..=num_symbols as usize {
            if h.symbols_lists_array[i] == h.symbols_lists_array[k] {
                return BROTLI_DECODER_ERROR_FORMAT_SIMPLE_HUFFMAN_SAME;
            }
        }
    }

    SUCCESS
}

/// `ProcessSingleCodeLength`: process single decoded symbol code length:
///  A) reset the repeat variable
///  B) remember code length (if it is not 0)
///  C) extend corresponding index-chain
///  D) reduce the Huffman space
///  E) update the histogram
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn process_single_code_length(
    code_len: Reg,
    symbol: &mut Reg,
    repeat: &mut Reg,
    space: &mut Reg,
    prev_code_len: &mut Reg,
    symbol_lists: &mut [u16; SYMBOL_LISTS_SIZE],
    code_length_histo: &mut [u16; 16],
    next_symbol: &mut [i32; 32],
) {
    *repeat = 0;
    if code_len != 0 {
        // code_len == 1..15
        let cl = code_len as usize;
        symbol_lists[(SYMBOL_LISTS_BASE + next_symbol[cl]) as usize] = *symbol as u16;
        next_symbol[cl] = *symbol as i32;
        *prev_code_len = code_len;
        *space = space.wrapping_sub(32768 >> code_len);
        code_length_histo[cl] = code_length_histo[cl].wrapping_add(1);
    }
    *symbol += 1;
}

/// `ProcessRepeatedCodeLength`: process repeated symbol code length.
///  A) Check if it is the extension of previous repeat sequence; if the
///     decoded value is not BROTLI_REPEAT_PREVIOUS_CODE_LENGTH, then it is a
///     new symbol-skip
///  B) Update repeat variable
///  C) Check if operation is feasible (fits alphabet)
///  D) For each symbol do the same operations as in ProcessSingleCodeLength
///
/// PRECONDITION: code_len == BROTLI_REPEAT_PREVIOUS_CODE_LENGTH or
///               code_len == BROTLI_REPEAT_ZERO_CODE_LENGTH
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn process_repeated_code_length(
    code_len: Reg,
    mut repeat_delta: Reg,
    alphabet_size: Reg,
    symbol: &mut Reg,
    repeat: &mut Reg,
    space: &mut Reg,
    prev_code_len: &mut Reg,
    repeat_code_len: &mut Reg,
    symbol_lists: &mut [u16; SYMBOL_LISTS_SIZE],
    code_length_histo: &mut [u16; 16],
    next_symbol: &mut [i32; 32],
) {
    let mut extra_bits: Reg = 3; // for BROTLI_REPEAT_ZERO_CODE_LENGTH
    let mut new_len: Reg = 0; // for BROTLI_REPEAT_ZERO_CODE_LENGTH
    if code_len == BROTLI_REPEAT_PREVIOUS_CODE_LENGTH as Reg {
        new_len = *prev_code_len;
        extra_bits = 2;
    }
    if *repeat_code_len != new_len {
        *repeat = 0;
        *repeat_code_len = new_len;
    }
    let old_repeat = *repeat;
    if *repeat > 0 {
        *repeat = repeat.wrapping_sub(2);
        *repeat <<= extra_bits;
    }
    *repeat = repeat.wrapping_add(repeat_delta + 3);
    repeat_delta = repeat.wrapping_sub(old_repeat);
    if symbol.wrapping_add(repeat_delta) > alphabet_size {
        *symbol = alphabet_size;
        *space = 0xFFFFF;
        return;
    }
    if *repeat_code_len != 0 {
        let rcl = *repeat_code_len as usize;
        let last = *symbol + repeat_delta;
        let mut next = next_symbol[rcl];
        loop {
            symbol_lists[(SYMBOL_LISTS_BASE + next) as usize] = *symbol as u16;
            next = *symbol as i32;
            *symbol += 1;
            if *symbol == last {
                break;
            }
        }
        next_symbol[rcl] = next;
        *space = space.wrapping_sub(repeat_delta << (15 - *repeat_code_len));
        code_length_histo[rcl] = (code_length_histo[rcl] as Reg).wrapping_add(repeat_delta) as u16;
    } else {
        *symbol += repeat_delta;
    }
}

/// `ReadSymbolCodeLengths`: reads and decodes symbol codelengths.
fn read_symbol_code_lengths(alphabet_size: Reg, br: &mut BitReader, h: &mut MetablockHeaderArena, inp: &[u8]) -> i32 {
    let mut symbol = h.symbol;
    let mut repeat = h.repeat;
    let mut space = h.space;
    let mut prev_code_len = h.prev_code_len;
    let mut repeat_code_len = h.repeat_code_len;
    if !br.warmup(inp) {
        return NEEDS_MORE_INPUT;
    }
    while symbol < alphabet_size && space > 0 {
        if !br.check_input_amount() {
            h.symbol = symbol;
            h.repeat = repeat;
            h.prev_code_len = prev_code_len;
            h.repeat_code_len = repeat_code_len;
            h.space = space;
            return NEEDS_MORE_INPUT;
        }
        br.fill_bit_window16(inp);
        let p = h.table[(br.get_bits_unmasked() & bit_mask(5)) as usize];
        br.drop_bits(p.bits()); // Use 1..5 bits.
        let code_len = p.value(); // code_len == 0..17
        if code_len < BROTLI_REPEAT_PREVIOUS_CODE_LENGTH as Reg {
            process_single_code_length(
                code_len,
                &mut symbol,
                &mut repeat,
                &mut space,
                &mut prev_code_len,
                &mut h.symbols_lists_array,
                &mut h.code_length_histo,
                &mut h.next_symbol,
            );
        } else {
            // code_len == 16..17, extra_bits == 2..3
            let extra_bits: Reg = if code_len == BROTLI_REPEAT_PREVIOUS_CODE_LENGTH as Reg { 2 } else { 3 };
            let repeat_delta = br.get_bits_unmasked() & bit_mask(extra_bits);
            br.drop_bits(extra_bits);
            process_repeated_code_length(
                code_len,
                repeat_delta,
                alphabet_size,
                &mut symbol,
                &mut repeat,
                &mut space,
                &mut prev_code_len,
                &mut repeat_code_len,
                &mut h.symbols_lists_array,
                &mut h.code_length_histo,
                &mut h.next_symbol,
            );
        }
    }
    h.space = space;
    SUCCESS
}

/// `SafeReadSymbolCodeLengths`.
fn safe_read_symbol_code_lengths(alphabet_size: Reg, br: &mut BitReader, h: &mut MetablockHeaderArena, inp: &[u8]) -> i32 {
    let mut get_byte = false;
    while h.symbol < alphabet_size && h.space > 0 {
        let mut bits: Reg = 0;
        if get_byte && !br.pull_byte(inp) {
            return NEEDS_MORE_INPUT;
        }
        get_byte = false;
        let available_bits = br.get_available_bits();
        if available_bits != 0 {
            bits = br.get_bits_unmasked() as u32 as Reg;
        }
        let p = h.table[(bits & bit_mask(5)) as usize];
        if p.bits() > available_bits {
            get_byte = true;
            continue;
        }
        let code_len = p.value(); // code_len == 0..17
        if code_len < BROTLI_REPEAT_PREVIOUS_CODE_LENGTH as Reg {
            br.drop_bits(p.bits());
            process_single_code_length(
                code_len,
                &mut h.symbol,
                &mut h.repeat,
                &mut h.space,
                &mut h.prev_code_len,
                &mut h.symbols_lists_array,
                &mut h.code_length_histo,
                &mut h.next_symbol,
            );
        } else {
            // code_len == 16..17, extra_bits == 2..3
            let extra_bits = code_len - 14;
            let repeat_delta = (bits >> p.bits()) & bit_mask(extra_bits);
            if available_bits < p.bits() + extra_bits {
                get_byte = true;
                continue;
            }
            br.drop_bits(p.bits() + extra_bits);
            process_repeated_code_length(
                code_len,
                repeat_delta,
                alphabet_size,
                &mut h.symbol,
                &mut h.repeat,
                &mut h.space,
                &mut h.prev_code_len,
                &mut h.repeat_code_len,
                &mut h.symbols_lists_array,
                &mut h.code_length_histo,
                &mut h.next_symbol,
            );
        }
    }
    SUCCESS
}

/// `ReadCodeLengthCodeLengths`: reads and decodes 15..18 codes using static
/// prefix code.  Each code is 2..4 bits long. In total 30..72 bits are used.
fn read_code_length_code_lengths(br: &mut BitReader, h: &mut MetablockHeaderArena, inp: &[u8]) -> i32 {
    let mut num_codes = h.repeat;
    let mut space = h.space;
    let mut i = h.sub_loop_counter;
    while i < BROTLI_CODE_LENGTH_CODES as Reg {
        let code_len_idx = K_CODE_LENGTH_CODE_ORDER[i as usize] as usize;
        let mut ix: Reg = 0;
        if !br.safe_get_bits(inp, 4, &mut ix) {
            let available_bits = br.get_available_bits();
            if available_bits != 0 {
                ix = br.get_bits_unmasked() & 0xF;
            } else {
                ix = 0;
            }
            if K_CODE_LENGTH_PREFIX_LENGTH[ix as usize] as Reg > available_bits {
                h.sub_loop_counter = i;
                h.repeat = num_codes;
                h.space = space;
                h.substate_huffman = HuffmanState::Complex;
                return NEEDS_MORE_INPUT;
            }
        }
        let v = K_CODE_LENGTH_PREFIX_VALUE[ix as usize];
        br.drop_bits(K_CODE_LENGTH_PREFIX_LENGTH[ix as usize] as Reg);
        h.code_length_code_lengths[code_len_idx] = v;
        if v != 0 {
            space = space.wrapping_sub(32 >> v);
            num_codes += 1;
            h.code_length_histo[v as usize] += 1;
            if space.wrapping_sub(1) >= 32 {
                // space is 0 or wrapped around.
                break;
            }
        }
        i += 1;
    }
    if !(num_codes == 1 || space == 0) {
        return BROTLI_DECODER_ERROR_FORMAT_CL_SPACE;
    }
    SUCCESS
}

/// `ReadHuffmanCode`: decodes the Huffman tables.
/// There are 2 scenarios:
///  A) Huffman code contains only few symbols (1..4). Those symbols are read
///     directly; their code lengths are defined by the number of symbols.
///     For this scenario 4 - 49 bits will be read.
///
///  B) 2-phase decoding:
///  B.1) Small Huffman table is decoded; it is specified with code lengths
///       encoded with predefined entropy code. 32 - 74 bits are used.
///  B.2) Decoded table is used to decode code lengths of symbols in
///       resulting Huffman table. In worst case 3520 bits are read.
fn read_huffman_code(
    alphabet_size_max: Reg,
    alphabet_size_limit: Reg,
    table: &mut [HuffmanCode],
    mut opt_table_size: Option<&mut Reg>,
    br: &mut BitReader,
    h: &mut MetablockHeaderArena,
    inp: &[u8],
) -> i32 {
    // State machine.
    let mut st = h.substate_huffman;
    loop {
        match st {
            HuffmanState::None => {
                if !br.safe_read_bits(inp, 2, &mut h.sub_loop_counter) {
                    return NEEDS_MORE_INPUT;
                }
                // The value is used as follows:
                // 1 for simple code;
                // 0 for no skipping, 2 skips 2 code lengths, 3 skips 3 code
                // lengths
                if h.sub_loop_counter != 1 {
                    h.space = 32;
                    h.repeat = 0; // num_codes
                    for x in h.code_length_histo[..6].iter_mut() {
                        *x = 0;
                    }
                    h.code_length_code_lengths = [0; BROTLI_CODE_LENGTH_CODES];
                    h.substate_huffman = HuffmanState::Complex;
                    st = HuffmanState::Complex;
                    continue;
                }
                st = HuffmanState::SimpleSize;
            }
            HuffmanState::SimpleSize => {
                // Read symbols, codes & code lengths directly.
                if !br.safe_read_bits(inp, 2, &mut h.symbol) {
                    // num_symbols
                    h.substate_huffman = HuffmanState::SimpleSize;
                    return NEEDS_MORE_INPUT;
                }
                h.sub_loop_counter = 0;
                st = HuffmanState::SimpleRead;
            }
            HuffmanState::SimpleRead => {
                let result = read_simple_huffman_symbols(alphabet_size_max, alphabet_size_limit, br, h, inp);
                if result != SUCCESS {
                    return result;
                }
                st = HuffmanState::SimpleBuild;
            }
            HuffmanState::SimpleBuild => {
                if h.symbol == 3 {
                    let mut bits: Reg = 0;
                    if !br.safe_read_bits(inp, 1, &mut bits) {
                        h.substate_huffman = HuffmanState::SimpleBuild;
                        return NEEDS_MORE_INPUT;
                    }
                    h.symbol += bits;
                }
                let num_symbols = h.symbol as u32;
                let table_size = brotli_build_simple_huffman_table(
                    table,
                    HUFFMAN_TABLE_BITS as i32,
                    &mut h.symbols_lists_array,
                    num_symbols,
                );
                if let Some(t) = opt_table_size.as_deref_mut() {
                    *t = table_size as Reg;
                }
                h.substate_huffman = HuffmanState::None;
                return SUCCESS;
            }
            // Decode Huffman-coded code lengths.
            HuffmanState::Complex => {
                let result = read_code_length_code_lengths(br, h, inp);
                if result != SUCCESS {
                    return result;
                }
                brotli_build_code_lengths_huffman_table(&mut h.table, &h.code_length_code_lengths, &h.code_length_histo);
                h.code_length_histo = [0; 16];
                for i in 0..=15usize {
                    h.next_symbol[i] = i as i32 - (15 + 1);
                    h.symbols_lists_array[(SYMBOL_LISTS_BASE + h.next_symbol[i]) as usize] = 0xFFFF;
                }

                h.symbol = 0;
                h.prev_code_len = crate::common::constants::BROTLI_INITIAL_REPEATED_CODE_LENGTH as Reg;
                h.repeat = 0;
                h.repeat_code_len = 0;
                h.space = 32768;
                h.substate_huffman = HuffmanState::LengthSymbols;
                st = HuffmanState::LengthSymbols;
            }
            HuffmanState::LengthSymbols => {
                let mut result = read_symbol_code_lengths(alphabet_size_limit, br, h, inp);
                if result == NEEDS_MORE_INPUT {
                    result = safe_read_symbol_code_lengths(alphabet_size_limit, br, h, inp);
                }
                if result != SUCCESS {
                    return result;
                }

                if h.space != 0 {
                    return BROTLI_DECODER_ERROR_FORMAT_HUFFMAN_SPACE;
                }
                let table_size = brotli_build_huffman_table(
                    table,
                    HUFFMAN_TABLE_BITS as i32,
                    &h.symbols_lists_array,
                    SYMBOL_LISTS_BASE,
                    &mut h.code_length_histo,
                );
                if let Some(t) = opt_table_size.as_deref_mut() {
                    *t = table_size as Reg;
                }
                h.substate_huffman = HuffmanState::None;
                return SUCCESS;
            }
        }
    }
}

/// `ReadBlockLength`: decodes a block length by reading 3..39 bits.
#[inline(always)]
fn read_block_length(table: &[HuffmanCode], br: &mut BitReader, inp: &[u8]) -> Reg {
    let code = read_symbol(table, br, inp) as usize;
    let nbits = K_BROTLI_PREFIX_CODE_RANGES[code].nbits as Reg; // nbits == 2..24
    K_BROTLI_PREFIX_CODE_RANGES[code].offset as Reg + br.read_bits24(inp, nbits)
}

/// `SafeReadBlockLength`.
/// WARNING: if state is not BROTLI_STATE_READ_BLOCK_LENGTH_NONE, then
/// reading can't be continued with ReadBlockLength.
#[inline(always)]
fn safe_read_block_length(
    substate: &mut ReadBlockLengthState,
    block_length_index: &mut Reg,
    result: &mut Reg,
    table: &[HuffmanCode],
    br: &mut BitReader,
    inp: &[u8],
) -> bool {
    let mut index: Reg = 0;
    if *substate == ReadBlockLengthState::None {
        if !safe_read_symbol(table, br, inp, &mut index) {
            return false;
        }
    } else {
        index = *block_length_index;
    }
    let mut bits: Reg = 0;
    let range = K_BROTLI_PREFIX_CODE_RANGES[index as usize];
    let nbits = range.nbits as Reg;
    let offset = range.offset as Reg;
    if !br.safe_read_bits(inp, nbits, &mut bits) {
        *block_length_index = index;
        *substate = ReadBlockLengthState::Suffix;
        return false;
    }
    *result = offset + bits;
    *substate = ReadBlockLengthState::None;
    true
}

/// `InverseMoveToFrontTransform`.
///
/// Transform:
///  1) initialize list L with values 0, 1,... 255
///  2) For each input element X:
///     2.1) let Y = L[X]
///     2.2) remove X-th element from L
///     2.3) prepend Y to L
///     2.4) append Y to output
///
/// In most cases max(Y) <= 7, so most of L remains intact.  To reduce the
/// cost of initialization, we reuse L, remember the upper bound of Y values,
/// and reinitialize only first elements in L.
#[inline(never)]
fn inverse_move_to_front_transform(v: &mut [u8], v_len: Reg, mtf: &mut [u8; 4 * 65], mtf_upper_bound: &mut Reg) {
    // `mtf_u8` is `(uint8_t*)&state->mtf[1]`: byte offset 4, so that
    // mtf_u8[-1] is addressable.
    const BASE: usize = 4;
    // Reinitialize elements that could have been changed.
    let mut upper_bound = *mtf_upper_bound;
    // Initialize list using 4 consequent values pattern (endian-neutral:
    // byte k gets value k).
    let words = if upper_bound < 1 { 1 } else { upper_bound } as usize + 1;
    for k in 0..4 * words {
        mtf[BASE + k] = k as u8;
    }

    // Transform the input.
    upper_bound = 0;
    for i in 0..v_len as usize {
        let index = v[i] as usize;
        let value = mtf[BASE + index];
        upper_bound |= v[i] as Reg;
        v[i] = value;
        mtf[BASE - 1] = value;
        mtf.copy_within(BASE - 1..BASE + index, BASE);
    }
    // Remember amount of elements to be reinitialized.
    *mtf_upper_bound = upper_bound >> 2;
}

/// `HuffmanTreeGroupDecode`: decodes a series of Huffman table using
/// ReadHuffmanCode function.
fn huffman_tree_group_decode(group: &mut HuffmanTreeGroup, br: &mut BitReader, h: &mut MetablockHeaderArena, inp: &[u8]) -> i32 {
    if h.substate_tree_group != TreeGroupState::Loop {
        h.next = group.codes_start;
        h.htree_index = 0;
        h.substate_tree_group = TreeGroupState::Loop;
    }
    while h.htree_index < group.num_htrees as i32 {
        let mut table_size: Reg = 0;
        let next = h.next;
        let result = read_huffman_code(
            group.alphabet_size_max as Reg,
            group.alphabet_size_limit as Reg,
            &mut group.mem[next..],
            Some(&mut table_size),
            br,
            h,
            inp,
        );
        if result != SUCCESS {
            return result;
        }
        group.htrees[h.htree_index as usize] = next as u32;
        h.next += table_size as usize;
        h.htree_index += 1;
    }
    h.substate_tree_group = TreeGroupState::None;
    SUCCESS
}

#[inline(always)]
fn check_input_amount<const SAFE: bool>(br: &BitReader) -> bool {
    if SAFE {
        return true;
    }
    br.check_input_amount()
}

/// `SafeReadBits`.
#[inline(always)]
fn safe_read_bits(br: &mut BitReader, inp: &[u8], n_bits: Reg, val: &mut Reg) -> bool {
    if n_bits != 0 {
        br.safe_read_bits(inp, n_bits, val)
    } else {
        *val = 0;
        true
    }
}

/// `SafeReadBits32`.
#[inline(always)]
fn safe_read_bits32(br: &mut BitReader, inp: &[u8], n_bits: Reg, val: &mut Reg) -> bool {
    if n_bits != 0 {
        br.safe_read_bits32(inp, n_bits, val)
    } else {
        *val = 0;
        true
    }
}

/// `EnsureCompoundDictionaryInitialized`.
fn ensure_compound_dictionary_initialized(addon: &mut CompoundDictionary) {
    // 256 = (1 << 8) slots in block map.
    let mut block_bits: u32 = 8;
    let mut cursor: u32 = 0;
    let mut index: usize = 0;
    let maximal_address: u32 = addon.total_size.wrapping_sub(1);
    debug_assert!(addon.total_size > 0);
    if addon.block_bits != 255 {
        return;
    }
    while (maximal_address >> block_bits) != 0 {
        block_bits += 1;
    }
    block_bits -= 8;
    addon.block_bits = block_bits as u8;
    while cursor <= maximal_address {
        // We have sentinel value equal maximal_address + 1.
        while addon.chunk_offsets[index + 1] < cursor {
            index += 1;
        }
        addon.block_map[(cursor >> block_bits) as usize] = index as u8;
        cursor = cursor.wrapping_add(1u32 << block_bits);
        if cursor == 0 {
            break;
        }
    }
    // Now if X is in the range [0..maximal_address] then
    // block_map[X >> block_bits] is in [0..num_chunks).
}

enum Label {
    CommandBegin,
    CommandInner,
    AfterLiterals,
    CommandPostDecodeLiterals,
    CommandPostWrapCopy,
    NextLiteralBlock,
    SaveStateAndReturn,
}

impl DecoderState {
    /// `SaveErrorCode`: saves error code and converts it to
    /// BrotliDecoderResult.
    #[inline(never)]
    fn save_error_code(&mut self, e: i32, consumed_input: usize) -> BrotliDecoderResult {
        self.error_code = e;
        self.used_input = self.used_input.wrapping_add(consumed_input as u64);
        if self.buffer_length != 0 && self.br.next_in == self.br.last_in {
            // If internal buffer is depleted at last, reset it.
            self.buffer_length = 0;
        }
        result_from_code(e)
    }

    /// `DecodeWindowBits`: decodes WBITS by reading 1 - 7 bits, or 0x11 for
    /// "Large Window Brotli".  Precondition: bit-reader accumulator has at
    /// least 8 bits.
    fn decode_window_bits(&mut self) -> i32 {
        let large_window = self.large_window;
        self.large_window = 0;
        let br = &mut self.br;
        let mut n = br.take_bits(1);
        if n == 0 {
            self.window_bits = 16;
            return SUCCESS;
        }
        n = br.take_bits(3);
        if n != 0 {
            self.window_bits = ((17 + n) & 63) as u32;
            return SUCCESS;
        }
        n = br.take_bits(3);
        if n == 1 {
            if large_window != 0 {
                n = br.take_bits(1);
                if n == 1 {
                    return BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS;
                }
                self.large_window = 1;
                return SUCCESS;
            } else {
                return BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS;
            }
        }
        if n != 0 {
            self.window_bits = ((8 + n) & 63) as u32;
            return SUCCESS;
        }
        self.window_bits = 17;
        SUCCESS
    }

    /// `DecodeMetaBlockLength`: decodes a metablock length and flags by
    /// reading 2 - 31 bits.
    #[inline(never)]
    fn decode_meta_block_length(&mut self, inp: &[u8]) -> i32 {
        let mut bits: Reg = 0;
        loop {
            match self.substate_metablock_header {
                MetablockHeaderState::None => {
                    if !self.br.safe_read_bits(inp, 1, &mut bits) {
                        return NEEDS_MORE_INPUT;
                    }
                    self.is_last_metablock = if bits != 0 { 1 } else { 0 };
                    self.meta_block_remaining_len = 0;
                    self.is_uncompressed = 0;
                    self.is_metadata = 0;
                    if self.is_last_metablock == 0 {
                        self.substate_metablock_header = MetablockHeaderState::Nibbles;
                        continue;
                    }
                    self.substate_metablock_header = MetablockHeaderState::Empty;
                }
                MetablockHeaderState::Empty => {
                    if !self.br.safe_read_bits(inp, 1, &mut bits) {
                        return NEEDS_MORE_INPUT;
                    }
                    if bits != 0 {
                        self.substate_metablock_header = MetablockHeaderState::None;
                        return SUCCESS;
                    }
                    self.substate_metablock_header = MetablockHeaderState::Nibbles;
                }
                MetablockHeaderState::Nibbles => {
                    if !self.br.safe_read_bits(inp, 2, &mut bits) {
                        return NEEDS_MORE_INPUT;
                    }
                    self.size_nibbles = (bits + 4) as u8 as u32;
                    self.loop_counter = 0;
                    if bits == 3 {
                        self.is_metadata = 1;
                        self.substate_metablock_header = MetablockHeaderState::Reserved;
                        continue;
                    }
                    self.substate_metablock_header = MetablockHeaderState::Size;
                }
                MetablockHeaderState::Size => {
                    let mut i = self.loop_counter;
                    while i < self.size_nibbles as i32 {
                        if !self.br.safe_read_bits(inp, 4, &mut bits) {
                            self.loop_counter = i;
                            return NEEDS_MORE_INPUT;
                        }
                        if i + 1 == self.size_nibbles as i32 && self.size_nibbles > 4 && bits == 0 {
                            return BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE;
                        }
                        self.meta_block_remaining_len |= (bits << (i * 4)) as i32;
                        i += 1;
                    }
                    self.substate_metablock_header = MetablockHeaderState::Uncompressed;
                }
                MetablockHeaderState::Uncompressed => {
                    if self.is_last_metablock == 0 {
                        if !self.br.safe_read_bits(inp, 1, &mut bits) {
                            return NEEDS_MORE_INPUT;
                        }
                        self.is_uncompressed = if bits != 0 { 1 } else { 0 };
                    }
                    self.meta_block_remaining_len += 1;
                    self.substate_metablock_header = MetablockHeaderState::None;
                    return SUCCESS;
                }
                MetablockHeaderState::Reserved => {
                    if !self.br.safe_read_bits(inp, 1, &mut bits) {
                        return NEEDS_MORE_INPUT;
                    }
                    if bits != 0 {
                        return BROTLI_DECODER_ERROR_FORMAT_RESERVED;
                    }
                    self.substate_metablock_header = MetablockHeaderState::Bytes;
                }
                MetablockHeaderState::Bytes => {
                    if !self.br.safe_read_bits(inp, 2, &mut bits) {
                        return NEEDS_MORE_INPUT;
                    }
                    if bits == 0 {
                        self.substate_metablock_header = MetablockHeaderState::None;
                        return SUCCESS;
                    }
                    self.size_nibbles = bits as u8 as u32;
                    self.substate_metablock_header = MetablockHeaderState::Metadata;
                }
                MetablockHeaderState::Metadata => {
                    let mut i = self.loop_counter;
                    while i < self.size_nibbles as i32 {
                        if !self.br.safe_read_bits(inp, 8, &mut bits) {
                            self.loop_counter = i;
                            return NEEDS_MORE_INPUT;
                        }
                        if i + 1 == self.size_nibbles as i32 && self.size_nibbles > 1 && bits == 0 {
                            return BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_META_NIBBLE;
                        }
                        self.meta_block_remaining_len |= (bits << (i * 8)) as i32;
                        i += 1;
                    }
                    self.meta_block_remaining_len += 1;
                    self.substate_metablock_header = MetablockHeaderState::None;
                    return SUCCESS;
                }
            }
        }
    }

    /// `DecodeContextMap`: decodes a context map.
    /// Decoding is done in 4 phases:
    ///  1) Read auxiliary information (6..16 bits) and allocate memory.
    ///     In case of trivial context map, decoding is finished at this
    ///     phase.
    ///  2) Decode Huffman table using ReadHuffmanCode function.
    ///     This table will be used for reading context map items.
    ///  3) Read context map items; "0" values could be run-length encoded.
    ///  4) Optionally, apply InverseMoveToFront transform to the resulting
    ///     map.
    ///
    /// `dist` selects `dist_context_map` / `num_dist_htrees` instead of
    /// `context_map` / `num_literal_htrees`.
    fn decode_context_map(&mut self, context_map_size: Reg, dist: bool, inp: &[u8]) -> i32 {
        let (context_map_arg, num_htrees) = if dist {
            (&mut self.dist_context_map, &mut self.num_dist_htrees)
        } else {
            (&mut self.context_map, &mut self.num_literal_htrees)
        };
        let br = &mut self.br;
        let h = &mut self.header;

        let mut st = h.substate_context_map;
        loop {
            match st {
                ContextMapState::None => {
                    let result = decode_var_len_uint8(&mut self.substate_decode_uint8, br, inp, num_htrees);
                    if result != SUCCESS {
                        return result;
                    }
                    *num_htrees += 1;
                    h.context_index = 0;
                    match Buf::try_new(&self.alloc, context_map_size as usize) {
                        Some(b) => *context_map_arg = b,
                        None => {
                            *context_map_arg = Buf::empty();
                            return BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MAP;
                        }
                    }
                    if *num_htrees <= 1 {
                        // memset(*context_map_arg, 0, context_map_size):
                        // Buf is zero-initialized.
                        return SUCCESS;
                    }
                    h.substate_context_map = ContextMapState::ReadPrefix;
                    st = ContextMapState::ReadPrefix;
                }
                ContextMapState::ReadPrefix => {
                    let mut bits: Reg = 0;
                    // In next stage ReadHuffmanCode uses at least 4 bits, so
                    // it is safe to peek 4 bits ahead.
                    if !br.safe_get_bits(inp, 5, &mut bits) {
                        return NEEDS_MORE_INPUT;
                    }
                    if (bits & 1) != 0 {
                        // Use RLE for zeros.
                        h.max_run_length_prefix = (bits >> 1) + 1;
                        br.drop_bits(5);
                    } else {
                        h.max_run_length_prefix = 0;
                        br.drop_bits(1);
                    }
                    h.substate_context_map = ContextMapState::Huffman;
                    st = ContextMapState::Huffman;
                }
                ContextMapState::Huffman => {
                    let alphabet_size = *num_htrees + h.max_run_length_prefix;
                    let result = read_huffman_code(alphabet_size, alphabet_size, &mut self.context_map_table, None, br, h, inp);
                    if result != SUCCESS {
                        return result;
                    }
                    h.code = 0xFFFF;
                    h.substate_context_map = ContextMapState::Decode;
                    st = ContextMapState::Decode;
                }
                ContextMapState::Decode => {
                    let mut context_index = h.context_index;
                    let max_run_length_prefix = h.max_run_length_prefix;
                    let context_map: &mut [u8] = context_map_arg;
                    let mut code = h.code;
                    let mut skip_preamble = code != 0xFFFF;
                    while context_index < context_map_size || skip_preamble {
                        if !skip_preamble {
                            if !safe_read_symbol(&self.context_map_table, br, inp, &mut code) {
                                h.code = 0xFFFF;
                                h.context_index = context_index;
                                return NEEDS_MORE_INPUT;
                            }

                            if code == 0 {
                                context_map[context_index as usize] = 0;
                                context_index += 1;
                                continue;
                            }
                            if code > max_run_length_prefix {
                                context_map[context_index as usize] = (code - max_run_length_prefix) as u8;
                                context_index += 1;
                                continue;
                            }
                        } else {
                            skip_preamble = false;
                        }
                        // RLE sub-stage.
                        {
                            let mut reps: Reg = 0;
                            if !br.safe_read_bits(inp, code, &mut reps) {
                                h.code = code;
                                h.context_index = context_index;
                                return NEEDS_MORE_INPUT;
                            }
                            reps += (1 as Reg) << code;
                            if context_index + reps > context_map_size {
                                return BROTLI_DECODER_ERROR_FORMAT_CONTEXT_MAP_REPEAT;
                            }
                            loop {
                                context_map[context_index as usize] = 0;
                                context_index += 1;
                                reps -= 1;
                                if reps == 0 {
                                    break;
                                }
                            }
                        }
                    }
                    st = ContextMapState::Transform;
                }
                ContextMapState::Transform => {
                    let mut bits: Reg = 0;
                    if !br.safe_read_bits(inp, 1, &mut bits) {
                        h.substate_context_map = ContextMapState::Transform;
                        return NEEDS_MORE_INPUT;
                    }
                    if bits != 0 {
                        inverse_move_to_front_transform(
                            context_map_arg,
                            context_map_size,
                            &mut self.mtf,
                            &mut self.mtf_upper_bound,
                        );
                    }
                    h.substate_context_map = ContextMapState::None;
                    return SUCCESS;
                }
            }
        }
    }

    /// `DecodeBlockTypeAndLength`: decodes a command or literal and updates
    /// block type ring-buffer. Reads 3..54 bits.
    #[inline(always)]
    fn decode_block_type_and_length<const SAFE: bool>(&mut self, tree_type: usize, inp: &[u8]) -> i32 {
        let max_block_type = self.num_block_types[tree_type];
        let type_tree = &self.block_type_trees[tree_type * BROTLI_HUFFMAN_MAX_SIZE_258..];
        let len_tree = &self.block_type_trees[BLOCK_LEN_TREES_OFFSET + tree_type * BROTLI_HUFFMAN_MAX_SIZE_26..];
        let br = &mut self.br;
        let mut block_type: Reg = 0;
        if max_block_type <= 1 {
            return BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
        }

        // Read 0..15 + 3..39 bits.
        if !SAFE {
            block_type = read_symbol(type_tree, br, inp);
            self.block_length[tree_type] = read_block_length(len_tree, br, inp);
        } else {
            let memento = br.save_state();
            if !safe_read_symbol(type_tree, br, inp, &mut block_type) {
                return NEEDS_MORE_INPUT;
            }
            if !safe_read_block_length(
                &mut self.substate_read_block_length,
                &mut self.block_length_index,
                &mut self.block_length[tree_type],
                len_tree,
                br,
                inp,
            ) {
                self.substate_read_block_length = ReadBlockLengthState::None;
                br.restore_state(&memento);
                return NEEDS_MORE_INPUT;
            }
        }

        let ringbuffer = &mut self.block_type_rb[tree_type * 2..tree_type * 2 + 2];
        if block_type == 1 {
            block_type = ringbuffer[1] + 1;
        } else if block_type == 0 {
            block_type = ringbuffer[0];
        } else {
            block_type -= 2;
        }
        if block_type >= max_block_type {
            block_type -= max_block_type;
        }
        ringbuffer[0] = ringbuffer[1];
        ringbuffer[1] = block_type;
        SUCCESS
    }

    /// `DetectTrivialLiteralBlockTypes`.
    #[inline(always)]
    fn detect_trivial_literal_block_types(&mut self) {
        self.trivial_literal_contexts = [0; 8];
        for i in 0..self.num_block_types[0] as usize {
            let offset = i << BROTLI_LITERAL_CONTEXT_BITS;
            let mut error: usize = 0;
            let sample = self.context_map[offset] as usize;
            for j in 0..(1usize << BROTLI_LITERAL_CONTEXT_BITS) {
                error |= (self.context_map[offset + j] as usize) ^ sample;
            }
            if error == 0 {
                self.trivial_literal_contexts[i >> 5] |= 1u32 << (i & 31);
            }
        }
    }

    /// `PrepareLiteralDecoding`.
    #[inline(always)]
    fn prepare_literal_decoding(&mut self) {
        let block_type = self.block_type_rb[1];
        let context_offset = (block_type << BROTLI_LITERAL_CONTEXT_BITS) as usize;
        self.context_map_slice = context_offset;
        let trivial = self.trivial_literal_contexts[(block_type >> 5) as usize] as usize;
        self.trivial_literal_context = ((trivial >> (block_type & 31)) & 1) as i32;
        self.literal_htree = self.literal_hgroup.htrees[self.context_map[context_offset] as usize] as usize;
        let context_mode = self.context_modes[block_type as usize] & 3;
        self.context_lookup = brotli_context_lut(ContextType::from_u32(context_mode as u32));
    }

    /// `DecodeLiteralBlockSwitchInternal`: decodes the block type and
    /// updates the state for literal context. Reads 3..54 bits.
    #[inline(never)]
    fn decode_literal_block_switch_internal<const SAFE: bool>(&mut self, inp: &[u8]) -> i32 {
        let result = self.decode_block_type_and_length::<SAFE>(0, inp);
        if result != SUCCESS {
            return result;
        }
        self.prepare_literal_decoding();
        SUCCESS
    }

    /// `DecodeCommandBlockSwitchInternal`: block switch for insert/copy
    /// length. Reads 3..54 bits.
    #[inline(never)]
    fn decode_command_block_switch_internal<const SAFE: bool>(&mut self, inp: &[u8]) -> i32 {
        let result = self.decode_block_type_and_length::<SAFE>(1, inp);
        if result != SUCCESS {
            return result;
        }
        self.htree_command = self.insert_copy_hgroup.htrees[self.block_type_rb[3] as usize] as usize;
        SUCCESS
    }

    /// `DecodeDistanceBlockSwitchInternal`: block switch for distance codes.
    /// Reads 3..54 bits.
    #[inline(never)]
    fn decode_distance_block_switch_internal<const SAFE: bool>(&mut self, inp: &[u8]) -> i32 {
        let result = self.decode_block_type_and_length::<SAFE>(2, inp);
        if result != SUCCESS {
            return result;
        }
        self.dist_context_map_slice = (self.block_type_rb[5] << BROTLI_DISTANCE_CONTEXT_BITS) as usize;
        self.dist_htree_index = self.dist_context_map[self.dist_context_map_slice + self.distance_context as usize];
        SUCCESS
    }

    /// `UnwrittenBytes`.
    #[inline(always)]
    fn unwritten_bytes(&self, wrap: bool) -> usize {
        let pos = if wrap && self.pos > self.ringbuffer_size { self.ringbuffer_size as usize } else { self.pos as usize };
        let partial_pos_rb = self.rb_roundtrips.wrapping_mul(self.ringbuffer_size as usize).wrapping_add(pos);
        partial_pos_rb.wrapping_sub(self.partial_pos_out)
    }

    /// `WriteRingBuffer`: dumps output.  Returns NEEDS_MORE_OUTPUT only if
    /// there is more output to push and either ring-buffer is as big as
    /// window size, or `force` is true.
    #[inline(never)]
    fn write_ring_buffer(
        &mut self,
        available_out: &mut usize,
        next_out: &mut OutSink,
        total_out: Option<&mut usize>,
        force: bool,
    ) -> i32 {
        let start = self.partial_pos_out & (self.ringbuffer_mask as usize);
        let to_write = self.unwritten_bytes(true);
        let mut num_written = *available_out;
        if num_written > to_write {
            num_written = to_write;
        }
        if self.meta_block_remaining_len < 0 {
            return BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_1;
        }
        match next_out {
            OutSink::Take(slot) => *slot = Some(start),
            OutSink::Buf { buf, pos } => {
                buf[*pos..*pos + num_written].copy_from_slice(&self.ringbuffer[start..start + num_written]);
                *pos += num_written;
            }
            OutSink::Null => {}
        }
        *available_out -= num_written;
        self.partial_pos_out = self.partial_pos_out.wrapping_add(num_written);
        if let Some(t) = total_out {
            *t = self.partial_pos_out;
        }
        if num_written < to_write {
            if self.ringbuffer_size == (1i32 << self.window_bits) || force {
                return NEEDS_MORE_OUTPUT;
            } else {
                return SUCCESS;
            }
        }
        // Wrap ring buffer only if it has reached its maximal size.
        if self.ringbuffer_size == (1i32 << self.window_bits) && self.pos >= self.ringbuffer_size {
            self.pos -= self.ringbuffer_size;
            self.rb_roundtrips = self.rb_roundtrips.wrapping_add(1);
            self.should_wrap_ringbuffer = if self.pos != 0 { 1 } else { 0 };
        }
        SUCCESS
    }

    /// `WrapRingBuffer`.
    #[inline(never)]
    fn wrap_ring_buffer(&mut self) {
        if self.should_wrap_ringbuffer != 0 {
            let end = self.ringbuffer_size as usize;
            self.ringbuffer.copy_within(end..end + self.pos as usize, 0);
            self.should_wrap_ringbuffer = 0;
        }
    }

    /// `BrotliEnsureRingBuffer`: allocates ring-buffer.
    ///
    /// s->ringbuffer_size MUST be updated by BrotliCalculateRingBufferSize
    /// before this function is called.
    ///
    /// Last two bytes of ring-buffer are initialized to 0, so context
    /// calculation could be done uniformly for the first two and all other
    /// positions.
    #[inline(never)]
    fn ensure_ring_buffer(&mut self) -> bool {
        if self.ringbuffer_size == self.new_ringbuffer_size {
            return true;
        }
        let new_size = self.new_ringbuffer_size as usize;
        let mut rb = match Buf::try_new_zeroed(&self.alloc, new_size.wrapping_add(K_RING_BUFFER_WRITE_AHEAD_SLACK)) {
            Some(b) => b,
            // Restore previous value.
            None => return false,
        };
        rb[new_size - 2] = 0;
        rb[new_size - 1] = 0;

        if !self.ringbuffer.is_empty() {
            let pos = self.pos as usize;
            rb[..pos].copy_from_slice(&self.ringbuffer[..pos]);
        }
        // The old ring buffer (if any) is freed here.
        self.ringbuffer = rb;

        self.ringbuffer_size = self.new_ringbuffer_size;
        self.ringbuffer_mask = self.new_ringbuffer_size - 1;
        true
    }

    /// `SkipMetadataBlock`.
    #[inline(never)]
    fn skip_metadata_block(&mut self, inp: &[u8]) -> i32 {
        if self.meta_block_remaining_len == 0 {
            return SUCCESS;
        }

        debug_assert!((self.br.get_available_bits() & 7) == 0);

        // Drain accumulator.
        if self.br.get_available_bits() >= 8 {
            let mut buffer = [0u8; 8];
            let mut nbytes = (self.br.get_available_bits() >> 3) as i32;
            debug_assert!(nbytes <= 8);
            if nbytes > self.meta_block_remaining_len {
                nbytes = self.meta_block_remaining_len;
            }
            self.br.copy_bytes(&mut buffer, inp, nbytes as usize);
            if let Some(f) = self.metadata_chunk_func {
                // SAFETY: client callback, called exactly like in C with a
                // pointer to `nbytes` valid bytes.
                unsafe { f(self.metadata_callback_opaque, buffer.as_ptr(), nbytes as usize) };
            }
            self.meta_block_remaining_len -= nbytes;
            if self.meta_block_remaining_len == 0 {
                return SUCCESS;
            }
        }

        // Direct access to metadata is possible.
        let mut nbytes = self.br.get_remaining_bytes() as i32;
        if nbytes > self.meta_block_remaining_len {
            nbytes = self.meta_block_remaining_len;
        }
        if nbytes > 0 {
            if let Some(f) = self.metadata_chunk_func {
                let data = &inp[self.br.next_in..self.br.next_in + nbytes as usize];
                // SAFETY: client callback, called exactly like in C with a
                // pointer to `nbytes` valid input bytes.
                unsafe { f(self.metadata_callback_opaque, data.as_ptr(), nbytes as usize) };
            }
            self.br.drop_bytes(nbytes as usize);
            self.meta_block_remaining_len -= nbytes;
            if self.meta_block_remaining_len == 0 {
                return SUCCESS;
            }
        }

        debug_assert!(self.br.get_remaining_bytes() == 0);

        NEEDS_MORE_INPUT
    }

    /// `CopyUncompressedBlockToOutput`.
    #[inline(never)]
    fn copy_uncompressed_block_to_output(
        &mut self,
        available_out: &mut usize,
        next_out: &mut OutSink,
        mut total_out: Option<&mut usize>,
        inp: &[u8],
    ) -> i32 {
        // TODO(eustas): avoid allocation for single uncompressed block.
        if !self.ensure_ring_buffer() {
            return BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_1;
        }

        // State machine
        loop {
            match self.substate_uncompressed {
                UncompressedState::None => {
                    let mut nbytes = self.br.get_remaining_bytes() as i32;
                    if nbytes > self.meta_block_remaining_len {
                        nbytes = self.meta_block_remaining_len;
                    }
                    if self.pos + nbytes > self.ringbuffer_size {
                        nbytes = self.ringbuffer_size - self.pos;
                    }
                    // Copy remaining bytes from s->br.buf_ to ring-buffer.
                    let pos = self.pos as usize;
                    self.br.copy_bytes(&mut self.ringbuffer[pos..], inp, nbytes as usize);
                    self.pos += nbytes;
                    self.meta_block_remaining_len -= nbytes;
                    if self.pos < (1i32 << self.window_bits) {
                        if self.meta_block_remaining_len == 0 {
                            return SUCCESS;
                        }
                        return NEEDS_MORE_INPUT;
                    }
                    self.substate_uncompressed = UncompressedState::Write;
                }
                UncompressedState::Write => {
                    let result = self.write_ring_buffer(available_out, next_out, total_out.as_deref_mut(), false);
                    if result != SUCCESS {
                        return result;
                    }
                    if self.ringbuffer_size == (1i32 << self.window_bits) {
                        self.max_distance = self.max_backward_distance;
                    }
                    self.substate_uncompressed = UncompressedState::None;
                }
            }
        }
    }

    /// `AttachCompoundDictionary`.
    fn attach_compound_dictionary(&mut self, data: *const u8, size: usize) -> bool {
        // Soft lie: no dictionary is attached; i.e. this call is not
        // accounted towards SHARED_BROTLI_MAX_COMPOUND_DICTS limit.
        if size == 0 {
            return true;
        }
        if size > SHARED_BROTLI_MAX_RAW_DICT_SIZE as usize {
            return false;
        }
        if self.state != RunningState::Uninited {
            return false;
        }
        if self.compound_dictionary.is_none() {
            let addon = CompoundDictionary {
                num_chunks: 0,
                block_bits: 255,
                br_index: 0,
                total_size: 0,
                br_offset: 0,
                br_length: 0,
                br_copied: 0,
                chunks: [core::ptr::null(); 16],
                chunk_offsets: [0; 16],
                block_map: [0; 256],
            };
            match Boxed::try_new(&self.alloc, addon) {
                Some(b) => self.compound_dictionary = Some(b),
                None => return false,
            }
        }
        let addon = match self.compound_dictionary.as_mut() {
            Some(a) => a,
            None => return false,
        };
        if addon.num_chunks as usize == SHARED_BROTLI_MAX_COMPOUND_DICTS {
            return false;
        }
        if size > (SHARED_BROTLI_MAX_RAW_DICT_SIZE - addon.total_size) as usize {
            return false;
        }
        let n = addon.num_chunks as usize;
        addon.chunks[n] = data;
        addon.num_chunks += 1;
        addon.total_size += size as u32;
        let total = addon.total_size;
        addon.chunk_offsets[n + 1] = total;
        true
    }

    /// `InitializeCompoundDictionaryCopy`.
    fn initialize_compound_dictionary_copy(&mut self, address: u32, length: u32) -> bool {
        let addon = match self.compound_dictionary.as_mut() {
            Some(a) => a,
            None => return false,
        };
        debug_assert!(addon.total_size > 0);
        debug_assert!(address < addon.total_size);
        debug_assert!(length > 0);
        ensure_compound_dictionary_initialized(addon);
        let mut index = addon.block_map[(address >> addon.block_bits) as usize] as usize;
        // Several chunks might be mapped to the same block index.
        while address >= addon.chunk_offsets[index + 1] {
            index += 1;
        }
        // Check that the whole chunk is within dictionary bounds.
        if length > addon.total_size - address {
            return false;
        }
        // Update the recent distances cache.
        self.dist_rb[(self.dist_rb_idx & 3) as usize] = self.distance_code;
        self.dist_rb_idx = self.dist_rb_idx.wrapping_add(1);
        self.meta_block_remaining_len = self.meta_block_remaining_len.wrapping_sub(length as i32);
        addon.br_index = index as u16;
        addon.br_offset = address - addon.chunk_offsets[index];
        addon.br_length = length;
        addon.br_copied = 0;
        true
    }

    /// `GetCompoundDictionarySize`.
    #[inline(always)]
    fn get_compound_dictionary_size(&self) -> u32 {
        match &self.compound_dictionary {
            Some(a) => a.total_size,
            None => 0,
        }
    }

    /// `CopyFromCompoundDictionary`.
    fn copy_from_compound_dictionary(&mut self, mut pos: i32) -> i32 {
        let addon = match self.compound_dictionary.as_mut() {
            Some(a) => a,
            None => return 0,
        };
        let orig_pos = pos;
        while addon.br_length != addon.br_copied {
            let idx = addon.br_index as usize;
            let space = self.ringbuffer_size - pos;
            let rem_chunk_length = (addon.chunk_offsets[idx + 1] - addon.chunk_offsets[idx]) - addon.br_offset;
            let mut length = addon.br_length - addon.br_copied;
            if length > rem_chunk_length {
                length = rem_chunk_length;
            }
            if length > space as u32 {
                length = space as u32;
            }
            // SAFETY: chunk `idx` is client memory of
            // `chunk_offsets[idx + 1] - chunk_offsets[idx]` bytes that must
            // outlive the decoder (C contract of BrotliDecoderAttachDictionary);
            // `br_offset + length` does not exceed it.
            let src = unsafe {
                core::slice::from_raw_parts(addon.chunks[idx].add(addon.br_offset as usize), length as usize)
            };
            let p = pos as usize;
            self.ringbuffer[p..p + length as usize].copy_from_slice(src);
            pos += length as i32;
            addon.br_offset += length;
            addon.br_copied += length;
            if length == rem_chunk_length {
                addon.br_index += 1;
                addon.br_offset = 0;
            }
            if pos == self.ringbuffer_size {
                break;
            }
        }
        pos - orig_pos
    }

    /// `BrotliCalculateRingBufferSize`: calculates the smallest feasible ring
    /// buffer.
    ///
    /// If we know the data size is small, do not allocate more ring buffer
    /// size than needed to reduce memory usage.
    ///
    /// When this method is called, metablock size and flags MUST be decoded.
    #[inline(never)]
    fn calculate_ring_buffer_size(&mut self) {
        let window_size: i32 = 1 << self.window_bits;
        let mut new_ringbuffer_size = window_size;
        // We need at least 2 bytes of ring buffer size to get the last two
        // bytes for context from there
        let mut min_size = if self.ringbuffer_size != 0 { self.ringbuffer_size } else { 1024 };

        // If maximum is already reached, no further extension is retired.
        if self.ringbuffer_size == window_size {
            return;
        }

        // Metadata blocks does not touch ring buffer.
        if self.is_metadata != 0 {
            return;
        }

        let mut output_size = if self.ringbuffer.is_empty() { 0 } else { self.pos };
        output_size += self.meta_block_remaining_len;
        min_size = if min_size < output_size { output_size } else { min_size };

        if self.canny_ringbuffer_allocation != 0 {
            // Reduce ring buffer size to save memory when server is
            // unscrupulous. In worst case memory usage might be 1.5x bigger
            // for a short period of ring buffer reallocation.
            while (new_ringbuffer_size >> 1) >= min_size {
                new_ringbuffer_size >>= 1;
            }
        }

        self.new_ringbuffer_size = new_ringbuffer_size;
    }

    /// `ReadContextModes`: reads 1..256 2-bit context modes.
    fn read_context_modes(&mut self, inp: &[u8]) -> i32 {
        let mut i = self.loop_counter;

        while i < self.num_block_types[0] as i32 {
            let mut bits: Reg = 0;
            if !self.br.safe_read_bits(inp, 2, &mut bits) {
                self.loop_counter = i;
                return NEEDS_MORE_INPUT;
            }
            self.context_modes[i as usize] = bits as u8;
            i += 1;
        }
        SUCCESS
    }

    /// `TakeDistanceFromRingBuffer`.
    #[inline(always)]
    fn take_distance_from_ring_buffer(&mut self) {
        let offset = self.distance_code - 3;
        if self.distance_code <= 3 {
            // Compensate double distance-ring-buffer roll for dictionary
            // items.
            self.distance_context = 1 >> self.distance_code;
            self.distance_code = self.dist_rb[(self.dist_rb_idx.wrapping_sub(offset) & 3) as usize];
            self.dist_rb_idx = self.dist_rb_idx.wrapping_sub(self.distance_context);
        } else {
            let mut index_delta = 3;
            let mut base = self.distance_code - 10;
            if self.distance_code < 10 {
                base = self.distance_code - 4;
            } else {
                index_delta = 2;
            }
            // Unpack one of six 4-bit values.
            let delta = ((0x605142 >> (4 * base)) & 0xF) - 3;
            self.distance_code = self.dist_rb[(self.dist_rb_idx.wrapping_add(index_delta) & 0x3) as usize].wrapping_add(delta);
            if self.distance_code <= 0 {
                // A huge distance will cause a BROTLI_FAILURE() soon.
                // This is a little faster than failing here.
                self.distance_code = 0x7FFFFFFF;
            }
        }
    }

    /// `CalculateDistanceLut`: calculates distance lookup table.
    /// NB: it is possible to have all 64 tables precalculated.
    fn calculate_distance_lut(&mut self) {
        let b = &mut self.body;
        let npostfix = self.distance_postfix_bits;
        let ndirect = self.num_direct_distance_codes;
        let alphabet_size_limit = self.distance_hgroup.alphabet_size_limit as Reg;
        let postfix: Reg = (1 as Reg) << npostfix;
        let mut bits: Reg = 1;
        let mut half: Reg = 0;

        // Skip short codes.
        let mut i = BROTLI_NUM_DISTANCE_SHORT_CODES as usize;

        // Fill direct codes.
        for j in 0..ndirect {
            b.dist_extra_bits[i] = 0;
            b.dist_offset[i] = j + 1;
            i += 1;
        }

        // Fill regular distance codes.
        while (i as Reg) < alphabet_size_limit {
            let base = ndirect
                .wrapping_add((((2 + half) << bits).wrapping_sub(4)) << npostfix)
                .wrapping_add(1);
            // Always fill the complete group.
            for j in 0..postfix {
                b.dist_extra_bits[i] = bits as u8;
                b.dist_offset[i] = base.wrapping_add(j);
                i += 1;
            }
            bits += half;
            half ^= 1;
        }
    }

    /// `ReadDistanceInternal`. Precondition: s->distance_code < 0.
    #[inline(always)]
    fn read_distance_internal<const SAFE: bool>(&mut self, inp: &[u8]) -> bool {
        let mut code: Reg = 0;
        let mut bits: Reg = 0;
        let mut memento = BitReaderState::default();
        let tree = self.distance_hgroup.htrees[self.dist_htree_index as usize] as usize;
        let distance_tree = &self.distance_hgroup.mem[tree..];
        let br = &mut self.br;
        if !SAFE {
            code = read_symbol(distance_tree, br, inp);
        } else {
            memento = br.save_state();
            if !safe_read_symbol(distance_tree, br, inp, &mut code) {
                return false;
            }
        }
        self.block_length[2] = self.block_length[2].wrapping_sub(1);
        // Convert the distance code to the actual distance by possibly
        // looking up past distances from the s->dist_rb.
        self.distance_context = 0;
        if (code & !0xF) == 0 {
            self.distance_code = code as i32;
            self.take_distance_from_ring_buffer();
            return true;
        }
        let extra = self.body.dist_extra_bits[code as usize] as Reg;
        if !SAFE {
            bits = br.read_bits32(inp, extra);
        } else if !safe_read_bits32(br, inp, extra, &mut bits) {
            self.block_length[2] = self.block_length[2].wrapping_add(1);
            br.restore_state(&memento);
            return false;
        }
        self.distance_code = self.body.dist_offset[code as usize].wrapping_add(bits << self.distance_postfix_bits) as i32;
        true
    }

    /// `ReadCommandInternal`.
    #[inline(always)]
    fn read_command_internal<const SAFE: bool>(&mut self, inp: &[u8], insert_length: &mut i32) -> bool {
        let mut cmd_code: Reg = 0;
        let mut insert_len_extra: Reg = 0;
        let mut copy_length: Reg = 0;
        let mut memento = BitReaderState::default();
        let table = &self.insert_copy_hgroup.mem[self.htree_command..];
        let br = &mut self.br;
        if !SAFE {
            cmd_code = read_symbol(table, br, inp);
        } else {
            memento = br.save_state();
            if !safe_read_symbol(table, br, inp, &mut cmd_code) {
                return false;
            }
        }
        let v = K_CMD_LUT[cmd_code as usize];
        self.distance_code = v.distance_code as i32;
        self.distance_context = v.context as i32;
        self.dist_htree_index = self.dist_context_map[self.dist_context_map_slice + self.distance_context as usize];
        *insert_length = v.insert_len_offset as i32;
        if !SAFE {
            if v.insert_len_extra_bits != 0 {
                insert_len_extra = br.read_bits24(inp, v.insert_len_extra_bits as Reg);
            }
            copy_length = br.read_bits24(inp, v.copy_len_extra_bits as Reg);
        } else if !safe_read_bits(br, inp, v.insert_len_extra_bits as Reg, &mut insert_len_extra)
            || !safe_read_bits(br, inp, v.copy_len_extra_bits as Reg, &mut copy_length)
        {
            br.restore_state(&memento);
            return false;
        }
        self.copy_length = copy_length as i32 + v.copy_len_offset as i32;
        self.block_length[1] = self.block_length[1].wrapping_sub(1);
        *insert_length += insert_len_extra as i32;
        true
    }

    /// `ProcessCommandsInternal`.
    #[inline(always)]
    fn process_commands_internal<const SAFE: bool>(&mut self, inp: &[u8]) -> i32 {
        let mut pos = self.pos;
        let mut i = self.loop_counter;
        let mut result = SUCCESS;
        let compound_dictionary_size = self.get_compound_dictionary_size();

        let mut label;
        if !check_input_amount::<SAFE>(&self.br) {
            result = NEEDS_MORE_INPUT;
            label = Label::SaveStateAndReturn;
        } else {
            if !SAFE {
                let _ = self.br.warmup(inp);
            }
            // Jump into state machine.
            label = match self.state {
                RunningState::CommandBegin => Label::CommandBegin,
                RunningState::CommandInner => Label::CommandInner,
                RunningState::CommandPostDecodeLiterals => Label::CommandPostDecodeLiterals,
                RunningState::CommandPostWrapCopy => Label::CommandPostWrapCopy,
                _ => return BROTLI_DECODER_ERROR_UNREACHABLE,
            };
        }

        loop {
            match label {
                Label::CommandBegin => {
                    if SAFE {
                        self.state = RunningState::CommandBegin;
                    }
                    if !check_input_amount::<SAFE>(&self.br) {
                        self.state = RunningState::CommandBegin;
                        result = NEEDS_MORE_INPUT;
                        label = Label::SaveStateAndReturn;
                        continue;
                    }
                    if self.block_length[1] == 0 {
                        let status = self.decode_command_block_switch_internal::<SAFE>(inp);
                        if status != SUCCESS {
                            result = status;
                            label = Label::SaveStateAndReturn;
                            continue;
                        }
                        label = Label::CommandBegin;
                        continue;
                    }
                    // Read the insert/copy length in the command.
                    if !self.read_command_internal::<SAFE>(inp, &mut i) && SAFE {
                        result = NEEDS_MORE_INPUT;
                        label = Label::SaveStateAndReturn;
                        continue;
                    }
                    if i == 0 {
                        label = Label::CommandPostDecodeLiterals;
                        continue;
                    }
                    self.meta_block_remaining_len = self.meta_block_remaining_len.wrapping_sub(i);
                    label = Label::CommandInner;
                }

                Label::CommandInner => {
                    if SAFE {
                        self.state = RunningState::CommandInner;
                    }
                    // Read the literals in the command.
                    if self.trivial_literal_context != 0 {
                        let mut bits: Reg = 0;
                        let mut value: Reg = 0;
                        let table = &self.literal_hgroup.mem[self.literal_htree..];
                        let br = &mut self.br;
                        if !SAFE {
                            preload_symbol(table, br, inp, &mut bits, &mut value);
                            // This is a hottest part of the decode, so we copy
                            // the loop below and optimize it by calculating the
                            // number of steps where all checks evaluate to
                            // false (ringbuffer size/block size/input size).
                            // Since all checks are loop invariant, we just need
                            // to find minimal number of iterations for a simple
                            // loop, and run the full version for the remainder.
                            let mut num_steps = i - 1;
                            if num_steps > 0 && (num_steps as Reg) > self.block_length[0] {
                                // Safe cast, since block_length < steps
                                num_steps = self.block_length[0] as i32;
                            }
                            if self.ringbuffer_size >= pos && (self.ringbuffer_size - pos) <= num_steps {
                                num_steps = self.ringbuffer_size - pos - 1;
                            }
                            if num_steps < 0 {
                                num_steps = 0;
                            }
                            num_steps = copy_preloaded_symbols_to_u8(
                                table,
                                br,
                                inp,
                                &mut bits,
                                &mut value,
                                &mut self.ringbuffer,
                                pos,
                                num_steps,
                            );
                            pos += num_steps;
                            self.block_length[0] = self.block_length[0].wrapping_sub(num_steps as Reg);
                            i -= num_steps;
                            label = loop {
                                if !br.check_input_amount() {
                                    self.state = RunningState::CommandInner;
                                    result = NEEDS_MORE_INPUT;
                                    break Label::SaveStateAndReturn;
                                }
                                if self.block_length[0] == 0 {
                                    break Label::NextLiteralBlock;
                                }
                                copy_preloaded_symbols_to_u8(
                                    table,
                                    br,
                                    inp,
                                    &mut bits,
                                    &mut value,
                                    &mut self.ringbuffer,
                                    pos,
                                    1,
                                );
                                self.block_length[0] -= 1;
                                pos += 1;
                                if pos == self.ringbuffer_size {
                                    self.state = RunningState::CommandInnerWrite;
                                    i -= 1;
                                    break Label::SaveStateAndReturn;
                                }
                                i -= 1;
                                if i == 0 {
                                    break Label::AfterLiterals;
                                }
                            };
                        } else {
                            // safe
                            label = loop {
                                let mut literal: Reg = 0;
                                if self.block_length[0] == 0 {
                                    break Label::NextLiteralBlock;
                                }
                                if !safe_read_symbol(table, br, inp, &mut literal) {
                                    result = NEEDS_MORE_INPUT;
                                    break Label::SaveStateAndReturn;
                                }
                                self.ringbuffer[pos as usize] = literal as u8;
                                self.block_length[0] -= 1;
                                pos += 1;
                                if pos == self.ringbuffer_size {
                                    self.state = RunningState::CommandInnerWrite;
                                    i -= 1;
                                    break Label::SaveStateAndReturn;
                                }
                                i -= 1;
                                if i == 0 {
                                    break Label::AfterLiterals;
                                }
                            };
                        }
                    } else {
                        let mask = self.ringbuffer_mask;
                        let mut p1 = self.ringbuffer[((pos - 1) & mask) as usize];
                        let mut p2 = self.ringbuffer[((pos - 2) & mask) as usize];
                        let lut = self.context_lookup;
                        let br = &mut self.br;
                        label = loop {
                            if !check_input_amount::<SAFE>(br) {
                                self.state = RunningState::CommandInner;
                                result = NEEDS_MORE_INPUT;
                                break Label::SaveStateAndReturn;
                            }
                            if self.block_length[0] == 0 {
                                break Label::NextLiteralBlock;
                            }
                            let context = brotli_context(p1, p2, lut);
                            let htree = self.literal_hgroup.htrees
                                [self.context_map[self.context_map_slice + context as usize] as usize]
                                as usize;
                            let hc = &self.literal_hgroup.mem[htree..];
                            p2 = p1;
                            if !SAFE {
                                p1 = read_symbol(hc, br, inp) as u8;
                            } else {
                                let mut literal: Reg = 0;
                                if !safe_read_symbol(hc, br, inp, &mut literal) {
                                    result = NEEDS_MORE_INPUT;
                                    break Label::SaveStateAndReturn;
                                }
                                p1 = literal as u8;
                            }
                            self.ringbuffer[pos as usize] = p1;
                            self.block_length[0] -= 1;
                            pos += 1;
                            if pos == self.ringbuffer_size {
                                self.state = RunningState::CommandInnerWrite;
                                i -= 1;
                                break Label::SaveStateAndReturn;
                            }
                            i -= 1;
                            if i == 0 {
                                break Label::AfterLiterals;
                            }
                        };
                    }
                }

                Label::AfterLiterals => {
                    if self.meta_block_remaining_len <= 0 {
                        self.state = RunningState::MetablockDone;
                        label = Label::SaveStateAndReturn;
                        continue;
                    }
                    label = Label::CommandPostDecodeLiterals;
                }

                Label::CommandPostDecodeLiterals => {
                    if SAFE {
                        self.state = RunningState::CommandPostDecodeLiterals;
                    }
                    if self.distance_code >= 0 {
                        // Implicit distance case.
                        self.distance_context = if self.distance_code != 0 { 0 } else { 1 };
                        self.dist_rb_idx = self.dist_rb_idx.wrapping_sub(1);
                        self.distance_code = self.dist_rb[(self.dist_rb_idx & 3) as usize];
                    } else {
                        // Read distance code in the command, unless it was
                        // implicitly zero.
                        if self.block_length[2] == 0 {
                            let status = self.decode_distance_block_switch_internal::<SAFE>(inp);
                            if status != SUCCESS {
                                result = status;
                                label = Label::SaveStateAndReturn;
                                continue;
                            }
                        }
                        if !self.read_distance_internal::<SAFE>(inp) && SAFE {
                            result = NEEDS_MORE_INPUT;
                            label = Label::SaveStateAndReturn;
                            continue;
                        }
                    }
                    if self.max_distance != self.max_backward_distance {
                        self.max_distance =
                            if pos < self.max_backward_distance { pos } else { self.max_backward_distance };
                    }
                    i = self.copy_length;
                    // Apply copy of LZ77 back-reference, or static dictionary
                    // reference if the distance is larger than the max LZ77
                    // distance
                    if self.distance_code > self.max_distance {
                        // The maximum allowed distance is
                        // BROTLI_MAX_ALLOWED_DISTANCE = 0x7FFFFFFC. With this
                        // choice, no signed overflow can occur after decoding
                        // a special distance code (e.g., after adding 3 to
                        // the last distance).
                        if self.distance_code > BROTLI_MAX_ALLOWED_DISTANCE as i32 {
                            return BROTLI_DECODER_ERROR_FORMAT_DISTANCE;
                        }
                        // Check that LZ77-dictionary address is non-negative.
                        if ((self.distance_code - self.max_distance) as u32).wrapping_sub(1) < compound_dictionary_size {
                            // Given that `s->distance_code - s->max_distance >
                            // 0` we have `address` is strictly less than
                            // `compound_dictionary_size`.
                            let address = compound_dictionary_size - (self.distance_code - self.max_distance) as u32;
                            if !self.initialize_compound_dictionary_copy(address, i as u32) {
                                return BROTLI_DECODER_ERROR_COMPOUND_DICTIONARY;
                            }
                            pos += self.copy_from_compound_dictionary(pos);
                            if pos >= self.ringbuffer_size {
                                self.state = RunningState::CommandPostWrite1;
                                label = Label::SaveStateAndReturn;
                                continue;
                            }
                            // In else branch we have:
                            // `s->distance_code - s->max_distance - 1 >=
                            // compound_dictionary_size`; that implies that
                            // `compound_dictionary_size` could be cast to int.
                        } else if i >= SHARED_BROTLI_MIN_DICTIONARY_WORD_LENGTH as i32
                            && i <= SHARED_BROTLI_MAX_DICTIONARY_WORD_LENGTH as i32
                        {
                            let mask_rb = self.ringbuffer_mask;
                            let p1 = self.ringbuffer[((pos - 1) & mask_rb) as usize];
                            let p2 = self.ringbuffer[((pos - 2) & mask_rb) as usize];
                            let dictionary = match self.dictionary.as_deref() {
                                Some(d) => d,
                                None => return BROTLI_DECODER_ERROR_UNREACHABLE,
                            };
                            let mut dict_id: u8 = if dictionary.context_based {
                                dictionary.context_map[brotli_context(p1, p2, self.context_lookup) as usize]
                            } else {
                                0
                            };
                            let iu = i as usize;
                            let mut words: &BrotliDictionary = dictionary.words[dict_id as usize];
                            let mut transforms: &BrotliTransforms = dictionary.transforms[dict_id as usize];
                            let mut offset = words.offsets_by_length[iu] as i32;
                            let mut shift = words.size_bits_by_length[iu] as Reg;
                            let mut address = self.distance_code - self.max_distance - 1 - compound_dictionary_size as i32;
                            let mut mask = bit_mask(shift) as i32;
                            let mut word_idx = address & mask;
                            let mut transform_idx = address >> shift;
                            // Compensate double distance-ring-buffer roll.
                            self.dist_rb_idx = self.dist_rb_idx.wrapping_add(self.distance_context);
                            offset += word_idx * i;
                            // If the distance is out of bound, select a next
                            // static dictionary if there exist multiple.
                            if (transform_idx >= transforms.num_transforms as i32
                                || words.size_bits_by_length[iu] == 0)
                                && dictionary.num_dictionaries > 1
                            {
                                let mut dist_remaining = address
                                    .wrapping_sub((((1u32 << shift) & !1u32) as i32).wrapping_mul(transforms.num_transforms as i32));
                                let mut dict_id2: u8 = 0;
                                while dict_id2 < dictionary.num_dictionaries {
                                    let words2 = dictionary.words[dict_id2 as usize];
                                    if dict_id2 != dict_id && words2.size_bits_by_length[iu] != 0 {
                                        let transforms2 = dictionary.transforms[dict_id2 as usize];
                                        let shift2 = words2.size_bits_by_length[iu] as Reg;
                                        let num = (((1u32 << shift2) & !1u32) as i32)
                                            .wrapping_mul(transforms2.num_transforms as i32);
                                        if dist_remaining < num {
                                            dict_id = dict_id2;
                                            words = words2;
                                            transforms = transforms2;
                                            address = dist_remaining;
                                            shift = shift2;
                                            mask = bit_mask(shift) as i32;
                                            word_idx = address & mask;
                                            transform_idx = address >> shift;
                                            offset = words.offsets_by_length[iu] as i32 + word_idx * i;
                                            break;
                                        }
                                        dist_remaining = dist_remaining.wrapping_sub(num);
                                    }
                                    dict_id2 += 1;
                                }
                            }
                            let _ = dict_id;
                            if words.size_bits_by_length[iu] == 0 {
                                return BROTLI_DECODER_ERROR_FORMAT_DICTIONARY;
                            }
                            if words.data.is_null() {
                                return BROTLI_DECODER_ERROR_DICTIONARY_NOT_SET;
                            }
                            if transform_idx < transforms.num_transforms as i32 {
                                let word = &words.data()[offset as usize..];
                                let mut len = i;
                                let p = pos as usize;
                                if transform_idx == transforms.cut_off_transforms[0] as i32 {
                                    self.ringbuffer[p..p + len as usize].copy_from_slice(&word[..len as usize]);
                                } else {
                                    len = transform_dictionary_word(
                                        &mut self.ringbuffer[p..],
                                        word,
                                        len,
                                        transforms,
                                        transform_idx,
                                    );
                                    if len == 0 && self.distance_code <= 120 {
                                        return BROTLI_DECODER_ERROR_FORMAT_TRANSFORM;
                                    }
                                }
                                pos += len;
                                self.meta_block_remaining_len = self.meta_block_remaining_len.wrapping_sub(len);
                                if pos >= self.ringbuffer_size {
                                    self.state = RunningState::CommandPostWrite1;
                                    label = Label::SaveStateAndReturn;
                                    continue;
                                }
                            } else {
                                return BROTLI_DECODER_ERROR_FORMAT_TRANSFORM;
                            }
                        } else {
                            return BROTLI_DECODER_ERROR_FORMAT_DICTIONARY;
                        }
                    } else {
                        let src_start = (pos - self.distance_code) & self.ringbuffer_mask;
                        let copy_dst = pos as usize;
                        let copy_src = src_start as usize;
                        let dst_end = pos + i;
                        let src_end = src_start + i;
                        // Update the recent distances cache.
                        self.dist_rb[(self.dist_rb_idx & 3) as usize] = self.distance_code;
                        self.dist_rb_idx = self.dist_rb_idx.wrapping_add(1);
                        self.meta_block_remaining_len = self.meta_block_remaining_len.wrapping_sub(i);
                        // There are 32+ bytes of slack in the ring-buffer
                        // allocation. Also, we have 16 short codes, that make
                        // these 16 bytes irrelevant in the ring-buffer. Let's
                        // copy over them as a first guess.
                        self.ringbuffer.copy_within(copy_src..copy_src + 16, copy_dst);
                        if src_end > pos && dst_end > src_start {
                            // Regions intersect.
                            label = Label::CommandPostWrapCopy;
                            continue;
                        }
                        if dst_end >= self.ringbuffer_size || src_end >= self.ringbuffer_size {
                            // At least one region wraps.
                            label = Label::CommandPostWrapCopy;
                            continue;
                        }
                        pos += i;
                        if i > 16 {
                            if i > 32 {
                                self.ringbuffer.copy_within(copy_src + 16..copy_src + i as usize, copy_dst + 16);
                            } else {
                                // This branch covers about 45% cases. Fixed size
                                // short copy allows more compiler optimizations.
                                self.ringbuffer.copy_within(copy_src + 16..copy_src + 32, copy_dst + 16);
                            }
                        }
                    }
                    if self.meta_block_remaining_len <= 0 {
                        // Next metablock, if any.
                        self.state = RunningState::MetablockDone;
                        label = Label::SaveStateAndReturn;
                    } else {
                        label = Label::CommandBegin;
                    }
                }

                Label::CommandPostWrapCopy => {
                    let mut wrap_guard = self.ringbuffer_size - pos;
                    let mask = self.ringbuffer_mask;
                    let distance_code = self.distance_code;
                    let mut wrapped = false;
                    loop {
                        i -= 1;
                        if i < 0 {
                            break;
                        }
                        self.ringbuffer[pos as usize] = self.ringbuffer[((pos - distance_code) & mask) as usize];
                        pos += 1;
                        wrap_guard -= 1;
                        if wrap_guard == 0 {
                            wrapped = true;
                            break;
                        }
                    }
                    if wrapped {
                        self.state = RunningState::CommandPostWrite2;
                        label = Label::SaveStateAndReturn;
                        continue;
                    }
                    if self.meta_block_remaining_len <= 0 {
                        // Next metablock, if any.
                        self.state = RunningState::MetablockDone;
                        label = Label::SaveStateAndReturn;
                    } else {
                        label = Label::CommandBegin;
                    }
                }

                Label::NextLiteralBlock => {
                    let status = self.decode_literal_block_switch_internal::<SAFE>(inp);
                    if status != SUCCESS {
                        result = status;
                        label = Label::SaveStateAndReturn;
                        continue;
                    }
                    label = Label::CommandInner;
                }

                Label::SaveStateAndReturn => {
                    self.pos = pos;
                    self.loop_counter = i;
                    return result;
                }
            }
        }
    }

    /// `ProcessCommands`.
    #[inline(never)]
    fn process_commands(&mut self, inp: &[u8]) -> i32 {
        self.process_commands_internal::<false>(inp)
    }

    /// `SafeProcessCommands`.
    #[inline(never)]
    fn safe_process_commands(&mut self, inp: &[u8]) -> i32 {
        self.process_commands_internal::<true>(inp)
    }

    /// `BrotliDecoderSetParameter`.
    pub fn set_parameter(&mut self, p: i32, value: u32) -> bool {
        if self.state != RunningState::Uninited {
            return false;
        }
        match p {
            BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION => {
                self.canny_ringbuffer_allocation = if value != 0 { 0 } else { 1 };
                true
            }
            BROTLI_DECODER_PARAM_LARGE_WINDOW => {
                self.large_window = if value != 0 { 1 } else { 0 };
                true
            }
            _ => false,
        }
    }

    /// `BrotliDecoderAttachDictionary`.
    ///
    /// # Safety
    /// `data` must point to `data_size` readable bytes that stay valid (and
    /// unchanged) for the whole lifetime of the decoder.
    pub unsafe fn attach_dictionary(&mut self, dict_type: i32, data_size: usize, data: *const u8) -> bool {
        let num_prefix_before = match &self.dictionary {
            Some(d) => d.num_prefix,
            None => return false,
        };
        if self.state != RunningState::Uninited {
            return false;
        }
        let ok = match self.dictionary.as_mut() {
            Some(d) => d.attach(dict_type as u32, data_size, data),
            None => false,
        };
        if !ok {
            return false;
        }
        let mut i = num_prefix_before;
        loop {
            let (num_prefix, prefix, prefix_size) = match &self.dictionary {
                Some(d) => {
                    if i >= d.num_prefix {
                        break;
                    }
                    (d.num_prefix, d.prefix[i as usize], d.prefix_size[i as usize])
                }
                None => return false,
            };
            let _ = num_prefix;
            if !self.attach_compound_dictionary(prefix, prefix_size) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// `BrotliDecoderSetMetadataCallbacks`.
    ///
    /// # Safety
    /// The callbacks are invoked with `opaque` during decompression, exactly
    /// like the C library does.
    pub unsafe fn set_metadata_callbacks(
        &mut self,
        start_func: MetadataStartFunc,
        chunk_func: MetadataChunkFunc,
        opaque: *mut c_void,
    ) {
        self.metadata_start_func = start_func;
        self.metadata_chunk_func = chunk_func;
        self.metadata_callback_opaque = opaque;
    }

    /// Core of `BrotliDecoderDecompressStream`, in C terms:
    ///
    /// * `input` is `[*next_in, *next_in + *available_in)`; `*in_pos` is the
    ///   number of bytes of `input` consumed so far (C: how far `*next_in`
    ///   has advanced), so `*available_in == input.len() - *in_pos`.
    /// * `available_out` is `*available_out`; `next_out` is `None` if
    ///   `next_out == NULL || *next_out == NULL`, otherwise the output window
    ///   `[*next_out, *next_out + *available_out)`.  The number of bytes
    ///   written is the decrease of `*available_out`.
    ///
    /// Invariant: input stream is never overconsumed:
    ///  - invalid input implies that the whole stream is invalid -> any
    ///    amount of input could be read and discarded
    ///  - when result is "needs more input", then at least one more byte is
    ///    REQUIRED to complete decoding; all input data MUST be consumed by
    ///    decoder, so client could swap the input buffer
    ///  - when result is "needs more output" decoder MUST ensure that it
    ///    doesn't hold more than 7 bits in bit reader; this saves client from
    ///    swapping input buffer ahead of time
    ///  - when result is "success" decoder MUST return all unused data back
    ///    to input buffer; this is possible because the invariant is held on
    ///    enter
    pub(crate) fn decompress_stream_raw(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        available_out: &mut usize,
        next_out: Option<&mut [u8]>,
        mut total_out: Option<&mut usize>,
    ) -> BrotliDecoderResult {
        let mut result = SUCCESS;
        let input_size = input.len() - *in_pos;
        macro_rules! consumed {
            () => {
                input_size - (input.len() - *in_pos)
            };
        }
        // Ensure that |total_out| is set, even if no data will ever be pushed
        // out.
        if let Some(t) = total_out.as_deref_mut() {
            *t = self.partial_pos_out;
        }
        // Do not try to process further in a case of unrecoverable error.
        if self.error_code < 0 {
            return BrotliDecoderResult::Error;
        }
        let mut sink = match next_out {
            _ if *available_out == 0 => OutSink::Null,
            Some(buf) => OutSink::Buf { buf, pos: 0 },
            None => {
                return self.save_error_code(BROTLI_DECODER_ERROR_INVALID_ARGUMENTS, consumed!());
            }
        };
        // Local (equally aligned) copy of the internal input buffer; it is
        // only modified in this function.
        let mut buffer = self.buffer;
        if self.buffer_length == 0 {
            // Just connect bit reader to input stream.
            self.br.set_input(*in_pos, input.len() - *in_pos);
        } else {
            // At least one byte of input is required. More than one byte of
            // input may be required to complete the transaction -> reading
            // more data must be done in a loop -> do it in a main loop.
            result = NEEDS_MORE_INPUT;
            self.br.set_input(0, self.buffer_length as usize);
        }
        // State machine
        loop {
            if result != SUCCESS {
                // Error, needs more input/output.
                if result == NEEDS_MORE_INPUT {
                    if !self.ringbuffer.is_empty() {
                        // Pro-actively push output.
                        let intermediate_result =
                            self.write_ring_buffer(available_out, &mut sink, total_out.as_deref_mut(), true);
                        // WriteRingBuffer checks s->meta_block_remaining_len
                        // validity.
                        if intermediate_result < 0 {
                            result = intermediate_result;
                            break;
                        }
                    }
                    if self.buffer_length != 0 {
                        // Used with internal buffer.
                        if self.br.next_in == self.br.last_in {
                            // Successfully finished read transaction.
                            // Accumulator contains less than 8 bits, because
                            // internal buffer is expanded byte-by-byte until
                            // it is enough to complete read.
                            self.buffer_length = 0;
                            // Switch to input stream and restart.
                            result = SUCCESS;
                            self.br.set_input(*in_pos, input.len() - *in_pos);
                            continue;
                        } else if input.len() - *in_pos != 0 {
                            // Not enough data in buffer, but can take one more
                            // byte from input stream.
                            result = SUCCESS;
                            debug_assert!(self.buffer_length < 8);
                            buffer.0[self.buffer_length as usize] = input[*in_pos];
                            self.buffer_length += 1;
                            self.br.set_input(0, self.buffer_length as usize);
                            *in_pos += 1;
                            // Retry with more data in buffer.
                            continue;
                        }
                        // Can't finish reading and no more input.
                        break;
                    } else {
                        // Input stream doesn't contain enough input.
                        // Copy tail to internal buffer and return.
                        *in_pos = self.br.next_in;
                        while input.len() - *in_pos != 0 {
                            buffer.0[self.buffer_length as usize] = input[*in_pos];
                            self.buffer_length += 1;
                            *in_pos += 1;
                        }
                        break;
                    }
                    // Unreachable.
                }

                // Fail or needs more output.

                if self.buffer_length != 0 {
                    // Just consumed the buffered input and produced some
                    // output. Otherwise it would result in "needs more
                    // input". Reset internal buffer.
                    self.buffer_length = 0;
                } else {
                    // Using input stream in last iteration. When decoder
                    // switches to input stream it has less than 8 bits in
                    // accumulator, so it is safe to return unused
                    // accumulator bits there.
                    self.br.unload();
                    *in_pos = self.br.next_in;
                }
                break;
            }
            let inp: &[u8] = if self.buffer_length != 0 { &buffer.0[..] } else { input };
            match self.state {
                RunningState::Uninited => {
                    // Prepare to the first read.
                    if !self.br.warmup(inp) {
                        result = NEEDS_MORE_INPUT;
                        continue;
                    }
                    // Decode window size.
                    result = self.decode_window_bits(); // Reads 1..8 bits.
                    if result != SUCCESS {
                        continue;
                    }
                    if self.large_window != 0 {
                        self.state = RunningState::LargeWindowBits;
                        continue;
                    }
                    self.state = RunningState::Initialize;
                }

                RunningState::LargeWindowBits => {
                    let mut bits: Reg = 0;
                    if !self.br.safe_read_bits(inp, 6, &mut bits) {
                        result = NEEDS_MORE_INPUT;
                        continue;
                    }
                    self.window_bits = (bits & 63) as u32;
                    if self.window_bits < BROTLI_LARGE_MIN_WBITS || self.window_bits > BROTLI_LARGE_MAX_WBITS {
                        result = BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS;
                        continue;
                    }
                    self.state = RunningState::Initialize;
                    // Fall through.
                }

                RunningState::Initialize => {
                    // Maximum distance, see section 9.1. of the spec.
                    self.max_backward_distance = (1i32 << self.window_bits) - BROTLI_WINDOW_GAP as i32;

                    // Allocate memory for both block_type_trees and
                    // block_len_trees.
                    match Buf::try_new(
                        &self.alloc,
                        3 * (BROTLI_HUFFMAN_MAX_SIZE_258 + BROTLI_HUFFMAN_MAX_SIZE_26),
                    ) {
                        Some(b) => self.block_type_trees = b,
                        None => {
                            self.block_type_trees = Buf::empty();
                            result = BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES;
                            continue;
                        }
                    }

                    self.state = RunningState::MetablockBegin;
                    // Fall through.
                }

                RunningState::MetablockBegin => {
                    self.metablock_begin();
                    self.state = RunningState::MetablockHeader;
                    // Fall through.
                }

                RunningState::MetablockHeader => {
                    result = self.decode_meta_block_length(inp); // Reads 2 - 31 bits.
                    if result != SUCCESS {
                        continue;
                    }
                    if (self.is_metadata != 0 || self.is_uncompressed != 0) && !self.br.jump_to_byte_boundary() {
                        result = BROTLI_DECODER_ERROR_FORMAT_PADDING_1;
                        continue;
                    }
                    if self.is_metadata != 0 {
                        self.state = RunningState::Metadata;
                        if let Some(f) = self.metadata_start_func {
                            // SAFETY: client callback, invoked exactly like
                            // in C.
                            unsafe { f(self.metadata_callback_opaque, self.meta_block_remaining_len as usize) };
                        }
                        continue;
                    }
                    if self.meta_block_remaining_len == 0 {
                        self.state = RunningState::MetablockDone;
                        continue;
                    }
                    self.calculate_ring_buffer_size();
                    if self.is_uncompressed != 0 {
                        self.state = RunningState::Uncompressed;
                        continue;
                    }
                    self.state = RunningState::BeforeCompressedMetablockHeader;
                    // Fall through.
                }

                RunningState::BeforeCompressedMetablockHeader => {
                    let h = &mut self.header;
                    self.loop_counter = 0;
                    // Initialize compressed metablock header arena.
                    h.sub_loop_counter = 0;
                    // Make small negative indexes addressable (symbol_lists
                    // base is SYMBOL_LISTS_BASE).
                    h.substate_huffman = HuffmanState::None;
                    h.substate_tree_group = TreeGroupState::None;
                    h.substate_context_map = ContextMapState::None;
                    self.state = RunningState::HuffmanCode0;
                    // Fall through.
                }

                RunningState::HuffmanCode0 => {
                    if self.loop_counter >= 3 {
                        self.state = RunningState::MetablockHeader2;
                        continue;
                    }
                    let lc = self.loop_counter as usize;
                    // Reads 1..11 bits.
                    result = decode_var_len_uint8(
                        &mut self.substate_decode_uint8,
                        &mut self.br,
                        inp,
                        &mut self.num_block_types[lc],
                    );
                    if result != SUCCESS {
                        continue;
                    }
                    self.num_block_types[lc] += 1;
                    if self.num_block_types[lc] < 2 {
                        self.loop_counter += 1;
                        continue;
                    }
                    self.state = RunningState::HuffmanCode1;
                    // Fall through.
                }

                RunningState::HuffmanCode1 => {
                    let lc = self.loop_counter as usize;
                    let alphabet_size = self.num_block_types[lc] + 2;
                    let tree_offset = lc * BROTLI_HUFFMAN_MAX_SIZE_258;
                    result = read_huffman_code(
                        alphabet_size,
                        alphabet_size,
                        &mut self.block_type_trees[tree_offset..],
                        None,
                        &mut self.br,
                        &mut self.header,
                        inp,
                    );
                    if result != SUCCESS {
                        continue;
                    }
                    self.state = RunningState::HuffmanCode2;
                    // Fall through.
                }

                RunningState::HuffmanCode2 => {
                    let lc = self.loop_counter as usize;
                    let alphabet_size = BROTLI_NUM_BLOCK_LEN_SYMBOLS as Reg;
                    let tree_offset = BLOCK_LEN_TREES_OFFSET + lc * BROTLI_HUFFMAN_MAX_SIZE_26;
                    result = read_huffman_code(
                        alphabet_size,
                        alphabet_size,
                        &mut self.block_type_trees[tree_offset..],
                        None,
                        &mut self.br,
                        &mut self.header,
                        inp,
                    );
                    if result != SUCCESS {
                        continue;
                    }
                    self.state = RunningState::HuffmanCode3;
                    // Fall through.
                }

                RunningState::HuffmanCode3 => {
                    let lc = self.loop_counter as usize;
                    let tree_offset = BLOCK_LEN_TREES_OFFSET + lc * BROTLI_HUFFMAN_MAX_SIZE_26;
                    if !safe_read_block_length(
                        &mut self.substate_read_block_length,
                        &mut self.block_length_index,
                        &mut self.block_length[lc],
                        &self.block_type_trees[tree_offset..],
                        &mut self.br,
                        inp,
                    ) {
                        result = NEEDS_MORE_INPUT;
                        continue;
                    }
                    self.loop_counter += 1;
                    self.state = RunningState::HuffmanCode0;
                }

                RunningState::Uncompressed => {
                    result = self.copy_uncompressed_block_to_output(
                        available_out,
                        &mut sink,
                        total_out.as_deref_mut(),
                        inp,
                    );
                    if result != SUCCESS {
                        continue;
                    }
                    self.state = RunningState::MetablockDone;
                }

                RunningState::Metadata => {
                    result = self.skip_metadata_block(inp);
                    if result != SUCCESS {
                        continue;
                    }
                    self.state = RunningState::MetablockDone;
                }

                RunningState::MetablockHeader2 => {
                    let mut bits: Reg = 0;
                    if !self.br.safe_read_bits(inp, 6, &mut bits) {
                        result = NEEDS_MORE_INPUT;
                        continue;
                    }
                    self.distance_postfix_bits = bits & bit_mask(2);
                    bits >>= 2;
                    self.num_direct_distance_codes = bits << self.distance_postfix_bits;
                    match Buf::try_new(&self.alloc, self.num_block_types[0] as usize) {
                        Some(b) => self.context_modes = b,
                        None => {
                            self.context_modes = Buf::empty();
                            result = BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES;
                            continue;
                        }
                    }
                    self.loop_counter = 0;
                    self.state = RunningState::ContextModes;
                    // Fall through.
                }

                RunningState::ContextModes => {
                    result = self.read_context_modes(inp);
                    if result != SUCCESS {
                        continue;
                    }
                    self.state = RunningState::ContextMap1;
                    // Fall through.
                }

                RunningState::ContextMap1 => {
                    result =
                        self.decode_context_map(self.num_block_types[0] << BROTLI_LITERAL_CONTEXT_BITS, false, inp);
                    if result != SUCCESS {
                        continue;
                    }
                    self.detect_trivial_literal_block_types();
                    self.state = RunningState::ContextMap2;
                    // Fall through.
                }

                RunningState::ContextMap2 => {
                    let npostfix = self.distance_postfix_bits;
                    let ndirect = self.num_direct_distance_codes;
                    let mut distance_alphabet_size_max =
                        brotli_distance_alphabet_size(npostfix as u32, ndirect as u32, BROTLI_MAX_DISTANCE_BITS) as Reg;
                    let mut distance_alphabet_size_limit = distance_alphabet_size_max;
                    let mut allocation_success = true;
                    if self.large_window != 0 {
                        let limit = brotli_calculate_distance_code_limit(
                            BROTLI_MAX_ALLOWED_DISTANCE as u32,
                            npostfix as u32,
                            ndirect as u32,
                        );
                        distance_alphabet_size_max =
                            brotli_distance_alphabet_size(npostfix as u32, ndirect as u32, BROTLI_LARGE_MAX_DISTANCE_BITS)
                                as Reg;
                        distance_alphabet_size_limit = limit.max_alphabet_size as Reg;
                    }
                    result = self.decode_context_map(self.num_block_types[2] << BROTLI_DISTANCE_CONTEXT_BITS, true, inp);
                    if result != SUCCESS {
                        continue;
                    }
                    let alloc = self.alloc;
                    allocation_success &= huffman_tree_group_init(
                        &alloc,
                        &mut self.literal_hgroup,
                        BROTLI_NUM_LITERAL_SYMBOLS as Reg,
                        BROTLI_NUM_LITERAL_SYMBOLS as Reg,
                        self.num_literal_htrees,
                    );
                    allocation_success &= huffman_tree_group_init(
                        &alloc,
                        &mut self.insert_copy_hgroup,
                        BROTLI_NUM_COMMAND_SYMBOLS as Reg,
                        BROTLI_NUM_COMMAND_SYMBOLS as Reg,
                        self.num_block_types[1],
                    );
                    allocation_success &= huffman_tree_group_init(
                        &alloc,
                        &mut self.distance_hgroup,
                        distance_alphabet_size_max,
                        distance_alphabet_size_limit,
                        self.num_dist_htrees,
                    );
                    if !allocation_success {
                        // return BROTLI_SAVE_ERROR_CODE(...)
                        result = BROTLI_DECODER_ERROR_ALLOC_TREE_GROUPS;
                        break;
                    }
                    self.loop_counter = 0;
                    self.state = RunningState::TreeGroup;
                    // Fall through.
                }

                RunningState::TreeGroup => {
                    let hgroup = match self.loop_counter {
                        0 => &mut self.literal_hgroup,
                        1 => &mut self.insert_copy_hgroup,
                        2 => &mut self.distance_hgroup,
                        _ => {
                            // return BROTLI_SAVE_ERROR_CODE(...)
                            result = BROTLI_DECODER_ERROR_UNREACHABLE;
                            break;
                        }
                    };
                    result = huffman_tree_group_decode(hgroup, &mut self.br, &mut self.header, inp);
                    if result != SUCCESS {
                        continue;
                    }
                    self.loop_counter += 1;
                    if self.loop_counter < 3 {
                        continue;
                    }
                    self.state = RunningState::BeforeCompressedMetablockBody;
                    // Fall through.
                }

                RunningState::BeforeCompressedMetablockBody => {
                    self.prepare_literal_decoding();
                    self.dist_context_map_slice = 0;
                    self.htree_command = self.insert_copy_hgroup.htrees[0] as usize;
                    if !self.ensure_ring_buffer() {
                        result = BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_2;
                        continue;
                    }
                    self.calculate_distance_lut();
                    self.state = RunningState::CommandBegin;
                    // Fall through.
                }

                RunningState::CommandBegin
                | RunningState::CommandInner
                | RunningState::CommandPostDecodeLiterals
                | RunningState::CommandPostWrapCopy => {
                    result = self.process_commands(inp);
                    if result == NEEDS_MORE_INPUT {
                        result = self.safe_process_commands(inp);
                    }
                }

                RunningState::CommandInnerWrite
                | RunningState::CommandPostWrite1
                | RunningState::CommandPostWrite2 => {
                    result = self.write_ring_buffer(available_out, &mut sink, total_out.as_deref_mut(), false);
                    if result != SUCCESS {
                        continue;
                    }
                    self.wrap_ring_buffer();
                    if self.ringbuffer_size == (1i32 << self.window_bits) {
                        self.max_distance = self.max_backward_distance;
                    }
                    if self.state == RunningState::CommandPostWrite1 {
                        let pending = match &self.compound_dictionary {
                            Some(addon) => addon.br_length != addon.br_copied,
                            None => false,
                        };
                        if pending {
                            self.pos += self.copy_from_compound_dictionary(self.pos);
                            if self.pos >= self.ringbuffer_size {
                                continue;
                            }
                        }
                        if self.meta_block_remaining_len == 0 {
                            // Next metablock, if any.
                            self.state = RunningState::MetablockDone;
                        } else {
                            self.state = RunningState::CommandBegin;
                        }
                    } else if self.state == RunningState::CommandPostWrite2 {
                        self.state = RunningState::CommandPostWrapCopy;
                    } else {
                        // BROTLI_STATE_COMMAND_INNER_WRITE
                        if self.loop_counter == 0 {
                            if self.meta_block_remaining_len == 0 {
                                self.state = RunningState::MetablockDone;
                            } else {
                                self.state = RunningState::CommandPostDecodeLiterals;
                            }
                            continue;
                        }
                        self.state = RunningState::CommandInner;
                    }
                }

                RunningState::MetablockDone => {
                    if self.meta_block_remaining_len < 0 {
                        result = BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_2;
                        continue;
                    }
                    self.cleanup_after_metablock();
                    if self.is_last_metablock == 0 {
                        self.state = RunningState::MetablockBegin;
                        continue;
                    }
                    if !self.br.jump_to_byte_boundary() {
                        result = BROTLI_DECODER_ERROR_FORMAT_PADDING_2;
                        continue;
                    }
                    if self.buffer_length == 0 {
                        self.br.unload();
                        *in_pos = self.br.next_in;
                    }
                    self.state = RunningState::Done;
                    // Fall through.
                }

                RunningState::Done => {
                    if !self.ringbuffer.is_empty() {
                        result = self.write_ring_buffer(available_out, &mut sink, total_out.as_deref_mut(), true);
                        if result != SUCCESS {
                            continue;
                        }
                    }
                    // return BROTLI_SAVE_ERROR_CODE(result)
                    break;
                }
            }
        }
        self.buffer = buffer;
        self.save_error_code(result, consumed!())
    }

    /// `BrotliDecoderDecompressStream` on slices.
    ///
    /// `input[*in_pos..]` is the available input, `output[*out_pos..]` the
    /// available output; both positions are advanced.  `total_out` (if
    /// given) receives the total number of bytes produced so far.
    pub fn decompress_stream(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        total_out: Option<&mut usize>,
    ) -> BrotliDecoderResult {
        let window = &mut output[*out_pos..];
        let mut available_out = window.len();
        let initial = available_out;
        let mut consumed = 0usize;
        let r = self.decompress_stream_raw(&input[*in_pos..], &mut consumed, &mut available_out, Some(window), total_out);
        *in_pos += consumed;
        *out_pos += initial - available_out;
        r
    }

    /// `BrotliDecoderHasMoreOutput`.
    pub fn has_more_output(&self) -> bool {
        // After unrecoverable error remaining output is considered
        // nonsensical.
        if self.error_code < 0 {
            return false;
        }
        !self.ringbuffer.is_empty() && self.unwritten_bytes(false) != 0
    }

    /// `BrotliDecoderTakeOutput`: `*size` is the requested amount (0 means
    /// "as much as possible"); on return it holds the size of the returned
    /// chunk.  `None` corresponds to a NULL result.
    pub fn take_output(&mut self, size: &mut usize) -> Option<&[u8]> {
        let mut available_out = if *size != 0 { *size } else { 1usize << 24 };
        let requested_out = available_out;
        if self.ringbuffer.is_empty() || self.error_code < 0 {
            *size = 0;
            return None;
        }
        self.wrap_ring_buffer();
        let mut sink = OutSink::Take(None);
        let status = self.write_ring_buffer(&mut available_out, &mut sink, None, true);
        // Either WriteRingBuffer returns those "success" codes...
        if status == SUCCESS || status == NEEDS_MORE_OUTPUT {
            *size = requested_out - available_out;
            match sink {
                OutSink::Take(Some(start)) => Some(&self.ringbuffer[start..start + *size]),
                _ => None,
            }
        } else {
            // ... or stream is broken. Normally this should be caught by
            // BrotliDecoderDecompressStream, this is just a safeguard.
            if status < 0 {
                let _ = self.save_error_code(status, 0);
            }
            *size = 0;
            None
        }
    }

    /// `BrotliDecoderIsUsed`.
    pub fn is_used(&self) -> bool {
        self.state != RunningState::Uninited || self.br.get_available_bits() != 0
    }

    /// `BrotliDecoderIsFinished`.
    pub fn is_finished(&self) -> bool {
        self.state == RunningState::Done && !self.has_more_output()
    }

    /// `BrotliDecoderGetErrorCode`.
    pub fn get_error_code(&self) -> BrotliDecoderErrorCode {
        self.error_code
    }
}

/// `BrotliDecoderDecompress` (one-shot).
///
/// `decoded` is `None` if `decoded_buffer` is NULL; `*decoded_size` is the
/// capacity on input and receives the decoded size.
pub fn decompress_raw(encoded: &[u8], decoded_size: &mut usize, decoded: Option<&mut [u8]>) -> BrotliDecoderResult {
    let mut total_out: usize = 0;
    let mut in_pos: usize = 0;
    let mut available_out = *decoded_size;
    let mut s = match DecoderState::new(Allocator::default()) {
        Some(s) => s,
        None => return BrotliDecoderResult::Error,
    };
    let mut result = s.decompress_stream_raw(encoded, &mut in_pos, &mut available_out, decoded, Some(&mut total_out));
    *decoded_size = total_out;
    drop(s); // BrotliDecoderStateCleanup
    if result != BrotliDecoderResult::Success {
        result = BrotliDecoderResult::Error;
    }
    result
}

/// `BrotliDecoderDecompress` on slices: decodes `encoded` into `decoded`.
/// Returns the result and the decoded size.
pub fn decompress(encoded: &[u8], decoded: &mut [u8]) -> (BrotliDecoderResult, usize) {
    let mut size = decoded.len();
    let r = decompress_raw(encoded, &mut size, Some(decoded));
    (r, size)
}

/// `BrotliDecoderEnsureStaticInit` wrapper used by instance creation.
#[inline(always)]
pub(crate) fn ensure_static_init() -> bool {
    brotli_decoder_ensure_static_init()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CalculateDistanceLut` fills complete groups past the alphabet
    /// limit; check that the 544-entry arena always suffices.
    #[test]
    fn distance_lut_fits_arena() {
        for npostfix in 0..=3u32 {
            for k in 0..=15u32 {
                let ndirect = k << npostfix;
                let small = brotli_distance_alphabet_size(npostfix, ndirect, BROTLI_MAX_DISTANCE_BITS);
                let large =
                    brotli_calculate_distance_code_limit(BROTLI_MAX_ALLOWED_DISTANCE as u32, npostfix, ndirect).max_alphabet_size;
                for limit in [small, large] {
                    let mut s = DecoderState::new(Allocator::default()).unwrap();
                    s.distance_postfix_bits = npostfix as Reg;
                    s.num_direct_distance_codes = ndirect as Reg;
                    s.distance_hgroup.alphabet_size_limit = limit as u16;
                    s.calculate_distance_lut();
                }
            }
        }
    }

    #[test]
    fn error_strings() {
        assert_eq!(error_string(BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE), "_ERROR_FORMAT_EXUBERANT_NIBBLE");
        assert_eq!(error_string(BROTLI_DECODER_NO_ERROR), "_NO_ERROR");
        assert_eq!(error_string(-23), "INVALID");
        assert_eq!(error_string(4), "INVALID");
    }
}
