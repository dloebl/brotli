//! Port of `c/enc/encode.c` and `c/enc/state.h`: the streaming encoder.

use super::backward_references::brotli_create_backward_references;
use super::backward_references_hq::{brotli_create_hq_zopfli_backward_references, brotli_create_zopfli_backward_references};
use super::bit_cost::brotli_bits_entropy;
use super::brotli_bit_stream::{
    brotli_store_meta_block, brotli_store_meta_block_fast, brotli_store_meta_block_trivial,
    brotli_store_uncompressed_meta_block,
};
use super::command::Command;
use super::compound_dictionary::{
    create_prepared_dictionary, PreparedDictionary, K_LEAN_PREPARED_DICTIONARY_MAGIC, K_MANAGED_DICTIONARY_MAGIC,
    K_PREPARED_DICTIONARY_MAGIC, K_SHARED_DICTIONARY_MAGIC,
};
use super::compress_fragment::{brotli_compress_fragment_fast, init_command_prefix_codes, BrotliOnePassArena};
use super::compress_fragment_two_pass::{
    brotli_compress_fragment_two_pass, BrotliTwoPassArena, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE,
};
use super::encoder_dict::SharedEncoderDictionary;
use super::fast_log::{fast_log2, log2_floor_non_zero};
use super::hash::{hasher_size, init_or_stitch_to_previous_block, Hasher};
use super::histogram::{HistogramCommand, HistogramDistance, HistogramLiteral};
use super::memory::{Boxed, Buf, MemoryManager};
use super::metablock::{
    brotli_build_meta_block, brotli_build_meta_block_greedy, brotli_init_distance_params, brotli_optimize_histograms,
    MetaBlockSplit, BROTLI_MAX_STATIC_CONTEXTS,
};
use super::params::{
    Base64Region, BrotliDistanceParams, BrotliEncoderParams, BrotliHasherParams, BROTLI_DEFAULT_BASE64_MODE,
    BROTLI_DEFAULT_MAX_BASE64_REGIONS, BROTLI_DEFAULT_MIN_BASE64_REGION_LEN, BROTLI_DEFAULT_SIMD_HASHER,
    BROTLI_MODE_FONT, BROTLI_MODE_GENERIC,
};
use super::quality::*;
use super::ringbuffer::RingBuffer;
use super::utf8_util::{brotli_is_mostly_utf8, K_MIN_UTF8_RATIO};
use super::write_bits::brotli_write_bits;
use crate::common::constants::{
    brotli_distance_alphabet_size, brotli_max_backward_limit, BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
    BROTLI_MAX_DISTANCE, BROTLI_MAX_DISTANCE_BITS, BROTLI_MAX_NDIRECT, BROTLI_MAX_NPOSTFIX, BROTLI_MAX_WINDOW_BITS,
    BROTLI_NUM_DISTANCE_SHORT_CODES, BROTLI_WINDOW_GAP,
};
use crate::common::context::{brotli_context, brotli_context_lut, ContextType};
use crate::common::version::BROTLI_VERSION;

/// `BrotliEncoderOperation`.
pub const BROTLI_OPERATION_PROCESS: u32 = 0;
pub const BROTLI_OPERATION_FLUSH: u32 = 1;
pub const BROTLI_OPERATION_FINISH: u32 = 2;
pub const BROTLI_OPERATION_EMIT_METADATA: u32 = 3;

/// `BrotliEncoderParameter`.
pub const BROTLI_PARAM_MODE: u32 = 0;
pub const BROTLI_PARAM_QUALITY: u32 = 1;
pub const BROTLI_PARAM_LGWIN: u32 = 2;
pub const BROTLI_PARAM_LGBLOCK: u32 = 3;
pub const BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING: u32 = 4;
pub const BROTLI_PARAM_SIZE_HINT: u32 = 5;
pub const BROTLI_PARAM_LARGE_WINDOW: u32 = 6;
pub const BROTLI_PARAM_NPOSTFIX: u32 = 7;
pub const BROTLI_PARAM_NDIRECT: u32 = 8;
pub const BROTLI_PARAM_STREAM_OFFSET: u32 = 9;
pub const BROTLI_PARAM_BASE64_MODE: u32 = 10;
pub const BROTLI_PARAM_MAX_BASE64_REGIONS: u32 = 11;
pub const BROTLI_PARAM_SIMD_HASHER: u32 = 12;
pub const BROTLI_PARAM_HASHER_OPT: u32 = 13;
pub const BROTLI_PARAM_MIN_BASE64_REGION_LEN: u32 = 14;

/// `BrotliEncoderStreamState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamState {
    /// Default state.
    Processing = 0,
    /// Intermediate state; after next block is emitted, byte-padding should
    /// be performed before getting back to default state.
    FlushRequested = 1,
    /// Last metablock was produced; no more input is acceptable.
    Finished = 2,
    /// Flushing compressed block and writing meta-data block header.
    MetadataHead = 3,
    /// Writing metadata block body.
    MetadataBody = 4,
}

/// `BrotliEncoderFlintState`.
pub const BROTLI_FLINT_NEEDS_2_BYTES: i8 = 2;
pub const BROTLI_FLINT_NEEDS_1_BYTE: i8 = 1;
pub const BROTLI_FLINT_WAITING_FOR_PROCESSING: i8 = 0;
pub const BROTLI_FLINT_WAITING_FOR_FLUSHING: i8 = -1;
pub const BROTLI_FLINT_DONE: i8 = -2;

/// Where the pending output (C: `next_out_`) lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NextOut {
    /// C: `NULL`.
    Null,
    /// Offset into `storage_`.
    Storage(usize),
    /// Offset into `tiny_buf_`.
    Tiny(usize),
}

impl NextOut {
    #[inline]
    fn advance(self, n: usize) -> NextOut {
        match self {
            NextOut::Null => NextOut::Null,
            NextOut::Storage(o) => NextOut::Storage(o + n),
            NextOut::Tiny(o) => NextOut::Tiny(o + n),
        }
    }
}

/// Input / output cursor of one `BrotliEncoderCompressStream` call.
/// `available_in == input.len() - in_pos`, `available_out ==
/// output.len() - out_pos`.
pub struct StreamIo<'a, 'b> {
    pub input: &'a [u8],
    pub in_pos: usize,
    pub output: &'b mut [u8],
    pub out_pos: usize,
}

impl StreamIo<'_, '_> {
    #[inline]
    fn available_in(&self) -> usize {
        self.input.len() - self.in_pos
    }
    #[inline]
    fn available_out(&self) -> usize {
        self.output.len() - self.out_pos
    }
}

/// `BrotliEncoderStateStruct`.
pub struct BrotliEncoderState {
    pub params: BrotliEncoderParams,
    pub memory_manager_: MemoryManager,
    pub input_pos_: u64,
    pub ringbuffer_: RingBuffer,
    /// `cmd_alloc_size_` == `commands_.len()`.
    pub commands_: Buf<Command>,
    pub num_commands_: usize,
    pub num_literals_: usize,
    pub last_insert_len_: usize,
    pub last_flush_pos_: u64,
    pub last_processed_pos_: u64,
    pub dist_cache_: [i32; BROTLI_NUM_DISTANCE_SHORT_CODES as usize],
    pub saved_dist_cache_: [i32; 4],
    pub last_bytes_: u16,
    pub last_bytes_bits_: u8,
    /// "Flint" is a tiny uncompressed block emitted before the continuation
    /// block to unwire literal context from previous data. Despite being
    /// i8, field is actually BrotliEncoderFlintState enum.
    pub flint_: i8,
    pub prev_byte_: u8,
    pub prev_byte2_: u8,
    /// `storage_size_` == `storage_.len()`.
    pub storage_: Buf<u8>,
    pub hasher_: Hasher,
    /// Hash table for FAST_ONE_PASS_COMPRESSION_QUALITY mode.
    pub small_table_: [i32; 1 << 10],
    /// Allocated only when needed.
    pub large_table_: Buf<i32>,
    pub large_table_size_: usize,
    pub one_pass_arena_: Option<Boxed<BrotliOnePassArena>>,
    pub two_pass_arena_: Option<Boxed<BrotliTwoPassArena>>,
    /// Command and literal buffers for FAST_TWO_PASS_COMPRESSION_QUALITY.
    pub command_buf_: Buf<u32>,
    pub literal_buf_: Buf<u8>,
    pub total_in_: u64,
    next_out_: NextOut,
    pub available_out_: usize,
    pub total_out_: u64,
    /// Temporary buffer for padding flush bits or metadata block header /
    /// body.
    pub tiny_buf_: [u8; 16],
    pub remaining_metadata_bytes_: u32,
    pub stream_state_: StreamState,
    pub is_last_block_emitted_: bool,
    pub is_initialized_: bool,
}

#[inline]
fn input_block_size(s: &BrotliEncoderState) -> usize {
    1usize << s.params.lgblock
}

#[inline]
fn unprocessed_input_size(s: &BrotliEncoderState) -> u64 {
    s.input_pos_.wrapping_sub(s.last_processed_pos_)
}

#[inline]
fn remaining_input_block_size(s: &BrotliEncoderState) -> usize {
    let delta = unprocessed_input_size(s);
    let block_size = input_block_size(s);
    if delta >= block_size as u64 {
        return 0;
    }
    block_size - delta as usize
}

/// Wraps 64-bit input position to 32-bit ring-buffer position preserving
/// "not-a-first-lap" feature.
#[inline]
fn wrap_position(position: u64) -> u32 {
    let mut result = position as u32;
    let gb = position >> 30;
    if gb > 2 {
        // Wrap every 2GiB; The first 3GB are continuous.
        result = (result & ((1u32 << 30) - 1)) | ((((gb - 1) & 1) as u32 + 1) << 30);
    }
    result
}

/// `GetBrotliStorage`: makes sure `storage_` has at least `size` bytes.
#[inline]
fn get_brotli_storage(s: &mut BrotliEncoderState, size: usize) {
    if s.storage_.len() < size {
        s.storage_ = Buf::empty();
        s.storage_ = Buf::new(&s.memory_manager_, size);
    }
}

fn hash_table_size(max_table_size: usize, input_size: usize) -> usize {
    let mut htsize: usize = 256;
    while htsize < max_table_size && htsize < input_size {
        htsize <<= 1;
    }
    htsize
}

/// `GetHashTable`: selects (and zeroes) the hash table for qualities 0/1;
/// returns its size.  Use [`hash_table`] to access it.
fn get_hash_table(s: &mut BrotliEncoderState, quality: i32, input_size: usize) -> usize {
    // Use smaller hash table when input.size() is smaller, since we fill the
    // table, incurring O(hash table size) overhead for compression, and if
    // the input is short, we won't need that many hash table entries anyway.
    let max_table_size = max_hash_table_size(quality);
    let mut htsize = hash_table_size(max_table_size, input_size);
    debug_assert!(max_table_size >= 256);
    if quality == FAST_ONE_PASS_COMPRESSION_QUALITY {
        // Only odd shifts are supported by fast-one-pass.
        if (htsize & 0xAAAAA) == 0 {
            htsize <<= 1;
        }
    }

    if htsize <= s.small_table_.len() {
        for v in s.small_table_[..htsize].iter_mut() {
            *v = 0;
        }
    } else {
        if htsize > s.large_table_size_ {
            s.large_table_size_ = htsize;
            s.large_table_ = Buf::empty();
            s.large_table_ = Buf::new(&s.memory_manager_, htsize);
        }
        for v in s.large_table_[..htsize].iter_mut() {
            *v = 0;
        }
    }
    htsize
}

/// The table selected by [`get_hash_table`] for `table_size`.
#[inline]
fn hash_table<'a>(small: &'a mut [i32; 1 << 10], large: &'a mut Buf<i32>, table_size: usize) -> &'a mut [i32] {
    if table_size <= small.len() {
        &mut small[..]
    } else {
        &mut large[..]
    }
}

fn encode_window_bits(lgwin: i32, large_window: bool, last_bytes: &mut u16, last_bytes_bits: &mut u8) {
    if large_window {
        *last_bytes = (((lgwin & 0x3F) << 8) | 0x11) as u16;
        *last_bytes_bits = 14;
    } else if lgwin == 16 {
        *last_bytes = 0;
        *last_bytes_bits = 1;
    } else if lgwin == 17 {
        *last_bytes = 1;
        *last_bytes_bits = 7;
    } else if lgwin > 17 {
        *last_bytes = (((lgwin - 17) << 1) | 0x01) as u16;
        *last_bytes_bits = 4;
    } else {
        *last_bytes = (((lgwin - 8) << 4) | 0x01) as u16;
        *last_bytes_bits = 7;
    }
}

// TODO(eustas): avoid FP calculations.
fn estimate_entropy(population: &[u32], size: usize) -> f64 {
    let mut total: usize = 0;
    let mut result: f64 = 0.0;
    for &p in &population[..size] {
        total += p as usize;
        result += (p as f64) * fast_log2(p as usize);
    }
    (total as f64) * fast_log2(total) - result
}

static K_STATIC_CONTEXT_MAP_CONTINUATION: [u32; 64] = [
    1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
static K_STATIC_CONTEXT_MAP_SIMPLE_UTF8: [u32; 64] = [
    0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
static K_STATIC_CONTEXT_MAP_COMPLEX_UTF8: [u32; 64] = [
    11, 11, 12, 12, /* 0 special */
    0, 0, 0, 0, /* 4 lf */
    1, 1, 9, 9, /* 8 space */
    2, 2, 2, 2, /* !, first after space/lf and after something else. */
    1, 1, 1, 1, /* " */
    8, 3, 3, 3, /* % */
    1, 1, 1, 1, /* ({[ */
    2, 2, 2, 2, /* }]) */
    8, 4, 4, 4, /* :; */
    8, 7, 4, 4, /* . */
    8, 0, 0, 0, /* > */
    3, 3, 3, 3, /* [0..9] */
    5, 5, 10, 5, /* [A-Z] */
    5, 5, 10, 5, 6, 6, 6, 6, /* [a-z] */
    6, 6, 6, 6,
];

/// Decide about the context map based on the ability of the prediction
/// ability of the previous byte UTF8-prefix on the next byte. The prediction
/// ability is calculated as Shannon entropy. Here we need Shannon entropy
/// instead of 'BrotliBitsEntropy' since the prefix will be encoded with the
/// remaining 6 bits of the following byte, and BrotliBitsEntropy will assume
/// that symbol to be stored alone using Huffman coding.
fn choose_context_map(
    quality: i32,
    bigram_histo: &[u32],
    num_literal_contexts: &mut usize,
    literal_context_map: &mut Option<&'static [u32]>,
) {
    let mut monogram_histo = [0u32; 3];
    let mut two_prefix_histo = [0u32; 6];
    let mut entropy = [0f64; 4];
    for i in 0..9 {
        monogram_histo[i % 3] += bigram_histo[i];
        two_prefix_histo[i % 6] += bigram_histo[i];
    }
    entropy[1] = estimate_entropy(&monogram_histo, 3);
    entropy[2] = estimate_entropy(&two_prefix_histo, 3) + estimate_entropy(&two_prefix_histo[3..], 3);
    entropy[3] = 0.0;
    for i in 0..3 {
        entropy[3] += estimate_entropy(&bigram_histo[3 * i..], 3);
    }

    let total: usize = monogram_histo[0] as usize + monogram_histo[1] as usize + monogram_histo[2] as usize;
    debug_assert!(total != 0);
    entropy[0] = 1.0 / (total as f64);
    entropy[1] *= entropy[0];
    entropy[2] *= entropy[0];
    entropy[3] *= entropy[0];

    if quality < MIN_QUALITY_FOR_HQ_CONTEXT_MODELING {
        // 3 context models is a bit slower, don't use it at lower qualities.
        entropy[3] = entropy[1] * 10.0;
    }
    // If expected savings by symbol are less than 0.2 bits, skip the context
    // modeling -- in exchange for faster decoding speed.
    if entropy[1] - entropy[2] < 0.2 && entropy[1] - entropy[3] < 0.2 {
        *num_literal_contexts = 1;
    } else if entropy[2] - entropy[3] < 0.02 {
        *num_literal_contexts = 2;
        *literal_context_map = Some(&K_STATIC_CONTEXT_MAP_SIMPLE_UTF8);
    } else {
        *num_literal_contexts = 3;
        *literal_context_map = Some(&K_STATIC_CONTEXT_MAP_CONTINUATION);
    }
}

/// Decide if we want to use a more complex static context map containing 13
/// context values, based on the entropy reduction of histograms over the
/// first 5 bits of literals.
fn should_use_complex_static_context_map(
    input: &[u8],
    mut start_pos: usize,
    length: usize,
    mask: usize,
    _quality: i32,
    size_hint: usize,
    num_literal_contexts: &mut usize,
    literal_context_map: &mut Option<&'static [u32]>,
    arena: &mut [u32],
) -> bool {
    // Try the more complex static context map only for long data.
    if size_hint < (1 << 20) {
        return false;
    }
    let end_pos = start_pos + length;
    // To make entropy calculations faster, we collect histograms over the 5
    // most significant bits of literals. One histogram without context and 13
    // additional histograms for each context value.
    let mut total: u32 = 0;
    let mut entropy = [0f64; 3];
    let utf8_lut = brotli_context_lut(ContextType::Utf8);
    for v in arena[..32 * (BROTLI_MAX_STATIC_CONTEXTS + 1)].iter_mut() {
        *v = 0;
    }
    let (combined_histo, context_histo) = arena.split_at_mut(32);
    while start_pos + 64 <= end_pos {
        let stride_end_pos = start_pos + 64;
        let mut prev2 = input[start_pos & mask];
        let mut prev1 = input[(start_pos + 1) & mask];
        // To make the analysis of the data faster we only examine 64 byte
        // long strides at every 4kB intervals.
        for pos in start_pos + 2..stride_end_pos {
            let literal = input[pos & mask];
            let context = K_STATIC_CONTEXT_MAP_COMPLEX_UTF8[brotli_context(prev1, prev2, utf8_lut) as usize] as u8;
            total += 1;
            combined_histo[(literal >> 3) as usize] += 1;
            context_histo[((context as usize) << 5) + (literal >> 3) as usize] += 1;
            prev2 = prev1;
            prev1 = literal;
        }
        start_pos += 4096;
    }
    entropy[1] = estimate_entropy(combined_histo, 32);
    entropy[2] = 0.0;
    for i in 0..BROTLI_MAX_STATIC_CONTEXTS {
        entropy[2] += estimate_entropy(&context_histo[i << 5..], 32);
    }
    entropy[0] = 1.0 / (total as f64);
    entropy[1] *= entropy[0];
    entropy[2] *= entropy[0];
    // The triggering heuristics below were tuned by compressing the
    // individual files of the silesia corpus. If we skip this kind of context
    // modeling for not very well compressible input (i.e. entropy using
    // context modeling is 60% of maximal entropy) or if expected savings by
    // symbol are less than 0.2 bits, then in every case when it triggers, the
    // final compression ratio is improved. Note however that this heuristics
    // might be too strict for some cases and could be tuned further.
    if entropy[2] > 3.0 || entropy[1] - entropy[2] < 0.2 {
        false
    } else {
        *num_literal_contexts = BROTLI_MAX_STATIC_CONTEXTS;
        *literal_context_map = Some(&K_STATIC_CONTEXT_MAP_COMPLEX_UTF8);
        true
    }
}

fn decide_over_literal_context_modeling(
    input: &[u8],
    mut start_pos: usize,
    length: usize,
    mask: usize,
    quality: i32,
    size_hint: usize,
    num_literal_contexts: &mut usize,
    literal_context_map: &mut Option<&'static [u32]>,
    arena: &mut [u32],
) {
    if quality < MIN_QUALITY_FOR_CONTEXT_MODELING || length < 64 {
        return;
    }
    if should_use_complex_static_context_map(
        input,
        start_pos,
        length,
        mask,
        quality,
        size_hint,
        num_literal_contexts,
        literal_context_map,
        arena,
    ) {
        // Context map was already set, nothing else to do.
        return;
    }
    // Gather bi-gram data of the UTF8 byte prefixes. To make the analysis of
    // UTF8 data faster we only examine 64 byte long strides at every 4kB
    // intervals.
    let end_pos = start_pos + length;
    let bigram_prefix_histo = &mut arena[..9];
    for v in bigram_prefix_histo.iter_mut() {
        *v = 0;
    }
    const LUT: [usize; 4] = [0, 0, 1, 2];
    while start_pos + 64 <= end_pos {
        let stride_end_pos = start_pos + 64;
        let mut prev = LUT[(input[start_pos & mask] >> 6) as usize] * 3;
        for pos in start_pos + 1..stride_end_pos {
            let literal = input[pos & mask];
            bigram_prefix_histo[prev + LUT[(literal >> 6) as usize]] += 1;
            prev = LUT[(literal >> 6) as usize] * 3;
        }
        start_pos += 4096;
    }
    choose_context_map(quality, bigram_prefix_histo, num_literal_contexts, literal_context_map);
}

fn should_compress(
    data: &[u8],
    mask: usize,
    last_flush_pos: u64,
    bytes: usize,
    num_literals: usize,
    num_commands: usize,
) -> bool {
    // TODO(eustas): find more precise minimal block overhead.
    if bytes <= 2 {
        return false;
    }
    if num_commands < (bytes >> 8) + 2 && (num_literals as f64) > 0.99 * (bytes as f64) {
        let mut literal_histo = [0u32; 256];
        const K_SAMPLE_RATE: u32 = 13;
        const K_INV_SAMPLE_RATE: f64 = 1.0 / 13.0;
        const K_MIN_ENTROPY: f64 = 7.92;
        let bit_cost_threshold = (bytes as f64) * K_MIN_ENTROPY * K_INV_SAMPLE_RATE;
        let t = (bytes + K_SAMPLE_RATE as usize - 1) / K_SAMPLE_RATE as usize;
        let mut pos = last_flush_pos as u32;
        for _ in 0..t {
            literal_histo[data[pos as usize & mask] as usize] += 1;
            pos = pos.wrapping_add(K_SAMPLE_RATE);
        }
        if brotli_bits_entropy(&literal_histo, 256) > bit_cost_threshold {
            return false;
        }
    }
    true
}

/// Chooses the literal context mode for a metablock.
fn choose_context_mode(params: &BrotliEncoderParams, data: &[u8], pos: usize, mask: usize, length: usize) -> ContextType {
    // We only do the computation for the option of something else than
    // CONTEXT_UTF8 for the highest qualities
    if params.quality >= MIN_QUALITY_FOR_HQ_BLOCK_SPLITTING && !brotli_is_mostly_utf8(data, pos, mask, length, K_MIN_UTF8_RATIO) {
        return ContextType::Signed;
    }
    ContextType::Utf8
}

fn write_meta_block_internal(
    m: &MemoryManager,
    data: &[u8],
    mask: usize,
    last_flush_pos: u64,
    bytes: usize,
    is_last: bool,
    base64_regions: &[Base64Region],
    literal_context_mode: ContextType,
    params: &BrotliEncoderParams,
    prev_byte: u8,
    prev_byte2: u8,
    num_literals: usize,
    num_commands: usize,
    commands: &mut [Command],
    saved_dist_cache: &[i32; 4],
    dist_cache: &mut [i32],
    storage_ix: &mut usize,
    storage: &mut [u8],
) {
    let wrapped_last_flush_pos = wrap_position(last_flush_pos) as usize;
    let literal_context_lut = brotli_context_lut(literal_context_mode);
    let mut block_params: BrotliEncoderParams = *params;

    if bytes == 0 {
        // Write the ISLAST and ISEMPTY bits.
        brotli_write_bits(2, 3, storage_ix, storage);
        *storage_ix = (*storage_ix + 7) & (!7u32 as usize);
        return;
    }

    if !should_compress(data, mask, last_flush_pos, bytes, num_literals, num_commands) {
        // Restore the distance cache, as its last update by
        // CreateBackwardReferences is now unused.
        dist_cache[..4].copy_from_slice(saved_dist_cache);
        brotli_store_uncompressed_meta_block(is_last, data, wrapped_last_flush_pos, mask, bytes, storage_ix, storage);
        return;
    }

    debug_assert!(*storage_ix <= 14);
    let last_bytes: u16 = ((storage[1] as u16) << 8) | storage[0] as u16;
    let last_bytes_bits: u8 = *storage_ix as u8;
    let commands = &mut commands[..num_commands];
    if params.quality <= MAX_QUALITY_FOR_STATIC_ENTROPY_CODES {
        brotli_store_meta_block_fast(m, data, wrapped_last_flush_pos, bytes, mask, is_last, params, commands, storage_ix, storage);
    } else if params.quality < MIN_QUALITY_FOR_BLOCK_SPLIT {
        brotli_store_meta_block_trivial(m, data, wrapped_last_flush_pos, bytes, mask, is_last, params, commands, storage_ix, storage);
    } else {
        let mut mb = MetaBlockSplit::new();
        if params.quality < MIN_QUALITY_FOR_HQ_BLOCK_SPLITTING {
            let mut num_literal_contexts: usize = 1;
            let mut literal_context_map: Option<&'static [u32]> = None;
            if !params.disable_literal_context_modeling {
                // TODO(eustas): pull to higher level and reuse.
                let mut arena: Buf<u32> = Buf::new(m, 32 * (BROTLI_MAX_STATIC_CONTEXTS + 1));
                decide_over_literal_context_modeling(
                    data,
                    wrapped_last_flush_pos,
                    bytes,
                    mask,
                    params.quality,
                    params.size_hint,
                    &mut num_literal_contexts,
                    &mut literal_context_map,
                    &mut arena,
                );
            }
            brotli_build_meta_block_greedy(
                m,
                data,
                wrapped_last_flush_pos,
                mask,
                base64_regions,
                prev_byte,
                prev_byte2,
                literal_context_lut,
                num_literal_contexts,
                literal_context_map,
                commands,
                &mut mb,
            );
        } else {
            brotli_build_meta_block(
                m,
                data,
                wrapped_last_flush_pos,
                mask,
                base64_regions,
                &mut block_params,
                prev_byte,
                prev_byte2,
                commands,
                literal_context_mode,
                &mut mb,
            );
        }
        if params.quality >= MIN_QUALITY_FOR_OPTIMIZE_HISTOGRAMS {
            // The number of distance symbols effectively used for distance
            // histograms. It might be less than distance alphabet size for
            // "Large Window Brotli" (32-bit).
            brotli_optimize_histograms(block_params.dist.alphabet_size_limit, &mut mb);
        }
        brotli_store_meta_block(
            m,
            data,
            wrapped_last_flush_pos,
            bytes,
            mask,
            prev_byte,
            prev_byte2,
            is_last,
            &block_params,
            literal_context_mode,
            commands,
            &mb,
            storage_ix,
            storage,
        );
    }
    if bytes + 4 < (*storage_ix >> 3) {
        // Restore the distance cache and last byte.
        dist_cache[..4].copy_from_slice(saved_dist_cache);
        storage[0] = last_bytes as u8;
        storage[1] = (last_bytes >> 8) as u8;
        *storage_ix = last_bytes_bits as usize;
        brotli_store_uncompressed_meta_block(is_last, data, wrapped_last_flush_pos, mask, bytes, storage_ix, storage);
    }
}

fn choose_distance_params(params: &mut BrotliEncoderParams) {
    let mut distance_postfix_bits: u32 = 0;
    let mut num_direct_distance_codes: u32 = 0;

    if params.quality >= MIN_QUALITY_FOR_NONZERO_DISTANCE_PARAMS {
        if params.mode == BROTLI_MODE_FONT {
            distance_postfix_bits = 1;
            num_direct_distance_codes = 12;
        } else {
            distance_postfix_bits = params.dist.distance_postfix_bits;
            num_direct_distance_codes = params.dist.num_direct_distance_codes;
        }
        // NB: in C an oversized shift is UB, but the result is irrelevant
        // then (the first condition below holds).
        let ndirect_msb = num_direct_distance_codes.wrapping_shr(distance_postfix_bits) & 0x0F;
        if distance_postfix_bits > BROTLI_MAX_NPOSTFIX
            || num_direct_distance_codes > BROTLI_MAX_NDIRECT
            || ndirect_msb.wrapping_shl(distance_postfix_bits) != num_direct_distance_codes
        {
            distance_postfix_bits = 0;
            num_direct_distance_codes = 0;
        }
    }

    brotli_init_distance_params(&mut params.dist, distance_postfix_bits, num_direct_distance_codes, params.large_window);
}

/// `BrotliEncoderInitParams`.
fn brotli_encoder_init_params() -> BrotliEncoderParams {
    let alphabet = brotli_distance_alphabet_size(0, 0, BROTLI_MAX_DISTANCE_BITS);
    BrotliEncoderParams {
        mode: BROTLI_MODE_GENERIC,
        large_window: false,
        quality: BROTLI_DEFAULT_QUALITY,
        lgwin: BROTLI_DEFAULT_WINDOW,
        lgblock: 0,
        stream_offset: 0,
        size_hint: 0,
        disable_literal_context_modeling: false,
        hasher: BrotliHasherParams::default(),
        dist: BrotliDistanceParams {
            distance_postfix_bits: 0,
            num_direct_distance_codes: 0,
            alphabet_size_max: alphabet,
            alphabet_size_limit: alphabet,
            max_distance: BROTLI_MAX_DISTANCE,
        },
        dictionary: SharedEncoderDictionary::new(),
        base64_mode: BROTLI_DEFAULT_BASE64_MODE,
        max_base64_regions: BROTLI_DEFAULT_MAX_BASE64_REGIONS,
        min_base64_region_len: BROTLI_DEFAULT_MIN_BASE64_REGION_LEN,
        simd_hasher: BROTLI_DEFAULT_SIMD_HASHER,
        hasher_opt: false,
    }
}

/// Marks all input as processed.  Returns true if position wrapping occurs.
fn update_last_processed_pos(s: &mut BrotliEncoderState) -> bool {
    let wrapped_last_processed_pos = wrap_position(s.last_processed_pos_);
    let wrapped_input_pos = wrap_position(s.input_pos_);
    s.last_processed_pos_ = s.input_pos_;
    wrapped_input_pos < wrapped_last_processed_pos
}

/// `ExtendLastCommand`.
fn extend_last_command(s: &mut BrotliEncoderState, bytes: &mut u32, wrapped_last_processed_pos: &mut u32) {
    let last_command = &mut s.commands_[s.num_commands_ - 1];
    let data = s.ringbuffer_.buffer();
    let mask = s.ringbuffer_.mask_;
    let max_backward_distance: u64 = (1u64 << s.params.lgwin) - BROTLI_WINDOW_GAP as u64;
    let last_copy_len: u64 = (last_command.copy_len_ & 0x1FFFFFF) as u64;
    let last_processed_pos: u64 = s.last_processed_pos_.wrapping_sub(last_copy_len);
    let max_distance: u64 = if last_processed_pos < max_backward_distance { last_processed_pos } else { max_backward_distance };
    let cmd_dist: u64 = s.dist_cache_[0] as i64 as u64;
    let distance_code: u32 = last_command.restore_distance_code(&s.params.dist);
    let dict = &s.params.dictionary.compound;
    let compound_dictionary_size: usize = dict.total_size;
    if distance_code < BROTLI_NUM_DISTANCE_SHORT_CODES
        || (distance_code - (BROTLI_NUM_DISTANCE_SHORT_CODES - 1)) as u64 == cmd_dist
    {
        if cmd_dist <= max_distance {
            while *bytes != 0
                && data[(*wrapped_last_processed_pos & mask) as usize]
                    == data[((*wrapped_last_processed_pos as u64).wrapping_sub(cmd_dist) & mask as u64) as usize]
            {
                last_command.copy_len_ = last_command.copy_len_.wrapping_add(1);
                *bytes -= 1;
                *wrapped_last_processed_pos = wrapped_last_processed_pos.wrapping_add(1);
            }
        } else if (cmd_dist - max_distance - 1) < compound_dictionary_size as u64 && last_copy_len < cmd_dist - max_distance {
            let address: usize = compound_dictionary_size - (cmd_dist - max_distance) as usize + last_copy_len as usize;
            let mut br_index: usize = 0;
            while address >= dict.chunk_offsets[br_index + 1] {
                br_index += 1;
            }
            let mut br_offset = address - dict.chunk_offsets[br_index];
            let mut chunk = dict.chunk_source(br_index);
            let mut chunk_length = dict.chunk_offsets[br_index + 1] - dict.chunk_offsets[br_index];
            while *bytes != 0 && data[(*wrapped_last_processed_pos & mask) as usize] == chunk[br_offset] {
                last_command.copy_len_ = last_command.copy_len_.wrapping_add(1);
                *bytes -= 1;
                *wrapped_last_processed_pos = wrapped_last_processed_pos.wrapping_add(1);
                br_offset += 1;
                if br_offset == chunk_length {
                    br_index += 1;
                    br_offset = 0;
                    if br_index != dict.num_chunks {
                        chunk = dict.chunk_source(br_index);
                        chunk_length = dict.chunk_offsets[br_index + 1] - dict.chunk_offsets[br_index];
                    } else {
                        break;
                    }
                }
            }
        }
        // The copy length is at most the metablock size, and thus
        // expressible.
        last_command.cmd_prefix_ = super::command::get_length_code(
            last_command.insert_len_ as usize,
            ((last_command.copy_len_ & 0x1FFFFFF) as i32 + (last_command.copy_len_ >> 25) as i32) as isize as usize,
            (last_command.dist_prefix_ & 0x3FF) == 0,
        );
    }
}

impl BrotliEncoderState {
    /// `BrotliEncoderInitState`.
    pub fn new(m: MemoryManager) -> Self {
        let mut s = BrotliEncoderState {
            params: brotli_encoder_init_params(),
            memory_manager_: m,
            input_pos_: 0,
            ringbuffer_: RingBuffer::new(),
            commands_: Buf::empty(),
            num_commands_: 0,
            num_literals_: 0,
            last_insert_len_: 0,
            last_flush_pos_: 0,
            last_processed_pos_: 0,
            dist_cache_: [0; BROTLI_NUM_DISTANCE_SHORT_CODES as usize],
            saved_dist_cache_: [0; 4],
            last_bytes_: 0,
            last_bytes_bits_: 0,
            flint_: 0,
            prev_byte_: 0,
            prev_byte2_: 0,
            storage_: Buf::empty(),
            hasher_: Hasher::new(),
            small_table_: [0; 1 << 10],
            large_table_: Buf::empty(),
            large_table_size_: 0,
            one_pass_arena_: None,
            two_pass_arena_: None,
            command_buf_: Buf::empty(),
            literal_buf_: Buf::empty(),
            total_in_: 0,
            next_out_: NextOut::Null,
            available_out_: 0,
            total_out_: 0,
            tiny_buf_: [0; 16],
            remaining_metadata_bytes_: 0,
            stream_state_: StreamState::Processing,
            is_last_block_emitted_: false,
            is_initialized_: false,
        };
        // Initialize distance cache.
        s.dist_cache_[0] = 4;
        s.dist_cache_[1] = 11;
        s.dist_cache_[2] = 15;
        s.dist_cache_[3] = 16;
        // Save the state of the distance cache in case we need to restore it
        // for emitting an uncompressed block.
        s.saved_dist_cache_.copy_from_slice(&s.dist_cache_[..4]);
        s.hasher_.common.num_base64_regions = 0;
        s
    }

    /// `BrotliEncoderSetParameter`.
    pub fn set_parameter(&mut self, p: u32, value: u32) -> bool {
        // Changing parameters on the fly is not implemented yet.
        if self.is_initialized_ {
            return false;
        }
        // TODO(eustas): Validate/clamp parameters here.
        match p {
            BROTLI_PARAM_MODE => {
                self.params.mode = value;
                true
            }
            BROTLI_PARAM_QUALITY => {
                self.params.quality = value as i32;
                true
            }
            BROTLI_PARAM_LGWIN => {
                self.params.lgwin = value as i32;
                true
            }
            BROTLI_PARAM_LGBLOCK => {
                self.params.lgblock = value as i32;
                true
            }
            BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING => {
                if value != 0 && value != 1 {
                    return false;
                }
                self.params.disable_literal_context_modeling = value != 0;
                true
            }
            BROTLI_PARAM_SIZE_HINT => {
                self.params.size_hint = value as usize;
                true
            }
            BROTLI_PARAM_LARGE_WINDOW => {
                self.params.large_window = value != 0;
                true
            }
            BROTLI_PARAM_NPOSTFIX => {
                self.params.dist.distance_postfix_bits = value;
                true
            }
            BROTLI_PARAM_NDIRECT => {
                self.params.dist.num_direct_distance_codes = value;
                true
            }
            BROTLI_PARAM_STREAM_OFFSET => {
                if value > (1u32 << 30) {
                    return false;
                }
                self.params.stream_offset = value as usize;
                true
            }
            BROTLI_PARAM_BASE64_MODE => {
                self.params.base64_mode = (value & 1) as i32;
                true
            }
            BROTLI_PARAM_MAX_BASE64_REGIONS => {
                self.params.max_base64_regions = value as usize;
                true
            }
            BROTLI_PARAM_MIN_BASE64_REGION_LEN => {
                self.params.min_base64_region_len = value as usize;
                true
            }
            BROTLI_PARAM_SIMD_HASHER => {
                if value > 2 {
                    return false;
                }
                self.params.simd_hasher = value;
                true
            }
            BROTLI_PARAM_HASHER_OPT => {
                if value != 0 && value != 1 {
                    return false;
                }
                self.params.hasher_opt = value != 0;
                true
            }
            _ => false,
        }
    }

    /// `EnsureInitialized`.
    fn ensure_initialized(&mut self) -> bool {
        if self.is_initialized_ {
            return true;
        }

        self.last_bytes_bits_ = 0;
        self.last_bytes_ = 0;
        self.flint_ = BROTLI_FLINT_DONE;
        self.remaining_metadata_bytes_ = u32::MAX;

        sanitize_params(&mut self.params);
        self.params.lgblock = compute_lg_block(&self.params);
        choose_distance_params(&mut self.params);

        if self.params.stream_offset != 0 {
            self.flint_ = BROTLI_FLINT_NEEDS_2_BYTES;
            // Poison the distance cache. -16 +- 3 is still less than zero
            // (invalid).
            self.dist_cache_[0] = -16;
            self.dist_cache_[1] = -16;
            self.dist_cache_[2] = -16;
            self.dist_cache_[3] = -16;
            self.saved_dist_cache_.copy_from_slice(&self.dist_cache_[..4]);
        }

        self.ringbuffer_.setup(&self.params);

        // Initialize last byte with stream header.
        {
            let mut lgwin = self.params.lgwin;
            if self.params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY
                || self.params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY
            {
                lgwin = lgwin.max(18);
            }
            if self.params.stream_offset == 0 {
                encode_window_bits(lgwin, self.params.large_window, &mut self.last_bytes_, &mut self.last_bytes_bits_);
            } else {
                // Bigger values have the same effect, but could cause
                // overflows.
                self.params.stream_offset = self.params.stream_offset.min(brotli_max_backward_limit(lgwin as u32));
            }
        }

        let m = self.memory_manager_;
        if self.params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY {
            let mut arena = Boxed::new(&m, BrotliOnePassArena::default());
            init_command_prefix_codes(&mut arena);
            self.one_pass_arena_ = Some(arena);
        } else if self.params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY {
            self.two_pass_arena_ = Some(Boxed::new(&m, BrotliTwoPassArena::default()));
        }

        self.is_initialized_ = true;
        true
    }

    /// Copies the given input data to the internal ring buffer of the
    /// compressor. No processing of the data occurs at this time and this
    /// function can be called multiple times before calling
    /// WriteBrotliData() to process the accumulated input. At most
    /// input_block_size() bytes of input data can be copied to the ring
    /// buffer, otherwise the next WriteBrotliData() will fail.
    fn copy_input_to_ring_buffer(&mut self, input: &[u8]) {
        let m = self.memory_manager_;
        self.ringbuffer_.write(&m, input);
        self.input_pos_ += input.len() as u64;

        // TL;DR: If needed, initialize 7 more bytes in the ring buffer to
        // make the hashing not depend on uninitialized data. This makes
        // compression deterministic and it prevents uninitialized memory
        // warnings in Valgrind.  (See encode.c for the full story.)
        //
        // Only clear during the first round of ring-buffer writes. On
        // subsequent rounds data in the ring-buffer would be affected.
        if self.ringbuffer_.pos_ <= self.ringbuffer_.mask_ {
            // This is the first time when the ring buffer is being written.
            // We clear 7 bytes just after the bytes that have been copied
            // from the input buffer.
            let pos = self.ringbuffer_.pos_ as usize;
            for b in self.ringbuffer_.buffer_mut()[pos..pos + 7].iter_mut() {
                *b = 0;
            }
        }
    }

    /// Processes the accumulated input data and sets `available_out_` to the
    /// length of the new output meta-block (and `next_out_` to its start),
    /// or to zero if no new output meta-block has been created (in this case
    /// the processed input data is buffered internally).  If `is_last` or
    /// `force_flush` is true, an output meta-block is always created.
    /// However, until `is_last` is true encoder may retain up to 7 bits of
    /// the last byte of output. Byte-alignment could be enforced by emitting
    /// an empty meta-data block.  Returns false if the size of the input data
    /// is larger than input_block_size().
    ///
    /// (C `EncodeData(s, is_last, force_flush, &s->available_out_,
    /// &s->next_out_)`.)
    fn encode_data(&mut self, is_last: bool, force_flush: bool) -> bool {
        let delta = unprocessed_input_size(self);
        let mut bytes: u32 = delta as u32;
        let mut wrapped_last_processed_pos = wrap_position(self.last_processed_pos_);
        let m = self.memory_manager_;
        let fast_compress = self.params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY
            || self.params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY;
        let mask = self.ringbuffer_.mask_;

        if delta == 0 {
            // No new input; still might want to flush or finish.
            if !self.ringbuffer_.is_allocated() {
                // No input has been processed so far.
                if is_last {
                    // Emit complete finalized stream.
                    debug_assert!(self.last_bytes_bits_ <= 14);
                    self.last_bytes_ |= (3u32 << self.last_bytes_bits_) as u16;
                    self.last_bytes_bits_ += 2;
                    self.tiny_buf_[0] = self.last_bytes_ as u8;
                    self.tiny_buf_[1] = (self.last_bytes_ >> 8) as u8;
                    self.next_out_ = NextOut::Tiny(0);
                    self.available_out_ = (self.last_bytes_bits_ as usize + 7) >> 3;
                    return true;
                } else {
                    // No data, not last -> no-op.
                    self.available_out_ = 0;
                    return true;
                }
            } else {
                // Fast compress performs flush every block -> flush is no-op.
                if !is_last && (!force_flush || fast_compress) {
                    // Another no-op.
                    self.available_out_ = 0;
                    return true;
                }
            }
        }

        if self.params.quality > self.params.dictionary.max_quality {
            return false;
        }
        // Adding more blocks after "last" block is forbidden.
        if self.is_last_block_emitted_ {
            return false;
        }
        if is_last {
            self.is_last_block_emitted_ = true;
        }

        if delta > input_block_size(self) as u64 {
            return false;
        }
        if self.params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY && self.command_buf_.is_empty() {
            self.command_buf_ = Buf::new(&m, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE);
            self.literal_buf_ = Buf::new(&m, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE);
        }

        if fast_compress {
            let mut storage_ix: usize = self.last_bytes_bits_ as usize;
            get_brotli_storage(self, 2u32.wrapping_mul(bytes).wrapping_add(503) as usize);
            self.storage_[0] = self.last_bytes_ as u8;
            self.storage_[1] = (self.last_bytes_ >> 8) as u8;
            let table_size = get_hash_table(self, self.params.quality, bytes as usize);
            {
                let s = &mut *self;
                let data = s.ringbuffer_.buffer();
                let input = &data[(wrapped_last_processed_pos & mask) as usize..];
                let table = hash_table(&mut s.small_table_, &mut s.large_table_, table_size);
                if s.params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY {
                    brotli_compress_fragment_fast(
                        s.one_pass_arena_.as_mut().expect("one pass arena"),
                        input,
                        bytes as usize,
                        is_last,
                        table,
                        table_size,
                        &mut storage_ix,
                        &mut s.storage_,
                    );
                } else {
                    brotli_compress_fragment_two_pass(
                        s.two_pass_arena_.as_mut().expect("two pass arena"),
                        input,
                        bytes as usize,
                        is_last,
                        &mut s.command_buf_,
                        &mut s.literal_buf_,
                        table,
                        table_size,
                        &mut storage_ix,
                        &mut s.storage_,
                    );
                }
            }
            self.last_bytes_ = self.storage_[storage_ix >> 3] as u16;
            self.last_bytes_bits_ = (storage_ix & 7) as u8;
            update_last_processed_pos(self);
            self.next_out_ = NextOut::Storage(0);
            self.available_out_ = storage_ix >> 3;
            return true;
        }

        {
            // Theoretical max number of commands is 1 per 2 bytes.
            let mut newsize = self.num_commands_ + bytes as usize / 2 + 1;
            if newsize > self.commands_.len() {
                // Reserve a bit more memory to allow merging with a next
                // block without reallocation: that would impact speed.
                newsize += (bytes as usize / 4) + 16;
                let mut new_commands: Buf<Command> = Buf::new(&m, newsize);
                if !self.commands_.is_empty() {
                    new_commands[..self.num_commands_].copy_from_slice(&self.commands_[..self.num_commands_]);
                }
                self.commands_ = new_commands;
            }
        }

        let literal_context_mode;
        {
            let s = &mut *self;
            let data = s.ringbuffer_.buffer();
            init_or_stitch_to_previous_block(
                &m,
                &mut s.hasher_,
                data,
                mask as usize,
                &mut s.params,
                wrapped_last_processed_pos as usize,
                bytes as usize,
                is_last,
            );
            literal_context_mode = choose_context_mode(
                &s.params,
                data,
                wrap_position(s.last_flush_pos_) as usize,
                mask as usize,
                (s.input_pos_ - s.last_flush_pos_) as usize,
            );
        }
        let literal_context_lut = brotli_context_lut(literal_context_mode);

        if self.num_commands_ != 0 && self.last_insert_len_ == 0 {
            extend_last_command(self, &mut bytes, &mut wrapped_last_processed_pos);
        }

        {
            let s = &mut *self;
            let data = s.ringbuffer_.buffer();
            let commands = &mut s.commands_[s.num_commands_..];
            if s.params.quality == ZOPFLIFICATION_QUALITY {
                debug_assert!(s.params.hasher.type_ == 10);
                brotli_create_zopfli_backward_references(
                    &m,
                    bytes as usize,
                    wrapped_last_processed_pos as usize,
                    data,
                    mask as usize,
                    literal_context_lut,
                    &s.params,
                    &mut s.hasher_,
                    &mut s.dist_cache_,
                    &mut s.last_insert_len_,
                    commands,
                    &mut s.num_commands_,
                    &mut s.num_literals_,
                );
            } else if s.params.quality == HQ_ZOPFLIFICATION_QUALITY {
                debug_assert!(s.params.hasher.type_ == 10);
                brotli_create_hq_zopfli_backward_references(
                    &m,
                    bytes as usize,
                    wrapped_last_processed_pos as usize,
                    data,
                    mask as usize,
                    literal_context_lut,
                    &s.params,
                    &mut s.hasher_,
                    &mut s.dist_cache_,
                    &mut s.last_insert_len_,
                    commands,
                    &mut s.num_commands_,
                    &mut s.num_literals_,
                );
            } else {
                brotli_create_backward_references(
                    bytes as usize,
                    wrapped_last_processed_pos as usize,
                    data,
                    mask as usize,
                    literal_context_lut,
                    &s.params,
                    &mut s.hasher_,
                    &mut s.dist_cache_,
                    &mut s.last_insert_len_,
                    commands,
                    &mut s.num_commands_,
                    &mut s.num_literals_,
                );
            }
        }

        {
            let max_length = max_metablock_size(&self.params);
            let max_literals = max_length / 8;
            let max_commands = max_length / 8;
            let processed_bytes = (self.input_pos_ - self.last_flush_pos_) as usize;
            // If maximal possible additional block doesn't fit metablock,
            // flush now.
            // TODO(eustas): Postpone decision until next block arrives?
            let next_input_fits_metablock = processed_bytes + input_block_size(self) <= max_length;
            // If block splitting is not used, then flush as soon as there is
            // some amount of commands / literals produced.
            let should_flush = self.params.quality < MIN_QUALITY_FOR_BLOCK_SPLIT
                && self.num_literals_ + self.num_commands_ >= MAX_NUM_DELAYED_SYMBOLS;
            if !is_last
                && !force_flush
                && !should_flush
                && next_input_fits_metablock
                && self.num_literals_ < max_literals
                && self.num_commands_ < max_commands
            {
                // Merge with next input block. Everything will happen later.
                if update_last_processed_pos(self) {
                    self.hasher_.reset();
                }
                self.available_out_ = 0;
                return true;
            }
        }

        // Create the last insert-only command.
        if self.last_insert_len_ > 0 {
            self.commands_[self.num_commands_] = Command::new_insert(self.last_insert_len_);
            self.num_commands_ += 1;
            self.num_literals_ += self.last_insert_len_;
            self.last_insert_len_ = 0;
        }

        if !is_last && self.input_pos_ == self.last_flush_pos_ {
            // We have no new input data and we don't have to finish the
            // stream, so nothing to do.
            self.available_out_ = 0;
            return true;
        }
        debug_assert!(self.input_pos_ >= self.last_flush_pos_);
        debug_assert!(self.input_pos_ > self.last_flush_pos_ || is_last);
        debug_assert!(self.input_pos_ - self.last_flush_pos_ <= 1u64 << 24);
        {
            let metablock_size: u32 = (self.input_pos_ - self.last_flush_pos_) as u32;
            get_brotli_storage(self, 2u32.wrapping_mul(metablock_size).wrapping_add(503) as usize);
            let mut storage_ix: usize = self.last_bytes_bits_ as usize;
            self.storage_[0] = self.last_bytes_ as u8;
            self.storage_[1] = (self.last_bytes_ >> 8) as u8;
            {
                let s = &mut *self;
                let data = s.ringbuffer_.buffer();
                let n_b64 = s.hasher_.common.num_base64_regions.min(s.hasher_.common.base64_regions.len());
                write_meta_block_internal(
                    &m,
                    data,
                    mask as usize,
                    s.last_flush_pos_,
                    metablock_size as usize,
                    is_last,
                    &s.hasher_.common.base64_regions[..n_b64],
                    literal_context_mode,
                    &s.params,
                    s.prev_byte_,
                    s.prev_byte2_,
                    s.num_literals_,
                    s.num_commands_,
                    &mut s.commands_,
                    &s.saved_dist_cache_,
                    &mut s.dist_cache_,
                    &mut storage_ix,
                    &mut s.storage_,
                );
            }
            self.hasher_.common.num_base64_regions = 0;
            self.last_bytes_ = self.storage_[storage_ix >> 3] as u16;
            self.last_bytes_bits_ = (storage_ix & 7) as u8;
            self.last_flush_pos_ = self.input_pos_;
            if update_last_processed_pos(self) {
                self.hasher_.reset();
            }
            {
                let data = self.ringbuffer_.buffer();
                if self.last_flush_pos_ > 0 {
                    self.prev_byte_ = data[((self.last_flush_pos_ as u32).wrapping_sub(1) & mask) as usize];
                }
                if self.last_flush_pos_ > 1 {
                    self.prev_byte2_ = data[((self.last_flush_pos_ - 2) as u32 & mask) as usize];
                }
            }
            self.num_commands_ = 0;
            self.num_literals_ = 0;
            // Save the state of the distance cache in case we need to restore
            // it for emitting an uncompressed block.
            self.saved_dist_cache_.copy_from_slice(&self.dist_cache_[..4]);
            self.next_out_ = NextOut::Storage(0);
            self.available_out_ = storage_ix >> 3;
            true
        }
    }

    /// Dumps remaining output bits and metadata header to `tiny_buf_`.
    /// Returns number of produced bytes.
    /// REQUIRED: `block_size` <= (1 << 24).
    fn write_metadata_header(&mut self, block_size: usize) -> usize {
        let header = &mut self.tiny_buf_;
        let mut storage_ix: usize = self.last_bytes_bits_ as usize;
        header[0] = self.last_bytes_ as u8;
        header[1] = (self.last_bytes_ >> 8) as u8;
        self.last_bytes_ = 0;
        self.last_bytes_bits_ = 0;

        brotli_write_bits(1, 0, &mut storage_ix, header);
        brotli_write_bits(2, 3, &mut storage_ix, header);
        brotli_write_bits(1, 0, &mut storage_ix, header);
        if block_size == 0 {
            brotli_write_bits(2, 0, &mut storage_ix, header);
        } else {
            let nbits: u32 =
                if block_size == 1 { 1 } else { log2_floor_non_zero((block_size as u32 - 1) as usize) + 1 };
            let nbytes: u32 = (nbits + 7) / 8;
            brotli_write_bits(2, nbytes as u64, &mut storage_ix, header);
            brotli_write_bits(8 * nbytes as usize, (block_size - 1) as u64, &mut storage_ix, header);
        }
        (storage_ix + 7) >> 3
    }

    /// The bytes of the pending output (`next_out_`, `available_out_`).
    fn pending_output(&self) -> &[u8] {
        match self.next_out_ {
            NextOut::Null => &[],
            NextOut::Storage(o) => &self.storage_[o..o + self.available_out_],
            NextOut::Tiny(o) => &self.tiny_buf_[o..o + self.available_out_],
        }
    }

    fn inject_byte_padding_block(&mut self) {
        let mut seal: u32 = self.last_bytes_ as u32;
        let mut seal_bits: usize = self.last_bytes_bits_ as usize;
        self.last_bytes_ = 0;
        self.last_bytes_bits_ = 0;
        // is_last = 0, data_nibbles = 11, reserved = 0, meta_nibbles = 00
        seal |= 0x6u32 << seal_bits;
        seal_bits += 6;
        // If we have already created storage, then append to it.  Storage is
        // valid until next block is being compressed.
        let destination = if self.next_out_ != NextOut::Null {
            self.next_out_.advance(self.available_out_)
        } else {
            self.next_out_ = NextOut::Tiny(0);
            NextOut::Tiny(0)
        };
        let dst: &mut [u8] = match destination {
            NextOut::Storage(o) => &mut self.storage_[o..],
            NextOut::Tiny(o) => &mut self.tiny_buf_[o..],
            NextOut::Null => unreachable!(),
        };
        dst[0] = seal as u8;
        if seal_bits > 8 {
            dst[1] = (seal >> 8) as u8;
        }
        if seal_bits > 16 {
            dst[2] = (seal >> 16) as u8;
        }
        self.available_out_ += (seal_bits + 7) >> 3;
    }

    /// Fills the `total_out`, if it is not None.
    fn set_total_out(&self, total_out: &mut Option<&mut usize>) {
        if let Some(t) = total_out {
            // Saturating conversion uint64_t -> size_t
            let mut result = usize::MAX;
            if self.total_out_ < result as u64 {
                result = self.total_out_ as usize;
            }
            **t = result;
        }
    }

    /// Injects padding bits or pushes compressed data to output.  Returns
    /// false if nothing is done.
    fn inject_flush_or_push_output(&mut self, io: &mut StreamIo, total_out: &mut Option<&mut usize>) -> bool {
        if self.stream_state_ == StreamState::FlushRequested && self.last_bytes_bits_ != 0 {
            self.inject_byte_padding_block();
            return true;
        }

        if self.available_out_ != 0 && io.available_out() != 0 {
            let copy_output_size = self.available_out_.min(io.available_out());
            io.output[io.out_pos..io.out_pos + copy_output_size].copy_from_slice(&self.pending_output()[..copy_output_size]);
            io.out_pos += copy_output_size;
            self.next_out_ = self.next_out_.advance(copy_output_size);
            self.available_out_ -= copy_output_size;
            self.total_out_ += copy_output_size as u64;
            self.set_total_out(total_out);
            return true;
        }

        false
    }

    fn check_flush_complete(&mut self) {
        if self.stream_state_ == StreamState::FlushRequested && self.available_out_ == 0 {
            self.stream_state_ = StreamState::Processing;
            self.next_out_ = NextOut::Null;
        }
    }

    fn compress_stream_fast(&mut self, op: u32, io: &mut StreamIo, total_out: &mut Option<&mut usize>) -> bool {
        let block_size_limit: usize = 1usize << self.params.lgwin;
        let buf_size: usize = K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE.min(io.available_in().min(block_size_limit));
        let m = self.memory_manager_;
        let mut tmp_command_buf: Buf<u32> = Buf::empty();
        let mut tmp_literal_buf: Buf<u8> = Buf::empty();
        let mut use_tmp = false;
        if self.params.quality != FAST_ONE_PASS_COMPRESSION_QUALITY
            && self.params.quality != FAST_TWO_PASS_COMPRESSION_QUALITY
        {
            return false;
        }
        if self.params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY {
            if self.command_buf_.is_empty() && buf_size == K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE {
                self.command_buf_ = Buf::new(&m, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE);
                self.literal_buf_ = Buf::new(&m, K_COMPRESS_FRAGMENT_TWO_PASS_BLOCK_SIZE);
            }
            if self.command_buf_.is_empty() {
                tmp_command_buf = Buf::new(&m, buf_size);
                tmp_literal_buf = Buf::new(&m, buf_size);
                use_tmp = true;
            }
        }

        loop {
            if self.inject_flush_or_push_output(io, total_out) {
                continue;
            }

            // Compress block only when internal output buffer is empty,
            // stream is not finished, there is no pending flush request, and
            // there is either additional input or pending operation.
            if self.available_out_ == 0
                && self.stream_state_ == StreamState::Processing
                && (io.available_in() != 0 || op != BROTLI_OPERATION_PROCESS)
            {
                let block_size = block_size_limit.min(io.available_in());
                let is_last = io.available_in() == block_size && op == BROTLI_OPERATION_FINISH;
                let force_flush = io.available_in() == block_size && op == BROTLI_OPERATION_FLUSH;
                let max_out_size = 2 * block_size + 503;
                let mut inplace = true;
                let mut storage_ix: usize = self.last_bytes_bits_ as usize;

                if force_flush && block_size == 0 {
                    self.stream_state_ = StreamState::FlushRequested;
                    continue;
                }
                if max_out_size > io.available_out() {
                    inplace = false;
                    get_brotli_storage(self, max_out_size);
                }
                let table_size;
                {
                    let (last_bytes, quality) = (self.last_bytes_, self.params.quality);
                    {
                        let storage: &mut [u8] =
                            if inplace { &mut io.output[io.out_pos..] } else { &mut self.storage_[..] };
                        storage[0] = last_bytes as u8;
                        storage[1] = (last_bytes >> 8) as u8;
                    }
                    table_size = get_hash_table(self, quality, block_size);
                    let s = &mut *self;
                    let storage: &mut [u8] = if inplace { &mut io.output[io.out_pos..] } else { &mut s.storage_[..] };
                    let table = hash_table(&mut s.small_table_, &mut s.large_table_, table_size);
                    let input = &io.input[io.in_pos..];
                    if quality == FAST_ONE_PASS_COMPRESSION_QUALITY {
                        brotli_compress_fragment_fast(
                            s.one_pass_arena_.as_mut().expect("one pass arena"),
                            input,
                            block_size,
                            is_last,
                            table,
                            table_size,
                            &mut storage_ix,
                            storage,
                        );
                    } else {
                        let (cb, lb): (&mut [u32], &mut [u8]) = if use_tmp {
                            (&mut tmp_command_buf, &mut tmp_literal_buf)
                        } else {
                            (&mut s.command_buf_, &mut s.literal_buf_)
                        };
                        brotli_compress_fragment_two_pass(
                            s.two_pass_arena_.as_mut().expect("two pass arena"),
                            input,
                            block_size,
                            is_last,
                            cb,
                            lb,
                            table,
                            table_size,
                            &mut storage_ix,
                            storage,
                        );
                    }
                }
                if block_size != 0 {
                    io.in_pos += block_size;
                    self.total_in_ += block_size as u64;
                }
                let last_byte;
                if inplace {
                    let out_bytes = storage_ix >> 3;
                    debug_assert!(out_bytes <= io.available_out());
                    debug_assert!((storage_ix & 7) == 0 || out_bytes < io.available_out());
                    last_byte = io.output[io.out_pos + (storage_ix >> 3)];
                    io.out_pos += out_bytes;
                    self.total_out_ += out_bytes as u64;
                    self.set_total_out(total_out);
                } else {
                    let out_bytes = storage_ix >> 3;
                    self.next_out_ = NextOut::Storage(0);
                    self.available_out_ = out_bytes;
                    last_byte = self.storage_[storage_ix >> 3];
                }
                self.last_bytes_ = last_byte as u16;
                self.last_bytes_bits_ = (storage_ix & 7) as u8;

                if force_flush {
                    self.stream_state_ = StreamState::FlushRequested;
                }
                if is_last {
                    self.stream_state_ = StreamState::Finished;
                }
                continue;
            }
            break;
        }
        drop(tmp_command_buf);
        drop(tmp_literal_buf);
        self.check_flush_complete();
        true
    }

    fn process_metadata(&mut self, io: &mut StreamIo, total_out: &mut Option<&mut usize>) -> bool {
        if io.available_in() > (1usize << 24) {
            return false;
        }
        // Switch to metadata block workflow, if required.
        if self.stream_state_ == StreamState::Processing {
            self.remaining_metadata_bytes_ = io.available_in() as u32;
            self.stream_state_ = StreamState::MetadataHead;
        }
        if self.stream_state_ != StreamState::MetadataHead && self.stream_state_ != StreamState::MetadataBody {
            return false;
        }

        loop {
            if self.inject_flush_or_push_output(io, total_out) {
                continue;
            }
            if self.available_out_ != 0 {
                break;
            }

            if self.input_pos_ != self.last_flush_pos_ {
                let result = self.encode_data(false, true);
                if !result {
                    return false;
                }
                continue;
            }

            if self.stream_state_ == StreamState::MetadataHead {
                self.next_out_ = NextOut::Tiny(0);
                self.available_out_ = self.write_metadata_header(self.remaining_metadata_bytes_ as usize);
                self.stream_state_ = StreamState::MetadataBody;
                continue;
            } else {
                // Exit workflow only when there is no more input and no more
                // output. Otherwise client may continue producing empty
                // metadata blocks.
                if self.remaining_metadata_bytes_ == 0 {
                    self.remaining_metadata_bytes_ = u32::MAX;
                    self.stream_state_ = StreamState::Processing;
                    break;
                }
                if io.available_out() != 0 {
                    // Directly copy input to output.
                    let copy = (self.remaining_metadata_bytes_ as usize).min(io.available_out());
                    io.output[io.out_pos..io.out_pos + copy].copy_from_slice(&io.input[io.in_pos..io.in_pos + copy]);
                    io.in_pos += copy;
                    self.total_in_ += copy as u64; // not actually data input, though
                    self.remaining_metadata_bytes_ -= copy as u32;
                    io.out_pos += copy;
                } else {
                    // This guarantees progress in "TakeOutput" workflow.
                    let copy = self.remaining_metadata_bytes_.min(16) as usize;
                    self.next_out_ = NextOut::Tiny(0);
                    self.tiny_buf_[..copy].copy_from_slice(&io.input[io.in_pos..io.in_pos + copy]);
                    io.in_pos += copy;
                    self.total_in_ += copy as u64; // not actually data input, though
                    self.remaining_metadata_bytes_ -= copy as u32;
                    self.available_out_ = copy;
                }
                continue;
            }
        }

        true
    }

    fn update_size_hint(&mut self, available_in: usize) {
        if self.params.size_hint == 0 {
            let delta: u64 = unprocessed_input_size(self);
            let tail: u64 = available_in as u64;
            let limit: u32 = 1u32 << 30;
            let total: u32 = if delta >= limit as u64 || tail >= limit as u64 || delta + tail >= limit as u64 {
                limit
            } else {
                (delta + tail) as u32
            };
            self.params.size_hint = total as usize;
        }
    }

    /// `BrotliEncoderCompressStream`.
    ///
    /// `io.input[io.in_pos..]` is the available input, `io.output
    /// [io.out_pos..]` the available output space; both positions are
    /// advanced.  `total_out` (if any) is updated like in C.
    pub fn compress_stream(&mut self, op: u32, io: &mut StreamIo, mut total_out: Option<&mut usize>) -> bool {
        if !self.ensure_initialized() {
            return false;
        }

        // Unfinished metadata block; check requirements.
        if self.remaining_metadata_bytes_ != u32::MAX {
            if io.available_in() != self.remaining_metadata_bytes_ as usize {
                return false;
            }
            if op != BROTLI_OPERATION_EMIT_METADATA {
                return false;
            }
        }

        if op == BROTLI_OPERATION_EMIT_METADATA {
            self.update_size_hint(0); // First data metablock might be emitted here.
            return self.process_metadata(io, &mut total_out);
        }

        if self.stream_state_ == StreamState::MetadataHead || self.stream_state_ == StreamState::MetadataBody {
            return false;
        }

        if self.stream_state_ != StreamState::Processing && io.available_in() != 0 {
            return false;
        }
        if self.params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY
            || self.params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY
        {
            return self.compress_stream_fast(op, io, &mut total_out);
        }
        loop {
            let mut remaining_block_size = remaining_input_block_size(self);
            // Shorten input to flint size.
            if self.flint_ >= 0 && remaining_block_size > self.flint_ as usize {
                remaining_block_size = self.flint_ as usize;
            }

            if remaining_block_size != 0 && io.available_in() != 0 {
                let copy_input_size = remaining_block_size.min(io.available_in());
                let input = io.input;
                self.copy_input_to_ring_buffer(&input[io.in_pos..io.in_pos + copy_input_size]);
                io.in_pos += copy_input_size;
                self.total_in_ += copy_input_size as u64;
                if self.flint_ > 0 {
                    self.flint_ = (self.flint_ as i32 - copy_input_size as i32) as i8;
                }
                continue;
            }

            if self.inject_flush_or_push_output(io, &mut total_out) {
                // Exit the "emit flint" workflow.
                if self.flint_ == BROTLI_FLINT_WAITING_FOR_FLUSHING {
                    self.check_flush_complete();
                    if self.stream_state_ == StreamState::Processing {
                        self.flint_ = BROTLI_FLINT_DONE;
                    }
                }
                continue;
            }

            // Compress data only when internal output buffer is empty, stream
            // is not finished and there is no pending flush request.
            if self.available_out_ == 0 && self.stream_state_ == StreamState::Processing {
                if remaining_block_size == 0 || op != BROTLI_OPERATION_PROCESS {
                    let is_last = io.available_in() == 0 && op == BROTLI_OPERATION_FINISH;
                    let mut force_flush = io.available_in() == 0 && op == BROTLI_OPERATION_FLUSH;
                    // Force emitting (uncompressed) piece containing flint.
                    if !is_last && self.flint_ == 0 {
                        self.flint_ = BROTLI_FLINT_WAITING_FOR_FLUSHING;
                        force_flush = true;
                    }
                    self.update_size_hint(io.available_in());
                    let result = self.encode_data(is_last, force_flush);
                    if !result {
                        return false;
                    }
                    if force_flush {
                        self.stream_state_ = StreamState::FlushRequested;
                    }
                    if is_last {
                        self.stream_state_ = StreamState::Finished;
                    }
                    continue;
                }
            }
            break;
        }
        self.check_flush_complete();
        true
    }

    /// `BrotliEncoderIsFinished`.
    pub fn is_finished(&self) -> bool {
        self.stream_state_ == StreamState::Finished && !self.has_more_output()
    }

    /// `BrotliEncoderHasMoreOutput`.
    pub fn has_more_output(&self) -> bool {
        self.available_out_ != 0
    }

    /// `BrotliEncoderTakeOutput`: returns a pointer to (and the number in
    /// `*size` of) the bytes taken, or NULL with `*size == 0`.  The data
    /// stays valid until the next call into the encoder.
    pub fn take_output_raw(&mut self, size: &mut usize) -> *const u8 {
        let mut consumed_size = self.available_out_;
        let result: *const u8 = match self.next_out_ {
            NextOut::Null => core::ptr::null(),
            NextOut::Storage(o) => self.storage_.as_ptr().wrapping_add(o),
            NextOut::Tiny(o) => self.tiny_buf_.as_ptr().wrapping_add(o),
        };
        if *size != 0 {
            consumed_size = (*size).min(self.available_out_);
        }
        if consumed_size != 0 {
            self.next_out_ = self.next_out_.advance(consumed_size);
            self.available_out_ -= consumed_size;
            self.total_out_ += consumed_size as u64;
            self.check_flush_complete();
            *size = consumed_size;
            result
        } else {
            *size = 0;
            core::ptr::null()
        }
    }

    /// Safe wrapper of [`take_output_raw`](Self::take_output_raw).
    pub fn take_output(&mut self, size: &mut usize) -> Option<&[u8]> {
        let p = self.take_output_raw(size);
        if p.is_null() {
            None
        } else {
            // SAFETY: `p` points to `*size` bytes inside `storage_` or
            // `tiny_buf_`, which are not modified while `self` is borrowed.
            Some(unsafe { core::slice::from_raw_parts(p, *size) })
        }
    }

    /// `BrotliEncoderAttachPreparedDictionary` for a prepared (compound)
    /// dictionary.
    ///
    /// # Safety
    /// `prepared` must outlive the encoder (C API contract).
    pub unsafe fn attach_prepared_dictionary(&mut self, prepared: &PreparedDictionary) -> bool {
        self.params.dictionary.compound.attach(prepared)
    }
}

/// `BrotliEncoderMaxCompressedSize`.
pub fn brotli_encoder_max_compressed_size(input_size: usize) -> usize {
    // [window bits / empty metadata] + N * [uncompressed] + [last empty]
    let num_large_blocks = input_size >> 14;
    let overhead = 2usize.wrapping_add(4usize.wrapping_mul(num_large_blocks)).wrapping_add(3).wrapping_add(1);
    let result = input_size.wrapping_add(overhead);
    if input_size == 0 {
        return 2;
    }
    if result < input_size {
        0
    } else {
        result
    }
}

/// Wraps data to uncompressed brotli stream with minimal window size.
/// `output` should point at region with at least
/// BrotliEncoderMaxCompressedSize addressable bytes.  Returns the length of
/// stream.
pub fn make_uncompressed_stream(input: &[u8], output: &mut [u8]) -> usize {
    let input_size = input.len();
    let mut size = input_size;
    let mut result: usize = 0;
    let mut offset: usize = 0;
    if input_size == 0 {
        output[0] = 6;
        return 1;
    }
    output[result] = 0x21; // window bits = 10, is_last = false
    result += 1;
    output[result] = 0x03; // empty metadata, padding
    result += 1;
    while size > 0 {
        let mut nibbles: u32 = 0;
        let chunk_size: u32 = if size > (1usize << 24) { 1u32 << 24 } else { size as u32 };
        if chunk_size > (1u32 << 16) {
            nibbles = if chunk_size > (1u32 << 20) { 2 } else { 1 };
        }
        let bits: u32 = (nibbles << 1) | ((chunk_size - 1) << 3) | (1u32 << (19 + 4 * nibbles));
        output[result] = bits as u8;
        output[result + 1] = (bits >> 8) as u8;
        output[result + 2] = (bits >> 16) as u8;
        result += 3;
        if nibbles == 2 {
            output[result] = (bits >> 24) as u8;
            result += 1;
        }
        output[result..result + chunk_size as usize].copy_from_slice(&input[offset..offset + chunk_size as usize]);
        result += chunk_size as usize;
        offset += chunk_size as usize;
        size -= chunk_size as usize;
    }
    output[result] = 3;
    result + 1
}

/// `BrotliEncoderCompress`: one-shot compression of `input` into
/// `encoded_buffer`; `*encoded_size` is the capacity on entry and the
/// produced size on exit (exact C semantics, incl. the uncompressed
/// fallback).
pub fn brotli_encoder_compress(
    quality: i32,
    lgwin: i32,
    mode: u32,
    input: &[u8],
    encoded_size: &mut usize,
    encoded_buffer: &mut [u8],
) -> bool {
    let input_size = input.len();
    let out_size = *encoded_size;
    let max_out_size = brotli_encoder_max_compressed_size(input_size);
    if out_size == 0 {
        // Output buffer needs at least one byte.
        return false;
    }
    if input_size == 0 {
        // Handle the special case of empty input.
        *encoded_size = 1;
        encoded_buffer[0] = 6;
        return true;
    }

    let fallback;
    {
        let mut s = BrotliEncoderState::new(MemoryManager::default());
        let mut total_out: usize = 0;
        // TODO(eustas): check that parameters are sane.
        s.set_parameter(BROTLI_PARAM_QUALITY, quality as u32);
        s.set_parameter(BROTLI_PARAM_LGWIN, lgwin as u32);
        s.set_parameter(BROTLI_PARAM_MODE, mode);
        s.set_parameter(BROTLI_PARAM_SIZE_HINT, input_size as u32);
        if lgwin > BROTLI_MAX_WINDOW_BITS {
            s.set_parameter(BROTLI_PARAM_LARGE_WINDOW, 1);
        }
        let mut io = StreamIo { input, in_pos: 0, output: &mut encoded_buffer[..out_size], out_pos: 0 };
        let mut result = s.compress_stream(BROTLI_OPERATION_FINISH, &mut io, Some(&mut total_out));
        if !s.is_finished() {
            result = false;
        }
        *encoded_size = total_out;
        drop(s);
        fallback = !result || (max_out_size != 0 && *encoded_size > max_out_size);
    }
    if !fallback {
        return true;
    }
    *encoded_size = 0;
    if max_out_size == 0 {
        return false;
    }
    if out_size >= max_out_size {
        *encoded_size = make_uncompressed_stream(input, encoded_buffer);
        return true;
    }
    false
}

/// `BrotliEncoderVersion`.
pub fn brotli_encoder_version() -> u32 {
    BROTLI_VERSION
}

/// `sizeof(BrotliEncoderState)` of the C library on this target (leaks into
/// `BrotliEncoderEstimatePeakMemoryUsage`).
pub const C_SIZEOF_ENCODER_STATE: usize = if cfg!(target_pointer_width = "64") {
    7920
} else if core::mem::align_of::<u64>() == 4 {
    6828
} else {
    6936
};

/// `sizeof(ManagedDictionary)` of the C library on this target.
pub const C_SIZEOF_MANAGED_DICTIONARY: usize = if cfg!(target_pointer_width = "64") { 40 } else { 20 };
/// `sizeof(PreparedDictionary)` of the C library.
pub const C_SIZEOF_PREPARED_DICTIONARY: usize = 24;

/// `BrotliEncoderEstimatePeakMemoryUsage`.
pub fn brotli_encoder_estimate_peak_memory_usage(quality: i32, lgwin: i32, input_size: usize) -> usize {
    let mut params = brotli_encoder_init_params();
    // BROTLI_ENCODER_MEMORY_MANAGER_SLOTS == 0 (BROTLI_ENCODER_EXIT_ON_OOM).
    let memory_manager_size: usize = 0;
    params.quality = quality;
    params.lgwin = lgwin;
    params.size_hint = input_size;
    params.large_window = lgwin > BROTLI_MAX_WINDOW_BITS;
    sanitize_params(&mut params);
    params.lgblock = compute_lg_block(&params);
    let mut hp = params.hasher;
    choose_hasher(&params, &mut hp);
    params.hasher = hp;
    if params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY || params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY {
        let mut state_size = C_SIZEOF_ENCODER_STATE;
        let block_size = input_size.min(1usize << params.lgwin);
        let hash_table_size = hash_table_size(max_hash_table_size(params.quality), block_size);
        let hash_size = if hash_table_size < (1usize << 10) { 0 } else { core::mem::size_of::<i32>() * hash_table_size };
        let cmdbuf_size =
            if params.quality == FAST_TWO_PASS_COMPRESSION_QUALITY { 5 * block_size.min(1usize << 17) } else { 0 };
        if params.quality == FAST_ONE_PASS_COMPRESSION_QUALITY {
            state_size += core::mem::size_of::<BrotliOnePassArena>();
        } else {
            state_size += core::mem::size_of::<BrotliTwoPassArena>();
        }
        hash_size + cmdbuf_size + state_size
    } else {
        let short_ringbuffer_size: usize = 1usize << params.lgblock;
        let ringbuffer_bits = compute_rb_bits(&params);
        let ringbuffer_size = if input_size < short_ringbuffer_size {
            input_size
        } else {
            (1usize << ringbuffer_bits) + short_ringbuffer_size
        };
        let mut hash_size = [0usize; 4];
        let metablock_size = input_size.min(max_metablock_size(&params));
        let inputblock_size = input_size.min(1usize << params.lgblock);
        let mut cmdbuf_size = metablock_size * 2 + inputblock_size * 6;
        let outbuf_size = metablock_size * 2 + 503;
        let mut histogram_size: usize = 0;
        hasher_size(&params, true, input_size, &mut hash_size);
        if params.quality < MIN_QUALITY_FOR_BLOCK_SPLIT {
            cmdbuf_size =
                cmdbuf_size.min(MAX_NUM_DELAYED_SYMBOLS * core::mem::size_of::<Command>() + inputblock_size * 12);
        }
        if params.quality >= MIN_QUALITY_FOR_HQ_BLOCK_SPLITTING {
            // Only a very rough estimation, based on enwik8.
            histogram_size = 200 << 20;
        } else if params.quality >= MIN_QUALITY_FOR_BLOCK_SPLIT {
            let literal_histograms = (metablock_size / 6144).min(256);
            let command_histograms = (metablock_size / 6144).min(256);
            let distance_histograms = (metablock_size / 6144).min(256);
            histogram_size = literal_histograms * core::mem::size_of::<HistogramLiteral>()
                + command_histograms * core::mem::size_of::<HistogramCommand>()
                + distance_histograms * core::mem::size_of::<HistogramDistance>();
        }
        memory_manager_size
            + ringbuffer_size
            + hash_size[0]
            + hash_size[1]
            + hash_size[2]
            + hash_size[3]
            + cmdbuf_size
            + outbuf_size
            + histogram_size
    }
}

/// `ManagedDictionary`: the object behind `BrotliEncoderPreparedDictionary*`
/// returned by `BrotliEncoderPrepareDictionary`.  `magic` must be the first
/// field (the API distinguishes dictionary kinds by the leading u32).
#[repr(C)]
pub struct ManagedDictionary {
    pub magic: u32,
    pub memory_manager_: MemoryManager,
    pub dictionary: Option<Boxed<PreparedDictionary>>,
}

/// `BrotliEncoderGetPreparedDictionarySize` for a prepared dictionary
/// (`overhead` is the size of the managing wrapper, if any).
pub fn prepared_dictionary_size(dictionary: &PreparedDictionary, overhead: usize) -> usize {
    if dictionary.magic == K_PREPARED_DICTIONARY_MAGIC {
        // Keep in sync with step 3 of CreatePreparedDictionary
        C_SIZEOF_PREPARED_DICTIONARY
            + dictionary.source_size as usize
            + (core::mem::size_of::<u32>() << dictionary.slot_bits)
            + (core::mem::size_of::<u16>() << dictionary.bucket_bits)
            + (core::mem::size_of::<u32>() * dictionary.num_items as usize)
            + overhead
    } else if dictionary.magic == K_LEAN_PREPARED_DICTIONARY_MAGIC {
        C_SIZEOF_PREPARED_DICTIONARY
            + core::mem::size_of::<*const u8>()
            + (core::mem::size_of::<u32>() << dictionary.slot_bits)
            + (core::mem::size_of::<u16>() << dictionary.bucket_bits)
            + (core::mem::size_of::<u32>() * dictionary.num_items as usize)
            + overhead
    } else {
        0
    }
}

/// Creates a managed raw prepared dictionary
/// (`BrotliEncoderPrepareDictionary` with `BROTLI_SHARED_DICTIONARY_RAW`).
///
/// # Safety
/// `data` must outlive the returned dictionary and every encoder it is
/// attached to.
pub unsafe fn prepare_raw_dictionary(m: MemoryManager, data: &[u8]) -> Option<PreparedDictionary> {
    create_prepared_dictionary(&m, data)
}

/// Magic constants re-exported for the FFI layer.
pub const MANAGED_DICTIONARY_MAGIC: u32 = K_MANAGED_DICTIONARY_MAGIC;
pub const SHARED_DICTIONARY_MAGIC: u32 = K_SHARED_DICTIONARY_MAGIC;
