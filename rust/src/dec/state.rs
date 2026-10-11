//! Port of `c/dec/state.h` / `state.c`: Brotli state for partial streaming
//! decoding.

use core::ffi::c_void;

use super::bit_reader::{BitReader, Reg};
use super::huffman::{HuffmanCode, HuffmanTreeGroup, BROTLI_HUFFMAN_MAX_CODE_LENGTH, BROTLI_HUFFMAN_MAX_SIZE_272};
use crate::common::alloc::{Allocator, Boxed, Buf};
use crate::common::constants::{BROTLI_CODE_LENGTH_CODES, BROTLI_NUM_COMMAND_SYMBOLS};
use crate::common::context::{brotli_context_lut, ContextLut, ContextType};
use crate::common::shared_dictionary::SharedDictionary;

/// `brotli_decoder_metadata_start_func`.
pub type MetadataStartFunc = Option<unsafe extern "C" fn(opaque: *mut c_void, size: usize)>;
/// `brotli_decoder_metadata_chunk_func`.
pub type MetadataChunkFunc = Option<unsafe extern "C" fn(opaque: *mut c_void, data: *const u8, size: usize)>;

/// `BrotliRunningState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunningState {
    Uninited,
    LargeWindowBits,
    Initialize,
    MetablockBegin,
    MetablockHeader,
    MetablockHeader2,
    ContextModes,
    CommandBegin,
    CommandInner,
    CommandPostDecodeLiterals,
    CommandPostWrapCopy,
    Uncompressed,
    Metadata,
    CommandInnerWrite,
    MetablockDone,
    CommandPostWrite1,
    CommandPostWrite2,
    BeforeCompressedMetablockHeader,
    HuffmanCode0,
    HuffmanCode1,
    HuffmanCode2,
    HuffmanCode3,
    ContextMap1,
    ContextMap2,
    TreeGroup,
    BeforeCompressedMetablockBody,
    Done,
}

/// `BrotliRunningMetablockHeaderState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetablockHeaderState {
    None,
    Empty,
    Nibbles,
    Size,
    Uncompressed,
    Reserved,
    Bytes,
    Metadata,
}

/// `BrotliRunningUncompressedState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UncompressedState {
    None,
    Write,
}

/// `BrotliRunningTreeGroupState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeGroupState {
    None,
    Loop,
}

/// `BrotliRunningContextMapState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextMapState {
    None,
    ReadPrefix,
    Huffman,
    Decode,
    Transform,
}

/// `BrotliRunningHuffmanState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HuffmanState {
    None,
    SimpleSize,
    SimpleRead,
    SimpleBuild,
    Complex,
    LengthSymbols,
}

/// `BrotliRunningDecodeUint8State`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeUint8State {
    None,
    Short,
    Long,
}

/// `BrotliRunningReadBlockLengthState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadBlockLengthState {
    None,
    Suffix,
}

/// `BrotliDecoderCompoundDictionary`: decoder state addon used for the
/// compound dictionary functionality.
pub struct CompoundDictionary {
    pub num_chunks: u8,
    pub block_bits: u8,
    pub br_index: u16,
    pub total_size: u32,
    pub br_offset: u32,
    pub br_length: u32,
    pub br_copied: u32,
    /// Client-owned chunk data (C contract: must outlive the decoder).
    pub chunks: [*const u8; 16],
    pub chunk_offsets: [u32; 16],
    pub block_map: [u8; 256],
}

/// The internal input buffer (`union { uint64_t u64; uint8_t u8[8]; }` in
/// C): 8-byte aligned, because `BrotliWarmupBitReader` looks at the address
/// alignment on platforms without fast unaligned reads.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct InputBuffer(pub [u8; 8]);

/// Size of `symbols_lists_array`.
pub const SYMBOL_LISTS_SIZE: usize = BROTLI_HUFFMAN_MAX_CODE_LENGTH as usize + 1 + BROTLI_NUM_COMMAND_SYMBOLS;
/// `h->symbol_lists = &h->symbols_lists_array[BROTLI_HUFFMAN_MAX_CODE_LENGTH + 1]`
pub const SYMBOL_LISTS_BASE: i32 = BROTLI_HUFFMAN_MAX_CODE_LENGTH + 1;

/// `BrotliMetablockHeaderArena`.
///
/// In C this shares memory (union) with [`MetablockBodyArena`]; both are
/// fully (re-)initialized before use, so separate storage is equivalent.
pub struct MetablockHeaderArena {
    pub substate_tree_group: TreeGroupState,
    pub substate_context_map: ContextMapState,
    pub substate_huffman: HuffmanState,

    pub sub_loop_counter: Reg,

    pub repeat_code_len: Reg,
    pub prev_code_len: Reg,

    // For ReadHuffmanCode.
    pub symbol: Reg,
    pub repeat: Reg,
    pub space: Reg,

    /// Huffman table for "histograms".
    pub table: [HuffmanCode; 32],
    /// Storage for symbol_lists (heads of symbol chains); C addresses it
    /// relative to `SYMBOL_LISTS_BASE`.
    pub symbols_lists_array: [u16; SYMBOL_LISTS_SIZE],
    /// Tails of symbol chains.
    pub next_symbol: [i32; 32],
    pub code_length_code_lengths: [u8; BROTLI_CODE_LENGTH_CODES],
    /// Population counts for the code lengths.
    pub code_length_histo: [u16; 16],

    // For HuffmanTreeGroupDecode.
    pub htree_index: i32,
    /// Index into the tree group's `mem`.
    pub next: usize,

    // For DecodeContextMap.
    pub context_index: Reg,
    pub max_run_length_prefix: Reg,
    pub code: Reg,
}

impl MetablockHeaderArena {
    fn new() -> Self {
        MetablockHeaderArena {
            substate_tree_group: TreeGroupState::None,
            substate_context_map: ContextMapState::None,
            substate_huffman: HuffmanState::None,
            sub_loop_counter: 0,
            repeat_code_len: 0,
            prev_code_len: 0,
            symbol: 0,
            repeat: 0,
            space: 0,
            table: [HuffmanCode(0); 32],
            symbols_lists_array: [0; SYMBOL_LISTS_SIZE],
            next_symbol: [0; 32],
            code_length_code_lengths: [0; BROTLI_CODE_LENGTH_CODES],
            code_length_histo: [0; 16],
            htree_index: 0,
            next: 0,
            context_index: 0,
            max_run_length_prefix: 0,
            code: 0,
        }
    }
}

/// `BrotliMetablockBodyArena`.
pub struct MetablockBodyArena {
    pub dist_extra_bits: [u8; 544],
    pub dist_offset: [Reg; 544],
}

/// Literal/Command/Distance block size maximum; same as maximum metablock
/// size; used as block size when there is no block switching.
pub const BROTLI_BLOCK_SIZE_CAP: Reg = 1 << 24;

/// `BrotliDecoderStateStruct`.
pub struct DecoderState {
    pub(crate) state: RunningState,

    /// This counter is reused for several disjoint loops.
    pub(crate) loop_counter: i32,

    pub(crate) br: BitReader,

    pub(crate) alloc: Allocator,

    /// Temporary storage for remaining input. Brotli stream format is
    /// designed in a way, that 64 bits are enough to make progress in
    /// decoding.
    pub(crate) buffer: InputBuffer,
    pub(crate) buffer_length: Reg,

    pub(crate) pos: i32,
    pub(crate) max_backward_distance: i32,
    pub(crate) max_distance: i32,
    pub(crate) ringbuffer_size: i32,
    pub(crate) ringbuffer_mask: i32,
    pub(crate) dist_rb_idx: i32,
    pub(crate) dist_rb: [i32; 4],
    pub(crate) error_code: i32,
    pub(crate) meta_block_remaining_len: i32,

    /// `ringbuffer`; `ringbuffer_end` is `ringbuffer_size`.
    pub(crate) ringbuffer: Buf<u8>,
    /// Index of the current command tree in `insert_copy_hgroup.mem`.
    pub(crate) htree_command: usize,
    /// `context_lookup` (NULL in C until the first metablock body; it is
    /// never used before being set).
    pub(crate) context_lookup: ContextLut,
    /// Offset of `context_map_slice` in `context_map`.
    pub(crate) context_map_slice: usize,
    /// Offset of `dist_context_map_slice` in `dist_context_map`.
    pub(crate) dist_context_map_slice: usize,

    pub(crate) literal_hgroup: HuffmanTreeGroup,
    pub(crate) insert_copy_hgroup: HuffmanTreeGroup,
    pub(crate) distance_hgroup: HuffmanTreeGroup,
    /// `block_type_trees`; `block_len_trees` starts at
    /// `3 * BROTLI_HUFFMAN_MAX_SIZE_258`.
    pub(crate) block_type_trees: Buf<HuffmanCode>,
    /// This is true if the literal context map histogram type always matches
    /// the block type. It is then not needed to keep the context (faster
    /// decoding).
    pub(crate) trivial_literal_context: i32,
    /// Distance context is actual after command is decoded and before
    /// distance is computed. After distance computation it is used as a
    /// temporary variable.
    pub(crate) distance_context: i32,
    pub(crate) block_length: [Reg; 3],
    pub(crate) block_length_index: Reg,
    pub(crate) num_block_types: [Reg; 3],
    pub(crate) block_type_rb: [Reg; 6],
    pub(crate) distance_postfix_bits: Reg,
    pub(crate) num_direct_distance_codes: Reg,
    pub(crate) num_dist_htrees: Reg,
    pub(crate) dist_context_map: Buf<u8>,
    /// Index of the current literal tree in `literal_hgroup.mem`.
    pub(crate) literal_htree: usize,

    // For partial write operations.
    /// how many times we went around the ring-buffer
    pub(crate) rb_roundtrips: usize,
    /// how much output to the user in total
    pub(crate) partial_pos_out: usize,

    // For InverseMoveToFrontTransform.
    pub(crate) mtf_upper_bound: Reg,
    /// `uint32_t mtf[64 + 1]` viewed as bytes.
    pub(crate) mtf: [u8; 4 * (64 + 1)],

    pub(crate) copy_length: i32,
    pub(crate) distance_code: i32,

    pub(crate) dist_htree_index: u8,

    pub(crate) metadata_start_func: MetadataStartFunc,
    pub(crate) metadata_chunk_func: MetadataChunkFunc,
    pub(crate) metadata_callback_opaque: *mut c_void,

    /// For reporting: how many bytes of input are consumed.
    pub(crate) used_input: u64,

    // States inside function calls.
    pub(crate) substate_metablock_header: MetablockHeaderState,
    pub(crate) substate_uncompressed: UncompressedState,
    pub(crate) substate_decode_uint8: DecodeUint8State,
    pub(crate) substate_read_block_length: ReadBlockLengthState,

    pub(crate) new_ringbuffer_size: i32,

    // Bit fields of the C struct.
    pub(crate) is_last_metablock: u32,
    pub(crate) is_uncompressed: u32,
    pub(crate) is_metadata: u32,
    pub(crate) should_wrap_ringbuffer: u32,
    pub(crate) canny_ringbuffer_allocation: u32,
    pub(crate) large_window: u32,
    /// 6-bit field.
    pub(crate) window_bits: u32,
    /// 8-bit field.
    pub(crate) size_nibbles: u32,

    pub(crate) num_literal_htrees: Reg,
    pub(crate) context_map: Buf<u8>,
    pub(crate) context_modes: Buf<u8>,

    pub(crate) dictionary: Option<Boxed<SharedDictionary>>,
    pub(crate) compound_dictionary: Option<Boxed<CompoundDictionary>>,

    /// 256 bits
    pub(crate) trivial_literal_contexts: [u32; 8],

    pub(crate) header: MetablockHeaderArena,
    /// `arena.header.context_map_table` (kept outside of the header arena
    /// so that it can be borrowed independently).
    pub(crate) context_map_table: [HuffmanCode; BROTLI_HUFFMAN_MAX_SIZE_272],
    pub(crate) body: MetablockBodyArena,
}

/// `BROTLI_DECODER_FREE` of a buffer: like C, the free callback is invoked
/// even for NULL (empty) buffers.
#[inline]
pub(crate) fn decoder_free<T: Copy + Default>(alloc: &Allocator, b: &mut Buf<T>) {
    if b.is_empty() {
        // SAFETY: freeing NULL is what the C code does; free functions must
        // accept NULL.
        unsafe { alloc.free_raw(core::ptr::null_mut()) }
    } else {
        b.free();
    }
}

impl DecoderState {
    /// `BrotliDecoderStateInit`.  Returns `None` if the shared dictionary
    /// instance could not be allocated.
    ///
    /// `alloc` must be `Allocator::new(alloc_func, free_func, opaque)` of
    /// the C arguments (callers validate the pair).
    pub fn new(alloc: Allocator) -> Option<DecoderState> {
        let dictionary = Boxed::try_new(&alloc, SharedDictionary::new())?;
        Some(DecoderState {
            state: RunningState::Uninited,
            loop_counter: 0,
            br: BitReader::default(),
            alloc,
            buffer: InputBuffer([0; 8]),
            buffer_length: 0,
            pos: 0,
            max_backward_distance: 0,
            max_distance: 0,
            ringbuffer_size: 0,
            ringbuffer_mask: 0,
            dist_rb_idx: 0,
            dist_rb: [16, 15, 11, 4],
            error_code: 0, // BROTLI_DECODER_NO_ERROR
            meta_block_remaining_len: 0,
            ringbuffer: Buf::empty(),
            htree_command: 0,
            context_lookup: brotli_context_lut(ContextType::Lsb6),
            context_map_slice: 0,
            dist_context_map_slice: 0,
            literal_hgroup: HuffmanTreeGroup::default(),
            insert_copy_hgroup: HuffmanTreeGroup::default(),
            distance_hgroup: HuffmanTreeGroup::default(),
            block_type_trees: Buf::empty(),
            trivial_literal_context: 0,
            distance_context: 0,
            block_length: [0; 3],
            block_length_index: 0,
            num_block_types: [0; 3],
            block_type_rb: [0; 6],
            distance_postfix_bits: 0,
            num_direct_distance_codes: 0,
            num_dist_htrees: 0,
            dist_context_map: Buf::empty(),
            literal_htree: 0,
            rb_roundtrips: 0,
            partial_pos_out: 0,
            mtf_upper_bound: 63,
            mtf: [0; 4 * 65],
            copy_length: 0,
            distance_code: 0,
            dist_htree_index: 0,
            metadata_start_func: None,
            metadata_chunk_func: None,
            metadata_callback_opaque: core::ptr::null_mut(),
            used_input: 0,
            substate_metablock_header: MetablockHeaderState::None,
            substate_uncompressed: UncompressedState::None,
            substate_decode_uint8: DecodeUint8State::None,
            substate_read_block_length: ReadBlockLengthState::None,
            new_ringbuffer_size: 0,
            is_last_metablock: 0,
            is_uncompressed: 0,
            is_metadata: 0,
            should_wrap_ringbuffer: 0,
            canny_ringbuffer_allocation: 1,
            large_window: 0,
            window_bits: 0,
            size_nibbles: 0,
            num_literal_htrees: 0,
            context_map: Buf::empty(),
            context_modes: Buf::empty(),
            dictionary: Some(dictionary),
            compound_dictionary: None,
            trivial_literal_contexts: [0; 8],
            header: MetablockHeaderArena::new(),
            context_map_table: [HuffmanCode(0); BROTLI_HUFFMAN_MAX_SIZE_272],
            body: MetablockBodyArena { dist_extra_bits: [0; 544], dist_offset: [0; 544] },
        })
    }

    /// `BrotliDecoderStateMetablockBegin`.
    pub(crate) fn metablock_begin(&mut self) {
        self.meta_block_remaining_len = 0;
        self.block_length = [BROTLI_BLOCK_SIZE_CAP; 3];
        self.num_block_types = [1; 3];
        self.block_type_rb = [1, 0, 1, 0, 1, 0];
        // context_map / context_modes / dist_context_map are NULL here in C
        // (freed by BrotliDecoderStateCleanupAfterMetablock).
        self.context_map_slice = 0;
        self.literal_htree = 0;
        self.dist_context_map_slice = 0;
        self.dist_htree_index = 0;
        self.context_lookup = brotli_context_lut(ContextType::Lsb6);
        // literal_hgroup / insert_copy_hgroup / distance_hgroup: codes and
        // htrees are already freed (NULL).
    }

    /// `BrotliDecoderStateCleanupAfterMetablock`.
    pub(crate) fn cleanup_after_metablock(&mut self) {
        let alloc = self.alloc;
        decoder_free(&alloc, &mut self.context_modes);
        decoder_free(&alloc, &mut self.context_map);
        decoder_free(&alloc, &mut self.dist_context_map);
        decoder_free(&alloc, &mut self.literal_hgroup.mem);
        decoder_free(&alloc, &mut self.insert_copy_hgroup.mem);
        decoder_free(&alloc, &mut self.distance_hgroup.mem);
    }

    /// `BrotliDecoderStateCleanup`.
    pub(crate) fn cleanup(&mut self) {
        self.cleanup_after_metablock();
        let alloc = self.alloc;
        // BROTLI_DECODER_FREE(s, s->compound_dictionary)
        match self.compound_dictionary.take() {
            Some(b) => drop(b),
            // SAFETY: C frees NULL here.
            None => unsafe { alloc.free_raw(core::ptr::null_mut()) },
        }
        // BrotliSharedDictionaryDestroyInstance(s->dictionary)
        if let Some(d) = self.dictionary.take() {
            // SAFETY: C frees the (NULL) custom word / transform lists of the
            // shared dictionary before the instance itself.
            unsafe {
                alloc.free_raw(core::ptr::null_mut());
                alloc.free_raw(core::ptr::null_mut());
                alloc.free_raw(core::ptr::null_mut());
            }
            drop(d);
        }
        decoder_free(&alloc, &mut self.ringbuffer);
        decoder_free(&alloc, &mut self.block_type_trees);
    }
}

impl Drop for DecoderState {
    fn drop(&mut self) {
        // The C state is cleaned up exactly once (BrotliDecoderStateCleanup)
        // when it is destroyed.
        if self.dictionary.is_some() {
            self.cleanup();
        }
    }
}

/// `BrotliDecoderHuffmanTreeGroupInit`.
pub(crate) fn huffman_tree_group_init(
    alloc: &Allocator,
    group: &mut HuffmanTreeGroup,
    alphabet_size_max: Reg,
    alphabet_size_limit: Reg,
    ntrees: Reg,
) -> bool {
    // 376 = 256 (1-st level table) + 4 + 7 + 15 + 31 + 63 (2-nd level
    // mix-tables). This number is discovered "unlimited" "enough"
    // calculator; it is actually a wee bigger than required in several cases
    // (especially for alphabets with less than 16 symbols).
    let max_table_size = alphabet_size_limit as usize + 376;
    let code_size = ntrees as usize * max_table_size;
    // sizeof(HuffmanCode*) * ntrees bytes, in units of sizeof(HuffmanCode).
    let htree_size = ntrees as usize * (core::mem::size_of::<*const HuffmanCode>() / core::mem::size_of::<HuffmanCode>());
    let p = Buf::try_new(alloc, code_size + htree_size);
    group.alphabet_size_max = alphabet_size_max as u16;
    group.alphabet_size_limit = alphabet_size_limit as u16;
    group.num_htrees = ntrees as u16;
    group.codes_start = htree_size;
    match p {
        Some(b) => {
            group.mem = b;
            true
        }
        None => {
            group.mem = Buf::empty();
            false
        }
    }
}
