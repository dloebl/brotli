//! Port of `c/enc/compound_dictionary.h` / `compound_dictionary.c`:
//! LZ77 prefix ("compound") dictionaries with precomputed hash chains.

use super::memory::{Buf, MemoryManager};
use crate::common::constants::SHARED_BROTLI_MAX_COMPOUND_DICTS;

pub const K_PREPARED_DICTIONARY_MAGIC: u32 = 0xDEBCEDE0;
pub const K_SHARED_DICTIONARY_MAGIC: u32 = 0xDEBCEDE1;
pub const K_MANAGED_DICTIONARY_MAGIC: u32 = 0xDEBCEDE2;
pub const K_LEAN_PREPARED_DICTIONARY_MAGIC: u32 = 0xDEBCEDE3;

pub const K_PREPARED_DICTIONARY_HASH_MUL64_LONG: u64 = (0x1FE35A7Bu64 << 32) | 0xD3579BD3u64;

/// `SHARED_BROTLI_MAX_RAW_DICT_SIZE` == `1u << (23u + sizeof(size_t))`.
pub const SHARED_BROTLI_MAX_RAW_DICT_SIZE: usize = 1usize << (23 + core::mem::size_of::<usize>());

/// `PreparedDictionary` ("lean" flavour: the source is referenced, not
/// copied).  `magic` must stay the first field: the C API distinguishes
/// dictionary kinds by the leading `uint32_t`.
#[repr(C)]
pub struct PreparedDictionary {
    pub magic: u32,
    pub num_items: u32,
    pub source_size: u32,
    pub hash_bits: u32,
    pub bucket_bits: u32,
    pub slot_bits: u32,
    /// `uint32_t slot_offsets[1 << slot_bits]`
    pub slot_offsets: Buf<u32>,
    /// `uint16_t heads[1 << bucket_bits]`
    pub heads: Buf<u16>,
    /// `uint32_t items[num_items]`
    pub items: Buf<u32>,
    /// Client-owned source data (`source_size` bytes).
    source: *const u8,
}

impl PreparedDictionary {
    /// Dictionary source bytes.
    #[inline]
    pub fn source(&self) -> &[u8] {
        if self.source_size == 0 || self.source.is_null() {
            &[]
        } else {
            // SAFETY: the C API contract requires the client to keep the
            // dictionary data alive while the prepared dictionary is used.
            unsafe { core::slice::from_raw_parts(self.source, self.source_size as usize) }
        }
    }
    /// `PreparedDictionaryView::hash_shift` == `64 - bucket_bits`.
    #[inline]
    pub fn hash_shift(&self) -> u32 {
        64 - self.bucket_bits
    }
    /// `PreparedDictionaryView::slot_mask`.
    #[inline]
    pub fn slot_mask(&self) -> u32 {
        (!0u32) >> (32 - self.slot_bits)
    }
    /// `PreparedDictionaryView::hash_mask`.
    #[inline]
    pub fn hash_mask(&self) -> u64 {
        (!0u64) >> (64 - self.hash_bits)
    }
}

fn create_prepared_dictionary_with_params(
    m: &MemoryManager,
    source: &[u8],
    bucket_bits: u32,
    slot_bits: u32,
    hash_bits: u32,
    bucket_limit: u16,
) -> Option<PreparedDictionary> {
    let source_size = source.len();
    // Step 1: create "bloated" hasher.
    let num_slots: u32 = 1u32 << slot_bits;
    let num_buckets: u32 = 1u32 << bucket_bits;
    let hash_shift: u32 = 64 - bucket_bits;
    let hash_mask: u64 = (!0u64) >> (64 - hash_bits);
    let slot_mask: u32 = num_slots - 1;
    let mut total_items: u32 = 0;

    if slot_bits > 16 {
        return None;
    }
    if slot_bits > bucket_bits {
        return None;
    }
    if bucket_bits - slot_bits >= 16 {
        return None;
    }

    let mut slot_size: Buf<u32> = Buf::new(m, num_slots as usize);
    let mut slot_limit: Buf<u32> = Buf::new(m, num_slots as usize);
    let mut num: Buf<u16> = Buf::new(m, num_buckets as usize);
    let mut bucket_heads: Buf<u32> = Buf::new(m, num_buckets as usize);
    let mut next_bucket: Buf<u32> = Buf::new(m, source_size);

    // TODO(eustas): apply custom "store" order.
    let mut i: usize = 0;
    while i + 7 < source_size {
        let v = u64::from_le_bytes(source[i..i + 8].try_into().unwrap());
        let h: u64 = (v & hash_mask).wrapping_mul(K_PREPARED_DICTIONARY_HASH_MUL64_LONG);
        let key = (h >> hash_shift) as u32 as usize;
        let mut count: u16 = num[key];
        next_bucket[i] = if count == 0 { u32::MAX } else { bucket_heads[key] };
        bucket_heads[key] = i as u32;
        count += 1;
        if count > bucket_limit {
            count = bucket_limit;
        }
        num[key] = count;
        i += 1;
    }

    // Step 2: find slot limits.
    for i in 0..num_slots as usize {
        let mut overflow;
        slot_limit[i] = bucket_limit as u32;
        loop {
            let limit = slot_limit[i];
            let mut count: u32 = 0;
            overflow = false;
            let mut j = i;
            while j < num_buckets as usize {
                let mut size = num[j] as u32;
                // Last chain may span behind 64K limit; overflow happens only
                // if we are about to use 0xFFFF+ as item offset.
                if count >= 0xFFFF {
                    overflow = true;
                    break;
                }
                if size > limit {
                    size = limit;
                }
                count += size;
                j += num_slots as usize;
            }
            if !overflow {
                slot_size[i] = count;
                total_items += count;
                break;
            }
            slot_limit[i] -= 1;
        }
    }

    // Step 3: transfer data to "slim" hasher.
    let mut slot_offsets: Buf<u32> = Buf::new(m, num_slots as usize);
    let mut heads: Buf<u16> = Buf::new(m, num_buckets as usize);
    let mut items: Buf<u32> = Buf::new(m, total_items as usize);

    total_items = 0;
    for i in 0..num_slots as usize {
        slot_offsets[i] = total_items;
        total_items += slot_size[i];
        slot_size[i] = 0;
    }
    for i in 0..num_buckets as usize {
        let slot = (i as u32 & slot_mask) as usize;
        let mut count: u32 = num[i] as u32;
        if count > slot_limit[slot] {
            count = slot_limit[slot];
        }
        if count == 0 {
            heads[i] = 0xFFFF;
            continue;
        }
        let mut cursor: usize = slot_size[slot] as usize;
        heads[i] = cursor as u16;
        cursor += slot_offsets[slot] as usize;
        slot_size[slot] += count;
        let mut pos = bucket_heads[i];
        for _ in 0..count {
            items[cursor] = pos;
            cursor += 1;
            pos = next_bucket[pos as usize];
        }
        items[cursor - 1] |= 0x80000000;
    }

    Some(PreparedDictionary {
        magic: K_LEAN_PREPARED_DICTIONARY_MAGIC,
        num_items: total_items,
        source_size: source_size as u32,
        hash_bits,
        bucket_bits,
        slot_bits,
        slot_offsets,
        heads,
        items,
        source: source.as_ptr(),
    })
}

/// `CreatePreparedDictionary`.
///
/// The returned dictionary references `source`, which must outlive it.
pub fn create_prepared_dictionary(m: &MemoryManager, source: &[u8]) -> Option<PreparedDictionary> {
    let mut bucket_bits: u32 = 17;
    let mut slot_bits: u32 = 7;
    let hash_bits: u32 = 40;
    let bucket_limit: u16 = 32;
    let mut volume: usize = 16usize << bucket_bits;
    if source.len() > SHARED_BROTLI_MAX_RAW_DICT_SIZE {
        return None;
    }
    // Tune parameters to fit dictionary size.
    while volume < source.len() && bucket_bits < 22 {
        bucket_bits += 1;
        slot_bits += 1;
        volume <<= 1;
    }
    create_prepared_dictionary_with_params(m, source, bucket_bits, slot_bits, hash_bits, bucket_limit)
}

/// `CompoundDictionary`.
///
/// Chunks are client-owned prepared dictionaries; the C API contract
/// requires them to outlive the encoder they are attached to.
#[derive(Clone, Copy, Debug)]
pub struct CompoundDictionary {
    /// LZ77 prefix, compound dictionary
    pub num_chunks: usize,
    pub total_size: usize,
    /// Client instances.
    pub chunks: [Option<&'static PreparedDictionary>; SHARED_BROTLI_MAX_COMPOUND_DICTS + 1],
    pub chunk_offsets: [usize; SHARED_BROTLI_MAX_COMPOUND_DICTS + 1],
}

impl core::fmt::Debug for PreparedDictionary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedDictionary")
            .field("magic", &self.magic)
            .field("num_items", &self.num_items)
            .field("source_size", &self.source_size)
            .finish()
    }
}

impl Default for CompoundDictionary {
    fn default() -> Self {
        Self::new()
    }
}

impl CompoundDictionary {
    pub fn new() -> Self {
        CompoundDictionary {
            num_chunks: 0,
            total_size: 0,
            chunks: [None; SHARED_BROTLI_MAX_COMPOUND_DICTS + 1],
            chunk_offsets: [0; SHARED_BROTLI_MAX_COMPOUND_DICTS + 1],
        }
    }

    /// Chunk `i` (< `num_chunks`).
    #[inline]
    pub fn chunk(&self, i: usize) -> &'static PreparedDictionary {
        self.chunks[i].expect("compound dictionary chunk")
    }

    /// `chunk_source[i]`: source bytes of chunk `i`.
    #[inline]
    pub fn chunk_source(&self, i: usize) -> &'static [u8] {
        self.chunk(i).source()
    }

    /// `AttachPreparedDictionary`.
    ///
    /// # Safety
    /// `dictionary` must outlive every use of this compound dictionary.
    pub unsafe fn attach(&mut self, dictionary: &PreparedDictionary) -> bool {
        if self.num_chunks == SHARED_BROTLI_MAX_COMPOUND_DICTS {
            return false;
        }
        let length = dictionary.source_size as usize;
        if length > SHARED_BROTLI_MAX_RAW_DICT_SIZE - self.total_size {
            return false;
        }
        let index = self.num_chunks;
        self.total_size += length;
        // SAFETY: lifetime extended per the C API contract (see above).
        self.chunks[index] = Some(&*(dictionary as *const PreparedDictionary));
        self.chunk_offsets[index + 1] = self.total_size;
        self.num_chunks += 1;
        true
    }
}
