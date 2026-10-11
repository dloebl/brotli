//! Port of `c/enc/backward_references.h` / `backward_references.c` /
//! `backward_references_inc.h` / `backward_references_opt_inc.h`: function
//! to find backward reference copies.
//!
//! OWNER: worker "hashers".

use super::command::Command;
use super::hash::{
    lookup_compound_dictionary_match, lookup_compound_dictionary_match_opt, minimum_better_length,
    prefetch_compound_dictionary_match_opt, Hasher, HasherCommon, HasherImpl, HasherPrivate, HasherSearchResult,
    PreparedDictionaryProbe, PreparedDictionaryProbes, BROTLI_SCORE_BASE,
};
use super::params::{BrotliEncoderParams, K_IS_BASE64};
use super::quality::{literal_spree_length_for_sparse_search, HAVE_SIMD_HASHERS, MIN_QUALITY_FOR_EXTENSIVE_REFERENCE_SEARCH};
use crate::common::constants::{brotli_max_backward_limit, BROTLI_NUM_DISTANCE_SHORT_CODES, SHARED_BROTLI_MAX_COMPOUND_DICTS};
use crate::common::context::{brotli_context, ContextLut};

const K_BASE64_TRIGGER_LEN: usize = 8;

#[inline(always)]
fn is_base64_char(c: u8) -> bool {
    K_IS_BASE64[c as usize] != 0
}

/// `MatchTrigger`.
fn match_trigger(ringbuffer: &[u8], mask: usize, pos: usize) -> bool {
    let trigger = b";base64,";
    for i in 0..K_BASE64_TRIGGER_LEN {
        if ringbuffer[(pos + i) & mask] != trigger[i] {
            return false;
        }
    }
    true
}

/// `kBase64Trigger64` (";base64," little endian).
const K_BASE64_TRIGGER64: u64 = (0x2C343665u64 << 32) | 0x7361623Bu64;

/// `FindNextBase64Trigger`.
fn find_next_base64_trigger(ringbuffer: &[u8], mask: usize, mut pos: usize, end: usize) -> usize {
    while pos + K_BASE64_TRIGGER_LEN <= end {
        let ringbuffer_size = mask + 1;
        let pos_index = pos & mask;
        let contiguous_len = ringbuffer_size - pos_index;
        let max_scan_len = end - pos;
        let scan_len = if contiguous_len < max_scan_len { contiguous_len } else { max_scan_len };

        let found = ringbuffer[pos_index..pos_index + scan_len].iter().position(|&c| c == b';');
        if let Some(offset) = found {
            if offset + K_BASE64_TRIGGER_LEN <= scan_len {
                let p = pos_index + offset;
                if u64::from_le_bytes(ringbuffer[p..p + 8].try_into().unwrap()) == K_BASE64_TRIGGER64 {
                    return pos + offset;
                }
            } else if pos + offset + K_BASE64_TRIGGER_LEN <= end {
                if match_trigger(ringbuffer, mask, pos + offset) {
                    return pos + offset;
                }
            } else {
                return end;
            }
            pos += offset + 1;
        } else {
            pos += scan_len;
        }
    }
    end
}

/// `CompareRingbuffer`.
fn compare_ringbuffer(ringbuffer: &[u8], mask: usize, mut pos1: usize, mut pos2: usize, mut len: usize) -> bool {
    let idx1 = pos1 & mask;
    let idx2 = pos2 & mask;
    if idx1 + len <= mask + 1 && idx2 + len <= mask + 1 {
        return ringbuffer[idx1..idx1 + len] == ringbuffer[idx2..idx2 + len];
    }
    while len > 0 {
        let chunk1 = mask + 1 - (pos1 & mask);
        let chunk2 = mask + 1 - (pos2 & mask);
        let mut chunk = if chunk1 < chunk2 { chunk1 } else { chunk2 };
        if len < chunk {
            chunk = len;
        }
        let a = pos1 & mask;
        let b = pos2 & mask;
        if ringbuffer[a..a + chunk] != ringbuffer[b..b + chunk] {
            return false;
        }
        pos1 += chunk;
        pos2 += chunk;
        len -= chunk;
    }
    true
}

/// `ComputeDistanceCode`.
#[inline(always)]
fn compute_distance_code(distance: usize, max_distance: usize, dist_cache: &[i32]) -> usize {
    if distance <= max_distance {
        let distance_plus_3 = distance.wrapping_add(3);
        let offset0 = distance_plus_3.wrapping_sub(dist_cache[0] as usize);
        let offset1 = distance_plus_3.wrapping_sub(dist_cache[1] as usize);
        if distance == dist_cache[0] as usize {
            return 0;
        } else if distance == dist_cache[1] as usize {
            return 1;
        } else if offset0 < 7 {
            return (0x9750468 >> (4 * offset0)) & 0xF;
        } else if offset1 < 7 {
            return (0xFDB1ACE >> (4 * offset1)) & 0xF;
        } else if distance == dist_cache[2] as usize {
            return 2;
        } else if distance == dist_cache[3] as usize {
            return 3;
        }
    }
    distance.wrapping_add(BROTLI_NUM_DISTANCE_SHORT_CODES as usize - 1)
}

/// Minimum score to accept a backward reference.
const K_MIN_SCORE: usize = BROTLI_SCORE_BASE + 100;

#[inline(always)]
fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

#[inline(always)]
fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

/// `CreateBackwardReferences` of `backward_references_inc.h`, instantiated
/// for hasher `H` with `ENABLE_COMPOUND_DICTIONARY == COMPOUND`.
#[inline(never)]
fn create_backward_references<H: HasherImpl, const COMPOUND: bool>(
    num_bytes: usize,
    mut position: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    literal_context_lut: ContextLut,
    params: &BrotliEncoderParams,
    privat: &mut H,
    common: &mut HasherCommon,
    dist_cache: &mut [i32],
    last_insert_len: &mut usize,
    commands: &mut [Command],
    num_commands: &mut usize,
    num_literals: &mut usize,
) {
    // Set maximum distance, see section 9.1. of the spec.
    let max_backward_limit = brotli_max_backward_limit(params.lgwin as u32);
    let position_offset = params.stream_offset;

    let mut n_commands = 0usize;
    let mut insert_length = *last_insert_len;
    let pos_end = position + num_bytes;
    let store_end = if num_bytes >= H::STORE_LOOKAHEAD { position + num_bytes - H::STORE_LOOKAHEAD + 1 } else { position };

    // For speed up heuristics for random data.
    let random_heuristics_window_size = literal_spree_length_for_sparse_search(params);
    let mut apply_random_heuristics = position + random_heuristics_window_size;
    let gap = params.dictionary.compound.total_size;
    let contextual = &params.dictionary.contextual;

    privat.prepare_distance_cache(dist_cache);

    let mut next_base64_pos = pos_end;
    if params.base64_mode != 0 && common.num_base64_regions < params.max_base64_regions {
        next_base64_pos = find_next_base64_trigger(ringbuffer, ringbuffer_mask, position, pos_end);
    }
    'main: while position + H::HASH_TYPE_LENGTH < pos_end {
        'skip_base64_trigger: {
            if position >= next_base64_pos {
                if position > next_base64_pos {
                    // A previous backward match jumped over the trigger
                    // position.  Find the next trigger from the current
                    // position safely checking pos_end.
                    next_base64_pos = find_next_base64_trigger(ringbuffer, ringbuffer_mask, position, pos_end);
                    if position < next_base64_pos {
                        break 'skip_base64_trigger;
                    }
                }
                // Find where it ends
                let mut scan_pos = position + K_BASE64_TRIGGER_LEN;
                let mut first_equal_pos = 0usize;
                while scan_pos < pos_end {
                    let c = ringbuffer[scan_pos & ringbuffer_mask];
                    if is_base64_char(c) {
                        if first_equal_pos != 0 {
                            scan_pos = first_equal_pos;
                            break;
                        }
                        scan_pos += 1;
                    } else if c == b'=' {
                        if first_equal_pos == 0 {
                            first_equal_pos = scan_pos;
                        }
                        scan_pos += 1;
                    } else {
                        break;
                    }
                }
                // Jump directly to the end of base64 block
                let start_pos = position + K_BASE64_TRIGGER_LEN;
                let mut length = scan_pos - start_pos;
                // Exclude '=' characters from the flat 6-bit entropy block
                while length > 0 && ringbuffer[(start_pos + length - 1) & ringbuffer_mask] == b'=' {
                    length -= 1;
                }
                let mut is_dupe = false;
                let copy_len = scan_pos - position;
                let mut dupe_dist = 0usize;
                let mut matched_region_idx = 0usize;
                if length > 0 && common.num_base64_regions > 0 {
                    let mut r = common.num_base64_regions;
                    while r > 0 {
                        r -= 1;
                        let prev_start = common.base64_regions[r].start_literal_pos;
                        let prev_length = common.base64_regions[r].length;
                        if prev_length != length {
                            continue;
                        }
                        let prev_pos = prev_start.wrapping_sub(K_BASE64_TRIGGER_LEN);
                        let distance = position.wrapping_sub(prev_pos);
                        if distance == 0 || distance > max_backward_limit {
                            continue;
                        }
                        if compare_ringbuffer(ringbuffer, ringbuffer_mask, prev_pos, position, copy_len) {
                            is_dupe = true;
                            dupe_dist = distance;
                            matched_region_idx = r;
                            break;
                        }
                    }
                }
                if is_dupe {
                    let dictionary_start = min(position + position_offset, max_backward_limit);
                    let distance_code = compute_distance_code(dupe_dist, dictionary_start + gap, dist_cache);
                    if dupe_dist <= dictionary_start + gap && distance_code > 0 {
                        dist_cache[3] = dist_cache[2];
                        dist_cache[2] = dist_cache[1];
                        dist_cache[1] = dist_cache[0];
                        dist_cache[0] = dupe_dist as i32;
                        privat.prepare_distance_cache(dist_cache);
                    }
                    commands[n_commands] = Command::new(&params.dist, insert_length, copy_len, 0, distance_code);
                    n_commands += 1;
                    *num_literals += insert_length;
                    insert_length = 0;
                    position = scan_pos;
                    // NB: the matched region must keep describing its own
                    // literals: the duplicate is emitted as a copy (no
                    // literals).  The C library used to move the region into
                    // the copy, which mapped it onto the following
                    // (non-base64) literals and produced invalid streams
                    // (fixed in c/enc/backward_references_inc.h as well).
                    let _ = matched_region_idx;
                    apply_random_heuristics = position + 2 * copy_len + random_heuristics_window_size;
                    if common.num_base64_regions < params.max_base64_regions {
                        next_base64_pos = find_next_base64_trigger(ringbuffer, ringbuffer_mask, position, pos_end);
                    } else {
                        next_base64_pos = pos_end;
                    }
                    continue 'main;
                }
                if length >= params.min_base64_region_len && length > 0 {
                    let idx = common.num_base64_regions;
                    common.base64_regions[idx].start_literal_pos = start_pos;
                    common.base64_regions[idx].length = length;
                    common.num_base64_regions += 1;
                    insert_length += scan_pos - position;
                    position = scan_pos;
                    if common.num_base64_regions < params.max_base64_regions {
                        next_base64_pos = find_next_base64_trigger(ringbuffer, ringbuffer_mask, position, pos_end);
                    } else {
                        next_base64_pos = pos_end;
                    }
                    continue 'main;
                } else {
                    next_base64_pos = find_next_base64_trigger(ringbuffer, ringbuffer_mask, position + 1, pos_end);
                    break 'skip_base64_trigger;
                }
            }
        }
        let mut max_length = pos_end - position;
        let mut max_distance = min(position, max_backward_limit);
        let mut dictionary_start = min(position + position_offset, max_backward_limit);
        let mut dict_id = 0usize;
        let mut p1 = 0u8;
        if contextual.context_based {
            p1 = if position >= 1 { ringbuffer[(position - 1) & ringbuffer_mask] } else { 0 };
            let p2 = if position >= 2 { ringbuffer[(position - 2) & ringbuffer_mask] } else { 0 };
            dict_id = contextual.context_map[brotli_context(p1, p2, literal_context_lut) as usize] as usize;
        }
        let mut sr = HasherSearchResult { len: 0, len_code_delta: 0, distance: 0, score: K_MIN_SCORE };
        privat.find_longest_match(
            common,
            contextual.dict[dict_id],
            ringbuffer,
            ringbuffer_mask,
            dist_cache,
            position,
            max_length,
            max_distance,
            dictionary_start + gap,
            params.dist.max_distance,
            &mut sr,
        );
        if COMPOUND {
            lookup_compound_dictionary_match(
                &params.dictionary.compound,
                ringbuffer,
                ringbuffer_mask,
                dist_cache,
                position,
                max_length,
                dictionary_start,
                params.dist.max_distance,
                &mut sr,
            );
        }
        if sr.score > K_MIN_SCORE {
            // Found a match. Let's look for something even better ahead.
            let mut delayed_backward_references_in_row = 0;
            max_length -= 1;
            loop {
                let cost_diff_lazy: usize = 175;
                let mut sr2 = HasherSearchResult {
                    len: if params.quality < MIN_QUALITY_FOR_EXTENSIVE_REFERENCE_SEARCH {
                        min(sr.len.wrapping_sub(1), max_length)
                    } else {
                        0
                    },
                    len_code_delta: 0,
                    distance: 0,
                    score: K_MIN_SCORE,
                };
                max_distance = min(position + 1, max_backward_limit);
                dictionary_start = min(position + 1 + position_offset, max_backward_limit);
                if contextual.context_based {
                    let p2 = p1;
                    p1 = ringbuffer[position & ringbuffer_mask];
                    dict_id = contextual.context_map[brotli_context(p1, p2, literal_context_lut) as usize] as usize;
                }
                privat.find_longest_match(
                    common,
                    contextual.dict[dict_id],
                    ringbuffer,
                    ringbuffer_mask,
                    dist_cache,
                    position + 1,
                    max_length,
                    max_distance,
                    dictionary_start + gap,
                    params.dist.max_distance,
                    &mut sr2,
                );
                if COMPOUND {
                    lookup_compound_dictionary_match(
                        &params.dictionary.compound,
                        ringbuffer,
                        ringbuffer_mask,
                        dist_cache,
                        position + 1,
                        max_length,
                        dictionary_start,
                        params.dist.max_distance,
                        &mut sr2,
                    );
                }
                if sr2.score >= sr.score + cost_diff_lazy {
                    // Ok, let's just write one byte for now and start a match
                    // from the next byte.
                    position += 1;
                    insert_length += 1;
                    sr = sr2;
                    delayed_backward_references_in_row += 1;
                    if delayed_backward_references_in_row < 4 && position + H::HASH_TYPE_LENGTH < pos_end {
                        max_length -= 1;
                        continue;
                    }
                }
                break;
            }
            apply_random_heuristics = position + 2 * sr.len + random_heuristics_window_size;
            dictionary_start = min(position + position_offset, max_backward_limit);
            {
                // The first 16 codes are special short-codes,
                // and the minimum offset is 1.
                let distance_code = compute_distance_code(sr.distance, dictionary_start + gap, dist_cache);
                if sr.distance <= dictionary_start + gap && distance_code > 0 {
                    dist_cache[3] = dist_cache[2];
                    dist_cache[2] = dist_cache[1];
                    dist_cache[1] = dist_cache[0];
                    dist_cache[0] = sr.distance as i32;
                    privat.prepare_distance_cache(dist_cache);
                }
                commands[n_commands] = Command::new(&params.dist, insert_length, sr.len, sr.len_code_delta, distance_code);
                n_commands += 1;
            }
            *num_literals += insert_length;
            insert_length = 0;
            // Put the hash keys into the table, if there are enough bytes
            // left.  Depending on the hasher implementation, it can push all
            // positions in the given range or only a subset of them.
            // Avoid hash poisoning with RLE data.
            {
                let mut range_start = position + 2;
                let range_end = min(position + sr.len, store_end);
                if sr.distance < (sr.len >> 2) {
                    range_start =
                        min(range_end, max(range_start, (position + sr.len).wrapping_sub(sr.distance << 2)));
                }
                privat.store_range(ringbuffer, ringbuffer_mask, range_start, range_end);
            }
            position += sr.len;
        } else {
            insert_length += 1;
            position += 1;
            // If we have not seen matches for a long time, we can skip some
            // match lookups. Unsuccessful match lookups are very very
            // expensive and this kind of a heuristic speeds up compression
            // quite a lot.
            if position > apply_random_heuristics {
                // Going through uncompressible data, jump.
                if position > apply_random_heuristics + 4 * random_heuristics_window_size {
                    // It is quite a long time since we saw a copy, so we
                    // assume that this data is not compressible, and store
                    // hashes less often. Hashes of non compressible data are
                    // less likely to turn out to be useful in the future,
                    // too, so we store less of them to not to flood out the
                    // hash table of good compressible data.
                    let k_margin = max(H::STORE_LOOKAHEAD - 1, 4);
                    let pos_jump = min(position + 16, pos_end - k_margin);
                    while position < pos_jump {
                        privat.store(ringbuffer, ringbuffer_mask, position);
                        insert_length += 4;
                        position += 4;
                    }
                } else {
                    let k_margin = max(H::STORE_LOOKAHEAD - 1, 2);
                    let pos_jump = min(position + 8, pos_end - k_margin);
                    while position < pos_jump {
                        privat.store(ringbuffer, ringbuffer_mask, position);
                        insert_length += 2;
                        position += 2;
                    }
                }
            }
        }
    }
    // NB: `position` may exceed `pos_end` here (by up to 7): when a copy
    // jumps over a found `;base64,` trigger, the next iteration treats the
    // current position as the trigger and skips 8 bytes.  C relies on
    // `size_t` wrap-around to net the insert length out; do the same.
    insert_length = insert_length.wrapping_add(pos_end.wrapping_sub(position));
    *last_insert_len = insert_length;
    *num_commands += n_commands;
}

/// `CreateBackwardReferences` of `backward_references_opt_inc.h` (used for
/// H59), with `ENABLE_COMPOUND_DICTIONARY == COMPOUND`.
#[inline(never)]
fn create_backward_references_opt<H: HasherImpl, const COMPOUND: bool>(
    num_bytes: usize,
    mut position: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    literal_context_lut: ContextLut,
    params: &BrotliEncoderParams,
    privat: &mut H,
    common: &mut HasherCommon,
    dist_cache: &mut [i32],
    last_insert_len: &mut usize,
    commands: &mut [Command],
    num_commands: &mut usize,
    num_literals: &mut usize,
) {
    // Set maximum distance, see section 9.1. of the spec.
    let max_backward_limit = brotli_max_backward_limit(params.lgwin as u32);
    let position_offset = params.stream_offset;

    let mut n_commands = 0usize;
    let mut insert_length = *last_insert_len;
    let pos_end = position + num_bytes;
    let store_end = if num_bytes >= H::STORE_LOOKAHEAD { position + num_bytes - H::STORE_LOOKAHEAD + 1 } else { position };

    // For speed up heuristics for random data.
    let random_heuristics_window_size = literal_spree_length_for_sparse_search(params);
    let mut apply_random_heuristics = position + random_heuristics_window_size;
    let gap = params.dictionary.compound.total_size;
    let contextual = &params.dictionary.contextual;
    // Compound-dictionary probe state: written by the prefetch helper before
    // each FindLongestMatch, consumed by the lookup after it.
    let mut dict_probes: PreparedDictionaryProbes = [PreparedDictionaryProbe::default(); SHARED_BROTLI_MAX_COMPOUND_DICTS + 1];

    privat.prepare_distance_cache(dist_cache);

    let mut next_base64_pos = pos_end;
    if params.base64_mode != 0 && common.num_base64_regions < params.max_base64_regions {
        next_base64_pos = find_next_base64_trigger(ringbuffer, ringbuffer_mask, position, pos_end);
    }
    while position + H::HASH_TYPE_LENGTH < pos_end {
        if position >= next_base64_pos {
            // Find where it ends
            let mut scan_pos = position + K_BASE64_TRIGGER_LEN;
            let mut first_equal_pos = 0usize;
            while scan_pos < pos_end {
                let c = ringbuffer[scan_pos & ringbuffer_mask];
                if is_base64_char(c) {
                    if first_equal_pos != 0 {
                        scan_pos = first_equal_pos;
                        break;
                    }
                    scan_pos += 1;
                } else if c == b'=' {
                    if first_equal_pos == 0 {
                        first_equal_pos = scan_pos;
                    }
                    scan_pos += 1;
                } else {
                    break;
                }
            }
            // Jump directly to the end of base64 block
            // Skip the ';base64,' trigger
            let start_pos = position + K_BASE64_TRIGGER_LEN;
            let mut length = scan_pos - start_pos;
            // Exclude '=' characters from the flat 6-bit entropy block
            while length > 0 && ringbuffer[(start_pos + length - 1) & ringbuffer_mask] == b'=' {
                length -= 1;
            }
            if length > 0 {
                let idx = common.num_base64_regions;
                common.base64_regions[idx].start_literal_pos = start_pos;
                common.base64_regions[idx].length = length;
                common.num_base64_regions += 1;
            }
            insert_length += scan_pos - position;
            position = scan_pos;
            if common.num_base64_regions < params.max_base64_regions {
                next_base64_pos = find_next_base64_trigger(ringbuffer, ringbuffer_mask, position, pos_end);
            } else {
                next_base64_pos = pos_end;
            }
            continue;
        }
        let mut max_length = pos_end - position;
        let mut max_distance = min(position, max_backward_limit);
        let mut dictionary_start = min(position + position_offset, max_backward_limit);
        let mut dict_id = 0usize;
        let mut p1 = 0u8;
        if contextual.context_based {
            p1 = if position >= 1 { ringbuffer[(position - 1) & ringbuffer_mask] } else { 0 };
            let p2 = if position >= 2 { ringbuffer[(position - 2) & ringbuffer_mask] } else { 0 };
            dict_id = contextual.context_map[brotli_context(p1, p2, literal_context_lut) as usize] as usize;
        }
        let mut sr = HasherSearchResult { len: 0, len_code_delta: 0, distance: 0, score: K_MIN_SCORE };
        if COMPOUND {
            prefetch_compound_dictionary_match_opt(
                &params.dictionary.compound,
                ringbuffer,
                ringbuffer_mask,
                position,
                &mut dict_probes,
            );
        }
        privat.find_longest_match(
            common,
            contextual.dict[dict_id],
            ringbuffer,
            ringbuffer_mask,
            dist_cache,
            position,
            max_length,
            max_distance,
            dictionary_start + gap,
            params.dist.max_distance,
            &mut sr,
        );
        if COMPOUND {
            lookup_compound_dictionary_match_opt(
                &params.dictionary.compound,
                &dict_probes,
                ringbuffer,
                ringbuffer_mask,
                dist_cache,
                position,
                max_length,
                dictionary_start,
                params.dist.max_distance,
                &mut sr,
            );
        }
        if sr.score > K_MIN_SCORE {
            // Found a match. Let's look for something even better ahead.
            let mut delayed_backward_references_in_row = 0;
            max_length -= 1;
            loop {
                let cost_diff_lazy: usize = 175;
                let mut sr2 = HasherSearchResult {
                    len: if params.quality < MIN_QUALITY_FOR_EXTENSIVE_REFERENCE_SEARCH {
                        min(sr.len.wrapping_sub(1), max_length)
                    } else {
                        min(minimum_better_length(sr.score + cost_diff_lazy - 1), max_length)
                    },
                    len_code_delta: 0,
                    distance: 0,
                    score: K_MIN_SCORE,
                };
                max_distance = min(position + 1, max_backward_limit);
                dictionary_start = min(position + 1 + position_offset, max_backward_limit);
                if contextual.context_based {
                    let p2 = p1;
                    p1 = ringbuffer[position & ringbuffer_mask];
                    dict_id = contextual.context_map[brotli_context(p1, p2, literal_context_lut) as usize] as usize;
                }
                if COMPOUND {
                    prefetch_compound_dictionary_match_opt(
                        &params.dictionary.compound,
                        ringbuffer,
                        ringbuffer_mask,
                        position + 1,
                        &mut dict_probes,
                    );
                }
                privat.find_longest_match(
                    common,
                    contextual.dict[dict_id],
                    ringbuffer,
                    ringbuffer_mask,
                    dist_cache,
                    position + 1,
                    max_length,
                    max_distance,
                    dictionary_start + gap,
                    params.dist.max_distance,
                    &mut sr2,
                );
                if COMPOUND {
                    lookup_compound_dictionary_match_opt(
                        &params.dictionary.compound,
                        &dict_probes,
                        ringbuffer,
                        ringbuffer_mask,
                        dist_cache,
                        position + 1,
                        max_length,
                        dictionary_start,
                        params.dist.max_distance,
                        &mut sr2,
                    );
                }
                if sr2.score >= sr.score + cost_diff_lazy {
                    // Ok, let's just write one byte for now and start a match
                    // from the next byte.
                    position += 1;
                    insert_length += 1;
                    sr = sr2;
                    delayed_backward_references_in_row += 1;
                    if delayed_backward_references_in_row < 4 && position + H::HASH_TYPE_LENGTH < pos_end {
                        max_length -= 1;
                        continue;
                    }
                }
                break;
            }
            apply_random_heuristics = position + 2 * sr.len + random_heuristics_window_size;
            dictionary_start = min(position + position_offset, max_backward_limit);
            {
                // The first 16 codes are special short-codes,
                // and the minimum offset is 1.
                let distance_code = compute_distance_code(sr.distance, dictionary_start + gap, dist_cache);
                if sr.distance <= dictionary_start + gap && distance_code > 0 {
                    dist_cache[3] = dist_cache[2];
                    dist_cache[2] = dist_cache[1];
                    dist_cache[1] = dist_cache[0];
                    dist_cache[0] = sr.distance as i32;
                    privat.prepare_distance_cache(dist_cache);
                }
                commands[n_commands] = Command::new(&params.dist, insert_length, sr.len, sr.len_code_delta, distance_code);
                n_commands += 1;
            }
            *num_literals += insert_length;
            insert_length = 0;
            // Put the hash keys into the table, if there are enough bytes
            // left.  Depending on the hasher implementation, it can push all
            // positions in the given range or only a subset of them.
            // Avoid hash poisoning with RLE data.
            {
                let mut range_start = position + 2;
                let range_end = min(position + sr.len, store_end);
                if sr.distance < (sr.len >> 2) {
                    range_start =
                        min(range_end, max(range_start, (position + sr.len).wrapping_sub(sr.distance << 2)));
                }
                // (The C code prefetches the compound dictionary heads[]
                // line of the next search position here.)
                privat.store_range(ringbuffer, ringbuffer_mask, range_start, range_end);
            }
            position += sr.len;
        } else {
            insert_length += 1;
            position += 1;
            // If we have not seen matches for a long time, we can skip some
            // match lookups. Unsuccessful match lookups are very very
            // expensive and this kind of a heuristic speeds up compression
            // quite a lot.
            if position > apply_random_heuristics {
                // Going through uncompressible data, jump.
                if position > apply_random_heuristics + 4 * random_heuristics_window_size {
                    // It is quite a long time since we saw a copy, so we
                    // assume that this data is not compressible, and store
                    // hashes less often. Hashes of non compressible data are
                    // less likely to turn out to be useful in the future,
                    // too, so we store less of them to not to flood out the
                    // hash table of good compressible data.
                    let k_margin = max(H::STORE_LOOKAHEAD - 1, 4);
                    let pos_jump = min(position + 16, pos_end - k_margin);
                    while position < pos_jump {
                        privat.store(ringbuffer, ringbuffer_mask, position);
                        insert_length += 4;
                        position += 4;
                    }
                } else {
                    let k_margin = max(H::STORE_LOOKAHEAD - 1, 2);
                    let pos_jump = min(position + 8, pos_end - k_margin);
                    while position < pos_jump {
                        privat.store(ringbuffer, ringbuffer_mask, position);
                        insert_length += 2;
                        position += 2;
                    }
                }
            }
        }
    }
    // NB: `position` may exceed `pos_end` here (by up to 7): when a copy
    // jumps over a found `;base64,` trigger, the next iteration treats the
    // current position as the trigger and skips 8 bytes.  C relies on
    // `size_t` wrap-around to net the insert length out; do the same.
    insert_length = insert_length.wrapping_add(pos_end.wrapping_sub(position));
    *last_insert_len = insert_length;
    *num_commands += n_commands;
}

/// `BrotliCreateBackwardReferences`.
///
/// `ringbuffer` is the ring buffer (`buffer_`), `dist_cache` has 16 entries
/// (only the first 4 are state; the rest is scratch for
/// `PrepareDistanceCache`).  New commands are written to `commands[0..]`
/// and `*num_commands` is incremented by their number (like C, where
/// `commands` points to `&commands_[num_commands_]`).
pub fn brotli_create_backward_references(
    num_bytes: usize,
    position: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    literal_context_lut: ContextLut,
    params: &BrotliEncoderParams,
    hasher: &mut Hasher,
    dist_cache: &mut [i32],
    last_insert_len: &mut usize,
    commands: &mut [Command],
    num_commands: &mut usize,
    num_literals: &mut usize,
) {
    let Hasher { common, privat } = hasher;
    macro_rules! call {
        ($f:ident, $h:expr, $compound:expr) => {
            $f::<_, { $compound }>(
                num_bytes,
                position,
                ringbuffer,
                ringbuffer_mask,
                literal_context_lut,
                params,
                $h,
                common,
                dist_cache,
                last_insert_len,
                commands,
                num_commands,
                num_literals,
            )
        };
    }
    let t = params.hasher.type_;
    if params.dictionary.compound.num_chunks != 0 {
        match privat {
            HasherPrivate::H3(h) if t == 3 => return call!(create_backward_references, h, true),
            HasherPrivate::H4(h) if t == 4 => return call!(create_backward_references, h, true),
            HasherPrivate::H5(h) if t == 5 => return call!(create_backward_references, h, true),
            HasherPrivate::H6(h) if t == 6 => return call!(create_backward_references, h, true),
            HasherPrivate::H58(h) if t == 58 && HAVE_SIMD_HASHERS => {
                return call!(create_backward_references, h, true)
            }
            HasherPrivate::H59(h) if t == 59 && HAVE_SIMD_HASHERS => {
                return call!(create_backward_references_opt, h, true)
            }
            HasherPrivate::H68(h) if t == 68 && HAVE_SIMD_HASHERS => {
                return call!(create_backward_references, h, true)
            }
            HasherPrivate::H40(h) if t == 40 => return call!(create_backward_references, h, true),
            HasherPrivate::H41(h) if t == 41 => return call!(create_backward_references, h, true),
            HasherPrivate::H42(h) if t == 42 => return call!(create_backward_references, h, true),
            HasherPrivate::H55(h) if t == 55 => return call!(create_backward_references, h, true),
            HasherPrivate::H65(h) if t == 65 => return call!(create_backward_references, h, true),
            // C: BROTLI_DCHECK(BROTLI_FALSE) and fall through to the
            // non-compound variants (H2, H35, H54 have none).
            _ => {}
        }
    }

    match privat {
        HasherPrivate::H2(h) if t == 2 => call!(create_backward_references, h, false),
        HasherPrivate::H3(h) if t == 3 => call!(create_backward_references, h, false),
        HasherPrivate::H4(h) if t == 4 => call!(create_backward_references, h, false),
        HasherPrivate::H5(h) if t == 5 => call!(create_backward_references, h, false),
        HasherPrivate::H6(h) if t == 6 => call!(create_backward_references, h, false),
        HasherPrivate::H40(h) if t == 40 => call!(create_backward_references, h, false),
        HasherPrivate::H41(h) if t == 41 => call!(create_backward_references, h, false),
        HasherPrivate::H42(h) if t == 42 => call!(create_backward_references, h, false),
        HasherPrivate::H54(h) if t == 54 => call!(create_backward_references, h, false),
        HasherPrivate::H58(h) if t == 58 && HAVE_SIMD_HASHERS => call!(create_backward_references, h, false),
        HasherPrivate::H59(h) if t == 59 && HAVE_SIMD_HASHERS => call!(create_backward_references_opt, h, false),
        HasherPrivate::H68(h) if t == 68 && HAVE_SIMD_HASHERS => call!(create_backward_references, h, false),
        HasherPrivate::H35(h) if t == 35 => call!(create_backward_references, h, false),
        HasherPrivate::H55(h) if t == 55 => call!(create_backward_references, h, false),
        HasherPrivate::H65(h) if t == 65 => call!(create_backward_references, h, false),
        // C: BROTLI_DCHECK(BROTLI_FALSE).
        _ => {}
    }
}
