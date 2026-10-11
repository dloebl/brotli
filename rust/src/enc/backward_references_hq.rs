//! Port of `c/enc/backward_references_hq.h` / `backward_references_hq.c`:
//! Zopfli-style backward references (qualities 10 and 11).
//!
//! OWNER: worker "hashers".

use super::command::{combine_length_codes, get_copy_extra, get_copy_length_code, get_insert_extra, get_insert_length_code, Command};
use super::fast_log::fast_log2;
use super::hash::{
    find_match_length, lookup_all_compound_dictionary_matches, BackwardMatch, Hasher, HasherCore, HasherPrivate,
    MAX_NUM_MATCHES_H10, H10,
};
use super::literal_cost::brotli_estimate_bit_costs_for_literals;
use super::memory::{Boxed, Buf, MemoryManager};
use super::params::{BrotliDistanceParams, BrotliEncoderParams};
use super::prefix::prefix_encode_copy_distance;
use super::quality::{
    max_zopfli_candidates, max_zopfli_len, BROTLI_LONG_COPY_QUICK_STEP, MAX_ZOPFLI_LEN_QUALITY_11,
};
use crate::common::constants::{
    brotli_max_backward_limit, BROTLI_NUM_COMMAND_SYMBOLS, BROTLI_NUM_DISTANCE_SHORT_CODES, BROTLI_NUM_LITERAL_SYMBOLS,
    BROTLI_UINT32_MAX,
};
use crate::common::context::{brotli_context, ContextLut};

/// BrotliCalculateDistanceCodeLimit(BROTLI_MAX_ALLOWED_DISTANCE, 3, 120).
const BROTLI_MAX_EFFECTIVE_DISTANCE_ALPHABET_SIZE: usize = 544;

/// ~= 2 ^ 127
const K_INFINITY: f32 = 1.7e38f32;

static K_DISTANCE_CACHE_INDEX: [u32; 16] = [0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1];
static K_DISTANCE_CACHE_OFFSET: [i32; 16] = [0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3];

/// `ZopfliNode`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZopfliNode {
    /// Best length to get up to this byte (not including this byte itself)
    /// highest 7 bit is used to reconstruct the length code.
    pub length: u32,
    /// Distance associated with the length.
    pub distance: u32,
    /// Number of literal inserts before this copy; highest 5 bits contain
    /// distance short code + 1 (or zero if no short code).
    pub dcode_insert_length: u32,
    /// This union holds information used by dynamic-programming. During
    /// forward pass |cost| it used to store the goal function. When node is
    /// processed its |cost| is invalidated in favor of |shortcut|. On path
    /// back-tracing pass |next| is assigned the offset to next node on the
    /// path.  (C: `union { float cost; uint32_t next; uint32_t shortcut; }`,
    /// stored as raw bits.)
    pub u: u32,
}

impl ZopfliNode {
    /// `u.cost`: smallest cost to get to this byte from the beginning, as
    /// found so far.
    #[inline(always)]
    pub fn cost(&self) -> f32 {
        f32::from_bits(self.u)
    }
    #[inline(always)]
    pub fn set_cost(&mut self, cost: f32) {
        self.u = cost.to_bits();
    }
    /// `u.next`: offset to the next node on the path. Equals to
    /// command_length() of the next node on the path. For last node equals
    /// to BROTLI_UINT32_MAX.
    #[inline(always)]
    pub fn next(&self) -> u32 {
        self.u
    }
    /// `u.shortcut`: node position that provides next distance for distance
    /// cache.
    #[inline(always)]
    pub fn shortcut(&self) -> u32 {
        self.u
    }

    /// `ZopfliNodeCopyLength`.
    #[inline(always)]
    fn copy_length(&self) -> u32 {
        self.length & 0x1FFFFFF
    }

    /// `ZopfliNodeLengthCode`.
    #[inline(always)]
    fn length_code(&self) -> u32 {
        let modifier = self.length >> 25;
        self.copy_length().wrapping_add(9).wrapping_sub(modifier)
    }

    /// `ZopfliNodeCopyDistance`.
    #[inline(always)]
    fn copy_distance(&self) -> u32 {
        self.distance
    }

    /// `ZopfliNodeDistanceCode`.
    #[inline(always)]
    fn distance_code(&self) -> u32 {
        let short_code = self.dcode_insert_length >> 27;
        if short_code == 0 {
            self.copy_distance().wrapping_add(BROTLI_NUM_DISTANCE_SHORT_CODES - 1)
        } else {
            short_code - 1
        }
    }

    /// `ZopfliNodeCommandLength`.
    #[inline(always)]
    fn command_length(&self) -> u32 {
        self.copy_length().wrapping_add(self.dcode_insert_length & 0x7FFFFFF)
    }
}

/// `BrotliInitZopfliNodes`.
pub fn brotli_init_zopfli_nodes(array: &mut [ZopfliNode]) {
    let stub = ZopfliNode { length: 1, distance: 0, dcode_insert_length: 0, u: K_INFINITY.to_bits() };
    for n in array.iter_mut() {
        *n = stub;
    }
}

/// Temporary data for ZopfliCostModelSetFromCommands.
struct ZopfliCostModelArena {
    histogram_literal: [u32; BROTLI_NUM_LITERAL_SYMBOLS],
    histogram_cmd: [u32; BROTLI_NUM_COMMAND_SYMBOLS],
    histogram_dist: [u32; BROTLI_MAX_EFFECTIVE_DISTANCE_ALPHABET_SIZE],
    cost_literal: [f32; BROTLI_NUM_LITERAL_SYMBOLS],
}

/// Histogram based cost model for zopflification.
struct ZopfliCostModel {
    /// The insert and copy length symbols.
    cost_cmd: [f32; BROTLI_NUM_COMMAND_SYMBOLS],
    cost_dist: Buf<f32>,
    distance_histogram_size: u32,
    /// Cumulative costs of literals per position in the stream.
    literal_costs: Buf<f32>,
    min_cost_cmd: f32,
    num_bytes: usize,
    // Temporary data (a union in C).
    literal_histograms: [usize; 3 * 256],
    arena: ZopfliCostModelArena,
}

impl ZopfliCostModel {
    /// `BROTLI_ALLOC(m, ZopfliCostModel, 1)` (uninitialized in C; every
    /// field is written before it is read).
    fn alloc(m: &MemoryManager) -> Boxed<ZopfliCostModel> {
        Boxed::new(
            m,
            ZopfliCostModel {
                cost_cmd: [0.0; BROTLI_NUM_COMMAND_SYMBOLS],
                cost_dist: Buf::empty(),
                distance_histogram_size: 0,
                literal_costs: Buf::empty(),
                min_cost_cmd: 0.0,
                num_bytes: 0,
                literal_histograms: [0; 3 * 256],
                arena: ZopfliCostModelArena {
                    histogram_literal: [0; BROTLI_NUM_LITERAL_SYMBOLS],
                    histogram_cmd: [0; BROTLI_NUM_COMMAND_SYMBOLS],
                    histogram_dist: [0; BROTLI_MAX_EFFECTIVE_DISTANCE_ALPHABET_SIZE],
                    cost_literal: [0.0; BROTLI_NUM_LITERAL_SYMBOLS],
                },
            },
        )
    }

    /// `InitZopfliCostModel`.
    fn init(&mut self, m: &MemoryManager, dist: &BrotliDistanceParams, num_bytes: usize) {
        self.num_bytes = num_bytes;
        self.literal_costs = Buf::new(m, num_bytes + 2);
        self.cost_dist = Buf::new(m, dist.alphabet_size_limit as usize);
        self.distance_histogram_size = dist.alphabet_size_limit;
    }

    /// `CleanupZopfliCostModel`.
    fn cleanup(&mut self) {
        self.literal_costs.free();
        self.cost_dist.free();
    }

    /// `ZopfliCostModelSetFromCommands`.
    fn set_from_commands(
        &mut self,
        position: usize,
        ringbuffer: &[u8],
        ringbuffer_mask: usize,
        commands: &[Command],
        num_commands: usize,
        last_insert_len: usize,
    ) {
        let arena = &mut self.arena;
        let mut pos = position.wrapping_sub(last_insert_len);
        let mut min_cost_cmd = K_INFINITY;
        let cost_cmd = &mut self.cost_cmd;

        arena.histogram_literal.fill(0);
        arena.histogram_cmd.fill(0);
        arena.histogram_dist.fill(0);

        for cmd in commands[..num_commands].iter() {
            let inslength = cmd.insert_len_ as usize;
            let copylength = cmd.copy_len() as usize;
            let distcode = (cmd.dist_prefix_ & 0x3FF) as usize;
            let cmdcode = cmd.cmd_prefix_ as usize;

            arena.histogram_cmd[cmdcode] += 1;
            if cmdcode >= 128 {
                arena.histogram_dist[distcode] += 1;
            }

            for j in 0..inslength {
                arena.histogram_literal[ringbuffer[pos.wrapping_add(j) & ringbuffer_mask] as usize] += 1;
            }

            pos = pos.wrapping_add(inslength + copylength);
        }

        set_cost(&arena.histogram_literal, BROTLI_NUM_LITERAL_SYMBOLS, true, &mut arena.cost_literal);
        set_cost(&arena.histogram_cmd, BROTLI_NUM_COMMAND_SYMBOLS, false, cost_cmd);
        set_cost(&arena.histogram_dist, self.distance_histogram_size as usize, false, &mut self.cost_dist);

        for c in cost_cmd.iter() {
            min_cost_cmd = if min_cost_cmd < *c { min_cost_cmd } else { *c };
        }
        self.min_cost_cmd = min_cost_cmd;

        {
            let literal_costs = &mut self.literal_costs[..];
            let mut literal_carry: f32 = 0.0;
            let num_bytes = self.num_bytes;
            literal_costs[0] = 0.0;
            for i in 0..num_bytes {
                literal_carry += arena.cost_literal[ringbuffer[(position + i) & ringbuffer_mask] as usize];
                literal_costs[i + 1] = literal_costs[i] + literal_carry;
                literal_carry -= literal_costs[i + 1] - literal_costs[i];
            }
        }
    }

    /// `ZopfliCostModelSetFromLiteralCosts`.
    fn set_from_literal_costs(&mut self, position: usize, ringbuffer: &[u8], ringbuffer_mask: usize) {
        let num_bytes = self.num_bytes;
        brotli_estimate_bit_costs_for_literals(
            position,
            num_bytes,
            ringbuffer_mask,
            ringbuffer,
            &mut self.literal_histograms,
            &mut self.literal_costs[1..],
        );
        let literal_costs = &mut self.literal_costs[..];
        let mut literal_carry: f32 = 0.0;
        literal_costs[0] = 0.0;
        for i in 0..num_bytes {
            literal_carry += literal_costs[i + 1];
            literal_costs[i + 1] = literal_costs[i] + literal_carry;
            literal_carry -= literal_costs[i + 1] - literal_costs[i];
        }
        for i in 0..BROTLI_NUM_COMMAND_SYMBOLS {
            self.cost_cmd[i] = fast_log2(11 + i as u32 as usize) as f32;
        }
        for i in 0..self.distance_histogram_size as usize {
            self.cost_dist[i] = fast_log2(20 + i as u32 as usize) as f32;
        }
        self.min_cost_cmd = fast_log2(11) as f32;
    }

    /// `ZopfliCostModelGetCommandCost`.
    #[inline(always)]
    fn get_command_cost(&self, cmdcode: u16) -> f32 {
        self.cost_cmd[cmdcode as usize]
    }

    /// `ZopfliCostModelGetDistanceCost`.
    #[inline(always)]
    fn get_distance_cost(&self, distcode: usize) -> f32 {
        self.cost_dist[distcode]
    }

    /// `ZopfliCostModelGetLiteralCosts`.
    #[inline(always)]
    fn get_literal_costs(&self, from: usize, to: usize) -> f32 {
        self.literal_costs[to] - self.literal_costs[from]
    }

    /// `ZopfliCostModelGetMinCostCmd`.
    #[inline(always)]
    fn get_min_cost_cmd(&self) -> f32 {
        self.min_cost_cmd
    }
}

/// `SetCost`.
fn set_cost(histogram: &[u32], histogram_size: usize, literal_histogram: bool, cost: &mut [f32]) {
    let mut sum: usize = 0;
    for i in 0..histogram_size {
        sum += histogram[i] as usize;
    }
    let log2sum = fast_log2(sum) as f32;
    let mut missing_symbol_sum = sum;
    if !literal_histogram {
        for i in 0..histogram_size {
            if histogram[i] == 0 {
                missing_symbol_sum += 1;
            }
        }
    }
    let missing_symbol_cost = fast_log2(missing_symbol_sum) as f32 + 2.0f32;
    for i in 0..histogram_size {
        if histogram[i] == 0 {
            cost[i] = missing_symbol_cost;
            continue;
        }

        // Shannon bits for this symbol.
        cost[i] = log2sum - fast_log2(histogram[i] as usize) as f32;

        // Cannot be coded with less than 1 bit
        if cost[i] < 1.0f32 {
            cost[i] = 1.0f32;
        }
    }
}

/// `UpdateZopfliNode`.
/// REQUIRES: len >= 2, start_pos <= pos
/// REQUIRES: cost < kInfinity, nodes[start_pos].cost < kInfinity
/// Maintains the "ZopfliNode array invariant".
#[inline(always)]
fn update_zopfli_node(
    nodes: &mut [ZopfliNode],
    pos: usize,
    start_pos: usize,
    len: usize,
    len_code: usize,
    dist: usize,
    short_code: usize,
    cost: f32,
) {
    let next = &mut nodes[pos + len];
    next.length = (len | (len.wrapping_add(9).wrapping_sub(len_code) << 25)) as u32;
    next.distance = dist as u32;
    next.dcode_insert_length = ((short_code << 27) | (pos - start_pos)) as u32;
    next.set_cost(cost);
}

/// `PosData`.
#[derive(Clone, Copy, Debug, Default)]
struct PosData {
    pos: usize,
    distance_cache: [i32; 4],
    costdiff: f32,
    cost: f32,
}

/// Maintains the smallest 8 cost difference together with their positions
struct StartPosQueue {
    q: [PosData; 8],
    idx: usize,
}

impl StartPosQueue {
    /// `InitStartPosQueue`.
    fn new() -> Self {
        StartPosQueue { q: [PosData::default(); 8], idx: 0 }
    }

    /// `StartPosQueueSize`.
    #[inline(always)]
    fn size(&self) -> usize {
        if self.idx < 8 {
            self.idx
        } else {
            8
        }
    }

    /// `StartPosQueuePush`.
    fn push(&mut self, posdata: &PosData) {
        let mut offset = !self.idx & 7;
        self.idx = self.idx.wrapping_add(1);
        let len = self.size();
        let q = &mut self.q;
        q[offset] = *posdata;
        // Restore the sorted order. In the list of |len| items at most
        // |len - 1| adjacent element comparisons / swaps are required.
        for _ in 1..len {
            if q[offset & 7].costdiff > q[(offset + 1) & 7].costdiff {
                q.swap(offset & 7, (offset + 1) & 7);
            }
            offset += 1;
        }
    }

    /// `StartPosQueueAt`.
    #[inline(always)]
    fn at(&self, k: usize) -> &PosData {
        &self.q[k.wrapping_sub(self.idx) & 7]
    }
}

/// `ComputeMinimumCopyLength`: returns the minimum possible copy length
/// that can improve the cost of any future position.
fn compute_minimum_copy_length(start_cost: f32, nodes: &[ZopfliNode], num_bytes: usize, pos: usize) -> usize {
    // Compute the minimum possible cost of reaching any future position.
    let mut min_cost = start_cost;
    let mut len: usize = 2;
    let mut next_len_bucket: usize = 4;
    let mut next_len_offset: usize = 10;
    while pos + len <= num_bytes && nodes[pos + len].cost() <= min_cost {
        // We already reached (pos + len) with no more cost than the minimum
        // possible cost of reaching anything from this pos, so there is no
        // point in looking for lengths <= len.
        len += 1;
        if len == next_len_offset {
            // We reached the next copy length code bucket, so we add one more
            // extra bit to the minimum cost.
            min_cost += 1.0f32;
            next_len_offset += next_len_bucket;
            next_len_bucket *= 2;
        }
    }
    len
}

/// `ComputeDistanceShortcut`.
/// REQUIRES: nodes[pos].cost < kInfinity
/// REQUIRES: nodes[0..pos] satisfies that "ZopfliNode array invariant".
fn compute_distance_shortcut(block_start: usize, pos: usize, max_backward_limit: usize, gap: usize, nodes: &[ZopfliNode]) -> u32 {
    let c_len = nodes[pos].copy_length() as usize;
    let i_len = (nodes[pos].dcode_insert_length & 0x7FFFFFF) as usize;
    let dist = nodes[pos].copy_distance() as usize;
    // Since |block_start + pos| is the end position of the command, the copy
    // part starts from |block_start + pos - c_len|. Distances that are
    // greater than this or greater than |max_backward_limit| + |gap| are
    // static dictionary references, and do not update the last distances.
    // Also distance code 0 (last distance) does not update the last
    // distances.
    if pos == 0 {
        0
    } else if dist + c_len <= block_start + pos + gap
        && dist <= max_backward_limit + gap
        && nodes[pos].distance_code() > 0
    {
        pos as u32
    } else {
        nodes[pos - c_len - i_len].shortcut()
    }
}

/// `ComputeDistanceCache`: fills in dist_cache[0..3] with the last four
/// distances (as defined by Section 4. of the Spec) that would be used at
/// (block_start + pos) if we used the shortest path of commands from
/// block_start, computed from nodes[0..pos]. The last four distances at
/// block_start are in starting_dist_cache[0..3].
/// REQUIRES: nodes[pos].cost < kInfinity
/// REQUIRES: nodes[0..pos] satisfies that "ZopfliNode array invariant".
fn compute_distance_cache(pos: usize, starting_dist_cache: &[i32], nodes: &[ZopfliNode], dist_cache: &mut [i32; 4]) {
    let mut idx = 0usize;
    let mut p = nodes[pos].shortcut() as usize;
    while idx < 4 && p > 0 {
        let i_len = (nodes[p].dcode_insert_length & 0x7FFFFFF) as usize;
        let c_len = nodes[p].copy_length() as usize;
        let dist = nodes[p].copy_distance() as usize;
        dist_cache[idx] = dist as i32;
        idx += 1;
        // Because of prerequisite, p >= c_len + i_len >= 2.
        p = nodes[p - c_len - i_len].shortcut() as usize;
    }
    let mut s = 0usize;
    while idx < 4 {
        dist_cache[idx] = starting_dist_cache[s];
        s += 1;
        idx += 1;
    }
}

/// `EvaluateNode`: maintains "ZopfliNode array invariant" and pushes node
/// to the queue, if it is eligible.
fn evaluate_node(
    block_start: usize,
    pos: usize,
    max_backward_limit: usize,
    gap: usize,
    starting_dist_cache: &[i32],
    model: &ZopfliCostModel,
    queue: &mut StartPosQueue,
    nodes: &mut [ZopfliNode],
) {
    // Save cost, because ComputeDistanceCache invalidates it.
    let node_cost = nodes[pos].cost();
    nodes[pos].u = compute_distance_shortcut(block_start, pos, max_backward_limit, gap, nodes);
    if node_cost <= model.get_literal_costs(0, pos) {
        let mut posdata = PosData {
            pos,
            distance_cache: [0; 4],
            cost: node_cost,
            costdiff: node_cost - model.get_literal_costs(0, pos),
        };
        compute_distance_cache(pos, starting_dist_cache, nodes, &mut posdata.distance_cache);
        queue.push(&posdata);
    }
}

/// `UpdateNodes`: returns longest copy length.
fn update_nodes(
    num_bytes: usize,
    block_start: usize,
    pos: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    params: &BrotliEncoderParams,
    max_backward_limit: usize,
    starting_dist_cache: &[i32],
    num_matches: usize,
    matches: &[BackwardMatch],
    model: &ZopfliCostModel,
    queue: &mut StartPosQueue,
    nodes: &mut [ZopfliNode],
) -> usize {
    let stream_offset = params.stream_offset;
    let cur_ix = block_start + pos;
    let cur_ix_masked = cur_ix & ringbuffer_mask;
    let max_distance = if cur_ix < max_backward_limit { cur_ix } else { max_backward_limit };
    let dictionary_start =
        if cur_ix + stream_offset < max_backward_limit { cur_ix + stream_offset } else { max_backward_limit };
    let max_len = num_bytes - pos;
    let max_zopfli_len = max_zopfli_len(params);
    let max_iters = max_zopfli_candidates(params);
    let min_len;
    let mut result: usize = 0;
    let addon = &params.dictionary.compound;
    let gap = addon.total_size;

    evaluate_node(block_start + stream_offset, pos, max_backward_limit, gap, starting_dist_cache, model, queue, nodes);

    {
        let posdata = queue.at(0);
        let min_cost = posdata.cost + model.get_min_cost_cmd() + model.get_literal_costs(posdata.pos, pos);
        min_len = compute_minimum_copy_length(min_cost, nodes, num_bytes, pos);
    }

    // Go over the command starting positions in order of increasing cost
    // difference.
    let mut k = 0usize;
    while k < max_iters && k < queue.size() {
        let posdata = *queue.at(k);
        let start = posdata.pos;
        let inscode = get_insert_length_code(pos - start);
        let start_costdiff = posdata.costdiff;
        let base_cost = start_costdiff + get_insert_extra(inscode) as f32 + model.get_literal_costs(0, pos);

        // Look for last distance matches using the distance cache from this
        // starting position.
        let mut best_len = min_len - 1;
        let mut j = 0usize;
        while j < BROTLI_NUM_DISTANCE_SHORT_CODES as usize && best_len < max_len {
            let idx = K_DISTANCE_CACHE_INDEX[j] as usize;
            let backward = posdata.distance_cache[idx].wrapping_add(K_DISTANCE_CACHE_OFFSET[j]) as usize;
            let mut prev_ix = cur_ix.wrapping_sub(backward);
            let len;
            let continuation = ringbuffer[cur_ix_masked + best_len];
            if cur_ix_masked + best_len > ringbuffer_mask {
                break;
            }
            if backward > dictionary_start.wrapping_add(gap) {
                // Word dictionary -> ignore.
                j += 1;
                continue;
            }
            if backward <= max_distance {
                // Regular backward reference.
                if prev_ix >= cur_ix {
                    j += 1;
                    continue;
                }

                prev_ix &= ringbuffer_mask;
                if prev_ix + best_len > ringbuffer_mask || continuation != ringbuffer[prev_ix + best_len] {
                    j += 1;
                    continue;
                }
                len = find_match_length(&ringbuffer[prev_ix..], &ringbuffer[cur_ix_masked..], max_len);
            } else if backward > dictionary_start {
                let mut d = 0usize;
                let mut offset = dictionary_start + 1 + addon.total_size - 1;
                while offset >= backward + addon.chunk_offsets[d + 1] {
                    d += 1;
                }
                let source = addon.chunk_source(d);
                offset = offset - addon.chunk_offsets[d] - backward;
                let mut limit = addon.chunk_offsets[d + 1] - addon.chunk_offsets[d] - offset;
                limit = if limit > max_len { max_len } else { limit };
                if best_len >= limit || continuation != source[offset + best_len] {
                    j += 1;
                    continue;
                }
                len = find_match_length(&source[offset..], &ringbuffer[cur_ix_masked..], limit);
            } else {
                // "Gray" area. It is addressable by decoder, but this encoder
                // instance does not have that data -> should not touch it.
                j += 1;
                continue;
            }
            {
                let dist_cost = base_cost + model.get_distance_cost(j);
                let mut l = best_len + 1;
                while l <= len {
                    let copycode = get_copy_length_code(l);
                    let cmdcode = combine_length_codes(inscode, copycode, j == 0);
                    let cost = (if cmdcode < 128 { base_cost } else { dist_cost })
                        + get_copy_extra(copycode) as f32
                        + model.get_command_cost(cmdcode);
                    if cost < nodes[pos + l].cost() {
                        update_zopfli_node(nodes, pos, start, l, l, backward, j + 1, cost);
                        result = if result > l { result } else { l };
                    }
                    best_len = l;
                    l += 1;
                }
            }
            j += 1;
        }

        // At higher iterations look only for new last distance matches,
        // since looking only for new command start positions with the same
        // distances does not help much.
        if k >= 2 {
            k += 1;
            continue;
        }

        {
            // Loop through all possible copy lengths at this position.
            let mut len = min_len;
            for m in matches[..num_matches].iter() {
                let mtch = *m;
                let dist = mtch.distance as usize;
                let is_dictionary_match = dist > dictionary_start + gap;
                // We already tried all possible last distance matches, so we
                // can use normal distance code here.
                let dist_code = dist + BROTLI_NUM_DISTANCE_SHORT_CODES as usize - 1;
                let (dist_symbol, _distextra) = prefix_encode_copy_distance(
                    dist_code,
                    params.dist.num_direct_distance_codes as usize,
                    params.dist.distance_postfix_bits as usize,
                );
                let distnumextra = (dist_symbol >> 10) as u32;
                let dist_cost =
                    base_cost + distnumextra as f32 + model.get_distance_cost((dist_symbol & 0x3FF) as usize);

                // Try all copy lengths up until the maximum copy length
                // corresponding to this distance. If the distance refers to
                // the static dictionary, or the maximum length is long
                // enough, try only one maximum length.
                let max_match_len = mtch.length();
                if len < max_match_len && (is_dictionary_match || max_match_len > max_zopfli_len) {
                    len = max_match_len;
                }
                while len <= max_match_len {
                    let len_code = if is_dictionary_match { mtch.length_code() } else { len };
                    let copycode = get_copy_length_code(len_code);
                    let cmdcode = combine_length_codes(inscode, copycode, false);
                    let cost = dist_cost + get_copy_extra(copycode) as f32 + model.get_command_cost(cmdcode);
                    if cost < nodes[pos + len].cost() {
                        update_zopfli_node(nodes, pos, start, len, len_code, dist, 0, cost);
                        result = if result > len { result } else { len };
                    }
                    len += 1;
                }
            }
        }
        k += 1;
    }
    result
}

/// `ComputeShortestPathFromNodes`.
fn compute_shortest_path_from_nodes(num_bytes: usize, nodes: &mut [ZopfliNode]) -> usize {
    let mut index = num_bytes;
    let mut num_commands = 0usize;
    while (nodes[index].dcode_insert_length & 0x7FFFFFF) == 0 && nodes[index].length == 1 {
        index -= 1;
    }
    nodes[index].u = BROTLI_UINT32_MAX;
    while index != 0 {
        let len = nodes[index].command_length() as usize;
        index -= len;
        nodes[index].u = len as u32;
        num_commands += 1;
    }
    num_commands
}

/// `BrotliZopfliCreateCommands`.
/// REQUIRES: nodes != NULL and len(nodes) >= num_bytes + 1
pub fn brotli_zopfli_create_commands(
    num_bytes: usize,
    block_start: usize,
    nodes: &[ZopfliNode],
    dist_cache: &mut [i32],
    last_insert_len: &mut usize,
    params: &BrotliEncoderParams,
    commands: &mut [Command],
    num_literals: &mut usize,
) {
    let stream_offset = params.stream_offset;
    let max_backward_limit = brotli_max_backward_limit(params.lgwin as u32);
    let mut pos = 0usize;
    let mut offset = nodes[0].next();
    let gap = params.dictionary.compound.total_size;
    let mut i = 0usize;
    while offset != BROTLI_UINT32_MAX {
        let next = &nodes[pos + offset as usize];
        let copy_length = next.copy_length() as usize;
        let mut insert_length = (next.dcode_insert_length & 0x7FFFFFF) as usize;
        pos += insert_length;
        offset = next.next();
        if i == 0 {
            insert_length += *last_insert_len;
            *last_insert_len = 0;
        }
        {
            let distance = next.copy_distance() as usize;
            let len_code = next.length_code() as usize;
            let dictionary_start = if block_start + pos + stream_offset < max_backward_limit {
                block_start + pos + stream_offset
            } else {
                max_backward_limit
            };
            let is_dictionary = distance > dictionary_start + gap;
            let dist_code = next.distance_code() as usize;
            commands[i] = Command::new(
                &params.dist,
                insert_length,
                copy_length,
                (len_code as i32).wrapping_sub(copy_length as i32),
                dist_code,
            );

            if !is_dictionary && dist_code > 0 {
                dist_cache[3] = dist_cache[2];
                dist_cache[2] = dist_cache[1];
                dist_cache[1] = dist_cache[0];
                dist_cache[0] = distance as i32;
            }
        }

        *num_literals += insert_length;
        pos += copy_length;
        i += 1;
    }
    *last_insert_len += num_bytes - pos;
}

/// `ZopfliIterate`.
fn zopfli_iterate(
    num_bytes: usize,
    position: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    params: &BrotliEncoderParams,
    gap: usize,
    dist_cache: &[i32],
    model: &ZopfliCostModel,
    num_matches: &[u32],
    matches: &[BackwardMatch],
    nodes: &mut [ZopfliNode],
) -> usize {
    let stream_offset = params.stream_offset;
    let max_backward_limit = brotli_max_backward_limit(params.lgwin as u32);
    let max_zopfli_len = max_zopfli_len(params);
    let mut queue = StartPosQueue::new();
    let mut cur_match_pos = 0usize;
    nodes[0].length = 0;
    nodes[0].set_cost(0.0);
    let mut i = 0usize;
    while i + 3 < num_bytes {
        let mut skip = update_nodes(
            num_bytes,
            position,
            i,
            ringbuffer,
            ringbuffer_mask,
            params,
            max_backward_limit,
            dist_cache,
            num_matches[i] as usize,
            &matches[cur_match_pos..],
            model,
            &mut queue,
            nodes,
        );
        if skip < BROTLI_LONG_COPY_QUICK_STEP {
            skip = 0;
        }
        cur_match_pos += num_matches[i] as usize;
        if num_matches[i] == 1 && matches[cur_match_pos - 1].length() > max_zopfli_len {
            let l = matches[cur_match_pos - 1].length();
            skip = if l > skip { l } else { skip };
        }
        if skip > 1 {
            skip -= 1;
            while skip != 0 {
                i += 1;
                if i + 3 >= num_bytes {
                    break;
                }
                evaluate_node(position + stream_offset, i, max_backward_limit, gap, dist_cache, model, &mut queue, nodes);
                cur_match_pos += num_matches[i] as usize;
                skip -= 1;
            }
        }
        i += 1;
    }
    compute_shortest_path_from_nodes(num_bytes, nodes)
}

/// `MergeMatches` within one buffer: merges `matches[src1..src1 + len1]`
/// and `matches[src2..src2 + len2]` into `matches[dst..]` (the destination
/// never overtakes the sources).
fn merge_matches(matches: &mut [BackwardMatch], mut dst: usize, mut src1: usize, mut len1: usize, mut src2: usize, mut len2: usize) {
    while len1 > 0 && len2 > 0 {
        let l1 = matches[src1].length();
        let l2 = matches[src2].length();
        if l1 < l2 || ((l1 == l2) && (matches[src1].distance < matches[src2].distance)) {
            matches[dst] = matches[src1];
            dst += 1;
            src1 += 1;
            len1 -= 1;
        } else {
            matches[dst] = matches[src2];
            dst += 1;
            src2 += 1;
            len2 -= 1;
        }
    }
    while len1 > 0 {
        matches[dst] = matches[src1];
        dst += 1;
        src1 += 1;
        len1 -= 1;
    }
    while len2 > 0 {
        matches[dst] = matches[src2];
        dst += 1;
        src2 += 1;
        len2 -= 1;
    }
}

#[inline(always)]
fn dict_id_at(params: &BrotliEncoderParams, ringbuffer: &[u8], ringbuffer_mask: usize, pos: usize, lut: ContextLut) -> usize {
    let contextual = &params.dictionary.contextual;
    if contextual.context_based {
        let p1 = if pos >= 1 { ringbuffer[(pos - 1) & ringbuffer_mask] } else { 0 };
        let p2 = if pos >= 2 { ringbuffer[(pos - 2) & ringbuffer_mask] } else { 0 };
        contextual.context_map[brotli_context(p1, p2, lut) as usize] as usize
    } else {
        0
    }
}

/// `BrotliZopfliComputeShortestPath`: computes the shortest path of
/// commands from position to at most position + num_bytes.
///
/// On return, path->size() is the number of commands found and path[i] is
/// the length of the i-th command (copy length plus insert length).
/// Note that the sum of the lengths of all commands can be less than
/// num_bytes.
///
/// On return, the nodes[0..num_bytes] array will have the following
/// "ZopfliNode array invariant":
/// For each i in [1..num_bytes], if nodes[i].cost < kInfinity, then
///   (1) nodes[i].copy_length() >= 2
///   (2) nodes[i].command_length() <= i and
///   (3) nodes[i - nodes[i].command_length()].cost < kInfinity
///
/// REQUIRES: nodes != NULL and len(nodes) >= num_bytes + 1
pub fn brotli_zopfli_compute_shortest_path(
    m: &MemoryManager,
    num_bytes: usize,
    position: usize,
    ringbuffer: &[u8],
    ringbuffer_mask: usize,
    literal_context_lut: ContextLut,
    params: &BrotliEncoderParams,
    dist_cache: &[i32],
    hasher: &mut H10,
    nodes: &mut [ZopfliNode],
) -> usize {
    let stream_offset = params.stream_offset;
    let max_backward_limit = brotli_max_backward_limit(params.lgwin as u32);
    let max_zopfli_len = max_zopfli_len(params);
    let mut queue = StartPosQueue::new();
    let mut matches: Buf<BackwardMatch> = Buf::new(m, 2 * (MAX_NUM_MATCHES_H10 + 64));
    let store_end =
        if num_bytes >= H10::STORE_LOOKAHEAD { position + num_bytes - H10::STORE_LOOKAHEAD + 1 } else { position };
    let addon = &params.dictionary.compound;
    let gap = addon.total_size;
    let lz_matches_offset = if addon.num_chunks != 0 { MAX_NUM_MATCHES_H10 + 128 } else { 0 };
    let mut model = ZopfliCostModel::alloc(m);
    nodes[0].length = 0;
    nodes[0].set_cost(0.0);
    model.init(m, &params.dist, num_bytes);
    model.set_from_literal_costs(position, ringbuffer, ringbuffer_mask);
    let mut i = 0usize;
    while i + H10::HASH_TYPE_LENGTH - 1 < num_bytes {
        let pos = position + i;
        let max_distance = if pos < max_backward_limit { pos } else { max_backward_limit };
        let dictionary_start = if pos + stream_offset < max_backward_limit { pos + stream_offset } else { max_backward_limit };
        let dict_id = dict_id_at(params, ringbuffer, ringbuffer_mask, pos, literal_context_lut);
        let mut num_matches = hasher.find_all_matches(
            params.dictionary.contextual.dict[dict_id],
            ringbuffer,
            ringbuffer_mask,
            pos,
            num_bytes - i,
            max_distance,
            dictionary_start + gap,
            params,
            &mut matches[lz_matches_offset..],
        );
        if addon.num_chunks != 0 {
            let cd_matches = lookup_all_compound_dictionary_matches(
                addon,
                ringbuffer,
                ringbuffer_mask,
                pos,
                3,
                num_bytes - i,
                dictionary_start,
                params.dist.max_distance,
                &mut matches[lz_matches_offset - 64..],
                64,
            );
            merge_matches(&mut matches, 0, lz_matches_offset - 64, cd_matches, lz_matches_offset, num_matches);
            num_matches += cd_matches;
        }
        if num_matches > 0 && matches[num_matches - 1].length() > max_zopfli_len {
            matches[0] = matches[num_matches - 1];
            num_matches = 1;
        }
        let mut skip = update_nodes(
            num_bytes,
            position,
            i,
            ringbuffer,
            ringbuffer_mask,
            params,
            max_backward_limit,
            dist_cache,
            num_matches,
            &matches,
            &model,
            &mut queue,
            nodes,
        );
        if skip < BROTLI_LONG_COPY_QUICK_STEP {
            skip = 0;
        }
        if num_matches == 1 && matches[0].length() > max_zopfli_len {
            let l = matches[0].length();
            skip = if l > skip { l } else { skip };
        }
        if skip > 1 {
            // Add the tail of the copy to the hasher.
            let end = if pos + skip < store_end { pos + skip } else { store_end };
            hasher.store_range(ringbuffer, ringbuffer_mask, pos + 1, end);
            skip -= 1;
            while skip != 0 {
                i += 1;
                #[allow(clippy::int_plus_one)]
                if i + H10::HASH_TYPE_LENGTH - 1 >= num_bytes {
                    break;
                }
                evaluate_node(position + stream_offset, i, max_backward_limit, gap, dist_cache, &model, &mut queue, nodes);
                skip -= 1;
            }
        }
        i += 1;
    }
    model.cleanup();
    drop(model);
    drop(matches);
    compute_shortest_path_from_nodes(num_bytes, nodes)
}

/// `BrotliCreateZopfliBackwardReferences` (quality 10).  Same conventions as
/// `brotli_create_backward_references`.
pub fn brotli_create_zopfli_backward_references(
    m: &MemoryManager,
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
    let h10 = match &mut hasher.privat {
        HasherPrivate::H10(h) => h,
        // C: BROTLI_DCHECK(s->params.hasher.type == 10).
        _ => return,
    };
    let mut nodes: Buf<ZopfliNode> = Buf::new(m, num_bytes + 1);
    brotli_init_zopfli_nodes(&mut nodes);
    *num_commands += brotli_zopfli_compute_shortest_path(
        m,
        num_bytes,
        position,
        ringbuffer,
        ringbuffer_mask,
        literal_context_lut,
        params,
        dist_cache,
        h10,
        &mut nodes,
    );
    brotli_zopfli_create_commands(num_bytes, position, &nodes, dist_cache, last_insert_len, params, commands, num_literals);
}

/// `BrotliCreateHqZopfliBackwardReferences` (quality 11).
pub fn brotli_create_hq_zopfli_backward_references(
    m: &MemoryManager,
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
    let h10 = match &mut hasher.privat {
        HasherPrivate::H10(h) => h,
        // C: BROTLI_DCHECK(s->params.hasher.type == 10).
        _ => return,
    };
    let stream_offset = params.stream_offset;
    let max_backward_limit = brotli_max_backward_limit(params.lgwin as u32);
    let mut num_matches: Buf<u32> = Buf::new(m, num_bytes);
    let mut matches: Buf<BackwardMatch> = Buf::new(m, 4 * num_bytes);
    let store_end =
        if num_bytes >= H10::STORE_LOOKAHEAD { position + num_bytes - H10::STORE_LOOKAHEAD + 1 } else { position };
    let mut cur_match_pos = 0usize;
    let mut model = ZopfliCostModel::alloc(m);
    let addon = &params.dictionary.compound;
    let gap = addon.total_size;
    let shadow_matches = if addon.num_chunks != 0 { MAX_NUM_MATCHES_H10 + 128 } else { 0 };
    let mut i = 0usize;
    while i + H10::HASH_TYPE_LENGTH - 1 < num_bytes {
        let pos = position + i;
        let max_distance = if pos < max_backward_limit { pos } else { max_backward_limit };
        let dictionary_start = if pos + stream_offset < max_backward_limit { pos + stream_offset } else { max_backward_limit };
        let max_length = num_bytes - i;
        let dict_id = dict_id_at(params, ringbuffer, ringbuffer_mask, pos, literal_context_lut);
        // Ensure that we have enough free slots.
        matches.ensure_capacity(m, cur_match_pos + MAX_NUM_MATCHES_H10 + shadow_matches);
        let mut num_found_matches = h10.find_all_matches(
            params.dictionary.contextual.dict[dict_id],
            ringbuffer,
            ringbuffer_mask,
            pos,
            max_length,
            max_distance,
            dictionary_start + gap,
            params,
            &mut matches[cur_match_pos + shadow_matches..],
        );
        if addon.num_chunks != 0 {
            let cd_matches = lookup_all_compound_dictionary_matches(
                addon,
                ringbuffer,
                ringbuffer_mask,
                pos,
                3,
                max_length,
                dictionary_start,
                params.dist.max_distance,
                &mut matches[cur_match_pos + shadow_matches - 64..],
                64,
            );
            merge_matches(
                &mut matches,
                cur_match_pos,
                cur_match_pos + shadow_matches - 64,
                cd_matches,
                cur_match_pos + shadow_matches,
                num_found_matches,
            );
            num_found_matches += cd_matches;
        }
        let cur_match_end = cur_match_pos + num_found_matches;
        num_matches[i] = num_found_matches as u32;
        if num_found_matches > 0 {
            let match_len = matches[cur_match_end - 1].length();
            if match_len > MAX_ZOPFLI_LEN_QUALITY_11 {
                let skip = match_len - 1;
                matches[cur_match_pos] = matches[cur_match_end - 1];
                cur_match_pos += 1;
                num_matches[i] = 1;
                // Add the tail of the copy to the hasher.
                let end = if pos + match_len < store_end { pos + match_len } else { store_end };
                h10.store_range(ringbuffer, ringbuffer_mask, pos + 1, end);
                for v in num_matches[i + 1..i + 1 + skip].iter_mut() {
                    *v = 0;
                }
                i += skip;
            } else {
                cur_match_pos = cur_match_end;
            }
        }
        i += 1;
    }
    let orig_num_literals = *num_literals;
    let orig_last_insert_len = *last_insert_len;
    let mut orig_dist_cache = [0i32; 4];
    orig_dist_cache.copy_from_slice(&dist_cache[..4]);
    let orig_num_commands = *num_commands;
    let mut nodes: Buf<ZopfliNode> = Buf::new(m, num_bytes + 1);
    model.init(m, &params.dist, num_bytes);
    for i in 0..2 {
        brotli_init_zopfli_nodes(&mut nodes);
        if i == 0 {
            model.set_from_literal_costs(position, ringbuffer, ringbuffer_mask);
        } else {
            model.set_from_commands(
                position,
                ringbuffer,
                ringbuffer_mask,
                commands,
                *num_commands - orig_num_commands,
                orig_last_insert_len,
            );
        }
        *num_commands = orig_num_commands;
        *num_literals = orig_num_literals;
        *last_insert_len = orig_last_insert_len;
        dist_cache[..4].copy_from_slice(&orig_dist_cache);
        *num_commands += zopfli_iterate(
            num_bytes,
            position,
            ringbuffer,
            ringbuffer_mask,
            params,
            gap,
            dist_cache,
            &model,
            &num_matches,
            &matches,
            &mut nodes,
        );
        brotli_zopfli_create_commands(num_bytes, position, &nodes, dist_cache, last_insert_len, params, commands, num_literals);
    }
    model.cleanup();
}
