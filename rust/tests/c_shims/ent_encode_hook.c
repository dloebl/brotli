/* Test shim (owner: worker "entropy").

   Compiles a private copy of the reference c/enc/encode.c in which every call
   into the entropy-coding / bit-stream modules (compress_fragment*,
   metablock, brotli_bit_stream) is routed through a hook.  Each hook
   snapshots the exact inputs encode.c passes, calls the real C function, and
   then hands inputs + C outputs to a callback registered by the Rust test,
   which replays the call with the Rust port and compares the results.

   The public API of this copy is renamed to ent_BrotliEncoder* so that it
   does not clash with the reference library (ref_BrotliEncoder*). */

/* Rename the public symbols defined in encode.c (they are force-renamed to
   ref_* by tools/ref_prefix.h; the reference library already defines those).
   This must come before any header is included so that the prototypes get the
   same names as the definitions. */
#undef BrotliEncoderSetParameter
#define BrotliEncoderSetParameter ent_BrotliEncoderSetParameter
#undef BrotliEncoderCreateInstance
#define BrotliEncoderCreateInstance ent_BrotliEncoderCreateInstance
#undef BrotliEncoderDestroyInstance
#define BrotliEncoderDestroyInstance ent_BrotliEncoderDestroyInstance
#undef BrotliEncoderMaxCompressedSize
#define BrotliEncoderMaxCompressedSize ent_BrotliEncoderMaxCompressedSize
#undef BrotliEncoderCompress
#define BrotliEncoderCompress ent_BrotliEncoderCompress
#undef BrotliEncoderCompressStream
#define BrotliEncoderCompressStream ent_BrotliEncoderCompressStream
#undef BrotliEncoderIsFinished
#define BrotliEncoderIsFinished ent_BrotliEncoderIsFinished
#undef BrotliEncoderHasMoreOutput
#define BrotliEncoderHasMoreOutput ent_BrotliEncoderHasMoreOutput
#undef BrotliEncoderTakeOutput
#define BrotliEncoderTakeOutput ent_BrotliEncoderTakeOutput
#undef BrotliEncoderVersion
#define BrotliEncoderVersion ent_BrotliEncoderVersion
#undef BrotliEncoderPrepareDictionary
#define BrotliEncoderPrepareDictionary ent_BrotliEncoderPrepareDictionary
#undef BrotliEncoderDestroyPreparedDictionary
#define BrotliEncoderDestroyPreparedDictionary \
  ent_BrotliEncoderDestroyPreparedDictionary
#undef BrotliEncoderAttachPreparedDictionary
#define BrotliEncoderAttachPreparedDictionary \
  ent_BrotliEncoderAttachPreparedDictionary
#undef BrotliEncoderEstimatePeakMemoryUsage
#define BrotliEncoderEstimatePeakMemoryUsage \
  ent_BrotliEncoderEstimatePeakMemoryUsage
#undef BrotliEncoderGetPreparedDictionarySize
#define BrotliEncoderGetPreparedDictionarySize \
  ent_BrotliEncoderGetPreparedDictionarySize

#include <stdlib.h>
#include <string.h>

#include <brotli/encode.h>
#include <brotli/shared_dictionary.h>

#include "common/constants.h"
#include "common/context.h"
#include "common/platform.h"
#include "common/version.h"
#include "enc/backward_references_hq.h"
#include "enc/backward_references.h"
#include "enc/bit_cost.h"
#include "enc/brotli_bit_stream.h"
#include "enc/command.h"
#include "enc/compound_dictionary.h"
#include "enc/compress_fragment_two_pass.h"
#include "enc/compress_fragment.h"
#include "enc/dictionary_hash.h"
#include "enc/encoder_dict.h"
#include "enc/fast_log.h"
#include "enc/hash.h"
#include "enc/histogram.h"
#include "enc/memory.h"
#include "enc/metablock.h"
#include "enc/params.h"
#include "enc/quality.h"
#include "enc/ringbuffer.h"
#include "enc/state.h"
#include "enc/static_init.h"
#include "enc/utf8_util.h"
#include "enc/write_bits.h"

/* ------------------------------------------------------------------------ */
/* Callbacks (set by the Rust test).                                         */

typedef void (*ent_cb_fast_t)(const BrotliOnePassArena* before,
    const BrotliOnePassArena* after, const uint8_t* input, size_t input_size,
    int is_last, const int* table_before, size_t table_size,
    size_t storage_ix_before, const uint8_t* storage_before,
    size_t storage_ix_after, const uint8_t* storage_after);

typedef void (*ent_cb_two_pass_t)(const BrotliTwoPassArena* before,
    const BrotliTwoPassArena* after, const uint8_t* input, size_t input_size,
    int is_last, const int* table_before, size_t table_size,
    size_t storage_ix_before, const uint8_t* storage_before,
    size_t storage_ix_after, const uint8_t* storage_after);

/* kind: 0 = BrotliStoreMetaBlockFast, 1 = BrotliStoreMetaBlockTrivial */
typedef void (*ent_cb_store_simple_t)(int kind, const uint8_t* input,
    size_t start_pos, size_t length, size_t mask, int is_last,
    const BrotliDistanceParams* dist, const Command* commands,
    size_t n_commands, size_t storage_ix_before, const uint8_t* storage_before,
    size_t storage_ix_after, const uint8_t* storage_after);

typedef void (*ent_cb_greedy_t)(const uint8_t* ringbuffer, size_t pos,
    size_t mask, const Base64Region* regions, size_t num_regions,
    uint8_t prev_byte, uint8_t prev_byte2, int literal_context_mode,
    size_t num_contexts, const uint32_t* static_context_map,
    const Command* commands, size_t n_commands, const MetaBlockSplit* mb);

typedef void (*ent_cb_build_t)(const uint8_t* ringbuffer, size_t pos,
    size_t mask, const Base64Region* regions, size_t num_regions, int quality,
    int large_window, int disable_literal_context_modeling,
    const BrotliDistanceParams* dist_before,
    const BrotliDistanceParams* dist_after, uint8_t prev_byte,
    uint8_t prev_byte2, const Command* cmds_before, const Command* cmds_after,
    size_t num_commands, int literal_context_mode, const MetaBlockSplit* mb);

typedef void (*ent_cb_optimize_t)(uint32_t num_distance_codes,
    const MetaBlockSplit* mb_before, const MetaBlockSplit* mb_after);

typedef void (*ent_cb_store_t)(const uint8_t* input, size_t start_pos,
    size_t length, size_t mask, uint8_t prev_byte, uint8_t prev_byte2,
    int is_last, const BrotliDistanceParams* dist, int literal_context_mode,
    const Command* commands, size_t n_commands, const MetaBlockSplit* mb,
    size_t storage_ix_before, const uint8_t* storage_before,
    size_t storage_ix_after, const uint8_t* storage_after);

typedef void (*ent_cb_uncompressed_t)(int is_final_block, const uint8_t* input,
    size_t position, size_t mask, size_t len, size_t storage_ix_before,
    const uint8_t* storage_before, size_t storage_ix_after,
    const uint8_t* storage_after);

typedef struct EntHooks {
  ent_cb_fast_t fast;
  ent_cb_two_pass_t two_pass;
  ent_cb_store_simple_t store_simple;
  ent_cb_greedy_t greedy;
  ent_cb_build_t build;
  ent_cb_optimize_t optimize;
  ent_cb_store_t store;
  ent_cb_uncompressed_t uncompressed;
} EntHooks;

static EntHooks g_ent_hooks;

void ent_set_hooks(const EntHooks* hooks) {
  if (hooks) {
    g_ent_hooks = *hooks;
  } else {
    memset(&g_ent_hooks, 0, sizeof(g_ent_hooks));
  }
}

size_t ent_sizeof_one_pass_arena(void) { return sizeof(BrotliOnePassArena); }
size_t ent_sizeof_two_pass_arena(void) { return sizeof(BrotliTwoPassArena); }
size_t ent_sizeof_meta_block_split(void) { return sizeof(MetaBlockSplit); }
size_t ent_sizeof_histogram_literal(void) { return sizeof(HistogramLiteral); }
size_t ent_sizeof_histogram_command(void) { return sizeof(HistogramCommand); }
size_t ent_sizeof_histogram_distance(void) {
  return sizeof(HistogramDistance);
}

/* Copy of storage[0 .. (storage_ix >> 3)] (the bytes that may contain
   already written bits). */
static uint8_t* SnapshotStorage(size_t storage_ix, const uint8_t* storage) {
  size_t n = (storage_ix >> 3) + 1;
  uint8_t* copy = (uint8_t*)malloc(n);
  memcpy(copy, storage, n);
  return copy;
}

static int ContextModeOfLut(ContextLut lut) {
  return (int)((lut - _kBrotliContextLookupTable) >> 9);
}

/* ------------------------------------------------------------------------ */
/* Hooks.                                                                    */

static void ent_hook_BrotliCompressFragmentFast(BrotliOnePassArena* s,
    const uint8_t* input, size_t input_size, BROTLI_BOOL is_last, int* table,
    size_t table_size, size_t* storage_ix, uint8_t* storage) {
  BrotliOnePassArena* before = NULL;
  int* table_before = NULL;
  uint8_t* storage_before = NULL;
  size_t storage_ix_before = *storage_ix;
  if (g_ent_hooks.fast) {
    before = (BrotliOnePassArena*)malloc(sizeof(BrotliOnePassArena));
    memcpy(before, s, sizeof(*s));
    table_before = (int*)malloc(table_size * sizeof(int));
    memcpy(table_before, table, table_size * sizeof(int));
    storage_before = SnapshotStorage(*storage_ix, storage);
  }
  BrotliCompressFragmentFast(s, input, input_size, is_last, table, table_size,
                             storage_ix, storage);
  if (g_ent_hooks.fast) {
    g_ent_hooks.fast(before, s, input, input_size, is_last ? 1 : 0,
                     table_before, table_size, storage_ix_before,
                     storage_before, *storage_ix, storage);
    free(before);
    free(table_before);
    free(storage_before);
  }
}

static void ent_hook_BrotliCompressFragmentTwoPass(BrotliTwoPassArena* s,
    const uint8_t* input, size_t input_size, BROTLI_BOOL is_last,
    uint32_t* command_buf, uint8_t* literal_buf, int* table, size_t table_size,
    size_t* storage_ix, uint8_t* storage) {
  BrotliTwoPassArena* before = NULL;
  int* table_before = NULL;
  uint8_t* storage_before = NULL;
  size_t storage_ix_before = *storage_ix;
  if (g_ent_hooks.two_pass) {
    before = (BrotliTwoPassArena*)malloc(sizeof(BrotliTwoPassArena));
    memcpy(before, s, sizeof(*s));
    table_before = (int*)malloc(table_size * sizeof(int));
    memcpy(table_before, table, table_size * sizeof(int));
    storage_before = SnapshotStorage(*storage_ix, storage);
  }
  BrotliCompressFragmentTwoPass(s, input, input_size, is_last, command_buf,
                                literal_buf, table, table_size, storage_ix,
                                storage);
  if (g_ent_hooks.two_pass) {
    g_ent_hooks.two_pass(before, s, input, input_size, is_last ? 1 : 0,
                         table_before, table_size, storage_ix_before,
                         storage_before, *storage_ix, storage);
    free(before);
    free(table_before);
    free(storage_before);
  }
}

static void ent_hook_BrotliStoreMetaBlockFast(MemoryManager* m,
    const uint8_t* input, size_t start_pos, size_t length, size_t mask,
    BROTLI_BOOL is_last, const BrotliEncoderParams* params,
    const Command* commands, size_t n_commands,
    size_t* storage_ix, uint8_t* storage) {
  uint8_t* storage_before = NULL;
  size_t storage_ix_before = *storage_ix;
  if (g_ent_hooks.store_simple) {
    storage_before = SnapshotStorage(*storage_ix, storage);
  }
  BrotliStoreMetaBlockFast(m, input, start_pos, length, mask, is_last, params,
                           commands, n_commands, storage_ix, storage);
  if (g_ent_hooks.store_simple) {
    g_ent_hooks.store_simple(0, input, start_pos, length, mask,
                             is_last ? 1 : 0, &params->dist, commands,
                             n_commands, storage_ix_before, storage_before,
                             *storage_ix, storage);
    free(storage_before);
  }
}

static void ent_hook_BrotliStoreMetaBlockTrivial(MemoryManager* m,
    const uint8_t* input, size_t start_pos, size_t length, size_t mask,
    BROTLI_BOOL is_last, const BrotliEncoderParams* params,
    const Command* commands, size_t n_commands,
    size_t* storage_ix, uint8_t* storage) {
  uint8_t* storage_before = NULL;
  size_t storage_ix_before = *storage_ix;
  if (g_ent_hooks.store_simple) {
    storage_before = SnapshotStorage(*storage_ix, storage);
  }
  BrotliStoreMetaBlockTrivial(m, input, start_pos, length, mask, is_last,
                              params, commands, n_commands, storage_ix,
                              storage);
  if (g_ent_hooks.store_simple) {
    g_ent_hooks.store_simple(1, input, start_pos, length, mask,
                             is_last ? 1 : 0, &params->dist, commands,
                             n_commands, storage_ix_before, storage_before,
                             *storage_ix, storage);
    free(storage_before);
  }
}

static void ent_hook_BrotliBuildMetaBlockGreedy(
    MemoryManager* m, const uint8_t* ringbuffer, size_t pos, size_t mask,
    const Base64Region* base64_regions, size_t num_base64_regions,
    uint8_t prev_byte, uint8_t prev_byte2, ContextLut literal_context_lut,
    size_t num_contexts, const uint32_t* static_context_map,
    const Command* commands, size_t n_commands, MetaBlockSplit* mb) {
  BrotliBuildMetaBlockGreedy(m, ringbuffer, pos, mask, base64_regions,
                             num_base64_regions, prev_byte, prev_byte2,
                             literal_context_lut, num_contexts,
                             static_context_map, commands, n_commands, mb);
  if (g_ent_hooks.greedy) {
    g_ent_hooks.greedy(ringbuffer, pos, mask, base64_regions,
                       num_base64_regions, prev_byte, prev_byte2,
                       ContextModeOfLut(literal_context_lut), num_contexts,
                       static_context_map, commands, n_commands, mb);
  }
}

static void ent_hook_BrotliBuildMetaBlock(MemoryManager* m,
    const uint8_t* ringbuffer, const size_t pos, const size_t mask,
    const Base64Region* base64_regions, size_t num_base64_regions,
    BrotliEncoderParams* params, uint8_t prev_byte, uint8_t prev_byte2,
    Command* cmds, size_t num_commands, ContextType literal_context_mode,
    MetaBlockSplit* mb) {
  Command* cmds_before = NULL;
  BrotliDistanceParams dist_before = params->dist;
  if (g_ent_hooks.build) {
    cmds_before = (Command*)malloc(num_commands * sizeof(Command) + 1);
    memcpy(cmds_before, cmds, num_commands * sizeof(Command));
  }
  BrotliBuildMetaBlock(m, ringbuffer, pos, mask, base64_regions,
                       num_base64_regions, params, prev_byte, prev_byte2, cmds,
                       num_commands, literal_context_mode, mb);
  if (g_ent_hooks.build) {
    g_ent_hooks.build(ringbuffer, pos, mask, base64_regions,
                      num_base64_regions, params->quality,
                      params->large_window ? 1 : 0,
                      params->disable_literal_context_modeling ? 1 : 0,
                      &dist_before, &params->dist, prev_byte, prev_byte2,
                      cmds_before, cmds, num_commands,
                      (int)literal_context_mode, mb);
    free(cmds_before);
  }
}

static void ent_hook_BrotliOptimizeHistograms(uint32_t num_distance_codes,
                                              MetaBlockSplit* mb) {
  MetaBlockSplit before;
  if (g_ent_hooks.optimize) {
    before = *mb;
    before.literal_histograms = (HistogramLiteral*)malloc(
        mb->literal_histograms_size * sizeof(HistogramLiteral) + 1);
    memcpy(before.literal_histograms, mb->literal_histograms,
           mb->literal_histograms_size * sizeof(HistogramLiteral));
    before.command_histograms = (HistogramCommand*)malloc(
        mb->command_histograms_size * sizeof(HistogramCommand) + 1);
    memcpy(before.command_histograms, mb->command_histograms,
           mb->command_histograms_size * sizeof(HistogramCommand));
    before.distance_histograms = (HistogramDistance*)malloc(
        mb->distance_histograms_size * sizeof(HistogramDistance) + 1);
    memcpy(before.distance_histograms, mb->distance_histograms,
           mb->distance_histograms_size * sizeof(HistogramDistance));
  }
  BrotliOptimizeHistograms(num_distance_codes, mb);
  if (g_ent_hooks.optimize) {
    g_ent_hooks.optimize(num_distance_codes, &before, mb);
    free(before.literal_histograms);
    free(before.command_histograms);
    free(before.distance_histograms);
  }
}

static void ent_hook_BrotliStoreMetaBlock(MemoryManager* m,
    const uint8_t* input, size_t start_pos, size_t length, size_t mask,
    uint8_t prev_byte, uint8_t prev_byte2, BROTLI_BOOL is_last,
    const BrotliEncoderParams* params, ContextType literal_context_mode,
    const Command* commands, size_t n_commands, const MetaBlockSplit* mb,
    size_t* storage_ix, uint8_t* storage) {
  uint8_t* storage_before = NULL;
  size_t storage_ix_before = *storage_ix;
  if (g_ent_hooks.store) {
    storage_before = SnapshotStorage(*storage_ix, storage);
  }
  BrotliStoreMetaBlock(m, input, start_pos, length, mask, prev_byte,
                       prev_byte2, is_last, params, literal_context_mode,
                       commands, n_commands, mb, storage_ix, storage);
  if (g_ent_hooks.store) {
    g_ent_hooks.store(input, start_pos, length, mask, prev_byte, prev_byte2,
                      is_last ? 1 : 0, &params->dist,
                      (int)literal_context_mode, commands, n_commands, mb,
                      storage_ix_before, storage_before, *storage_ix, storage);
    free(storage_before);
  }
}

static void ent_hook_BrotliStoreUncompressedMetaBlock(
    BROTLI_BOOL is_final_block, const uint8_t* BROTLI_RESTRICT input,
    size_t position, size_t mask, size_t len,
    size_t* BROTLI_RESTRICT storage_ix, uint8_t* BROTLI_RESTRICT storage) {
  uint8_t* storage_before = NULL;
  size_t storage_ix_before = *storage_ix;
  if (g_ent_hooks.uncompressed) {
    storage_before = SnapshotStorage(*storage_ix, storage);
  }
  BrotliStoreUncompressedMetaBlock(is_final_block, input, position, mask, len,
                                   storage_ix, storage);
  if (g_ent_hooks.uncompressed) {
    g_ent_hooks.uncompressed(is_final_block ? 1 : 0, input, position, mask,
                             len, storage_ix_before, storage_before,
                             *storage_ix, storage);
    free(storage_before);
  }
}

/* Route the calls of encode.c through the hooks. */
#define BrotliCompressFragmentFast ent_hook_BrotliCompressFragmentFast
#define BrotliCompressFragmentTwoPass ent_hook_BrotliCompressFragmentTwoPass
#define BrotliStoreMetaBlockFast ent_hook_BrotliStoreMetaBlockFast
#define BrotliStoreMetaBlockTrivial ent_hook_BrotliStoreMetaBlockTrivial
#define BrotliBuildMetaBlockGreedy ent_hook_BrotliBuildMetaBlockGreedy
#define BrotliBuildMetaBlock ent_hook_BrotliBuildMetaBlock
#define BrotliOptimizeHistograms ent_hook_BrotliOptimizeHistograms
#define BrotliStoreMetaBlock ent_hook_BrotliStoreMetaBlock
#define BrotliStoreUncompressedMetaBlock \
  ent_hook_BrotliStoreUncompressedMetaBlock

#include "enc/encode.c"
