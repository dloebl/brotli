/* C shims for the differential tests of the matching side of the encoder
   (hashers, backward references, Zopfli, static dictionary).
   OWNER: worker "hashers".

   A "session" replicates what encode.c does around the matching functions:
   parameter setup (BrotliEncoderInitParams, SanitizeParams, ComputeLgBlock,
   ChooseDistanceParams), ring buffer writes (CopyInputToRingBuffer),
   InitOrStitchToPreviousBlock, ExtendLastCommand, the backward reference
   search, the last insert command at metablock end, position wrapping
   (UpdateLastProcessedPos / HasherReset). */

#include <stdlib.h>
#include <string.h>

#include <brotli/encode.h>

#include "enc/backward_references.h"
#include "enc/backward_references_hq.h"
#include "enc/command.h"
#include "enc/compound_dictionary.h"
#include "enc/encoder_dict.h"
#include "enc/hash.h"
#include "enc/memory.h"
#include "enc/metablock.h"
#include "enc/params.h"
#include "enc/quality.h"
#include "enc/ringbuffer.h"
#include "enc/static_dict.h"
#include "common/context.h"

typedef struct HsSession {
  MemoryManager m;
  BrotliEncoderParams params;
  RingBuffer rb;
  Hasher hasher;
  int dist_cache[16];
  int saved_dist_cache[4];
  size_t last_insert_len;
  Command* commands;
  size_t cmd_alloc_size;
  size_t num_commands;
  size_t num_literals;
  uint64_t input_pos;
  uint64_t last_processed_pos;
  uint64_t last_flush_pos;
  size_t num_prepared;
  PreparedDictionary* prepared[SHARED_BROTLI_MAX_COMPOUND_DICTS];
} HsSession;

/* Parameters as seen by the matching code after EnsureInitialized. */
typedef struct HsParamsOut {
  int quality;
  int lgwin;
  int lgblock;
  int large_window;
  size_t stream_offset;
  BrotliDistanceParams dist;
} HsParamsOut;

static void* hashshim_calloc(void* opaque, size_t n) {
  (void)opaque;
  return calloc(1, n);
}

/* Fills fresh allocations with garbage: detects reads of uninitialized
   memory by the C code (Rust zero-initializes). */
static void* hashshim_poison_alloc(void* opaque, size_t n) {
  void* p = malloc(n);
  (void)opaque;
  if (p) memset(p, 0xA5, n);
  return p;
}

static void hashshim_free(void* opaque, void* p) {
  (void)opaque;
  free(p);
}

static uint32_t HsWrapPosition(uint64_t position) {
  uint32_t result = (uint32_t)position;
  uint64_t gb = position >> 30;
  if (gb > 2) {
    /* Wrap every 2GiB; The first 3GB are continuous. */
    result = (result & ((1u << 30) - 1)) | ((uint32_t)((gb - 1) & 1) + 1) << 30;
  }
  return result;
}

static void HsInitParams(BrotliEncoderParams* params) {
  params->mode = BROTLI_DEFAULT_MODE;
  params->large_window = BROTLI_FALSE;
  params->quality = BROTLI_DEFAULT_QUALITY;
  params->lgwin = BROTLI_DEFAULT_WINDOW;
  params->lgblock = 0;
  params->stream_offset = 0;
  params->size_hint = 0;
  params->disable_literal_context_modeling = BROTLI_FALSE;
  BrotliInitSharedEncoderDictionary(&params->dictionary);
  params->base64_mode = (int)BROTLI_DEFAULT_BASE64_MODE;
  params->max_base64_regions = BROTLI_DEFAULT_MAX_BASE64_REGIONS;
  params->min_base64_region_len = BROTLI_DEFAULT_MIN_BASE64_REGION_LEN;
  params->simd_hasher = BROTLI_DEFAULT_SIMD_HASHER;
  params->hasher_opt = BROTLI_FALSE;
  params->dist.distance_postfix_bits = 0;
  params->dist.num_direct_distance_codes = 0;
  params->dist.alphabet_size_max =
      BROTLI_DISTANCE_ALPHABET_SIZE(0, 0, BROTLI_MAX_DISTANCE_BITS);
  params->dist.alphabet_size_limit = params->dist.alphabet_size_max;
  params->dist.max_distance = BROTLI_MAX_DISTANCE;
}

static void HsChooseDistanceParams(BrotliEncoderParams* params) {
  uint32_t distance_postfix_bits = 0;
  uint32_t num_direct_distance_codes = 0;

  if (params->quality >= MIN_QUALITY_FOR_NONZERO_DISTANCE_PARAMS) {
    uint32_t ndirect_msb;
    if (params->mode == BROTLI_MODE_FONT) {
      distance_postfix_bits = 1;
      num_direct_distance_codes = 12;
    } else {
      distance_postfix_bits = params->dist.distance_postfix_bits;
      num_direct_distance_codes = params->dist.num_direct_distance_codes;
    }
    ndirect_msb = (num_direct_distance_codes >> distance_postfix_bits) & 0x0F;
    if (distance_postfix_bits > BROTLI_MAX_NPOSTFIX ||
        num_direct_distance_codes > BROTLI_MAX_NDIRECT ||
        (ndirect_msb << distance_postfix_bits) != num_direct_distance_codes) {
      distance_postfix_bits = 0;
      num_direct_distance_codes = 0;
    }
  }

  BrotliInitDistanceParams(&params->dist, distance_postfix_bits,
                           num_direct_distance_codes, params->large_window);
}

HsSession* hashshim_create(int quality, int lgwin, int lgblock, int mode,
                     size_t size_hint, int large_window, size_t stream_offset,
                     int base64_mode, size_t max_base64_regions,
                     size_t min_base64_region_len, int simd_hasher,
                     int hasher_opt, int npostfix, int ndirect,
                     uint64_t initial_pos, int zero_alloc) {
  HsSession* s = (HsSession*)calloc(1, sizeof(HsSession));
  if (zero_alloc == 1) {
    BrotliInitMemoryManager(&s->m, hashshim_calloc, hashshim_free, NULL);
  } else if (zero_alloc == 2) {
    BrotliInitMemoryManager(&s->m, hashshim_poison_alloc, hashshim_free, NULL);
  } else {
    BrotliInitMemoryManager(&s->m, 0, 0, 0);
  }
  HsInitParams(&s->params);
  s->params.quality = quality;
  s->params.lgwin = lgwin;
  s->params.lgblock = lgblock;
  s->params.mode = (BrotliEncoderMode)mode;
  s->params.size_hint = size_hint;
  s->params.large_window = TO_BROTLI_BOOL(large_window);
  s->params.stream_offset = stream_offset;
  s->params.base64_mode = base64_mode;
  s->params.max_base64_regions = max_base64_regions;
  s->params.min_base64_region_len = min_base64_region_len;
  s->params.simd_hasher = (BrotliEncoderSimdHasher)simd_hasher;
  s->params.hasher_opt = TO_BROTLI_BOOL(hasher_opt);
  s->params.dist.distance_postfix_bits = (uint32_t)npostfix;
  s->params.dist.num_direct_distance_codes = (uint32_t)ndirect;

  /* EnsureInitialized */
  SanitizeParams(&s->params);
  s->params.lgblock = ComputeLgBlock(&s->params);
  HsChooseDistanceParams(&s->params);
  s->dist_cache[0] = 4;
  s->dist_cache[1] = 11;
  s->dist_cache[2] = 15;
  s->dist_cache[3] = 16;
  if (s->params.stream_offset != 0) {
    s->dist_cache[0] = -16;
    s->dist_cache[1] = -16;
    s->dist_cache[2] = -16;
    s->dist_cache[3] = -16;
    s->params.stream_offset = BROTLI_MIN(size_t, s->params.stream_offset,
        BROTLI_MAX_BACKWARD_LIMIT(s->params.lgwin));
  }
  memcpy(s->saved_dist_cache, s->dist_cache, sizeof(s->saved_dist_cache));
  RingBufferInit(&s->rb);
  RingBufferSetup(&s->params, &s->rb);
  HasherInit(&s->hasher);
  s->hasher.common.num_base64_regions = 0;

  s->input_pos = initial_pos;
  s->last_processed_pos = initial_pos;
  s->last_flush_pos = initial_pos;
  if (initial_pos != 0) {
    if (initial_pos < (1u << 31)) {
      s->rb.pos_ = (uint32_t)initial_pos;
    } else {
      s->rb.pos_ = ((uint32_t)initial_pos & 0x7FFFFFFFu) | 0x80000000u;
    }
  }
  return s;
}

void hashshim_get_params(const HsSession* s, HsParamsOut* out) {
  out->quality = s->params.quality;
  out->lgwin = s->params.lgwin;
  out->lgblock = s->params.lgblock;
  out->large_window = s->params.large_window ? 1 : 0;
  out->stream_offset = s->params.stream_offset;
  out->dist = s->params.dist;
}

int hashshim_attach(HsSession* s, const uint8_t* data, size_t size) {
  PreparedDictionary* d = CreatePreparedDictionary(&s->m, data, size);
  if (!d) return 0;
  if (!AttachPreparedDictionary(&s->params.dictionary.compound, d)) {
    DestroyPreparedDictionary(&s->m, d);
    return 0;
  }
  s->prepared[s->num_prepared++] = d;
  return 1;
}

void hashshim_destroy(HsSession* s) {
  size_t i;
  free(s->commands);
  RingBufferFree(&s->m, &s->rb);
  DestroyHasher(&s->m, &s->hasher);
  for (i = 0; i < s->num_prepared; ++i) {
    DestroyPreparedDictionary(&s->m, s->prepared[i]);
  }
  free(s);
}

static void HsExtendLastCommand(HsSession* s, uint32_t* bytes,
                                uint32_t* wrapped_last_processed_pos) {
  Command* last_command = &s->commands[s->num_commands - 1];
  const uint8_t* data = s->rb.buffer_;
  const uint32_t mask = s->rb.mask_;
  uint64_t max_backward_distance =
      (((uint64_t)1) << s->params.lgwin) - BROTLI_WINDOW_GAP;
  uint64_t last_copy_len = last_command->copy_len_ & 0x1FFFFFF;
  uint64_t last_processed_pos = s->last_processed_pos - last_copy_len;
  uint64_t max_distance = last_processed_pos < max_backward_distance ?
      last_processed_pos : max_backward_distance;
  uint64_t cmd_dist = (uint64_t)s->dist_cache[0];
  uint32_t distance_code = CommandRestoreDistanceCode(last_command,
                                                      &s->params.dist);
  const CompoundDictionary* dict = &s->params.dictionary.compound;
  size_t compound_dictionary_size = dict->total_size;
  if (distance_code < BROTLI_NUM_DISTANCE_SHORT_CODES ||
      distance_code - (BROTLI_NUM_DISTANCE_SHORT_CODES - 1) == cmd_dist) {
    if (cmd_dist <= max_distance) {
      while (*bytes != 0 && data[*wrapped_last_processed_pos & mask] ==
             data[(*wrapped_last_processed_pos - cmd_dist) & mask]) {
        last_command->copy_len_++;
        (*bytes)--;
        (*wrapped_last_processed_pos)++;
      }
    } else {
      if ((cmd_dist - max_distance - 1) < compound_dictionary_size &&
          last_copy_len < cmd_dist - max_distance) {
        size_t address =
            compound_dictionary_size - (size_t)(cmd_dist - max_distance) +
            (size_t)last_copy_len;
        size_t br_index = 0;
        size_t br_offset;
        const uint8_t* chunk;
        size_t chunk_length;
        while (address >= dict->chunk_offsets[br_index + 1]) br_index++;
        br_offset = address - dict->chunk_offsets[br_index];
        chunk = dict->chunk_source[br_index];
        chunk_length =
            dict->chunk_offsets[br_index + 1] - dict->chunk_offsets[br_index];
        while (*bytes != 0 && data[*wrapped_last_processed_pos & mask] ==
               chunk[br_offset]) {
          last_command->copy_len_++;
          (*bytes)--;
          (*wrapped_last_processed_pos)++;
          if (++br_offset == chunk_length) {
            br_index++;
            br_offset = 0;
            if (br_index != dict->num_chunks) {
              chunk = dict->chunk_source[br_index];
              chunk_length = dict->chunk_offsets[br_index + 1] -
                  dict->chunk_offsets[br_index];
            } else {
              break;
            }
          }
        }
      }
    }
    /* The copy length is at most the metablock size, and thus expressible. */
    GetLengthCode(last_command->insert_len_,
                  (size_t)((int)(last_command->copy_len_ & 0x1FFFFFF) +
                           (int)(last_command->copy_len_ >> 25)),
                  TO_BROTLI_BOOL((last_command->dist_prefix_ & 0x3FF) == 0),
                  &last_command->cmd_prefix_);
  }
}

/* Processes one input block (<= 1 << lgblock bytes).  Returns 0 on error. */
int hashshim_process(HsSession* s, const uint8_t* input, size_t n, int is_last) {
  uint64_t delta;
  uint32_t bytes;
  uint32_t wrapped_last_processed_pos;
  uint8_t* data;
  uint32_t mask;
  ContextLut literal_context_lut = BROTLI_CONTEXT_LUT(CONTEXT_UTF8);

  if (n > ((size_t)1 << s->params.lgblock)) return 0;
  /* CopyInputToRingBuffer */
  if (n > 0) {
    RingBufferWrite(&s->m, input, n, &s->rb);
    s->input_pos += n;
    if (s->rb.pos_ <= s->rb.mask_) {
      memset(s->rb.buffer_ + s->rb.pos_, 0, 7);
    }
  }

  delta = s->input_pos - s->last_processed_pos;
  bytes = (uint32_t)delta;
  wrapped_last_processed_pos = HsWrapPosition(s->last_processed_pos);
  data = s->rb.buffer_;
  mask = s->rb.mask_;
  if (!data) return 1;

  {
    /* Theoretical max number of commands is 1 per 2 bytes. */
    size_t newsize = s->num_commands + bytes / 2 + 1;
    if (newsize > s->cmd_alloc_size) {
      Command* new_commands;
      newsize += (bytes / 4) + 16;
      s->cmd_alloc_size = newsize;
      new_commands = (Command*)malloc(sizeof(Command) * newsize);
      if (s->commands) {
        memcpy(new_commands, s->commands, sizeof(Command) * s->num_commands);
        free(s->commands);
      }
      s->commands = new_commands;
    }
  }

  InitOrStitchToPreviousBlock(&s->m, &s->hasher, data, mask, &s->params,
      wrapped_last_processed_pos, bytes, is_last);

  if (s->num_commands && s->last_insert_len == 0) {
    HsExtendLastCommand(s, &bytes, &wrapped_last_processed_pos);
  }

  if (s->params.quality == ZOPFLIFICATION_QUALITY) {
    BrotliCreateZopfliBackwardReferences(&s->m, bytes,
        wrapped_last_processed_pos, data, mask, literal_context_lut,
        &s->params, &s->hasher, s->dist_cache, &s->last_insert_len,
        &s->commands[s->num_commands], &s->num_commands, &s->num_literals);
  } else if (s->params.quality == HQ_ZOPFLIFICATION_QUALITY) {
    BrotliCreateHqZopfliBackwardReferences(&s->m, bytes,
        wrapped_last_processed_pos, data, mask, literal_context_lut,
        &s->params, &s->hasher, s->dist_cache, &s->last_insert_len,
        &s->commands[s->num_commands], &s->num_commands, &s->num_literals);
  } else {
    BrotliCreateBackwardReferences(bytes, wrapped_last_processed_pos,
        data, mask, literal_context_lut, &s->params, &s->hasher,
        s->dist_cache, &s->last_insert_len, &s->commands[s->num_commands],
        &s->num_commands, &s->num_literals);
  }
  return 1;
}

/* Metablock end: the last insert-only command, then the reset done after
   WriteMetaBlockInternal (optionally restoring the distance cache like the
   uncompressed-metablock fallback does). */
void hashshim_flush(HsSession* s, int restore_dist_cache) {
  if (s->last_insert_len > 0) {
    InitInsertCommand(&s->commands[s->num_commands++], s->last_insert_len);
    s->num_literals += s->last_insert_len;
    s->last_insert_len = 0;
  }
  if (restore_dist_cache) {
    memcpy(s->dist_cache, s->saved_dist_cache, 4 * sizeof(s->dist_cache[0]));
  }
  s->hasher.common.num_base64_regions = 0;
  s->last_flush_pos = s->input_pos;
  s->num_commands = 0;
  s->num_literals = 0;
  memcpy(s->saved_dist_cache, s->dist_cache, sizeof(s->saved_dist_cache));
}

/* UpdateLastProcessedPos + HasherReset on wrap. Returns 1 if wrapped. */
int hashshim_update_last_processed_pos(HsSession* s) {
  uint32_t wrapped_last_processed_pos = HsWrapPosition(s->last_processed_pos);
  uint32_t wrapped_input_pos = HsWrapPosition(s->input_pos);
  s->last_processed_pos = s->input_pos;
  if (wrapped_input_pos < wrapped_last_processed_pos) {
    HasherReset(&s->hasher);
    return 1;
  }
  return 0;
}

size_t hashshim_num_commands(const HsSession* s) { return s->num_commands; }
const Command* hashshim_commands(const HsSession* s) { return s->commands; }
size_t hashshim_num_literals(const HsSession* s) { return s->num_literals; }
size_t hashshim_last_insert_len(const HsSession* s) { return s->last_insert_len; }
const int* hashshim_dist_cache(const HsSession* s) { return s->dist_cache; }
int hashshim_hasher_type(const HsSession* s) { return s->params.hasher.type; }
size_t hashshim_num_base64_regions(const HsSession* s) {
  return s->hasher.common.num_base64_regions;
}
const Base64Region* hashshim_base64_regions(const HsSession* s) {
  return s->hasher.common.base64_regions;
}
size_t hashshim_dict_num_lookups(const HsSession* s) {
  return s->hasher.common.dict_num_lookups;
}
size_t hashshim_dict_num_matches(const HsSession* s) {
  return s->hasher.common.dict_num_matches;
}

/* HasherSize as called by BrotliEncoderEstimatePeakMemoryUsage, with
   explicit one_shot / input_size and SIMD options. */
int hashshim_hasher_size(int quality, int lgwin, size_t size_hint, int simd_hasher,
                   int hasher_opt, int one_shot, size_t input_size,
                   size_t* out) {
  BrotliEncoderParams params;
  HsInitParams(&params);
  params.quality = quality;
  params.lgwin = lgwin;
  params.size_hint = size_hint;
  params.large_window = lgwin > BROTLI_MAX_WINDOW_BITS;
  params.simd_hasher = (BrotliEncoderSimdHasher)simd_hasher;
  params.hasher_opt = TO_BROTLI_BOOL(hasher_opt);
  SanitizeParams(&params);
  params.lgblock = ComputeLgBlock(&params);
  ChooseHasher(&params, &params.hasher);
  out[0] = out[1] = out[2] = out[3] = 0;
  HasherSize(&params, TO_BROTLI_BOOL(one_shot), input_size, out);
  return params.hasher.type;
}

uint64_t hashshim_matching_tag_mask(size_t chunk_count, uint8_t tag,
                              const uint8_t* tag_bucket, size_t head) {
  return GetMatchingTagMask(chunk_count, tag, tag_bucket, head);
}

int hashshim_static_dict_matches(const uint8_t* data, size_t min_length,
                           size_t max_length, uint32_t* matches) {
  SharedEncoderDictionary dict;
  BrotliInitSharedEncoderDictionary(&dict);
  return BrotliFindAllStaticDictionaryMatches(dict.contextual.dict[0], data,
      min_length, max_length, matches);
}
