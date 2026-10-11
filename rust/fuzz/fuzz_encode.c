/* Differential fuzzer: Rust encoder vs. reference C encoder.

   A fuzzer-chosen parameter set and operation script (PROCESS / FLUSH /
   EMIT_METADATA / FINISH with arbitrary input/output chunking, TakeOutput,
   prepared dictionaries, out-of-protocol calls) is executed on both encoders
   in lockstep; after every call all observable state is compared (return
   value, consumed input, produced bytes, total_out, HasMoreOutput,
   IsFinished, TakeOutput).  The produced stream is also decoded again
   (round trip).  One-shot compression and the size estimation functions
   are compared as well. */

#include "fuzz_common.h"

#define OUT_BUF_SIZE ((size_t)1 << 18)
static uint8_t out_a[OUT_BUF_SIZE];
static uint8_t out_b[OUT_BUF_SIZE];

typedef struct {
  uint8_t* data;
  size_t size;
  size_t cap;
  int overflow;
} ByteVec;

static void vec_append(ByteVec* v, const uint8_t* p, size_t n) {
  if (v->overflow) return;
  if (v->size + n > ((size_t)256 << 20)) { v->overflow = 1; return; }
  if (v->size + n > v->cap) {
    size_t c = v->cap ? v->cap : 4096;
    while (c < v->size + n) c *= 2;
    v->data = (uint8_t*)realloc(v->data, c);
    v->cap = c;
  }
  if (n) memcpy(v->data + v->size, p, n);
  v->size += n;
}

static const char* kWords[] = {
    "the ", "of ", "and ", "brotli ", "compression ", "<div class=\"", "\">", "</div>\n", "function(",
    "){return ", ";base64,", "QUJDRA==", "0123456789", "  ", "\n", "http://www.", ".com/", "é", "日本",
    "\xff\xfe", "\x00\x01\x02", "aaaaaaaa", "The ", "ing ", "tion", "{\"key\": ", "}, ", "null",
};

/* Builds the data to compress from the fuzz input. */
static uint8_t* make_data(FuzzRng* rng, uint8_t kind, uint8_t param, const uint8_t* raw, size_t raw_size,
                          size_t cap, size_t* out_size) {
  ByteVec v = {NULL, 0, 0, 0};
  size_t i;
  switch (kind % 5) {
    case 0:
    default:
      vec_append(&v, raw, raw_size < cap ? raw_size : cap);
      break;
    case 1: { /* repeated with mutations */
      size_t reps = 1 + (size_t)(param % 64);
      for (i = 0; i < reps && v.size + raw_size <= cap; ++i) {
        size_t start = v.size;
        vec_append(&v, raw, raw_size);
        if (raw_size && v.size > start) v.data[start + rng_below(rng, raw_size)] ^= (uint8_t)rng_next(rng);
      }
      break;
    }
    case 2: { /* synthetic text */
      size_t target = (raw_size + 1) * (1 + (size_t)(param % 32)) * 16;
      if (target > cap) target = cap;
      while (v.size < target) {
        const char* w = kWords[rng_below(rng, sizeof(kWords) / sizeof(kWords[0]))];
        size_t n = strlen(w);
        if (strcmp(w, "\x00\x01\x02") == 0) n = 3;
        vec_append(&v, (const uint8_t*)w, n);
        if (raw_size && rng_below(rng, 8) == 0) {
          size_t off = rng_below(rng, raw_size);
          size_t len = rng_below(rng, raw_size - off + 1);
          if (len > 64) len = 64;
          vec_append(&v, raw + off, len);
        }
      }
      break;
    }
    case 3: { /* data + noise + data */
      size_t noise = (size_t)param * 256;
      vec_append(&v, raw, raw_size < cap ? raw_size : cap);
      for (i = 0; i < noise && v.size < cap; ++i) {
        uint8_t b = (uint8_t)rng_next(rng);
        vec_append(&v, &b, 1);
      }
      if (v.size + raw_size <= cap) vec_append(&v, raw, raw_size);
      break;
    }
    case 4: { /* long runs / low entropy */
      size_t target = (size_t)(param + 1) * 4096;
      if (target > cap) target = cap;
      while (v.size < target) {
        uint8_t b = raw_size ? raw[rng_below(rng, raw_size)] : (uint8_t)rng_below(rng, 3);
        size_t run = 1 + rng_below(rng, 300);
        for (i = 0; i < run && v.size < target; ++i) vec_append(&v, &b, 1);
      }
      break;
    }
  }
  if (!v.data) v.data = (uint8_t*)malloc(1);
  *out_size = v.size;
  return v.data;
}

static void compare_state(BrotliEncoderState* a, BrotliEncoderState* b) {
  CHECK_EQ("HasMoreOutput", rust_api.EncoderHasMoreOutput(a), ref_api.EncoderHasMoreOutput(b));
  CHECK_EQ("IsFinished", rust_api.EncoderIsFinished(a), ref_api.EncoderIsFinished(b));
}

/* Decodes `stream` with the given API and checks that it reproduces
   `expected`. */
static void check_roundtrip(const BrotliApi* api, const uint8_t* stream, size_t stream_size,
                            const uint8_t* expected, size_t expected_size, int large_window,
                            const uint8_t* const* dicts, const size_t* dict_sizes, size_t num_dicts) {
  BrotliDecoderState* d = api->DecoderCreateInstance(NULL, NULL, NULL);
  size_t avail_in = stream_size;
  const uint8_t* next_in = stream;
  size_t produced = 0;
  size_t i;
  BrotliDecoderResult r;
  api->DecoderSetParameter(d, BROTLI_DECODER_PARAM_LARGE_WINDOW, large_window ? 1u : 0u);
  for (i = 0; i < num_dicts; ++i) {
    CHECK_TRUE("roundtrip AttachDictionary",
               api->DecoderAttachDictionary(d, BROTLI_SHARED_DICTIONARY_RAW, dict_sizes[i], dicts[i]));
  }
  do {
    size_t avail_out = OUT_BUF_SIZE;
    uint8_t* next_out = out_a;
    r = api->DecoderDecompressStream(d, &avail_in, &next_in, &avail_out, &next_out, NULL);
    {
      size_t n = OUT_BUF_SIZE - avail_out;
      CHECK_TRUE("roundtrip output too long", produced + n <= expected_size);
      CHECK_MEM("roundtrip output", out_a, expected + produced, n);
      produced += n;
    }
  } while (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
  if (r != BROTLI_DECODER_RESULT_SUCCESS) {
    fprintf(stderr, "roundtrip (%s decoder) failed: result %d error %d (%s)\n", api->name, (int)r,
            (int)api->DecoderGetErrorCode(d), api->DecoderErrorString(api->DecoderGetErrorCode(d)));
  }
  CHECK_EQ("roundtrip result", r, BROTLI_DECODER_RESULT_SUCCESS);
  CHECK_EQ("roundtrip size", produced, expected_size);
  CHECK_EQ("roundtrip trailing input", avail_in, 0);
  api->DecoderDestroyInstance(d);
}

#define MAX_PREPARED 17

int LLVMFuzzerTestOneInput(const uint8_t* fuzz, size_t fuzz_size) {
  FuzzInput in = {fuzz, fuzz_size, 0};
  FuzzRng rng;
  uint8_t h[24];
  int quality, lgwin, mode;
  uint8_t* data;
  size_t data_size, cap;
  size_t i;
  int large_window;
  int ok = 1;            /* all calls succeeded so far */
  int protocol_ok = 1;   /* only valid call sequences so far */
  int stream_offset_used = 0;
  int base64_used = 0;
  AllocStats stats_a = {0, 0}, stats_b = {0, 0};
  BrotliEncoderState* a;
  BrotliEncoderState* b;
  BrotliEncoderPreparedDictionary* prep_a[MAX_PREPARED];
  BrotliEncoderPreparedDictionary* prep_b[MAX_PREPARED];
  const uint8_t* dicts[MAX_PREPARED];
  size_t dict_sizes[MAX_PREPARED];
  size_t num_prepared = 0, num_attached = 0;
  ByteVec produced = {NULL, 0, 0, 0};
  ByteVec consumed = {NULL, 0, 0, 0};
  size_t pos = 0;
  size_t iterations = 0;

  if (fuzz_size < sizeof(h)) return 0;
  for (i = 0; i < sizeof(h); ++i) h[i] = in_u8(&in);
  rng.s = (uint64_t)h[18] | ((uint64_t)h[19] << 8) | ((uint64_t)h[23] << 16);

  quality = (h[0] & 0x80) ? (int)(int8_t)h[0] : (h[0] % 12);
  lgwin = (h[1] & 0x80) ? (int)(h[1] & 0x3F) : 10 + (h[1] % 21);
  large_window = (h[2] & 1) || lgwin > BROTLI_MAX_WINDOW_BITS;
  mode = h[3] % 4;

  cap = quality >= 10 ? ((size_t)192 << 10) : quality >= 4 ? ((size_t)1 << 21) : ((size_t)4 << 20);
  data = make_data(&rng, h[16], h[17], fuzz + in.pos, fuzz_size - in.pos, cap, &data_size);

  /* --- Pure functions. --- */
  CHECK_EQ("MaxCompressedSize", rust_api.EncoderMaxCompressedSize(data_size),
           ref_api.EncoderMaxCompressedSize(data_size));
  {
    size_t s = (size_t)rng_next(&rng) >> (rng_next(&rng) % 64);
    CHECK_EQ("MaxCompressedSize(any)", rust_api.EncoderMaxCompressedSize(s), ref_api.EncoderMaxCompressedSize(s));
    CHECK_EQ("EstimatePeakMemoryUsage", rust_api.EncoderEstimatePeakMemoryUsage(quality, lgwin, data_size),
             ref_api.EncoderEstimatePeakMemoryUsage(quality, lgwin, data_size));
    s = (size_t)rng_next(&rng) >> (32 + rng_next(&rng) % 32);
    CHECK_EQ("EstimatePeakMemoryUsage(any)", rust_api.EncoderEstimatePeakMemoryUsage(quality, lgwin, s),
             ref_api.EncoderEstimatePeakMemoryUsage(quality, lgwin, s));
  }
  CHECK_EQ("Version", rust_api.EncoderVersion(), ref_api.EncoderVersion());

  /* --- One-shot API. --- */
  if (h[2] & 128) {
    size_t max = ref_api.EncoderMaxCompressedSize(data_size);
    size_t capacity;
    uint8_t* buf_a;
    uint8_t* buf_b;
    size_t size_a, size_b;
    BROTLI_BOOL ra, rb;
    switch (rng_below(&rng, 4)) {
      case 0: capacity = max; break;
      case 1: capacity = rng_below(&rng, max + 2); break;
      case 2: capacity = rng_below(&rng, 64); break;
      default: capacity = max + 1024; break;
    }
    buf_a = (uint8_t*)malloc(capacity + 1);
    buf_b = (uint8_t*)malloc(capacity + 1);
    memset(buf_a, 0x3C, capacity + 1);
    memset(buf_b, 0x3C, capacity + 1);
    size_a = size_b = capacity;
    ra = rust_api.EncoderCompress(quality, lgwin, (BrotliEncoderMode)mode, data_size, data, &size_a, buf_a);
    rb = ref_api.EncoderCompress(quality, lgwin, (BrotliEncoderMode)mode, data_size, data, &size_b, buf_b);
    CHECK_EQ("Compress result", ra, rb);
    CHECK_EQ("Compress size", size_a, size_b);
    CHECK_MEM("Compress buffer", buf_a, buf_b, capacity + 1);
    if (ra && lgwin <= BROTLI_LARGE_MAX_WINDOW_BITS && quality >= 0) {
      check_roundtrip(&rust_api, buf_a, size_a, data, data_size, 1, NULL, NULL, 0);
    }
    free(buf_a);
    free(buf_b);
  }

  /* --- Streaming API. --- */
  if (h[22] & 1) {
    a = rust_api.EncoderCreateInstance(fuzz_garbage_alloc, fuzz_free, &stats_a);
  } else {
    a = rust_api.EncoderCreateInstance(NULL, NULL, NULL);
  }
  b = ref_api.EncoderCreateInstance(fuzz_zalloc, fuzz_free, &stats_b);
  CHECK_TRUE("create", a && b);

#define SET_BOTH(P, V)                                                                     \
  do {                                                                                     \
    uint32_t v__ = (uint32_t)(V);                                                          \
    CHECK_EQ("SetParameter(" #P ")", rust_api.EncoderSetParameter(a, P, v__),             \
             ref_api.EncoderSetParameter(b, P, v__));                                      \
  } while (0)

  SET_BOTH(BROTLI_PARAM_QUALITY, quality);
  SET_BOTH(BROTLI_PARAM_LGWIN, lgwin);
  SET_BOTH(BROTLI_PARAM_MODE, mode);
  if (large_window) SET_BOTH(BROTLI_PARAM_LARGE_WINDOW, 1);
  if (h[2] & 2) SET_BOTH(BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING, (h[23] & 4) ? 2 : 1);
  if (h[2] & 4) SET_BOTH(BROTLI_PARAM_LGBLOCK, (h[4] & 0x80) ? (h[4] & 0x1F) : (h[4] % 2 ? 0 : 16 + h[4] % 9));
  if (h[2] & 8) {
    uint32_t hint = (uint32_t)h[5] | ((uint32_t)h[6] << 8) | ((uint32_t)h[7] << 16) | ((uint32_t)h[8] << 24);
    if (h[23] & 8) hint = (uint32_t)data_size;
    SET_BOTH(BROTLI_PARAM_SIZE_HINT, hint);
  }
  if (h[2] & 16) {
    SET_BOTH(BROTLI_PARAM_NPOSTFIX, h[9] % 5);
    SET_BOTH(BROTLI_PARAM_NDIRECT, (h[10] & 0x80) ? (uint32_t)h[10] : (uint32_t)((h[10] % 16) << (h[9] % 4)));
  }
  if (h[2] & 32) {
    uint32_t off = ((uint32_t)h[11] | ((uint32_t)h[12] << 8)) << (h[23] % 16);
    CHECK_EQ("SetParameter(STREAM_OFFSET)", rust_api.EncoderSetParameter(a, BROTLI_PARAM_STREAM_OFFSET, off),
             ref_api.EncoderSetParameter(b, BROTLI_PARAM_STREAM_OFFSET, off));
    if (off != 0 && off <= (1u << 30)) stream_offset_used = 1;
  }
  if (h[13] & 1) {
    SET_BOTH(BROTLI_PARAM_BASE64_MODE, (h[13] & 2) ? 3 : 1);
    base64_used = 1;
  }
  if (h[13] & 4) SET_BOTH(BROTLI_PARAM_MAX_BASE64_REGIONS, h[13] >> 3);
  if (h[14]) SET_BOTH(BROTLI_PARAM_MIN_BASE64_REGION_LEN, (uint32_t)h[14] * 37);
  if (h[15] & 0x0F) SET_BOTH(BROTLI_PARAM_SIMD_HASHER, (h[15] & 0x0F) % 5);
  if (h[15] & 0x30) SET_BOTH(BROTLI_PARAM_HASHER_OPT, ((h[15] >> 4) & 3) % 3);
  if (h[15] & 0x40) {
    uint32_t p = (uint32_t)rng_below(&rng, 20);
    uint32_t v = (uint32_t)rng_next(&rng) >> rng_below(&rng, 32);
    CHECK_EQ("SetParameter(random)", rust_api.EncoderSetParameter(a, (BrotliEncoderParameter)p, v),
             ref_api.EncoderSetParameter(b, (BrotliEncoderParameter)p, v));
    if (p == BROTLI_PARAM_STREAM_OFFSET && v) stream_offset_used = 1;
    if (p == BROTLI_PARAM_BASE64_MODE) base64_used = 1;
    if (p == BROTLI_PARAM_LARGE_WINDOW) large_window = 1; /* decoder side is permissive */
  }

  /* Prepared (compound) dictionaries. */
  if (h[2] & 64) {
    size_t n = (h[21] & 0x80) ? MAX_PREPARED : 1 + (size_t)(h[21] % 3);
    for (i = 0; i < n; ++i) {
      size_t off = rng_below(&rng, data_size + 1);
      size_t len = rng_below(&rng, data_size - off + 1);
      BrotliSharedDictionaryType t = rng_below(&rng, 16) == 0 ? BROTLI_SHARED_DICTIONARY_SERIALIZED
                                                                : BROTLI_SHARED_DICTIONARY_RAW;
      int qq = (int)rng_below(&rng, 12);
      dicts[num_prepared] = data + off;
      dict_sizes[num_prepared] = len;
      prep_a[num_prepared] = rust_api.EncoderPrepareDictionary(t, len, data + off, qq, NULL, NULL, NULL);
      prep_b[num_prepared] = ref_api.EncoderPrepareDictionary(t, len, data + off, qq, fuzz_zalloc, fuzz_free, NULL);
      CHECK_EQ("PrepareDictionary null", prep_a[num_prepared] == NULL, prep_b[num_prepared] == NULL);
      if (!prep_a[num_prepared]) continue;
      CHECK_EQ("GetPreparedDictionarySize", rust_api.EncoderGetPreparedDictionarySize(prep_a[num_prepared]),
               ref_api.EncoderGetPreparedDictionarySize(prep_b[num_prepared]));
      {
        BROTLI_BOOL ra = rust_api.EncoderAttachPreparedDictionary(a, prep_a[num_prepared]);
        BROTLI_BOOL rb = ref_api.EncoderAttachPreparedDictionary(b, prep_b[num_prepared]);
        CHECK_EQ("AttachPreparedDictionary", ra, rb);
        if (ra) {
          /* The decoder needs the same chunks, in order. */
          dicts[num_attached] = dicts[num_prepared];
          dict_sizes[num_attached] = dict_sizes[num_prepared];
          num_attached++;
        }
      }
      num_prepared++;
    }
  }

  /* Operation script. */
  {
    int pending_op = -1;         /* op that must be continued, or -1 */
    size_t meta_left = 0;        /* metadata bytes not yet consumed */
    const uint8_t* meta_ptr = NULL;
    int finished = 0;
    int wild = (h[20] & 0x80) != 0;
    size_t max_in = (h[20] & 1) ? 1 : (h[20] & 2) ? 100 : (size_t)-1;
    size_t max_out = (h[20] & 4) ? 1 : (h[20] & 8) ? 700 : OUT_BUF_SIZE;
    int take_mode = (h[20] & 16) != 0;

    while (!finished && iterations++ < 400000) {
      int op;
      size_t in_chunk, out_chunk;
      size_t ai_a, ai_b, ao_a, ao_b;
      const uint8_t* ni_a;
      const uint8_t* ni_b;
      const uint8_t* in_base;
      uint8_t* no_a = out_a;
      uint8_t* no_b = out_b;
      size_t total_a = 3, total_b = 3;
      int use_total = (int)rng_below(&rng, 2);
      BROTLI_BOOL ra, rb;
      int is_meta;

      if (pending_op >= 0) {
        op = pending_op;
      } else {
        uint64_t r = rng_below(&rng, 100);
        if (pos == data_size) {
          op = (r < 10) ? BROTLI_OPERATION_FLUSH : (r < 20) ? BROTLI_OPERATION_EMIT_METADATA : BROTLI_OPERATION_FINISH;
        } else {
          op = (r < 80) ? BROTLI_OPERATION_PROCESS : (r < 90) ? BROTLI_OPERATION_FLUSH
             : (r < 95) ? BROTLI_OPERATION_EMIT_METADATA : BROTLI_OPERATION_FINISH;
        }
        if (op == BROTLI_OPERATION_EMIT_METADATA) {
          size_t off = rng_below(&rng, data_size + 1);
          meta_left = rng_below(&rng, data_size - off + 1);
          if (meta_left > 1000 && rng_below(&rng, 4)) meta_left = rng_below(&rng, 1000);
          meta_ptr = data + off;
        }
      }
      is_meta = (op == BROTLI_OPERATION_EMIT_METADATA);
      if (is_meta) {
        in_base = meta_ptr;
        in_chunk = meta_left;  /* protocol: the whole metadata block */
      } else {
        in_base = data + pos;
        in_chunk = rng_chunk(&rng, max_in);
        if (in_chunk > data_size - pos) in_chunk = data_size - pos;
        if (op == BROTLI_OPERATION_FINISH || op == BROTLI_OPERATION_FLUSH) {
          /* Protocol: the same input must be passed until consumed. */
          if (pending_op >= 0 || rng_below(&rng, 2)) in_chunk = data_size - pos;
        }
      }
      out_chunk = rng_chunk(&rng, max_out);
      if (take_mode && rng_below(&rng, 2)) out_chunk = 0;
      if (out_chunk == 0 && !take_mode && rng_below(&rng, 3) == 0) out_chunk = max_out;

      if (wild && rng_below(&rng, 64) == 0) {
        /* Out-of-protocol call: random op and input size. */
        op = (int)rng_below(&rng, 5);
        in_chunk = rng_below(&rng, data_size - pos + 1);
        in_base = data + pos;
        is_meta = 0;
        protocol_ok = 0;
      }

      ai_a = ai_b = in_chunk;
      ni_a = ni_b = in_base;
      ao_a = ao_b = out_chunk;
      ra = rust_api.EncoderCompressStream(a, (BrotliEncoderOperation)op, &ai_a, &ni_a, &ao_a, &no_a,
                                          use_total ? &total_a : NULL);
      rb = ref_api.EncoderCompressStream(b, (BrotliEncoderOperation)op, &ai_b, &ni_b, &ao_b, &no_b,
                                         use_total ? &total_b : NULL);
      CHECK_EQ("CompressStream result", ra, rb);
      CHECK_EQ("available_in", ai_a, ai_b);
      CHECK_EQ("next_in", ni_a - in_base, ni_b - in_base);
      CHECK_EQ("available_out", ao_a, ao_b);
      CHECK_EQ("next_out", no_a - out_a, no_b - out_b);
      CHECK_EQ("total_out", total_a, total_b);
      CHECK_MEM("output", out_a, out_b, out_chunk - ao_a);
      compare_state(a, b);
      vec_append(&produced, out_a, out_chunk - ao_a);
      if (!ra) ok = 0;
      if (is_meta) {
        meta_ptr += in_chunk - ai_a;
        meta_left -= in_chunk - ai_a;
      } else {
        vec_append(&consumed, in_base, in_chunk - ai_a);
        pos += in_chunk - ai_a;
      }

      if (take_mode && rng_below(&rng, 2)) {
        size_t sz_a = rng_chunk(&rng, (size_t)1 << 20), sz_b = sz_a;
        const uint8_t* pa = rust_api.EncoderTakeOutput(a, &sz_a);
        const uint8_t* pb = ref_api.EncoderTakeOutput(b, &sz_b);
        CHECK_EQ("TakeOutput size", sz_a, sz_b);
        CHECK_EQ("TakeOutput null", pa == NULL, pb == NULL);
        CHECK_MEM("TakeOutput data", pa, pb, sz_a);
        vec_append(&produced, pa, sz_a);
        compare_state(a, b);
      }

      if (!ra) {
        if (!protocol_ok || rng_below(&rng, 4) == 0) break;
        pending_op = -1;
        continue;
      }
      /* Track the operation protocol. */
      if (op == BROTLI_OPERATION_PROCESS) {
        pending_op = -1;
      } else if (op == BROTLI_OPERATION_FLUSH) {
        pending_op = (ai_a != 0 || rust_api.EncoderHasMoreOutput(a)) ? op : -1;
      } else if (op == BROTLI_OPERATION_EMIT_METADATA && is_meta) {
        pending_op = (meta_left != 0 || rust_api.EncoderHasMoreOutput(a)) ? op : -1;
      } else if (op == BROTLI_OPERATION_FINISH) {
        pending_op = op;
        if (rust_api.EncoderIsFinished(a)) finished = 1;
      } else {
        pending_op = -1;
      }
    }

    if (finished && ok && protocol_ok && !stream_offset_used && !produced.overflow && !consumed.overflow &&
        quality >= 0) {
      /* NB: with BROTLI_PARAM_BASE64_MODE the C reference may produce broken
         streams (it reads uninitialized memory, see rust/fuzz/README.md);
         the Rust output must always round trip. */
      check_roundtrip(&rust_api, produced.data, produced.size, consumed.data, consumed.size, large_window,
                      dicts, dict_sizes, num_attached);
      if (!base64_used) {
        check_roundtrip(&ref_api, produced.data, produced.size, consumed.data, consumed.size, large_window,
                        dicts, dict_sizes, num_attached);
      }
    }
  }

  rust_api.EncoderDestroyInstance(a);
  ref_api.EncoderDestroyInstance(b);
  for (i = 0; i < num_prepared; ++i) {
    rust_api.EncoderDestroyPreparedDictionary(prep_a[i]);
    ref_api.EncoderDestroyPreparedDictionary(prep_b[i]);
  }
  CHECK_EQ("leaked allocations (rust)", stats_a.live, 0);
  free(produced.data);
  free(consumed.data);
  free(data);
  return 0;
}
