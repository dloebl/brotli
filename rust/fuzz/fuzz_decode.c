/* Differential fuzzer: Rust decoder vs. reference C decoder.

   Both decoders are driven in lockstep with identical (fuzzer-chosen) input
   and output chunk sizes; after every call all observable state is compared:
   return code, consumed input, produced output (bytes), total_out, error
   code/string, HasMoreOutput/IsUsed/IsFinished, TakeOutput results and
   metadata callbacks.  The one-shot API is compared as well. */

#include "fuzz_common.h"

typedef struct {
  uint64_t hash;
  uint64_t count;
} MetaLog;

static void meta_mix(MetaLog* log, uint64_t v) {
  log->hash = (log->hash ^ v) * 0x100000001B3ull;
  log->count++;
}

static void meta_start(void* opaque, size_t size) {
  MetaLog* log = (MetaLog*)opaque;
  meta_mix(log, 0x5354415254ull);
  meta_mix(log, (uint64_t)size);
}

static void meta_chunk(void* opaque, const uint8_t* data, size_t size) {
  MetaLog* log = (MetaLog*)opaque;
  size_t i;
  meta_mix(log, 0x4348554E4Bull);
  meta_mix(log, (uint64_t)size);
  for (i = 0; i < size; ++i) meta_mix(log, data[i]);
}

#define MAX_DICTS 17
#define MAX_OUT_TOTAL ((size_t)64 << 20)
#define OUT_BUF_SIZE ((size_t)1 << 17)

static uint8_t out_a[OUT_BUF_SIZE];
static uint8_t out_b[OUT_BUF_SIZE];

static void compare_state(BrotliDecoderState* a, BrotliDecoderState* b) {
  CHECK_EQ("HasMoreOutput", rust_api.DecoderHasMoreOutput(a), ref_api.DecoderHasMoreOutput(b));
  CHECK_EQ("IsUsed", rust_api.DecoderIsUsed(a), ref_api.DecoderIsUsed(b));
  CHECK_EQ("IsFinished", rust_api.DecoderIsFinished(a), ref_api.DecoderIsFinished(b));
  CHECK_EQ("GetErrorCode", rust_api.DecoderGetErrorCode(a), ref_api.DecoderGetErrorCode(b));
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzInput in = {data, size, 0};
  FuzzRng rng;
  uint8_t flags, mode;
  const uint8_t* dicts[MAX_DICTS];
  size_t dict_sizes[MAX_DICTS];
  size_t num_dicts = 0;
  const uint8_t* stream;
  size_t stream_size;
  AllocStats stats_a = {0, 0, 0}, stats_b = {0, 0, 0};
  BrotliDecoderState* a;
  BrotliDecoderState* b;
  MetaLog log_a = {0xCBF29CE484222325ull, 0}, log_b = {0xCBF29CE484222325ull, 0};
  size_t pos = 0, total_produced = 0;
  size_t iterations = 0;
  size_t i;

  if (size < 4) return 0;
  flags = in_u8(&in);
  mode = in_u8(&in);
  rng.s = in_u16(&in);

  if (flags & 4) {
    uint8_t n = in_u8(&in);
    num_dicts = (n & 0x80) ? MAX_DICTS : (size_t)(n % 4);
    for (i = 0; i < num_dicts; ++i) {
      size_t len = in_u16(&in) % 4096;
      if (len > in.size - in.pos) len = in.size - in.pos;
      dicts[i] = in.data + in.pos;
      dict_sizes[i] = len;
      in.pos += len;
    }
  }
  stream = in.data + in.pos;
  stream_size = in.size - in.pos;

  /* --- One-shot API. --- */
  if (flags & 64) {
    size_t cap = (size_t)rng_chunk(&rng, (size_t)1 << 20);
    uint8_t* buf_a = (uint8_t*)malloc(cap + 1);
    uint8_t* buf_b = (uint8_t*)malloc(cap + 1);
    size_t size_a = cap, size_b = cap;
    BrotliDecoderResult ra, rb;
    memset(buf_a, 0x5A, cap + 1);
    memset(buf_b, 0x5A, cap + 1);
    ra = rust_api.DecoderDecompress(stream_size, stream, &size_a, buf_a);
    rb = ref_api.DecoderDecompress(stream_size, stream, &size_b, buf_b);
    CHECK_EQ("Decompress result", ra, rb);
    CHECK_EQ("Decompress size", size_a, size_b);
    CHECK_MEM("Decompress buffer", buf_a, buf_b, cap + 1);
    free(buf_a);
    free(buf_b);
  }

  /* --- Streaming API. --- */
  if (mode & 16) {
    /* Allocation failure injection: the n-th allocation fails on both. */
    stats_a.fail_at = stats_b.fail_at = 1 + (long)((mode >> 5) + rng_below(&rng, 24));
    a = rust_api.DecoderCreateInstance(fuzz_failing_alloc, fuzz_free, &stats_a);
    b = ref_api.DecoderCreateInstance(fuzz_failing_alloc, fuzz_free, &stats_b);
    CHECK_EQ("create (allocation failure)", a == NULL, b == NULL);
    CHECK_EQ("allocation count", stats_a.total, stats_b.total);
    if (!a) {
      CHECK_EQ("leaked allocations (rust)", stats_a.live, 0);
      CHECK_EQ("leaked allocations (c)", stats_b.live, 0);
      return 0;
    }
  } else if (flags & 16) {
    /* Rust: garbage-filling custom allocator; C: zero-filling allocator. */
    a = rust_api.DecoderCreateInstance(fuzz_garbage_alloc, fuzz_free, &stats_a);
    b = ref_api.DecoderCreateInstance(fuzz_zalloc, fuzz_free, &stats_b);
  } else {
    a = rust_api.DecoderCreateInstance(NULL, NULL, NULL);
    b = ref_api.DecoderCreateInstance(fuzz_zalloc, fuzz_free, &stats_b);
  }
  CHECK_TRUE("create", a && b);

  {
    uint32_t lw = (flags & 1) ? 1u : 0u;
    uint32_t rr = (flags & 2) ? 1u : 0u;
    CHECK_EQ("SetParameter(LARGE_WINDOW)",
             rust_api.DecoderSetParameter(a, BROTLI_DECODER_PARAM_LARGE_WINDOW, lw),
             ref_api.DecoderSetParameter(b, BROTLI_DECODER_PARAM_LARGE_WINDOW, lw));
    CHECK_EQ("SetParameter(DISABLE_RING_BUFFER_REALLOCATION)",
             rust_api.DecoderSetParameter(a, BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION, rr),
             ref_api.DecoderSetParameter(b, BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION, rr));
    if (flags & 128) {
      uint32_t p = (uint32_t)rng_below(&rng, 5);
      uint32_t v = (uint32_t)rng_next(&rng);
      CHECK_EQ("SetParameter(random)", rust_api.DecoderSetParameter(a, (BrotliDecoderParameter)p, v),
               ref_api.DecoderSetParameter(b, (BrotliDecoderParameter)p, v));
    }
  }
  for (i = 0; i < num_dicts; ++i) {
    BrotliSharedDictionaryType t =
        (rng_below(&rng, 16) == 0) ? BROTLI_SHARED_DICTIONARY_SERIALIZED : BROTLI_SHARED_DICTIONARY_RAW;
    CHECK_EQ("AttachDictionary", rust_api.DecoderAttachDictionary(a, t, dict_sizes[i], dicts[i]),
             ref_api.DecoderAttachDictionary(b, t, dict_sizes[i], dicts[i]));
  }
  if (flags & 32) {
    rust_api.DecoderSetMetadataCallbacks(a, meta_start, meta_chunk, &log_a);
    ref_api.DecoderSetMetadataCallbacks(b, meta_start, meta_chunk, &log_b);
  }
  compare_state(a, b);

  while (1) {
    size_t max_in = (mode & 1) ? 1 : (mode & 2) ? 64 : stream_size;
    size_t max_out = (mode & 4) ? 1 : (mode & 8) ? 1024 : OUT_BUF_SIZE;
    size_t in_chunk = rng_chunk(&rng, max_in);
    size_t out_chunk = rng_chunk(&rng, max_out);
    size_t avail_in_a, avail_in_b, avail_out_a, avail_out_b;
    const uint8_t* next_in_a;
    const uint8_t* next_in_b;
    uint8_t* next_out_a = out_a;
    uint8_t* next_out_b = out_b;
    size_t total_a = 7, total_b = 7;
    int use_total = (int)rng_below(&rng, 2);
    BrotliDecoderResult ra, rb;

    if (in_chunk > stream_size - pos) in_chunk = stream_size - pos;
    if ((flags & 8) && rng_below(&rng, 2)) out_chunk = 0; /* TakeOutput mode */
    avail_in_a = avail_in_b = in_chunk;
    next_in_a = next_in_b = stream + pos;
    avail_out_a = avail_out_b = out_chunk;

    ra = rust_api.DecoderDecompressStream(a, &avail_in_a, &next_in_a, &avail_out_a, &next_out_a,
                                          use_total ? &total_a : NULL);
    rb = ref_api.DecoderDecompressStream(b, &avail_in_b, &next_in_b, &avail_out_b, &next_out_b,
                                         use_total ? &total_b : NULL);
    CHECK_EQ("DecompressStream result", ra, rb);
    CHECK_EQ("available_in", avail_in_a, avail_in_b);
    CHECK_EQ("next_in", next_in_a - stream, next_in_b - stream);
    CHECK_EQ("available_out", avail_out_a, avail_out_b);
    CHECK_EQ("next_out", next_out_a - out_a, next_out_b - out_b);
    CHECK_EQ("total_out", total_a, total_b);
    CHECK_MEM("output", out_a, out_b, out_chunk - avail_out_a);
    CHECK_EQ("metadata callbacks count", log_a.count, log_b.count);
    CHECK_EQ("metadata callbacks hash", log_a.hash, log_b.hash);
    compare_state(a, b);
    if (mode & 16) CHECK_EQ("allocation count", stats_a.total, stats_b.total);
    pos += in_chunk - avail_in_a;
    total_produced += out_chunk - avail_out_a;

    if ((flags & 128) && rng_below(&rng, 16) == 0) {
      /* Mid-stream parameter changes must be rejected identically. */
      uint32_t p = (uint32_t)rng_below(&rng, 3);
      uint32_t v = (uint32_t)rng_below(&rng, 3);
      CHECK_EQ("SetParameter(mid-stream)", rust_api.DecoderSetParameter(a, (BrotliDecoderParameter)p, v),
               ref_api.DecoderSetParameter(b, (BrotliDecoderParameter)p, v));
    }
    if ((flags & 32) && rng_below(&rng, 32) == 0) {
      /* Metadata callbacks may be (un)set at any time. */
      if (rng_below(&rng, 2)) {
        rust_api.DecoderSetMetadataCallbacks(a, NULL, NULL, NULL);
        ref_api.DecoderSetMetadataCallbacks(b, NULL, NULL, NULL);
      } else {
        rust_api.DecoderSetMetadataCallbacks(a, meta_start, meta_chunk, &log_a);
        ref_api.DecoderSetMetadataCallbacks(b, meta_start, meta_chunk, &log_b);
      }
    }
    if ((flags & 8) && rng_below(&rng, 2)) {
      size_t sz_a = rng_chunk(&rng, (size_t)1 << 20), sz_b = sz_a;
      const uint8_t* pa = rust_api.DecoderTakeOutput(a, &sz_a);
      const uint8_t* pb = ref_api.DecoderTakeOutput(b, &sz_b);
      CHECK_EQ("TakeOutput size", sz_a, sz_b);
      CHECK_EQ("TakeOutput null", pa == NULL, pb == NULL);
      CHECK_MEM("TakeOutput data", pa, pb, sz_a);
      total_produced += sz_a;
      compare_state(a, b);
    }

    if (ra == BROTLI_DECODER_RESULT_SUCCESS || ra == BROTLI_DECODER_RESULT_ERROR) {
      /* Calls after the end must behave identically, too. */
      size_t ai = stream_size - pos, bi = ai, ao = 16, bo = 16;
      const uint8_t* ni = stream + pos;
      const uint8_t* mi = stream + pos;
      uint8_t* no = out_a;
      uint8_t* mo = out_b;
      ra = rust_api.DecoderDecompressStream(a, &ai, &ni, &ao, &no, NULL);
      rb = ref_api.DecoderDecompressStream(b, &bi, &mi, &bo, &mo, NULL);
      CHECK_EQ("post-end result", ra, rb);
      CHECK_EQ("post-end available_in", ai, bi);
      CHECK_EQ("post-end available_out", ao, bo);
      CHECK_MEM("post-end output", out_a, out_b, 16 - ao);
      compare_state(a, b);
      break;
    }
    if (++iterations > 200000 || total_produced > MAX_OUT_TOTAL) break;
    if (ra == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && pos == stream_size && in_chunk == 0 &&
        rng_below(&rng, 4) == 0) {
      break;
    }
  }
  {
    BrotliDecoderErrorCode code = rust_api.DecoderGetErrorCode(a);
    const char* sa = rust_api.DecoderErrorString(code);
    const char* sb = ref_api.DecoderErrorString(code);
    CHECK_TRUE("ErrorString", strcmp(sa, sb) == 0);
    {
      int c = (int)(rng_next(&rng) % 80) - 40;
      CHECK_TRUE("ErrorString(any)", strcmp(rust_api.DecoderErrorString((BrotliDecoderErrorCode)c),
                                            ref_api.DecoderErrorString((BrotliDecoderErrorCode)c)) == 0);
    }
  }
  if (flags & 128) {
    /* Attaching a dictionary to a used instance must fail identically. */
    CHECK_EQ("AttachDictionary(after use)",
             rust_api.DecoderAttachDictionary(a, BROTLI_SHARED_DICTIONARY_RAW, stream_size, stream),
             ref_api.DecoderAttachDictionary(b, BROTLI_SHARED_DICTIONARY_RAW, stream_size, stream));
  }
  rust_api.DecoderDestroyInstance(a);
  ref_api.DecoderDestroyInstance(b);
  CHECK_EQ("leaked allocations (rust)", stats_a.live, 0);
  CHECK_EQ("leaked allocations (c)", stats_b.live, 0);
  CHECK_EQ("Version", rust_api.DecoderVersion(), ref_api.DecoderVersion());
  return 0;
}
