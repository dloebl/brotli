/* Shared helpers of the differential fuzzers. */
#ifndef BROTLI_RUST_FUZZ_COMMON_H_
#define BROTLI_RUST_FUZZ_COMMON_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

/* Abort with a message on the first behavioral difference. */
#define CHECK_EQ(what, a, b)                                                    \
  do {                                                                          \
    unsigned long long a__ = (unsigned long long)(a);                           \
    unsigned long long b__ = (unsigned long long)(b);                           \
    if (a__ != b__) {                                                           \
      fprintf(stderr, "MISMATCH %s:%d: %s: rust=%llu c=%llu\n", __FILE__,       \
              __LINE__, what, a__, b__);                                        \
      abort();                                                                  \
    }                                                                           \
  } while (0)

#define CHECK_MEM(what, a, b, n)                                                \
  do {                                                                          \
    size_t n__ = (size_t)(n);                                                   \
    if (n__ && memcmp((a), (b), n__) != 0) {                                    \
      size_t i__ = 0;                                                           \
      while (((const uint8_t*)(a))[i__] == ((const uint8_t*)(b))[i__]) ++i__;   \
      fprintf(stderr, "MISMATCH %s:%d: %s: bytes differ at %zu of %zu\n",       \
              __FILE__, __LINE__, what, i__, n__);                              \
      abort();                                                                  \
    }                                                                           \
  } while (0)

#define CHECK_TRUE(what, cond)                                                  \
  do {                                                                          \
    if (!(cond)) {                                                              \
      fprintf(stderr, "FAILURE %s:%d: %s\n", __FILE__, __LINE__, what);         \
      abort();                                                                  \
    }                                                                           \
  } while (0)

/* Deterministic PRNG (splitmix64). */
typedef struct { uint64_t s; } FuzzRng;

static inline uint64_t rng_next(FuzzRng* r) {
  uint64_t z = (r->s += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

/* Uniform-ish in [0, n). */
static inline size_t rng_below(FuzzRng* r, size_t n) {
  return n ? (size_t)(rng_next(r) % n) : 0;
}

/* Chunk size biased towards small values / edge cases, in [0, max]. */
static inline size_t rng_chunk(FuzzRng* r, size_t max) {
  uint64_t v = rng_next(r);
  size_t n;
  switch (v & 7) {
    case 0: n = 0; break;
    case 1: n = 1; break;
    case 2: n = (size_t)((v >> 8) % 16); break;
    case 3: n = (size_t)((v >> 8) % 512); break;
    case 4: n = (size_t)((v >> 8) % 65536); break;
    default: n = max; break;
  }
  return n > max ? max : n;
}

/* Byte reader over the fuzz input. */
typedef struct {
  const uint8_t* data;
  size_t size;
  size_t pos;
} FuzzInput;

static inline uint8_t in_u8(FuzzInput* in) {
  return in->pos < in->size ? in->data[in->pos++] : 0;
}
static inline uint16_t in_u16(FuzzInput* in) {
  uint16_t lo = in_u8(in);
  return (uint16_t)(lo | (in_u8(in) << 8));
}
static inline uint32_t in_u32(FuzzInput* in) {
  uint32_t lo = in_u16(in);
  return lo | ((uint32_t)in_u16(in) << 16);
}

/* Allocator that zero-fills (makes the C reference deterministic even where it
   reads uninitialized memory) and counts live allocations. */
typedef struct {
  long live;
  long total;
  long fail_at; /* if > 0: the fail_at-th allocation fails (returns NULL) */
} AllocStats;

static void* fuzz_zalloc(void* opaque, size_t size) {
  AllocStats* st = (AllocStats*)opaque;
  void* p = calloc(1, size ? size : 1);
  if (st && p) { st->live++; st->total++; }
  return p;
}

static void fuzz_free(void* opaque, void* p) {
  AllocStats* st = (AllocStats*)opaque;
  if (st && p) st->live--;
  free(p);
}

/* Zero-filling allocator with failure injection. */
static void* fuzz_failing_alloc(void* opaque, size_t size) {
  AllocStats* st = (AllocStats*)opaque;
  void* p;
  if (st->fail_at > 0 && st->total + 1 == st->fail_at) {
    st->total++;
    return NULL;
  }
  p = calloc(1, size ? size : 1);
  if (p) { st->live++; st->total++; }
  return p;
}

/* Allocator that fills memory with garbage (tests that nothing depends on
   uninitialized contents; only used for the Rust side, where it must not
   matter). */
static void* fuzz_garbage_alloc(void* opaque, size_t size) {
  AllocStats* st = (AllocStats*)opaque;
  void* p = malloc(size ? size : 1);
  /* Fill (at most) the first MiB: enough to catch reliance on uninitialized
     memory without touching every page of huge (lazily used) buffers. */
  if (p) memset(p, 0xA5, size < ((size_t)1 << 20) ? size : ((size_t)1 << 20));
  if (st && p) { st->live++; st->total++; }
  return p;
}

#endif
