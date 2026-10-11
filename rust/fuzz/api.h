/* Table of the public Brotli API, instantiated twice: once bound to the Rust
   library (api_rust.c) and once bound to the reference C library compiled
   with all exported symbols renamed to ref_* (api_ref.c). */
#ifndef BROTLI_RUST_FUZZ_API_H_
#define BROTLI_RUST_FUZZ_API_H_

#include <brotli/decode.h>
#include <brotli/encode.h>
#include <brotli/shared_dictionary.h>

typedef struct BrotliApi {
  const char* name;
  /* encode.h */
  BROTLI_BOOL (*EncoderSetParameter)(BrotliEncoderState*, BrotliEncoderParameter, uint32_t);
  BrotliEncoderState* (*EncoderCreateInstance)(brotli_alloc_func, brotli_free_func, void*);
  void (*EncoderDestroyInstance)(BrotliEncoderState*);
  BrotliEncoderPreparedDictionary* (*EncoderPrepareDictionary)(
      BrotliSharedDictionaryType, size_t, const uint8_t*, int, brotli_alloc_func, brotli_free_func, void*);
  void (*EncoderDestroyPreparedDictionary)(BrotliEncoderPreparedDictionary*);
  BROTLI_BOOL (*EncoderAttachPreparedDictionary)(BrotliEncoderState*, const BrotliEncoderPreparedDictionary*);
  size_t (*EncoderMaxCompressedSize)(size_t);
  BROTLI_BOOL (*EncoderCompress)(int, int, BrotliEncoderMode, size_t, const uint8_t*, size_t*, uint8_t*);
  BROTLI_BOOL (*EncoderCompressStream)(BrotliEncoderState*, BrotliEncoderOperation, size_t*, const uint8_t**,
                                       size_t*, uint8_t**, size_t*);
  BROTLI_BOOL (*EncoderIsFinished)(BrotliEncoderState*);
  BROTLI_BOOL (*EncoderHasMoreOutput)(BrotliEncoderState*);
  const uint8_t* (*EncoderTakeOutput)(BrotliEncoderState*, size_t*);
  size_t (*EncoderEstimatePeakMemoryUsage)(int, int, size_t);
  size_t (*EncoderGetPreparedDictionarySize)(const BrotliEncoderPreparedDictionary*);
  uint32_t (*EncoderVersion)(void);
  /* decode.h */
  BROTLI_BOOL (*DecoderSetParameter)(BrotliDecoderState*, BrotliDecoderParameter, uint32_t);
  BROTLI_BOOL (*DecoderAttachDictionary)(BrotliDecoderState*, BrotliSharedDictionaryType, size_t, const uint8_t*);
  BrotliDecoderState* (*DecoderCreateInstance)(brotli_alloc_func, brotli_free_func, void*);
  void (*DecoderDestroyInstance)(BrotliDecoderState*);
  BrotliDecoderResult (*DecoderDecompress)(size_t, const uint8_t*, size_t*, uint8_t*);
  BrotliDecoderResult (*DecoderDecompressStream)(BrotliDecoderState*, size_t*, const uint8_t**, size_t*, uint8_t**,
                                                 size_t*);
  BROTLI_BOOL (*DecoderHasMoreOutput)(const BrotliDecoderState*);
  const uint8_t* (*DecoderTakeOutput)(BrotliDecoderState*, size_t*);
  BROTLI_BOOL (*DecoderIsUsed)(const BrotliDecoderState*);
  BROTLI_BOOL (*DecoderIsFinished)(const BrotliDecoderState*);
  BrotliDecoderErrorCode (*DecoderGetErrorCode)(const BrotliDecoderState*);
  const char* (*DecoderErrorString)(BrotliDecoderErrorCode);
  uint32_t (*DecoderVersion)(void);
  void (*DecoderSetMetadataCallbacks)(BrotliDecoderState*, brotli_decoder_metadata_start_func,
                                      brotli_decoder_metadata_chunk_func, void*);
  /* shared_dictionary.h */
  BrotliSharedDictionary* (*SharedDictionaryCreateInstance)(brotli_alloc_func, brotli_free_func, void*);
  void (*SharedDictionaryDestroyInstance)(BrotliSharedDictionary*);
  BROTLI_BOOL (*SharedDictionaryAttach)(BrotliSharedDictionary*, BrotliSharedDictionaryType, size_t,
                                        const uint8_t*);
  /* "soft-private" exports of libbrotlicommon */
  const void* (*GetDictionary)(void);
  const void* (*GetTransforms)(void);
  int (*TransformDictionaryWord)(uint8_t*, const uint8_t*, int, const void*, int);
  void* (*DefaultAllocFunc)(void*, size_t);
  void (*DefaultFreeFunc)(void*, void*);
  const uint8_t* context_lookup_table;
  const void* prefix_code_ranges;
} BrotliApi;

/* Layout of the exported BrotliDictionary (c/common/dictionary.h). */
typedef struct FuzzBrotliDictionary {
  uint8_t size_bits_by_length[32];
  uint32_t offsets_by_length[32];
  size_t data_size;
  const uint8_t* data;
} FuzzBrotliDictionary;

/* Layout of the exported BrotliTransforms (c/common/transform.h). */
typedef struct FuzzBrotliTransforms {
  uint16_t prefix_suffix_size;
  const uint8_t* prefix_suffix;
  const uint16_t* prefix_suffix_map;
  uint32_t num_transforms;
  const uint8_t* transforms;
  const uint8_t* params;
  int16_t cutOffTransforms[10];
} FuzzBrotliTransforms;

extern const BrotliApi rust_api;
extern const BrotliApi ref_api;

#endif
