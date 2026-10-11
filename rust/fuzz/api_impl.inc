/* Instantiates a BrotliApi table bound to whatever the API names resolve to
   (see api_rust.c / api_ref.c). */
extern const void* BrotliGetDictionary(void);
extern const void* BrotliGetTransforms(void);
extern int BrotliTransformDictionaryWord(uint8_t*, const uint8_t*, int, const void*, int);
extern void* BrotliDefaultAllocFunc(void*, size_t);
extern void BrotliDefaultFreeFunc(void*, void*);
extern const uint8_t _kBrotliContextLookupTable[2048];
extern const uint8_t _kBrotliPrefixCodeRanges[];

const BrotliApi API_NAME = {
  API_LABEL,
  BrotliEncoderSetParameter,
  BrotliEncoderCreateInstance,
  BrotliEncoderDestroyInstance,
  BrotliEncoderPrepareDictionary,
  BrotliEncoderDestroyPreparedDictionary,
  BrotliEncoderAttachPreparedDictionary,
  BrotliEncoderMaxCompressedSize,
  BrotliEncoderCompress,
  BrotliEncoderCompressStream,
  BrotliEncoderIsFinished,
  BrotliEncoderHasMoreOutput,
  BrotliEncoderTakeOutput,
  BrotliEncoderEstimatePeakMemoryUsage,
  BrotliEncoderGetPreparedDictionarySize,
  BrotliEncoderVersion,
  BrotliDecoderSetParameter,
  BrotliDecoderAttachDictionary,
  BrotliDecoderCreateInstance,
  BrotliDecoderDestroyInstance,
  BrotliDecoderDecompress,
  BrotliDecoderDecompressStream,
  BrotliDecoderHasMoreOutput,
  BrotliDecoderTakeOutput,
  BrotliDecoderIsUsed,
  BrotliDecoderIsFinished,
  BrotliDecoderGetErrorCode,
  BrotliDecoderErrorString,
  BrotliDecoderVersion,
  BrotliDecoderSetMetadataCallbacks,
  BrotliSharedDictionaryCreateInstance,
  BrotliSharedDictionaryDestroyInstance,
  BrotliSharedDictionaryAttach,
  BrotliGetDictionary,
  BrotliGetTransforms,
  BrotliTransformDictionaryWord,
  BrotliDefaultAllocFunc,
  BrotliDefaultFreeFunc,
  _kBrotliContextLookupTable,
  _kBrotliPrefixCodeRanges,
};
