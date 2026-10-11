/* Test shim (owner: worker "entropy"): thin wrappers around internal
   functions of the reference encoder (entropy coding / bit stream side), for
   direct differential tests with synthetic inputs. */

#include <stdlib.h>
#include <string.h>

#include "common/constants.h"
#include "common/context.h"
#include "common/platform.h"
#include "enc/bit_cost.h"
#include "enc/block_splitter.h"
#include "enc/brotli_bit_stream.h"
#include "enc/cluster.h"
#include "enc/command.h"
#include "enc/compress_fragment.h"
#include "enc/compress_fragment_two_pass.h"
#include "enc/encoder_dict.h"
#include "enc/entropy_encode.h"
#include "enc/histogram.h"
#include "enc/memory.h"
#include "enc/metablock.h"
#include "enc/params.h"
#include "enc/quality.h"

static void InitParams(BrotliEncoderParams* params, int quality,
                       int large_window, int disable_lcm,
                       const BrotliDistanceParams* dist) {
  memset(params, 0, sizeof(*params));
  params->mode = BROTLI_MODE_GENERIC;
  params->quality = quality;
  params->lgwin = 22;
  params->lgblock = 0;
  params->large_window = large_window ? BROTLI_TRUE : BROTLI_FALSE;
  params->disable_literal_context_modeling =
      disable_lcm ? BROTLI_TRUE : BROTLI_FALSE;
  BrotliInitSharedEncoderDictionary(&params->dictionary);
  params->dist = *dist;
}

/* ---- entropy_encode ---- */

void ent_c_create_huffman_tree(const uint32_t* data, size_t length,
                               int tree_limit, uint8_t* depth) {
  HuffmanTree* tree = (HuffmanTree*)malloc((2 * length + 1) * sizeof(HuffmanTree));
  BrotliCreateHuffmanTree(data, length, tree_limit, tree, depth);
  free(tree);
}

void ent_c_optimize_huffman_counts_for_rle(size_t length, uint32_t* counts,
                                           uint8_t* good_for_rle) {
  BrotliOptimizeHuffmanCountsForRle(length, counts, good_for_rle);
}

void ent_c_write_huffman_tree(const uint8_t* depth, size_t length,
                              size_t* tree_size, uint8_t* tree,
                              uint8_t* extra_bits_data) {
  BrotliWriteHuffmanTree(depth, length, tree_size, tree, extra_bits_data);
}

void ent_c_convert_bit_depths_to_symbols(const uint8_t* depth, size_t len,
                                         uint16_t* bits) {
  BrotliConvertBitDepthsToSymbols(depth, len, bits);
}

/* ---- bit_cost ---- */

double ent_c_bits_entropy(const uint32_t* population, size_t size) {
  return BrotliBitsEntropy(population, size);
}

double ent_c_population_cost_literal(const HistogramLiteral* h) {
  return BrotliPopulationCostLiteral(h);
}
double ent_c_population_cost_command(const HistogramCommand* h) {
  return BrotliPopulationCostCommand(h);
}
double ent_c_population_cost_distance(const HistogramDistance* h) {
  return BrotliPopulationCostDistance(h);
}

/* ---- cluster ---- */

void ent_c_cluster_histograms_literal(const HistogramLiteral* in,
    size_t in_size, size_t max_histograms, HistogramLiteral* out,
    size_t* out_size, uint32_t* histogram_symbols) {
  MemoryManager m;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  BrotliClusterHistogramsLiteral(&m, in, in_size, max_histograms, out,
                                 out_size, histogram_symbols);
}

void ent_c_cluster_histograms_command(const HistogramCommand* in,
    size_t in_size, size_t max_histograms, HistogramCommand* out,
    size_t* out_size, uint32_t* histogram_symbols) {
  MemoryManager m;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  BrotliClusterHistogramsCommand(&m, in, in_size, max_histograms, out,
                                 out_size, histogram_symbols);
}

void ent_c_cluster_histograms_distance(const HistogramDistance* in,
    size_t in_size, size_t max_histograms, HistogramDistance* out,
    size_t* out_size, uint32_t* histogram_symbols) {
  MemoryManager m;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  BrotliClusterHistogramsDistance(&m, in, in_size, max_histograms, out,
                                  out_size, histogram_symbols);
}

/* ---- brotli_bit_stream ---- */

void ent_c_store_huffman_tree(const uint8_t* depths, size_t num,
                              size_t* storage_ix, uint8_t* storage) {
  HuffmanTree tree[2 * BROTLI_NUM_COMMAND_SYMBOLS + 1];
  BrotliStoreHuffmanTree(depths, num, tree, storage_ix, storage);
}

void ent_c_build_and_store_huffman_tree_fast(const uint32_t* histogram,
    size_t histogram_total, size_t max_bits, uint8_t* depth, uint16_t* bits,
    size_t* storage_ix, uint8_t* storage) {
  HuffmanTree tree[2 * BROTLI_NUM_COMMAND_SYMBOLS + 1];
  BrotliBuildAndStoreHuffmanTreeFast(tree, histogram, histogram_total,
                                     max_bits, depth, bits, storage_ix,
                                     storage);
}

void ent_c_store_uncompressed_meta_block(int is_final_block,
    const uint8_t* input, size_t position, size_t mask, size_t len,
    size_t* storage_ix, uint8_t* storage) {
  BrotliStoreUncompressedMetaBlock(is_final_block, input, position, mask, len,
                                   storage_ix, storage);
}

/* ---- commands ---- */

void ent_c_init_command(const BrotliDistanceParams* dist, size_t insertlen,
    size_t copylen, int copylen_code_delta, size_t distance_code,
    Command* out) {
  InitCommand(out, dist, insertlen, copylen, copylen_code_delta,
              distance_code);
}

void ent_c_init_insert_command(size_t insertlen, Command* out) {
  InitInsertCommand(out, insertlen);
}

void ent_c_init_distance_params(BrotliDistanceParams* dist, uint32_t npostfix,
                                uint32_t ndirect, int large_window) {
  BrotliInitDistanceParams(dist, npostfix, ndirect,
                           large_window ? BROTLI_TRUE : BROTLI_FALSE);
}

/* ---- metablock ---- */

MetaBlockSplit* ent_c_new_mb(void) {
  MetaBlockSplit* mb = (MetaBlockSplit*)malloc(sizeof(MetaBlockSplit));
  InitMetaBlockSplit(mb);
  return mb;
}

void ent_c_destroy_mb(MetaBlockSplit* mb) {
  MemoryManager m;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  DestroyMetaBlockSplit(&m, mb);
  free(mb);
}

void ent_c_split_block(const Command* cmds, size_t num_commands,
    const uint8_t* data, size_t pos, size_t mask, int quality,
    MetaBlockSplit* mb) {
  MemoryManager m;
  BrotliEncoderParams params;
  BrotliDistanceParams dist;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  BrotliInitDistanceParams(&dist, 0, 0, BROTLI_FALSE);
  InitParams(&params, quality, 0, 0, &dist);
  BrotliSplitBlock(&m, cmds, num_commands, data, pos, mask, &params,
                   &mb->literal_split, &mb->command_split,
                   &mb->distance_split);
}

void ent_c_build_meta_block_greedy(const uint8_t* ringbuffer, size_t pos,
    size_t mask, const Base64Region* regions, size_t num_regions,
    uint8_t prev_byte, uint8_t prev_byte2, int literal_context_mode,
    size_t num_contexts, const uint32_t* static_context_map,
    const Command* commands, size_t n_commands, MetaBlockSplit* mb) {
  MemoryManager m;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  BrotliBuildMetaBlockGreedy(&m, ringbuffer, pos, mask, regions, num_regions,
      prev_byte, prev_byte2,
      BROTLI_CONTEXT_LUT((ContextType)literal_context_mode), num_contexts,
      static_context_map, commands, n_commands, mb);
}

void ent_c_build_meta_block(const uint8_t* ringbuffer, size_t pos,
    size_t mask, const Base64Region* regions, size_t num_regions, int quality,
    int large_window, int disable_lcm, BrotliDistanceParams* dist,
    uint8_t prev_byte, uint8_t prev_byte2, Command* cmds, size_t num_commands,
    int literal_context_mode, MetaBlockSplit* mb) {
  MemoryManager m;
  BrotliEncoderParams params;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  InitParams(&params, quality, large_window, disable_lcm, dist);
  BrotliBuildMetaBlock(&m, ringbuffer, pos, mask, regions, num_regions,
                       &params, prev_byte, prev_byte2, cmds, num_commands,
                       (ContextType)literal_context_mode, mb);
  *dist = params.dist;
}

void ent_c_optimize_histograms(uint32_t num_distance_codes,
                               MetaBlockSplit* mb) {
  BrotliOptimizeHistograms(num_distance_codes, mb);
}

void ent_c_store_meta_block(const uint8_t* input, size_t start_pos,
    size_t length, size_t mask, uint8_t prev_byte, uint8_t prev_byte2,
    int is_last, const BrotliDistanceParams* dist, int literal_context_mode,
    const Command* commands, size_t n_commands, const MetaBlockSplit* mb,
    size_t* storage_ix, uint8_t* storage) {
  MemoryManager m;
  BrotliEncoderParams params;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  InitParams(&params, 5, 0, 0, dist);
  BrotliStoreMetaBlock(&m, input, start_pos, length, mask, prev_byte,
                       prev_byte2, is_last ? BROTLI_TRUE : BROTLI_FALSE,
                       &params, (ContextType)literal_context_mode, commands,
                       n_commands, mb, storage_ix, storage);
}

void ent_c_store_meta_block_simple(int kind, const uint8_t* input,
    size_t start_pos, size_t length, size_t mask, int is_last,
    const BrotliDistanceParams* dist, const Command* commands,
    size_t n_commands, size_t* storage_ix, uint8_t* storage) {
  MemoryManager m;
  BrotliEncoderParams params;
  BrotliInitMemoryManager(&m, 0, 0, 0);
  InitParams(&params, kind == 0 ? 2 : 3, 0, 0, dist);
  if (kind == 0) {
    BrotliStoreMetaBlockFast(&m, input, start_pos, length, mask,
                             is_last ? BROTLI_TRUE : BROTLI_FALSE, &params,
                             commands, n_commands, storage_ix, storage);
  } else {
    BrotliStoreMetaBlockTrivial(&m, input, start_pos, length, mask,
                                is_last ? BROTLI_TRUE : BROTLI_FALSE, &params,
                                commands, n_commands, storage_ix, storage);
  }
}

/* ---- compress_fragment ---- */

/* Copy of the static InitCommandPrefixCodes of encode.c. */
static void InitCommandPrefixCodes(BrotliOnePassArena* s) {
  static const BROTLI_MODEL("small") uint8_t kDefaultCommandDepths[128] = {
    0, 4, 4, 5, 6, 6, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8,
    0, 0, 0, 4, 4, 4, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7,
    7, 7, 10, 10, 10, 10, 10, 10, 0, 4, 4, 5, 5, 5, 6, 6,
    7, 8, 8, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4,
    4, 4, 4, 5, 5, 5, 5, 5, 5, 6, 6, 7, 7, 7, 8, 10,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
  };
  static const BROTLI_MODEL("small") uint16_t kDefaultCommandBits[128] = {
    0,   0,   8,   9,   3,  35,   7,   71,
    39, 103,  23,  47, 175, 111, 239,   31,
    0,   0,   0,   4,  12,   2,  10,    6,
    13,  29,  11,  43,  27,  59,  87,   55,
    15,  79, 319, 831, 191, 703, 447,  959,
    0,  14,   1,  25,   5,  21,  19,   51,
    119, 159,  95, 223, 479, 991,  63,  575,
    127, 639, 383, 895, 255, 767, 511, 1023,
    14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    27, 59, 7, 39, 23, 55, 30, 1, 17, 9, 25, 5, 0, 8, 4, 12,
    2, 10, 6, 21, 13, 29, 3, 19, 11, 15, 47, 31, 95, 63, 127, 255,
    767, 2815, 1791, 3839, 511, 2559, 1535, 3583, 1023, 3071, 2047, 4095,
  };
  static const BROTLI_MODEL("small") uint8_t kDefaultCommandCode[] = {
    0xff, 0x77, 0xd5, 0xbf, 0xe7, 0xde, 0xea, 0x9e, 0x51, 0x5d, 0xde, 0xc6,
    0x70, 0x57, 0xbc, 0x58, 0x58, 0x58, 0xd8, 0xd8, 0x58, 0xd5, 0xcb, 0x8c,
    0xea, 0xe0, 0xc3, 0x87, 0x1f, 0x83, 0xc1, 0x60, 0x1c, 0x67, 0xb2, 0xaa,
    0x06, 0x83, 0xc1, 0x60, 0x30, 0x18, 0xcc, 0xa1, 0xce, 0x88, 0x54, 0x94,
    0x46, 0xe1, 0xb0, 0xd0, 0x4e, 0xb2, 0xf7, 0x04, 0x00,
  };
  static const size_t kDefaultCommandCodeNumBits = 448;
  memcpy(s->cmd_depth, kDefaultCommandDepths, sizeof(kDefaultCommandDepths));
  memcpy(s->cmd_bits, kDefaultCommandBits, sizeof(kDefaultCommandBits));
  memcpy(s->cmd_code, kDefaultCommandCode, sizeof(kDefaultCommandCode));
  s->cmd_code_numbits = kDefaultCommandCodeNumBits;
}

BrotliOnePassArena* ent_c_new_one_pass_arena(void) {
  BrotliOnePassArena* s = (BrotliOnePassArena*)calloc(1, sizeof(*s));
  InitCommandPrefixCodes(s);
  return s;
}

BrotliTwoPassArena* ent_c_new_two_pass_arena(void) {
  return (BrotliTwoPassArena*)calloc(1, sizeof(BrotliTwoPassArena));
}

void ent_c_free(void* p) { free(p); }

void ent_c_compress_fragment_fast(BrotliOnePassArena* s, const uint8_t* input,
    size_t input_size, int is_last, int* table, size_t table_size,
    size_t* storage_ix, uint8_t* storage) {
  BrotliCompressFragmentFast(s, input, input_size,
                             is_last ? BROTLI_TRUE : BROTLI_FALSE, table,
                             table_size, storage_ix, storage);
}

void ent_c_compress_fragment_two_pass(BrotliTwoPassArena* s,
    const uint8_t* input, size_t input_size, int is_last,
    uint32_t* command_buf, uint8_t* literal_buf, int* table,
    size_t table_size, size_t* storage_ix, uint8_t* storage) {
  BrotliCompressFragmentTwoPass(s, input, input_size,
                                is_last ? BROTLI_TRUE : BROTLI_FALSE,
                                command_buf, literal_buf, table, table_size,
                                storage_ix, storage);
}

/* Static context maps of encode.c (ChooseContextMap /
   ShouldUseComplexStaticContextMap). */
const uint32_t* ent_c_static_context_map(int which) {
  static const uint32_t kStaticContextMapContinuation[64] = {
    1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  static const uint32_t kStaticContextMapSimpleUTF8[64] = {
    0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  static const uint32_t kStaticContextMapComplexUTF8[64] = {
    11, 11, 12, 12, /* 0 special */
    0, 0, 0, 0, /* 4 lf */
    1, 1, 9, 9, /* 8 space */
    2, 2, 2, 2, /* !, first after space/lf and after something else. */
    1, 1, 1, 1, /* " */
    8, 3, 3, 3, /* % */
    1, 1, 1, 1, /* ({[ */
    2, 2, 2, 2, /* }]) */
    8, 4, 4, 4, /* :; */
    8, 7, 4, 4, /* . */
    8, 0, 0, 0, /* > */
    3, 3, 3, 3, /* [0..9] */
    5, 5, 10, 5, /* [A-Z] */
    5, 5, 10, 5,
    6, 6, 6, 6, /* [a-z] */
    6, 6, 6, 6,
  };
  switch (which) {
    case 2: return kStaticContextMapSimpleUTF8;
    case 3: return kStaticContextMapContinuation;
    case 13: return kStaticContextMapComplexUTF8;
    default: return NULL;
  }
}
