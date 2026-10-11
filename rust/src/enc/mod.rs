//! Port of `c/enc`: the Brotli encoder.

// Foundation (shared types and utilities).
pub mod command;
pub mod compound_dictionary;
pub mod encoder_dict;
pub mod fast_log;
pub mod find_match_length;
pub mod literal_cost;
pub mod memory;
pub mod params;
pub mod prefix;
pub mod quality;
pub mod ringbuffer;
pub mod static_dict_lut;
pub mod static_dict_tables;
pub mod utf8_util;
pub mod write_bits;

// Entropy coding / bit stream side.
pub mod bit_cost;
pub mod block_splitter;
pub mod brotli_bit_stream;
pub mod cluster;
pub mod compress_fragment;
pub mod compress_fragment_two_pass;
pub mod entropy_encode;
pub mod entropy_encode_static;
pub mod histogram;
pub mod metablock;

// Matching side.
pub mod backward_references;
pub mod backward_references_hq;
pub mod hash;
pub mod static_dict;

// Top level.
pub mod encode;
