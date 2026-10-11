# Brotli in Rust

This directory contains the implementation of the brotli libraries
(`libbrotlicommon`, `libbrotlidec`, `libbrotlienc`) in Rust. It is a faithful,
function-by-function port of the C implementation in [`../c`](../c) and is a
**drop-in replacement** for it:

* **Same API** – the public headers in [`../c/include/brotli`](../c/include/brotli)
  are unchanged; C/C++ code compiles against them as before.
* **Same ABI** – the shared libraries have the same names, SONAMEs /
  install names, versions and *exactly* the same exported symbols as the C
  build (`BrotliEncoder*`, `BrotliDecoder*`, `BrotliSharedDictionary*`, plus the
  "soft-private" `BrotliGetDictionary`, `BrotliGetTransforms`,
  `BrotliTransformDictionaryWord`, `BrotliDefaultAllocFunc`,
  `BrotliDefaultFreeFunc`, `BrotliSetDictionaryData`,
  `_kBrotliContextLookupTable`, `_kBrotliPrefixCodeRanges`). Binaries linked
  against the C libraries run unchanged against the Rust ones.
* **Same behavior** – the encoder produces byte-identical output for every
  parameter combination; the decoder behaves identically for every input and
  every chunking of input/output buffers (return codes, bytes consumed and
  produced per call, error codes, metadata callbacks, custom allocator use,
  allocation-failure handling). This is verified by differential fuzzing
  against the C implementation (see [`fuzz/`](fuzz/README.md)).

## Building

The libraries are built by the top-level CMake project (Rust is the default):

    mkdir out && cd out
    cmake -DCMAKE_BUILD_TYPE=Release ..
    cmake --build . && ctest

This requires a Rust toolchain (`cargo`, Rust ≥ 1.70; see https://rustup.rs).
Options:

| CMake variable | Meaning |
| --- | --- |
| `BROTLI_USE_RUST` (`ON`) | `OFF` builds the C implementation from `c/` instead |
| `BUILD_SHARED_LIBS`, `BROTLI_BUILD_FOR_PACKAGE` | as before |
| `BROTLI_BUILD_ENC_EXTRA_API` (`OFF`) | also export `BrotliEncoderEstimatePeakMemoryUsage` / `BrotliEncoderGetPreparedDictionarySize` from the shared `libbrotlienc` (they are hidden by default, like in the C build) |
| `BROTLI_CARGO`, `BROTLI_RUST_TARGET`, `BROTLI_RUST_PROFILE` | cargo executable, target triple (cross builds), cargo profile |

The Python extension can be built against the Rust library with
`USE_RUST_BROTLI=1 python setup.py build_ext` (or `pip install`).

### How the libraries are produced

`capi/` is a `no_std` `staticlib` crate exporting the C ABI; its archive only
depends on libc (`malloc`, `free`, `exit`, `abort`, `write`) and libm (`log2`) —
no Rust runtime. CMake ([`cmake/BrotliRust.cmake`](cmake/BrotliRust.cmake))
links the three shared libraries from it, each with its own export list
([`cmake/*.sym`](cmake)) and dead-code stripping; the three static libraries
are copies of the archive (linking any combination of them works, as archive
members are only pulled in once).

## Layout

| Rust | C original |
| --- | --- |
| `src/common/` | `c/common/` (dictionary, transforms, context, constants, shared dictionary) |
| `src/dec/` | `c/dec/` (bit reader, Huffman decoding, state machine) |
| `src/enc/` | `c/enc/` (one module per C file; hashers in `src/enc/hash/`) |
| `src/ffi/` | the C ABI (`common.rs`, `dec.rs`, `enc.rs`) |
| `capi/` | the C ABI static library |
| `tools/` | generators that extract the static tables from the C sources |

The code is safe Rust except for the FFI layer, the client allocator
(`common/alloc.rs`), the raw-pointer `BrotliTransformDictionaryWord` export and
access to client-owned dictionary memory. All heap memory is allocated through
the client's `alloc_func`/`free_func` (`Buf<T>`), like in C; the encoder
terminates the process on allocation failure (C's default
`BROTLI_ENCODER_EXIT_ON_OOM` policy), the decoder reports
`BROTLI_DECODER_ERROR_ALLOC_*`.

The crate (`brotli`, `no_std`) can also be used directly from Rust
(`brotli::enc::encode::BrotliEncoderState`, `brotli::dec::Decoder`), but its
API mirrors the C one and is not designed as an idiomatic Rust API.

## Testing

    cargo test --release --features c-reference

The `c-reference` feature compiles the C implementation from `../c` with all
exported symbols renamed to `ref_*` ([`tools/ref_prefix.h`](tools/ref_prefix.h))
and links it into the tests, which then compare both implementations: the
decoder in lockstep on all test vectors, generated and corrupted streams with
random chunking and allocation-failure injection; every hasher, the backward
reference search and Zopfli; metablock building and bit stream writing (via C
shims in `tests/c_shims/`); the whole encoder; and the common API exhaustively.
See [`PORTING.md`](PORTING.md) for the porting conventions.

## Notes on compatibility

* **Floating point.** The encoder's heuristics use floating point. The Rust
  port implements strict IEEE-754 semantics, i.e. it is identical to the C
  library on x86-64 and to any C build without excess precision or
  contraction (`-ffp-contract=off`). C builds that fuse multiply-adds (the
  default of clang/gcc on AArch64 and other FMA targets) or that use x87
  excess precision (32-bit x86 without SSE2 math) can make slightly different
  encoder decisions, i.e. the C library's own output already differs between
  platforms in rare cases. Decoding is unaffected (integer only).
* **Pointer width.** As in C, the encoder's match scoring depends on
  `sizeof(size_t)` and the SIMD hashers (qualities 5–7) only exist on 64-bit
  targets; the decoder uses the 64-bit bit reader on 64-bit targets. The Rust
  port mirrors this, so it matches the C library *of the same target*
  (verified on aarch64 macOS/Linux and i686 Linux).
* **Compilers.** Differential fuzzing on Linux revealed that clang 14 (LLVM 14)
  miscompiles part of `c/enc/literal_cost.c` on aarch64 (see
  [`fuzz/README.md`](fuzz/README.md)); C libraries built with it produce
  different (valid) output at qualities 10/11. The Rust port is not affected.
* **Invalid input values** behave like in C, e.g. passing an operation that is
  not a `BrotliEncoderOperation` to `BrotliEncoderCompressStream` loops forever
  in both.
* **Bugs found in the C implementation** by the differential fuzzers were
  fixed in both implementations (see `../CHANGELOG.md`).
* Not ported: the `BROTLI_EXPERIMENTAL` serialized shared dictionaries (the
  public header documents `BROTLI_SHARED_DICTIONARY_SERIALIZED` as "DO NOT
  USE: methods accepting this value will fail", which is the behavior), and
  the non-default C build switches (`BROTLI_EXTERNAL_DICTIONARY_DATA`,
  lazy/early static initialization, `BROTLI_ENCODER_CLEANUP_ON_OOM`).
