# Differential fuzzing: Rust vs. C

These libFuzzer targets run the Rust implementation and the reference C
implementation (`../../c`, compiled with every exported symbol renamed to
`ref_*`) side by side through the **public C API** and abort on the first
observable difference.

| Target | What is compared |
| --- | --- |
| `fuzz_decode` | `BrotliDecoderDecompressStream` in lockstep with fuzzer-chosen input/output chunk sizes (incl. 0/1-byte buffers and the `TakeOutput` workflow): return codes, consumed/produced bytes, output, `total_out`, error code and string, `HasMoreOutput`/`IsUsed`/`IsFinished`, metadata callbacks, behavior after the end of the stream; `BrotliDecoderDecompress` incl. undersized buffers; compound dictionaries; parameters; custom allocators (the Rust side gets garbage-filled memory); allocation-failure injection (the n-th allocation fails on both sides; allocation counts must match); leak checks. |
| `fuzz_encode` | A fuzzer-chosen parameter set (all qualities, windows up to 30 incl. large window, modes, lgblock, size hint, npostfix/ndirect, stream offset, base64 mode, SIMD hasher options, out-of-range values) and operation script (`PROCESS` / `FLUSH` / `EMIT_METADATA` / `FINISH`, arbitrary chunking, `TakeOutput`, out-of-protocol calls, prepared dictionaries) executed in lockstep, comparing every call; the produced stream is decoded again by both decoders; `BrotliEncoderCompress` with arbitrary output capacities (whole buffer compared); `MaxCompressedSize`, `EstimatePeakMemoryUsage`, `GetPreparedDictionarySize`. Input data is the fuzz input or expanded from it (repetitions, synthetic text, noise, runs, base64 regions). |

The Rust library is built with the `fuzz` cargo profile (release optimizations
plus debug assertions and overflow checks); both libraries are instrumented
for coverage feedback. The C reference is compiled with `-ffp-contract=off`
(see "Floating point" in `../README.md`) and, inside the encoder fuzzer, uses
a zero-filling allocator, so that it is deterministic even where it reads
uninitialized memory.

## Running

    ./build.sh                       # needs clang with libFuzzer (Homebrew LLVM on macOS)
    python3 gen_seeds.py             # seed corpora from ../../tests/testdata
    ./out/fuzz_decode -fork=4 -ignore_crashes=1 -artifact_prefix=artifacts/ corpus/decode
    ./out/fuzz_encode -fork=4 -ignore_crashes=1 -timeout=300 -max_len=70000 -artifact_prefix=artifacts/ corpus/encode
    FUZZ_ENCODE_CAP=8192 ./out/fuzz_encode -max_len=8192 ...   # many small sessions

`FUZZ_TRACE=1` makes `fuzz_encode` print every call of the operation script.
Inputs that once revealed a difference are kept in `regressions/`; replay them
with `./out/fuzz_encode regressions/encode/*` (and `fuzz_decode` for
`regressions/decode/`).

## Findings

Differences found so far, all fixed:

* **Rust:** `insert_length` arithmetic must wrap like C's `size_t` when a
  copy jumps over a `;base64,` trigger (overflow check, no output change).
* **C bug:** after a metadata block was drained through the 16-byte
  `tiny_buf_`, a quality 0/1 flush that needs padding wrote the padding past
  `tiny_buf_` into `remaining_metadata_bytes_`, after which every
  `BrotliEncoderCompressStream` call failed (`regressions/encode/tiny-buf-padding-overflow`).
* **C bug:** in base64 mode, a repeated base64 region was emitted as a copy
  but its region record was moved into the copy; the region was then mapped
  onto the following literals, which were forced into the base64 block and
  written with zero-length codes (reading uninitialized memory) — the stream
  did not decode.
* **Compiler bug (not a difference of the port):** on aarch64 Linux,
  Debian clang 14.0.6 at `-O1` and above miscompiles `UTF8Position()` inlined
  into the sliding window loop of `EstimateBitCostsForLiteralsUTF8()`
  (`c/enc/literal_cost.c`, UBSan-clean code): the C reference then computes
  different literal costs and emits a different (valid) stream at qualities
  10/11 (`regressions/encode/clang14-aarch64-literal-cost-miscompile`). gcc,
  clang 14 at `-O0`, Apple clang 21 and LLVM 23 at all optimization levels
  agree with the Rust port. Use a different compiler for the C reference.
* Harness: operation values outside `BrotliEncoderOperation` make both
  encoders loop forever; the harness only uses valid values.
