# Porting brotli from C to Rust — conventions

This crate is a **faithful port** of the reference C implementation in `../c`
(this exact revision). Goals, in priority order:

1. **Bit-exact behavior.** The encoder must produce byte-identical output to
   the C encoder for every parameter combination; the decoder must behave
   identically to the C decoder for every input *and every chunking* of
   input/output buffers (same return codes, same bytes consumed/produced per
   call, same error codes). This is verified by differential fuzzing against
   the C library.
2. **C ABI/API compatibility.** `src/ffi/*` exports exactly the symbols of
   `c/include/brotli/*.h` (plus the soft-private common symbols).
3. Memory safety: safe Rust with slices + indices; `unsafe` only where
   unavoidable (FFI, client-owned memory) and with a `// SAFETY:` comment.
4. Performance comparable to C (avoid gratuitous copies / allocations in hot
   loops).

## Toolchain

The Homebrew `rustc` on this machine is broken; always use rustup's:

    export PATH=$HOME/.cargo/bin:$PATH

## Porting rules

* Port function by function, keeping C names recognizable (`snake_case` of the
  C name, e.g. `BrotliStoreMetaBlock` → `brotli_store_meta_block`,
  `FindLongestMatchH5` → method `find_longest_match` on `H5`). Keep the C
  comments that explain *why*.
* Keep the **exact arithmetic**:
  * C integer types → same-width Rust types (`size_t` → `usize`, `int` →
    `i32`, `uint32_t` → `u32`, ...). Mirror C conversions with `as`.
  * Where C relies on unsigned wrap-around, use `wrapping_*` explicitly (we
    fuzz with overflow checks enabled; an unintended overflow panics).
  * C `float` → `f32`, `double` → `f64`; keep the evaluation order and the
    precision of every intermediate exactly as C does (C promotes
    `float op double` to double, `float op float` stays float, int→float
    conversions, etc.). **Never** use `mul_add` (the C reference is compiled
    with `-ffp-contract=off`). `log2` → `f64::log2`.
  * Comparisons involving floats: keep the same operator (`<` vs `<=`) and
    operand order.
* Templates (`*_inc.h` with `FN()` / `HASHER()` macros): use generics,
  traits, const generics or macros — whatever keeps the code identical for
  every instantiation.
* `BROTLI_64_BITS`, `BROTLI_MAX_SIMD_QUALITY` etc.: mirror the C platform
  logic with `cfg(target_pointer_width = "64")` (see `enc/quality.rs`).
  SSE2/NEON code paths in C compute the same results as their portable
  fallbacks; port the portable code (or anything producing identical
  results).
* `BROTLI_DCHECK` → `debug_assert!`. `BROTLI_LOG`/dumps → omit.

## Memory

* Every heap allocation that C does via `BROTLI_ALLOC` / `BROTLI_DECODER_ALLOC`
  must go through the client allocator: use
  `crate::common::alloc::Buf<T>` (`Buf::new(m, n)` aborts the process on
  OOM, which is the encoder's C policy `BROTLI_ENCODER_EXIT_ON_OOM`;
  `Buf::try_new` returns `None`, used by the decoder to report
  `BROTLI_DECODER_ERROR_ALLOC_*`). `Buf` is zero/default-initialized,
  derefs to a slice, frees on drop. `Buf::ensure_capacity` is
  `BROTLI_ENSURE_CAPACITY`. Single objects: `Boxed<T>`.
* Do **not** use `Vec`/`Box` for data that C allocates on the heap (it would
  bypass the client allocator). Stack arrays where C uses stack arrays are
  fine (beware of huge ones).
* The encoder `MemoryManager` is `crate::common::alloc::Allocator` (`Copy`).

## Module ownership (parallel porting)

Each module file has an `OWNER:` line. Only edit files you own. If you
need something from a file you do not own, implement a private helper in
your own module and mention it in your report. The `pub` signatures already
present in the skeleton stubs are **the contract** between modules: implement
them exactly (you may add more `pub` items). Submodules go into a directory
named after your file (e.g. `src/enc/hash/h5.rs` declared from
`src/enc/hash.rs`), so you never need to touch `src/enc/mod.rs`.

Foundation (already done, owner: main): `src/common/*`, `src/enc/{command,
compound_dictionary, encoder_dict, fast_log, find_match_length, literal_cost,
memory, params, prefix, quality, ringbuffer, static_dict_lut,
static_dict_tables, utf8_util, write_bits}.rs`, `src/enc/encode.rs`,
`src/ffi/{mod,common,enc}.rs`, `build.rs`, `Cargo.toml`.

## Static tables

Never retype tables by hand. Generate them from the C sources with a small C
program that `#include`s the C file and prints Rust (see
`tools/gen_common_tables.c`, `tools/gen_enc_dict_tables.c`). Floats: print
with `%.17e` (round-trips exactly).

## Testing against C

`cargo test --features c-reference` compiles the reference C library from
`../c` with all exported symbols renamed to `ref_*` (see
`tools/ref_prefix.h`; bindings in `tests/cref/mod.rs`) and links it into the
tests. Internal C functions (non-static ones like `BrotliStoreMetaBlock`, and
static inline ones via your own wrapper) can be exercised through **C shims**:
put `tests/c_shims/<owner>_*.c` files there (they are compiled with `-I../c`
and `-I../c/include` and the same `ref_` prefix header) and declare the shim
functions in your Rust integration test (`tests/<owner>_*.rs`). Plain C
structs shared with Rust must be `#[repr(C)]` (`Command`, `BrotliHasherParams`,
`BrotliDistanceParams`, `Base64Region`, `DictWord` already are).

Example test file header:

```rust
#![cfg(feature = "c-reference")]
mod cref; // tests/cref/mod.rs: ref_* public API bindings + helpers
extern "C" { fn my_shim(...); }
```

The final gate is differential fuzzing of the whole library against C.
