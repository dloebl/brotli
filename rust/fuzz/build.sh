#!/bin/sh
# Builds the differential fuzzers (libFuzzer):
#   fuzz/out/fuzz_decode  - Rust decoder vs. C reference decoder
#   fuzz/out/fuzz_encode  - Rust encoder vs. C reference encoder
#
# Both the Rust library and the reference C library are instrumented for
# coverage feedback.  The Rust library is built with debug assertions and
# overflow checks (profile "fuzz").
#
# Environment:
#   CLANG       clang with libFuzzer support (default: Homebrew LLVM / clang)
#   SANITIZE    extra -fsanitize= list for the C parts (e.g. "address")
#   C_REF_DIR   reference C sources (default: ../c)
set -eu
cd "$(dirname "$0")"
FUZZ_DIR=$(pwd)
RUST_DIR=$(cd .. && pwd)
C_REF_DIR=${C_REF_DIR:-$RUST_DIR/../c}
OUT=$FUZZ_DIR/out
mkdir -p "$OUT/obj"

if [ -z "${CLANG:-}" ]; then
  if [ -x /opt/homebrew/opt/llvm/bin/clang ]; then CLANG=/opt/homebrew/opt/llvm/bin/clang; else CLANG=clang; fi
fi
SAN="fuzzer-no-link"
LINK_SAN="fuzzer"
if [ -n "${SANITIZE:-}" ]; then SAN="$SAN,$SANITIZE"; LINK_SAN="$LINK_SAN,$SANITIZE"; fi
SYSROOT=""
if [ "$(uname)" = "Darwin" ]; then SYSROOT="-isysroot $(xcrun --show-sdk-path)"; fi

# 1. Rust library with sanitizer coverage.
TARGET=$(rustc -vV | sed -n 's/^host: //p')
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares -Cforce-frame-pointers=yes" \
  cargo build --manifest-path "$RUST_DIR/Cargo.toml" -p brotli-capi --profile fuzz --target "$TARGET" \
  --target-dir "$FUZZ_DIR/target"
RUST_LIB="$FUZZ_DIR/target/$TARGET/fuzz/libbrotli_capi.a"

# 2. Reference C library, all exported symbols renamed to ref_*.
CFLAGS="-O2 -g -fno-omit-frame-pointer -ffp-contract=off -fsanitize=$SAN $SYSROOT"
for f in "$C_REF_DIR"/common/*.c "$C_REF_DIR"/dec/*.c "$C_REF_DIR"/enc/*.c; do
  o="$OUT/obj/ref_$(basename "$(dirname "$f")")_$(basename "$f" .c).o"
  $CLANG $CFLAGS -I"$C_REF_DIR/include" -include "$RUST_DIR/tools/ref_prefix.h" -c "$f" -o "$o" &
done
wait
$CLANG $CFLAGS -I"$C_REF_DIR/include" -include "$RUST_DIR/tools/ref_prefix.h" -c api_ref.c -o "$OUT/obj/api_ref.o"
$CLANG $CFLAGS -I"$C_REF_DIR/include" -c api_rust.c -o "$OUT/obj/api_rust.o"

# 3. Harnesses.
for t in fuzz_decode fuzz_encode; do
  $CLANG $CFLAGS -I"$C_REF_DIR/include" -c $t.c -o "$OUT/obj/$t.o"
  $CLANG -fsanitize=$LINK_SAN $SYSROOT -o "$OUT/$t" "$OUT/obj/$t.o" "$OUT/obj/api_rust.o" "$OUT/obj/api_ref.o" \
    "$OUT"/obj/ref_*.o "$RUST_LIB" -lm
done
echo "built: $OUT/fuzz_decode $OUT/fuzz_encode"
