//! Port of the platform detection of `c/common/platform.h` that affects
//! observable behavior.

#![allow(unexpected_cfgs)]

/// `BROTLI_64_BITS`: C enables its 64-bit code paths on the architectures it
/// recognizes as 64-bit (`BROTLI_TARGET_64_BITS`: x86-64, AArch64,
/// PowerPC64, RISC-V 64, LoongArch64, MIPS64), *not* based on the pointer
/// width (e.g. s390x is 64-bit but excluded).  `BROTLI_BUILD_64_BIT` /
/// `BROTLI_BUILD_32_BIT` correspond to `--cfg brotli_build_64_bit` /
/// `--cfg brotli_build_32_bit`.
///
/// Affects the decoder's bit reader width and, in the encoder, the
/// availability of the SIMD hashers (`BROTLI_TZCNT64` →
/// `BROTLI_MAX_SIMD_QUALITY`).
pub const BROTLI_64_BITS: bool = cfg!(any(
    brotli_build_64_bit,
    all(
        not(brotli_build_32_bit),
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "powerpc64",
            target_arch = "riscv64",
            target_arch = "loongarch64",
            target_arch = "mips64",
            target_arch = "mips64r6"
        )
    )
));
