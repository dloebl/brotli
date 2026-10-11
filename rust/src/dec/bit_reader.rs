//! Port of `c/dec/bit_reader.h` / `bit_reader.c`: bit reading helpers.
//!
//! In C the bit reader keeps raw pointers into the current input buffer.
//! Here it keeps *indices* into the current input slice instead; every
//! function that actually touches input bytes receives that slice (`inp`)
//! explicitly.  The decoder guarantees that the indices always refer to the
//! slice that was last connected with [`BitReader::set_input`].

// Build knobs mirroring the C macros `BROTLI_BUILD_64_BIT`,
// `BROTLI_BUILD_32_BIT` and `BROTLI_BUILD_NO_UNALIGNED_READ_FAST`
// (`--cfg brotli_build_64_bit` etc.); used to test all platform variants.
#![allow(unexpected_cfgs)]

/// `brotli_reg_t`: `BROTLI_64_BITS` (platform.h) selects a 64-bit
/// accumulator on the targets that C recognizes as 64-bit
/// (`BROTLI_TARGET_64_BITS`), unless overridden.
#[cfg(any(
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
))]
pub type Reg = u64;
/// `brotli_reg_t`.
#[cfg(not(any(
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
)))]
pub type Reg = u32;

/// `BROTLI_64_BITS`.
pub const BROTLI_64_BITS: bool = core::mem::size_of::<Reg>() == 8;
const _: () = assert!(BROTLI_64_BITS == crate::common::platform::BROTLI_64_BITS);

/// `BROTLI_UNALIGNED_READ_FAST` (platform.h).
#[cfg(all(
    not(brotli_build_no_unaligned_read_fast),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        all(target_arch = "arm", target_feature = "v7")
    )
))]
pub const BROTLI_UNALIGNED_READ_FAST: bool = true;
/// `BROTLI_UNALIGNED_READ_FAST` (platform.h).
#[cfg(not(all(
    not(brotli_build_no_unaligned_read_fast),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        all(target_arch = "arm", target_feature = "v7")
    )
)))]
pub const BROTLI_UNALIGNED_READ_FAST: bool = false;

/// `BROTLI_IS_CONSTANT(n_bits)` for call sites that pass a literal constant:
/// GCC / Clang see the literal after the forced inlining of the bit reader
/// helpers (`__builtin_constant_p`), MSVC has no such builtin (always 0).
///
/// This choice is observable: it changes how many bytes are prefetched
/// into the accumulator, which in turn changes the chunking of metadata
/// delivered through the metadata chunk callback.
#[cfg(not(target_env = "msvc"))]
pub const BROTLI_IS_CONSTANT_LITERAL: bool = true;
/// `BROTLI_IS_CONSTANT(n_bits)` for literal call sites (MSVC: always 0).
#[cfg(target_env = "msvc")]
pub const BROTLI_IS_CONSTANT_LITERAL: bool = false;

const REG_BITS: Reg = (core::mem::size_of::<Reg>() << 3) as Reg;

/// `BROTLI_SHORT_FILL_BIT_WINDOW_READ`
pub const BROTLI_SHORT_FILL_BIT_WINDOW_READ: usize = core::mem::size_of::<Reg>() >> 1;

/// 162 bits + 7 bytes
pub const BROTLI_FAST_INPUT_SLACK: usize = 28;

/// `BitMask(n)`: same values as `kBrotliBitMask` for `n <= 32`.
#[inline(always)]
pub fn bit_mask(n: Reg) -> Reg {
    debug_assert!(n <= 32);
    ((1u64 << n) - 1) as Reg
}

#[inline(always)]
fn load16le(inp: &[u8], i: usize) -> Reg {
    let b = &inp[i..i + 2];
    u16::from_le_bytes([b[0], b[1]]) as Reg
}

#[inline(always)]
fn load32le(inp: &[u8], i: usize) -> Reg {
    let b = &inp[i..i + 4];
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as Reg
}

#[inline(always)]
fn load64le(inp: &[u8], i: usize) -> u64 {
    let b = &inp[i..i + 8];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// `BrotliBitReader`.
#[derive(Clone, Copy, Debug, Default)]
pub struct BitReader {
    /// pre-fetched bits
    pub val: Reg,
    /// current bit-reading position in val
    pub bit_pos: Reg,
    /// the byte we're reading from
    pub next_in: usize,
    /// position from which "fast-path" is prohibited
    pub guard_in: usize,
    /// == next_in + avail_in
    pub last_in: usize,
}

/// `BrotliBitReaderState` (memento).
#[derive(Clone, Copy, Debug, Default)]
pub struct BitReaderState {
    pub val: Reg,
    pub bit_pos: Reg,
    pub next_in: usize,
    pub avail_in: usize,
}

/// `BrotliLoadBits`.
#[inline(always)]
fn load_bits(val: Reg, new_bits: Reg, _count: Reg, offset: Reg) -> Reg {
    val | (new_bits << offset)
}

impl BitReader {
    /// `BrotliInitBitReader`.
    pub fn init(&mut self) {
        self.val = 0;
        self.bit_pos = 0;
    }

    /// `BrotliWarmupBitReader`: ensures that the accumulator is not empty.
    /// May consume up to `sizeof(brotli_reg_t) - 1` bytes of input.
    pub fn warmup(&mut self, inp: &[u8]) -> bool {
        let mut aligned_read_mask: usize = (core::mem::size_of::<Reg>() >> 1) - 1;
        // Fixing alignment after unaligned BrotliFillWindow would result
        // accumulator overflow. If unalignment is caused by
        // BrotliSafeReadBits, then there is enough space in accumulator to
        // fix alignment.
        if BROTLI_UNALIGNED_READ_FAST {
            aligned_read_mask = 0;
        }
        if self.get_available_bits() == 0 {
            self.val = 0;
            if !self.pull_byte(inp) {
                return false;
            }
        }
        while ((inp.as_ptr() as usize).wrapping_add(self.next_in) & aligned_read_mask) != 0 {
            if !self.pull_byte(inp) {
                // If we consumed all the input, we don't care about the
                // alignment.
                return true;
            }
        }
        true
    }

    /// `BrotliSafeReadBits32Slow`.
    #[inline(never)]
    pub fn safe_read_bits32_slow(&mut self, inp: &[u8], n_bits: Reg, val: &mut Reg) -> bool {
        debug_assert!(n_bits <= 32);
        debug_assert!(n_bits > 24);
        let memento = self.save_state();
        let mut low_val: Reg = 0;
        let mut high_val: Reg = 0;
        if !self.safe_read_bits(inp, 16, &mut low_val) || !self.safe_read_bits(inp, n_bits - 16, &mut high_val) {
            self.restore_state(&memento);
            return false;
        }
        *val = low_val | (high_val << 16);
        true
    }

    /// `BrotliBitReaderGetAvailIn`.
    #[inline(always)]
    pub fn get_avail_in(&self) -> usize {
        self.last_in.wrapping_sub(self.next_in)
    }

    /// `BrotliBitReaderSaveState`.
    #[inline(always)]
    pub fn save_state(&self) -> BitReaderState {
        BitReaderState { val: self.val, bit_pos: self.bit_pos, next_in: self.next_in, avail_in: self.get_avail_in() }
    }

    /// `BrotliBitReaderSetInput`.
    #[inline(always)]
    pub fn set_input(&mut self, next_in: usize, avail_in: usize) {
        self.next_in = next_in;
        self.last_in = if avail_in == 0 { next_in } else { next_in.wrapping_add(avail_in) };
        if avail_in.wrapping_add(1) > BROTLI_FAST_INPUT_SLACK {
            self.guard_in = next_in.wrapping_add(avail_in.wrapping_add(1) - BROTLI_FAST_INPUT_SLACK);
        } else {
            self.guard_in = next_in;
        }
    }

    /// `BrotliBitReaderRestoreState`.
    #[inline(always)]
    pub fn restore_state(&mut self, from: &BitReaderState) {
        self.val = from.val;
        self.bit_pos = from.bit_pos;
        self.next_in = from.next_in;
        self.set_input(from.next_in, from.avail_in);
    }

    /// `BrotliGetAvailableBits`.
    #[inline(always)]
    pub fn get_available_bits(&self) -> Reg {
        self.bit_pos
    }

    /// `BrotliGetRemainingBytes`: amount of unread bytes the bit reader
    /// still has buffered from the input, including whole bytes in `val`.
    /// Capped with the maximal ring-buffer size.
    #[inline(always)]
    pub fn get_remaining_bytes(&self) -> usize {
        const K_CAP: usize = 1usize << crate::common::constants::BROTLI_LARGE_MAX_WBITS;
        let avail_in = self.get_avail_in();
        if avail_in > K_CAP {
            return K_CAP;
        }
        avail_in + (self.get_available_bits() >> 3) as usize
    }

    /// `BrotliCheckInputAmount`: checks if there are at least
    /// `BROTLI_FAST_INPUT_SLACK` bytes left in the input.
    #[inline(always)]
    pub fn check_input_amount(&self) -> bool {
        self.next_in < self.guard_in
    }

    /// `BrotliFillBitWindow` for a compile-time constant `n_bits <= 8`.
    #[inline(always)]
    pub fn fill_bit_window_8(&mut self, inp: &[u8]) {
        if BROTLI_UNALIGNED_READ_FAST && BROTLI_IS_CONSTANT_LITERAL {
            let bit_pos = self.bit_pos;
            if BROTLI_64_BITS {
                if bit_pos <= 8 {
                    self.val = load_bits(self.val, load64le(inp, self.next_in) as Reg, 56, bit_pos);
                    self.bit_pos = bit_pos + 56;
                    self.next_in += 7;
                }
            } else if bit_pos <= 8 {
                self.val = load_bits(self.val, load32le(inp, self.next_in), 24, bit_pos);
                self.bit_pos = bit_pos + 24;
                self.next_in += 3;
            }
        } else {
            self.fill_bit_window_generic(inp);
        }
    }

    /// `BrotliFillBitWindow` for a compile-time constant `8 < n_bits <= 16`.
    #[inline(always)]
    pub fn fill_bit_window_16(&mut self, inp: &[u8]) {
        if BROTLI_64_BITS && BROTLI_UNALIGNED_READ_FAST && BROTLI_IS_CONSTANT_LITERAL {
            let bit_pos = self.bit_pos;
            if bit_pos <= 16 {
                self.val = load_bits(self.val, load64le(inp, self.next_in) as Reg, 48, bit_pos);
                self.bit_pos = bit_pos + 48;
                self.next_in += 6;
            }
        } else {
            self.fill_bit_window_generic(inp);
        }
    }

    /// `BrotliFillBitWindow` for a non-constant `n_bits` (or a constant
    /// larger than 16): guarantees at least 33 (64-bit) / 17 (32-bit) bits.
    #[inline(always)]
    pub fn fill_bit_window_generic(&mut self, inp: &[u8]) {
        let bit_pos = self.bit_pos;
        if BROTLI_64_BITS {
            if bit_pos <= 32 {
                self.val = load_bits(self.val, load32le(inp, self.next_in), 32, bit_pos);
                self.bit_pos = bit_pos + 32;
                self.next_in += BROTLI_SHORT_FILL_BIT_WINDOW_READ;
            }
        } else if bit_pos <= 16 {
            self.val = load_bits(self.val, load16le(inp, self.next_in), 16, bit_pos);
            self.bit_pos = bit_pos + 16;
            self.next_in += BROTLI_SHORT_FILL_BIT_WINDOW_READ;
        }
    }

    /// `BrotliFillBitWindow16`: guarantees only 16 bits and reads no more
    /// than `BROTLI_SHORT_FILL_BIT_WINDOW_READ` bytes of input.
    #[inline(always)]
    pub fn fill_bit_window16(&mut self, inp: &[u8]) {
        // BrotliFillBitWindow(br, 17)
        self.fill_bit_window_generic(inp);
    }

    /// `BrotliPullByte`: tries to pull one byte of input to accumulator.
    #[inline(always)]
    pub fn pull_byte(&mut self, inp: &[u8]) -> bool {
        if self.next_in == self.last_in {
            return false;
        }
        self.val = load_bits(self.val, inp[self.next_in] as Reg, 8, self.bit_pos);
        self.bit_pos += 8;
        self.next_in += 1;
        true
    }

    /// `BrotliGetBitsUnmasked`.
    #[inline(always)]
    pub fn get_bits_unmasked(&self) -> Reg {
        self.val
    }

    /// `BrotliGet16BitsUnmasked`: the result contains at least 16 valid bits.
    #[inline(always)]
    pub fn get_16_bits_unmasked(&mut self, inp: &[u8]) -> Reg {
        self.fill_bit_window_16(inp);
        self.get_bits_unmasked()
    }

    /// `BrotliGetBits(br, 8)` (constant `n_bits <= 8`).
    #[inline(always)]
    pub fn get_bits_8(&mut self, inp: &[u8], n_bits: Reg) -> Reg {
        debug_assert!(n_bits <= 8);
        self.fill_bit_window_8(inp);
        self.get_bits_unmasked() & bit_mask(n_bits)
    }

    /// `BrotliSafeGetBits`: tries to peek the specified amount of bits.
    #[inline(always)]
    pub fn safe_get_bits(&mut self, inp: &[u8], n_bits: Reg, val: &mut Reg) -> bool {
        while self.get_available_bits() < n_bits {
            if !self.pull_byte(inp) {
                return false;
            }
        }
        *val = self.get_bits_unmasked() & bit_mask(n_bits);
        true
    }

    /// `BrotliDropBits`: advances the bit pos by `n_bits`.
    #[inline(always)]
    pub fn drop_bits(&mut self, n_bits: Reg) {
        self.bit_pos = self.bit_pos.wrapping_sub(n_bits);
        self.val >>= n_bits;
    }

    /// `BrotliBitReaderNormalize`: makes sure that there are no spectre bits
    /// in the accumulator.
    #[inline(always)]
    pub fn normalize(&mut self) {
        if self.bit_pos < REG_BITS {
            self.val &= ((1 as Reg) << self.bit_pos).wrapping_sub(1);
        }
    }

    /// `BrotliBitReaderUnload`.
    #[inline(always)]
    pub fn unload(&mut self) {
        let unused_bytes = self.get_available_bits() >> 3;
        let unused_bits = unused_bytes << 3;
        debug_assert!(unused_bytes as usize <= self.next_in);
        self.next_in = if unused_bytes == 0 { self.next_in } else { self.next_in.wrapping_sub(unused_bytes as usize) };
        self.bit_pos -= unused_bits;
        self.normalize();
    }

    /// `BrotliTakeBits`. Precondition: accumulator MUST contain at least
    /// `n_bits`.
    #[inline(always)]
    pub fn take_bits(&mut self, n_bits: Reg) -> Reg {
        let val = self.get_bits_unmasked() & bit_mask(n_bits);
        self.drop_bits(n_bits);
        val
    }

    /// `BrotliReadBits24`: assumes that there is enough input to perform
    /// BrotliFillBitWindow.
    #[inline(always)]
    pub fn read_bits24(&mut self, inp: &[u8], n_bits: Reg) -> Reg {
        debug_assert!(n_bits <= 24);
        if BROTLI_64_BITS || n_bits <= 16 {
            self.fill_bit_window_generic(inp);
            self.take_bits(n_bits)
        } else {
            self.fill_bit_window_generic(inp); // BrotliFillBitWindow(br, 16)
            let low_val = self.take_bits(16);
            self.fill_bit_window_8(inp); // BrotliFillBitWindow(br, 8)
            let high_val = self.take_bits(n_bits - 16);
            low_val | (high_val << 16)
        }
    }

    /// `BrotliReadBits32`: same as `read_bits24`, but up to 32 bits.
    #[inline(always)]
    pub fn read_bits32(&mut self, inp: &[u8], n_bits: Reg) -> Reg {
        debug_assert!(n_bits <= 32);
        if BROTLI_64_BITS || n_bits <= 16 {
            self.fill_bit_window_generic(inp);
            self.take_bits(n_bits)
        } else {
            self.fill_bit_window_generic(inp); // BrotliFillBitWindow(br, 16)
            let low_val = self.take_bits(16);
            self.fill_bit_window_generic(inp); // BrotliFillBitWindow(br, 16)
            let high_val = self.take_bits(n_bits - 16);
            low_val | (high_val << 16)
        }
    }

    /// `BrotliSafeReadBits`: tries to read the specified amount of bits.
    /// Up to 24 bits are allowed.
    #[inline(always)]
    pub fn safe_read_bits(&mut self, inp: &[u8], n_bits: Reg, val: &mut Reg) -> bool {
        debug_assert!(n_bits <= 24);
        while self.get_available_bits() < n_bits {
            if !self.pull_byte(inp) {
                return false;
            }
        }
        *val = self.take_bits(n_bits);
        true
    }

    /// `BrotliSafeReadBits32`: same as `safe_read_bits`, up to 32 bits.
    #[inline(always)]
    pub fn safe_read_bits32(&mut self, inp: &[u8], n_bits: Reg, val: &mut Reg) -> bool {
        debug_assert!(n_bits <= 32);
        if BROTLI_64_BITS || n_bits <= 24 {
            while self.get_available_bits() < n_bits {
                if !self.pull_byte(inp) {
                    return false;
                }
            }
            *val = self.take_bits(n_bits);
            true
        } else {
            self.safe_read_bits32_slow(inp, n_bits, val)
        }
    }

    /// `BrotliJumpToByteBoundary`: advances the bit reader position to the
    /// next byte boundary and verifies that any skipped bits are zero.
    #[inline(always)]
    pub fn jump_to_byte_boundary(&mut self) -> bool {
        let pad_bits_count = self.get_available_bits() & 0x7;
        let mut pad_bits: Reg = 0;
        if pad_bits_count != 0 {
            pad_bits = self.take_bits(pad_bits_count);
        }
        self.normalize();
        pad_bits == 0
    }

    /// `BrotliDropBytes`.
    #[inline(always)]
    pub fn drop_bytes(&mut self, num: usize) {
        // Check detour is legal: accumulator must to be empty.
        debug_assert!(self.bit_pos == 0);
        debug_assert!(self.val == 0);
        self.next_in += num;
    }

    /// `BrotliCopyBytes`: copies remaining input bytes stored in the bit
    /// reader to `dest`. `num` may not be larger than
    /// `get_remaining_bytes`.
    #[inline(always)]
    pub fn copy_bytes(&mut self, dest: &mut [u8], inp: &[u8], mut num: usize) {
        let mut d = 0usize;
        while self.get_available_bits() >= 8 && num > 0 {
            dest[d] = self.get_bits_unmasked() as u8;
            self.drop_bits(8);
            d += 1;
            num -= 1;
        }
        self.normalize();
        if num > 0 {
            dest[d..d + num].copy_from_slice(&inp[self.next_in..self.next_in + num]);
            self.drop_bytes(num);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bit_mask_matches_c_table() {
        for n in 0..=32u32 {
            assert_eq!(bit_mask(n as Reg) as u64, super::super::tables::K_BROTLI_BIT_MASK[n as usize] as u64);
        }
    }
}
