//! Port of `c/enc/command.h` / `command.c`.

use super::fast_log::log2_floor_non_zero;
use super::params::BrotliDistanceParams;
use super::prefix::prefix_encode_copy_distance;
use crate::common::constants::{BROTLI_NUM_DISTANCE_SHORT_CODES, BROTLI_NUM_INS_COPY_CODES};

pub static K_BROTLI_INS_BASE: [u32; BROTLI_NUM_INS_COPY_CODES] =
    [0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594];
pub static K_BROTLI_INS_EXTRA: [u32; BROTLI_NUM_INS_COPY_CODES] =
    [0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24];
pub static K_BROTLI_COPY_BASE: [u32; BROTLI_NUM_INS_COPY_CODES] =
    [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118];
pub static K_BROTLI_COPY_EXTRA: [u32; BROTLI_NUM_INS_COPY_CODES] =
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24];

/// `GetInsertLengthCode`.
#[inline(always)]
pub fn get_insert_length_code(insertlen: usize) -> u16 {
    if insertlen < 6 {
        insertlen as u16
    } else if insertlen < 130 {
        let nbits = log2_floor_non_zero(insertlen - 2) - 1;
        ((nbits << 1) as usize + ((insertlen - 2) >> nbits) + 2) as u16
    } else if insertlen < 2114 {
        (log2_floor_non_zero(insertlen - 66) + 10) as u16
    } else if insertlen < 6210 {
        21
    } else if insertlen < 22594 {
        22
    } else {
        23
    }
}

/// `GetCopyLengthCode`.
#[inline(always)]
pub fn get_copy_length_code(copylen: usize) -> u16 {
    if copylen < 10 {
        copylen.wrapping_sub(2) as u16
    } else if copylen < 134 {
        let nbits = log2_floor_non_zero(copylen - 6) - 1;
        ((nbits << 1) as usize + ((copylen - 6) >> nbits) + 4) as u16
    } else if copylen < 2118 {
        (log2_floor_non_zero(copylen - 70) + 12) as u16
    } else {
        23
    }
}

/// `CombineLengthCodes`.
#[inline(always)]
pub fn combine_length_codes(inscode: u16, copycode: u16, use_last_distance: bool) -> u16 {
    let bits64: u16 = (copycode & 0x7) | ((inscode & 0x7) << 3);
    if use_last_distance && inscode < 8 && copycode < 16 {
        if copycode < 8 {
            bits64
        } else {
            bits64 | 64
        }
    } else {
        // Specification: 5 Encoding of ... (last table)
        // offset = 2 * index, where index is in range [0..8]
        let mut offset: u32 = 2 * ((copycode as u32 >> 3) + 3 * (inscode as u32 >> 3));
        // All values in specification are K * 64, where
        //   K = [2, 3, 6, 4, 5, 8, 7, 9, 10],
        //   i + 1 = [1, 2, 3, 4, 5, 6, 7, 8,  9],
        //   K - i - 1 = [1, 1, 3, 0, 0, 2, 0, 1,  2] = D.
        offset = (offset << 5) + 0x40 + ((0x520D40u32 >> offset) & 0xC0);
        (offset as u16) | bits64
    }
}

/// `GetLengthCode`.
#[inline(always)]
pub fn get_length_code(insertlen: usize, copylen: usize, use_last_distance: bool) -> u16 {
    let inscode = get_insert_length_code(insertlen);
    let copycode = get_copy_length_code(copylen);
    combine_length_codes(inscode, copycode, use_last_distance)
}

#[inline(always)]
pub fn get_insert_base(inscode: u16) -> u32 {
    K_BROTLI_INS_BASE[inscode as usize]
}
#[inline(always)]
pub fn get_insert_extra(inscode: u16) -> u32 {
    K_BROTLI_INS_EXTRA[inscode as usize]
}
#[inline(always)]
pub fn get_copy_base(copycode: u16) -> u32 {
    K_BROTLI_COPY_BASE[copycode as usize]
}
#[inline(always)]
pub fn get_copy_extra(copycode: u16) -> u32 {
    K_BROTLI_COPY_EXTRA[copycode as usize]
}

/// `Command` (layout-compatible with the C struct).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Command {
    pub insert_len_: u32,
    /// Stores copy_len in low 25 bits and copy_code - copy_len in high 7 bit.
    pub copy_len_: u32,
    /// Stores distance extra bits.
    pub dist_extra_: u32,
    pub cmd_prefix_: u16,
    /// Stores distance code in low 10 bits and number of extra bits in high 6
    /// bits.
    pub dist_prefix_: u16,
}

impl Command {
    /// `InitCommand`.  `distance_code` is e.g. 0 for same-as-last short code,
    /// or 16 for offset 1.
    #[inline(always)]
    pub fn new(dist: &BrotliDistanceParams, insertlen: usize, copylen: usize, copylen_code_delta: i32, distance_code: usize) -> Command {
        // Don't rely on signed int representation, use honest casts.
        let delta: u32 = (copylen_code_delta as i8) as u8 as u32;
        let (dist_prefix_, dist_extra_) = prefix_encode_copy_distance(
            distance_code,
            dist.num_direct_distance_codes as usize,
            dist.distance_postfix_bits as usize,
        );
        let cmd_prefix_ = get_length_code(
            insertlen,
            (copylen as i64 + copylen_code_delta as i64) as usize,
            (dist_prefix_ & 0x3FF) == 0,
        );
        Command {
            insert_len_: insertlen as u32,
            copy_len_: (copylen as u32) | (delta << 25),
            dist_extra_,
            cmd_prefix_,
            dist_prefix_,
        }
    }

    /// `InitCommand` on an existing value.
    #[inline(always)]
    pub fn init(&mut self, dist: &BrotliDistanceParams, insertlen: usize, copylen: usize, copylen_code_delta: i32, distance_code: usize) {
        *self = Command::new(dist, insertlen, copylen, copylen_code_delta, distance_code);
    }

    /// `InitInsertCommand`.
    #[inline]
    pub fn new_insert(insertlen: usize) -> Command {
        Command {
            insert_len_: insertlen as u32,
            copy_len_: 4 << 25,
            dist_extra_: 0,
            dist_prefix_: BROTLI_NUM_DISTANCE_SHORT_CODES as u16,
            cmd_prefix_: get_length_code(insertlen, 4, false),
        }
    }

    /// `CommandRestoreDistanceCode`.
    #[inline]
    pub fn restore_distance_code(&self, dist: &BrotliDistanceParams) -> u32 {
        if (self.dist_prefix_ as u32 & 0x3FF) < BROTLI_NUM_DISTANCE_SHORT_CODES + dist.num_direct_distance_codes {
            self.dist_prefix_ as u32 & 0x3FF
        } else {
            let dcode = self.dist_prefix_ as u32 & 0x3FF;
            let nbits = self.dist_prefix_ as u32 >> 10;
            let extra = self.dist_extra_;
            let postfix_mask = (1u32 << dist.distance_postfix_bits) - 1;
            let hcode = (dcode - dist.num_direct_distance_codes - BROTLI_NUM_DISTANCE_SHORT_CODES) >> dist.distance_postfix_bits;
            let lcode = (dcode - dist.num_direct_distance_codes - BROTLI_NUM_DISTANCE_SHORT_CODES) & postfix_mask;
            let offset = ((2 + (hcode & 1)) << nbits).wrapping_sub(4);
            (offset.wrapping_add(extra) << dist.distance_postfix_bits)
                .wrapping_add(lcode)
                .wrapping_add(dist.num_direct_distance_codes)
                .wrapping_add(BROTLI_NUM_DISTANCE_SHORT_CODES)
        }
    }

    /// `CommandDistanceContext`.
    #[inline]
    pub fn distance_context(&self) -> u32 {
        let r = self.cmd_prefix_ as u32 >> 6;
        let c = self.cmd_prefix_ as u32 & 7;
        if (r == 0 || r == 2 || r == 4 || r == 7) && (c <= 2) {
            return c;
        }
        3
    }

    /// `CommandCopyLen`.
    #[inline(always)]
    pub fn copy_len(&self) -> u32 {
        self.copy_len_ & 0x1FFFFFF
    }

    /// `CommandCopyLenCode`.
    #[inline(always)]
    pub fn copy_len_code(&self) -> u32 {
        let modifier = self.copy_len_ >> 25;
        let delta: i32 = ((modifier | ((modifier & 0x40) << 1)) as u8) as i8 as i32;
        ((self.copy_len_ & 0x1FFFFFF) as i32).wrapping_add(delta) as u32
    }
}

/// Free-function aliases with the C names, for convenience of porting.
#[inline(always)]
pub fn init_insert_command(cmd: &mut Command, insertlen: usize) {
    *cmd = Command::new_insert(insertlen);
}
