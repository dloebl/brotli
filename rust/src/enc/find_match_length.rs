//! Port of `c/enc/find_match_length.h`.

/// `FindMatchLengthWithLimit`: number of equal leading bytes of `s1` and
/// `s2`, at most `limit`.
///
/// Both slices must contain at least `limit` bytes (as in C, where reading
/// past them would be undefined behavior); the limit is clamped defensively.
#[inline(always)]
pub fn find_match_length_with_limit(s1: &[u8], s2: &[u8], limit: usize) -> usize {
    debug_assert!(s1.len() >= limit && s2.len() >= limit, "find_match_length_with_limit: slices shorter than limit");
    let limit = limit.min(s1.len()).min(s2.len());
    let mut matched = 0usize;
    while matched + 8 <= limit {
        let a = u64::from_le_bytes(s1[matched..matched + 8].try_into().unwrap());
        let b = u64::from_le_bytes(s2[matched..matched + 8].try_into().unwrap());
        let x = a ^ b;
        if x != 0 {
            return matched + (x.trailing_zeros() as usize >> 3);
        }
        matched += 8;
    }
    while matched < limit && s1[matched] == s2[matched] {
        matched += 1;
    }
    matched
}
