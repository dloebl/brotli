//! Port of `c/enc/static_dict.h` / `static_dict.c`: class to model the
//! static dictionary.
//!
//! OWNER: worker "hashers".
//!
//! Default (non-experimental) build: the encoder dictionary has no "heavy"
//! words trie and the contextual dictionary always holds a single
//! dictionary, so only `BrotliFindAllStaticDictionaryMatchesFor` of that
//! dictionary is evaluated.

use super::encoder_dict::BrotliEncoderDictionary;
use super::hash::{find_match_length, hash15};
use super::static_dict_lut::DictWord;
use crate::common::dictionary::BrotliDictionary;
use crate::common::transform::BROTLI_TRANSFORM_UPPERCASE_FIRST;

pub const BROTLI_MAX_STATIC_DICTIONARY_MATCH_LEN: usize = 37;
pub const K_INVALID_MATCH: u32 = 0xFFFFFFF;

#[inline(always)]
fn add_match(distance: usize, len: usize, len_code: usize, matches: &mut [u32]) {
    let m = ((distance << 5).wrapping_add(len_code)) as u32;
    if m < matches[len] {
        matches[len] = m;
    }
}

#[inline(always)]
fn dict_match_length(dictionary: &BrotliDictionary, data: &[u8], id: usize, len: usize, maxlen: usize) -> usize {
    let offset = dictionary.offsets_by_length[len] as usize + len * id;
    find_match_length(&dictionary.data()[offset..], data, if len < maxlen { len } else { maxlen })
}

#[inline(always)]
fn is_match(dictionary: &BrotliDictionary, w: DictWord, data: &[u8], max_length: usize) -> bool {
    if w.len as usize > max_length {
        false
    } else {
        let offset = dictionary.offsets_by_length[w.len as usize] as usize + (w.len as usize) * (w.idx as usize);
        let dict = &dictionary.data()[offset..];
        let wl = w.len as usize;
        if w.transform == 0 {
            // Match against base dictionary word.
            find_match_length(dict, data, wl) == wl
        } else if w.transform == 10 {
            // Match against uppercase first transform.
            // Note that there are only ASCII uppercase words in the lookup
            // table.
            dict[0] >= b'a'
                && dict[0] <= b'z'
                && (dict[0] ^ 32) == data[0]
                && find_match_length(&dict[1..], &data[1..], wl.wrapping_sub(1)) == wl.wrapping_sub(1)
        } else {
            // Match against uppercase all transform.
            // Note that there are only ASCII uppercase words in the lookup
            // table.
            for i in 0..wl {
                if dict[i] >= b'a' && dict[i] <= b'z' {
                    if (dict[i] ^ 32) != data[i] {
                        return false;
                    }
                } else if dict[i] != data[i] {
                    return false;
                }
            }
            true
        }
    }
}

/// `BrotliFindAllStaticDictionaryMatchesFor`: finds matches for a single
/// static dictionary.
fn find_all_static_dictionary_matches_for(
    dictionary: &BrotliEncoderDictionary,
    data: &[u8],
    min_length: usize,
    max_length: usize,
    matches: &mut [u32],
) -> bool {
    let words = dictionary.words;
    let mut has_found_match = false;
    {
        let mut offset = dictionary.buckets[hash15(data) as usize] as usize;
        let mut end = offset == 0;
        while !end {
            let mut w = dictionary.dict_words[offset];
            offset += 1;
            let l = (w.len & 0x1F) as usize;
            let n = 1usize << words.size_bits_by_length[l];
            let id = w.idx as usize;
            end = (w.len & 0x80) != 0;
            w.len = l as u8;
            if w.transform == 0 {
                let matchlen = dict_match_length(words, data, id, l, max_length);
                // Transform "" + BROTLI_TRANSFORM_IDENTITY + ""
                if matchlen == l {
                    add_match(id, l, l, matches);
                    has_found_match = true;
                }
                // Transforms "" + BROTLI_TRANSFORM_OMIT_LAST_1 + "" and
                //            "" + BROTLI_TRANSFORM_OMIT_LAST_1 + "ing "
                if matchlen >= l - 1 {
                    add_match(id + 12 * n, l - 1, l, matches);
                    if l + 2 < max_length && data[l - 1] == b'i' && data[l] == b'n' && data[l + 1] == b'g' && data[l + 2] == b' ' {
                        add_match(id + 49 * n, l + 3, l, matches);
                    }
                    has_found_match = true;
                }
                // Transform "" + BROTLI_TRANSFORM_OMIT_LAST_# + "" (# = 2 .. 9)
                let mut minlen = min_length;
                if l > 9 {
                    minlen = if minlen > l - 9 { minlen } else { l - 9 };
                }
                let maxlen = if matchlen < l - 2 { matchlen } else { l - 2 };
                let mut len = minlen;
                while len <= maxlen {
                    let cut = l - len;
                    let transform_id = (cut << 2) + ((dictionary.cutoff_transforms >> (cut * 6)) & 0x3F) as usize;
                    add_match(id + transform_id * n, len, l, matches);
                    has_found_match = true;
                    len += 1;
                }
                if matchlen < l || l + 6 >= max_length {
                    continue;
                }
                let s = &data[l..];
                // Transforms "" + BROTLI_TRANSFORM_IDENTITY + <suffix>
                if s[0] == b' ' {
                    add_match(id + n, l + 1, l, matches);
                    if s[1] == b'a' {
                        if s[2] == b' ' {
                            add_match(id + 28 * n, l + 3, l, matches);
                        } else if s[2] == b's' {
                            if s[3] == b' ' {
                                add_match(id + 46 * n, l + 4, l, matches);
                            }
                        } else if s[2] == b't' {
                            if s[3] == b' ' {
                                add_match(id + 60 * n, l + 4, l, matches);
                            }
                        } else if s[2] == b'n' {
                            if s[3] == b'd' && s[4] == b' ' {
                                add_match(id + 10 * n, l + 5, l, matches);
                            }
                        }
                    } else if s[1] == b'b' {
                        if s[2] == b'y' && s[3] == b' ' {
                            add_match(id + 38 * n, l + 4, l, matches);
                        }
                    } else if s[1] == b'i' {
                        if s[2] == b'n' {
                            if s[3] == b' ' {
                                add_match(id + 16 * n, l + 4, l, matches);
                            }
                        } else if s[2] == b's' {
                            if s[3] == b' ' {
                                add_match(id + 47 * n, l + 4, l, matches);
                            }
                        }
                    } else if s[1] == b'f' {
                        if s[2] == b'o' {
                            if s[3] == b'r' && s[4] == b' ' {
                                add_match(id + 25 * n, l + 5, l, matches);
                            }
                        } else if s[2] == b'r' {
                            if s[3] == b'o' && s[4] == b'm' && s[5] == b' ' {
                                add_match(id + 37 * n, l + 6, l, matches);
                            }
                        }
                    } else if s[1] == b'o' {
                        if s[2] == b'f' {
                            if s[3] == b' ' {
                                add_match(id + 8 * n, l + 4, l, matches);
                            }
                        } else if s[2] == b'n' {
                            if s[3] == b' ' {
                                add_match(id + 45 * n, l + 4, l, matches);
                            }
                        }
                    } else if s[1] == b'n' {
                        if s[2] == b'o' && s[3] == b't' && s[4] == b' ' {
                            add_match(id + 80 * n, l + 5, l, matches);
                        }
                    } else if s[1] == b't' {
                        if s[2] == b'h' {
                            if s[3] == b'e' {
                                if s[4] == b' ' {
                                    add_match(id + 5 * n, l + 5, l, matches);
                                }
                            } else if s[3] == b'a' {
                                if s[4] == b't' && s[5] == b' ' {
                                    add_match(id + 29 * n, l + 6, l, matches);
                                }
                            }
                        } else if s[2] == b'o' {
                            if s[3] == b' ' {
                                add_match(id + 17 * n, l + 4, l, matches);
                            }
                        }
                    } else if s[1] == b'w' {
                        if s[2] == b'i' && s[3] == b't' && s[4] == b'h' && s[5] == b' ' {
                            add_match(id + 35 * n, l + 6, l, matches);
                        }
                    }
                } else if s[0] == b'"' {
                    add_match(id + 19 * n, l + 1, l, matches);
                    if s[1] == b'>' {
                        add_match(id + 21 * n, l + 2, l, matches);
                    }
                } else if s[0] == b'.' {
                    add_match(id + 20 * n, l + 1, l, matches);
                    if s[1] == b' ' {
                        add_match(id + 31 * n, l + 2, l, matches);
                        if s[2] == b'T' && s[3] == b'h' {
                            if s[4] == b'e' {
                                if s[5] == b' ' {
                                    add_match(id + 43 * n, l + 6, l, matches);
                                }
                            } else if s[4] == b'i' {
                                if s[5] == b's' && s[6] == b' ' {
                                    add_match(id + 75 * n, l + 7, l, matches);
                                }
                            }
                        }
                    }
                } else if s[0] == b',' {
                    add_match(id + 76 * n, l + 1, l, matches);
                    if s[1] == b' ' {
                        add_match(id + 14 * n, l + 2, l, matches);
                    }
                } else if s[0] == b'\n' {
                    add_match(id + 22 * n, l + 1, l, matches);
                    if s[1] == b'\t' {
                        add_match(id + 50 * n, l + 2, l, matches);
                    }
                } else if s[0] == b']' {
                    add_match(id + 24 * n, l + 1, l, matches);
                } else if s[0] == b'\'' {
                    add_match(id + 36 * n, l + 1, l, matches);
                } else if s[0] == b':' {
                    add_match(id + 51 * n, l + 1, l, matches);
                } else if s[0] == b'(' {
                    add_match(id + 57 * n, l + 1, l, matches);
                } else if s[0] == b'=' {
                    if s[1] == b'"' {
                        add_match(id + 70 * n, l + 2, l, matches);
                    } else if s[1] == b'\'' {
                        add_match(id + 86 * n, l + 2, l, matches);
                    }
                } else if s[0] == b'a' {
                    if s[1] == b'l' && s[2] == b' ' {
                        add_match(id + 84 * n, l + 3, l, matches);
                    }
                } else if s[0] == b'e' {
                    if s[1] == b'd' {
                        if s[2] == b' ' {
                            add_match(id + 53 * n, l + 3, l, matches);
                        }
                    } else if s[1] == b'r' {
                        if s[2] == b' ' {
                            add_match(id + 82 * n, l + 3, l, matches);
                        }
                    } else if s[1] == b's' {
                        if s[2] == b't' && s[3] == b' ' {
                            add_match(id + 95 * n, l + 4, l, matches);
                        }
                    }
                } else if s[0] == b'f' {
                    if s[1] == b'u' && s[2] == b'l' && s[3] == b' ' {
                        add_match(id + 90 * n, l + 4, l, matches);
                    }
                } else if s[0] == b'i' {
                    if s[1] == b'v' {
                        if s[2] == b'e' && s[3] == b' ' {
                            add_match(id + 92 * n, l + 4, l, matches);
                        }
                    } else if s[1] == b'z' {
                        if s[2] == b'e' && s[3] == b' ' {
                            add_match(id + 100 * n, l + 4, l, matches);
                        }
                    }
                } else if s[0] == b'l' {
                    if s[1] == b'e' {
                        if s[2] == b's' && s[3] == b's' && s[4] == b' ' {
                            add_match(id + 93 * n, l + 5, l, matches);
                        }
                    } else if s[1] == b'y' {
                        if s[2] == b' ' {
                            add_match(id + 61 * n, l + 3, l, matches);
                        }
                    }
                } else if s[0] == b'o' {
                    if s[1] == b'u' && s[2] == b's' && s[3] == b' ' {
                        add_match(id + 106 * n, l + 4, l, matches);
                    }
                }
            } else {
                // Set is_all_caps=0 for BROTLI_TRANSFORM_UPPERCASE_FIRST and
                //     is_all_caps=1 otherwise (BROTLI_TRANSFORM_UPPERCASE_ALL)
                // transform.
                let is_all_caps = w.transform != BROTLI_TRANSFORM_UPPERCASE_FIRST;
                if !is_match(words, w, data, max_length) {
                    continue;
                }
                // Transform "" + kUppercase{First,All} + ""
                add_match(id + (if is_all_caps { 44 } else { 9 }) * n, l, l, matches);
                has_found_match = true;
                if l + 1 >= max_length {
                    continue;
                }
                // Transforms "" + kUppercase{First,All} + <suffix>
                let s = &data[l..];
                if s[0] == b' ' {
                    add_match(id + (if is_all_caps { 68 } else { 4 }) * n, l + 1, l, matches);
                } else if s[0] == b'"' {
                    add_match(id + (if is_all_caps { 87 } else { 66 }) * n, l + 1, l, matches);
                    if s[1] == b'>' {
                        add_match(id + (if is_all_caps { 97 } else { 69 }) * n, l + 2, l, matches);
                    }
                } else if s[0] == b'.' {
                    add_match(id + (if is_all_caps { 101 } else { 79 }) * n, l + 1, l, matches);
                    if s[1] == b' ' {
                        add_match(id + (if is_all_caps { 114 } else { 88 }) * n, l + 2, l, matches);
                    }
                } else if s[0] == b',' {
                    add_match(id + (if is_all_caps { 112 } else { 99 }) * n, l + 1, l, matches);
                    if s[1] == b' ' {
                        add_match(id + (if is_all_caps { 107 } else { 58 }) * n, l + 2, l, matches);
                    }
                } else if s[0] == b'\'' {
                    add_match(id + (if is_all_caps { 94 } else { 74 }) * n, l + 1, l, matches);
                } else if s[0] == b'(' {
                    add_match(id + (if is_all_caps { 113 } else { 78 }) * n, l + 1, l, matches);
                } else if s[0] == b'=' {
                    if s[1] == b'"' {
                        add_match(id + (if is_all_caps { 105 } else { 104 }) * n, l + 2, l, matches);
                    } else if s[1] == b'\'' {
                        add_match(id + (if is_all_caps { 116 } else { 108 }) * n, l + 2, l, matches);
                    }
                }
            }
        }
    }
    // Transforms with prefixes " " and "."
    if max_length >= 5 && (data[0] == b' ' || data[0] == b'.') {
        let is_space = data[0] == b' ';
        let mut offset = dictionary.buckets[hash15(&data[1..]) as usize] as usize;
        let mut end = offset == 0;
        while !end {
            let mut w = dictionary.dict_words[offset];
            offset += 1;
            let l = (w.len & 0x1F) as usize;
            let n = 1usize << words.size_bits_by_length[l];
            let id = w.idx as usize;
            end = (w.len & 0x80) != 0;
            w.len = l as u8;
            if w.transform == 0 {
                if !is_match(words, w, &data[1..], max_length - 1) {
                    continue;
                }
                // Transforms " " + BROTLI_TRANSFORM_IDENTITY + "" and
                //            "." + BROTLI_TRANSFORM_IDENTITY + ""
                add_match(id + (if is_space { 6 } else { 32 }) * n, l + 1, l, matches);
                has_found_match = true;
                if l + 2 >= max_length {
                    continue;
                }
                // Transforms " " + BROTLI_TRANSFORM_IDENTITY + <suffix> and
                //            "." + BROTLI_TRANSFORM_IDENTITY + <suffix>
                let s = &data[l + 1..];
                if s[0] == b' ' {
                    add_match(id + (if is_space { 2 } else { 77 }) * n, l + 2, l, matches);
                } else if s[0] == b'(' {
                    add_match(id + (if is_space { 89 } else { 67 }) * n, l + 2, l, matches);
                } else if is_space {
                    if s[0] == b',' {
                        add_match(id + 103 * n, l + 2, l, matches);
                        if s[1] == b' ' {
                            add_match(id + 33 * n, l + 3, l, matches);
                        }
                    } else if s[0] == b'.' {
                        add_match(id + 71 * n, l + 2, l, matches);
                        if s[1] == b' ' {
                            add_match(id + 52 * n, l + 3, l, matches);
                        }
                    } else if s[0] == b'=' {
                        if s[1] == b'"' {
                            add_match(id + 81 * n, l + 3, l, matches);
                        } else if s[1] == b'\'' {
                            add_match(id + 98 * n, l + 3, l, matches);
                        }
                    }
                }
            } else if is_space {
                // Set is_all_caps=0 for BROTLI_TRANSFORM_UPPERCASE_FIRST and
                //     is_all_caps=1 otherwise (BROTLI_TRANSFORM_UPPERCASE_ALL)
                // transform.
                let is_all_caps = w.transform != BROTLI_TRANSFORM_UPPERCASE_FIRST;
                if !is_match(words, w, &data[1..], max_length - 1) {
                    continue;
                }
                // Transforms " " + kUppercase{First,All} + ""
                add_match(id + (if is_all_caps { 85 } else { 30 }) * n, l + 1, l, matches);
                has_found_match = true;
                if l + 2 >= max_length {
                    continue;
                }
                // Transforms " " + kUppercase{First,All} + <suffix>
                let s = &data[l + 1..];
                if s[0] == b' ' {
                    add_match(id + (if is_all_caps { 83 } else { 15 }) * n, l + 2, l, matches);
                } else if s[0] == b',' {
                    if !is_all_caps {
                        add_match(id + 109 * n, l + 2, l, matches);
                    }
                    if s[1] == b' ' {
                        add_match(id + (if is_all_caps { 111 } else { 65 }) * n, l + 3, l, matches);
                    }
                } else if s[0] == b'.' {
                    add_match(id + (if is_all_caps { 115 } else { 96 }) * n, l + 2, l, matches);
                    if s[1] == b' ' {
                        add_match(id + (if is_all_caps { 117 } else { 91 }) * n, l + 3, l, matches);
                    }
                } else if s[0] == b'=' {
                    if s[1] == b'"' {
                        add_match(id + (if is_all_caps { 110 } else { 118 }) * n, l + 3, l, matches);
                    } else if s[1] == b'\'' {
                        add_match(id + (if is_all_caps { 119 } else { 120 }) * n, l + 3, l, matches);
                    }
                }
            }
        }
    }
    if max_length >= 6 {
        // Transforms with prefixes "e ", "s ", ", " and "\xC2\xA0"
        if (data[1] == b' ' && (data[0] == b'e' || data[0] == b's' || data[0] == b','))
            || (data[0] == 0xC2 && data[1] == 0xA0)
        {
            let mut offset = dictionary.buckets[hash15(&data[2..]) as usize] as usize;
            let mut end = offset == 0;
            while !end {
                let mut w = dictionary.dict_words[offset];
                offset += 1;
                let l = (w.len & 0x1F) as usize;
                let n = 1usize << words.size_bits_by_length[l];
                let id = w.idx as usize;
                end = (w.len & 0x80) != 0;
                w.len = l as u8;
                if w.transform == 0 && is_match(words, w, &data[2..], max_length - 2) {
                    if data[0] == 0xC2 {
                        add_match(id + 102 * n, l + 2, l, matches);
                        has_found_match = true;
                    } else if l + 2 < max_length && data[l + 2] == b' ' {
                        let t = if data[0] == b'e' {
                            18
                        } else if data[0] == b's' {
                            7
                        } else {
                            13
                        };
                        add_match(id + t * n, l + 3, l, matches);
                        has_found_match = true;
                    }
                }
            }
        }
    }
    if max_length >= 9 {
        // Transforms with prefixes " the " and ".com/"
        if (data[0] == b' ' && data[1] == b't' && data[2] == b'h' && data[3] == b'e' && data[4] == b' ')
            || (data[0] == b'.' && data[1] == b'c' && data[2] == b'o' && data[3] == b'm' && data[4] == b'/')
        {
            let mut offset = dictionary.buckets[hash15(&data[5..]) as usize] as usize;
            let mut end = offset == 0;
            while !end {
                let mut w = dictionary.dict_words[offset];
                offset += 1;
                let l = (w.len & 0x1F) as usize;
                let n = 1usize << words.size_bits_by_length[l];
                let id = w.idx as usize;
                end = (w.len & 0x80) != 0;
                w.len = l as u8;
                if w.transform == 0 && is_match(words, w, &data[5..], max_length - 5) {
                    add_match(id + (if data[0] == b' ' { 41 } else { 72 }) * n, l + 5, l, matches);
                    has_found_match = true;
                    if l + 5 < max_length {
                        let s = &data[l + 5..];
                        if data[0] == b' ' && l + 8 < max_length && s[0] == b' ' && s[1] == b'o' && s[2] == b'f' && s[3] == b' ' {
                            add_match(id + 62 * n, l + 9, l, matches);
                            if l + 12 < max_length && s[4] == b't' && s[5] == b'h' && s[6] == b'e' && s[7] == b' ' {
                                add_match(id + 73 * n, l + 13, l, matches);
                            }
                        }
                    }
                }
            }
        }
    }
    has_found_match
}

/// `BrotliFindAllStaticDictionaryMatches`.
///
/// Matches data against static dictionary words, and for each length l, for
/// which a match is found, updates matches[l] to be the minimum possible
///   (distance << 5) + len_code.
/// Returns true if matches have been found, otherwise false.
/// Prerequisites:
///   matches array is at least BROTLI_MAX_STATIC_DICTIONARY_MATCH_LEN + 1
///   long; all elements are initialized to kInvalidMatch
pub fn brotli_find_all_static_dictionary_matches(
    dictionary: &BrotliEncoderDictionary,
    data: &[u8],
    min_length: usize,
    max_length: usize,
    matches: &mut [u32],
) -> bool {
    // In the default build `dictionary->parent->num_dictionaries` is always
    // 1, so the second-dictionary pass of the C code never runs.
    find_all_static_dictionary_matches_for(dictionary, data, min_length, max_length, matches)
}
