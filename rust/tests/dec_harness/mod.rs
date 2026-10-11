//! Differential testing harness: runs the Rust decoder (through its C ABI,
//! `brotli::ffi::dec`) and the reference C decoder (`ref_*`) in lockstep and
//! asserts identical observable behavior after every call.
//!
//! Used by `tests/dec_diff.rs` and `examples/dec_fuzz.rs`.
#![allow(dead_code, clippy::missing_safety_doc)]

use std::ffi::{c_void, CStr};
use std::ptr::{null, null_mut};

use brotli::ffi::dec as rs;

use crate::cref::*;

extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
}

// ---------------------------------------------------------------------------
// Random numbers.

#[derive(Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    pub fn next_u64(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
    pub fn range(&mut self, lo: u64, hi_inclusive: u64) -> u64 {
        lo + self.below(hi_inclusive - lo + 1)
    }
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

// ---------------------------------------------------------------------------
// Encoder helpers (C reference encoder).

pub const BROTLI_PARAM_MODE: i32 = 0;
pub const BROTLI_PARAM_QUALITY: i32 = 1;
pub const BROTLI_PARAM_LGWIN: i32 = 2;
pub const BROTLI_PARAM_LGBLOCK: i32 = 3;
pub const BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING: i32 = 4;
pub const BROTLI_PARAM_SIZE_HINT: i32 = 5;
pub const BROTLI_PARAM_LARGE_WINDOW: i32 = 6;
pub const BROTLI_PARAM_NPOSTFIX: i32 = 7;
pub const BROTLI_PARAM_NDIRECT: i32 = 8;

pub const OP_PROCESS: i32 = 0;
pub const OP_FLUSH: i32 = 1;
pub const OP_FINISH: i32 = 2;
pub const OP_EMIT_METADATA: i32 = 3;

/// Description of an encoded stream.
#[derive(Clone, Debug, Default)]
pub struct EncodeSpec {
    pub quality: u32,
    pub lgwin: u32,
    pub large_window: bool,
    pub mode: u32,
    pub npostfix: Option<u32>,
    pub ndirect: Option<u32>,
    pub lgblock: Option<u32>,
    pub disable_literal_context_modeling: bool,
    /// Raw compound dictionaries (attached to the encoder as prepared
    /// dictionaries, and to the decoders as RAW dictionaries).
    pub dicts: Vec<Vec<u8>>,
}

/// One step of the encoding plan.
#[derive(Clone, Debug)]
pub enum EncStep {
    Data(usize),
    Flush,
    Metadata(Vec<u8>),
}

/// Streams `data` through the C encoder following `plan` (sizes of data
/// chunks, flushes, metadata blocks), then finishes the stream.
pub fn encode_stream(data: &[u8], spec: &EncodeSpec, plan: &[EncStep]) -> Vec<u8> {
    try_encode_stream(data, spec, plan).expect("encoder failed")
}

/// Like [`encode_stream`]; `None` if the C encoder rejects the parameters.
pub fn try_encode_stream(data: &[u8], spec: &EncodeSpec, plan: &[EncStep]) -> Option<Vec<u8>> {
    unsafe {
        let e = ref_BrotliEncoderCreateInstance(None, None, null_mut());
        assert!(!e.is_null());
        ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_QUALITY, spec.quality);
        if spec.large_window {
            assert_eq!(ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_LARGE_WINDOW, 1), 1);
        }
        ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_LGWIN, spec.lgwin);
        ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_MODE, spec.mode);
        if let Some(v) = spec.npostfix {
            ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_NPOSTFIX, v);
        }
        if let Some(v) = spec.ndirect {
            ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_NDIRECT, v);
        }
        if let Some(v) = spec.lgblock {
            ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_LGBLOCK, v);
        }
        if spec.disable_literal_context_modeling {
            ref_BrotliEncoderSetParameter(e, BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING, 1);
        }
        let mut prepared = Vec::new();
        for d in &spec.dicts {
            let p = ref_BrotliEncoderPrepareDictionary(0, d.len(), d.as_ptr(), 11, None, None, null_mut());
            assert!(!p.is_null());
            assert_eq!(ref_BrotliEncoderAttachPreparedDictionary(e, p), 1);
            prepared.push(p);
        }
        let mut out = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut pos = 0usize;
        let mut failed = false;
        let mut run = |op: i32, input: &[u8], out: &mut Vec<u8>| {
            let mut avail_in = input.len();
            let mut next_in = input.as_ptr();
            loop {
                if failed {
                    return;
                }
                let mut avail_out = buf.len();
                let mut next_out = buf.as_mut_ptr();
                let ok = ref_BrotliEncoderCompressStream(
                    e,
                    op,
                    &mut avail_in,
                    &mut next_in,
                    &mut avail_out,
                    &mut next_out,
                    null_mut(),
                );
                if ok != 1 {
                    failed = true;
                    return;
                }
                out.extend_from_slice(&buf[..buf.len() - avail_out]);
                let more = ref_BrotliEncoderHasMoreOutput(e) != 0;
                match op {
                    OP_FINISH => {
                        if ref_BrotliEncoderIsFinished(e) != 0 {
                            break;
                        }
                    }
                    _ => {
                        if avail_in == 0 && !more {
                            break;
                        }
                    }
                }
            }
        };
        for step in plan {
            match step {
                EncStep::Data(n) => {
                    let end = (pos + n).min(data.len());
                    run(OP_PROCESS, &data[pos..end], &mut out);
                    pos = end;
                }
                EncStep::Flush => run(OP_FLUSH, &[], &mut out),
                EncStep::Metadata(m) => run(OP_EMIT_METADATA, m, &mut out),
            }
        }
        run(OP_FINISH, &data[pos..], &mut out);
        drop(run);
        ref_BrotliEncoderDestroyInstance(e);
        for p in prepared {
            ref_BrotliEncoderDestroyPreparedDictionary(p);
        }
        if failed {
            None
        } else {
            Some(out)
        }
    }
}

// ---------------------------------------------------------------------------
// Allocators and callbacks.

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct AllocStats {
    pub calls: usize,
    pub frees: usize,
    pub null_frees: usize,
    pub live: isize,
    pub fail_at: Option<usize>,
}

pub unsafe extern "C" fn test_alloc(opaque: *mut c_void, size: usize) -> *mut c_void {
    let c = &mut *(opaque as *mut AllocStats);
    let n = c.calls;
    c.calls += 1;
    if c.fail_at == Some(n) {
        return null_mut();
    }
    let p = malloc(size.max(1));
    if !p.is_null() {
        c.live += 1;
    }
    p
}

pub unsafe extern "C" fn test_free(opaque: *mut c_void, p: *mut c_void) {
    let c = &mut *(opaque as *mut AllocStats);
    c.frees += 1;
    if p.is_null() {
        c.null_frees += 1;
    } else {
        c.live -= 1;
        free(p);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetaEvent {
    Start(usize),
    Chunk(Vec<u8>),
}

pub unsafe extern "C" fn meta_start(opaque: *mut c_void, size: usize) {
    let ev = &mut *(opaque as *mut Vec<MetaEvent>);
    ev.push(MetaEvent::Start(size));
}

pub unsafe extern "C" fn meta_chunk(opaque: *mut c_void, data: *const u8, size: usize) {
    let ev = &mut *(opaque as *mut Vec<MetaEvent>);
    let v = if size == 0 { Vec::new() } else { std::slice::from_raw_parts(data, size).to_vec() };
    ev.push(MetaEvent::Chunk(v));
}

// ---------------------------------------------------------------------------
// Lockstep configuration.

#[derive(Clone, Debug, Default)]
pub struct DecodeConfig {
    /// `BROTLI_DECODER_PARAM_LARGE_WINDOW` value to set (if any).
    pub large_window: Option<u32>,
    /// `BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION` value.
    pub disable_rb_realloc: Option<u32>,
    /// RAW dictionaries to attach (in order).
    pub dicts: Vec<Vec<u8>>,
    /// Extra (dict_type, size) attach attempts with junk types / sizes.
    pub weird_attach: bool,
    pub metadata_callbacks: bool,
    /// Use counting allocators (optionally failing at the n-th call).
    pub custom_alloc: bool,
    pub fail_alloc_at: Option<usize>,
    /// Chunking profile: maximal input / output chunk size.
    pub max_in: usize,
    pub max_out: usize,
    /// Probability (per mille) of using TakeOutput instead of an output
    /// buffer.
    pub take_output_permille: u64,
    /// Bound on number of calls.
    pub max_calls: usize,
    /// Occasionally pass invalid arguments (`*available_out != 0` with a
    /// NULL output pointer).
    pub invalid_args: bool,
}

#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub calls: usize,
    pub output: Vec<u8>,
    pub last_result: i32,
    pub error_code: i32,
    pub finished: bool,
    pub alloc_calls: usize,
}

fn chunk_size(rng: &mut Rng, max: usize) -> usize {
    let v = match rng.below(10) {
        0 => 0,
        1 => 1,
        2 => rng.range(0, 8) as usize,
        3 => rng.range(0, 64) as usize,
        4..=6 => rng.range(0, max as u64) as usize,
        7 => max,
        8 => rng.range(0, (max / 8).max(1) as u64) as usize,
        _ => rng.range(0, 4096.min(max) as u64) as usize,
    };
    v.min(max)
}

struct Side {
    c: *mut c_void,
    r: *mut rs::BrotliDecoderState,
}

fn bool_eq(ctx: &str, a: i32, b: i32) {
    assert_eq!(a, b, "{ctx}");
}

/// Runs both decoders on `data` in lockstep. Panics on any difference.
pub fn run_lockstep(data: &[u8], cfg: &DecodeConfig, rng: &mut Rng) -> Outcome {
    let mut out = Outcome::default();
    let mut c_alloc = Box::new(AllocStats { fail_at: cfg.fail_alloc_at, ..Default::default() });
    let mut r_alloc = Box::new(AllocStats { fail_at: cfg.fail_alloc_at, ..Default::default() });
    let mut c_events: Box<Vec<MetaEvent>> = Box::default();
    let mut r_events: Box<Vec<MetaEvent>> = Box::default();
    unsafe {
        let s = if cfg.custom_alloc {
            Side {
                c: ref_BrotliDecoderCreateInstance(
                    Some(test_alloc),
                    Some(test_free),
                    &mut *c_alloc as *mut AllocStats as *mut c_void,
                ),
                r: rs::BrotliDecoderCreateInstance(
                    Some(test_alloc),
                    Some(test_free),
                    &mut *r_alloc as *mut AllocStats as *mut c_void,
                ),
            }
        } else {
            Side {
                c: ref_BrotliDecoderCreateInstance(None, None, null_mut()),
                r: rs::BrotliDecoderCreateInstance(None, None, null_mut()),
            }
        };
        assert_eq!(s.c.is_null(), s.r.is_null(), "create instance");
        assert_eq!(c_alloc.calls, r_alloc.calls, "alloc calls at create");
        if s.c.is_null() {
            assert_eq!(*c_alloc, *r_alloc);
            out.alloc_calls = c_alloc.calls;
            return out;
        }

        let check_state = |ctx: &str| {
            bool_eq(
                &format!("{ctx}: HasMoreOutput"),
                ref_BrotliDecoderHasMoreOutput(s.c),
                rs::BrotliDecoderHasMoreOutput(s.r),
            );
            bool_eq(&format!("{ctx}: IsFinished"), ref_BrotliDecoderIsFinished(s.c), rs::BrotliDecoderIsFinished(s.r));
            bool_eq(&format!("{ctx}: IsUsed"), ref_BrotliDecoderIsUsed(s.c), rs::BrotliDecoderIsUsed(s.r));
            bool_eq(
                &format!("{ctx}: GetErrorCode"),
                ref_BrotliDecoderGetErrorCode(s.c),
                rs::BrotliDecoderGetErrorCode(s.r),
            );
        };
        check_state("initial");

        // Parameters.
        if let Some(v) = cfg.large_window {
            bool_eq(
                "SetParameter(LARGE_WINDOW)",
                ref_BrotliDecoderSetParameter(s.c, 1, v),
                rs::BrotliDecoderSetParameter(s.r, 1, v),
            );
        }
        if let Some(v) = cfg.disable_rb_realloc {
            bool_eq(
                "SetParameter(DISABLE_RB_REALLOC)",
                ref_BrotliDecoderSetParameter(s.c, 0, v),
                rs::BrotliDecoderSetParameter(s.r, 0, v),
            );
        }
        if rng.chance(1, 8) {
            let p = [2i32, -1, 100, i32::MIN][rng.below(4) as usize];
            bool_eq("SetParameter(bad)", ref_BrotliDecoderSetParameter(s.c, p, 1), rs::BrotliDecoderSetParameter(s.r, p, 1));
        }
        // Dictionaries.
        let junk_dict = [1u8, 2, 3];
        for d in &cfg.dicts {
            if cfg.weird_attach && rng.chance(1, 4) {
                let t = [1i32, 2, -1][rng.below(3) as usize];
                bool_eq(
                    "AttachDictionary(bad type)",
                    ref_BrotliDecoderAttachDictionary(s.c, t, junk_dict.len(), junk_dict.as_ptr()),
                    rs::BrotliDecoderAttachDictionary(s.r, t, junk_dict.len(), junk_dict.as_ptr()),
                );
            }
            if cfg.weird_attach && rng.chance(1, 4) {
                bool_eq(
                    "AttachDictionary(empty)",
                    ref_BrotliDecoderAttachDictionary(s.c, 0, 0, junk_dict.as_ptr()),
                    rs::BrotliDecoderAttachDictionary(s.r, 0, 0, junk_dict.as_ptr()),
                );
            }
            bool_eq(
                "AttachDictionary",
                ref_BrotliDecoderAttachDictionary(s.c, 0, d.len(), d.as_ptr()),
                rs::BrotliDecoderAttachDictionary(s.r, 0, d.len(), d.as_ptr()),
            );
            assert_eq!(c_alloc.calls, r_alloc.calls, "alloc calls at attach");
        }
        if cfg.metadata_callbacks {
            ref_BrotliDecoderSetMetadataCallbacks(
                s.c,
                Some(meta_start),
                Some(meta_chunk),
                &mut *c_events as *mut Vec<MetaEvent> as *mut c_void,
            );
            rs::BrotliDecoderSetMetadataCallbacks(
                s.r,
                Some(meta_start),
                Some(meta_chunk),
                &mut *r_events as *mut Vec<MetaEvent> as *mut c_void,
            );
        }
        check_state("after setup");

        let mut in_pos = 0usize;
        let mut c_total: usize = 0;
        let mut r_total: usize = 0;
        let mut stalls = 0usize;
        let mut after_end = 0usize;
        let max_calls = if cfg.max_calls == 0 { 1_000_000 } else { cfg.max_calls };
        let mut obuf_c = vec![0u8; cfg.max_out.max(1) + 16];
        let mut obuf_r = vec![0u8; cfg.max_out.max(1) + 16];
        let mut last = -1;
        let late_dict = [7u8; 300];
        while out.calls < max_calls {
            out.calls += 1;
            let call = out.calls;
            if cfg.weird_attach && rng.chance(1, 20) {
                // Mid-stream parameter / dictionary / callback changes.
                match rng.below(4) {
                    0 => {
                        let p = rng.below(3) as i32;
                        let v = rng.below(3) as u32;
                        bool_eq(
                            &format!("call {call}: late SetParameter"),
                            ref_BrotliDecoderSetParameter(s.c, p, v),
                            rs::BrotliDecoderSetParameter(s.r, p, v),
                        );
                    }
                    1 => {
                        let t = rng.below(3) as i32;
                        let n = rng.below(late_dict.len() as u64 + 1) as usize;
                        bool_eq(
                            &format!("call {call}: late AttachDictionary"),
                            ref_BrotliDecoderAttachDictionary(s.c, t, n, late_dict.as_ptr()),
                            rs::BrotliDecoderAttachDictionary(s.r, t, n, late_dict.as_ptr()),
                        );
                    }
                    2 => {
                        ref_BrotliDecoderSetMetadataCallbacks(s.c, None, None, null_mut());
                        rs::BrotliDecoderSetMetadataCallbacks(s.r, None, None, null_mut());
                    }
                    _ => {
                        ref_BrotliDecoderSetMetadataCallbacks(
                            s.c,
                            Some(meta_start),
                            None,
                            &mut *c_events as *mut Vec<MetaEvent> as *mut c_void,
                        );
                        rs::BrotliDecoderSetMetadataCallbacks(
                            s.r,
                            Some(meta_start),
                            None,
                            &mut *r_events as *mut Vec<MetaEvent> as *mut c_void,
                        );
                    }
                }
                check_state(&format!("call {call} (late setup)"));
                assert_eq!(c_alloc.calls, r_alloc.calls, "call {call}: alloc calls after late setup");
                continue;
            }
            if rng.below(1000) < cfg.take_output_permille {
                // TakeOutput.
                let req = match rng.below(4) {
                    0 => 0,
                    1 => 1,
                    2 => rng.range(1, 100) as usize,
                    _ => rng.range(1, cfg.max_out.max(1) as u64) as usize,
                };
                let mut cs = req;
                let mut rsz = req;
                let cp = ref_BrotliDecoderTakeOutput(s.c, &mut cs);
                let rp = rs::BrotliDecoderTakeOutput(s.r, &mut rsz);
                assert_eq!(cp.is_null(), rp.is_null(), "call {call}: TakeOutput null-ness");
                assert_eq!(cs, rsz, "call {call}: TakeOutput size");
                if !cp.is_null() && cs != 0 {
                    let a = std::slice::from_raw_parts(cp, cs);
                    let b = std::slice::from_raw_parts(rp, rsz);
                    assert!(a == b, "call {call}: TakeOutput data");
                    out.output.extend_from_slice(a);
                }
                check_state(&format!("call {call} (take)"));
                assert_eq!(*c_events, *r_events, "call {call}: metadata events");
                continue;
            }
            // DecompressStream.
            let remaining = data.len() - in_pos;
            let in_n = chunk_size(rng, cfg.max_in).min(remaining);
            let out_mode = rng.below(16);
            let mut out_n = chunk_size(rng, cfg.max_out);
            let invalid = cfg.invalid_args && rng.chance(1, 50);
            let null_next_out = out_mode == 0; // next_out == NULL
            let null_inner = out_mode == 1; // *next_out == NULL
            if (null_next_out || null_inner) && !invalid {
                out_n = 0;
            }
            let use_total = !rng.chance(1, 5);
            let input = &data[in_pos..in_pos + in_n];
            let mut c_avail_in = in_n;
            let mut r_avail_in = in_n;
            let mut c_next_in = if in_n == 0 && rng.chance(1, 3) { null() } else { input.as_ptr() };
            let mut r_next_in = c_next_in;
            let mut c_avail_out = out_n;
            let mut r_avail_out = out_n;
            let mut c_next_out: *mut u8 = if null_inner { null_mut() } else { obuf_c.as_mut_ptr() };
            let mut r_next_out: *mut u8 = if null_inner { null_mut() } else { obuf_r.as_mut_ptr() };
            let c_next_out0 = c_next_out;
            let r_next_out0 = r_next_out;
            let c_tot_p: *mut usize = if use_total { &mut c_total } else { null_mut() };
            let r_tot_p: *mut usize = if use_total { &mut r_total } else { null_mut() };
            let rc = ref_BrotliDecoderDecompressStream(
                s.c,
                &mut c_avail_in,
                &mut c_next_in,
                &mut c_avail_out,
                if null_next_out { null_mut() } else { &mut c_next_out },
                c_tot_p,
            );
            let rr = rs::BrotliDecoderDecompressStream(
                s.r,
                &mut r_avail_in,
                &mut r_next_in,
                &mut r_avail_out,
                if null_next_out { null_mut() } else { &mut r_next_out },
                r_tot_p,
            );
            let ctx = format!(
                "call {call}: in_pos {in_pos} in_n {in_n} out_n {out_n} null_next_out {null_next_out} null_inner {null_inner}"
            );
            assert_eq!(rc, rr, "{ctx}: result");
            assert_eq!(c_avail_in, r_avail_in, "{ctx}: avail_in");
            let c_consumed = in_n - c_avail_in;
            if in_n != 0 || !c_next_in.is_null() {
                assert_eq!(c_next_in as usize - input.as_ptr() as usize, c_consumed, "{ctx}: C next_in");
                assert_eq!(r_next_in as usize - input.as_ptr() as usize, c_consumed, "{ctx}: Rust next_in");
            } else {
                assert!(r_next_in.is_null(), "{ctx}: next_in stays NULL");
            }
            assert_eq!(c_avail_out, r_avail_out, "{ctx}: avail_out");
            let produced = out_n - c_avail_out;
            assert_eq!(c_next_out as usize - c_next_out0 as usize, produced, "{ctx}: C next_out");
            assert_eq!(r_next_out as usize - r_next_out0 as usize, produced, "{ctx}: Rust next_out");
            if use_total {
                assert_eq!(c_total, r_total, "{ctx}: total_out");
            }
            if produced > 0 {
                assert!(obuf_c[..produced] == obuf_r[..produced], "{ctx}: output bytes");
                out.output.extend_from_slice(&obuf_c[..produced]);
            }
            check_state(&ctx);
            assert_eq!(*c_events, *r_events, "{ctx}: metadata events");
            assert_eq!(c_alloc.calls, r_alloc.calls, "{ctx}: alloc calls");
            assert_eq!(c_alloc.frees, r_alloc.frees, "{ctx}: free calls");
            in_pos += c_consumed;
            last = rc;
            out.last_result = rc;
            // Termination logic.
            match rc {
                0 => {
                    // Error: a couple more calls must also fail identically.
                    after_end += 1;
                    if after_end > 2 {
                        break;
                    }
                }
                1 => {
                    if ref_BrotliDecoderHasMoreOutput(s.c) == 0 {
                        after_end += 1;
                        if after_end > 2 {
                            break;
                        }
                    }
                }
                2 => {
                    if in_pos == data.len() {
                        stalls += 1;
                        if stalls > 6 {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        let _ = last;
        out.error_code = ref_BrotliDecoderGetErrorCode(s.c);
        out.finished = ref_BrotliDecoderIsFinished(s.c) != 0;
        ref_BrotliDecoderDestroyInstance(s.c);
        rs::BrotliDecoderDestroyInstance(s.r);
        if cfg.custom_alloc {
            assert_eq!(c_alloc.calls, r_alloc.calls, "final alloc calls");
            assert_eq!(c_alloc.frees, r_alloc.frees, "final free calls");
            assert_eq!(c_alloc.null_frees, r_alloc.null_frees, "final NULL free calls");
            assert_eq!(c_alloc.live, 0, "C leak");
            assert_eq!(r_alloc.live, 0, "Rust leak");
        }
        out.alloc_calls = c_alloc.calls;
    }
    out
}

/// One-shot `BrotliDecoderDecompress` differential check.
pub fn check_one_shot(data: &[u8], capacity: usize, null_out: bool) -> (i32, usize) {
    let mut bc = vec![0xA5u8; capacity + 8];
    let mut br = vec![0xA5u8; capacity + 8];
    let mut sc = capacity;
    let mut sr = capacity;
    let in_ptr = if data.is_empty() { null() } else { data.as_ptr() };
    let (rc, rr) = unsafe {
        (
            ref_BrotliDecoderDecompress(data.len(), in_ptr, &mut sc, if null_out { null_mut() } else { bc.as_mut_ptr() }),
            rs::BrotliDecoderDecompress(data.len(), in_ptr, &mut sr, if null_out { null_mut() } else { br.as_mut_ptr() }),
        )
    };
    assert_eq!(rc, rr, "one-shot result (capacity {capacity})");
    assert_eq!(sc, sr, "one-shot decoded_size (capacity {capacity})");
    assert!(bc == br, "one-shot output buffer (capacity {capacity})");
    (rc, sc)
}

/// Compares `BrotliDecoderErrorString` for a range of codes.
pub fn check_error_strings() {
    for c in (-200..200).chain([i32::MIN, i32::MAX, -1000, 1000]) {
        let a = unsafe { CStr::from_ptr(ref_BrotliDecoderErrorString(c)) };
        let b = unsafe { CStr::from_ptr(rs::BrotliDecoderErrorString(c)) };
        assert_eq!(a, b, "error string {c}");
    }
}

// ---------------------------------------------------------------------------
// Input generation.

pub fn synthetic_data(rng: &mut Rng, n: usize) -> Vec<u8> {
    match rng.below(6) {
        0 => rng.bytes(n),
        1 => {
            // Text-like.
            const WORDS: &[&str] = &[
                "the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog ", "Brotli ", "compression ",
                "\n", ". ", ", ", "time ", "world ", "<div>", "</div>", "http://", "www.", ".com",
            ];
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                v.extend_from_slice(WORDS[rng.below(WORDS.len() as u64) as usize].as_bytes());
            }
            v.truncate(n);
            v
        }
        2 => {
            // Repetitive with long matches.
            let unit = { let __n = rng.range(1, 300) as usize; rng.bytes(__n) };
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                if rng.chance(1, 10) {
                    v.push(rng.next_u64() as u8);
                } else {
                    v.extend_from_slice(&unit);
                }
            }
            v.truncate(n);
            v
        }
        3 => vec![rng.next_u64() as u8; n],
        4 => {
            // Low-entropy binary.
            (0..n).map(|i| ((i as u64 * 7 + rng.below(3)) % 13) as u8).collect()
        }
        _ => {
            // UTF-8 mix.
            let s = "Größe Ärger 漢字 カタカナ Привет мир ✓ ";
            let b = s.as_bytes();
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                let start = rng.below(b.len() as u64) as usize;
                let end = (start + rng.range(1, 20) as usize).min(b.len());
                v.extend_from_slice(&b[start..end]);
            }
            v.truncate(n);
            v
        }
    }
}

/// Testdata originals (files without ".compressed").
pub fn testdata_originals() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("testdata");
    let mut v = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if !name.contains(".compressed") {
            v.push((name, std::fs::read(&p).unwrap()));
        }
    }
    v.sort();
    v
}

/// Testdata compressed streams.
pub fn testdata_compressed() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("testdata");
    let mut v = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if name.contains(".compressed") {
            v.push((name, std::fs::read(&p).unwrap()));
        }
    }
    v.sort();
    v
}

/// Applies a random corruption.
pub fn mutate(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    match rng.below(7) {
        0 => {
            // Truncate.
            let n = rng.below(v.len() as u64 + 1) as usize;
            v.truncate(n);
        }
        1 | 2 => {
            // Bit flips.
            if !v.is_empty() {
                for _ in 0..rng.range(1, 4) {
                    let i = rng.below(v.len() as u64) as usize;
                    v[i] ^= 1 << rng.below(8);
                }
            }
        }
        3 => {
            // Byte overwrite.
            if !v.is_empty() {
                for _ in 0..rng.range(1, 3) {
                    let i = rng.below(v.len() as u64) as usize;
                    v[i] = rng.next_u64() as u8;
                }
            }
        }
        4 => {
            // Trailing garbage.
            let extra = { let __n = rng.range(1, 20) as usize; rng.bytes(__n) };
            v.extend_from_slice(&extra);
        }
        5 => {
            // Bit flip in the header region.
            if !v.is_empty() {
                let i = rng.below(v.len().min(16) as u64) as usize;
                v[i] ^= 1 << rng.below(8);
            }
        }
        _ => {
            // Splice random bytes in the middle.
            if !v.is_empty() {
                let i = rng.below(v.len() as u64) as usize;
                let junk = { let __n = rng.range(1, 8) as usize; rng.bytes(__n) };
                v.splice(i..i, junk);
            }
        }
    }
    v
}

/// Random encoding plan for streaming compression.
pub fn random_plan(rng: &mut Rng, len: usize, with_metadata: bool) -> Vec<EncStep> {
    let mut plan = Vec::new();
    let mut left = len;
    let steps = rng.range(0, 6);
    for _ in 0..steps {
        match rng.below(4) {
            0 | 1 => {
                let n = rng.below(left as u64 + 1) as usize;
                left -= n;
                plan.push(EncStep::Data(n));
            }
            2 => plan.push(EncStep::Flush),
            _ => {
                if with_metadata {
                    let n = match rng.below(4) {
                        0 => 0,
                        1 => rng.range(1, 16) as usize,
                        2 => rng.range(1, 300) as usize,
                        _ => rng.range(256, 70000) as usize,
                    };
                    plan.push(EncStep::Metadata(rng.bytes(n)));
                } else {
                    plan.push(EncStep::Flush);
                }
            }
        }
    }
    plan
}

/// A random stream (plus the parameters needed to decode it).
pub struct Case {
    pub data: Vec<u8>,
    pub cfg: DecodeConfig,
    pub description: String,
}

/// Generates a random test case.
pub fn random_case(rng: &mut Rng, originals: &[(String, Vec<u8>)], compressed: &[(String, Vec<u8>)]) -> Case {
    let mut cfg = DecodeConfig {
        max_in: [8usize, 64, 1024, 65536, 1 << 20][rng.below(5) as usize],
        max_out: [8usize, 64, 1024, 65536, 1 << 20][rng.below(5) as usize],
        take_output_permille: [0u64, 0, 50, 300][rng.below(4) as usize],
        metadata_callbacks: rng.chance(1, 2),
        custom_alloc: rng.chance(1, 4),
        invalid_args: rng.chance(1, 10),
        ..Default::default()
    };
    if rng.chance(1, 4) {
        cfg.disable_rb_realloc = Some(rng.below(3) as u32);
    }
    let kind = rng.below(12);
    let (mut data, description) = if kind >= 10 {
        let (d, large) = random_bitstream(rng);
        if large || rng.chance(1, 10) {
            cfg.large_window = Some(1);
        }
        (d, "random bitstream".to_string())
    } else if kind == 0 && !compressed.is_empty() {
        let (n, d) = &compressed[rng.below(compressed.len() as u64) as usize];
        (d.clone(), format!("testdata {n}"))
    } else if kind == 1 {
        // Garbage.
        let n = rng.range(0, 200) as usize;
        let mut g = rng.bytes(n);
        if !g.is_empty() && rng.chance(1, 2) {
            // Plausible window bits byte.
            g[0] = [0x0b, 0x1b, 0x8b, 0x21, 0x11, 0x81, 0x01][rng.below(7) as usize];
        }
        if rng.chance(1, 3) {
            cfg.large_window = Some(1);
        }
        (g, "garbage".to_string())
    } else {
        // Encode something.
        let src: Vec<u8> = if rng.chance(1, 2) && !originals.is_empty() {
            let (_, d) = &originals[rng.below(originals.len() as u64) as usize];
            let max = [256usize, 4096, 70000, 300000][rng.below(4) as usize];
            let start = rng.below(d.len().saturating_sub(max) as u64 + 1) as usize;
            d[start..(start + max).min(d.len())].to_vec()
        } else {
            let n = [0usize, 1, 10, 100, 1000, 20000, 100000][rng.below(7) as usize];
            let n = rng.range(0, n as u64) as usize;
            synthetic_data(rng, n)
        };
        let large_window = rng.chance(1, 5);
        let mut spec = EncodeSpec {
            quality: rng.range(0, 11) as u32,
            lgwin: if large_window { rng.range(10, 30) as u32 } else { rng.range(10, 24) as u32 },
            large_window,
            mode: rng.below(3) as u32,
            ..Default::default()
        };
        if rng.chance(1, 4) {
            spec.npostfix = Some(rng.range(0, 3) as u32);
            spec.ndirect = Some((rng.range(0, 15) << spec.npostfix.unwrap()) as u32);
        }
        if rng.chance(1, 6) {
            spec.lgblock = Some(rng.range(16, 24) as u32);
        }
        if rng.chance(1, 6) {
            spec.disable_literal_context_modeling = true;
        }
        if rng.chance(1, 5) && !src.is_empty() {
            // Compound dictionaries made of pieces of the source (so they
            // are actually referenced) and random data.
            let nd = rng.range(1, 3) as usize;
            for _ in 0..nd {
                let len = rng.range(1, src.len().min(50000) as u64) as usize;
                let start = rng.below((src.len() - len) as u64 + 1) as usize;
                let mut d = src[start..start + len].to_vec();
                if rng.chance(1, 3) {
                    d.extend_from_slice(&{ let __n = rng.range(1, 100) as usize; rng.bytes(__n) });
                }
                spec.dicts.push(d);
            }
        }
        let plan = if rng.chance(1, 2) { random_plan(rng, src.len(), true) } else { Vec::new() };
        let enc = match try_encode_stream(&src, &spec, &plan) {
            Some(e) => e,
            None => {
                // Unsupported parameter / operation combination (e.g. large
                // window with compound dictionaries, metadata right after a
                // flush in the fast encoders): simplify.
                spec.dicts.clear();
                match try_encode_stream(&src, &spec, &plan) {
                    Some(e) => e,
                    None => encode_stream(&src, &spec, &[]),
                }
            }
        };
        if large_window {
            cfg.large_window = Some(if rng.chance(1, 10) { 0 } else { 1 + rng.below(5) as u32 });
        } else if rng.chance(1, 8) {
            cfg.large_window = Some(rng.below(2) as u32);
        }
        cfg.dicts = spec.dicts.clone();
        if !cfg.dicts.is_empty() && rng.chance(1, 8) {
            // Missing / wrong dictionary.
            if rng.chance(1, 2) {
                cfg.dicts.pop();
            } else {
                let i = rng.below(cfg.dicts.len() as u64) as usize;
                let j = rng.below(cfg.dicts[i].len() as u64) as usize;
                cfg.dicts[i][j] ^= 0x40;
            }
        }
        cfg.weird_attach = rng.chance(1, 6);
        (enc, format!("encoded {} bytes, spec {:?}, plan steps {}", src.len(), spec_short(&spec), plan.len()))
    };
    if kind != 1 && rng.chance(1, 3) {
        data = mutate(rng, &data);
    }
    Case { data, cfg, description }
}

fn spec_short(s: &EncodeSpec) -> String {
    format!(
        "q{} w{} lw{} m{} np{:?} nd{:?} lb{:?} dlcm{} dicts{:?}",
        s.quality,
        s.lgwin,
        s.large_window,
        s.mode,
        s.npostfix,
        s.ndirect,
        s.lgblock,
        s.disable_literal_context_modeling,
        s.dicts.iter().map(|d| d.len()).collect::<Vec<_>>()
    )
}

thread_local! {
    static CURRENT_CASE: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Installs a panic hook that reports the current fuzz case (needed when
/// panics abort, e.g. in release builds of the fuzz example).
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        CURRENT_CASE.with(|c| {
            if let Ok(c) = c.try_borrow() {
                eprintln!("current case: {}", *c);
            }
        });
        prev(info);
    }));
}

/// Runs one random iteration (stream + lockstep + one-shot + allocation
/// failure injection) for `seed`.
pub fn fuzz_iteration(seed: u64, originals: &[(String, Vec<u8>)], compressed: &[(String, Vec<u8>)]) {
    let mut rng = Rng::new(seed);
    CURRENT_CASE.with(|c| *c.borrow_mut() = format!("seed {seed}: generating"));
    let case = random_case(&mut rng, originals, compressed);
    CURRENT_CASE.with(|c| *c.borrow_mut() = format!("seed {seed}: {}", case.description));
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut r2 = rng.clone();
        let outcome = run_lockstep(&case.data, &case.cfg, &mut r2);
        // One-shot API.
        if case.cfg.dicts.is_empty() && case.cfg.large_window.is_none() {
            let full = outcome.output.len();
            let caps = [full + 1, full, full.saturating_sub(1), 0, r2.below(full as u64 + 2) as usize];
            let cap = caps[r2.below(caps.len() as u64) as usize];
            check_one_shot(&case.data, cap, r2.chance(1, 20));
        }
        // Allocation failure injection.
        if case.cfg.custom_alloc && outcome.alloc_calls > 0 && r2.chance(1, 3) {
            let mut cfg = case.cfg.clone();
            cfg.fail_alloc_at = Some(r2.below(outcome.alloc_calls as u64 + 1) as usize);
            let mut r3 = rng.clone();
            run_lockstep(&case.data, &cfg, &mut r3);
        }
    }));
    if let Err(e) = run {
        eprintln!("FAILED seed {seed}: {}", case.description);
        std::panic::resume_unwind(e);
    }
}

// ---------------------------------------------------------------------------
// Structure-aware random bitstream generator: valid-ish headers (window
// bits, metadata / uncompressed / compressed metablocks, prefix codes,
// context maps) followed by random data bits.

pub struct BitWriter {
    pub bytes: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { bytes: Vec::new(), acc: 0, n: 0 }
    }
    pub fn write(&mut self, nbits: u32, value: u64) {
        let mut nb = nbits;
        let mut v = value;
        while nb > 0 {
            let take = nb.min(32);
            let part = v & ((1u64 << take) - 1);
            self.acc |= part << self.n;
            self.n += take;
            while self.n >= 8 {
                self.bytes.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
            v >>= take;
            nb -= take;
        }
    }
    pub fn pad(&mut self) {
        if self.n > 0 {
            let k = 8 - self.n;
            self.write(k, 0);
        }
    }
    pub fn finish(mut self) -> Vec<u8> {
        self.pad();
        self.bytes
    }
}

/// Random complete prefix code with `n` leaves (lengths <= max_len).
fn random_complete_lengths(rng: &mut Rng, n: usize, max_len: u32) -> Vec<u32> {
    let mut leaves = vec![0u32];
    while leaves.len() < n {
        let candidates: Vec<usize> = (0..leaves.len()).filter(|&i| leaves[i] < max_len).collect();
        if candidates.is_empty() {
            break;
        }
        let i = candidates[rng.below(candidates.len() as u64) as usize];
        let l = leaves[i] + 1;
        leaves[i] = l;
        leaves.push(l);
    }
    leaves
}

/// Canonical codes (as bit strings to be written first-bit-first).
fn canonical_codes(lengths: &[u32]) -> Vec<(u32, u64)> {
    let mut order: Vec<usize> = (0..lengths.len()).filter(|&i| lengths[i] > 0).collect();
    order.sort_by_key(|&i| (lengths[i], i));
    let mut codes = vec![(0u32, 0u64); lengths.len()];
    let mut code: u64 = 0;
    let mut prev_len = 0u32;
    for &i in &order {
        let l = lengths[i];
        code <<= l - prev_len;
        prev_len = l;
        // Reverse (stream is LSB-first, code is read MSB-first).
        let mut r = 0u64;
        for b in 0..l {
            if code & (1 << (l - 1 - b)) != 0 {
                r |= 1 << b;
            }
        }
        codes[i] = (l, r);
        code += 1;
    }
    codes
}

fn write_symbol(w: &mut BitWriter, codes: &[(u32, u64)], sym: usize) {
    let (l, c) = codes[sym];
    w.write(l, c);
}

/// Writes a prefix code over `alphabet_limit` symbols (max_bits derived from
/// `alphabet_max`) and returns the code (lengths per symbol; a single-symbol
/// code has all lengths 0 and returns `Single(sym)`).
enum Code {
    Single(usize),
    Codes(Vec<(u32, u64)>),
}

fn write_symbol_code(w: &mut BitWriter, code: &Code, sym: usize) {
    match code {
        Code::Single(_) => {}
        Code::Codes(c) => write_symbol(w, c, sym),
    }
}

fn write_prefix_code(w: &mut BitWriter, rng: &mut Rng, alphabet_max: usize, alphabet_limit: usize, invalid: bool) -> Code {
    let max_bits = {
        let mut x = alphabet_max - 1;
        let mut r = 0;
        while x != 0 {
            x >>= 1;
            r += 1;
        }
        r
    };
    if rng.chance(1, 3) {
        // Simple code.
        let nsym = rng.range(1, 4.min(alphabet_limit as u64)) as usize;
        w.write(2, 1);
        w.write(2, (nsym - 1) as u64);
        let mut syms: Vec<usize> = Vec::new();
        while syms.len() < nsym {
            let s = if invalid && rng.chance(1, 4) {
                rng.below(1 << max_bits) as usize
            } else {
                rng.below(alphabet_limit as u64) as usize
            };
            if !syms.contains(&s) || (invalid && rng.chance(1, 4)) {
                syms.push(s);
            }
        }
        for &s in &syms {
            w.write(max_bits, s as u64);
        }
        let mut lengths = vec![0u32; alphabet_limit.max(1 << max_bits)];
        match nsym {
            1 => return Code::Single(syms[0]),
            2 => {
                lengths[syms[0]] = 1;
                lengths[syms[1]] = 1;
            }
            3 => {
                lengths[syms[0]] = 1;
                lengths[syms[1]] = 2;
                lengths[syms[2]] = 2;
            }
            _ => {
                let tree_select = rng.chance(1, 2);
                w.write(1, tree_select as u64);
                if tree_select {
                    lengths[syms[0]] = 1;
                    lengths[syms[1]] = 2;
                    lengths[syms[2]] = 3;
                    lengths[syms[3]] = 3;
                } else {
                    for &s in &syms {
                        lengths[s] = 2;
                    }
                }
            }
        }
        return Code::Codes(canonical_codes(&lengths));
    }
    // Complex code.
    let n = rng.range(2, alphabet_limit.min(300) as u64) as usize;
    let leaf_lengths = random_complete_lengths(rng, n, 15);
    let mut symbols: Vec<usize> = Vec::new();
    let dense = rng.chance(1, 2);
    while symbols.len() < leaf_lengths.len() {
        let s = if dense { rng.below(n.min(alphabet_limit) as u64 * 2).min(alphabet_limit as u64 - 1) as usize } else { rng.below(alphabet_limit as u64) as usize };
        if !symbols.contains(&s) {
            symbols.push(s);
        }
        if symbols.len() >= alphabet_limit {
            break;
        }
    }
    let mut lengths = vec![0u32; alphabet_limit];
    for (k, &s) in symbols.iter().enumerate() {
        lengths[s] = leaf_lengths[k];
    }
    if invalid && rng.chance(1, 3) {
        let i = rng.below(alphabet_limit as u64) as usize;
        lengths[i] = rng.range(0, 15) as u32;
    }
    let last_nonzero = lengths.iter().rposition(|&l| l != 0).unwrap_or(0);
    // Plan the code-length symbol sequence.
    let use_repeats = rng.chance(2, 3);
    let mut seq: Vec<(usize, u32, u64)> = Vec::new(); // (cl symbol, extra bits, extra value)
    let mut i = 0usize;
    let mut prev_nonzero: u32 = 8;
    while i <= last_nonzero {
        let l = lengths[i];
        let mut run = 1;
        while i + run <= last_nonzero && lengths[i + run] == l {
            run += 1;
        }
        if use_repeats && l == 0 && run >= 3 {
            let r = run.min(10);
            seq.push((17, 3, (r - 3) as u64));
            i += r;
            // Break consecutive repeat codes with a literal (if possible).
            if i <= last_nonzero && lengths[i] == 0 {
                seq.push((0, 0, 0));
                i += 1;
            }
            continue;
        }
        if use_repeats && l != 0 && l == prev_nonzero && run >= 3 {
            let r = run.min(6);
            seq.push((16, 2, (r - 3) as u64));
            i += r;
            if i <= last_nonzero && lengths[i] == l {
                seq.push((l as usize, 0, 0));
                i += 1;
            }
            continue;
        }
        seq.push((l as usize, 0, 0));
        if l != 0 {
            prev_nonzero = l;
        }
        i += 1;
    }
    if invalid && rng.chance(1, 2) {
        // Random nested repeats / junk.
        for _ in 0..rng.range(1, 4) {
            let p = rng.below(seq.len() as u64 + 1) as usize;
            let s = rng.range(15, 17) as usize;
            let (eb, ev) = match s {
                16 => (2, rng.below(4)),
                17 => (3, rng.below(8)),
                _ => (0, 0),
            };
            seq.insert(p, (s, eb, ev));
        }
    }
    // Code-length code over the used symbols.
    let mut used: Vec<usize> = seq.iter().map(|x| x.0).collect();
    used.sort();
    used.dedup();
    let mut cl_lengths = vec![0u32; 18];
    if used.len() == 1 {
        cl_lengths[used[0]] = rng.range(1, 5) as u32;
    } else {
        let ll = random_complete_lengths(rng, used.len(), 5);
        for (k, &s) in used.iter().enumerate() {
            cl_lengths[s] = ll[k];
        }
    }
    if invalid && rng.chance(1, 4) {
        cl_lengths[rng.below(18) as usize] = rng.range(0, 5) as u32;
    }
    const ORDER: [usize; 18] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let hskip = if cl_lengths[1] == 0 && cl_lengths[2] == 0 && rng.chance(1, 2) {
        if cl_lengths[3] == 0 && rng.chance(1, 2) {
            3
        } else {
            2
        }
    } else {
        0
    };
    w.write(2, hskip);
    // Static code for code length code lengths: value -> (len, bits).
    const STATIC: [(u32, u64); 6] = [(2, 0), (4, 7), (3, 3), (2, 2), (2, 1), (4, 15)];
    let mut space: i32 = 32;
    let mut num_codes = 0;
    for &sym in ORDER.iter().skip(hskip as usize) {
        let v = cl_lengths[sym] as usize;
        let (l, b) = STATIC[v];
        w.write(l, b);
        if v != 0 {
            space -= 32 >> v;
            num_codes += 1;
            if space <= 0 {
                break;
            }
        }
    }
    let _ = num_codes;
    let cl_codes = canonical_codes(&cl_lengths);
    let single_cl = used.len() == 1;
    for &(s, eb, ev) in &seq {
        if !single_cl {
            write_symbol(w, &cl_codes, s);
        }
        w.write(eb, ev);
    }
    Code::Codes(canonical_codes(&lengths))
}

fn write_var_len_uint8(w: &mut BitWriter, v: u32) {
    if v == 0 {
        w.write(1, 0);
        return;
    }
    w.write(1, 1);
    let mut nbits = 0;
    while (v >> (nbits + 1)) != 0 {
        nbits += 1;
    }
    // v in [2^nbits, 2^(nbits+1))
    w.write(3, nbits as u64);
    if nbits > 0 {
        w.write(nbits, (v - (1 << nbits)) as u64);
    }
}

fn write_context_map(w: &mut BitWriter, rng: &mut Rng, size: usize, ntrees: u32, invalid: bool) {
    write_var_len_uint8(w, ntrees - 1);
    if ntrees < 2 {
        return;
    }
    let use_rle = rng.chance(1, 2);
    let rle_max = if use_rle { rng.range(1, 16) as u32 } else { 0 };
    if use_rle {
        w.write(1, 1);
        w.write(4, (rle_max - 1) as u64);
    } else {
        w.write(1, 0);
    }
    let alphabet = (ntrees + rle_max) as usize;
    let code = write_prefix_code(w, rng, alphabet, alphabet, invalid);
    let allowed: Vec<usize> = match &code {
        Code::Single(s) => vec![*s],
        Code::Codes(c) => (0..alphabet).filter(|&s| c[s].0 > 0).collect(),
    };
    let allowed = if allowed.is_empty() { vec![0] } else { allowed };
    // Context map values.
    let mut i = 0;
    let mut guard = 0;
    while i < size {
        guard += 1;
        let sym = allowed[rng.below(allowed.len() as u64) as usize];
        if sym >= 1 && sym <= rle_max as usize {
            let k = sym as u32;
            let len = (1usize << k) + rng.below(1 << k) as usize;
            if i + (1usize << k) > size && !(invalid && rng.chance(1, 3)) && guard < 1000 {
                continue;
            }
            let len = if i + len > size && !invalid { (size - i).max(1 << k) } else { len };
            write_symbol_code(w, &code, sym);
            w.write(k, (len - (1 << k)) as u64);
            i += len;
            continue;
        }
        write_symbol_code(w, &code, sym);
        i += 1;
    }
    w.write(1, rng.below(2)); // IMTF
}

/// Generates a random, mostly well-formed brotli stream.
pub fn random_bitstream(rng: &mut Rng) -> (Vec<u8>, bool) {
    let mut w = BitWriter::new();
    let invalid = rng.chance(1, 5);
    let large = rng.chance(1, 6);
    // Window bits.
    let wbits: u32;
    if large {
        w.write(8, 0x11);
        wbits = rng.range(10, 30) as u32;
        w.write(6, wbits as u64);
    } else {
        match rng.below(3) {
            0 => {
                w.write(1, 0);
                wbits = 16;
            }
            1 => {
                let n = rng.range(1, 7);
                w.write(1, 1);
                w.write(3, n);
                wbits = 17 + n as u32;
            }
            _ => {
                let n = [0u64, 2, 3, 4, 5, 6, 7][rng.below(7) as usize];
                w.write(1, 1);
                w.write(3, 0);
                w.write(3, n);
                wbits = if n == 0 { 17 } else { 8 + n as u32 };
            }
        }
    }
    let _ = wbits;
    let nblocks = rng.range(1, 4);
    for b in 0..nblocks {
        let last = b == nblocks - 1;
        let kind = if last { 3 } else { rng.below(4) };
        match kind {
            0 => {
                // Metadata.
                w.write(1, 0);
                w.write(2, 3);
                w.write(1, 0);
                let len = rng.range(0, 300) as usize;
                if len == 0 {
                    w.write(2, 0);
                } else {
                    let nbytes = if len - 1 < 256 { 1 } else { 2 };
                    w.write(2, nbytes);
                    w.write(8 * nbytes as u32, (len - 1) as u64);
                }
                w.pad();
                for _ in 0..len {
                    w.write(8, rng.below(256));
                }
            }
            1 => {
                // Uncompressed.
                let len = rng.range(1, 3000) as usize;
                w.write(1, 0);
                w.write(2, 0);
                w.write(16, (len - 1) as u64);
                w.write(1, 1);
                w.pad();
                for _ in 0..len {
                    w.write(8, rng.below(256));
                }
            }
            _ => {
                // Compressed (last): header + random data.
                w.write(1, 1);
                if rng.chance(1, 20) {
                    w.write(1, 1); // ISLASTEMPTY
                    break;
                }
                w.write(1, 0);
                let len = [16usize, 300, 5000, 70000][rng.below(4) as usize];
                let len = rng.range(1, len as u64) as usize;
                let nn = if len - 1 < (1 << 16) { 4 } else if len - 1 < (1 << 20) { 5 } else { 6 };
                w.write(2, nn - 4);
                w.write(4 * nn as u32, (len - 1) as u64);
                let mut nbt = [1u32; 3];
                for t in 0..3 {
                    nbt[t] = if rng.chance(1, 2) { 1 } else { rng.range(2, 8) as u32 };
                    if rng.chance(1, 20) {
                        nbt[t] = rng.range(2, 256) as u32;
                    }
                    write_var_len_uint8(&mut w, nbt[t] - 1);
                    if nbt[t] >= 2 {
                        let a = nbt[t] as usize + 2;
                        write_prefix_code(&mut w, rng, a, a, invalid);
                        let bl = write_prefix_code(&mut w, rng, 26, 26, invalid);
                        // First block length: random symbol of the code
                        // plus its extra bits.
                        let s = match &bl {
                            Code::Single(s) => *s,
                            Code::Codes(c) => {
                                let syms: Vec<usize> = (0..26).filter(|&s| c[s].0 > 0).collect();
                                if syms.is_empty() {
                                    0
                                } else {
                                    let s = syms[rng.below(syms.len() as u64) as usize];
                                    write_symbol(&mut w, c, s);
                                    s
                                }
                            }
                        };
                        let nbits = brotli::common::constants::K_BROTLI_PREFIX_CODE_RANGES[s.min(25)].nbits as u32;
                        let extra = if nbits > 12 { rng.below(1 << 12) } else { rng.below(1 << nbits) };
                        w.write(nbits, extra);
                    }
                }
                let npostfix = rng.range(0, 3) as u32;
                let ndirect_code = rng.range(0, 15) as u32;
                w.write(2, npostfix as u64);
                w.write(4, ndirect_code as u64);
                for _ in 0..nbt[0] {
                    w.write(2, rng.below(4));
                }
                let ntrees_l = if rng.chance(1, 3) { 1 } else { rng.range(1, 10) as u32 };
                write_context_map(&mut w, rng, (nbt[0] as usize) << 6, ntrees_l, invalid);
                let ntrees_d = if rng.chance(1, 3) { 1 } else { rng.range(1, 6) as u32 };
                write_context_map(&mut w, rng, (nbt[2] as usize) << 2, ntrees_d, invalid);
                for _ in 0..ntrees_l {
                    write_prefix_code(&mut w, rng, 256, 256, invalid);
                }
                for _ in 0..nbt[1] {
                    write_prefix_code(&mut w, rng, 704, 704, invalid);
                }
                let ndirect = ndirect_code << npostfix;
                let dist_max = 16 + ndirect + (if large { 62 } else { 24 } << (npostfix + 1));
                let dist_limit = if large {
                    brotli::common::constants::brotli_calculate_distance_code_limit(0x7FFFFFFC, npostfix, ndirect)
                        .max_alphabet_size
                } else {
                    dist_max
                };
                for _ in 0..ntrees_d {
                    write_prefix_code(&mut w, rng, dist_max as usize, dist_limit as usize, invalid);
                }
                // Random command data.
                let n = rng.range(0, 2000) as usize;
                for _ in 0..n {
                    w.write(8, rng.below(256));
                }
            }
        }
    }
    (w.finish(), large)
}
