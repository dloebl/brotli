//! Differential tests of the Rust decoder against the C reference decoder.
#![cfg(all(feature = "c-reference", feature = "ffi"))]
mod cref;
mod dec_harness;

use dec_harness::*;

fn base_cfg() -> DecodeConfig {
    DecodeConfig { max_in: 1 << 16, max_out: 1 << 16, ..Default::default() }
}

#[test]
fn error_strings_and_version() {
    check_error_strings();
    assert_eq!(unsafe { cref::ref_BrotliDecoderVersion() }, brotli::ffi::dec::BrotliDecoderVersion());
}

#[test]
fn testdata_lockstep() {
    let mut rng = Rng::new(1);
    for (name, data) in testdata_compressed() {
        for profile in 0..4 {
            let mut cfg = base_cfg();
            match profile {
                0 => {}
                1 => {
                    cfg.max_in = 7;
                    cfg.max_out = 13;
                    if data.len() > 20000 {
                        continue;
                    }
                }
                2 => {
                    cfg.take_output_permille = 400;
                    cfg.metadata_callbacks = true;
                    cfg.custom_alloc = true;
                }
                _ => {
                    cfg.max_in = 1;
                    cfg.max_out = 1 << 20;
                    cfg.disable_rb_realloc = Some(1);
                    if data.len() > 5000 {
                        continue;
                    }
                }
            }
            let o = run_lockstep(&data, &cfg, &mut rng);
            assert_eq!(o.last_result, 1, "{name} profile {profile}");
        }
    }
}

#[test]
fn qualities_and_windows() {
    let mut rng = Rng::new(2);
    let originals = testdata_originals();
    let src: Vec<u8> = originals.iter().find(|(n, _)| n == "alice29.txt").unwrap().1[..60000].to_vec();
    for q in 0..=11u32 {
        for lgwin in [10u32, 12, 16, 18, 22, 24] {
            let spec = EncodeSpec { quality: q, lgwin, ..Default::default() };
            let enc = encode_stream(&src, &spec, &[]);
            let mut cfg = base_cfg();
            cfg.max_in = [1usize, 17, 1000, 1 << 16][rng.below(4) as usize];
            cfg.max_out = [1usize, 100, 5000, 1 << 16][rng.below(4) as usize];
            if cfg.max_in < 10 && cfg.max_out < 10 {
                cfg.max_out = 1000;
            }
            let o = run_lockstep(&enc, &cfg, &mut rng);
            assert_eq!(o.last_result, 1);
            assert_eq!(o.output, src);
        }
    }
}

#[test]
fn large_window() {
    let mut rng = Rng::new(3);
    let mut src = synthetic_data(&mut rng, 300000);
    let copy = src[1000..60000].to_vec();
    src.extend_from_slice(&copy);
    for lgwin in [10u32, 16, 24, 25, 27, 30] {
        for q in [0u32, 2, 5, 9, 11] {
            let spec = EncodeSpec { quality: q, lgwin, large_window: true, ..Default::default() };
            let enc = encode_stream(&src, &spec, &[]);
            for lw in [None, Some(1u32)] {
                let mut cfg = base_cfg();
                cfg.large_window = lw;
                let o = run_lockstep(&enc, &cfg, &mut rng);
                if lw.is_some() {
                    assert_eq!(o.last_result, 1);
                    assert_eq!(o.output, src);
                }
            }
        }
    }
}

#[test]
fn metadata_and_flushes() {
    let mut rng = Rng::new(4);
    for it in 0..60 {
        let n = rng.range(0, 30000) as usize;
        let src = synthetic_data(&mut rng, n);
        let plan = random_plan(&mut rng, src.len(), true);
        let spec = EncodeSpec { quality: rng.range(0, 11) as u32, lgwin: rng.range(10, 24) as u32, ..Default::default() };
        let enc = encode_stream(&src, &spec, &plan);
        let mut cfg = base_cfg();
        cfg.metadata_callbacks = it % 4 != 3;
        cfg.max_in = [1usize, 5, 300, 1 << 16][rng.below(4) as usize];
        cfg.max_out = [1usize, 50, 3000, 1 << 16][rng.below(4) as usize];
        cfg.take_output_permille = [0u64, 200][rng.below(2) as usize];
        let o = run_lockstep(&enc, &cfg, &mut rng);
        assert_eq!(o.last_result, 1);
        assert_eq!(o.output, src);
    }
}

#[test]
fn compound_dictionaries() {
    let mut rng = Rng::new(5);
    let originals = testdata_originals();
    let alice = originals.iter().find(|(n, _)| n == "alice29.txt").unwrap().1.clone();
    for it in 0..40 {
        let src = alice[it * 1000..it * 1000 + 20000].to_vec();
        let nd = rng.range(1, 4) as usize;
        let mut dicts = Vec::new();
        for _ in 0..nd {
            let start = rng.below(alice.len() as u64 - 30000) as usize;
            let len = rng.range(1, 30000) as usize;
            dicts.push(alice[start..start + len].to_vec());
        }
        dicts.push(src[5000..9000].to_vec());
        let spec = EncodeSpec {
            quality: rng.range(0, 11) as u32,
            lgwin: rng.range(16, 24) as u32,
            dicts: dicts.clone(),
            ..Default::default()
        };
        let enc = encode_stream(&src, &spec, &[]);
        let mut cfg = base_cfg();
        cfg.dicts = dicts;
        cfg.custom_alloc = it % 2 == 0;
        cfg.weird_attach = it % 3 == 0;
        cfg.max_in = [3usize, 100, 1 << 16][rng.below(3) as usize];
        cfg.max_out = [7usize, 1000, 1 << 16][rng.below(3) as usize];
        let o = run_lockstep(&enc, &cfg, &mut rng);
        if !cfg.weird_attach {
            assert_eq!(o.last_result, 1);
            assert_eq!(o.output, src);
        }
    }
}

#[test]
fn attach_limits() {
    // 16 dictionaries (limit is 15), empty ones, after-use attaches.
    let mut rng = Rng::new(6);
    let dicts: Vec<Vec<u8>> = (0..17).map(|i| if i % 5 == 4 { Vec::new() } else { rng.bytes(100 + i) }).collect();
    let mut cfg = base_cfg();
    cfg.dicts = dicts;
    cfg.custom_alloc = true;
    let enc = encode_stream(b"hello hello hello", &EncodeSpec { quality: 5, lgwin: 16, ..Default::default() }, &[]);
    run_lockstep(&enc, &cfg, &mut rng);
}

#[test]
fn corrupted_streams() {
    let mut rng = Rng::new(7);
    let compressed = testdata_compressed();
    for _ in 0..300 {
        let (_, d) = &compressed[rng.below(compressed.len() as u64) as usize];
        if d.len() > 100000 {
            continue;
        }
        let m = mutate(&mut rng, d);
        let mut cfg = base_cfg();
        cfg.max_in = [1usize, 16, 1 << 16][rng.below(3) as usize];
        cfg.max_out = [1usize, 1000, 1 << 16][rng.below(3) as usize];
        if cfg.max_in == 1 && cfg.max_out == 1 {
            cfg.max_out = 1000;
        }
        cfg.custom_alloc = rng.chance(1, 2);
        run_lockstep(&m, &cfg, &mut rng);
        check_one_shot(&m, rng.below(200000) as usize, false);
    }
}

#[test]
fn random_garbage() {
    let mut rng = Rng::new(8);
    for _ in 0..3000 {
        let n = rng.range(0, 64) as usize;
        let g = rng.bytes(n);
        let mut cfg = base_cfg();
        cfg.max_in = [1usize, 4, 64][rng.below(3) as usize];
        cfg.max_out = [1usize, 64, 1 << 16][rng.below(3) as usize];
        if rng.chance(1, 3) {
            cfg.large_window = Some(1);
        }
        run_lockstep(&g, &cfg, &mut rng);
        check_one_shot(&g, rng.below(100) as usize, false);
    }
}

#[test]
fn one_shot_capacities() {
    let originals = testdata_originals();
    let mut rng = Rng::new(9);
    for (_, src) in originals.iter().take(12) {
        let src = &src[..src.len().min(100000)];
        let enc = encode_stream(src, &EncodeSpec { quality: 6, lgwin: 18, ..Default::default() }, &[]);
        for cap in [0usize, 1, src.len().saturating_sub(1), src.len(), src.len() + 1, rng.below(src.len() as u64 + 1) as usize] {
            check_one_shot(&enc, cap, false);
            check_one_shot(&enc, cap, true);
        }
    }
    check_one_shot(&[], 0, true);
    check_one_shot(&[], 10, false);
}

#[test]
fn allocation_failures() {
    let mut rng = Rng::new(10);
    let originals = testdata_originals();
    let src = &originals.iter().find(|(n, _)| n == "alice29.txt").unwrap().1[..30000];
    let dict = src[100..2000].to_vec();
    let enc = encode_stream(src, &EncodeSpec { quality: 9, lgwin: 20, dicts: vec![dict.clone()], ..Default::default() }, &[]);
    let mut cfg = base_cfg();
    cfg.custom_alloc = true;
    cfg.dicts = vec![dict];
    let o = run_lockstep(&enc, &cfg, &mut rng);
    assert_eq!(o.output, src);
    for k in 0..=o.alloc_calls {
        let mut c = cfg.clone();
        c.fail_alloc_at = Some(k);
        run_lockstep(&enc, &c, &mut rng);
    }
}

#[test]
fn random_cases_short() {
    let originals = testdata_originals();
    let compressed = testdata_compressed();
    for seed in 0..300u64 {
        fuzz_iteration(seed, &originals, &compressed);
    }
}

/// Long randomized differential loop: `DEC_FUZZ_ITERS` (default 20000)
/// iterations starting at seed `DEC_FUZZ_SEED` (default 1000).
#[test]
#[ignore]
fn random_cases_long() {
    let originals = testdata_originals();
    let compressed = testdata_compressed();
    let iters: u64 = std::env::var("DEC_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(20000);
    let seed0: u64 = std::env::var("DEC_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
    for seed in seed0..seed0 + iters {
        fuzz_iteration(seed, &originals, &compressed);
    }
}

#[test]
fn platform_config() {
    use brotli::dec::bit_reader::{BROTLI_64_BITS, BROTLI_UNALIGNED_READ_FAST};
    println!("BROTLI_64_BITS={BROTLI_64_BITS} BROTLI_UNALIGNED_READ_FAST={BROTLI_UNALIGNED_READ_FAST}");
}

#[test]
#[ignore]
fn debug_seed() {
    let originals = testdata_originals();
    let compressed = testdata_compressed();
    let seed: u64 = std::env::var("DEC_SEED").unwrap().parse().unwrap();
    let mut rng = Rng::new(seed);
    let case = random_case(&mut rng, &originals, &compressed);
    println!("{}", case.description);
}

/// Distances > 2^26 (more than 24 distance extra bits): large window plus a
/// huge compound dictionary. Slow; run with `--release -- --ignored`.
#[test]
#[ignore]
fn huge_distances() {
    let mut rng = Rng::new(11);
    let dict_len = 70 << 20;
    let mut dict = rng.bytes(dict_len);
    // Make the dictionary compressible-ish but unique.
    for i in (0..dict_len).step_by(3) {
        dict[i] = b'a' + (dict[i] % 4);
    }
    let mut src = Vec::new();
    for k in 0..20 {
        let start = k * 1000;
        src.extend_from_slice(&dict[start..start + 500]);
        src.extend_from_slice(&rng.bytes(50));
    }
    for (q, lgwin) in [(5u32, 30u32), (9, 30), (11, 24)] {
        let spec = EncodeSpec { quality: q, lgwin, large_window: lgwin > 24, dicts: vec![dict.clone()], ..Default::default() };
        let enc = match try_encode_stream(&src, &spec, &[]) {
            Some(e) => e,
            None => {
                println!("encoder rejected q{q} w{lgwin}");
                continue;
            }
        };
        println!("q{q} w{lgwin}: {} -> {} bytes", src.len(), enc.len());
        for profile in 0..3 {
            let mut cfg = base_cfg();
            cfg.dicts = vec![dict.clone()];
            cfg.large_window = if lgwin > 24 { Some(1) } else { None };
            match profile {
                0 => {}
                1 => {
                    cfg.max_in = 1;
                    cfg.max_out = 3;
                }
                _ => {
                    cfg.max_in = 30;
                    cfg.max_out = 100;
                    cfg.take_output_permille = 300;
                }
            }
            let o = run_lockstep(&enc, &cfg, &mut rng);
            assert_eq!(o.last_result, 1);
            assert_eq!(o.output, src);
        }
    }
}

#[test]
fn random_bitstreams() {
    let mut rng = Rng::new(12);
    let mut hist = std::collections::BTreeMap::new();
    for _ in 0..2000 {
        let (data, large) = random_bitstream(&mut rng);
        let mut cfg = base_cfg();
        cfg.max_in = [1usize, 7, 100, 1 << 16][rng.below(4) as usize];
        cfg.max_out = [1usize, 100, 1 << 16][rng.below(3) as usize];
        if cfg.max_in == 1 && cfg.max_out == 1 {
            cfg.max_out = 100;
        }
        cfg.metadata_callbacks = rng.chance(1, 2);
        if large {
            cfg.large_window = Some(1);
        }
        let o = run_lockstep(&data, &cfg, &mut rng);
        *hist.entry(o.error_code).or_insert(0) += 1;
    }
    println!("{hist:?}");
}


/// Stress test of the bitstream generator itself.
#[test]
#[ignore]
fn generator_stress() {
    let mut rng = Rng::new(13);
    let mut total = 0usize;
    for _ in 0..300000 {
        total += random_bitstream(&mut rng).0.len();
    }
    println!("{total}");
}
