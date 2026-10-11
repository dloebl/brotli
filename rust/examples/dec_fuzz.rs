//! Long randomized differential fuzzing of the Rust decoder against the C
//! reference decoder (lockstep, random chunking, metadata, dictionaries,
//! corruptions, allocation failures).
//!
//!     cargo run --release --features c-reference --example dec_fuzz -- \
//!         [iterations] [first_seed] [threads] [max_seconds]
//!
//! Use `--profile fuzz` to run with debug assertions and overflow checks.

#[cfg(all(feature = "c-reference", feature = "ffi"))]
#[path = "../tests/cref/mod.rs"]
mod cref;
#[cfg(all(feature = "c-reference", feature = "ffi"))]
#[path = "../tests/dec_harness/mod.rs"]
mod dec_harness;

#[cfg(all(feature = "c-reference", feature = "ffi"))]
fn main() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let args: Vec<String> = std::env::args().collect();
    let iters: u64 = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(10000);
    let seed0: u64 = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
    let threads: u64 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(4);
    let max_secs: u64 = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(u64::MAX);
    dec_harness::install_panic_hook();
    let originals = Arc::new(dec_harness::testdata_originals());
    let compressed = Arc::new(dec_harness::testdata_compressed());
    let next = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicU64::new(0));
    let start = std::time::Instant::now();
    let mut hs = Vec::new();
    for _ in 0..threads {
        let (o, c, n, d) = (originals.clone(), compressed.clone(), next.clone(), done.clone());
        hs.push(std::thread::spawn(move || loop {
            let i = n.fetch_add(1, Ordering::SeqCst);
            if i >= iters || start.elapsed().as_secs() >= max_secs {
                break;
            }
            dec_harness::fuzz_iteration(seed0 + i, &o, &c);
            let k = d.fetch_add(1, Ordering::SeqCst) + 1;
            if k % 1000 == 0 {
                eprintln!("{k} iterations OK ({:.0}s)", start.elapsed().as_secs_f64());
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    println!(
        "dec_fuzz: {} iterations clean (seeds {}..), {:.1}s",
        done.load(Ordering::SeqCst),
        seed0,
        start.elapsed().as_secs_f64()
    );
}

#[cfg(not(all(feature = "c-reference", feature = "ffi")))]
fn main() {
    eprintln!("dec_fuzz requires --features c-reference");
}
