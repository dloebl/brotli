//! Build script.  Only does something with the development feature
//! `c-reference`: it compiles the reference C implementation for
//! differential testing.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "c-reference")]
    c_reference::build();
}

#[cfg(feature = "c-reference")]
mod c_reference {
    use std::path::{Path, PathBuf};

    fn c_files(dir: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("reading {}: {}", dir.display(), e))
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().map(|x| x == "c").unwrap_or(false))
            .collect();
        v.sort();
        v
    }

    pub fn build() {
        let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let c_root = std::env::var("BROTLI_C_REFERENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| manifest.join("..").join("c"));
        let prefix_h = manifest.join("tools").join("ref_prefix.h");
        let mut build = cc::Build::new();
        build
            .include(c_root.join("include"))
            .include(&c_root)
            .flag("-include")
            .flag(prefix_h.to_str().unwrap())
            // Rust never contracts a*b+c into FMA; make C do the same so the
            // floating point heuristics of the encoder are bit-identical.
            .flag_if_supported("-ffp-contract=off")
            .opt_level(2)
            .warnings(false);
        for sub in ["common", "dec", "enc"] {
            let d = c_root.join(sub);
            println!("cargo:rerun-if-changed={}", d.display());
            for f in c_files(&d) {
                build.file(f);
            }
        }
        let shims = manifest.join("tests").join("c_shims");
        if shims.is_dir() {
            println!("cargo:rerun-if-changed={}", shims.display());
            for f in c_files(&shims) {
                println!("cargo:rerun-if-changed={}", f.display());
                build.file(f);
            }
        }
        build.compile("brotli_c_reference");
        println!("cargo:rustc-link-lib=m");
    }
}
