//! The C ABI static library (`libbrotli_capi.a` / `brotli_capi.lib`).
//!
//! All exported symbols (`BrotliEncoder*`, `BrotliDecoder*`,
//! `BrotliSharedDictionary*`, ...) come from `brotli::ffi`.  This crate is
//! `no_std`: the resulting archive only depends on libc (`malloc`, `free`,
//! `exit`, `abort`, `write`) and libm (`log2`), like the C implementation.
//! The build system turns it into `libbrotlicommon`, `libbrotlidec` and
//! `libbrotlienc`.

#![no_std]

// Make sure the implementation (and its `#[no_mangle]` exports) is linked.
pub use brotli;

extern "C" {
    fn abort() -> !;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

struct StderrBuf {
    buf: [u8; 512],
    len: usize,
}

impl core::fmt::Write for StderrBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Panics never happen for valid API use; they indicate an internal bug.
/// Like a failed `BROTLI_DCHECK` / `BROTLI_CRASH()` in C, report and abort.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let mut w = StderrBuf { buf: [0; 512], len: 0 };
    let _ = writeln!(w, "brotli (rust): internal error: {}", info);
    unsafe {
        write(2, w.buf.as_ptr(), w.len);
        abort()
    }
}

/// Precompiled `core` objects reference the unwinding personality routine;
/// with `panic = "abort"` it is never called.  Defined so that C linkers
/// never see an undefined symbol.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
