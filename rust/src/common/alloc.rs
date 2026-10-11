//! Memory management mirroring the C library semantics.
//!
//! The C API lets clients supply custom `alloc_func` / `free_func` callbacks
//! plus an `opaque` pointer.  All internal buffers of encoder / decoder
//! instances are allocated through those callbacks, exactly like in C.
//!
//! [`Buf<T>`] is a fixed-size, owned, zero/default-initialized array allocated
//! through an [`Allocator`].  It derefs to `[T]`, so the rest of the code base
//! works with ordinary (bounds-checked) slices.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

/// `brotli_alloc_func` from `<brotli/types.h>`.
pub type BrotliAllocFunc = Option<unsafe extern "C" fn(opaque: *mut c_void, size: usize) -> *mut c_void>;
/// `brotli_free_func` from `<brotli/types.h>`.
pub type BrotliFreeFunc = Option<unsafe extern "C" fn(opaque: *mut c_void, address: *mut c_void)>;

extern "C" {
    fn calloc(count: usize, size: usize) -> *mut c_void;
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn exit(code: i32) -> !;
}

/// `BrotliDefaultAllocFunc`.
///
/// # Safety
/// Plain `malloc`; the result must be released with [`default_free_func`].
pub unsafe extern "C" fn default_alloc_func(_opaque: *mut c_void, size: usize) -> *mut c_void {
    malloc(size)
}

/// `BrotliDefaultFreeFunc`.
///
/// # Safety
/// `address` must be NULL or come from [`default_alloc_func`].
pub unsafe extern "C" fn default_free_func(_opaque: *mut c_void, address: *mut c_void) {
    free(address)
}

/// Allocation callbacks (the equivalent of C `MemoryManager`).
#[derive(Clone, Copy)]
pub struct Allocator {
    alloc_func: unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void,
    free_func: unsafe extern "C" fn(*mut c_void, *mut c_void),
    opaque: *mut c_void,
}

impl core::fmt::Debug for Allocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Allocator").field("opaque", &self.opaque).finish()
    }
}

impl Default for Allocator {
    fn default() -> Self {
        Allocator { alloc_func: default_alloc_func, free_func: default_free_func, opaque: core::ptr::null_mut() }
    }
}

impl Allocator {
    /// Mirrors `BrotliInitMemoryManager`: if `alloc_func` is NULL, default
    /// malloc/free are used (and `opaque` is ignored).
    ///
    /// If `alloc_func` is set but `free_func` is NULL, freeing is a no-op
    /// (in C it would crash).  Callers validate the pair beforehand anyway.
    pub fn new(alloc_func: BrotliAllocFunc, free_func: BrotliFreeFunc, opaque: *mut c_void) -> Self {
        match alloc_func {
            None => Allocator::default(),
            Some(a) => Allocator { alloc_func: a, free_func: free_func.unwrap_or(noop_free), opaque },
        }
    }

    /// Raw allocation through the client callback.
    ///
    /// # Safety
    /// The returned memory is uninitialized.
    #[inline]
    pub unsafe fn alloc_raw(&self, size: usize) -> *mut c_void {
        (self.alloc_func)(self.opaque, size)
    }

    /// True if these are the default (malloc / free) callbacks.
    #[inline]
    pub fn is_default(&self) -> bool {
        self.alloc_func as usize == default_alloc_func as usize && self.free_func as usize == default_free_func as usize
    }

    /// Raw free through the client callback.
    ///
    /// # Safety
    /// `ptr` must have been obtained from [`Allocator::alloc_raw`] of an
    /// allocator with the same callbacks.
    #[inline]
    pub unsafe fn free_raw(&self, ptr: *mut c_void) {
        (self.free_func)(self.opaque, ptr)
    }
}

unsafe extern "C" fn noop_free(_opaque: *mut c_void, _address: *mut c_void) {}

/// Mirrors `BrotliBootstrapAlloc`: allocates the instance object itself.
/// Both callbacks NULL → malloc; both set → custom; mixed → failure (NULL).
///
/// # Safety
/// Calls the client allocator; the returned memory is uninitialized.
pub unsafe fn bootstrap_alloc(size: usize, alloc_func: BrotliAllocFunc, free_func: BrotliFreeFunc, opaque: *mut c_void) -> *mut c_void {
    match (alloc_func, free_func) {
        (None, None) => malloc(size),
        (Some(a), Some(_)) => a(opaque, size),
        _ => core::ptr::null_mut(),
    }
}

/// Encoder out-of-memory policy (`BROTLI_ENCODER_EXIT_ON_OOM`, the C default).
#[cold]
pub fn oom_exit() -> ! {
    unsafe { exit(1) }
}

/// Types for which the all-zero bit pattern is a valid value equal to
/// `Default::default()`.
///
/// # Safety
/// Implementors must guarantee the above.
pub unsafe trait Zeroable: Copy + Default {}
unsafe impl Zeroable for u8 {}
unsafe impl Zeroable for u16 {}
unsafe impl Zeroable for u32 {}
unsafe impl Zeroable for u64 {}
unsafe impl Zeroable for usize {}
unsafe impl Zeroable for i8 {}
unsafe impl Zeroable for i16 {}
unsafe impl Zeroable for i32 {}
unsafe impl Zeroable for i64 {}
unsafe impl Zeroable for isize {}
unsafe impl Zeroable for f32 {}
unsafe impl Zeroable for f64 {}

/// Owned, fixed-length array allocated through an [`Allocator`].
///
/// Equivalent of a `T*` obtained via `BROTLI_ALLOC`, but initialized with
/// `T::default()` and with its length attached.  An empty `Buf` corresponds to
/// a NULL pointer in C and owns no memory.
pub struct Buf<T: Copy + Default> {
    ptr: NonNull<T>,
    len: usize,
    alloc: Allocator,
    _marker: PhantomData<T>,
}

impl<T: Copy + Default> Buf<T> {
    /// An empty buffer (C NULL); does not allocate.
    #[inline]
    pub fn empty() -> Self {
        Buf { ptr: NonNull::dangling(), len: 0, alloc: Allocator::default(), _marker: PhantomData }
    }

    /// Allocates `len` elements, returning `None` on allocation failure.
    /// `len == 0` yields an empty buffer without calling the allocator.
    pub fn try_new(m: &Allocator, len: usize) -> Option<Self> {
        if len == 0 {
            return Some(Self::empty());
        }
        let size = len.checked_mul(core::mem::size_of::<T>())?;
        let raw = unsafe { m.alloc_raw(size) } as *mut T;
        let ptr = NonNull::new(raw)?;
        debug_assert!((raw as usize) % core::mem::align_of::<T>() == 0);
        unsafe {
            let v = T::default();
            for i in 0..len {
                core::ptr::write(raw.add(i), v);
            }
        }
        Some(Buf { ptr, len, alloc: *m, _marker: PhantomData })
    }

    /// Like [`Buf::try_new`], for types whose all-zero bit pattern is their
    /// default value.  With the default allocator this uses `calloc`, so
    /// large buffers are backed by lazily materialized zero pages (same
    /// memory footprint as the C library's uninitialized `malloc`).
    pub fn try_new_zeroed(m: &Allocator, len: usize) -> Option<Self>
    where
        T: Zeroable,
    {
        if len == 0 {
            return Some(Self::empty());
        }
        let size = len.checked_mul(core::mem::size_of::<T>())?;
        let raw = if m.is_default() {
            unsafe { calloc(len, core::mem::size_of::<T>()) as *mut T }
        } else {
            let p = unsafe { m.alloc_raw(size) } as *mut T;
            if !p.is_null() {
                // SAFETY: `p` points to `size` writable bytes.
                unsafe { core::ptr::write_bytes(p as *mut u8, 0, size) };
            }
            p
        };
        let ptr = NonNull::new(raw)?;
        debug_assert!((raw as usize) % core::mem::align_of::<T>() == 0);
        Some(Buf { ptr, len, alloc: *m, _marker: PhantomData })
    }

    /// [`Buf::try_new_zeroed`]; terminates the process on OOM.
    #[inline]
    pub fn new_zeroed(m: &Allocator, len: usize) -> Self
    where
        T: Zeroable,
    {
        match Self::try_new_zeroed(m, len) {
            Some(b) => b,
            None => oom_exit(),
        }
    }

    /// Allocates `len` elements; terminates the process on OOM (encoder
    /// semantics, `BROTLI_ENCODER_EXIT_ON_OOM`).
    #[inline]
    pub fn new(m: &Allocator, len: usize) -> Self {
        match Self::try_new(m, len) {
            Some(b) => b,
            None => oom_exit(),
        }
    }

    /// Allocates a copy of `src`.
    pub fn from_slice(m: &Allocator, src: &[T]) -> Self {
        let mut b = Self::new(m, src.len());
        b.copy_from_slice(src);
        b
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mirrors `BROTLI_ENSURE_CAPACITY(m, T, buf, capacity, requested)` where
    /// capacity == `self.len()`: grows (doubling) preserving contents.
    pub fn ensure_capacity(&mut self, m: &Allocator, requested: usize) {
        if self.len < requested {
            let mut new_size = if self.len == 0 { requested } else { self.len };
            while new_size < requested {
                new_size *= 2;
            }
            let mut nb = Self::new(m, new_size);
            nb[..self.len].copy_from_slice(&self[..]);
            *self = nb;
        }
    }

    /// Releases memory; the buffer becomes empty (C: `BROTLI_FREE`).
    #[inline]
    pub fn free(&mut self) {
        *self = Self::empty();
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr.as_ptr()
    }
}

impl<T: Copy + Default> Default for Buf<T> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<T: Copy + Default> Drop for Buf<T> {
    fn drop(&mut self) {
        if self.len != 0 {
            unsafe { self.alloc.free_raw(self.ptr.as_ptr() as *mut c_void) }
        }
    }
}

impl<T: Copy + Default> Deref for Buf<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T: Copy + Default> DerefMut for Buf<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T: Copy + Default + core::fmt::Debug> core::fmt::Debug for Buf<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Buf").field("len", &self.len).finish()
    }
}

/// Allocates a single object of type `T` through the allocator and moves
/// `value` into it.  Used for instance objects handed out as opaque pointers.
pub struct Boxed<T> {
    ptr: NonNull<T>,
    alloc: Allocator,
}

impl<T> Boxed<T> {
    pub fn try_new(m: &Allocator, value: T) -> Option<Self> {
        let raw = unsafe { m.alloc_raw(core::mem::size_of::<T>().max(1)) } as *mut T;
        let ptr = NonNull::new(raw)?;
        unsafe { core::ptr::write(raw, value) };
        Some(Boxed { ptr, alloc: *m })
    }
    pub fn new(m: &Allocator, value: T) -> Self {
        match Self::try_new(m, value) {
            Some(b) => b,
            None => oom_exit(),
        }
    }
}

impl<T> Drop for Boxed<T> {
    fn drop(&mut self) {
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
            self.alloc.free_raw(self.ptr.as_ptr() as *mut c_void);
        }
    }
}

impl<T> Deref for Boxed<T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for Boxed<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }
}
