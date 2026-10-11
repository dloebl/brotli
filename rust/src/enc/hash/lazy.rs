//! Lazily initialized hash table storage.
//!
//! The C hashers `malloc` their big tables and never initialize the parts
//! that are not read before being written; for the H10 forest this can be
//! 8 GiB (1 GiB window), of which C only ever touches what the input
//! reaches.  `Buf::new` would zero (and thus commit) all of that memory up
//! front.  [`LazyPrefix`] allocates through the client allocator without
//! initializing, and fills a prefix the first time it is handed out, so
//! safe code only ever sees initialized memory.

use core::mem::MaybeUninit;

use crate::enc::memory::{Buf, MemoryManager};

/// Element storage that is not initialized on allocation.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Uninit<T: Copy>(MaybeUninit<T>);

impl<T: Copy> Default for Uninit<T> {
    #[inline(always)]
    fn default() -> Self {
        Uninit(MaybeUninit::uninit())
    }
}

#[inline(always)]
fn assume_init_mut<T: Copy>(s: &mut [Uninit<T>]) -> &mut [T] {
    // SAFETY: `Uninit<T>` is `repr(transparent)` over `MaybeUninit<T>`,
    // which has the layout of `T`; callers only pass fully initialized
    // regions.
    unsafe { &mut *(s as *mut [Uninit<T>] as *mut [T]) }
}

/// An array whose prefix `[0, initialized)` is initialized; `ensure`
/// extends the prefix by filling with `fill`.
pub struct LazyPrefix<T: Copy> {
    data: Buf<Uninit<T>>,
    initialized: usize,
    fill: T,
}

impl<T: Copy> LazyPrefix<T> {
    pub fn new(m: &MemoryManager, len: usize, fill: T) -> Self {
        LazyPrefix { data: Buf::new(m, len), initialized: 0, fill }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, len: usize) {
        let fill = self.fill;
        for e in self.data[self.initialized..len].iter_mut() {
            *e = Uninit(MaybeUninit::new(fill));
        }
        self.initialized = len;
    }

    /// Makes sure that `[0, len)` is initialized.
    #[inline(always)]
    pub fn ensure(&mut self, len: usize) {
        if len > self.initialized {
            self.grow(len);
        }
    }

    /// The initialized prefix.
    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        let n = self.initialized;
        // `[0, initialized)` has been filled by `grow`.
        assume_init_mut(&mut self.data[..n])
    }
}
