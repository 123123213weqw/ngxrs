//! Allocation counter for measurement builds (`--features alloc-count`).
//!
//! Used to establish how many heap operations a single request costs, so that
//! an optimisation can be aimed at a measured problem instead of a guess.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

pub static ALLOCS: AtomicUsize = AtomicUsize::new(0);
pub static BYTES: AtomicUsize = AtomicUsize::new(0);

/// Allocations attributed to a region, accumulated across requests:
/// 0 = request parse, 1 = dispatch (routing + content + write), 2 = logging.
pub static PHASE: [AtomicUsize; 3] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

/// Close off one region and start the next. `prev` is the mark value returned
/// by the previous call (0 for the first).
#[inline]
pub fn mark(prev: usize) -> usize {
    let now = ALLOCS.load(Ordering::Relaxed);
    if prev != 0 {
        PHASE[CURRENT.with(|c| c.get())].fetch_add(now - prev, Ordering::Relaxed);
    }
    now
}

thread_local! {
    static CURRENT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[inline]
pub fn set_phase(p: usize) {
    CURRENT.with(|c| c.set(p));
}

pub struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}
