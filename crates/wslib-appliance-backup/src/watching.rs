//! A global allocator for this crate's tests that records what the watching
//! thread frees, so a test can show that no freed buffer still holds a secret.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

static SERIAL: Mutex<()> = Mutex::new(());
thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
}
static OVERFLOWED: AtomicBool = AtomicBool::new(false);
static FREED: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static UNWIPED_ARGON2_MEMORY: AtomicUsize = AtomicUsize::new(0);

/// argon2's memory is `[u64; 128]` blocks aligned to 64: no padding, so every
/// byte of one is initialised.
const ARGON2_BLOCK: usize = 1024;

struct Watching;

// Every block is handed out zeroed and only byte buffers (align 1) and argon2's
// memory are read back, so each byte read is initialised. FREED is only resized
// while no thread is watching, so recording never allocates under its own lock.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.get() {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if layout.align() == 1 {
                let mut freed = lock(&FREED);
                if freed.capacity() - freed.len() >= block.len() {
                    freed.extend_from_slice(block);
                } else {
                    OVERFLOWED.store(true, Ordering::SeqCst);
                }
            } else if layout.align() == 64
                && layout.size().is_multiple_of(ARGON2_BLOCK)
                && block.iter().any(|&b| b != 0)
            {
                UNWIPED_ARGON2_MEMORY.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) struct Freed {
    pub(crate) bytes: Vec<u8>,
    pub(crate) unwiped_argon2_memory: usize,
}

impl Freed {
    pub(crate) fn holds(&self, needle: &[u8]) -> bool {
        self.bytes
            .windows(needle.len())
            .any(|window| window == needle)
    }
}

/// What `run` returned, and what it freed.
pub(crate) fn freed_during<T>(run: impl FnOnce() -> T) -> (T, Freed) {
    let _serial = lock(&SERIAL);
    {
        let mut freed = lock(&FREED);
        freed.clear();
        freed.reserve(8 << 20);
    }
    OVERFLOWED.store(false, Ordering::SeqCst);
    UNWIPED_ARGON2_MEMORY.store(0, Ordering::SeqCst);
    WATCHING.set(true);
    let returned = run();
    WATCHING.set(false);
    assert!(
        !OVERFLOWED.load(Ordering::SeqCst),
        "too much freed to record"
    );
    let freed = Freed {
        bytes: lock(&FREED).clone(),
        unwiped_argon2_memory: UNWIPED_ARGON2_MEMORY.load(Ordering::SeqCst),
    };
    (returned, freed)
}
