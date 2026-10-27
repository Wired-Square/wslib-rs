use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, Ordering};

use wslib_secret::Secret;

const VALUE: &str = "sk-live-0123456789abcdef";

static WATCHED: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static FREED: Mutex<Option<Vec<u8>>> = Mutex::new(None);

struct Watching;

// The watched block is a `String` whose length is its whole layout, so every
// byte read from it is initialised.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHED
            .compare_exchange(
                ptr,
                std::ptr::null_mut(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            let freed = unsafe { std::slice::from_raw_parts(ptr, layout.size()) }.to_vec();
            *FREED.lock().unwrap() = Some(freed);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

#[test]
fn a_dropped_secret_leaves_only_zeros_in_the_freed_buffer() {
    let value = VALUE.to_owned();
    assert_eq!(value.capacity(), value.len());
    let secret = Secret::new(value);
    WATCHED.store(secret.expose().as_ptr().cast_mut(), Ordering::SeqCst);
    drop(secret);
    let freed = FREED.lock().unwrap().take().expect("the buffer was freed");
    assert_eq!(freed.len(), VALUE.len());
    assert!(
        freed.iter().all(|&byte| byte == 0),
        "freed buffer held {freed:?}"
    );
}
