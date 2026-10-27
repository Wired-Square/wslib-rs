use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::{fs, path::PathBuf};

use wslib_secret::Secret;

const VALUE: &str = "sk-live-0123456789abcdef";

static SERIAL: Mutex<()> = Mutex::new(());
thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
}
static OVERFLOWED: AtomicBool = AtomicBool::new(false);
static FREED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Watching;

// Every block is handed out zeroed and only byte buffers (align 1) are read
// back, so each byte read is initialised. FREED is only resized while no
// thread is watching, so recording never allocates under its own lock.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.get() && layout.align() == 1 {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let mut freed = lock(&FREED);
            if freed.capacity() - freed.len() >= block.len() {
                freed.extend_from_slice(block);
            } else {
                OVERFLOWED.store(true, Ordering::SeqCst);
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

/// What `run` returned, and every byte buffer it freed.
fn freed_during<T>(run: impl FnOnce() -> T) -> (T, Vec<u8>) {
    let _serial = lock(&SERIAL);
    {
        let mut freed = lock(&FREED);
        freed.clear();
        freed.reserve(1 << 20);
    }
    OVERFLOWED.store(false, Ordering::SeqCst);
    WATCHING.set(true);
    let returned = run();
    WATCHING.set(false);
    assert!(
        !OVERFLOWED.load(Ordering::SeqCst),
        "too much freed to record"
    );
    (returned, lock(&FREED).clone())
}

fn assert_frees_no_plaintext(run: impl FnOnce()) {
    let ((), freed) = freed_during(run);
    assert!(
        !holds(&freed, VALUE.as_bytes()),
        "a freed buffer held the plaintext"
    );
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str, contents: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wslib-secret-zeroise-{name}-{}",
            std::process::id()
        ));
        fs::write(&path, contents).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn a_dropped_secret_leaves_no_plaintext() {
    let secret = Secret::new(VALUE);
    assert_frees_no_plaintext(|| drop(secret));
}

#[test]
fn reading_a_file_leaves_no_plaintext() {
    let file = Scratch::new("file", format!("{VALUE}\r\n").as_bytes());
    assert_frees_no_plaintext(|| {
        assert_eq!(Secret::from_file(&file.0).unwrap().expose(), VALUE);
    });
}

#[test]
fn a_file_that_is_not_utf8_leaves_no_plaintext() {
    let file = Scratch::new("not-utf8", &[VALUE.as_bytes(), b"\xff\n"].concat());
    assert_frees_no_plaintext(|| assert!(Secret::from_file(&file.0).is_err()));
}

#[test]
fn a_variable_refused_alongside_its_file_leaves_no_plaintext() {
    let file = Scratch::new("both", VALUE.as_bytes());
    let lookup = |var: &str| match var {
        "KEY" => Some(VALUE.into()),
        "KEY_FILE" => Some(file.0.clone().into_os_string()),
        _ => None,
    };
    assert_frees_no_plaintext(|| assert!(Secret::from_vars("KEY", lookup).is_err()));
}

#[cfg(unix)]
#[test]
fn a_variable_that_is_not_unicode_leaves_no_plaintext() {
    use std::os::unix::ffi::OsStringExt;

    let lookup = |var: &str| {
        (var == "KEY").then(|| std::ffi::OsString::from_vec([VALUE.as_bytes(), b"\xff"].concat()))
    };
    assert_frees_no_plaintext(|| assert!(Secret::from_vars("KEY", lookup).is_err()));
}

#[cfg(feature = "serde")]
#[test]
fn deserialising_bytes_that_are_not_utf8_leaves_no_plaintext() {
    use serde::de::{Deserialize, Deserializer, Visitor, value::Error};

    struct OwnedBytes(Vec<u8>);

    impl<'de> Deserializer<'de> for OwnedBytes {
        type Error = Error;

        fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            visitor.visit_byte_buf(self.0)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map struct enum identifier ignored_any
        }
    }

    let bytes = OwnedBytes([VALUE.as_bytes(), b"\xff"].concat());
    assert_frees_no_plaintext(|| assert!(Secret::deserialize(bytes).is_err()));
}

#[cfg(feature = "token")]
#[test]
fn a_random_secret_leaves_no_partial_copy() {
    use wslib_secret::Encoding;

    for encoding in [Encoding::Base64Url, Encoding::Base32] {
        let (secret, freed) = freed_during(|| Secret::random::<32>(encoding).unwrap());
        let prefix = &secret.expose().as_bytes()[..8];
        assert!(
            !holds(&freed, prefix),
            "{encoding:?}: a freed buffer held a prefix"
        );
    }
}
