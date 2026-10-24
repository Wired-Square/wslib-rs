//! A binary of its own, because it swaps the process's panic hook and installs
//! the global subscriber.
#![cfg(unix)]

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use wslib_service::{Daemon, Failure};

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn boom() -> Result<(), String> {
    panic!("boom")
}

#[test]
fn a_panic_is_logged_with_where_and_the_previous_hook_is_back_once_run_returns() {
    let captured = Captured::default();
    let writer = captured.clone();
    wslib_telemetry::Telemetry::new("info")
        .writer(move || writer.clone())
        .init();
    static PREVIOUS_CALLED: AtomicBool = AtomicBool::new(false);
    std::panic::set_hook(Box::new(|_| PREVIOUS_CALLED.store(true, Ordering::SeqCst)));

    let ran = Daemon::new("widgets").run(|_stop| async { boom() });
    assert!(matches!(ran, Err(Failure::Panicked)), "{ran:?}");
    assert!(
        !PREVIOUS_CALLED.load(Ordering::SeqCst),
        "replaced while main ran"
    );
    let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains("a thread of the service panicked at ")
            && logged.contains("panic_hook.rs")
            && logged.contains(": boom")
            && logged.contains("service=widgets"),
        "{logged}"
    );

    std::panic::catch_unwind(|| panic!("after")).unwrap_err();
    assert!(PREVIOUS_CALLED.load(Ordering::SeqCst), "restored");
}
