#![cfg(feature = "setup-core")]

use std::io;
use std::sync::{Arc, Mutex};

use wslib_telemetry::Telemetry;

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

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn written(telemetry: impl FnOnce(Telemetry) -> Telemetry) -> String {
    let captured = Captured::default();
    let writer = captured.clone();
    let _guard = telemetry(Telemetry::new("info").writer(move || writer.clone())).set_default();
    tracing::info!(target: "written", "to the writer");
    captured.text()
}

#[test]
fn a_writer_takes_the_lines_without_colour_by_default() {
    let text = written(|telemetry| telemetry);
    assert!(
        text.trim_end().ends_with("written: to the writer"),
        "{text}"
    );
    assert!(!text.contains('\x1b'), "{text:?}");
}

#[cfg(feature = "ansi")]
#[test]
fn a_writer_has_colour_when_asked() {
    let text = written(|telemetry| telemetry.ansi(true));
    assert!(text.contains('\x1b'), "{text:?}");
}
