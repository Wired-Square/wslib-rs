//! The journal formatter's writer: stdout, and when stdout is a journal stream,
//! each line prefixed with sd-daemon's `<N>` so journald stores it at its
//! event's priority rather than at `info`.
//!
//! journald reads a stream line by line, so every line of a multi-line event
//! carries the prefix. Anywhere else the text passes through unchanged.

use std::io::{self, Write};

use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;

pub(crate) fn stdout() -> LevelPrefix<impl Fn() -> io::StdoutLock<'static>> {
    LevelPrefix {
        inner: || io::stdout().lock(),
        journal: stdout_is_journal(),
    }
}

pub(crate) struct LevelPrefix<M> {
    inner: M,
    journal: bool,
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for LevelPrefix<M> {
    type Writer = Prefixed<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        Prefixed::new(self.inner.make_writer(), None)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        let prefix = self.journal.then(|| priority(meta.level()));
        Prefixed::new(self.inner.make_writer_for(meta), prefix)
    }
}

fn priority(level: &Level) -> &'static [u8] {
    match *level {
        Level::ERROR => b"<3>",
        Level::WARN => b"<4>",
        Level::INFO => b"<6>",
        _ => b"<7>",
    }
}

pub(crate) struct Prefixed<W> {
    inner: W,
    prefix: Option<&'static [u8]>,
    line_start: bool,
}

impl<W> Prefixed<W> {
    fn new(inner: W, prefix: Option<&'static [u8]>) -> Self {
        Self {
            inner,
            prefix,
            line_start: true,
        }
    }
}

impl<W: Write> Write for Prefixed<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(prefix) = self.prefix else {
            return self.inner.write(buf);
        };
        for line in buf.split_inclusive(|&b| b == b'\n') {
            if self.line_start {
                self.inner.write_all(prefix)?;
            }
            self.inner.write_all(line)?;
            self.line_start = line.ends_with(b"\n");
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Compares `JOURNAL_STREAM` with stdout itself, as systemd.exec(5) asks: a
/// child of the service inherits the variable without inheriting the stream.
#[cfg(unix)]
fn stdout_is_journal() -> bool {
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;

    let Ok(fd) = io::stdout().as_fd().try_clone_to_owned() else {
        return false;
    };
    std::fs::File::from(fd).metadata().is_ok_and(|stdout| {
        names_stream(
            std::env::var("JOURNAL_STREAM").ok().as_deref(),
            stdout.dev(),
            stdout.ino(),
        )
    })
}

#[cfg(not(unix))]
fn stdout_is_journal() -> bool {
    false
}

#[cfg(unix)]
fn names_stream(journal_stream: Option<&str>, dev: u64, ino: u64) -> bool {
    journal_stream
        .and_then(|value| value.split_once(':'))
        .is_some_and(|(d, i)| d.parse() == Ok(dev) && i.parse() == Ok(ino))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn written(journal: bool, emit: impl FnOnce()) -> String {
        let buffer = Buffer::default();
        let writer = LevelPrefix {
            inner: {
                let buffer = buffer.clone();
                move || buffer.clone()
            },
            journal,
        };
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_writer(writer),
        );
        tracing::subscriber::with_default(subscriber, emit);
        String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn on_the_journal_each_level_carries_its_sd_daemon_priority() {
        let text = written(true, || {
            tracing::error!("e");
            tracing::warn!("w");
            tracing::info!("i");
            tracing::debug!("d");
            tracing::trace!("t");
        });
        let prefixes: Vec<_> = text.lines().map(|line| &line[..3]).collect();
        assert_eq!(prefixes, ["<3>", "<4>", "<6>", "<7>", "<7>"], "{text}");
    }

    #[test]
    fn off_the_journal_the_text_is_unchanged() {
        let text = written(false, || tracing::warn!("w"));
        assert!(text.starts_with(" WARN"), "{text:?}");
    }

    #[test]
    fn every_line_of_a_multi_line_event_is_prefixed() {
        let text = written(true, || tracing::warn!("first\nsecond"));
        assert!(text.starts_with("<4> WARN"), "{text:?}");
        assert!(text.ends_with("first\n<4>second\n"), "{text:?}");
    }

    #[test]
    fn a_line_split_across_writes_is_prefixed_once() {
        let buffer = Buffer::default();
        let mut writer = Prefixed::new(buffer.clone(), Some(b"<4>"));
        for chunk in ["a", "b\nc", "\n"] {
            writer.write_all(chunk.as_bytes()).unwrap();
        }
        assert_eq!(*buffer.0.lock().unwrap(), b"<4>ab\n<4>c\n");
    }

    #[cfg(unix)]
    #[test]
    fn the_stream_is_the_journal_only_when_both_numbers_match() {
        assert!(names_stream(Some("8:12345"), 8, 12345));
        assert!(!names_stream(Some("8:12345"), 9, 12345));
        assert!(!names_stream(Some("8:12345"), 8, 12346));
        assert!(!names_stream(None, 8, 12345));
        assert!(!names_stream(Some("8"), 8, 12345));
        assert!(!names_stream(Some(""), 8, 12345));
    }
}
