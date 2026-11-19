//! The serial port SLCAN reads a device through: read-write and exclusive.

use std::io;

use tokio::{
    task::{JoinError, spawn_blocking},
    time::{Instant, timeout_at},
};
use wslib_can::{CanError, WriteFailed};
use wslib_serial::{Access, LineSettings, SerialError, SerialOptions, SerialPort};

pub(crate) fn open(path: &str, line: LineSettings) -> Result<SerialPort, CanError> {
    let options = SerialOptions {
        access: Access::ReadWrite,
        ..SerialOptions::default()
    };
    SerialPort::open(path, line, &options).map_err(error)
}

/// `open` on the blocking pool, so a stalled OS open can't outlast `deadline`:
/// its thread is abandoned then, and the port closed when it returns.
pub(crate) async fn open_before(
    path: &str,
    line: LineSettings,
    deadline: Instant,
) -> Result<SerialPort, CanError> {
    let owned = path.to_owned();
    match timeout_at(deadline, spawn_blocking(move || open(&owned, line))).await {
        Ok(opened) => finished(opened)?,
        Err(_) => Err(CanError::Open {
            device: path.to_owned(),
            source: io::ErrorKind::TimedOut.into(),
        }),
    }
}

/// Cancel-safe: writes `outbound` first, and returns at least a byte.
pub(crate) async fn read(
    port: &mut SerialPort,
    outbound: &mut Vec<u8>,
) -> Result<Vec<u8>, CanError> {
    if !outbound.is_empty() {
        let _ = port.write(outbound).await;
    }
    port.read().await.map_err(error)
}

pub(crate) fn error(error: SerialError) -> CanError {
    match error {
        SerialError::Open { path, source } => CanError::Open {
            device: path,
            source,
        },
        SerialError::Closed => CanError::Closed,
        SerialError::Read(e) => CanError::Read(e),
        SerialError::Panicked => CanError::Panicked,
        SerialError::Cancelled => CanError::Cancelled,
        e => CanError::Serial(e),
    }
}

pub(crate) fn unwritten(error: SerialError) -> WriteFailed {
    match error {
        SerialError::Write(e) => WriteFailed::Io(e),
        SerialError::Panicked => WriteFailed::Panicked,
        SerialError::Cancelled => WriteFailed::Cancelled,
        e => WriteFailed::Serial(e),
    }
}

pub(crate) fn finished<T>(joined: Result<T, JoinError>) -> Result<T, CanError> {
    joined.map_err(|e| {
        if e.is_panic() {
            CanError::Panicked
        } else {
            CanError::Cancelled
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::mpsc;

    use tokio::runtime::Builder;

    use super::*;

    pub(crate) fn panicked<T: Send + 'static>() -> Result<T, JoinError> {
        Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                spawn_blocking(|| -> T { panic!("a blocking call panicked") }).await
            })
    }

    pub(crate) fn cancelled<T: Send + 'static>(value: T) -> Result<T, JoinError> {
        let runtime = Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, held) = mpsc::channel::<()>();
            let busy = spawn_blocking(move || held.recv());
            let queued = spawn_blocking(move || value);
            queued.abort();
            release.send(()).unwrap();
            busy.await.unwrap().unwrap();
            queued.await
        })
    }

    #[test]
    fn an_open_that_panicked_is_panicked_and_one_cancelled_is_cancelled() {
        assert!(matches!(
            finished(panicked::<()>()),
            Err(CanError::Panicked)
        ));
        let cancelled = finished(cancelled(()));
        assert!(
            matches!(cancelled, Err(CanError::Cancelled)),
            "{cancelled:?}"
        );
    }

    #[test]
    fn each_serial_error_is_the_can_error_for_it() {
        let opened = error(SerialError::Open {
            path: "/dev/ttyACM0".into(),
            source: io::ErrorKind::NotFound.into(),
        });
        assert!(
            matches!(&opened, CanError::Open { device, source } if device == "/dev/ttyACM0" && source.kind() == io::ErrorKind::NotFound),
            "{opened:?}"
        );
        assert!(matches!(error(SerialError::Closed), CanError::Closed));
        let read = error(SerialError::Read(io::ErrorKind::BrokenPipe.into()));
        assert!(
            matches!(&read, CanError::Read(e) if e.kind() == io::ErrorKind::BrokenPipe),
            "{read:?}"
        );
        assert!(matches!(error(SerialError::Panicked), CanError::Panicked));
        assert!(matches!(error(SerialError::Cancelled), CanError::Cancelled));
        let written = error(SerialError::Write(io::ErrorKind::BrokenPipe.into()));
        assert!(
            matches!(written, CanError::Serial(SerialError::Write(_))),
            "{written:?}"
        );
        assert!(matches!(
            error(SerialError::UnsupportedBaud(1)),
            CanError::Serial(SerialError::UnsupportedBaud(1))
        ));
    }

    #[test]
    fn a_serial_write_that_failed_or_panicked_is_the_typed_write_failure() {
        assert!(matches!(
            unwritten(SerialError::Panicked),
            WriteFailed::Panicked
        ));
        assert!(matches!(
            unwritten(SerialError::Cancelled),
            WriteFailed::Cancelled
        ));
        let failed = unwritten(SerialError::Write(io::ErrorKind::BrokenPipe.into()));
        assert!(
            matches!(&failed, WriteFailed::Io(e) if e.kind() == io::ErrorKind::BrokenPipe),
            "{failed:?}"
        );
        assert!(matches!(
            unwritten(SerialError::Closed),
            WriteFailed::Serial(SerialError::Closed)
        ));
    }
}
