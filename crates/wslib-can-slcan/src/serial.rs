//! The serial port SLCAN reads a device through: read-write and exclusive.

use std::io;

use tokio::{
    task::{JoinError, spawn_blocking},
    time::{Instant, timeout_at},
};
use wslib_can::CanError;
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
        Ok(opened) => finished(opened, |source| CanError::Open {
            device: path.to_owned(),
            source,
        })?,
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
        SerialError::Read(e) | SerialError::Write(e) => CanError::Read(e),
        SerialError::Panicked => CanError::Panicked,
        e => CanError::Serial(e),
    }
}

pub(crate) fn unwritten(error: SerialError) -> io::Error {
    match error {
        SerialError::Write(e) => e,
        e => io::Error::other(self::error(e)),
    }
}

pub(crate) fn finished<T>(
    joined: Result<T, JoinError>,
    cancelled: impl FnOnce(io::Error) -> CanError,
) -> Result<T, CanError> {
    joined.map_err(|e| {
        if e.is_panic() {
            CanError::Panicked
        } else {
            cancelled(io::ErrorKind::Interrupted.into())
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

    fn not_opened(source: io::Error) -> CanError {
        CanError::Open {
            device: "/dev/ttyACM0".into(),
            source,
        }
    }

    #[test]
    fn an_open_that_panicked_is_panicked_and_one_cancelled_is_an_interrupted_open() {
        assert!(matches!(
            finished(panicked::<()>(), not_opened),
            Err(CanError::Panicked)
        ));
        let cancelled = finished(cancelled(()), not_opened);
        assert!(
            matches!(&cancelled, Err(CanError::Open { source, .. }) if source.kind() == io::ErrorKind::Interrupted),
            "{cancelled:?}"
        );
    }

    #[test]
    fn a_write_that_panicked_is_an_io_error_holding_panicked() {
        let panicked = unwritten(SerialError::Panicked);
        assert!(
            matches!(
                panicked
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<CanError>()),
                Some(CanError::Panicked)
            ),
            "{panicked:?}"
        );
        let failed = unwritten(SerialError::Write(io::ErrorKind::BrokenPipe.into()));
        assert_eq!(failed.kind(), io::ErrorKind::BrokenPipe);
        assert!(failed.get_ref().is_none());
    }
}
