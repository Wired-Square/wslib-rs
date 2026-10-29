//! The serial port GVRET reads a device through: read-write and exclusive.

use std::io;

use tokio::{
    task::spawn_blocking,
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
        Ok(opened) => opened.map_err(|e| CanError::Read(io::Error::other(e)))?,
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

fn error(error: SerialError) -> CanError {
    match error {
        SerialError::Open { path, source } => CanError::Open {
            device: path,
            source,
        },
        SerialError::Closed => CanError::Closed,
        SerialError::Read(e) => CanError::Read(e),
        e => CanError::Config(e.to_string()),
    }
}
