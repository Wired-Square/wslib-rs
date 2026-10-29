use std::time::Duration;

use super::{ExceptionCode, TransportError};

/// Why a request produced no data: did the device answer at all?
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The device answered; the connection is kept.
    #[error("{code}")]
    Exception {
        code: ExceptionCode,
        latency: Duration,
    },
    /// No usable answer; the socket has been dropped.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl RequestError {
    pub fn device_replied(&self) -> bool {
        matches!(self, Self::Exception { .. })
    }
}
