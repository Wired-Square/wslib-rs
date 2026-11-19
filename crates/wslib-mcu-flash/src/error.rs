use std::error::Error;

use crate::identity::{Mac, reported_mac};

#[derive(Debug, thiserror::Error)]
pub enum FlashError {
    #[error("{0}")]
    Message(String),
    /// A step failed in espflash, serialport, nusb, the OS, SMP or another
    /// step; `why` says which, and the source is its error.
    #[error("{why}")]
    Failed {
        why: String,
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    #[error("USB device {0:?} not attached")]
    NotAttached(String),
    #[error(
        "connected chip reports MAC {}, expected {expected}; nothing was written",
        reported_mac(*.actual)
    )]
    IdentityMismatch { expected: Mac, actual: Option<Mac> },
    #[error("cancelled by user")]
    Cancelled,
}

impl From<&str> for FlashError {
    fn from(s: &str) -> Self {
        FlashError::Message(s.to_string())
    }
}

pub(crate) fn failed(
    why: impl Into<String>,
    source: impl Error + Send + Sync + 'static,
) -> FlashError {
    FlashError::Failed {
        why: why.into(),
        source: Box::new(source),
    }
}

pub type Result<T> = std::result::Result<T, FlashError>;
