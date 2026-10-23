#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlashError {
    #[error("{0}")]
    Message(String),
    #[error("USB device with serial {0:?} not attached")]
    NotAttached(String),
    #[error("cancelled by user")]
    Cancelled,
}

impl From<String> for FlashError {
    fn from(s: String) -> Self {
        FlashError::Message(s)
    }
}

impl From<&str> for FlashError {
    fn from(s: &str) -> Self {
        FlashError::Message(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, FlashError>;
