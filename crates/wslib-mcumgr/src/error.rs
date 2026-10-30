#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "ble")]
    #[error("BLE: {0}")]
    Ble(#[from] btleplug::Error),

    #[cfg(feature = "ble")]
    #[error("the device has no SMP characteristic")]
    CharacteristicNotFound,

    #[error("the transport closed")]
    LinkClosed,

    #[error("SMP encode failed: {0}")]
    Encode(String),

    #[error("SMP decode failed: {0}")]
    Decode(String),

    /// `group` is set for a version 2 group error, whose `rc` is that group's.
    #[error("the device rejected {reason}: rc {rc}{}", .group.map(|g| format!(" in group {g}")).unwrap_or_default())]
    Rejected {
        rc: i32,
        group: Option<u16>,
        reason: String,
    },

    #[error("the device gave an answer that does not fit the request: {0}")]
    UnexpectedReply(String),

    #[error("no reply in time")]
    Timeout,

    #[error("upload stalled at offset {offset} of {total} bytes")]
    UploadStalled { offset: usize, total: usize },

    #[error("the device's hash of the uploaded image does not match")]
    HashMismatch,

    #[error("not an MCUboot image: {0}")]
    NotMcuboot(String),

    #[error("the device accepted no bytes at offset {offset}")]
    FsNoProgress { offset: usize },

    #[error("remote path is {path_len} bytes; this device takes paths of at most {limit}")]
    FsPathTooLong { path_len: usize, limit: usize },

    #[error("{path} on the device does not match: expected {expected}, found {found}")]
    FsVerifyMismatch {
        path: String,
        expected: String,
        found: String,
    },
}
