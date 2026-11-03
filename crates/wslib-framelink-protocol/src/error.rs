use crate::{
    frame_def::{MAX_SIGNALS, SIGNAL_MAX_BITS},
    manufacturer_data::PAYLOAD_LEN,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("COBS decode error")]
    CobsDecode,

    #[error("frame too short")]
    TooShort,

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("length mismatch: header says {header}, actual {actual}")]
    LengthMismatch { header: usize, actual: usize },

    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),

    #[error(
        "frame definition signal {signal_id}: bit_length {bit_length} is outside 1 to {SIGNAL_MAX_BITS}"
    )]
    SignalBits { signal_id: u16, bit_length: u16 },

    #[error("frame definition has {0} signals; at most {MAX_SIGNALS} fit")]
    TooManySignals(usize),

    #[error("frame definition id {0:#06x} is reserved for the signal store")]
    ReservedFrameDefId(u16),

    #[error("manufacturer data length {actual}, expected {PAYLOAD_LEN}")]
    ManufacturerDataLength { actual: usize },

    #[error("manufacturer data schema {found:#04x} is newer than supported {max_known:#04x}")]
    UnsupportedSchema { found: u8, max_known: u8 },

    #[error("signal key '{key}': expected 4-6 dot-separated segments")]
    SignalKeySegments { key: String },

    #[error("signal key '{key}': unknown target '{segment}'")]
    SignalKeyTarget { key: String, segment: String },

    #[error("signal key '{key}': bad target index '{segment}'")]
    SignalKeyTargetIndex { key: String, segment: String },

    #[error("signal key '{key}': unknown role '{segment}'")]
    SignalKeyRole { key: String, segment: String },

    #[error("signal key '{key}': unknown quantity '{segment}'")]
    SignalKeyQuantity { key: String, segment: String },

    #[error("signal key '{key}': bad channel '{segment}'")]
    SignalKeyChannel { key: String, segment: String },

    #[error("signal key '{key}': unknown aspect '{segment}'")]
    SignalKeyAspect { key: String, segment: String },
}

impl From<wslib_framing::cobs::CobsError> for Error {
    fn from(_: wslib_framing::cobs::CobsError) -> Self {
        Self::CobsDecode
    }
}
