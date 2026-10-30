//! Framing codecs for byte streams, COBS first, sharing one [`Framed`]
//! output.

pub mod cobs;

/// A frame a decoder released, and where in its input the frame ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framed {
    pub bytes: Vec<u8>,
    /// Bytes fed through the one that released it; always at least 1.
    pub end_offset: u64,
}
