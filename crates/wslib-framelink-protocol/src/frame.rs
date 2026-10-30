//! FrameLink frames: `00`, then a 5-byte header and the payload COBS-stuffed,
//! then `00`.
//!
//! Header, little-endian: `version_flags` (u8: bits 7–4 the protocol version,
//! 3–0 the flags), `type` (u8), `seq` (u8), `length` (u16, the payload's).
//! There is no CRC; the transport carries integrity.

use crate::Error;
use wslib_framing::cobs;

/// The only protocol version this crate speaks; a frame with any other is
/// refused.
pub const PROTOCOL_VERSION: u8 = 4;

pub const HEADER_SIZE: usize = 5;

/// A parsed FrameLink frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub flags: u8,
    pub msg_type: u8,
    pub seq: u8,
    pub payload: Vec<u8>,
}

/// A whole frame for the wire, delimiters included.
pub fn build_frame(msg_type: u8, flags: u8, seq: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut raw = Vec::with_capacity(HEADER_SIZE + payload.len());

    raw.push((PROTOCOL_VERSION << 4) | (flags & 0x0F));
    raw.push(msg_type);
    raw.push(seq);
    raw.extend_from_slice(&payload_len.to_le_bytes());
    raw.extend_from_slice(payload);

    cobs::encode(&raw)
}

/// Parses one frame's stuffed bytes, its delimiters removed. The block is
/// unstuffed before the version is read, so a corrupt block is
/// [`Error::CobsDecode`], never a wrong version.
pub fn parse_frame(cobs_data: &[u8]) -> Result<Frame, Error> {
    let decoded = cobs::decode(cobs_data)?;

    if decoded.len() < HEADER_SIZE {
        return Err(Error::TooShort);
    }

    let version_flags = decoded[0];
    let version = (version_flags >> 4) & 0x0F;

    if version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }

    let flags = version_flags & 0x0F;
    let msg_type = decoded[1];
    let seq = decoded[2];
    let length = u16::from_le_bytes([decoded[3], decoded[4]]) as usize;

    let actual_payload_len = decoded.len() - HEADER_SIZE;
    if length != actual_payload_len {
        return Err(Error::LengthMismatch {
            header: length,
            actual: actual_payload_len,
        });
    }

    let payload = decoded[HEADER_SIZE..HEADER_SIZE + length].to_vec();

    Ok(Frame {
        flags,
        msg_type,
        seq,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn build_parse_roundtrip_no_payload() {
        let wire = build_frame(MSG_PING, 0, 0, &[]);
        let cobs_data = &wire[1..wire.len() - 1];
        let frame = parse_frame(cobs_data).unwrap();
        assert_eq!(frame.msg_type, MSG_PING);
        assert_eq!(frame.flags, 0);
        assert_eq!(frame.seq, 0);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn build_parse_roundtrip_with_payload() {
        let payload = b"hello";
        let wire = build_frame(MSG_PING, FLAG_ACK_REQ, 42, payload);
        let cobs_data = &wire[1..wire.len() - 1];
        let frame = parse_frame(cobs_data).unwrap();
        assert_eq!(frame.msg_type, MSG_PING);
        assert_eq!(frame.flags, FLAG_ACK_REQ);
        assert_eq!(frame.seq, 42);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn wire_frame_has_zero_delimiters() {
        let wire = build_frame(MSG_PING, 0, 0, &[]);
        assert_eq!(wire[0], 0x00);
        assert_eq!(wire[wire.len() - 1], 0x00);
        for &b in &wire[1..wire.len() - 1] {
            assert_ne!(b, 0x00);
        }
    }

    #[test]
    fn parse_corrupted_data_fails() {
        let wire = build_frame(MSG_PING, 0, 0, &[0xAA]);
        let mut cobs_data = wire[1..wire.len() - 1].to_vec();
        cobs_data.insert(cobs_data.len() - 1, 0x42);
        assert!(parse_frame(&cobs_data).is_err());
    }

    #[test]
    fn parse_too_short_fails() {
        assert!(parse_frame(&[0x01]).is_err());
    }

    #[test]
    fn build_parse_max_seq() {
        let wire = build_frame(MSG_PONG, FLAG_RESPONSE, 255, &[0xAA, 0xBB]);
        let cobs_data = &wire[1..wire.len() - 1];
        let frame = parse_frame(cobs_data).unwrap();
        assert_eq!(frame.seq, 255);
        assert_eq!(frame.payload, &[0xAA, 0xBB]);
    }

    #[test]
    fn build_parse_payload_with_zeros() {
        let payload = [0x00, 0x01, 0x00, 0x02, 0x00];
        let wire = build_frame(MSG_PING, 0, 1, &payload);
        let cobs_data = &wire[1..wire.len() - 1];
        let frame = parse_frame(cobs_data).unwrap();
        assert_eq!(frame.payload, &payload);
    }

    #[test]
    fn build_parse_large_payload() {
        let payload: Vec<u8> = (0..502).map(|i| (i & 0xFF) as u8).collect();
        let wire = build_frame(MSG_PING, 0, 0, &payload);
        let cobs_data = &wire[1..wire.len() - 1];
        let frame = parse_frame(cobs_data).unwrap();
        assert_eq!(frame.payload, payload);
    }
}
