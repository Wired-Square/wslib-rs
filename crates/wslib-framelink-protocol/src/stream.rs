//! An interface's frames streamed to and from the host.
//!
//! STREAM_START (0x12): `iface_index(u8) config_len(u8) [config...]`
//! STREAM_STOP  (0x13): `iface_index(u8)`
//!
//! FRAME_RX (0x10): a batch of one or more received frames.
//!   `count(u16 LE)` followed by `count` entries, each:
//!   `timestamp_us(u64 LE) iface_index(u8) meta_len(u8) [metadata]
//!    data_len(u16 LE) [data]`
//!
//! FRAME_TX (0x11) carries a single such entry without the count prefix.
//!
//! CAN metadata (meta_len = 6):
//!   `can_id(u32 LE) dlc(u8) flags(u8)`
//!
//! RS-485 metadata (meta_len = 1):
//!   `framing_mode(u8)`

use serde::Serialize;

use crate::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct CanFilter {
    pub can_id: u32,
    pub can_mask: u32,
    /// [`CAN_FLAG_EXTENDED`](crate::frame_def::CAN_FLAG_EXTENDED): the
    /// filter matches extended ids.
    pub flags: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Rs485FramingMode {
    IdleLine = 0,
    FixedChunk = 1,
}

impl Rs485FramingMode {
    pub fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Rs485FramingMode::IdleLine),
            1 => Ok(Rs485FramingMode::FixedChunk),
            _ => Err(Error::InvalidPayload("unknown RS-485 framing mode")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StreamConfig {
    Can { filters: Vec<CanFilter> },
    Rs485 { mode: Rs485FramingMode, param: u16 },
}

/// A frame's metadata, decoded by its length.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[non_exhaustive]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum FrameMetadata {
    /// `flags` are the `frame_def::CAN_FLAG_*` bits.
    Can {
        can_id: u32,
        dlc: u8,
        flags: u8,
    },
    Rs485 {
        framing_mode: u8,
    },
    Unknown {
        meta_len: u8,
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct StreamFrame {
    pub timestamp_us: u64,
    pub iface_index: u8,
    pub metadata: FrameMetadata,
    pub data: Vec<u8>,
}

/// With no `config` the device uses its defaults.
pub fn build_stream_start(iface_index: u8, config: Option<StreamConfig>) -> Vec<u8> {
    match config {
        None => {
            vec![iface_index, 0]
        }
        Some(StreamConfig::Can { filters }) => {
            let config_len = 1 + filters.len() * 9;
            let mut buf = Vec::with_capacity(2 + config_len);
            buf.push(iface_index);
            buf.push(config_len as u8);
            buf.push(filters.len() as u8);
            for f in &filters {
                buf.extend_from_slice(&f.can_id.to_le_bytes());
                buf.extend_from_slice(&f.can_mask.to_le_bytes());
                buf.push(f.flags);
            }
            buf
        }
        Some(StreamConfig::Rs485 { mode, param }) => {
            let config_len: u8 = 3;
            let mut buf = Vec::with_capacity(2 + config_len as usize);
            buf.push(iface_index);
            buf.push(config_len);
            buf.push(mode as u8);
            buf.extend_from_slice(&param.to_le_bytes());
            buf
        }
    }
}

pub fn build_stream_stop(iface_index: u8) -> Vec<u8> {
    vec![iface_index]
}

/// Appends one FRAME_RX entry.
pub fn build_frame_rx_entry(
    buf: &mut Vec<u8>,
    timestamp_us: u64,
    iface_index: u8,
    metadata: &FrameMetadata,
    data: &[u8],
) {
    buf.extend_from_slice(&timestamp_us.to_le_bytes());
    encode_frame_entry(buf, iface_index, metadata, data);
}

pub fn build_frame_rx_batch(entries: &[StreamFrame]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for e in entries {
        build_frame_rx_entry(
            &mut buf,
            e.timestamp_us,
            e.iface_index,
            &e.metadata,
            &e.data,
        );
    }
    buf
}

/// One FRAME_RX entry without a count, stamped 0: the device uses its own
/// clock.
pub fn build_frame_tx(iface_index: u8, metadata: &FrameMetadata, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    build_frame_rx_entry(&mut buf, 0, iface_index, metadata, data);
    buf
}

pub struct BatchFrameEntry {
    pub iface_index: u8,
    pub metadata: FrameMetadata,
    pub data: Vec<u8>,
}

/// FRAME_TX_BATCH: a count, then entries without timestamps.
pub fn build_frame_tx_batch(frames: &[BatchFrameEntry]) -> Vec<u8> {
    let estimated: usize = 2 + frames
        .iter()
        .map(|e| 4 + metadata_len(&e.metadata) + e.data.len())
        .sum::<usize>();
    let mut buf = Vec::with_capacity(estimated);
    buf.extend_from_slice(&(frames.len() as u16).to_le_bytes());

    for entry in frames {
        encode_frame_entry(&mut buf, entry.iface_index, &entry.metadata, &entry.data);
    }

    buf
}

fn metadata_len(metadata: &FrameMetadata) -> usize {
    match metadata {
        FrameMetadata::Can { .. } => 6,
        FrameMetadata::Rs485 { .. } => 1,
        FrameMetadata::Unknown { .. } => 0,
    }
}

fn encode_frame_entry(buf: &mut Vec<u8>, iface_index: u8, metadata: &FrameMetadata, data: &[u8]) {
    buf.push(iface_index);
    match metadata {
        FrameMetadata::Can { can_id, dlc, flags } => {
            buf.push(6);
            buf.extend_from_slice(&can_id.to_le_bytes());
            buf.push(*dlc);
            buf.push(*flags);
        }
        FrameMetadata::Rs485 { framing_mode } => {
            buf.push(1);
            buf.push(*framing_mode);
        }
        FrameMetadata::Unknown { .. } => {
            buf.push(0);
        }
    }
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
}

/// One FRAME_RX entry at `offset`, and the offset after it.
pub fn parse_frame_rx_entry(payload: &[u8], offset: usize) -> Result<(StreamFrame, usize), Error> {
    let header_end = offset
        .checked_add(10)
        .ok_or(Error::InvalidPayload("FRAME_RX entry offset overflow"))?;
    if payload.len() < header_end {
        return Err(Error::InvalidPayload("truncated: FRAME_RX entry header"));
    }

    let timestamp_us = u64::from_le_bytes(
        payload[offset..offset + 8]
            .try_into()
            .expect("8-byte slice"),
    );
    let iface_index = payload[offset + 8];
    let meta_len = payload[offset + 9] as usize;

    let meta_start = offset + 10;
    let meta_end = meta_start + meta_len;

    if payload.len() < meta_end + 2 {
        return Err(Error::InvalidPayload("truncated: metadata or data_len"));
    }

    let metadata = parse_metadata(meta_len, &payload[meta_start..meta_end])?;

    let data_len = u16::from_le_bytes([payload[meta_end], payload[meta_end + 1]]) as usize;
    let data_start = meta_end + 2;
    let data_end = data_start + data_len;

    if payload.len() < data_end {
        return Err(Error::InvalidPayload("truncated: frame data"));
    }

    let data = payload[data_start..data_end].to_vec();

    Ok((
        StreamFrame {
            timestamp_us,
            iface_index,
            metadata,
            data,
        },
        data_end,
    ))
}

pub fn parse_frame_rx(payload: &[u8]) -> Result<Vec<StreamFrame>, Error> {
    if payload.len() < 2 {
        return Err(Error::InvalidPayload("truncated: FRAME_RX count"));
    }
    let count = u16::from_le_bytes([payload[0], payload[1]]) as usize;

    let mut frames = Vec::with_capacity(count);
    let mut offset = 2;
    for _ in 0..count {
        let (frame, next) = parse_frame_rx_entry(payload, offset)?;
        frames.push(frame);
        offset = next;
    }
    Ok(frames)
}

pub fn parse_frame_tx(payload: &[u8]) -> Result<StreamFrame, Error> {
    Ok(parse_frame_rx_entry(payload, 0)?.0)
}

fn parse_metadata(meta_len: usize, meta: &[u8]) -> Result<FrameMetadata, Error> {
    match meta_len {
        6 => {
            let can_id = u32::from_le_bytes([meta[0], meta[1], meta[2], meta[3]]);
            let dlc = meta[4];
            let flags = meta[5];
            Ok(FrameMetadata::Can { can_id, dlc, flags })
        }
        1 => Ok(FrameMetadata::Rs485 {
            framing_mode: meta[0],
        }),
        _ => Ok(FrameMetadata::Unknown {
            meta_len: meta_len as u8,
            raw: meta.to_vec(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_def::CAN_FLAG_EXTENDED;

    // -- build_stream_start tests --

    #[test]
    fn stream_start_default_config() {
        let payload = build_stream_start(2, None);
        assert_eq!(payload, vec![2, 0]);
    }

    #[test]
    fn stream_start_can_promiscuous() {
        let payload = build_stream_start(0, Some(StreamConfig::Can { filters: vec![] }));
        // iface_index=0, config_len=1 (just num_filters byte), num_filters=0
        assert_eq!(payload, vec![0, 1, 0]);
    }

    #[test]
    fn stream_start_can_with_filters() {
        let filters = vec![
            CanFilter {
                can_id: 0x100,
                can_mask: 0x7FF,
                flags: 0,
            },
            CanFilter {
                can_id: 0x18ABCDEF,
                can_mask: 0x1FFFFFFF,
                flags: CAN_FLAG_EXTENDED,
            },
        ];
        let payload = build_stream_start(1, Some(StreamConfig::Can { filters }));

        // iface_index=1
        assert_eq!(payload[0], 1);
        // config_len = 1 + 2*9 = 19
        assert_eq!(payload[1], 19);
        // num_filters = 2
        assert_eq!(payload[2], 2);

        // Filter 0: can_id=0x100
        let id0 = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
        assert_eq!(id0, 0x100);
        let mask0 = u32::from_le_bytes([payload[7], payload[8], payload[9], payload[10]]);
        assert_eq!(mask0, 0x7FF);
        assert_eq!(payload[11], 0); // flags

        // Filter 1: can_id=0x18ABCDEF, extended
        let id1 = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        assert_eq!(id1, 0x18ABCDEF);
        let mask1 = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        assert_eq!(mask1, 0x1FFFFFFF);
        assert_eq!(payload[20], CAN_FLAG_EXTENDED);
    }

    #[test]
    fn stream_start_rs485() {
        let payload = build_stream_start(
            3,
            Some(StreamConfig::Rs485 {
                mode: Rs485FramingMode::IdleLine,
                param: 5000,
            }),
        );
        assert_eq!(payload[0], 3); // iface_index
        assert_eq!(payload[1], 3); // config_len
        assert_eq!(payload[2], 0); // framing_mode = idle-line
        let param = u16::from_le_bytes([payload[3], payload[4]]);
        assert_eq!(param, 5000);
    }

    #[test]
    fn stream_start_rs485_fixed_chunk() {
        let payload = build_stream_start(
            0,
            Some(StreamConfig::Rs485 {
                mode: Rs485FramingMode::FixedChunk,
                param: 256,
            }),
        );
        assert_eq!(payload[2], 1); // framing_mode = fixed-chunk
        let param = u16::from_le_bytes([payload[3], payload[4]]);
        assert_eq!(param, 256);
    }

    // -- build_stream_stop tests --

    #[test]
    fn stream_stop_payload() {
        let payload = build_stream_stop(5);
        assert_eq!(payload, vec![5]);
    }

    // -- parse_frame_rx_entry tests (single-entry wire shape) --

    /// Helper to build a single FRAME_RX entry for CAN (no batch count prefix).
    fn build_can_entry(
        timestamp_us: u64,
        iface_index: u8,
        can_id: u32,
        dlc: u8,
        flags: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        build_frame_rx_entry(
            &mut buf,
            timestamp_us,
            iface_index,
            &FrameMetadata::Can { can_id, dlc, flags },
            data,
        );
        buf
    }

    /// Helper to build a single FRAME_RX entry for RS-485 (no batch count prefix).
    fn build_rs485_entry(
        timestamp_us: u64,
        iface_index: u8,
        framing_mode: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        build_frame_rx_entry(
            &mut buf,
            timestamp_us,
            iface_index,
            &FrameMetadata::Rs485 { framing_mode },
            data,
        );
        buf
    }

    #[test]
    fn parse_can_entry() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let payload = build_can_entry(1_000_000, 0, 0x100, 8, 0, &data);

        let (frame, consumed) = parse_frame_rx_entry(&payload, 0).unwrap();
        assert_eq!(consumed, payload.len());
        assert_eq!(frame.timestamp_us, 1_000_000);
        assert_eq!(frame.iface_index, 0);
        assert_eq!(
            frame.metadata,
            FrameMetadata::Can {
                can_id: 0x100,
                dlc: 8,
                flags: 0
            }
        );
        assert_eq!(frame.data, data);
    }

    #[test]
    fn parse_can_entry_extended_id() {
        let data = [0xAA, 0xBB];
        let payload = build_can_entry(500, 1, 0x18FF00FE, 2, CAN_FLAG_EXTENDED, &data);

        let (frame, _) = parse_frame_rx_entry(&payload, 0).unwrap();
        assert_eq!(frame.iface_index, 1);
        assert_eq!(
            frame.metadata,
            FrameMetadata::Can {
                can_id: 0x18FF00FE,
                dlc: 2,
                flags: CAN_FLAG_EXTENDED
            }
        );
        assert_eq!(frame.data, data);
    }

    #[test]
    fn parse_rs485_entry() {
        let data = b"HELLO";
        let payload = build_rs485_entry(2_500_000, 3, 0, data);

        let (frame, _) = parse_frame_rx_entry(&payload, 0).unwrap();
        assert_eq!(frame.timestamp_us, 2_500_000);
        assert_eq!(frame.iface_index, 3);
        assert_eq!(frame.metadata, FrameMetadata::Rs485 { framing_mode: 0 });
        assert_eq!(frame.data, b"HELLO");
    }

    #[test]
    fn parse_unknown_metadata() {
        // Build an entry with meta_len=3, unknown type
        let mut payload = Vec::new();
        payload.extend_from_slice(&42u64.to_le_bytes()); // timestamp
        payload.push(7); // iface_index
        payload.push(3); // meta_len
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // unknown metadata
        payload.extend_from_slice(&2u16.to_le_bytes()); // data_len
        payload.extend_from_slice(&[0x01, 0x02]); // data

        let (frame, _) = parse_frame_rx_entry(&payload, 0).unwrap();
        assert_eq!(frame.iface_index, 7);
        assert_eq!(
            frame.metadata,
            FrameMetadata::Unknown {
                meta_len: 3,
                raw: vec![0xAA, 0xBB, 0xCC]
            }
        );
        assert_eq!(frame.data, vec![0x01, 0x02]);
    }

    #[test]
    fn parse_zero_data_length() {
        let payload = build_can_entry(0, 0, 0x200, 0, 0, &[]);
        let (frame, _) = parse_frame_rx_entry(&payload, 0).unwrap();
        assert_eq!(frame.data.len(), 0);
        assert_eq!(
            frame.metadata,
            FrameMetadata::Can {
                can_id: 0x200,
                dlc: 0,
                flags: 0
            }
        );
    }

    #[test]
    fn parse_zero_metadata() {
        // meta_len = 0 should produce Unknown with empty raw
        let mut payload = Vec::new();
        payload.extend_from_slice(&100u64.to_le_bytes());
        payload.push(0); // iface_index
        payload.push(0); // meta_len = 0
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        let (frame, _) = parse_frame_rx_entry(&payload, 0).unwrap();
        assert_eq!(
            frame.metadata,
            FrameMetadata::Unknown {
                meta_len: 0,
                raw: vec![]
            }
        );
        assert_eq!(frame.data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn parse_max_timestamp() {
        let payload = build_can_entry(u64::MAX, 0, 0, 0, 0, &[]);
        let (frame, _) = parse_frame_rx_entry(&payload, 0).unwrap();
        assert_eq!(frame.timestamp_us, u64::MAX);
    }

    // -- entry error cases --

    #[test]
    fn parse_entry_empty_fails() {
        assert!(parse_frame_rx_entry(&[], 0).is_err());
    }

    #[test]
    fn parse_entry_truncated_header_fails() {
        // Only 8 bytes (timestamp) — missing iface_index, meta_len, data_len
        let payload = 0u64.to_le_bytes();
        assert!(parse_frame_rx_entry(&payload, 0).is_err());
    }

    #[test]
    fn parse_entry_truncated_metadata_fails() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.push(0); // iface_index
        payload.push(6); // meta_len = 6 (CAN), but only 2 bytes follow
        payload.extend_from_slice(&[0x00, 0x00]);

        assert!(parse_frame_rx_entry(&payload, 0).is_err());
    }

    #[test]
    fn parse_entry_truncated_data_fails() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.push(0); // iface_index
        payload.push(1); // meta_len = 1 (RS-485)
        payload.push(0); // framing_mode
        payload.extend_from_slice(&10u16.to_le_bytes()); // data_len = 10
        payload.extend_from_slice(&[0x01, 0x02]); // only 2 bytes of data

        assert!(parse_frame_rx_entry(&payload, 0).is_err());
    }

    // -- parse_frame_rx (batch: count + entries) tests --

    #[test]
    fn parse_frame_rx_empty_batch() {
        // count = 0 -> empty Vec
        let payload = 0u16.to_le_bytes();
        let frames = parse_frame_rx(&payload).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn parse_frame_rx_single_batch() {
        let entries = vec![StreamFrame {
            timestamp_us: 1_000_000,
            iface_index: 0,
            metadata: FrameMetadata::Can {
                can_id: 0x123,
                dlc: 8,
                flags: 0,
            },
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }];
        let payload = build_frame_rx_batch(&entries);
        let parsed = parse_frame_rx(&payload).unwrap();
        assert_eq!(parsed, entries);
    }

    #[test]
    fn parse_frame_rx_multi_batch_mixed_ifaces() {
        let entries = vec![
            StreamFrame {
                timestamp_us: 100,
                iface_index: 0,
                metadata: FrameMetadata::Can {
                    can_id: 0x100,
                    dlc: 2,
                    flags: 0,
                },
                data: vec![0xAA, 0xBB],
            },
            StreamFrame {
                timestamp_us: 200,
                iface_index: 2,
                metadata: FrameMetadata::Rs485 { framing_mode: 1 },
                data: b"hello".to_vec(),
            },
            StreamFrame {
                timestamp_us: 300,
                iface_index: 1,
                metadata: FrameMetadata::Can {
                    can_id: 0x18FF00FE,
                    dlc: 0,
                    flags: CAN_FLAG_EXTENDED,
                },
                data: vec![],
            },
        ];
        let payload = build_frame_rx_batch(&entries);
        let parsed = parse_frame_rx(&payload).unwrap();
        assert_eq!(parsed, entries);
    }

    #[test]
    fn parse_frame_rx_truncated_count_fails() {
        // Only 1 byte — cannot read the u16 count
        assert!(parse_frame_rx(&[0x01]).is_err());
    }

    #[test]
    fn parse_frame_rx_count_exceeds_entries_fails() {
        // count says 2, but only one entry follows
        let one = build_can_entry(1, 0, 0x100, 1, 0, &[0xFF]);
        let mut payload = 2u16.to_le_bytes().to_vec();
        payload.extend_from_slice(&one);
        assert!(parse_frame_rx(&payload).is_err());
    }

    #[test]
    fn parse_frame_rx_trailing_garbage_after_count_entries() {
        // count = 1, one valid entry, then stray bytes -> the one entry parses fine
        let one = build_can_entry(7, 0, 0x200, 1, 0, &[0x42]);
        let mut payload = 1u16.to_le_bytes().to_vec();
        payload.extend_from_slice(&one);
        payload.extend_from_slice(&[0xDE, 0xAD]); // trailing bytes, ignored
        let parsed = parse_frame_rx(&payload).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].data, vec![0x42]);
    }

    // -- parse_frame_tx (single FRAME_TX entry) --

    #[test]
    fn parse_frame_tx_single() {
        let meta = FrameMetadata::Can {
            can_id: 0x7FF,
            dlc: 3,
            flags: CAN_FLAG_EXTENDED,
        };
        let data = [0xAA, 0xBB, 0xCC];
        let payload = build_frame_tx(1, &meta, &data);
        let parsed = parse_frame_tx(&payload).unwrap();
        assert_eq!(parsed.iface_index, 1);
        assert_eq!(parsed.metadata, meta);
        assert_eq!(parsed.data, data);
    }

    // -- build_frame_tx tests --

    #[test]
    fn build_frame_tx_can() {
        let meta = FrameMetadata::Can {
            can_id: 0x1A3,
            dlc: 8,
            flags: 0,
        };
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let payload = build_frame_tx(0, &meta, &data);

        assert_eq!(&payload[0..8], &0u64.to_le_bytes());
        assert_eq!(payload[8], 0);
        assert_eq!(payload[9], 6);
        let can_id = u32::from_le_bytes([payload[10], payload[11], payload[12], payload[13]]);
        assert_eq!(can_id, 0x1A3);
        assert_eq!(payload[14], 8);
        assert_eq!(payload[15], 0);
        let data_len = u16::from_le_bytes([payload[16], payload[17]]);
        assert_eq!(data_len, 8);
        assert_eq!(&payload[18..26], &data);
    }

    #[test]
    fn build_frame_tx_rs485() {
        let meta = FrameMetadata::Rs485 { framing_mode: 0 };
        let data = b"HELLO";
        let payload = build_frame_tx(2, &meta, data);

        assert_eq!(payload[8], 2);
        assert_eq!(payload[9], 1);
        assert_eq!(payload[10], 0);
        let data_len = u16::from_le_bytes([payload[11], payload[12]]);
        assert_eq!(data_len, 5);
        assert_eq!(&payload[13..18], b"HELLO");
    }

    #[test]
    fn build_frame_tx_roundtrip() {
        let meta = FrameMetadata::Can {
            can_id: 0x7FF,
            dlc: 3,
            flags: CAN_FLAG_EXTENDED,
        };
        let data = [0xAA, 0xBB, 0xCC];
        let payload = build_frame_tx(1, &meta, &data);
        let parsed = parse_frame_tx(&payload).unwrap();
        assert_eq!(parsed.iface_index, 1);
        assert_eq!(parsed.metadata, meta);
        assert_eq!(parsed.data, data);
    }

    // -- Rs485FramingMode tests --

    #[test]
    fn framing_mode_from_u8() {
        assert_eq!(
            Rs485FramingMode::from_u8(0).unwrap(),
            Rs485FramingMode::IdleLine
        );
        assert_eq!(
            Rs485FramingMode::from_u8(1).unwrap(),
            Rs485FramingMode::FixedChunk
        );
        assert!(Rs485FramingMode::from_u8(2).is_err());
        assert!(Rs485FramingMode::from_u8(255).is_err());
    }
}
