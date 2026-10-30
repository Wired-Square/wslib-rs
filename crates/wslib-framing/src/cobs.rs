//! COBS (Consistent Overhead Byte Stuffing), both directions, framed by `0x00`.
//!
//! Protocol reference: Cheshire and Baker, "Consistent Overhead Byte
//! Stuffing", IEEE/ACM Transactions on Networking, 1999.
//!
//! [`CobsDecoder`]'s buffer is unbounded until a delimiter arrives, unless
//! built with a cap.

use crate::Framed;

pub const DELIMITER: u8 = 0x00;

/// A block that is not valid COBS: empty, holding a `0x00`, or cut short.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed COBS block")]
pub struct CobsError;

/// Stuffs `data` into a block holding no `0x00`, without delimiters.
pub fn stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 254 + 1);
    stuff_into(&mut out, data);
    out
}

fn stuff_into(out: &mut Vec<u8>, data: &[u8]) {
    let mut code_at = out.len();
    out.push(0);
    let mut code: u8 = 1;
    for &byte in data {
        if byte != DELIMITER {
            out.push(byte);
            code += 1;
        }
        if byte == DELIMITER || code == 0xFF {
            out[code_at] = code;
            code_at = out.len();
            out.push(0);
            code = 1;
        }
    }
    out[code_at] = code;
}

/// Unstuffs one block, its delimiters already removed.
pub fn decode(block: &[u8]) -> Result<Vec<u8>, CobsError> {
    if block.is_empty() {
        return Err(CobsError);
    }
    let mut out = Vec::with_capacity(block.len());
    let mut i = 0;
    while i < block.len() {
        let code = usize::from(block[i]);
        i += 1;
        if code == 0 || i + code - 1 > block.len() {
            return Err(CobsError);
        }
        let run = &block[i..i + code - 1];
        if run.contains(&DELIMITER) {
            return Err(CobsError);
        }
        out.extend_from_slice(run);
        i += code - 1;
        if code < 0xFF && i < block.len() {
            out.push(DELIMITER);
        }
    }
    Ok(out)
}

/// `0x00`, `data` stuffed, `0x00`: the leading delimiter flushes line noise.
pub fn encode_into(out: &mut Vec<u8>, data: &[u8]) {
    out.push(DELIMITER);
    stuff_into(out, data);
    out.push(DELIMITER);
}

pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 254 + 3);
    encode_into(&mut out, data);
    out
}

/// Splits a COBS byte stream at each `0x00` and unstuffs the blocks between.
/// Empty blocks are skipped; a malformed one is dropped and counted.
#[derive(Debug, Clone, Default)]
pub struct CobsDecoder {
    buffer: Vec<u8>,
    fed: u64,
    max_frame_len: Option<usize>,
    abandoning: bool,
    abandoned: u64,
    malformed: u64,
}

impl CobsDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// A block that grows past `max` bytes is abandoned up to the next
    /// delimiter and counted in [`abandoned_frames`](Self::abandoned_frames).
    pub fn with_max_frame_len(max: usize) -> Self {
        Self {
            max_frame_len: Some(max),
            ..Self::default()
        }
    }

    /// Feed received bytes, returning every frame a delimiter released.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Framed> {
        let mut out = Vec::new();
        for &byte in bytes {
            self.fed += 1;
            if byte == DELIMITER {
                self.abandoning = false;
                out.extend(self.take());
            } else if !self.abandoning {
                self.buffer.push(byte);
                if self
                    .max_frame_len
                    .is_some_and(|max| self.buffer.len() > max)
                {
                    self.buffer.clear();
                    self.abandoning = true;
                    self.abandoned += 1;
                }
            }
        }
        out
    }

    /// The residue unstuffed, if any; also ends an abandoned block.
    pub fn flush(&mut self) -> Option<Framed> {
        self.abandoning = false;
        self.take()
    }

    pub fn bytes_fed(&self) -> u64 {
        self.fed
    }

    /// Blocks abandoned for outgrowing the cap, since the decoder was built.
    pub fn abandoned_frames(&self) -> u64 {
        self.abandoned
    }

    /// Blocks dropped as malformed, since the decoder was built.
    pub fn malformed_frames(&self) -> u64 {
        self.malformed
    }

    fn take(&mut self) -> Option<Framed> {
        if self.buffer.is_empty() {
            return None;
        }
        let block = std::mem::take(&mut self.buffer);
        match decode(&block) {
            Ok(bytes) => Some(Framed {
                bytes,
                end_offset: self.fed,
            }),
            Err(CobsError) => {
                self.malformed += 1;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(frames: &[Framed]) -> Vec<&[u8]> {
        frames.iter().map(|f| f.bytes.as_slice()).collect()
    }

    fn round_trips(data: &[u8]) {
        let block = stuff(data);
        assert!(!block.contains(&DELIMITER), "{data:?}");
        assert_eq!(decode(&block).unwrap(), data, "{data:?}");
    }

    #[test]
    fn the_papers_vectors() {
        assert_eq!(stuff(&[]), [0x01]);
        assert_eq!(stuff(&[0x00]), [0x01, 0x01]);
        assert_eq!(stuff(&[0x42]), [0x02, 0x42]);
        assert_eq!(stuff(&[0x00, 0x00]), [0x01, 0x01, 0x01]);
        assert_eq!(
            stuff(&[0x11, 0x22, 0x00, 0x33]),
            [0x03, 0x11, 0x22, 0x02, 0x33]
        );
    }

    #[test]
    fn a_run_of_254_non_zero_bytes_takes_one_full_code() {
        let data: Vec<u8> = (1..=254).collect();
        let block = stuff(&data);
        assert_eq!(block[0], 0xFF);
        assert_eq!(block.len(), 256);
        assert_eq!(block[255], 0x01);
    }

    #[test]
    fn blocks_round_trip() {
        round_trips(&[]);
        round_trips(&[0x01, 0x02, 0x03, 0x04]);
        round_trips(&[0x00, 0x00, 0x00]);
        round_trips(&[0x00, 0x11, 0x00, 0x22, 0x33, 0x00]);
        round_trips(&(1..=254).collect::<Vec<u8>>());
        round_trips(&(1..=255).collect::<Vec<u8>>());
        round_trips(&(0..1000).map(|i| (i % 7) as u8).collect::<Vec<u8>>());
    }

    #[test]
    fn malformed_blocks_are_refused() {
        assert_eq!(decode(&[]), Err(CobsError));
        assert_eq!(decode(&[0x00]), Err(CobsError));
        assert_eq!(decode(&[0x03, 0x11]), Err(CobsError));
        assert_eq!(decode(&[0x03, 0x11, 0x00]), Err(CobsError));
    }

    #[test]
    fn encode_wraps_the_block_in_delimiters() {
        assert_eq!(encode(&[0x42]), [0x00, 0x02, 0x42, 0x00]);
        let mut out = vec![0xAA];
        encode_into(&mut out, &[0x00]);
        assert_eq!(out, [0xAA, 0x00, 0x01, 0x01, 0x00]);
    }

    #[test]
    fn delimiters_separate_frames_and_empty_blocks_are_skipped() {
        let mut stream = encode(&[0x01, 0x00]);
        stream.extend(encode(&[0x02]));
        let frames = CobsDecoder::new().feed(&stream);
        assert_eq!(bytes(&frames), [[0x01, 0x00].as_slice(), &[0x02]]);
        let ends: Vec<u64> = frames.iter().map(|f| f.end_offset).collect();
        assert_eq!(ends, [5, 9]);
    }

    #[test]
    fn a_malformed_block_is_dropped_and_counted() {
        let mut d = CobsDecoder::new();
        let frames = d.feed(&[0x03, 0x11, 0x00, 0x02, 0x42, 0x00]);
        assert_eq!(bytes(&frames), [[0x42].as_slice()]);
        assert_eq!(d.malformed_frames(), 1);
    }

    #[test]
    fn flush_returns_the_residue_ending_at_bytes_fed() {
        let mut d = CobsDecoder::new();
        assert!(d.feed(&[0x02, 0x42]).is_empty());
        let residue = d.flush().expect("a residue");
        assert_eq!(residue.bytes, [0x42]);
        assert_eq!(residue.end_offset, d.bytes_fed());
        assert_eq!(d.flush(), None);
    }

    #[test]
    fn a_block_past_the_cap_is_abandoned_up_to_the_next_delimiter() {
        let mut d = CobsDecoder::with_max_frame_len(3);
        let frames = d.feed(&[0x05, 0x01, 0x02, 0x03, 0x04, 0x00, 0x02, 0x42, 0x00]);
        assert_eq!(bytes(&frames), [[0x42].as_slice()]);
        assert_eq!(d.abandoned_frames(), 1);
    }

    #[test]
    fn a_block_at_the_cap_is_released() {
        let mut d = CobsDecoder::with_max_frame_len(3);
        let frames = d.feed(&[0x03, 0x01, 0x02, 0x00]);
        assert_eq!(bytes(&frames), [[0x01, 0x02].as_slice()]);
        assert_eq!(d.abandoned_frames(), 0);
    }
}
