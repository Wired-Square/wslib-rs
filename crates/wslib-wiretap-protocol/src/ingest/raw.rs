//! A serial line's bytes as the reads returned them, unframed.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{ID_SEQ_MASK, RecordKind};

/// One raw serial record's worth of a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawChunk {
    /// When its last byte arrived.
    pub at: SystemTime,
    /// The read it came from, counted from the line's open.
    pub seq: u32,
    pub data: Vec<u8>,
}

/// One serial line's raw capture, cut into records.
#[derive(Debug, Clone)]
pub struct RawTap {
    baud: u32,
    bits_per_char: u32,
    seq: u32,
}

impl RawTap {
    /// A tap on one line at `baud`, each character `bits_per_char` bits with
    /// its start, parity and stop bits.
    pub fn new(baud: u32, bits_per_char: u32) -> Self {
        Self {
            baud,
            bits_per_char,
            seq: 0,
        }
    }

    /// One read's bytes in chunks a record can carry, each stamped when its
    /// last byte arrived: `read_at` less the wire time of the bytes after it,
    /// never before the epoch.
    pub fn push(&mut self, bytes: &[u8], read_at: SystemTime) -> Vec<RawChunk> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1) & ID_SEQ_MASK;
        let mut after = bytes.len();
        bytes
            .chunks(RecordKind::RawSerial.max_payload())
            .map(|chunk| {
                after -= chunk.len();
                let at = read_at
                    .checked_sub(self.wire_time(after as u64))
                    .map_or(UNIX_EPOCH, |at| at.max(UNIX_EPOCH));
                RawChunk {
                    at,
                    seq,
                    data: chunk.to_vec(),
                }
            })
            .collect()
    }

    /// The line was opened again: its reads count from zero.
    pub fn reset(&mut self) {
        self.seq = 0;
    }

    /// `bytes` at the line rate, in whole microseconds.
    fn wire_time(&self, bytes: u64) -> Duration {
        let micros = bytes
            .saturating_mul(u64::from(self.bits_per_char) * 1_000_000)
            .checked_div(u64::from(self.baud));
        Duration::from_micros(micros.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 9600 baud, 8N1: 10 bits a character.
    fn tap_9600_8n1() -> RawTap {
        RawTap::new(9600, 10)
    }

    const T0: u64 = 1_700_000_000_000_000;

    fn at(us: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_micros(us)
    }

    #[test]
    fn a_long_read_is_chunked_and_each_chunk_stamped_by_its_last_byte() {
        let bytes: Vec<u8> = (0..600).map(|i| i as u8).collect();
        let chunks = tap_9600_8n1().push(&bytes, at(T0));

        let lens: Vec<usize> = chunks.iter().map(|c| c.data.len()).collect();
        assert_eq!(lens, [256, 256, 88]);
        assert_eq!(
            chunks
                .iter()
                .flat_map(|c| c.data.clone())
                .collect::<Vec<_>>(),
            bytes
        );
        // 10 bits a byte at 9600 baud, truncated to whole microseconds.
        let stamps: Vec<SystemTime> = chunks.iter().map(|c| c.at).collect();
        assert_eq!(stamps, [at(T0 - 358_333), at(T0 - 91_666), at(T0)]);
        assert!(chunks.iter().all(|c| c.seq == 0));
    }

    #[test]
    fn the_sequence_counts_reads_from_the_open_and_wraps_at_2_31() {
        let mut tap = tap_9600_8n1();
        let seqs = |tap: &mut RawTap, len: usize| -> Vec<u32> {
            tap.push(&vec![0; len], at(T0))
                .iter()
                .map(|c| c.seq)
                .collect()
        };
        assert_eq!(seqs(&mut tap, 1), [0]);
        assert_eq!(seqs(&mut tap, 300), [1, 1], "chunks of one read share it");
        assert_eq!(seqs(&mut tap, 1), [2]);

        tap.reset();
        assert_eq!(seqs(&mut tap, 1), [0], "counted again from a reopen");

        tap.seq = (1 << 31) - 1;
        assert_eq!(seqs(&mut tap, 1), [(1 << 31) - 1]);
        assert_eq!(seqs(&mut tap, 1), [0]);
    }

    #[test]
    fn wire_time_reaching_before_the_epoch_stamps_the_epoch() {
        let chunks = tap_9600_8n1().push(&[0; 300], at(1_000));
        assert_eq!(chunks[0].at, UNIX_EPOCH);
    }
}
