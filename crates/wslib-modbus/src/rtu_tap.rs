//! Modbus RTU messages off a serial line, each stamped with when it arrived.
//!
//! A message is stamped by the read that delivered its last byte: that read's
//! clock, less the wire time of the bytes after it in the read. Byte `i` of an
//! `n`-byte read at `at` arrived at `at − wire_time(n − 1 − i)`, so a message's
//! first byte arrived at `at − wire_time(raw.len() − 1)`. No stamp is earlier
//! than the clock of a read the tap has let go of, or than a stamp it has
//! already handed out, and none is earlier than the Unix epoch: a stamp can be
//! late, but it never goes backwards. The clock is the caller's.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use wslib_serial::LineSettings;

use crate::rtu_stream::{ModbusRtuMessage, ModbusRtuOptions, ModbusRtuStream};

/// A message off the line, stamped when its last byte arrived.
#[derive(Debug, Clone, PartialEq)]
pub struct TappedMessage {
    pub at: SystemTime,
    pub message: ModbusRtuMessage,
}

/// One read: the stream cursor after it, and its clock.
#[derive(Debug, Clone, Copy)]
struct ReadEnd {
    end: u64,
    at: SystemTime,
}

/// One serial line's RTU framer, and the reads that fed it.
#[derive(Debug)]
pub struct RtuTap {
    options: ModbusRtuOptions,
    line: LineSettings,
    stream: ModbusRtuStream,
    /// The reads that could still deliver a message's last byte, oldest first.
    reads: VecDeque<ReadEnd>,
    floor: SystemTime,
}

impl RtuTap {
    /// A tap on one line, framing it with `options`.
    pub fn new(options: &ModbusRtuOptions, line: LineSettings) -> Self {
        Self {
            options: options.clone(),
            line,
            stream: options.stream(),
            reads: VecDeque::new(),
            floor: UNIX_EPOCH,
        }
    }

    /// One read's bytes, and the wall clock when that read returned.
    pub fn push(&mut self, bytes: &[u8], read_at: SystemTime) -> Vec<TappedMessage> {
        let messages = self.stream.push_bytes(bytes);
        self.reads.push_back(ReadEnd {
            end: self.stream.bytes_fed(),
            at: read_at,
        });
        self.stamp_all(messages)
    }

    /// A gap: the line was lost or reopened. Forgets the half message and keeps the floor.
    pub fn reset(&mut self) {
        self.release_through(u64::MAX);
        self.stream = self.options.stream();
    }

    /// Reframes the line with `options` from here on, as a [`reset`](Self::reset)
    /// does: no stamp after it is earlier than one before it.
    pub fn set_options(&mut self, options: &ModbusRtuOptions) {
        self.options = options.clone();
        self.reset();
    }

    /// End of stream: what the buffer still yields, then the residue.
    pub fn finish(&mut self) -> (Vec<TappedMessage>, Vec<u8>) {
        let (messages, residue) = self.stream.finish();
        (self.stamp_all(messages), residue)
    }

    /// Bytes pushed since the tap was made or last reset, including a finished residue.
    pub fn bytes_fed(&self) -> u64 {
        self.stream.bytes_fed()
    }

    /// Whether bytes of a message neither completed nor given up on are
    /// buffered, so the next read continues it.
    pub fn mid_message(&self) -> bool {
        self.stream.buffer_start() < self.stream.bytes_fed()
    }

    fn stamp_all(&mut self, messages: Vec<ModbusRtuMessage>) -> Vec<TappedMessage> {
        let tapped = messages
            .into_iter()
            .map(|message| TappedMessage {
                at: self.stamp(message.end_offset),
                message,
            })
            .collect();
        self.release_through(self.stream.buffer_start());
        tapped
    }

    /// Messages come out in stream order, so the reads that ended before this
    /// one's last byte are done with.
    fn stamp(&mut self, end_offset: u64) -> SystemTime {
        self.release_through(end_offset.saturating_sub(1));
        let read = self.reads[0];
        let at = read
            .at
            .checked_sub(self.line.wire_time(read.end.saturating_sub(end_offset)))
            .unwrap_or(UNIX_EPOCH)
            .max(self.floor);
        self.floor = at;
        at
    }

    /// Lets go of every read that ended at or before `offset`, raising the floor
    /// to their clocks.
    fn release_through(&mut self, offset: u64) {
        while let Some(read) = self.reads.front().copied().filter(|r| r.end <= offset) {
            self.floor = self.floor.max(read.at);
            self.reads.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wslib_checksum::algorithms::crc16_modbus_checksum;
    use wslib_serial::Parity;

    use super::*;
    use crate::{CrcPolicy, MAX_RTU_LEN};

    fn with_crc(body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.extend(crc16_modbus_checksum(body).to_le_bytes());
        out
    }

    fn at(us: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_micros(us)
    }

    fn us(t: SystemTime) -> u64 {
        t.duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
    }

    /// 10 bits a byte, 1 041.67 µs each.
    const LINE_9600_8N1: LineSettings = LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };

    fn tap_on_9600_8n1() -> RtuTap {
        RtuTap::new(&ModbusRtuOptions::tapped(), LINE_9600_8N1)
    }

    fn keys(messages: &[TappedMessage]) -> Vec<(u8, u8, usize)> {
        messages
            .iter()
            .map(|m| {
                (
                    m.message.device_address,
                    m.message.function,
                    m.message.raw.len(),
                )
            })
            .collect()
    }

    fn stamps(messages: &[TappedMessage]) -> Vec<u64> {
        messages.iter().map(|m| us(m.at)).collect()
    }

    fn increasing(stamps: &[u64]) -> bool {
        stamps.windows(2).all(|w| w[0] < w[1])
    }

    fn one_register_read() -> Vec<u8> {
        with_crc(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
    }

    #[test]
    fn a_request_and_response_become_two_messages() {
        let mut tap = tap_on_9600_8n1();
        let request = with_crc(&[0x01, 0x03, 0x1E, 0x87, 0x00, 0x02]);
        let response = with_crc(&[0x01, 0x03, 0x04, 0x00, 0x00, 0x12, 0x34]);
        let line = [&request[..], &response[..]].concat();

        let got = tap.push(&line, at(1_700_000_000_000_000));
        assert_eq!(keys(&got), [(1, 3, 8), (1, 3, 9)]);
        assert_eq!(got[0].message.raw, request);
        assert_eq!(got[1].message.raw, response);
        assert!(got.iter().all(|m| m.message.crc_valid));
        assert_eq!(us(got[1].at), 1_700_000_000_000_000, "the read's time");
    }

    /// The Sungrow line's traffic: a vendor code the length table does not
    /// model, and a broadcast. Neither is declared anywhere; both are framed.
    #[test]
    fn an_undeclared_vendor_code_is_framed() {
        let mut tap = tap_on_9600_8n1();
        let battery = with_crc(&[0x01, 0x20, 0x01, 0xC8, 0x03, 0x11, 0x1A, 0x00, 0x02]);
        let dispatch = with_crc(&[
            0x00, 0x60, 0x00, 0x00, 0x00, 0x05, 0x0A, 0x00, 0x04, 0x01, 0xBB,
        ]);
        let line = [&battery[..], &dispatch[..]].concat();

        let mut got = Vec::new();
        for (i, b) in line.iter().enumerate() {
            got.extend(tap.push(std::slice::from_ref(b), at(i as u64)));
        }
        assert_eq!(keys(&got), [(1, 0x20, 11), (0, 0x60, 13)]);
        assert_eq!(got[0].message.raw, battery);
        assert_eq!(got[1].message.raw, dispatch);
        assert_eq!(us(got[0].at), 10, "stamped when its last byte arrived");
    }

    /// A long FC03 response whose interior happens to CRC-validate at a
    /// shorter length is still framed by the length table, whole.
    #[test]
    fn a_standard_code_keeps_its_length_rule_beside_the_search() {
        // A 125-register read response, 255 bytes, from a seed found by
        // searching: its 108-byte prefix carries a valid CRC of its own.
        let mut body = vec![0x01, 0x03, 250];
        let mut x = 138u32.wrapping_mul(2_654_435_761);
        for _ in 0..250 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            body.push(x as u8);
        }
        let response = with_crc(&body);
        assert!(
            (4..response.len()).any(|n| with_crc(&response[..n - 2]) == response[..n]),
            "the seed no longer yields a spurious inner CRC"
        );

        let got = tap_on_9600_8n1().push(&response, at(0));
        assert_eq!(keys(&got), [(1, 3, 255)]);
        assert_eq!(got[0].message.raw, response);
    }

    /// Joined across a gap, half a message leaves the framer lost, holding
    /// the next message until the search gives the false head up.
    #[test]
    fn a_reset_forgets_the_half_message() {
        let request = one_register_read();

        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(0)).is_empty());
        tap.reset();
        assert_eq!(
            keys(&tap.push(&request, at(1))),
            [(1, 3, 8)],
            "framed at once"
        );

        let mut joined = tap_on_9600_8n1();
        assert!(joined.push(&request[..5], at(0)).is_empty());
        assert!(joined.push(&request, at(1)).is_empty(), "lost, and holding");
    }

    /// A line opened mid-message: every message buffered behind the false
    /// head comes out of one read, and each carries the clock of the read
    /// that delivered its last byte.
    #[test]
    fn a_sync_burst_is_stamped_by_the_read_each_message_arrived_in() {
        let request = one_register_read();
        let line = [&request[..5], &request.repeat(40)[..]].concat();

        // One byte a read, a millisecond apart.
        let mut tap = tap_on_9600_8n1();
        let mut released = Vec::new();
        for (i, b) in line.iter().enumerate() {
            let batch = tap.push(std::slice::from_ref(b), at(i as u64 * 1000));
            if !batch.is_empty() {
                released.push(batch);
            }
        }

        assert!(
            released[0].len() > 1,
            "the sync released {} message(s)",
            released[0].len()
        );
        let got = stamps(&released.concat());
        assert_eq!(got.len(), 40, "every message framed");
        // Message k's last byte is at line offset 5 + 8k + 7, in the read of
        // that index.
        let expected: Vec<u64> = (0..40).map(|k| (12 + 8 * k) * 1000).collect();
        assert_eq!(got, expected);
    }

    /// The last message carries the read's clock; each earlier one sits
    /// 8 bytes, 8.3 ms at 9600 8N1, before the next.
    #[test]
    fn messages_in_one_read_are_spread_by_wire_time() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert_eq!(tap.push(&request, at(1_000_000)).len(), 1);

        let stamps = stamps(&tap.push(&request.repeat(10), at(1_100_000)));
        assert_eq!(stamps.len(), 10);
        assert_eq!(stamps[9], 1_100_000, "the last byte is the read's");
        assert_eq!(
            stamps[8],
            1_100_000 - 8_333,
            "one message of wire time earlier"
        );
        assert_eq!(stamps[0], 1_100_000 - 75_000, "72 bytes of wire time");
        assert!(increasing(&stamps));
    }

    /// Wire time cannot reach back past a read the tap has seen return,
    /// whether it completed a message, completed nothing, or was discarded
    /// by a reopen, nor past a stamp already handed out.
    #[test]
    fn a_stamp_never_reaches_behind_a_read_the_tap_has_seen() {
        let request = one_register_read();
        let ten = request.repeat(10);

        // Half a message at t, the rest and nine more half a millisecond
        // later: 75 ms of wire time, floored at t.
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(1_000_000)).is_empty());
        let got = stamps(&tap.push(&ten[5..], at(1_000_500)));
        assert_eq!(&got[..9], &[1_000_000; 9]);
        assert_eq!(got[9], 1_000_500);

        // A read that completed nothing, then a reopen.
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(2_000_000)).is_empty());
        tap.reset();
        assert_eq!(stamps(&tap.push(&ten, at(2_000_500)))[0], 2_000_000);

        // The clock steps back between reads.
        let mut tap = tap_on_9600_8n1();
        assert_eq!(us(tap.push(&request, at(2_000_000))[0].at), 2_000_000);
        assert_eq!(us(tap.push(&request, at(1_000_000))[0].at), 2_000_000);
        tap.reset();
        assert_eq!(us(tap.push(&request, at(1_500_000))[0].at), 2_000_000);
        assert_eq!(us(tap.push(&request, at(2_500_000))[0].at), 2_500_000);
    }

    #[test]
    fn a_clock_stepping_back_mid_message_holds_the_earlier_reads_clock() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(3_000_000)).is_empty());
        assert_eq!(stamps(&tap.push(&request[5..], at(1_000_000))), [3_000_000]);
    }

    /// Every read a reset lets go of raises the floor, not only the newest.
    #[test]
    fn a_reset_keeps_the_newest_clock_of_every_read_it_lets_go_of() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..3], at(3_000_000)).is_empty());
        assert!(tap.push(&request[3..5], at(1_000_000)).is_empty());
        tap.reset();
        assert_eq!(stamps(&tap.push(&request, at(2_000_000))), [3_000_000]);
    }

    #[test]
    fn a_pre_epoch_clock_stamps_the_epoch() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        let got = tap.push(&request, UNIX_EPOCH - Duration::from_secs(60));
        assert_eq!(got[0].at, UNIX_EPOCH);
        let got = tap.push(&request.repeat(2), at(1_000));
        assert_eq!(got[0].at, UNIX_EPOCH, "wire time reaching before the epoch");
        assert_eq!(us(got[1].at), 1_000);
    }

    /// Reads paced at the line rate, so byte `p` arrives at `p` byte times:
    /// however the line is chunked, a message's stamp less its own wire time
    /// is when its first byte arrived.
    #[test]
    fn the_first_byte_is_the_stamp_less_the_messages_wire_time() {
        // 12 bits a byte: exactly 1 250 µs, so no rounding hides a mismatch.
        let line = LineSettings {
            parity: Parity::Even,
            stop_bits: 2,
            ..LINE_9600_8N1
        };
        let byte_us = 1_250;
        let traffic = [
            one_register_read(),
            with_crc(&[0x00, 0x60, 0x00, 0x00, 0x00, 0x05, 0x0A]),
            with_crc(&[0x01, 0x03, 0x02, 0x12, 0x34]),
        ]
        .concat();
        let t0 = 1_700_000_000_000_000;

        for chunk in [1, 3, 64] {
            let mut tap = RtuTap::new(&ModbusRtuOptions::tapped(), line);
            let mut got = Vec::new();
            for (i, c) in traffic.chunks(chunk).enumerate() {
                let last_byte = (i * chunk + c.len() - 1) as u64;
                got.extend(tap.push(c, at(t0 + last_byte * byte_us)));
            }
            assert_eq!(got.len(), 3, "{chunk}-byte reads");
            for m in &got {
                let len = m.message.raw.len() as u64;
                let first_byte = m.message.end_offset - len;
                let derived = m.at - line.wire_time(len - 1);
                assert_eq!(us(derived), t0 + first_byte * byte_us, "{chunk}-byte reads");
            }
        }
    }

    #[test]
    fn the_ring_holds_only_reads_that_could_still_end_a_message() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        for (i, b) in request.iter().enumerate() {
            tap.push(std::slice::from_ref(b), at(i as u64));
        }
        assert!(tap.reads.is_empty(), "nothing buffered, nothing kept");

        tap.push(&request[..3], at(10));
        tap.push(&request[3..5], at(11));
        assert_eq!(tap.reads.len(), 2, "the reads under the half message");

        // A long line of noise and traffic, a byte a read.
        let mut x = 0x2545_F491u32;
        let mut most = 0;
        for i in 0..3_000u64 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let bytes = if i % 7 == 0 {
                request.clone()
            } else {
                vec![x as u8]
            };
            tap.push(&bytes, at(100 + i));
            most = most.max(tap.reads.len());
        }
        assert!(most <= 2 * MAX_RTU_LEN, "{most} reads kept");
    }

    #[test]
    fn finish_stamps_what_the_buffer_still_yields_by_its_own_read() {
        // CRC-invalid, and its third byte reads as a byte count, so a longer
        // candidate earns the wait until the end of the stream.
        let mut withheld = with_crc(&[0x01, 0x03, 0x04, 0x00, 0x00, 0x02]);
        withheld[7] ^= 0xFF;
        let options = ModbusRtuOptions {
            crc: CrcPolicy::Lenient,
            ..Default::default()
        };
        let mut tap = RtuTap::new(&options, LINE_9600_8N1);
        assert!(tap.push(&withheld[..4], at(1_000_000)).is_empty());
        assert!(tap.push(&withheld[4..], at(2_000_000)).is_empty());

        let (got, residue) = tap.finish();
        assert_eq!(stamps(&got), [2_000_000]);
        assert_eq!(got[0].message.raw, withheld);
        assert!(residue.is_empty());
        assert!(tap.reads.is_empty());

        let half = one_register_read()[..5].to_vec();
        assert!(tap.push(&half, at(3_000_000)).is_empty());
        assert_eq!(tap.finish(), (Vec::new(), half));
    }

    /// Rebuilt with `new`, the tap would forget the floor and stamp the second
    /// message at its own read's earlier clock.
    #[test]
    fn new_options_keep_the_floor_and_take_effect() {
        let request = one_register_read();
        let vendor = with_crc(&[0x01, 0x65, 0x02, 0x0B, 0xB8]);
        let mut tap = RtuTap::new(&ModbusRtuOptions::default(), LINE_9600_8N1);
        assert_eq!(stamps(&tap.push(&request, at(2_000_000))), [2_000_000]);
        assert!(tap.push(&vendor, at(2_100_000)).is_empty(), "undeclared");

        tap.set_options(&ModbusRtuOptions::tapped());
        assert_eq!(tap.bytes_fed(), 0);
        let got = tap.push(&vendor, at(1_000_000));
        assert_eq!(keys(&got), [(1, 0x65, 7)]);
        assert_eq!(stamps(&got), [2_100_000]);
    }

    #[test]
    fn new_options_forget_the_half_message() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(0)).is_empty());
        tap.set_options(&ModbusRtuOptions::tapped());
        assert!(!tap.mid_message());
        assert_eq!(keys(&tap.push(&request, at(1))), [(1, 3, 8)]);
    }

    #[test]
    fn bytes_fed_counts_every_byte_pushed() {
        let mut tap = tap_on_9600_8n1();
        let request = one_register_read();
        tap.push(&request, at(0));
        tap.push(&request[..3], at(1));
        assert_eq!(tap.bytes_fed(), 11);
    }

    #[test]
    fn bytes_fed_after_finish_is_the_residues_end() {
        let mut tap = tap_on_9600_8n1();
        tap.push(&one_register_read(), at(0));
        tap.push(&[0x01, 0x03, 0x00], at(1));
        let (_, residue) = tap.finish();
        assert_eq!(residue, [0x01, 0x03, 0x00]);
        assert_eq!(tap.bytes_fed(), 11);
    }

    #[test]
    fn a_reset_zeroes_bytes_fed() {
        let mut tap = tap_on_9600_8n1();
        tap.push(&one_register_read()[..5], at(0));
        tap.reset();
        assert_eq!(tap.bytes_fed(), 0);
    }

    #[test]
    fn a_half_received_message_is_mid_message_until_it_completes() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert!(!tap.mid_message());
        tap.push(&request[..5], at(0));
        assert!(tap.mid_message());
        assert_eq!(tap.push(&request[5..], at(1)).len(), 1);
        assert!(!tap.mid_message());
        tap.push(&request[..5], at(2));
        tap.reset();
        assert!(!tap.mid_message(), "a reset forgets the half message");
    }

    /// Bytes fed past the last message's end are not a message when the
    /// framer has already resynced over them.
    #[test]
    fn junk_resynced_over_is_not_mid_message() {
        let mut tap = tap_on_9600_8n1();
        let got = tap.push(&[&one_register_read()[..], &[0xFF; 6]].concat(), at(0));
        assert!(got[0].message.end_offset < tap.bytes_fed());
        assert!(!tap.mid_message());
    }

    /// A flush, then an outage that keeps the tap.
    #[test]
    fn bytes_fed_counts_up_from_zero_after_a_finish_and_reset() {
        let mut tap = tap_on_9600_8n1();
        tap.push(&one_register_read()[..5], at(0));
        tap.finish();
        tap.reset();

        let got = tap.push(&one_register_read(), at(1));
        assert_eq!(got[0].message.end_offset, 8);
        assert_eq!(tap.bytes_fed(), 8);
    }

    /// The real line, replayed. `RS485_RAW` names a capture of a real
    /// line: the bytes off the adapter exactly as `read` returned
    /// them, in order, with no timestamps, delimiters or headers.
    #[test]
    #[ignore = "needs a capture: RS485_RAW=<path to rs485.raw>"]
    fn the_sungrow_capture_frames_at_the_measured_coverage() {
        let path = std::env::var("RS485_RAW").expect("RS485_RAW names the capture");
        let bytes = std::fs::read(&path).expect("the capture");
        for chunk in [64usize, 4096] {
            let mut tap = tap_on_9600_8n1();
            let mut got = Vec::new();
            let mut burst = 0;
            for (i, c) in bytes.chunks(chunk).enumerate() {
                // Read as fast as the line can deliver a chunk.
                let read_at = UNIX_EPOCH + LINE_9600_8N1.wire_time(((i + 1) * chunk) as u64);
                let batch = tap.push(c, read_at);
                if burst == 0 {
                    burst = batch.len();
                }
                got.extend(batch);
            }
            assert!(
                increasing(&stamps(&got)),
                "{chunk}-byte reads: stamps not increasing"
            );
            eprintln!("{chunk}-byte reads: the sync released {burst} messages");
            let framed: usize = got.iter().map(|m| m.message.raw.len()).sum();
            let coverage = framed as f64 / bytes.len() as f64;
            eprintln!(
                "{chunk}-byte reads: {} messages, {framed} of {} bytes ({:.4}%)",
                got.len(),
                bytes.len(),
                coverage * 100.0
            );
            assert!(
                coverage >= 0.995,
                "{chunk}-byte reads: {framed} of {} bytes framed ({coverage:.4})",
                bytes.len()
            );
            for func in [0x20, 0x60, 0x65] {
                assert!(
                    got.iter().any(|m| m.message.function == func),
                    "{chunk}-byte reads: no {func:#04x} message"
                );
            }
            assert!(got.iter().all(|m| m.message.crc_valid));
        }
    }
}
