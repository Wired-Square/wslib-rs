//! A simulated bus, run through the SLCAN codec: a session's worth of mixed traffic
//! survives a round trip, arriving in order and unchanged, whatever the reads
//! are cut into. Deterministic: the generator is seeded and dependency-free,
//! so a failure is reproducible from the seed printed in the assertion.

use wslib_can::{dlc_to_len, payload_dlc};
use wslib_can_slcan as slcan;

/// xorshift64*. Not a good random number generator; a perfectly good source of
/// awkward frame sizes and read boundaries, which is all this needs.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// One frame as it was on the bus, before any protocol saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sample {
    arb_id: u32,
    extended: bool,
    fd: bool,
    brs: bool,
    rtr: bool,
    bus: u8,
    data: Vec<u8>,
}

impl Sample {
    /// The payload once the frame's length code has rounded it up. CAN FD has
    /// no 9, 10 or 11 byte length, so a transmitter pads and a receiver sees
    /// the padding — every codec here that writes a fixed-width payload region
    /// or a full line of hex agrees about that.
    fn padded(&self) -> Vec<u8> {
        let mut d = self.data.clone();
        d.resize(dlc_to_len(payload_dlc(d.len(), self.fd), self.fd), 0);
        d
    }
}

/// A plausible-looking mix: mostly short classic frames, some extended, some
/// CAN FD across every length code, and the occasional remote request.
fn bus_traffic(seed: u64, count: usize) -> Vec<Sample> {
    let mut rng = Rng::new(seed);
    (0..count)
        .map(|_| {
            let extended = rng.below(4) == 0;
            let fd = rng.below(3) == 0;
            let rtr = !fd && rng.below(16) == 0;
            Sample {
                arb_id: if extended {
                    rng.next() as u32 & 0x1FFF_FFFF
                } else {
                    rng.next() as u32 & 0x7FF
                },
                extended,
                fd,
                brs: fd && rng.below(2) == 0,
                rtr,
                bus: rng.below(4) as u8,
                data: if rtr {
                    Vec::new()
                } else {
                    let n = if fd { rng.below(65) } else { rng.below(9) };
                    rng.bytes(n)
                },
            }
        })
        .collect()
}

/// bytes — and collect everything that came back.
///
/// The point of an incremental decoder is that where the reads fall makes no
/// difference, and the way to be sure is to put a boundary everywhere.
fn in_chunks<T>(seed: u64, bytes: &[u8], mut decode: impl FnMut(&[u8]) -> Vec<T>) -> Vec<T> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let take = (1 + rng.below(40)).min(bytes.len() - at);
        out.extend(decode(&bytes[at..at + take]));
        at += take;
    }
    out
}

/// The same sample as an SLCAN line's frame.
fn as_slcan(s: &Sample) -> slcan::Frame {
    if s.rtr {
        slcan::Frame::remote(s.arb_id, s.extended, s.data.len() as u8)
    } else {
        slcan::Frame::data(s.arb_id, s.extended, s.fd, s.brs, s.data.clone())
    }
}

const SEEDS: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];
const FRAMES: usize = 200;

/// A device streaming lines, read in arbitrary chunks, with its replies and its
/// error bells mixed in.
#[test]
fn an_slcan_line_stream_survives_any_read_boundary() {
    for seed in SEEDS {
        let traffic = bus_traffic(seed, FRAMES);

        let mut wire = Vec::new();
        for (i, s) in traffic.iter().enumerate() {
            slcan::encode_frame_into(&mut wire, &as_slcan(s));
            // A bare `\r` is a command acknowledgement; a bell is a command
            // error. Neither is a frame, and neither may disturb one.
            match i % 23 {
                5 => wire.push(b'\r'),
                11 => wire.push(slcan::BELL),
                17 => wire.extend(b"V1013\r"),
                _ => {}
            }
        }

        let mut decoder = slcan::LineDecoder::new();
        let frames: Vec<_> = in_chunks(seed, &wire, |c| decoder.feed(c))
            .into_iter()
            .filter_map(|l| match l {
                slcan::Line::Frame(f) => Some(f),
                slcan::Line::Reply(_) => None,
            })
            .collect();

        assert_eq!(frames.len(), traffic.len(), "seed {seed}: frame count");
        for (i, (s, got)) in traffic.iter().zip(&frames).enumerate() {
            assert_eq!(
                (got.arb_id, got.extended, got.fd, got.brs, got.rtr),
                (s.arb_id, s.extended, s.fd, s.brs, s.rtr),
                "seed {seed}, frame {i}"
            );
            // A line must carry every byte its code names, so an inexact FD
            // payload arrives padded.
            let want = if s.rtr { Vec::new() } else { s.padded() };
            assert_eq!(got.data, want, "seed {seed}, frame {i}");
        }
    }
}
