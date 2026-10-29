//! A simulated bus, run through the candump codec: a session's worth of mixed traffic
//! survives a round trip, arriving in order and unchanged, whatever the reads
//! are cut into. Deterministic: the generator is seeded and dependency-free,
//! so a failure is reproducible from the seed printed in the assertion.

use wslib_can::{CanFrame, Direction, candump};

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

const SEEDS: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];
const FRAMES: usize = 200;

/// A log of a busy bus, written and read back. The text carries every flag and
/// keeps the length as written, so nothing is padded and nothing is lost, at
/// either end of the time range.
#[test]
fn a_candump_log_round_trips_every_flag_and_length() {
    for seed in SEEDS {
        let frames: Vec<CanFrame> = bus_traffic(seed, FRAMES)
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut frame = if s.rtr {
                    CanFrame::remote(0, s.arb_id, s.extended, (i % 9) as u8)
                } else {
                    CanFrame::data(0, s.arb_id, s.extended, s.fd, s.brs, s.data.clone())
                };
                frame.esi = s.fd && i % 5 == 0;
                frame
            })
            .collect();

        for start in [0, u64::MAX - FRAMES as u64] {
            let mut log = String::new();
            for (i, frame) in frames.iter().enumerate() {
                let direction = [None, Some(Direction::Rx), Some(Direction::Tx)][i % 3];
                candump::encode_line_into(&mut log, start + i as u64, "can0", frame, direction);
                log.push('\n');
            }
            let parsed: Vec<_> = candump::lines(log.lines())
                .map(|line| line.unwrap_or_else(|e| panic!("seed {seed}: {e}")))
                .collect();
            assert_eq!(parsed.len(), frames.len(), "seed {seed}: line count");
            for (i, (line, frame)) in parsed.iter().zip(&frames).enumerate() {
                assert_eq!(line.ts_us, start + i as u64, "seed {seed}");
                assert_eq!(&line.frame, frame, "seed {seed}");
            }
        }
    }
}
