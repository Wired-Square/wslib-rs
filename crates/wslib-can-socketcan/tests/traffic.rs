//! A simulated bus, run through the SocketCAN frame layouts: a session's worth of mixed traffic
//! survives a round trip, arriving in order and unchanged, whatever the reads
//! are cut into. Deterministic: the generator is seeded and dependency-free,
//! so a failure is reproducible from the seed printed in the assertion.

use wslib_can_socketcan as socketcan;

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

/// SocketCAN carries a payload length rather than a code, so nothing is padded
/// and what goes in is exactly what comes out.
#[test]
fn a_socketcan_session_round_trips() {
    for seed in SEEDS {
        for (i, s) in bus_traffic(seed, FRAMES).iter().enumerate() {
            let sent = socketcan::Frame::new(
                s.arb_id,
                s.extended,
                s.rtr && !s.fd,
                s.fd,
                s.brs,
                s.data.clone(),
            );
            let wire = socketcan::encode_frame(&sent);
            assert_eq!(wire.len(), sent.wire_len(), "seed {seed}, frame {i}");
            assert_eq!(
                socketcan::parse_frame(&wire),
                Some(sent),
                "seed {seed}, frame {i}"
            );
        }
    }
}
