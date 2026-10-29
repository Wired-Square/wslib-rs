//! A simulated bus, run through both ends of the GVRET codec: a session's worth of mixed traffic
//! survives a round trip, arriving in order and unchanged, whatever the reads
//! are cut into. Deterministic: the generator is seeded and dependency-free,
//! so a failure is reproducible from the seed printed in the assertion.

use wslib_can::{dlc_to_len, payload_dlc};
use wslib_can_gvret as gvret;

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

const SEEDS: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];
const FRAMES: usize = 200;

// ---------------------------------------------------------------------------
// GVRET
// ---------------------------------------------------------------------------

/// A device streaming a busy bus, read in arbitrary chunks. GVRET carries no
/// FD flag and no BRS, so what survives is the id, the bus, the length code and
/// the payload.
#[test]
fn a_gvret_device_stream_survives_any_read_boundary() {
    for seed in SEEDS {
        let traffic: Vec<Sample> = bus_traffic(seed, FRAMES)
            .into_iter()
            .filter(|s| !s.rtr) // GVRET has no remote frame
            .collect();

        let mut wire = Vec::new();
        for (i, s) in traffic.iter().enumerate() {
            gvret::encode_frame_into(
                &mut wire, i as u32, s.arb_id, s.extended, s.bus, &s.data, s.fd,
            );
            // Real devices interleave their replies with the traffic.
            match i % 37 {
                7 => wire.extend(gvret::encode_keepalive()),
                19 => wire.extend(gvret::encode_timebase(i as u32)),
                29 => wire.extend(gvret::encode_num_buses(2)),
                _ => {}
            }
        }

        let mut decoder = gvret::DeviceDecoder::new();
        let frames: Vec<_> = in_chunks(seed, &wire, |c| decoder.feed(c))
            .into_iter()
            .filter_map(|m| match m {
                gvret::DeviceMessage::Frame {
                    ts_us,
                    bus,
                    arb_id,
                    extended,
                    dlc,
                    data,
                } => Some((ts_us, bus, arb_id, extended, dlc, data)),
                _ => None,
            })
            .collect();

        assert_eq!(frames.len(), traffic.len(), "seed {seed}: frame count");
        for (i, (s, got)) in traffic.iter().zip(&frames).enumerate() {
            assert_eq!(
                *got,
                (
                    i as u32,
                    s.bus,
                    s.arb_id,
                    s.extended,
                    payload_dlc(s.data.len(), s.fd),
                    // Padded to the length code, because the code is the only
                    // framing this protocol has: a frame carrying fewer bytes
                    // than it claims eats the head of the next one.
                    s.padded(),
                ),
                "seed {seed}, frame {i}"
            );
        }
    }
}

/// The host end transmitting, decoded by the device end. Both live in this
/// crate now, so the pair can be asserted rather than assumed.
#[test]
fn a_gvret_transmit_stream_is_read_by_the_device_end() {
    for seed in SEEDS {
        // The transmit format carries a byte count, and the device end clamps
        // the payload it keeps to 8 — see below. Classic frames only, which is
        // what the format actually describes.
        let traffic: Vec<Sample> = bus_traffic(seed, FRAMES)
            .into_iter()
            .filter(|s| !s.fd && !s.rtr)
            .collect();

        let mut wire = gvret::SYNC.to_vec();
        for s in &traffic {
            gvret::encode_transmit_into(&mut wire, s.arb_id, s.extended, s.bus, &s.data);
        }

        let mut decoder = gvret::Decoder::new();
        let got = in_chunks(seed, &wire, |c| decoder.feed(c));

        assert_eq!(got.len(), traffic.len(), "seed {seed}");
        for (i, (s, cmd)) in traffic.iter().zip(&got).enumerate() {
            assert_eq!(
                *cmd,
                gvret::ClientCommand::Transmit {
                    bus: s.bus,
                    arb_id: s.arb_id,
                    extended: s.extended,
                    declared: s.data.len() as u8,
                    data: s.data.clone(),
                },
                "seed {seed}, frame {i}"
            );
        }
    }
}

/// The dialect note, asserted: a host may transmit a CAN FD payload, and the
/// device end keeps only the first eight bytes of it while consuming all of
/// them. Stated here because it is a real asymmetry between the two ends, not
/// because it is right.
#[test]
fn a_gvret_transmit_longer_than_a_classic_frame_is_truncated_not_desynchronised() {
    let mut wire = gvret::SYNC.to_vec();
    gvret::encode_transmit_into(&mut wire, 0x123, false, 0, &[0xAB; 12]);
    gvret::encode_transmit_into(&mut wire, 0x124, false, 0, &[0xCD; 2]);

    let got = gvret::Decoder::new().feed(&wire);
    assert_eq!(
        got,
        vec![
            gvret::ClientCommand::Transmit {
                bus: 0,
                arb_id: 0x123,
                extended: false,
                declared: 12,
                data: vec![0xAB; 8],
            },
            gvret::ClientCommand::Transmit {
                bus: 0,
                arb_id: 0x124,
                extended: false,
                declared: 2,
                data: vec![0xCD; 2],
            },
        ],
        "the payload is clamped, but the stream is not lost"
    );
}
