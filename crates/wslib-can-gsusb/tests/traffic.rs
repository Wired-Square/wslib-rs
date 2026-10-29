//! A simulated bus, run through the gs_usb host frame: a session's worth of mixed traffic
//! survives a round trip, in order and unchanged, one frame at a time or many
//! to a bulk transfer. Deterministic: the generator is seeded and
//! dependency-free, so a failure is reproducible from the seed printed in the
//! assertion.

use wslib_can::{dlc_to_len, payload_dlc};
use wslib_can_gsusb as gs_usb;

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

/// The same sample as a gs_usb host frame this host is transmitting.
fn as_gs_usb(s: &Sample) -> gs_usb::HostFrame {
    gs_usb::HostFrame::transmit(
        s.arb_id,
        s.extended,
        s.rtr && !s.fd,
        s.fd,
        s.brs,
        s.bus,
        s.data.clone(),
    )
}

const SEEDS: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];
const FRAMES: usize = 200;

/// gs_usb frames are fixed-size records rather than a stream, so what matters
/// is that a whole session round-trips — including the length code that is not
/// a byte count.
#[test]
fn a_gs_usb_session_round_trips() {
    for seed in SEEDS {
        for (i, s) in bus_traffic(seed, FRAMES).iter().enumerate() {
            let rtr = s.rtr && !s.fd;
            let wire = gs_usb::encode_host_frame(&as_gs_usb(s));
            assert_eq!(
                wire.len(),
                if s.fd {
                    gs_usb::FD_FRAME_BYTES
                } else {
                    gs_usb::CLASSIC_FRAME_BYTES
                },
                "seed {seed}, frame {i}"
            );

            let got = gs_usb::parse_host_frame(&wire).expect("a frame");
            assert_eq!(
                (
                    got.arb_id,
                    got.extended,
                    got.rtr,
                    got.fd,
                    got.brs,
                    got.channel
                ),
                (s.arb_id, s.extended, rtr, s.fd, s.brs, s.bus),
                "seed {seed}, frame {i}"
            );
            assert_eq!(got.dlc, payload_dlc(s.data.len(), s.fd));
            assert_eq!(got.data, s.padded(), "seed {seed}, frame {i}");
            assert!(!got.is_rx(), "a transmit is not a received frame");
        }
    }
}

/// Several gs_usb frames arrive in one bulk transfer, and a reader strides
/// through them. A frame whose size the stride got wrong would decode as
/// rubbish from the second one on.
#[test]
fn a_bulk_transfer_of_gs_usb_frames_strides_correctly() {
    for seed in SEEDS {
        // One transfer carries frames of one size, so the stride is fixed.
        for fd in [false, true] {
            let traffic: Vec<Sample> = bus_traffic(seed, 32)
                .into_iter()
                .map(|mut s| {
                    s.fd = fd;
                    s.rtr = s.rtr && !fd;
                    s.data.truncate(if fd { 64 } else { 8 });
                    s
                })
                .collect();

            let mut transfer = Vec::new();
            for s in &traffic {
                gs_usb::encode_host_frame_into(&mut transfer, &as_gs_usb(s));
            }

            let stride = if fd {
                gs_usb::FD_FRAME_BYTES
            } else {
                gs_usb::CLASSIC_FRAME_BYTES
            };
            assert_eq!(transfer.len(), stride * traffic.len());
            for (i, s) in traffic.iter().enumerate() {
                let got = gs_usb::parse_host_frame(&transfer[i * stride..(i + 1) * stride])
                    .expect("a frame");
                assert_eq!(got.arb_id, s.arb_id, "seed {seed}, fd {fd}, frame {i}");
                assert_eq!(got.data, s.padded(), "seed {seed}, fd {fd}, frame {i}");
            }
        }
    }
}
