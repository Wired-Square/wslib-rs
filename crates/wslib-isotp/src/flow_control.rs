use std::time::Duration;

use crate::pci::{CLASSIC_LEN, LOW_NIBBLE, PciKind};

pub(crate) const UNLIMITED_BLOCK: u8 = 0;

const MAX_MILLIS: u8 = 0x7F;
const FIRST_MICROS: u8 = 0xF1;
const LAST_MICROS: u8 = 0xF9;
const MICRO_STEPS: u8 = LAST_MICROS - FIRST_MICROS + 1;
const MICROS_STEP: Duration = Duration::from_micros(100);
const MILLI: Duration = Duration::from_millis(1);
const RESERVED: Duration = Duration::from_millis(MAX_MILLIS as u64);

/// A flow control's minimum gap between consecutive frames, as its raw byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpStMin"))]
pub struct StMin(pub u8);

impl StMin {
    /// 0x00 to 0x7F as milliseconds, 0xF1 to 0xF9 as 100 to 900 µs, and any
    /// reserved value as 127 ms.
    pub fn duration(self) -> Duration {
        match self.0 {
            millis @ 0..=MAX_MILLIS => Duration::from_millis(millis.into()),
            micros @ FIRST_MICROS..=LAST_MICROS => {
                MICROS_STEP * u32::from(micros - FIRST_MICROS + 1)
            }
            _ => RESERVED,
        }
    }

    /// The shortest encodable gap of at least `gap`, capped at 127 ms.
    pub fn from_duration(gap: Duration) -> Self {
        if gap.is_zero() {
            return Self(0);
        }
        let steps = gap.as_nanos().div_ceil(MICROS_STEP.as_nanos());
        if let Ok(steps @ 1..=MICRO_STEPS) = u8::try_from(steps) {
            return Self(FIRST_MICROS + steps - 1);
        }
        let millis = gap.as_nanos().div_ceil(MILLI.as_nanos());
        Self(u8::try_from(millis).map_or(MAX_MILLIS, |millis| millis.min(MAX_MILLIS)))
    }
}

/// A flow control's status nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpFlowStatus"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[repr(u8)]
pub enum FlowStatus {
    ContinueToSend = 0x0,
    Wait = 0x1,
    Overflow = 0x2,
}

impl FlowStatus {
    const ALL: [Self; 3] = [Self::ContinueToSend, Self::Wait, Self::Overflow];

    fn from_nibble(nibble: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|status| *status as u8 == nibble)
    }
}

/// A frame that [`FlowControl::parse`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FlowControlError {
    /// Not a flow control, or one too short or too long. A sender ignores it.
    #[error("not a flow control frame")]
    NotFlowControl,
    /// A flow control with a reserved status. A sender fails the send.
    #[error("flow control with reserved status {0:#x}")]
    ReservedStatus(u8),
}

/// A flow control frame. A block size of 0 asks for every consecutive frame
/// in one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpFlowControl"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct FlowControl {
    pub status: FlowStatus,
    pub block_size: u8,
    pub st_min: StMin,
}

impl FlowControl {
    /// The frame's three bytes, unpadded.
    pub fn encode(&self) -> Vec<u8> {
        vec![
            PciKind::FlowControl.pci_byte(self.status as u8),
            self.block_size,
            self.st_min.0,
        ]
    }

    /// Parses a flow control, padded or not.
    pub fn parse(frame: &[u8]) -> Result<Self, FlowControlError> {
        if frame.len() > CLASSIC_LEN {
            return Err(FlowControlError::NotFlowControl);
        }
        Self::parse_payload(frame)
    }

    pub(crate) fn parse_payload(payload: &[u8]) -> Result<Self, FlowControlError> {
        let [pci, block_size, st_min, ..] = *payload else {
            return Err(FlowControlError::NotFlowControl);
        };
        if PciKind::of(pci) != Some(PciKind::FlowControl) {
            return Err(FlowControlError::NotFlowControl);
        }
        let nibble = pci & LOW_NIBBLE;
        Ok(Self {
            status: FlowStatus::from_nibble(nibble)
                .ok_or(FlowControlError::ReservedStatus(nibble))?,
            block_size,
            st_min: StMin(st_min),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::CLASSIC_LEN;

    #[test]
    fn decodes_milliseconds() {
        assert_eq!(StMin(0x00).duration(), Duration::ZERO);
        assert_eq!(StMin(0x01).duration(), Duration::from_millis(1));
        assert_eq!(StMin(0x7F).duration(), Duration::from_millis(127));
    }

    #[test]
    fn decodes_hundreds_of_microseconds() {
        assert_eq!(StMin(0xF1).duration(), Duration::from_micros(100));
        assert_eq!(StMin(0xF5).duration(), Duration::from_micros(500));
        assert_eq!(StMin(0xF9).duration(), Duration::from_micros(900));
    }

    #[test]
    fn decodes_every_reserved_value_as_127_ms() {
        for raw in (0x80..=0xF0).chain(0xFA..=0xFF) {
            assert_eq!(
                StMin(raw).duration(),
                Duration::from_millis(127),
                "{raw:#04x}"
            );
        }
    }

    #[test]
    fn encodes_by_rounding_up() {
        let cases = [
            (Duration::ZERO, 0x00),
            (Duration::from_nanos(1), 0xF1),
            (Duration::from_micros(100), 0xF1),
            (Duration::from_micros(101), 0xF2),
            (Duration::from_micros(900), 0xF9),
            (Duration::from_micros(901), 0x01),
            (Duration::from_millis(1), 0x01),
            (Duration::from_micros(1001), 0x02),
            (Duration::from_millis(127), 0x7F),
        ];
        for (gap, raw) in cases {
            assert_eq!(StMin::from_duration(gap), StMin(raw), "{gap:?}");
        }
    }

    #[test]
    fn encodes_a_gap_over_127_ms_as_127_ms() {
        assert_eq!(
            StMin::from_duration(Duration::from_micros(127_001)),
            StMin(0x7F)
        );
        assert_eq!(StMin::from_duration(Duration::from_secs(1000)), StMin(0x7F));
        assert_eq!(StMin::from_duration(Duration::MAX), StMin(0x7F));
    }

    #[test]
    fn every_valid_value_round_trips() {
        for raw in (0x00..=0x7F).chain(0xF1..=0xF9) {
            assert_eq!(
                StMin::from_duration(StMin(raw).duration()),
                StMin(raw),
                "{raw:#04x}"
            );
        }
    }

    #[test]
    fn encodes_three_bytes() {
        let fc = FlowControl {
            status: FlowStatus::Wait,
            block_size: 8,
            st_min: StMin(0xF3),
        };
        assert_eq!(fc.encode(), [0x31, 0x08, 0xF3]);
        let fc = FlowControl {
            status: FlowStatus::Overflow,
            block_size: 0,
            st_min: StMin(0),
        };
        assert_eq!(fc.encode(), [0x32, 0x00, 0x00]);
    }

    #[test]
    fn parses_unpadded_and_padded() {
        let cts = FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size: 2,
            st_min: StMin(0x0A),
        };
        assert_eq!(FlowControl::parse(&[0x30, 0x02, 0x0A]), Ok(cts));
        assert_eq!(
            FlowControl::parse(&[0x30, 0x02, 0x0A, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
            Ok(cts)
        );
    }

    #[test]
    fn round_trips_every_status() {
        for status in FlowStatus::ALL {
            let fc = FlowControl {
                status,
                block_size: 0xFF,
                st_min: StMin(0xF9),
            };
            assert_eq!(FlowControl::parse(&fc.encode()), Ok(fc));
        }
    }

    #[test]
    fn tells_a_reserved_status_apart() {
        for nibble in 0x3..=0xF {
            let pci = PciKind::FlowControl.pci_byte(nibble);
            assert_eq!(
                FlowControl::parse(&[pci, 0, 0]),
                Err(FlowControlError::ReservedStatus(nibble)),
                "{pci:#04x}"
            );
        }
        assert_eq!(
            FlowControl::parse(&[0x3F, 0, 0, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]),
            Err(FlowControlError::ReservedStatus(0xF))
        );
    }

    #[test]
    fn refuses_a_short_frame_and_other_kinds() {
        for frame in [
            &[][..],
            &[0x30, 0x00],
            &[0x33, 0x00],
            &[0x21, 0x00, 0x00],
            &[0x30; CLASSIC_LEN + 1],
        ] {
            assert_eq!(
                FlowControl::parse(frame),
                Err(FlowControlError::NotFlowControl),
                "{frame:02x?}"
            );
        }
    }
}
