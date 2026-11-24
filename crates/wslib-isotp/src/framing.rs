use crate::flow_control::{FlowControl, FlowControlError};
use crate::pci::{
    CF_PCI_LEN, CLASSIC_LEN, FF_ESCAPE_PCI_LEN, FF_PCI_LEN, LOW_NIBBLE, MAX_MESSAGE, PciKind,
    SF_ESCAPE_PCI_LEN, SF_PCI_LEN,
};

const FD_LENGTHS: [u8; 8] = [8, 12, 16, 20, 24, 32, 48, 64];
const FD_MAX: usize = 64;

/// How a frame's first byte addresses it. Extended and mixed addressing carry
/// one byte before the PCI: `tx` on the frames this end sends, `rx` on the
/// frames it receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpAddressing"))]
#[cfg_attr(feature = "serde", serde(rename_all_fields = "camelCase"))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Addressing {
    #[default]
    Normal,
    /// A target address byte.
    Extended { tx: u8, rx: u8 },
    /// An address extension byte.
    Mixed { tx: u8, rx: u8 },
}

impl Addressing {
    /// The addressing the other end of the conversation uses.
    pub fn peer(self) -> Self {
        match self {
            Self::Normal => Self::Normal,
            Self::Extended { tx, rx } => Self::Extended { tx: rx, rx: tx },
            Self::Mixed { tx, rx } => Self::Mixed { tx: rx, rx: tx },
        }
    }

    fn bytes(self) -> Option<(u8, u8)> {
        match self {
            Self::Normal => None,
            Self::Extended { tx, rx } | Self::Mixed { tx, rx } => Some((tx, rx)),
        }
    }
}

/// A CAN FD data length ISO-TP may send with: 8, 12, 16, 20, 24, 32, 48 or 64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "u8", into = "u8")
)]
#[cfg_attr(
    feature = "ts",
    derive(ts_rs::TS),
    ts(rename = "IsoTpFdLength", type = "number")
)]
pub struct FdLength(u8);

impl FdLength {
    pub const MAX: Self = Self(FD_MAX as u8);

    pub fn new(len: u8) -> Option<Self> {
        FD_LENGTHS.contains(&len).then_some(Self(len))
    }

    pub fn get(self) -> usize {
        self.0.into()
    }

    fn at_least(len: usize) -> usize {
        FD_LENGTHS
            .into_iter()
            .map(usize::from)
            .find(|&valid| valid >= len)
            .unwrap_or(FD_MAX)
    }
}

/// A byte that is not a CAN FD data length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0} bytes is not a CAN FD data length")]
pub struct FdLengthError(pub u8);

impl TryFrom<u8> for FdLength {
    type Error = FdLengthError;

    fn try_from(len: u8) -> Result<Self, FdLengthError> {
        Self::new(len).ok_or(FdLengthError(len))
    }
}

impl From<FdLength> for u8 {
    fn from(len: FdLength) -> Self {
        len.0
    }
}

/// Classic 8-byte frames, or CAN FD frames sent at most the given length and
/// received at any length up to 64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpFrameFormat"))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FrameFormat {
    #[default]
    Classic,
    Fd(FdLength),
}

/// How ISO-TP lays its frames out on one conversation, from one end's side.
/// The default is normal addressing on classic frames, unpadded, at most
/// [`MAX_MESSAGE`] bytes a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "IsoTpFraming"))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[non_exhaustive]
pub struct Framing {
    pub addressing: Addressing,
    pub format: FrameFormat,
    /// Fills a sent frame of 8 bytes or fewer to 8. A CAN FD frame over 8
    /// bytes is always filled to a valid length, with this byte or
    /// [`FD_FILL`](Self::FD_FILL).
    pub padding: Option<u8>,
    /// The longest message sent or accepted. Above 4095, a first frame
    /// announcing a 32-bit length is read; a longer one is refused with an
    /// overflow.
    pub max_message: u32,
}

impl Default for Framing {
    fn default() -> Self {
        Self {
            addressing: Addressing::Normal,
            format: FrameFormat::Classic,
            padding: None,
            max_message: MAX_MESSAGE as u32,
        }
    }
}

pub(crate) enum Pdu<'a> {
    /// `None` for a single frame that carries no valid message.
    Single(Option<&'a [u8]>),
    /// `None` for a first frame that starts no valid message.
    First(Option<FirstFrame<'a>>),
    Consecutive {
        sn: u8,
        data: &'a [u8],
    },
    FlowControl(Result<FlowControl, FlowControlError>),
}

pub(crate) struct FirstFrame<'a> {
    pub len: usize,
    pub data: &'a [u8],
    pub cf_capacity: usize,
}

impl FirstFrame<'_> {
    /// The message so far, reserving no more than 4095 bytes however long
    /// the frame says it is.
    pub(crate) fn buffer(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(self.len.min(MAX_MESSAGE));
        message.extend_from_slice(self.data);
        message
    }
}

impl Framing {
    pub const FD_FILL: u8 = 0xCC;

    pub fn new(addressing: Addressing, format: FrameFormat) -> Self {
        Self {
            addressing,
            format,
            ..Self::default()
        }
    }

    /// The framing the other end of the conversation uses.
    pub fn peer(&self) -> Self {
        Self {
            addressing: self.addressing.peer(),
            ..*self
        }
    }

    pub fn is_fd(&self) -> bool {
        matches!(self.format, FrameFormat::Fd(_))
    }

    /// A received frame's kind, or `None` for one too long for the format,
    /// addressed elsewhere, empty, or of a reserved type.
    pub fn classify(&self, frame: &[u8]) -> Option<PciKind> {
        PciKind::of(*self.payload(frame)?.first()?)
    }

    /// The flow control frame this end sends, addressed and padded.
    pub fn encode_flow_control(&self, flow: &FlowControl) -> Vec<u8> {
        self.frame(&flow.encode())
    }

    /// Parses a received flow control, as [`FlowControl::parse`] does once the
    /// address byte is checked and stripped.
    pub fn parse_flow_control(&self, frame: &[u8]) -> Result<FlowControl, FlowControlError> {
        self.payload(frame).map_or(
            Err(FlowControlError::NotFlowControl),
            FlowControl::parse_payload,
        )
    }

    pub(crate) fn address_len(&self) -> usize {
        usize::from(self.addressing.bytes().is_some())
    }

    pub(crate) fn tx_dl(&self) -> usize {
        match self.format {
            FrameFormat::Classic => CLASSIC_LEN,
            FrameFormat::Fd(len) => len.get(),
        }
    }

    pub(crate) fn max_len(&self) -> usize {
        usize::try_from(self.max_message).unwrap_or(usize::MAX)
    }

    pub(crate) fn carries_rx_byte(&self, frame: &[u8]) -> bool {
        self.addressing
            .bytes()
            .is_none_or(|(_, rx)| frame.first() == Some(&rx))
    }

    pub(crate) fn single_capacity(&self, can_dl: usize) -> usize {
        let pci = if can_dl > CLASSIC_LEN {
            SF_ESCAPE_PCI_LEN
        } else {
            SF_PCI_LEN
        };
        can_dl - pci - self.address_len()
    }

    pub(crate) fn cf_capacity(&self, can_dl: usize) -> usize {
        can_dl - CF_PCI_LEN - self.address_len()
    }

    pub(crate) fn frame(&self, pdu: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(self.tx_dl());
        frame.extend(self.addressing.bytes().map(|(tx, _)| tx));
        frame.extend_from_slice(pdu);
        let len = match frame.len() {
            len if len > CLASSIC_LEN => FdLength::at_least(len),
            _ if self.padding.is_some() => CLASSIC_LEN,
            len => len,
        };
        frame.resize(len, self.padding.unwrap_or(Self::FD_FILL));
        frame
    }

    pub(crate) fn decode<'a>(&self, frame: &'a [u8]) -> Option<Pdu<'a>> {
        let payload = self.payload(frame)?;
        let pci = *payload.first()?;
        Some(match PciKind::of(pci)? {
            PciKind::Single => Pdu::Single(self.single(frame.len(), payload)),
            PciKind::First => Pdu::First(self.first(frame.len(), payload)),
            PciKind::Consecutive => Pdu::Consecutive {
                sn: pci & LOW_NIBBLE,
                data: &payload[CF_PCI_LEN..],
            },
            PciKind::FlowControl => Pdu::FlowControl(FlowControl::parse_payload(payload)),
        })
    }

    fn max_frame(&self) -> usize {
        match self.format {
            FrameFormat::Classic => CLASSIC_LEN,
            FrameFormat::Fd(_) => FD_MAX,
        }
    }

    fn payload<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        if frame.len() > self.max_frame() {
            return None;
        }
        match self.addressing.bytes() {
            None => Some(frame),
            Some((_, rx)) => match frame.split_first() {
                Some((&byte, rest)) if byte == rx => Some(rest),
                _ => None,
            },
        }
    }

    fn single<'a>(&self, can_dl: usize, payload: &'a [u8]) -> Option<&'a [u8]> {
        let (len, pci) = match (payload[0] & LOW_NIBBLE, can_dl > CLASSIC_LEN) {
            (0, true) => (usize::from(*payload.get(1)?), SF_ESCAPE_PCI_LEN),
            (len, false) => (usize::from(len), SF_PCI_LEN),
            _ => return None,
        };
        payload.get(pci..pci + len).filter(|data| !data.is_empty())
    }

    fn first<'a>(&self, can_dl: usize, payload: &'a [u8]) -> Option<FirstFrame<'a>> {
        if can_dl < CLASSIC_LEN {
            return None;
        }
        let short = u16::from_be_bytes([payload[0] & LOW_NIBBLE, *payload.get(1)?]);
        let (len, pci) = if short == 0 {
            let escaped = payload.get(FF_PCI_LEN..FF_ESCAPE_PCI_LEN)?;
            let len = usize::try_from(u32::from_be_bytes(escaped.try_into().ok()?)).ok()?;
            if self.max_len() <= MAX_MESSAGE || len <= MAX_MESSAGE {
                return None;
            }
            (len, FF_ESCAPE_PCI_LEN)
        } else {
            (usize::from(short), FF_PCI_LEN)
        };
        if len <= self.single_capacity(can_dl) {
            return None;
        }
        Some(FirstFrame {
            len,
            data: payload.get(pci..)?,
            cf_capacity: self.cf_capacity(can_dl),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_control::{FlowStatus, StMin};

    const TESTER: u8 = 0xF1;
    const ECU: u8 = 0x10;
    const EXTENDED: Addressing = Addressing::Extended {
        tx: ECU,
        rx: TESTER,
    };

    fn fd(len: u8) -> FrameFormat {
        FrameFormat::Fd(FdLength::new(len).unwrap())
    }

    #[test]
    fn the_can_fd_lengths_are_the_eight_iso_tp_may_send_with() {
        let valid: Vec<u8> = (0..=u8::MAX)
            .filter(|&l| FdLength::new(l).is_some())
            .collect();
        assert_eq!(valid, [8, 12, 16, 20, 24, 32, 48, 64]);
        assert_eq!(FdLength::try_from(13), Err(FdLengthError(13)));
        assert_eq!(u8::from(FdLength::MAX), 64);
    }

    #[test]
    fn extended_addressing_prefixes_every_sent_frame_with_its_tx_byte() {
        let framing = Framing::new(EXTENDED, FrameFormat::Classic);
        let fc = FlowControl {
            status: FlowStatus::ContinueToSend,
            block_size: 0,
            st_min: StMin(0),
        };
        assert_eq!(framing.encode_flow_control(&fc), [ECU, 0x30, 0, 0]);
    }

    #[test]
    fn extended_addressing_reads_only_frames_carrying_its_rx_byte() {
        let framing = Framing::new(EXTENDED, FrameFormat::Classic);
        assert_eq!(
            framing.classify(&[TESTER, 0x30, 0, 0]),
            Some(PciKind::FlowControl)
        );
        assert_eq!(framing.classify(&[ECU, 0x30, 0, 0]), None);
        assert_eq!(framing.classify(&[0x30, 0, 0]), None);
        assert_eq!(
            framing.parse_flow_control(&[ECU, 0x30, 0, 0]),
            Err(FlowControlError::NotFlowControl)
        );
        assert_eq!(
            framing.parse_flow_control(&[TESTER, 0x30, 0x02, 0x05, 0xCC]),
            Ok(FlowControl {
                status: FlowStatus::ContinueToSend,
                block_size: 2,
                st_min: StMin(5),
            })
        );
    }

    #[test]
    fn mixed_addressing_is_carried_on_the_wire_as_extended_is() {
        let mixed = Framing::new(
            Addressing::Mixed {
                tx: ECU,
                rx: TESTER,
            },
            FrameFormat::Classic,
        );
        let extended = Framing::new(EXTENDED, FrameFormat::Classic);
        assert_eq!(mixed.frame(&[0x01, 0x3E]), extended.frame(&[0x01, 0x3E]));
        assert_eq!(
            mixed.classify(&[TESTER, 0x01, 0x7E]),
            extended.classify(&[TESTER, 0x01, 0x7E])
        );
    }

    #[test]
    fn the_peer_swaps_the_address_bytes() {
        let framing = Framing::new(EXTENDED, fd(64));
        let peer = framing.peer();
        assert_eq!(
            peer.addressing,
            Addressing::Extended {
                tx: TESTER,
                rx: ECU
            }
        );
        assert_eq!(peer.format, framing.format);
        assert_eq!(peer.peer(), framing);
    }

    #[test]
    fn padding_fills_a_frame_of_8_or_fewer_to_8() {
        let mut framing = Framing::default();
        assert_eq!(framing.frame(&[0x01, 0x3E]), [0x01, 0x3E]);
        framing.padding = Some(0xAA);
        assert_eq!(
            framing.frame(&[0x01, 0x3E]),
            [0x01, 0x3E, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
        );
        let mut fd = Framing::new(Addressing::Normal, fd(64));
        assert_eq!(fd.frame(&[0x01, 0x3E]), [0x01, 0x3E]);
        fd.padding = Some(0x55);
        assert_eq!(fd.frame(&[0x01, 0x3E]).len(), CLASSIC_LEN);
    }

    #[test]
    fn a_can_fd_frame_over_8_bytes_is_filled_to_the_next_valid_length() {
        let framing = Framing::new(Addressing::Normal, fd(64));
        for (len, filled) in [(9, 12), (12, 12), (13, 16), (21, 24), (33, 48), (49, 64)] {
            let frame = framing.frame(&vec![0x21; len]);
            assert_eq!(frame.len(), filled, "{len}");
            assert!(frame[len..].iter().all(|&b| b == Framing::FD_FILL));
        }
        let mut padded = framing;
        padded.padding = Some(0x00);
        assert_eq!(padded.frame(&[0x21; 9])[9..], [0, 0, 0]);
    }

    #[test]
    fn a_classic_framing_ignores_a_frame_over_8_bytes_and_fd_one_over_64() {
        let classic = Framing::default();
        assert_eq!(classic.classify(&[0x21; 9]), None);
        let fd = Framing::new(Addressing::Normal, fd(8));
        assert_eq!(fd.classify(&[0x21; 64]), Some(PciKind::Consecutive));
        assert_eq!(fd.classify(&[0x21; 65]), None);
    }

    #[test]
    fn a_single_frame_of_8_bytes_or_fewer_carries_its_length_in_the_low_nibble() {
        let normal = Framing::default();
        assert_eq!(
            normal.single(8, &[0x07, 1, 2, 3, 4, 5, 6, 7]),
            Some(&[1, 2, 3, 4, 5, 6, 7][..])
        );
        assert_eq!(normal.single(8, &[0x00, 1, 2, 3, 4, 5, 6, 7]), None);
        assert_eq!(
            normal.single(12, &[0x03, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
    }

    #[test]
    fn a_single_frame_over_8_bytes_escapes_its_length_into_the_second_byte() {
        let normal = Framing::default();
        let mut frame = vec![0x00, 10];
        frame.extend(1..=10);
        assert_eq!(normal.single(12, &frame), Some(&frame[2..]));
        let mut short = frame.clone();
        short.truncate(8);
        assert_eq!(normal.single(8, &short), None);
        assert_eq!(
            normal.single(12, &[0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            None
        );
    }

    #[test]
    fn an_escaped_single_frame_is_read_at_any_length_its_frame_carries() {
        let normal = Framing::default();
        let escaped = |can_dl: usize, len: u8| {
            let mut frame = vec![0x00, len];
            frame.resize(can_dl, 0xCC);
            frame
        };
        assert_eq!(normal.single(64, &escaped(64, 3)), Some(&[0xCC; 3][..]));
        assert!(normal.single(12, &escaped(12, 7)).is_some());
        assert!(normal.single(64, &escaped(64, 62)).is_some());
        assert_eq!(normal.single(64, &escaped(64, 63)), None);
        assert_eq!(normal.single(64, &escaped(64, 0)), None);
    }

    #[test]
    fn a_first_frames_length_must_exceed_what_a_single_frame_of_its_size_carries() {
        let classic = Framing::default();
        assert!(classic.first(8, &[0x10, 0x07, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(classic.first(8, &[0x10, 0x08, 0, 0, 0, 0, 0, 0]).is_some());
        let extended = Framing::new(EXTENDED, FrameFormat::Classic);
        assert!(extended.first(8, &[0x10, 0x06, 0, 0, 0, 0, 0]).is_none());
        assert!(extended.first(8, &[0x10, 0x07, 0, 0, 0, 0, 0]).is_some());
        let fd = Framing::new(Addressing::Normal, fd(64));
        let mut frame = vec![0x10, 62];
        frame.resize(64, 0);
        assert!(fd.first(64, &frame).is_none());
        frame[1] = 63;
        assert!(fd.first(64, &frame).is_some());
    }

    #[test]
    fn an_escaped_first_frame_is_read_only_above_4095_and_with_a_cap_above_4095() {
        let mut framing = Framing::default();
        let escaped = |len: u32| {
            let mut frame = vec![0x10, 0x00];
            frame.extend(len.to_be_bytes());
            frame.extend([0xAA, 0xBB]);
            frame
        };
        assert!(framing.first(8, &escaped(5000)).is_none());
        framing.max_message = u32::MAX;
        let frame = escaped(5000);
        let first = framing.first(8, &frame).unwrap();
        assert_eq!((first.len, first.data), (5000, &[0xAA, 0xBB][..]));
        assert!(framing.first(8, &escaped(4095)).is_none());
        assert!(framing.first(8, &escaped(4096)).is_some());
    }
}
