use std::iter::FusedIterator;

use crate::framing::Framing;
use crate::pci::{CLASSIC_LEN, LOW_NIBBLE, MAX_MESSAGE, PciKind, SN_FIRST};

/// A message ISO-TP cannot carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LengthError {
    #[error("an ISO-TP message needs at least one byte")]
    Empty,
    #[error("{len} bytes is over the framing's message limit")]
    TooLong { len: usize },
}

/// One message cut into frames. [`first`](Self::first) is the single or first
/// frame, and iterating gives the consecutive frames.
#[derive(Debug, Clone)]
pub struct Segmenter<'a> {
    message: &'a [u8],
    framing: Framing,
    sent: usize,
    sn: u8,
}

impl<'a> Segmenter<'a> {
    /// Cuts `message` with the default [`Framing`], into unpadded classic
    /// frames of at most 4095 bytes a message.
    pub fn new(message: &'a [u8]) -> Result<Self, LengthError> {
        Self::with_framing(message, &Framing::default())
    }

    pub fn with_framing(message: &'a [u8], framing: &Framing) -> Result<Self, LengthError> {
        let len = message.len();
        if len == 0 {
            return Err(LengthError::Empty);
        }
        if len > framing.max_len() {
            return Err(LengthError::TooLong { len });
        }
        let mut segmenter = Self {
            message,
            framing: *framing,
            sent: 0,
            sn: SN_FIRST,
        };
        let room = framing.tx_dl() - framing.address_len() - segmenter.first_pci().len();
        segmenter.sent = len.min(room);
        Ok(segmenter)
    }

    /// True if the message fits a single frame, which needs no flow control.
    pub fn is_single(&self) -> bool {
        self.message.len() <= self.framing.single_capacity(self.framing.tx_dl())
    }

    /// The single or first frame. Unpadded on classic frames with normal
    /// addressing, a single frame is `1 + len` bytes and a first frame 8.
    pub fn first(&self) -> Vec<u8> {
        let mut pdu = self.first_pci();
        pdu.extend_from_slice(&self.message[..self.sent]);
        self.framing.frame(&pdu)
    }

    fn first_pci(&self) -> Vec<u8> {
        let len = self.message.len();
        if self.is_single() {
            if len <= self.framing.single_capacity(CLASSIC_LEN) {
                return vec![PciKind::Single.pci_byte(len as u8)];
            }
            return vec![PciKind::Single.pci_byte(0), len as u8];
        }
        if len <= MAX_MESSAGE {
            let [high, low] = (len as u16).to_be_bytes();
            return vec![PciKind::First.pci_byte(high), low];
        }
        let mut pci = vec![PciKind::First.pci_byte(0), 0];
        pci.extend((len as u32).to_be_bytes());
        pci
    }

    fn cf_capacity(&self) -> usize {
        self.framing.cf_capacity(self.framing.tx_dl())
    }
}

impl Iterator for Segmenter<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let rest = self
            .message
            .get(self.sent..)
            .filter(|rest| !rest.is_empty())?;
        let data = &rest[..rest.len().min(self.cf_capacity())];
        let mut pdu = vec![PciKind::Consecutive.pci_byte(self.sn)];
        pdu.extend_from_slice(data);
        self.sent += data.len();
        self.sn = (self.sn + 1) & LOW_NIBBLE;
        Some(self.framing.frame(&pdu))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let frames = (self.message.len() - self.sent).div_ceil(self.cf_capacity());
        (frames, Some(frames))
    }
}

impl ExactSizeIterator for Segmenter<'_> {}

impl FusedIterator for Segmenter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{Addressing, FdLength, FrameFormat};
    use crate::pci::{CF_MAX_DATA, FF_DATA, SF_MAX_DATA};

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    fn fd(len: u8) -> Framing {
        Framing::new(
            Addressing::Normal,
            FrameFormat::Fd(FdLength::new(len).unwrap()),
        )
    }

    fn extended() -> Framing {
        Framing::new(
            Addressing::Extended { tx: 0x10, rx: 0xF1 },
            FrameFormat::Classic,
        )
    }

    #[test]
    fn extended_addressing_leaves_6_bytes_in_a_classic_single_frame() {
        let framing = extended();
        let data = message(6);
        let segmenter = Segmenter::with_framing(&data, &framing).unwrap();
        assert!(segmenter.is_single());
        assert_eq!(segmenter.first(), [0x10, 0x06, 0, 1, 2, 3, 4, 5]);
        let data = message(7);
        let segmenter = Segmenter::with_framing(&data, &framing).unwrap();
        assert!(!segmenter.is_single());
        assert_eq!(segmenter.first(), [0x10, 0x10, 0x07, 0, 1, 2, 3, 4]);
        assert_eq!(segmenter.collect::<Vec<_>>(), [vec![0x10, 0x21, 5, 6]]);
    }

    #[test]
    fn a_can_fd_single_frame_over_7_bytes_escapes_its_length() {
        let framing = fd(64);
        let data = message(7);
        assert_eq!(
            Segmenter::with_framing(&data, &framing).unwrap().first(),
            [0x07, 0, 1, 2, 3, 4, 5, 6]
        );
        let data = message(8);
        let first = Segmenter::with_framing(&data, &framing).unwrap().first();
        assert_eq!(first[..2], [0x00, 0x08]);
        assert_eq!(first.len(), 12);
        let data = message(62);
        let segmenter = Segmenter::with_framing(&data, &framing).unwrap();
        assert!(segmenter.is_single());
        assert_eq!(segmenter.first().len(), 64);
        let data = message(63);
        assert!(
            !Segmenter::with_framing(&data, &framing)
                .unwrap()
                .is_single()
        );
    }

    #[test]
    fn can_fd_first_and_consecutive_frames_fill_the_tx_data_length() {
        let framing = fd(16);
        let data = message(41);
        let segmenter = Segmenter::with_framing(&data, &framing).unwrap();
        let first = segmenter.first();
        assert_eq!(first.len(), 16);
        assert_eq!(first[..2], [0x10, 41]);
        let last = segmenter.last().unwrap();
        assert_eq!(
            last[..13],
            [0x22, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40]
        );
        assert_eq!(last[13..], [Framing::FD_FILL; 3]);
    }

    #[test]
    fn a_message_over_4095_bytes_takes_an_escaped_first_frame() {
        let framing = Framing {
            max_message: 70_000,
            ..Framing::default()
        };
        let data = message(70_000);
        let segmenter = Segmenter::with_framing(&data, &framing).unwrap();
        assert_eq!(
            segmenter.first(),
            [0x10, 0x00, 0x00, 0x01, 0x11, 0x70, 0, 1]
        );
        assert_eq!(segmenter.len(), (70_000 - 2usize).div_ceil(CF_MAX_DATA));
        let data = message(MAX_MESSAGE);
        assert_eq!(
            Segmenter::with_framing(&data, &framing).unwrap().first()[..2],
            [0x1F, 0xFF]
        );
        let data = message(70_001);
        assert_eq!(
            Segmenter::with_framing(&data, &framing).unwrap_err(),
            LengthError::TooLong { len: 70_001 }
        );
    }

    #[test]
    fn padding_fills_every_classic_frame() {
        let framing = Framing {
            padding: Some(0xAA),
            ..Framing::default()
        };
        let data = message(9);
        let segmenter = Segmenter::with_framing(&data, &framing).unwrap();
        assert_eq!(segmenter.first().len(), CLASSIC_LEN);
        assert_eq!(
            segmenter.collect::<Vec<_>>(),
            [vec![0x21, 6, 7, 8, 0xAA, 0xAA, 0xAA, 0xAA]]
        );
    }

    #[test]
    fn refuses_an_empty_message_and_one_over_4095_bytes() {
        assert_eq!(Segmenter::new(&[]).unwrap_err(), LengthError::Empty);
        let long = message(MAX_MESSAGE + 1);
        assert_eq!(
            Segmenter::new(&long).unwrap_err(),
            LengthError::TooLong {
                len: MAX_MESSAGE + 1
            }
        );
        assert!(Segmenter::new(&long[..MAX_MESSAGE]).is_ok());
    }

    #[test]
    fn a_single_frame_is_one_plus_its_length() {
        for len in 1..=SF_MAX_DATA {
            let data = message(len);
            let mut segmenter = Segmenter::new(&data).unwrap();
            assert!(segmenter.is_single());
            let frame = segmenter.first();
            assert_eq!(frame.len(), 1 + len);
            assert_eq!(frame[0], len as u8);
            assert_eq!(&frame[1..], data);
            assert_eq!(segmenter.len(), 0);
            assert_eq!(segmenter.next(), None);
        }
    }

    #[test]
    fn eight_bytes_is_a_first_frame_and_one_short_consecutive_frame() {
        let data = message(8);
        let mut segmenter = Segmenter::new(&data).unwrap();
        assert!(!segmenter.is_single());
        assert_eq!(segmenter.first(), [0x10, 0x08, 0, 1, 2, 3, 4, 5]);
        assert_eq!(segmenter.len(), 1);
        assert_eq!(segmenter.next(), Some(vec![0x21, 6, 7]));
        assert_eq!(segmenter.next(), None);
        assert_eq!(segmenter.next(), None);
    }

    #[test]
    fn the_first_frame_carries_a_12_bit_length() {
        let data = message(MAX_MESSAGE);
        let first = Segmenter::new(&data).unwrap().first();
        assert_eq!(first.len(), CLASSIC_LEN);
        assert_eq!(first[..2], [0x1F, 0xFF]);
        let data = message(0x123);
        assert_eq!(Segmenter::new(&data).unwrap().first()[..2], [0x11, 0x23]);
    }

    #[test]
    fn consecutive_frames_are_full_but_the_last() {
        let data = message(62);
        let segmenter = Segmenter::new(&data).unwrap();
        assert_eq!(segmenter.len(), 8);
        let lengths: Vec<usize> = segmenter.map(|frame| frame.len()).collect();
        assert_eq!(lengths, [8, 8, 8, 8, 8, 8, 8, 1 + 7]);
        let data = message(63);
        let lengths: Vec<usize> = Segmenter::new(&data)
            .unwrap()
            .map(|frame| frame.len())
            .collect();
        assert_eq!(lengths.last(), Some(&(1 + 1)));
    }

    #[test]
    fn the_sequence_number_starts_at_1_and_wraps_to_0() {
        let data = message(FF_DATA + CF_MAX_DATA * 18);
        let sns: Vec<u8> = Segmenter::new(&data)
            .unwrap()
            .map(|frame| frame[0])
            .collect();
        let expected: Vec<u8> = (1..=0x0F).chain(0..=2).map(|sn| 0x20 | sn).collect();
        assert_eq!(sns, expected);
    }

    #[test]
    fn the_iterator_knows_its_length() {
        let data = message(1200);
        let mut segmenter = Segmenter::new(&data).unwrap();
        assert_eq!(segmenter.len(), (1200 - FF_DATA).div_ceil(CF_MAX_DATA));
        segmenter.next();
        assert_eq!(segmenter.len(), (1200 - FF_DATA).div_ceil(CF_MAX_DATA) - 1);
    }
}
