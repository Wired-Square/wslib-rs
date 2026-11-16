use std::iter::FusedIterator;

use crate::pci::{CF_MAX_DATA, FF_DATA, LOW_NIBBLE, MAX_MESSAGE, PciKind, SF_MAX_DATA, SN_FIRST};

/// A message ISO-TP cannot carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LengthError {
    #[error("an ISO-TP message needs at least one byte")]
    Empty,
    #[error("{len} bytes is over ISO-TP's {MAX_MESSAGE}-byte limit")]
    TooLong { len: usize },
}

/// One message cut into unpadded frames. [`first`](Self::first) is the single
/// or first frame, and iterating gives the consecutive frames.
#[derive(Debug, Clone)]
pub struct Segmenter<'a> {
    message: &'a [u8],
    sent: usize,
    sn: u8,
}

impl<'a> Segmenter<'a> {
    pub fn new(message: &'a [u8]) -> Result<Self, LengthError> {
        match message.len() {
            0 => Err(LengthError::Empty),
            len if len > MAX_MESSAGE => Err(LengthError::TooLong { len }),
            len => Ok(Self {
                message,
                sent: if len <= SF_MAX_DATA { len } else { FF_DATA },
                sn: SN_FIRST,
            }),
        }
    }

    /// True if the message fits a single frame, which needs no flow control.
    pub fn is_single(&self) -> bool {
        self.message.len() <= SF_MAX_DATA
    }

    /// The single frame, `1 + len` bytes, or the first frame, always 8.
    pub fn first(&self) -> Vec<u8> {
        let len = self.message.len();
        if self.is_single() {
            let mut frame = vec![PciKind::Single.pci_byte(len as u8)];
            frame.extend_from_slice(self.message);
            return frame;
        }
        let [high, low] = (len as u16).to_be_bytes();
        let mut frame = vec![PciKind::First.pci_byte(high), low];
        frame.extend_from_slice(&self.message[..FF_DATA]);
        frame
    }
}

impl Iterator for Segmenter<'_> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        let rest = self
            .message
            .get(self.sent..)
            .filter(|rest| !rest.is_empty())?;
        let data = &rest[..rest.len().min(CF_MAX_DATA)];
        let mut frame = vec![PciKind::Consecutive.pci_byte(self.sn)];
        frame.extend_from_slice(data);
        self.sent += data.len();
        self.sn = (self.sn + 1) & LOW_NIBBLE;
        Some(frame)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let frames = (self.message.len() - self.sent).div_ceil(CF_MAX_DATA);
        (frames, Some(frames))
    }
}

impl ExactSizeIterator for Segmenter<'_> {}

impl FusedIterator for Segmenter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::CLASSIC_LEN;

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
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
