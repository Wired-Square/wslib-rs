use super::{
    decode::{self, TABLE},
    frame::{Assembler, Frame, MAIN_RANGE_MASK},
};
use crate::sample::{Sample, Stamp};

/// A raw notification from the meter, as `Gw121Probe::start_tapped` taps it.
pub type Chunk = (Stamp, Vec<u8>);

/// Reassembles chunks into frames and decodes each as the probe does, so a
/// capture can be replayed.
#[derive(Debug, Default)]
pub struct Replay {
    assembler: Assembler,
}

/// One frame: the meter's raw mode, range and flags, and the samples decoded
/// from it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decoded {
    pub mode: u8,
    pub range: u8,
    pub flags: u8,
    pub sub_mode: u8,
    pub sub_flags: u8,
    pub samples: Vec<Sample>,
}

impl Replay {
    /// The frames this chunk completes, stamped with the chunk's stamp.
    pub fn push(&mut self, chunk: &Chunk) -> Vec<Decoded> {
        let (stamp, bytes) = chunk;
        self.assembler
            .push(bytes)
            .iter()
            .map(|bytes| {
                let frame = Frame::decode(bytes);
                Decoded {
                    mode: frame.main.mode,
                    range: frame.main.flags & MAIN_RANGE_MASK,
                    flags: frame.main.flags,
                    sub_mode: frame.sub.mode,
                    sub_flags: frame.sub.flags,
                    samples: decode::samples(&frame, &TABLE, *stamp),
                }
            })
            .collect()
    }
}
