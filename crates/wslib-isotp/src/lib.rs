//! ISO-TP (ISO 15765-2) as a sans-IO codec, and with `link` an async link over
//! a wslib-can adapter.
//!
//! A [`Framing`] sets the addressing (normal, extended or mixed), the frame
//! format (classic or CAN FD), padding, and the longest message. The default,
//! which [`Segmenter::new`] and [`Reassembler::new`] use, is normal addressing
//! on unpadded classic frames, read padded or not, at most [`MAX_MESSAGE`]
//! bytes a message; a first frame announcing a 32-bit length is ignored.
//!
//! [`IsoTpTap`] reassembles both sides of a conversation it only watches, and
//! [`detect`] picks out the ids in a window of traffic that carry ISO-TP.

mod detect;
mod flow_control;
mod framing;
#[cfg(feature = "link")]
mod link;
mod pci;
mod reassemble;
mod segment;
mod tap;
#[cfg(feature = "testing")]
pub mod testing;

pub use detect::{
    DEFAULT_FLOW_CONTROL_WINDOW, Detection, IdEvidence, KindCounts, MAX_ADDRESS_BYTES, Pair, detect,
};
pub use flow_control::{FlowControl, FlowControlError, FlowStatus, StMin};
pub use framing::{Addressing, FdLength, FdLengthError, FrameFormat, Framing};
#[cfg(feature = "link")]
pub use link::{IsoTpLink, LinkConfig, LinkStats, Messages, SendFailed, SendFailures};
pub use pci::{CLASSIC_LEN, MAX_MESSAGE, PciKind};
pub use reassemble::{Abort, Outcome, Reassembler, Step};
pub use segment::{LengthError, Segmenter};
pub use tap::{
    IndistinctSides, IsoTpTap, NoticeKind, Side, TapConfig, TapEvent, TapMessage, TapNotice,
    TimedFrame,
};
