//! ISO-TP (ISO 15765-2) on classic CAN as a sans-IO codec, and with `link` an
//! async link over a wslib-can adapter.
//!
//! It uses normal addressing and 8-byte frames, and carries at most
//! [`MAX_MESSAGE`] bytes a message. Frames are sent unpadded and read padded
//! or not. There is no CAN FD, extended or mixed addressing, or 32-bit
//! first-frame length. A first frame announcing fewer than 8 bytes, including
//! the 0 that starts a 32-bit length, ends any message in progress and is
//! otherwise ignored.

mod flow_control;
#[cfg(feature = "link")]
mod link;
mod pci;
mod reassemble;
mod segment;

pub use flow_control::{FlowControl, FlowControlError, FlowStatus, StMin};
#[cfg(feature = "link")]
pub use link::{IsoTpLink, LinkConfig, LinkStats, Messages, SendFailed, SendFailures};
pub use pci::{CLASSIC_LEN, MAX_MESSAGE, PciKind};
pub use reassemble::{Abort, Outcome, Reassembler, Step};
pub use segment::{LengthError, Segmenter};
