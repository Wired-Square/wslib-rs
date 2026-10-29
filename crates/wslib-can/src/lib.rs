//! CAN: the frame as it is on the bus, the data length code table, bit timing,
//! the candump and SavvyCAN text formats, and with `task` the task every CAN
//! transport runs.

pub mod bittiming;
pub mod candump;
pub mod dlc;
mod frame;
pub mod savvycan;
#[cfg(feature = "task")]
mod task;
mod text;

pub use dlc::{FD_DLC_LEN, dlc_to_len, len_to_dlc, payload_dlc};
pub use frame::{CanFlags, CanFrame, Direction, ErrorFrame, ErrorState};
#[cfg(feature = "task")]
pub use task::{
    BusState, CanError, CanEvent, CanOptions, CanRead, CanTask, CanWriter, Device, DeviceInfo,
    Limits, Received, SendRefused, Stamp, TimeMapping, Unsupported, open,
};

/// Arbitration id masks, one per id width: every CAN protocol masks the same 29
/// and 11 bits, and differs only in where it packs the flags alongside them.
pub const ARB_MASK_EXT: u32 = 0x1FFF_FFFF;
pub const ARB_MASK_STD: u32 = 0x0000_07FF;
