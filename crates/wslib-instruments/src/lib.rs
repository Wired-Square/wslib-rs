//! Bench-instrument readers behind one blocking [`probe::Probe`]: the EEVblog
//! 121GW over BLE and a WiredReflow board over CAN, each reading a FrameLink
//! signal. A probe runs its own runtime on its own thread, so it may be used
//! from inside a tokio runtime.

#![cfg_attr(
    not(test),
    forbid(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable
    )
)]

pub mod cluster;
pub mod gw121;
pub mod probe;
pub mod sample;
mod selected;
pub mod signal;
pub mod uri;
pub mod value;
pub mod wiredreflow;
