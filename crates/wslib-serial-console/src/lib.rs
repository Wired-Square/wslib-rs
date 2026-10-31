//! A serial console shared by every browser on a port: the wire types they
//! read, and with `monitor` the port's monitor, with `ws` its `/ws/serial`.

mod wire;

pub use wire::{
    COLOURS, ConsoleAction, ConsoleEvent, EndReason, Finished, MonitorState, Participant,
    RefusalReason, Span,
};

#[cfg(feature = "monitor")]
mod monitor;
#[cfg(feature = "monitor")]
pub use monitor::{Bounds, MonitorOptions, Monitors, PortKey, Refusal, Subscription, Update};

#[cfg(all(feature = "monitor", any(test, feature = "test-support")))]
pub mod test_support;
