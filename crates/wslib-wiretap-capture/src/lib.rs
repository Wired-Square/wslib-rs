//! A capture store in one SQLite file: frames or raw bytes per capture, with
//! their metadata and events.

mod events;
mod filter;
mod frames;
mod inventory;
mod model;
#[cfg(feature = "sqlite")]
mod store;

pub use events::{CaptureEvent, CaptureEventPatch, NewCaptureEvent};
pub use filter::{CaptureProtocol, FrameRowFilter, Sql, SqlValue};
pub use frames::{FrameRecord, STORED_LENGTH, StoredFrame};
pub use inventory::inventory_statement;
pub use model::{CaptureFrameInfo, CaptureKind, CaptureMetadata, Direction, TimestampedByte};
#[cfg(feature = "sqlite")]
pub use store::{
    Applied, Cancel, CaptureError, Result, Store, chain, inventory_row, sqlx, tuning,
    upgrade_legacy,
};
