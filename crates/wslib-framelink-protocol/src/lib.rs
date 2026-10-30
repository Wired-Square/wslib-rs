//! The FrameLink protocol, sans-io: frames, every message's payload, the
//! signal vocabulary and identity tuple, and BLE manufacturer data.

pub mod board_def;
pub mod bridge;
pub mod can_id;
pub mod capabilities;
pub mod counter;
pub mod dsig;
mod error;
pub mod file_xfer;
pub mod frame;
pub mod frame_def;
pub mod generator;
pub mod manufacturer_data;
pub mod persist;
pub mod stream;
pub mod types;
pub mod xform;

pub use error::Error;
pub use frame::PROTOCOL_VERSION;
pub use manufacturer_data::SCHEMA_VERSION_MAX;
pub use types::RULE_FORMAT;

/// The lowest id `used` does not hold, or `u16::MAX` when it holds them all.
pub fn next_free_id(used: impl Iterator<Item = u16>) -> u16 {
    let used: std::collections::HashSet<u16> = used.collect();
    (0..=u16::MAX)
        .find(|id| !used.contains(id))
        .unwrap_or(u16::MAX)
}

/// An ENABLE message: the id, then 1 or 0.
pub(crate) fn build_enable(id: u16, enabled: bool) -> Vec<u8> {
    let mut buf = id.to_le_bytes().to_vec();
    buf.push(u8::from(enabled));
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_free_id_returns_lowest_unused() {
        assert_eq!(next_free_id([0u16, 1, 3].into_iter()), 2);
        assert_eq!(next_free_id(std::iter::empty()), 0);
    }
}
