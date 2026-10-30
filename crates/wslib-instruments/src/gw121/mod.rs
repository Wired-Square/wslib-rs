#[cfg(feature = "ble")]
pub mod ble;
pub mod decode;
pub mod frame;
mod target;

pub use target::Target;

pub const METER_NAME: &str = "121GW";
