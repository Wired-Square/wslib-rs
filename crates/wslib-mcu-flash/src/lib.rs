//! Flashing microcontrollers: chip families and offsets, USB-serial port
//! resolution, firmware image parsing, a progress/cancel seam, and the
//! backends behind feature flags.
//!
//! The external-tool backends (`tool`, features `esptool` / `dfu-util`) are
//! `async` over a tokio process. The in-process backends (`esp`, `dfu`,
//! `stm32_uart`) block on a port or a USB handle; the caller wraps them in
//! `spawn_blocking`, and the crate picks no runtime for them.

pub mod artefact;
pub mod chip;
pub mod endpoint;
pub mod error;
pub mod image;
pub mod ports;
pub mod progress;

#[cfg(any(feature = "esptool", feature = "dfu-util"))]
pub mod tool;

#[cfg(feature = "espflash")]
pub mod esp;

#[cfg(feature = "dfu")]
pub mod dfu;

#[cfg(feature = "stm32-uart")]
pub mod stm32_uart;

#[cfg(any(feature = "espflash", feature = "stm32-uart"))]
mod output;

#[cfg(all(feature = "espflash", feature = "stm32-uart"))]
pub mod detect;

pub use artefact::MaterialisedArtefact;
pub use chip::ChipFamily;
pub use endpoint::{FlashEndpoint, Transport, UsbAccess};
pub use error::{FlashError, Result};
pub use ports::SerialPort;
pub use progress::{FlashProgress, FlashStage};
