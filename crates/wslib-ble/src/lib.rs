//! Bluetooth LE pairing on a host with no agent, and forgetting a bond.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//!
//! use wslib_ble::{Address, Pairing};
//!
//! let address: Address = "AA:BB:CC:DD:EE:FF".parse()?;
//! let pairing = Pairing::confirm("hci0", &address).await?;
//! pairing.pair(Duration::from_secs(30)).await?;
//! pairing.close().await?;
//! # Ok(())
//! # }
//! ```

mod address;
mod error;
#[cfg(not(target_os = "linux"))]
mod system;

pub use address::{Address, AddressParseError};
pub use error::{ForgetError, Forgotten, PairError, Paired, Refusal};
#[cfg(not(target_os = "linux"))]
pub use system::{Pairing, forget};
