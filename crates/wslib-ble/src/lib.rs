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
//!
//! The `testing` feature adds [`testing::FakeBluez`], on Unix.

mod address;
#[cfg(any(target_os = "linux", feature = "testing"))]
mod bluez;
mod error;
#[cfg(not(target_os = "linux"))]
mod system;
#[cfg(all(unix, feature = "testing"))]
pub mod testing;

pub use address::{Address, AddressParseError};
#[cfg(any(target_os = "linux", feature = "testing"))]
pub use bluez::forget_on;
pub use error::{ForgetError, Forgotten, PairError, Paired, Refusal};
#[cfg(not(target_os = "linux"))]
pub use system::Pairing;

/// Removes the host's bond with `address` and its record of the device on
/// `adapter`, so the device must be discovered again before it is used.
///
/// Off Linux it answers [`ForgetError::Unsupported`], since the operating
/// system gives no call for it.
pub async fn forget(adapter: &str, address: &Address) -> Result<Forgotten, ForgetError> {
    #[cfg(target_os = "linux")]
    {
        let connection = zbus::Connection::system()
            .await
            .map_err(ForgetError::Service)?;
        forget_on(&connection, adapter, address).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (adapter, address);
        Err(ForgetError::Unsupported)
    }
}
