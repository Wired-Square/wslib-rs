use std::time::Duration;

use crate::{Address, ForgetError, Forgotten, PairError, Paired};

/// The host's readiness to pair with one device, which this operating system
/// keeps by itself.
#[derive(Debug)]
pub struct Pairing(());

impl Pairing {
    /// Answers at once: the operating system confirms a pairing by itself.
    pub async fn confirm(_adapter: &str, _address: &Address) -> Result<Self, PairError> {
        Ok(Self(()))
    }

    /// Answers [`Paired::ByTheSystem`] at once.
    pub async fn pair(&self, _timeout: Duration) -> Result<Paired, PairError> {
        Ok(Paired::ByTheSystem)
    }

    /// Ends the guard, which holds nothing here.
    pub async fn close(self) -> Result<(), PairError> {
        Ok(())
    }
}

/// Answers [`ForgetError::Unsupported`]: the operating system gives no call
/// that removes a bond.
pub async fn forget(_adapter: &str, _address: &Address) -> Result<Forgotten, ForgetError> {
    Err(ForgetError::Unsupported)
}
