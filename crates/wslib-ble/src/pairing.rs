use std::time::Duration;

#[cfg(any(target_os = "linux", feature = "testing"))]
use crate::bluez::Session;
use crate::{Address, PairError, Paired};

/// The host's readiness to confirm a Just Works pairing with one device,
/// for as long as it lives.
///
/// BlueZ confirms no pairing while the host has no agent, so on Linux this
/// registers one, never as the default agent, and withdraws it when dropped.
/// The agent authorises a pairing BlueZ asks it about only for the one
/// device, and refuses any that needs a PIN or a passkey. BlueZ does not ask
/// about a pairing a process requests outright, so while a guard lives any
/// local process can pair any Just Works device: hold it only around
/// [`pair`](Self::pair). A host where another process has an agent is untested.
///
/// The order is `confirm`, connect, `pair`, then the encrypted reads and
/// writes, then drop. Dropping does not wait: it unregisters on the runtime
/// it is dropped in, and outside one leaves that to the connection closing.
/// [`close`](Self::close) waits and reports.
///
/// Off Linux the operating system pairs by itself and this holds nothing.
#[derive(Debug)]
pub struct Pairing {
    #[cfg(any(target_os = "linux", feature = "testing"))]
    session: Option<Session>,
}

impl Pairing {
    /// Readies the host to pair with `address`, which `adapter` (`hci0`) must
    /// have discovered, on a system-bus connection of its own.
    pub async fn confirm(adapter: &str, address: &Address) -> Result<Self, PairError> {
        #[cfg(target_os = "linux")]
        {
            let connection = zbus::Connection::system()
                .await
                .map_err(PairError::Service)?;
            Self::confirm_on(connection, adapter, address).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (adapter, address);
            Ok(Self {
                #[cfg(feature = "testing")]
                session: None,
            })
        }
    }

    /// [`confirm`](Self::confirm) over `connection`, which serves the agent
    /// and so holds one guard at a time.
    #[cfg(any(target_os = "linux", feature = "testing"))]
    pub async fn confirm_on(
        connection: zbus::Connection,
        adapter: &str,
        address: &Address,
    ) -> Result<Self, PairError> {
        let session = Session::confirm(connection, adapter, address).await?;
        Ok(Self {
            session: Some(session),
        })
    }

    /// Pairs now, answering once the bond is made or refused; a pairing still
    /// unanswered after `timeout`, or whose call is dropped, is cancelled.
    pub async fn pair(&self, timeout: Duration) -> Result<Paired, PairError> {
        #[cfg(any(target_os = "linux", feature = "testing"))]
        if let Some(session) = &self.session {
            return session.pair(timeout).await;
        }
        let _ = timeout;
        Ok(Paired::ByTheSystem)
    }

    /// Withdraws the agent and waits for BlueZ to say so.
    pub async fn close(self) -> Result<(), PairError> {
        #[cfg(any(target_os = "linux", feature = "testing"))]
        if let Some(session) = self.session {
            return session.close().await;
        }
        Ok(())
    }
}
