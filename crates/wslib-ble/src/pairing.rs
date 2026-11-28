use std::time::Duration;

#[cfg(any(target_os = "linux", feature = "testing"))]
use crate::bluez::Session;
use crate::{Address, PairError, Paired};

/// The host's readiness to authorise a Just Works pairing with one device,
/// for as long as its agent is registered.
///
/// BlueZ confirms no pairing while the host has no agent, so on Linux this
/// registers one, never as the default agent. The agent answers
/// `RequestAuthorization` for the one device's object path only, and rejects
/// everything else, `RequestConfirmation` included: it cannot compare digits.
/// BlueZ does not ask about a pairing a process requests outright, so while
/// the agent is registered any local process can pair any Just Works device:
/// hold the guard only around [`pair`](Self::pair). A host where another
/// process has an agent is untested.
///
/// The order is `confirm`, connect, `pair`, then the encrypted reads and
/// writes, then [`close`](Self::close).
///
/// Dropping the guard sends nothing. One made by [`confirm`](Self::confirm)
/// owns its connection, so the drop closes it and BlueZ removes the agent
/// with it; BlueZ also cancels a pairing a dropped `pair` left running on
/// that connection, and drops its record of the device. One made by
/// [`confirm_on`](Self::confirm_on) leaves its agent registered for as long
/// as the connection it was given lives, unless `close` is called.
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
    ///
    /// The caller must [`close`](Self::close) the guard: dropped, its agent
    /// stays registered until every clone of `connection` is gone. Not
    /// cancel-safe: a call dropped before it answers can leave the agent
    /// object served on `connection`.
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

    /// Pairs now, answering once the bond is made or refused; calls on one
    /// guard run one at a time.
    ///
    /// A pairing unanswered after `timeout` is cancelled before this answers
    /// if BlueZ accepts the cancel, otherwise by the next `pair` or
    /// [`close`](Self::close); a bond made as the limit passed stands, and
    /// the next `pair` answers [`Paired::Existing`]. BlueZ drops its record of
    /// a device whose pairing is cancelled, so the device must be discovered
    /// again.
    ///
    /// Not cancel-safe: a call dropped before it answers leaves BlueZ pairing
    /// until the next `pair`, which cancels it first, or `close`, or BlueZ's
    /// own timeout.
    pub async fn pair(&self, timeout: Duration) -> Result<Paired, PairError> {
        #[cfg(any(target_os = "linux", feature = "testing"))]
        if let Some(session) = &self.session {
            return session.pair(timeout).await;
        }
        let _ = timeout;
        Ok(Paired::ByTheSystem)
    }

    /// Cancels a pairing a dropped [`pair`](Self::pair) left running, then
    /// unregisters the agent and waits for BlueZ to say so.
    ///
    /// It is the only way a guard made by [`confirm_on`](Self::confirm_on)
    /// withdraws its agent while the connection lives. The agent is
    /// unregistered even when the cancelling fails; a failure to unregister
    /// is reported first, then one to cancel, and an agent BlueZ no longer
    /// holds is no failure.
    pub async fn close(self) -> Result<(), PairError> {
        #[cfg(any(target_os = "linux", feature = "testing"))]
        if let Some(session) = self.session {
            return session.close().await;
        }
        Ok(())
    }
}
