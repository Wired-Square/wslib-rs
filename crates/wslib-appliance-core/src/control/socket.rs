//! The account at the other end of a control socket, from its peer credentials.

use axum::serve::Listener;
use tokio::net::{UnixListener, UnixStream};

use crate::extract::LOCAL_ACTOR;

/// A control or app socket, whose peer is the client's effective uid at
/// `connect()`: `sudo` is audited as the account it ran as.
pub(crate) struct Peers(pub(crate) UnixListener);

impl Listener for Peers {
    type Io = UnixStream;
    type Addr = Option<u32>;

    async fn accept(&mut self) -> (UnixStream, Option<u32>) {
        let (stream, _) = Listener::accept(&mut self.0).await;
        let uid = wslib_host::peer_credentials(&stream)
            .ok()
            .map(|credentials| credentials.uid);
        (stream, uid)
    }

    fn local_addr(&self) -> std::io::Result<Option<u32>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "a control socket is named by its path",
        ))
    }
}

pub(super) fn rendered(uid: u32, account: Option<String>) -> String {
    match account {
        Some(name) => format!("{LOCAL_ACTOR}:{name}"),
        None => format!("{LOCAL_ACTOR}:uid={uid}"),
    }
}

/// Blocking; `None` unless the uid has a [plain](is_plain_account_name) name.
pub(super) fn account_name(uid: u32) -> Option<String> {
    wslib_host::account_name(uid)
        .ok()
        .flatten()
        .filter(|name| is_plain_account_name(name))
}

/// `[A-Za-z0-9._-]+` and an optional `$`: nothing that could forge a line or pass for the uid form.
pub(super) fn is_plain_account_name(name: &str) -> bool {
    let stem = name.strip_suffix('$').unwrap_or(name);
    !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
