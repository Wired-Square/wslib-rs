//! The account at the other end of a control socket, from its peer credentials.

use std::ffi::CStr;
use std::mem::MaybeUninit;

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
        let uid = stream.peer_cred().ok().map(|credentials| credentials.uid());
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
    const LARGEST: usize = 1 << 20;
    let mut buffer: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut entry = MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: each pointer is to a live local, and `buffer.len()` is its length.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        match status {
            libc::ERANGE if buffer.len() < LARGEST => buffer.resize(buffer.len() * 2, 0),
            0 if !found.is_null() => {
                // SAFETY: `found` is the filled `entry`; `pw_name` is NUL-terminated.
                let name = unsafe { CStr::from_ptr((*found).pw_name) };
                return name
                    .to_str()
                    .ok()
                    .filter(|name| is_plain_account_name(name))
                    .map(str::to_owned);
            }
            _ => return None,
        }
    }
}

/// `[A-Za-z0-9._-]+` and an optional `$`: nothing that could forge a line or pass for the uid form.
pub(super) fn is_plain_account_name(name: &str) -> bool {
    let stem = name.strip_suffix('$').unwrap_or(name);
    !stem.is_empty()
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
