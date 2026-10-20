//! Tells systemd a service is ready, stopping or still alive, by a datagram to
//! the socket named in `$NOTIFY_SOCKET` (sd_notify(3)), without libsystemd.
//!
//! ```no_run
//! wslib_systemd_notify::ready()?;
//! wslib_systemd_notify::status("serving")?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Every call is a successful no-op when `$NOTIFY_SOCKET` is unset or empty,
//! and on targets other than Unix. The `tokio` feature adds [`feed_watchdog`].

use std::env;
use std::ffi::OsStr;
use std::io;
use std::time::Duration;

#[cfg(feature = "tokio")]
mod feed;
#[cfg(feature = "tokio")]
pub use feed::feed_watchdog;

/// Sends `READY=1`: start-up has finished.
pub fn ready() -> io::Result<()> {
    notify(&[("READY", "1")])
}

/// Sends `STATUS=`: one line for `systemctl status`; a newline is refused.
pub fn status(text: &str) -> io::Result<()> {
    notify(&[("STATUS", text)])
}

/// Sends `STOPPING=1`: shutdown has begun.
pub fn stopping() -> io::Result<()> {
    notify(&[("STOPPING", "1")])
}

/// Sends `WATCHDOG=1`: the service is still alive.
pub fn watchdog() -> io::Result<()> {
    notify(&[("WATCHDOG", "1")])
}

/// Sends `KEY=value` lines in one datagram; a key that is empty or holds `=`,
/// or a newline anywhere, is refused as [`io::ErrorKind::InvalidInput`].
pub fn notify(fields: &[(&str, &str)]) -> io::Result<()> {
    let message = message(fields)?;
    send(env::var_os("NOTIFY_SOCKET").as_deref(), &message)
}

/// The watchdog interval systemd expects pings within, from `$WATCHDOG_USEC`,
/// or `None` if it is unset, invalid, or `$WATCHDOG_PID` names another process.
pub fn watchdog_interval() -> Option<Duration> {
    interval(
        env::var_os("WATCHDOG_USEC").as_deref(),
        env::var_os("WATCHDOG_PID").as_deref(),
        std::process::id(),
    )
}

fn interval(usec: Option<&OsStr>, pid: Option<&OsStr>, own_pid: u32) -> Option<Duration> {
    let ours = |pid: &OsStr| pid.to_str().and_then(|pid| pid.parse().ok()) == Some(own_pid);
    let usec: u64 = usec?.to_str()?.parse().ok()?;
    (usec > 0 && pid.is_none_or(ours)).then(|| Duration::from_micros(usec))
}

fn message(fields: &[(&str, &str)]) -> io::Result<String> {
    let mut message = String::new();
    for (key, value) in fields {
        if key.is_empty() || key.contains(['=', '\n']) || value.contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not a notify field: {key:?}={value:?}"),
            ));
        }
        if !message.is_empty() {
            message.push('\n');
        }
        message.push_str(key);
        message.push('=');
        message.push_str(value);
    }
    Ok(message)
}

#[cfg(unix)]
fn send(socket: Option<&OsStr>, message: &str) -> io::Result<()> {
    use std::os::unix::net::UnixDatagram;

    let Some(socket) = socket.filter(|socket| !socket.is_empty()) else {
        return Ok(());
    };
    let datagram = UnixDatagram::unbound()?;
    datagram.set_nonblocking(true)?;
    datagram.send_to_addr(message.as_bytes(), &address(socket)?)?;
    Ok(())
}

#[cfg(not(unix))]
fn send(_socket: Option<&OsStr>, _message: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn address(socket: &OsStr) -> io::Result<std::os::unix::net::SocketAddr> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::SocketAddr;

    match socket.as_bytes() {
        [b'/', ..] => SocketAddr::from_pathname(socket),
        #[cfg(target_os = "linux")]
        [b'@', name @ ..] => {
            use std::os::linux::net::SocketAddrExt;
            SocketAddr::from_abstract_name(name)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("NOTIFY_SOCKET is not a socket this target can reach: {socket:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<&OsStr> {
        Some(OsStr::new(s))
    }

    #[test]
    fn fields_are_newline_separated_key_value_lines() {
        let message = message(&[("READY", "1"), ("STATUS", "serving on :80")]).unwrap();
        assert_eq!(message, "READY=1\nSTATUS=serving on :80");
    }

    #[test]
    fn a_newline_or_a_bad_key_is_refused() {
        for fields in [
            [("STATUS", "one\nREADY=1")],
            [("STA\nTUS", "x")],
            [("A=B", "x")],
            [("", "x")],
        ] {
            let error = message(&fields).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{fields:?}");
        }
    }

    #[test]
    fn an_unset_or_empty_socket_is_a_successful_no_op() {
        send(None, "READY=1").unwrap();
        send(os(""), "READY=1").unwrap();
    }

    #[test]
    fn the_interval_is_watchdog_usec() {
        assert_eq!(
            interval(os("30000000"), None, 7),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn the_interval_applies_only_to_the_named_pid() {
        assert_eq!(
            interval(os("1000"), os("7"), 7),
            Some(Duration::from_millis(1))
        );
        assert_eq!(interval(os("1000"), os("8"), 7), None);
        assert_eq!(interval(os("1000"), os("seven"), 7), None);
    }

    #[test]
    fn no_interval_when_unset_zero_or_garbled() {
        assert_eq!(interval(None, None, 7), None);
        assert_eq!(interval(os("0"), None, 7), None);
        assert_eq!(interval(os("-5"), None, 7), None);
        assert_eq!(interval(os("30s"), None, 7), None);
    }

    #[cfg(unix)]
    pub(crate) mod socket {
        use std::os::unix::net::UnixDatagram;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU32, Ordering};

        pub(crate) struct Listener {
            pub(crate) socket: UnixDatagram,
            pub(crate) path: PathBuf,
        }

        impl Listener {
            pub(crate) fn bind() -> Self {
                static NEXT: AtomicU32 = AtomicU32::new(0);
                let dir = std::env::temp_dir().join(format!(
                    "wslib-sd-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("notify");
                let socket = UnixDatagram::bind(&path).unwrap();
                socket.set_nonblocking(true).unwrap();
                Self { socket, path }
            }

            pub(crate) fn received(&self) -> Vec<String> {
                let mut buf = [0; 4096];
                std::iter::from_fn(|| {
                    let n = self.socket.recv(&mut buf).ok()?;
                    Some(String::from_utf8(buf[..n].to_vec()).unwrap())
                })
                .collect()
            }
        }

        impl Drop for Listener {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn sends_one_datagram_to_a_path_socket() {
        let listener = socket::Listener::bind();
        let message = message(&[("READY", "1"), ("STATUS", "up")]).unwrap();
        send(Some(listener.path.as_os_str()), &message).unwrap();
        assert_eq!(listener.received(), ["READY=1\nSTATUS=up"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_relative_socket_is_refused() {
        let error = send(os("notify.sock"), "READY=1").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sends_to_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        let name = format!("wslib-sd-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&address).unwrap();
        send(os(&format!("@{name}")), "WATCHDOG=1").unwrap();
        let mut buf = [0; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }
}
