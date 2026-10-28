//! A client for tailscaled's LocalAPI over its Unix socket: the node's status
//! and prefs, logout and reset-auth, with errors that keep a tailscaled that
//! isn't running, one that doesn't answer and one that refuses apart.
//!
//! ```no_run
//! # async fn run() -> Result<(), wslib_tailscale::Error> {
//! let api = wslib_tailscale::LocalApi::default();
//! if let Some(name) = api.status().await?.enrolled() {
//!     println!("on the tailnet as {name}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The `testing` feature adds [`testing::FakeTailscaled`], on Unix.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod status;
#[cfg(all(feature = "testing", unix))]
pub mod testing;

pub use status::{BackendState, OwnNode, Prefs, Status};

const STATUS: &str = "/localapi/v0/status?peers=false";
const PREFS: &str = "/localapi/v0/prefs";
const ANSWER_CAP: usize = 1 << 20;

/// tailscaled's LocalAPI at a socket path.
#[derive(Debug, Clone)]
pub struct LocalApi {
    socket: PathBuf,
    read_timeout: Duration,
    change_timeout: Duration,
}

impl Default for LocalApi {
    fn default() -> Self {
        Self {
            socket: Self::SOCKET.into(),
            read_timeout: Duration::from_secs(5),
            change_timeout: Duration::from_secs(30),
        }
    }
}

impl LocalApi {
    /// Where tailscaled listens on Linux.
    pub const SOCKET: &str = "/run/tailscale/tailscaled.sock";

    /// The client for tailscaled at `socket`.
    pub fn with_socket(mut self, socket: impl Into<PathBuf>) -> Self {
        self.socket = socket.into();
        self
    }

    /// How long a `GET` waits for its answer; 5 s by default.
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// How long any other request waits; 30 s by default, as a logout waits on the control server.
    pub fn with_change_timeout(mut self, timeout: Duration) -> Self {
        self.change_timeout = timeout;
        self
    }

    /// The node's status, without its peers.
    pub async fn status(&self) -> Result<Status, Error> {
        self.status_within(self.read_timeout).await
    }

    /// The node's status, waiting at most `timeout`.
    pub async fn status_within(&self, timeout: Duration) -> Result<Status, Error> {
        parse(&self.ask("GET", STATUS, timeout).await?)
    }

    /// The node's prefs.
    pub async fn prefs(&self) -> Result<Prefs, Error> {
        parse(&self.request("GET", PREFS).await?)
    }

    /// Logs the node out of its tailnet.
    pub async fn logout(&self) -> Result<(), Error> {
        self.request("POST", "/localapi/v0/logout").await.map(drop)
    }

    /// Forgets the node's machine key, so the next login is a new node.
    pub async fn reset_auth(&self) -> Result<(), Error> {
        self.request("POST", "/localapi/v0/reset-auth")
            .await
            .map(drop)
    }

    /// Any LocalAPI request without a body; the body of a 2xx answer.
    pub async fn request(&self, method: &str, path: &str) -> Result<Vec<u8>, Error> {
        let timeout = match method {
            "GET" => self.read_timeout,
            _ => self.change_timeout,
        };
        self.ask(method, path, timeout).await
    }

    async fn ask(&self, method: &str, path: &str, timeout: Duration) -> Result<Vec<u8>, Error> {
        let request = format!(
            "{method} {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\nContent-Length: 0\r\n\r\n"
        );
        let raw = tokio::time::timeout(timeout, exchange(&self.socket, &request))
            .await
            .map_err(|_| Error::Silent)??;
        if raw.len() > ANSWER_CAP {
            return Err(Error::Malformed("an answer over 1 MiB".into()));
        }
        let (status, body) =
            answer(&raw).ok_or_else(|| Error::Malformed("not an HTTP answer".into()))?;
        if (200..=299).contains(&status) {
            return Ok(body.to_vec());
        }
        let said = String::from_utf8_lossy(body)
            .lines()
            .next()
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect();
        Err(Error::Refused { status, said })
    }
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|e| Error::Malformed(e.to_string()))
}

/// HTTP/1.0, so the answer is never chunked and ends when tailscaled closes.
#[cfg(unix)]
async fn exchange(socket: &Path, request: &str) -> Result<Vec<u8>, Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|e| match e.kind() {
            // A socket left behind by a tailscaled that exited refuses.
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => Error::Absent,
            _ => Error::Io(e),
        })?;
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    stream
        .take(ANSWER_CAP as u64 + 1)
        .read_to_end(&mut raw)
        .await?;
    Ok(raw)
}

#[cfg(not(unix))]
async fn exchange(_: &Path, _: &str) -> Result<Vec<u8>, Error> {
    Err(Error::Absent)
}

fn answer(raw: &[u8]) -> Option<(u16, &[u8])> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let status = std::str::from_utf8(&raw[..end])
        .ok()?
        .split(' ')
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, &raw[end + 4..]))
}

/// Why tailscaled gave no answer to use.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Nothing listens on the socket: tailscaled isn't running.
    Absent,
    /// tailscaled took longer than the timeout.
    Silent,
    /// tailscaled answered with a status outside 2xx; `said` is the first line of its body.
    Refused { status: u16, said: String },
    /// The answer was not HTTP, was over 1 MiB, or held JSON of another shape.
    Malformed(String),
    /// The socket failed otherwise.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("tailscaled is not running"),
            Self::Silent => f.write_str("tailscaled did not answer in time"),
            Self::Refused { status, said } => write!(f, "tailscaled refused ({status}): {said}"),
            Self::Malformed(why) => write!(f, "tailscaled's answer could not be read: {why}"),
            Self::Io(_) => f.write_str("tailscaled could not be reached"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Whether `address` is in Tailscale's ranges, `100.64.0.0/10` or
/// `fd7a:115c:a1e0::/48`, taking an IPv4-mapped IPv6 address as its IPv4 one.
pub fn is_tailnet_address(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(v4) => {
            let [first, second, ..] = v4.octets();
            first == 100 && second & 0xc0 == 64
        }
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tailscales_ranges_are_the_tailnet_and_a_mapped_address_is_unmapped() {
        let tailnet = [
            "100.64.0.0",
            "100.127.255.255",
            "fd7a:115c:a1e0::1",
            "::ffff:100.100.1.2",
        ];
        let not = [
            "100.63.255.255",
            "100.128.0.0",
            "10.0.0.1",
            "fd7a:115c:a1e1::1",
            "::1",
        ];
        for address in tailnet {
            assert!(is_tailnet_address(address.parse().unwrap()), "{address}");
        }
        for address in not {
            assert!(!is_tailnet_address(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn an_answer_splits_into_its_status_and_body() {
        assert_eq!(
            answer(b"HTTP/1.0 404 Not Found\r\nA: b\r\n\r\nno"),
            Some((404, &b"no"[..]))
        );
        assert_eq!(answer(b"HTTP/1.0 200 OK\r\n"), None);
        assert_eq!(answer(b"garbage\r\n\r\n"), None);
    }
}
