use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wslib_framelink_protocol::frame;
use wslib_framelink_protocol::types::{FLAG_NONE, MSG_PING};
use wslib_framelink_protocol::{Error as ProtocolError, PROTOCOL_VERSION};
use wslib_framing::cobs::{self, CobsDecoder};

use crate::Error;
use crate::client::MAX_STUFFED_FRAME;

const LISTEN_WINDOW: Duration = Duration::from_millis(1500);

/// The protocol version the device at `addr` replies in, or `None` when no
/// frame that parses or names its version comes back within a moment and a
/// half.
///
/// A device drops a frame of a version it does not speak, so a PING goes out
/// at each of the sixteen versions the header can name. This relies on every
/// version keeping the 5-byte header and COBS framing, so the version nibble
/// is read the same way whichever one answers. A device serves one client:
/// close any session to it first.
pub async fn probe_version(addr: SocketAddr) -> Result<Option<u8>, Error> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&pings()).await?;

    let mut decoder = CobsDecoder::with_max_frame_len(MAX_STUFFED_FRAME);
    let deadline = tokio::time::Instant::now() + LISTEN_WINDOW;
    let mut buf = [0u8; 512];
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Err(_) | Ok(Ok(0)) => return Ok(None),
            Ok(read) => read?,
        };
        let version =
            decoder.feed(&buf[..n]).iter().find_map(|block| {
                match frame::parse_unstuffed(&block.bytes) {
                    Ok(_) => Some(PROTOCOL_VERSION),
                    Err(ProtocolError::UnsupportedVersion(v)) => Some(v),
                    Err(_) => None,
                }
            });
        if version.is_some() {
            return Ok(version);
        }
    }
}

fn pings() -> Vec<u8> {
    let wire = frame::build_frame(MSG_PING, FLAG_NONE, 0, &[]);
    let raw = cobs::decode(&wire[1..wire.len() - 1]).expect("build_frame stuffs a valid block");
    (0..=0x0F)
        .flat_map(|version: u8| {
            let mut raw = raw.clone();
            raw[0] = version << 4 | raw[0] & 0x0F;
            cobs::encode(&raw)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use wslib_framelink_protocol::types::{FLAG_RESPONSE, MSG_PONG};

    #[test]
    fn the_ping_at_our_version_is_the_one_the_protocol_builds() {
        let ours = frame::build_frame(MSG_PING, FLAG_NONE, 0, &[]);
        let all = pings();
        assert_eq!(all.len(), 16 * ours.len());
        let at = usize::from(PROTOCOL_VERSION) * ours.len();
        assert_eq!(&all[at..at + ours.len()], ours);
    }

    /// Answers only the PING stamped `version`, with a PONG stamped the same.
    async fn device_speaking(version: Option<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut decoder = CobsDecoder::new();
            let mut buf = [0u8; 512];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                for ping in decoder.feed(&buf[..n]) {
                    if Some(ping.bytes[0] >> 4) != version {
                        continue;
                    }
                    let pong = frame::build_frame(MSG_PONG, FLAG_RESPONSE, 0, &[]);
                    let mut raw = cobs::decode(&pong[1..pong.len() - 1]).unwrap();
                    raw[0] = ping.bytes[0] & 0xF0 | raw[0] & 0x0F;
                    socket.write_all(&cobs::encode(&raw)).await.ok();
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_device_on_our_version_reports_it() {
        let addr = device_speaking(Some(PROTOCOL_VERSION)).await;
        assert_eq!(probe_version(addr).await.unwrap(), Some(PROTOCOL_VERSION));
    }

    #[tokio::test]
    async fn a_device_on_another_version_names_its_own() {
        let addr = device_speaking(Some(3)).await;
        assert_eq!(probe_version(addr).await.unwrap(), Some(3));
    }

    #[tokio::test]
    async fn a_silent_device_is_none() {
        let addr = device_speaking(None).await;
        assert_eq!(probe_version(addr).await.unwrap(), None);
    }

    #[tokio::test]
    async fn nobody_listening_is_an_error() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(matches!(probe_version(addr).await, Err(Error::Io(_))));
    }
}
