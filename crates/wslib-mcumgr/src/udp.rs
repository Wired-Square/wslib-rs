use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::{BoxFuture, Error, Session, Transport};

/// Larger than any SMP frame a device sends over a 1500-byte MTU.
const RECV_BUF_LEN: usize = 1500;

/// Leaves room under a 1500-byte MTU for the IP, UDP and SMP headers.
const UDP_CHUNK_SIZE: usize = 1024;

/// SMP over UDP, one frame per datagram.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Binds the peer's address family: on macOS an IPv6 socket is
    /// `IPV6_V6ONLY` and cannot reach an IPv4 peer.
    pub async fn connect(peer: SocketAddr) -> Result<Self, Error> {
        let local = match peer {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(peer).await?;
        Ok(Self { socket })
    }
}

impl Transport for UdpTransport {
    fn send(&self, frame: Vec<u8>) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.socket.send(&frame).await?;
            Ok(())
        })
    }

    fn receive(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async {
            let mut buf = vec![0; RECV_BUF_LEN];
            let len = self.socket.recv(&mut buf).await?;
            buf.truncate(len);
            Ok(buf)
        })
    }

    /// A datagram the device has no buffer for is lost, not queued.
    fn max_in_flight(&self) -> usize {
        1
    }

    /// A device's buffers are sized for BLE and would fragment a datagram.
    fn max_chunk_size(&self) -> usize {
        UDP_CHUNK_SIZE
    }
}

impl Session {
    /// A session over UDP. Its chunks stay within one unfragmented datagram
    /// whatever the device's buffers.
    pub async fn connect_udp(peer: SocketAddr) -> Result<Self, Error> {
        Ok(Self::new(
            Arc::new(UdpTransport::connect(peer).await?),
            UDP_CHUNK_SIZE,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Op, frame};

    #[tokio::test]
    async fn carries_a_frame_each_way_over_loopback() {
        let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session = Session::connect_udp(device.local_addr().unwrap())
            .await
            .unwrap();

        let echo = tokio::spawn(async move {
            #[derive(serde::Deserialize, serde::Serialize)]
            struct Echo {
                #[serde(alias = "d")]
                r: String,
            }
            let mut buf = [0; RECV_BUF_LEN];
            let (len, from) = device.recv_from(&mut buf).await.unwrap();
            let (header, echo): (_, Echo) = frame::decode(&buf[..len]).unwrap();
            let reply = frame::encode(
                Op::WriteResponse,
                header.group,
                header.command,
                header.seq,
                &echo,
            )
            .unwrap();
            device.send_to(&reply, from).await.unwrap();
        });

        assert_eq!(session.echo("hi").await.unwrap(), "hi");
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn negotiated_chunks_stay_within_one_datagram() {
        #[derive(serde::Serialize)]
        struct Params {
            buf_size: usize,
            buf_count: usize,
        }
        let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session = Session::connect_udp(device.local_addr().unwrap())
            .await
            .unwrap();

        let answer = tokio::spawn(async move {
            let mut buf = [0; RECV_BUF_LEN];
            let (len, from) = device.recv_from(&mut buf).await.unwrap();
            let header = crate::Header::decode(&buf[..len]).unwrap();
            let params = Params {
                buf_size: 4 * UDP_CHUNK_SIZE,
                buf_count: 4,
            };
            let reply = frame::encode(
                Op::ReadResponse,
                header.group,
                header.command,
                header.seq,
                &params,
            )
            .unwrap();
            device.send_to(&reply, from).await.unwrap();
        });

        session.negotiate_params().await.unwrap();
        answer.await.unwrap();

        assert_eq!(session.chunk_budget(), UDP_CHUNK_SIZE);
    }
}
