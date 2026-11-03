use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum_server::{AddrListener, Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// What one listener will hold and wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// Connections held at once; past it, peers wait in the kernel's backlog.
    pub connections: usize,
    /// How long a peer has to finish its handshake, say which protocol it
    /// speaks, and send each http/1.1 request head; each step gets its own
    /// `head`, so the first head may arrive up to about twice `head` in.
    pub head: Duration,
    /// How long open connections get to finish once the stop future completes.
    pub grace: Duration,
}

impl Bounds {
    /// For a listener serving an app.
    pub const SERVING: Self = Self {
        connections: 16,
        head: Duration::from_secs(10),
        grace: Duration::from_secs(10),
    };

    /// For the redirect listener: one head in, one 307 out.
    pub const REDIRECT: Self = Self {
        connections: 8,
        head: Duration::from_secs(5),
        grace: Duration::from_secs(10),
    };
}

impl Default for Bounds {
    fn default() -> Self {
        Self::SERVING
    }
}

/// A bound TCP listener held to its [`Bounds`].
pub struct Listener {
    tcp: TcpListener,
    local: SocketAddr,
    permits: Arc<Semaphore>,
    pub(crate) bounds: Bounds,
}

impl Listener {
    /// Bind `address` now, so a port taken fails here and port 0 resolves.
    pub async fn bind(address: SocketAddr, bounds: Bounds) -> io::Result<Self> {
        Self::from_tcp(TcpListener::bind(address).await?, bounds)
    }

    /// Hold a listener the caller bound to `bounds`.
    pub fn from_tcp(tcp: TcpListener, bounds: Bounds) -> io::Result<Self> {
        Ok(Self {
            local: tcp.local_addr()?,
            tcp,
            permits: Arc::new(Semaphore::new(bounds.connections)),
            bounds,
        })
    }

    /// The address bound, with the port the OS picked for port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

/// A peer's address, or the listener's own.
#[derive(Clone)]
pub struct Peer(SocketAddr);

impl Address for Peer {
    type Stream = Permitted<TcpStream>;
    type Listener = Arc<Listener>;
}

impl axum::extract::connect_info::Connected<Peer> for SocketAddr {
    fn connect_info(peer: Peer) -> Self {
        peer.0
    }
}

// The permit is taken before `accept`, so at the cap the connections waiting
// cost the kernel's backlog and not this process's descriptors.
impl AddrListener<Permitted<TcpStream>, Peer> for Arc<Listener> {
    async fn bind_to(_: Peer) -> io::Result<Self> {
        Err(made_bound())
    }

    async fn accept_stream(&self) -> io::Result<(Permitted<TcpStream>, Peer)> {
        let permit = permit(&self.permits).await?;
        loop {
            match self.tcp.accept().await {
                Ok((stream, peer)) => return Ok((Permitted { stream, permit }, Peer(peer))),
                Err(e) => backed_off(e).await,
            }
        }
    }

    fn get_local_addr(&self) -> io::Result<Peer> {
        Ok(Peer(self.local))
    }
}

pub(crate) fn made_bound() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "a bounded listener is made from one already bound",
    )
}

pub(crate) async fn permit(permits: &Arc<Semaphore>) -> io::Result<OwnedSemaphorePermit> {
    Arc::clone(permits)
        .acquire_owned()
        .await
        .map_err(io::Error::other)
}

// As axum's own `serve`: a peer gone before its accept is retried at once, and
// anything else, such as EMFILE, is logged and waited out rather than spun on.
pub(crate) async fn backed_off(e: io::Error) {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!("accept error: {e}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// A connection that gives its permit back when it ends.
pub struct Permitted<S> {
    pub(crate) stream: S,
    #[expect(dead_code, reason = "held for the connection's life; dropped with it")]
    pub(crate) permit: OwnedSemaphorePermit,
}

impl<S: AsyncRead + Unpin> AsyncRead for Permitted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Permitted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    async fn waited(kind: io::ErrorKind) -> Duration {
        let started = Instant::now();
        backed_off(io::Error::from(kind)).await;
        started.elapsed()
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_gone_before_its_accept_is_retried_at_once() {
        assert_eq!(
            waited(io::ErrorKind::ConnectionAborted).await,
            Duration::ZERO
        );
        assert_eq!(waited(io::ErrorKind::ConnectionReset).await, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn any_other_accept_error_waits_a_second() {
        let emfile = io::Error::from_raw_os_error(24).kind();
        assert_eq!(waited(emfile).await, Duration::from_secs(1));
    }
}
