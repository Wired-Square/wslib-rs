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
    /// speaks, and send each http/1.1 request head.
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
    type Stream = Permitted;
    type Listener = Listener;
}

impl axum::extract::connect_info::Connected<Peer> for SocketAddr {
    fn connect_info(peer: Peer) -> Self {
        peer.0
    }
}

// The permit is taken before `accept`, so at the cap the connections waiting
// cost the kernel's backlog and not this process's descriptors.
impl AddrListener<Permitted, Peer> for Listener {
    async fn bind_to(_: Peer) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a bounded listener is made from one already bound",
        ))
    }

    async fn accept_stream(&self) -> io::Result<(Permitted, Peer)> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (stream, peer) = self.tcp.accept().await?;
        Ok((Permitted { stream, permit }, Peer(peer)))
    }

    fn get_local_addr(&self) -> io::Result<Peer> {
        Ok(Peer(self.local))
    }
}

/// A connection that gives its permit back when it ends.
pub struct Permitted {
    stream: TcpStream,
    #[expect(dead_code, reason = "held for the connection's life; dropped with it")]
    permit: OwnedSemaphorePermit,
}

impl AsyncRead for Permitted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Permitted {
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
