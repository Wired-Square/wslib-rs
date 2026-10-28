//! A cap on how many connections a listener holds at once, and the deadline on
//! a request head; descriptors are process-wide, so every listener needs both.
//!
//! **The permit is acquired before `accept`**, so connections past the cap wait
//! in the kernel's backlog at no descriptor's cost, and **rides in [`Permitted`]
//! to the end of the connection**, keep-alive included. An axum-server `Accept`
//! acceptor runs after `accept`, so taking the permit there is too late.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use axum::serve::Listener;
use axum_server::accept::Accept;
use axum_server::{AddrListener, Address, Handle};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::{Builder, Http1Builder};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::Sleep;
use tokio_util::sync::CancellationToken;

/// Hold a connection's http/1.1 request head, and the wait for its next one, to
/// `head`. **A hyper timeout without a timer panics the connection task**, so
/// this installs both.
pub fn head_within(
    builder: &mut Builder<TokioExecutor>,
    head: Duration,
) -> Http1Builder<'_, TokioExecutor> {
    let mut http1 = builder.http1();
    http1.timer(TokioTimer::new()).header_read_timeout(head);
    http1
}

/// Serve until `stop`, then give what is open `grace` to end and close what
/// has not. `handle` must be the one `serving`'s server carries.
pub async fn until_stopped<A: Address>(
    serving: impl Future<Output = io::Result<()>>,
    handle: Handle<A>,
    stop: CancellationToken,
    grace: Duration,
) -> io::Result<()> {
    tokio::pin!(serving);
    tokio::select! {
        served = &mut serving => return served,
        () = stop.cancelled() => {}
    }
    let stopping = tokio::time::Instant::now();
    handle.graceful_shutdown(Some(grace));
    let served = serving.await;
    // The server reports no count of what it closed, only the time taken.
    if stopping.elapsed() >= grace {
        tracing::warn!(?grace, "closed connections still open at the grace period");
    }
    served
}

/// An address `L` reports, the peer's or its own, carrying the permits the
/// listener accepts against.
pub struct Bounded<L: Listener> {
    pub address: L::Addr,
    permits: Arc<Semaphore>,
}

impl<L: Listener> Clone for Bounded<L>
where
    L::Addr: Clone,
{
    fn clone(&self) -> Self {
        Self {
            address: self.address.clone(),
            permits: Arc::clone(&self.permits),
        }
    }
}

impl<L: Listener> Address for Bounded<L>
where
    L::Addr: Clone + Sync,
{
    type Stream = Permitted<L::Io>;
    type Listener = BoundedListener<L>;
}

/// The peer's address, as `ConnectInfo<SocketAddr>` hands it to a handler.
impl axum::extract::connect_info::Connected<Bounded<TcpListener>> for SocketAddr {
    fn connect_info(peer: Bounded<TcpListener>) -> Self {
        peer.address
    }
}

/// `L`, accepting only while one of its permits is free. Served through
/// `axum_server::Server::from_listener`: it is bound before it is bounded.
pub struct BoundedListener<L: Listener> {
    listener: Mutex<L>,
    local: Option<L::Addr>,
    permits: Arc<Semaphore>,
}

impl<L: Listener> BoundedListener<L>
where
    L::Addr: Clone,
{
    pub fn new(listener: L, connections: usize) -> Self {
        Self {
            local: listener.local_addr().ok(),
            listener: Mutex::new(listener),
            permits: Arc::new(Semaphore::new(connections)),
        }
    }

    pub fn local_addr(&self) -> io::Result<L::Addr> {
        self.local.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "this listener has no address")
        })
    }

    fn at(&self, address: L::Addr) -> Bounded<L> {
        Bounded {
            address,
            permits: Arc::clone(&self.permits),
        }
    }
}

impl<L: Listener> AddrListener<Permitted<L::Io>, Bounded<L>> for BoundedListener<L>
where
    L::Addr: Clone + Sync,
{
    async fn bind_to(_: Bounded<L>) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a bounded listener is made from one already bound",
        ))
    }

    async fn accept_stream(&self) -> io::Result<(Permitted<L::Io>, Bounded<L>)> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (stream, peer) = self.listener.lock().await.accept().await;
        Ok((Permitted { stream, permit }, self.at(peer)))
    }

    fn get_local_addr(&self) -> io::Result<Bounded<L>> {
        self.local_addr().map(|address| self.at(address))
    }
}

/// Bounds hyper's sniff for the h2 preface to `head` and refuses the preface,
/// for http/1.1 with upgrades.
#[derive(Clone)]
pub struct Http1Only {
    pub head: Duration,
}

impl<I, S> Accept<I, S> for Http1Only {
    type Stream = Sniffed<I>;
    type Service = S;
    type Future = std::future::Ready<io::Result<(Sniffed<I>, S)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        std::future::ready(Ok((Sniffed::new(stream, self.head), service)))
    }
}

/// hyper's own, copied: a hyper-util bump that changes the sniff changes this.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub struct Sniffed<S> {
    stream: S,
    sniff: Option<Sniff>,
}

struct Sniff {
    matched: usize,
    deadline: Pin<Box<Sleep>>,
}

impl<S> Sniffed<S> {
    fn new(stream: S, head: Duration) -> Self {
        Self {
            stream,
            sniff: Some(Sniff {
                matched: 0,
                deadline: Box::pin(tokio::time::sleep(head)),
            }),
        }
    }
}

/// Whether hyper could now tell the protocols apart: a divergence, the whole
/// preface, or an end of stream.
fn decided(matched: &mut usize, read: &[u8]) -> bool {
    let same = read
        .iter()
        .zip(&PREFACE[*matched..])
        .take_while(|(sent, expected)| sent == expected)
        .count();
    *matched += same;
    read.is_empty() || same < read.len() || *matched == PREFACE.len()
}

impl<S: AsyncRead + Unpin> AsyncRead for Sniffed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(sniff) = &mut this.sniff
            && sniff.deadline.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the peer did not begin a request",
            )));
        }
        let from = buf.filled().len();
        ready!(Pin::new(&mut this.stream).poll_read(cx, buf))?;
        if let Some(sniff) = this
            .sniff
            .take_if(|sniff| decided(&mut sniff.matched, &buf.filled()[from..]))
            && sniff.matched == PREFACE.len()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "h2 is not served here",
            )));
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Sniffed<S> {
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

/// A stream that gives its permit back when the connection ends, and not before.
pub struct Permitted<S> {
    stream: S,
    #[expect(dead_code, reason = "held for the connection's life; dropped with it")]
    permit: OwnedSemaphorePermit,
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
    use std::net::Ipv4Addr;
    use tokio::net::TcpStream;

    async fn holding_one() -> BoundedListener<TcpListener> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        BoundedListener::new(tcp, 1)
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("a local address");
        let (peer, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (peer.expect("connect"), accepted.expect("accept").0)
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_says_nothing_fails_at_its_deadline() {
        use tokio::io::AsyncReadExt;

        let (_peer, server) = pair().await;
        let mut sniffed = Sniffed::new(server, Duration::from_millis(100));

        let failed = sniffed
            .read(&mut [0u8; 1])
            .await
            .expect_err("the deadline ends it");
        assert_eq!(failed.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_settled_stream_drops_its_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut peer, server) = pair().await;
        let mut sniffed = Sniffed::new(server, Duration::from_secs(30));

        peer.write_all(b"GET").await.expect("a request line");
        sniffed
            .read_exact(&mut [0u8; 3])
            .await
            .expect("the bytes the peer sent");

        assert!(sniffed.sniff.is_none());
    }

    #[test]
    fn a_request_line_settles_it_on_its_first_byte() {
        assert!(decided(&mut 0, b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn a_preface_arriving_in_pieces_is_not_settled_until_the_last_one() {
        let mut matched = 0;
        assert!(!decided(&mut matched, b"PRI * HTTP/2.0"));
        assert!(!decided(&mut matched, b"\r\n\r\nSM\r\n"));
        assert!(decided(&mut matched, b"\r\n"));
        assert_eq!(matched, PREFACE.len());
    }

    #[test]
    fn a_prefix_of_the_preface_and_then_something_else_is_settled() {
        let mut matched = 0;
        assert!(!decided(&mut matched, b"PRI"));
        assert!(decided(&mut matched, b" / HTTP/1.1\r\n"));
        assert!(matched < PREFACE.len());
    }

    #[test]
    fn a_read_longer_than_what_is_left_of_the_preface_settles_it() {
        assert!(decided(&mut (PREFACE.len() - 2), b"\r\nGET / HTTP/1.1\r\n"));
    }

    #[test]
    fn the_end_of_the_stream_settles_it() {
        assert!(decided(&mut 0, b""));
    }

    #[tokio::test]
    async fn a_connection_past_the_cap_is_not_accepted_until_one_ends() {
        let listener = holding_one().await;
        let local = listener.local_addr().expect("a local address");

        let _first = TcpStream::connect(local).await.expect("connect");
        let (served, _) = listener.accept_stream().await.expect("accept");

        // The kernel's backlog takes this connect; no descriptor may be spent on it.
        let _second = TcpStream::connect(local).await.expect("connect");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept_stream())
                .await
                .is_err(),
            "a connection past the cap must wait in the backlog"
        );

        drop(served);
        tokio::time::timeout(Duration::from_secs(5), listener.accept_stream())
            .await
            .expect("the permit comes back with the connection")
            .expect("accept");
    }

    #[tokio::test]
    async fn a_stalled_request_holds_the_stop_for_the_grace_and_is_closed_saying_so() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const BRIEF: Duration = Duration::from_millis(200);

        let logs = crate::logs(&[]).ring().clone();
        let _logging = tracing::subscriber::set_default(logs.subscriber());
        let listener = holding_one().await;
        let local = listener.local_addr().expect("a local address");
        let handle = Handle::<Bounded<TcpListener>>::new();
        let server = axum_server::Server::from_listener(listener).handle(handle.clone());
        let stalls =
            axum::Router::new().route("/stalled", axum::routing::get(std::future::pending::<()>));
        let stop = CancellationToken::new();
        let serving = tokio::spawn(until_stopped(
            server.serve(stalls.into_make_service()),
            handle,
            stop.clone(),
            BRIEF,
        ));

        let mut peer = TcpStream::connect(local).await.expect("connect");
        peer.write_all(b"GET /stalled HTTP/1.1\r\nHost: box\r\n\r\n")
            .await
            .expect("writes");
        tokio::time::sleep(BRIEF).await;

        let stopped = tokio::time::Instant::now();
        stop.cancel();
        tokio::time::timeout(BRIEF + Duration::from_secs(5), serving)
            .await
            .expect("stops at the grace period")
            .expect("did not panic")
            .expect("served");
        assert!(stopped.elapsed() >= BRIEF, "{:?}", stopped.elapsed());
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut Vec::new()))
            .await
            .expect("the stalled connection is closed")
            .expect("reads");
        let records = logs.snapshot().records;
        assert!(
            records
                .iter()
                .any(|r| r.message == "closed connections still open at the grace period"),
            "{records:?}"
        );
    }
}
