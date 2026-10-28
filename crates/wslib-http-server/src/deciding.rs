//! hyper tells http/1.1 from h2 by reading up to the h2 preface, and times
//! that read against nothing, so a peer that connects and says nothing would
//! hold its slot under the cap for ever. This bounds the wait, ending it where
//! hyper's own sniff would decide rather than at the first byte. hyper serves
//! upgrades only through that sniff, so an http/1.1-only listener refuses the
//! preface here instead.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use axum_server::accept::Accept;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// hyper's own, copied: a hyper-util bump that changes the sniff changes this.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// An acceptor whose connections must reach a protocol decision in `within`.
#[derive(Clone)]
pub(crate) struct Deciding<A> {
    inner: A,
    within: Duration,
    h2: bool,
}

impl<A> Deciding<A> {
    pub(crate) fn within(inner: A, within: Duration) -> Self {
        Self {
            inner,
            within,
            h2: true,
        }
    }

    #[cfg(unix)]
    pub(crate) fn http1_within(inner: A, within: Duration) -> Self {
        Self {
            inner,
            within,
            h2: false,
        }
    }
}

impl<I, S, A> Accept<I, S> for Deciding<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: 'static,
    A::Service: 'static,
{
    type Stream = Undecided<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepting = self.inner.accept(stream, service);
        let (within, h2) = (self.within, self.h2);
        Box::pin(async move {
            let (stream, service) = accepting.await?;
            Ok((Undecided::new(stream, within, h2), service))
        })
    }
}

/// A stream that fails if the peer has not said which protocol it is speaking.
pub(crate) struct Undecided<S> {
    stream: S,
    sniff: Option<Sniff>,
}

struct Sniff {
    matched: usize,
    deadline: Pin<Box<Sleep>>,
    h2: bool,
}

impl<S> Undecided<S> {
    fn new(stream: S, within: Duration, h2: bool) -> Self {
        Self {
            stream,
            sniff: Some(Sniff {
                matched: 0,
                deadline: Box::pin(tokio::time::sleep(within)),
                h2,
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

impl<S: AsyncRead + Unpin> AsyncRead for Undecided<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let overdue = this
            .sniff
            .as_mut()
            .is_some_and(|sniff| sniff.deadline.as_mut().poll(cx).is_ready());
        if overdue {
            tracing::debug!("dropped a connection that never said what it was");
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
            && !sniff.h2
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

impl<S: AsyncWrite + Unpin> AsyncWrite for Undecided<S> {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

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
        let (_peer, server) = pair().await;
        let mut undecided = Undecided::new(server, Duration::from_millis(100), true);

        let failed = undecided
            .read(&mut [0u8; 1])
            .await
            .expect_err("the deadline ends it");
        assert_eq!(failed.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_settled_stream_drops_its_deadline() {
        let (mut peer, server) = pair().await;
        let mut undecided = Undecided::new(server, Duration::from_secs(30), true);

        peer.write_all(b"GET").await.expect("a request line");
        undecided
            .read_exact(&mut [0u8; 3])
            .await
            .expect("the bytes the peer sent");

        assert!(undecided.sniff.is_none());
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
    }

    #[test]
    fn a_prefix_of_the_preface_and_then_something_else_is_settled() {
        let mut matched = 0;
        assert!(!decided(&mut matched, b"PRI"));
        assert!(decided(&mut matched, b" / HTTP/1.1\r\n"));
    }

    #[test]
    fn a_read_longer_than_what_is_left_of_the_preface_settles_it() {
        assert!(decided(&mut (PREFACE.len() - 2), b"\r\nGET / HTTP/1.1\r\n"));
    }

    #[test]
    fn the_end_of_the_stream_settles_it() {
        assert!(decided(&mut 0, b""));
    }
}
