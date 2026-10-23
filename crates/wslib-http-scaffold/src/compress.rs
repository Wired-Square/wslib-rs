//! A cap on how many response encoders the process holds at once.
//!
//! A gzip encoder is ~235 KB that lives as long as the body it encodes, so the
//! connection and stream caps bound memory only as a product; this bounds the
//! encoders themselves.
//!
//! **A request that cannot have an encoder is served uncompressed, not delayed.**
//! Waiting for a permit would queue every request behind whichever bodies hold
//! one — a slow download holds its encoder until it drains — including requests
//! that turn out not to need one at all, since a permit is taken before the
//! response says whether it was encoded. Asking for no encoding instead degrades
//! a process under pressure to plaintext, which is slower on the wire and costs
//! it nothing it does not have. A cache cannot tell that apart from a client
//! that wanted no encoding, so a bundle file with no `.gz` fetched in that
//! moment stays plain for the life of its entry.
//!
//! The cap must sit **outside** `CompressionLayer`: it decides by editing the
//! request before that layer reads it, and it holds its permit against the body
//! that layer produced.
//!
//! **A body stored compressed is sent past the cap and holds no permit.** `Spa`
//! restores `Accept-Encoding` before it chooses a `.gz` and marks the response;
//! `CompressionLayer` has chosen its encoding before a handler runs, so the
//! restored header reaches only the handler.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::response::Response;
use http_body::{Frame, SizeHint};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::{BoxError, Layer, Service};

/// A layer holding at most `n` response encoders at once, applied outside
/// `CompressionLayer`; a request past the cap is served uncompressed.
#[derive(Clone, Debug)]
pub struct EncoderCap {
    permits: Arc<Semaphore>,
}

impl EncoderCap {
    /// The cap [`standard_layers`](crate::standard_layers) holds, about 15 MB of encoders.
    pub const DEFAULT: usize = 64;

    pub fn new(encoders: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(encoders)),
        }
    }
}

impl Default for EncoderCap {
    fn default() -> Self {
        Self::new(Self::DEFAULT)
    }
}

impl<S> Layer<S> for EncoderCap {
    type Service = Capped<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Capped {
            inner,
            permits: Arc::clone(&self.permits),
        }
    }
}

/// The service [`EncoderCap`] wraps around another.
#[derive(Clone, Debug)]
pub struct Capped<S> {
    inner: S,
    permits: Arc<Semaphore>,
}

impl<S, B> Service<Request> for Capped<S>
where
    S: Service<Request, Response = axum::http::Response<B>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok();
        if permit.is_none() {
            let headers = request.headers_mut();
            let declined = headers
                .get_all(header::ACCEPT_ENCODING)
                .iter()
                .cloned()
                .collect();
            headers.remove(header::ACCEPT_ENCODING);
            request.extensions_mut().insert(Declined(declined));
        }
        let calling = self.inner.call(request);
        Box::pin(async move {
            let response = calling.await?.map(Body::new);
            let encoded = response.headers().contains_key(header::CONTENT_ENCODING)
                && response.extensions().get::<Stored>().is_none();
            Ok(match permit {
                Some(permit) if encoded => response.map(|inner| Body::new(Held { inner, permit })),
                _ => response,
            })
        })
    }
}

/// The `Accept-Encoding` set aside from a request that found no encoder free.
#[derive(Clone)]
struct Declined(Vec<HeaderValue>);

/// Puts back the `Accept-Encoding` the cap set aside, for a handler about to
/// choose a stored copy, which needs no encoder.
pub(crate) fn restore_accept_encoding(request: &mut Request) {
    if let Some(Declined(values)) = request.extensions_mut().remove() {
        for value in values {
            request.headers_mut().append(header::ACCEPT_ENCODING, value);
        }
    }
}

/// Marks a response whose `Content-Encoding` was stored with its bytes.
#[derive(Clone)]
struct Stored;

pub(crate) fn mark_stored(response: &mut Response) {
    if response.headers().contains_key(header::CONTENT_ENCODING) {
        response.extensions_mut().insert(Stored);
    }
}

/// A body that gives its permit back when it is dropped.
struct Held {
    inner: Body,
    #[expect(dead_code, reason = "held for the body's life; dropped with it")]
    permit: OwnedSemaphorePermit,
}

impl http_body::Body for Held {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::routing::get;
    use tower::ServiceExt;
    use tower_http::compression::CompressionLayer;

    use super::*;

    /// A body long enough to be worth encoding, behind a cap of `encoders`.
    fn app(encoders: usize) -> Router {
        Router::new()
            .route("/", get(|| async { "x".repeat(1024) }))
            .layer(CompressionLayer::new())
            .layer(EncoderCap::new(encoders))
    }

    fn asking() -> Request {
        Request::get("/")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_body_past_the_cap_is_served_uncompressed_rather_than_delayed() {
        let app = app(1);

        let held = app.clone().oneshot(asking()).await.unwrap();
        assert_eq!(held.headers()[header::CONTENT_ENCODING], "gzip");

        // `held`'s body is still alive, so its permit is still out.
        let past = app.clone().oneshot(asking()).await.unwrap();
        assert!(past.headers().get(header::CONTENT_ENCODING).is_none());

        drop(held);
        let after = app.oneshot(asking()).await.unwrap();
        assert_eq!(after.headers()[header::CONTENT_ENCODING], "gzip");
    }

    #[tokio::test]
    async fn a_response_that_was_never_encoded_holds_no_permit() {
        let app = app(1);

        let plain = Request::get("/").body(Body::empty()).unwrap();
        let feed = app.clone().oneshot(plain).await.unwrap();
        assert!(feed.headers().get(header::CONTENT_ENCODING).is_none());

        let gz = app.oneshot(asking()).await.unwrap();
        assert_eq!(gz.headers()[header::CONTENT_ENCODING], "gzip");
    }
}
