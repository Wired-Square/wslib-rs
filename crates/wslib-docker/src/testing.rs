//! A fake engine for tests: an HTTP/1.1 server on a Unix socket that records
//! each request and answers it by its method and path.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tokio::sync::Notify;

use crate::Docker;

/// A request as the fake took it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub method: String,
    /// The path and query, with the API version: `/v1.44/containers/x/json`.
    pub uri: String,
    /// Empty when the request had none.
    pub content_type: String,
    pub body: Vec<u8>,
}

/// A fake engine serving a socket path, until the runtime it was started on stops.
#[derive(Debug, Clone)]
pub struct FakeEngine {
    socket: PathBuf,
    seen: Arc<Mutex<Vec<Seen>>>,
    gate: Arc<Notify>,
}

impl FakeEngine {
    /// Serves `socket`, answering each request with `answer(method, uri)`: a status and a body.
    pub fn serve<A>(socket: impl Into<PathBuf>, answer: A) -> Self
    where
        A: Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        Self::start(socket.into(), answer, None)
    }

    /// [`serve`](Self::serve), holding each request whose URI starts with `held`
    /// after recording it, until [`release`](Self::release) lets one through.
    pub fn holding<A>(socket: impl Into<PathBuf>, answer: A, held: &'static str) -> Self
    where
        A: Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        Self::start(socket.into(), answer, Some(held))
    }

    /// A client for this engine.
    pub fn docker(&self) -> Docker {
        Docker::default().with_socket(&self.socket)
    }

    /// Every request so far, oldest first.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Lets one held request be answered, now or when it arrives.
    pub fn release(&self) {
        self.gate.notify_one();
    }

    fn start<A>(socket: PathBuf, answer: A, held: Option<&'static str>) -> Self
    where
        A: Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = UnixListener::bind(&socket).expect("the fake engine binds its socket");
        let engine = Self {
            socket,
            seen: Arc::default(),
            gate: Arc::default(),
        };
        let answer = Arc::new(answer);
        let serving = engine.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (engine, answer) = (serving.clone(), answer.clone());
                let service = service_fn(move |request: Request<Incoming>| {
                    let (engine, answer) = (engine.clone(), answer.clone());
                    async move {
                        let uri = request.uri().to_string();
                        let method = request.method().to_string();
                        engine.record(request).await;
                        if held.is_some_and(|held| uri.starts_with(held)) {
                            engine.gate.notified().await;
                        }
                        let (status, reply) = answer(&method, &uri);
                        let response = Response::builder()
                            .status(StatusCode::from_u16(status).expect("a valid status"))
                            .body(Full::new(Bytes::from(reply)))
                            .expect("a response of valid parts");
                        Ok::<_, Infallible>(response)
                    }
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service),
                );
            }
        });
        engine
    }

    async fn record(&self, request: Request<Incoming>) {
        let seen = Seen {
            method: request.method().to_string(),
            uri: request.uri().to_string(),
            content_type: request
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|kind| kind.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            body: match request.into_body().collect().await {
                Ok(body) => body.to_bytes().to_vec(),
                Err(_) => Vec::new(),
            },
        };
        self.seen.lock().unwrap().push(seen);
    }
}
