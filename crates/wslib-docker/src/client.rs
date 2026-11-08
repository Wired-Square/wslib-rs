use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

use crate::ImageReference;

/// A request or answer body.
pub type Body = BoxBody<Bytes, io::Error>;

/// The Docker Engine at a socket path.
#[derive(Debug, Clone)]
pub struct Docker {
    socket: PathBuf,
    call_timeout: Duration,
    transfer_timeout: Duration,
}

impl Default for Docker {
    fn default() -> Self {
        Self {
            socket: Self::SOCKET.into(),
            call_timeout: Duration::from_secs(60),
            transfer_timeout: Duration::from_secs(600),
        }
    }
}

impl Docker {
    /// Where the engine listens on Linux.
    #[cfg(unix)]
    pub const SOCKET: &str = "/var/run/docker.sock";
    /// Where the engine listens on Windows.
    #[cfg(windows)]
    pub const SOCKET: &str = r"\\.\pipe\docker_engine";

    /// The API version every path is under, so the shapes asked for stay put
    /// across engine updates; Docker 29 accepts nothing older.
    pub const API_VERSION: &str = "1.44";

    /// The client for the engine at `socket`.
    pub fn with_socket(mut self, socket: impl Into<PathBuf>) -> Self {
        self.socket = socket.into();
        self
    }

    /// How long a call other than a load or a pull waits; 60 s by default.
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// How long a load or a pull waits for its whole progress stream; 10 min by default.
    pub fn with_transfer_timeout(mut self, timeout: Duration) -> Self {
        self.transfer_timeout = timeout;
        self
    }

    pub async fn ping(&self) -> Result<(), DockerError> {
        self.expect(Method::GET, "/_ping".into(), None)
            .await
            .map(drop)
    }

    /// The image's inspection, or `None` where the engine has no such image.
    pub async fn image(&self, reference: &str) -> Result<Option<Value>, DockerError> {
        self.inspect(format!("/images/{}/json", named(reference)?))
            .await
    }

    /// The container's inspection, or `None` where the engine has no such container.
    pub async fn container(&self, name: &str) -> Result<Option<Value>, DockerError> {
        self.inspect(format!("/containers/{}/json", named(name)?))
            .await
    }

    /// The network's inspection, or `None` where the engine has no such network.
    pub async fn network(&self, name: &str) -> Result<Option<Value>, DockerError> {
        self.inspect(format!("/networks/{}", named(name)?)).await
    }

    /// Creates the network `spec` describes, as the engine's `NetworkCreateRequest`.
    pub async fn create_network(&self, spec: &Value) -> Result<(), DockerError> {
        self.expect(Method::POST, "/networks/create".into(), Some(spec))
            .await
            .map(drop)
    }

    /// Creates the container `name` from `spec`, as the engine's `ContainerCreateRequest`.
    pub async fn create(&self, name: &str, spec: &Value) -> Result<(), DockerError> {
        let path = format!("/containers/create?name={}", named(name)?);
        self.expect(Method::POST, path, Some(spec)).await.map(drop)
    }

    /// Succeeds too when the container is already running.
    pub async fn start(&self, name: &str) -> Result<(), DockerError> {
        let path = format!("/containers/{}/start", named(name)?);
        self.expect(Method::POST, path, None).await.map(drop)
    }

    /// Succeeds too when the container is already stopped.
    pub async fn stop(&self, name: &str) -> Result<(), DockerError> {
        let path = format!("/containers/{}/stop", named(name)?);
        self.expect(Method::POST, path, None).await.map(drop)
    }

    /// Stops the container and keeps the engine from starting it again at boot.
    pub async fn stop_for_good(&self, name: &str) -> Result<(), DockerError> {
        let path = format!("/containers/{}/update", named(name)?);
        let never = json!({"RestartPolicy": {"Name": "no"}});
        self.expect(Method::POST, path, Some(&never)).await?;
        self.stop(name).await
    }

    /// Removes the container, running or not.
    pub async fn remove(&self, name: &str) -> Result<(), DockerError> {
        let path = format!("/containers/{}?force=true", named(name)?);
        self.expect(Method::DELETE, path, None).await.map(drop)
    }

    pub async fn remove_image(&self, reference: &str) -> Result<(), DockerError> {
        let path = format!("/images/{}", named(reference)?);
        self.expect(Method::DELETE, path, None).await.map(drop)
    }

    /// Loads a `docker save` archive, streamed from `archive`, and gives the
    /// references it loaded: `repository:tag` for a tagged image, `sha256:…` for an untagged one.
    pub async fn load(
        &self,
        archive: impl AsyncRead + Send + Sync + 'static,
    ) -> Result<Vec<String>, DockerError> {
        let body = StreamBody::new(ReaderStream::new(archive).map_ok(Frame::data)).boxed();
        let path = "/images/load?quiet=1".to_string();
        let tar = Some(("application/x-tar", body));
        let (status, body) = self
            .call(Method::POST, path, tar, self.transfer_timeout)
            .await?;
        loaded(&succeeded(status, body)?)
    }

    /// Pulls the one image the reference names, never all its tags, and gives the reference to inspect it by.
    pub async fn pull(&self, reference: &ImageReference) -> Result<String, DockerError> {
        let reference = reference.to_string();
        let path = format!("/images/create?fromImage={reference}");
        let (status, body) = self
            .call(Method::POST, path, None, self.transfer_timeout)
            .await?;
        progress(&succeeded(status, body)?)?;
        Ok(reference)
    }

    /// The events from `since` to `until` that pass `filters`; the engine answers once `until` comes, so the call
    /// waits until then and the call timeout after.
    pub async fn events(
        &self,
        since: SystemTime,
        until: SystemTime,
        filters: &EventFilters,
    ) -> Result<Vec<Event>, DockerError> {
        let path = format!(
            "/events?since={}&until={}&filters={}",
            timestamp(since),
            timestamp(until),
            filters.encoded()
        );
        let still_to_come = until.duration_since(SystemTime::now()).unwrap_or_default();
        let (status, body) = self
            .call(Method::GET, path, None, still_to_come + self.call_timeout)
            .await?;
        let body = succeeded(status, body)?;
        serde_json::Deserializer::from_slice(&body)
            .into_iter::<Value>()
            .map(|event| Ok(Event::decoded(event?)))
            .collect()
    }

    async fn call(
        &self,
        method: Method,
        path: String,
        body: Option<(&str, Body)>,
        within: Duration,
    ) -> Result<(StatusCode, Bytes), DockerError> {
        let request = Request::builder()
            .method(method)
            .uri(format!("/v{}{path}", Self::API_VERSION))
            .header(HOST, "docker");
        let request = match body {
            Some((kind, body)) => request.header(CONTENT_TYPE, kind).body(body),
            None => request.body(empty()),
        };
        exchange(
            &self.socket,
            request.expect("a request of valid parts"),
            within,
        )
        .await
    }

    async fn expect(
        &self,
        method: Method,
        path: String,
        json: Option<&Value>,
    ) -> Result<Bytes, DockerError> {
        let body = json.map(|json| ("application/json", full(json.to_string())));
        let (status, body) = self.call(method, path, body, self.call_timeout).await?;
        succeeded(status, body)
    }

    async fn inspect(&self, path: String) -> Result<Option<Value>, DockerError> {
        match self.expect(Method::GET, path, None).await {
            Ok(body) => Ok(Some(serde_json::from_slice(&body)?)),
            Err(DockerError::Refused { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Which events [`Docker::events`] gives: one of each key's values, for every key given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilters(BTreeMap<&'static str, Vec<String>>);

impl EventFilters {
    /// Of an object type, such as `container`, `image` or `network`.
    pub fn kind(self, kind: impl Into<String>) -> Self {
        self.with("type", kind)
    }

    /// Of an action, such as `start` or `die`.
    pub fn event(self, action: impl Into<String>) -> Self {
        self.with("event", action)
    }

    /// Of an object with a label: `key` for any value, `key=value` for one.
    pub fn label(self, label: impl Into<String>) -> Self {
        self.with("label", label)
    }

    /// Of a container, by name or ID.
    pub fn container(self, container: impl Into<String>) -> Self {
        self.with("container", container)
    }

    fn with(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.0.entry(key).or_default().push(value.into());
        self
    }

    fn encoded(&self) -> String {
        let json = serde_json::to_string(&self.0).expect("a map of strings serialises");
        json.bytes()
            .map(|b| match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
}

/// One of the engine's events; a field the engine left out is empty or 0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Event {
    /// The object type: `container`, `image`, `network` and so on.
    pub kind: String,
    pub action: String,
    /// Unix seconds.
    pub time: i64,
    /// Unix nanoseconds.
    pub time_nano: i64,
    pub actor: EventActor,
}

/// The object an event happened to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EventActor {
    pub id: String,
    /// For a container, its labels, `name` and `image`, and for a `die` its `exitCode`.
    pub attributes: BTreeMap<String, String>,
}

impl Event {
    fn decoded(event: Value) -> Self {
        let text = |at: &str| {
            event
                .pointer(at)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let number = |at: &str| {
            event
                .pointer(at)
                .and_then(Value::as_i64)
                .unwrap_or_default()
        };
        let attributes = event
            .pointer("/Actor/Attributes")
            .and_then(Value::as_object);
        Self {
            kind: text("/Type"),
            action: text("/Action"),
            time: number("/time"),
            time_nano: number("/timeNano"),
            actor: EventActor {
                id: text("/Actor/ID"),
                attributes: attributes
                    .into_iter()
                    .flatten()
                    .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_string())))
                    .collect(),
            },
        }
    }
}

/// Why a call to the engine failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum DockerError {
    /// Nothing to connect to at the socket, or no permission to.
    Unreachable(io::Error),
    Http(hyper::Error),
    Timeout,
    /// The engine said no; `status` is 200 for an error inside a load's or a pull's progress.
    Refused {
        status: u16,
        message: String,
    },
    Json(serde_json::Error),
    /// A name or reference with a character no engine object's name has, which would change the request's path.
    Name(String),
}

impl fmt::Display for DockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(e) => write!(f, "docker is unreachable: {e}"),
            Self::Http(e) => write!(f, "docker's HTTP failed: {e}"),
            Self::Timeout => f.write_str("docker took too long"),
            Self::Refused { status, message } => write!(f, "docker answered {status}: {message}"),
            Self::Json(e) => write!(f, "docker's answer is not JSON: {e}"),
            Self::Name(name) => write!(f, "{name:?} is not a docker name"),
        }
    }
}

impl std::error::Error for DockerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreachable(e) => Some(e),
            Self::Http(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Timeout | Self::Refused { .. } | Self::Name(_) => None,
        }
    }
}

impl From<io::Error> for DockerError {
    fn from(e: io::Error) -> Self {
        Self::Unreachable(e)
    }
}

impl From<hyper::Error> for DockerError {
    fn from(e: hyper::Error) -> Self {
        Self::Http(e)
    }
}

impl From<serde_json::Error> for DockerError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub fn empty() -> Body {
    full(Bytes::new())
}

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// One HTTP/1.1 request to whatever serves `socket`, the engine or not, and its
/// whole answer, within `within`.
pub async fn exchange(
    socket: &Path,
    request: Request<Body>,
    within: Duration,
) -> Result<(StatusCode, Bytes), DockerError> {
    tokio::time::timeout(within, async {
        let stream = connect(socket).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        tokio::spawn(connection);
        let response = sender.send_request(request).await?;
        let status = response.status();
        Ok((status, response.into_body().collect().await?.to_bytes()))
    })
    .await
    .map_err(|_| DockerError::Timeout)?
}

#[cfg(unix)]
async fn connect(socket: &Path) -> io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(socket).await
}

#[cfg(windows)]
async fn connect(pipe: &Path) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(pipe)
}

/// Container, network and image names, image references and IDs are all of
/// these characters; a `.` or `..` segment would climb out of the path.
fn named(name: &str) -> Result<&str, DockerError> {
    let allowed = |b: u8| b.is_ascii_alphanumeric() || b"_.-:/@".contains(&b);
    let named = !name.is_empty()
        && name.bytes().all(allowed)
        && name
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."));
    named
        .then_some(name)
        .ok_or_else(|| DockerError::Name(name.to_string()))
}

fn timestamp(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:09}", since.as_secs(), since.subsec_nanos())
}

/// 304 is the engine's "already so", for a start or a stop.
fn succeeded(status: StatusCode, body: Bytes) -> Result<Bytes, DockerError> {
    if status.is_success() || status == StatusCode::NOT_MODIFIED {
        return Ok(body);
    }
    let message = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|e| Some(e.get("message")?.as_str()?.to_string()))
        .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
    Err(DockerError::Refused {
        status: status.as_u16(),
        message,
    })
}

/// The lines of a load's or a pull's progress stream; an error in it fails the whole.
fn progress(stream: &[u8]) -> Result<Vec<Value>, DockerError> {
    let mut lines = Vec::new();
    for line in serde_json::Deserializer::from_slice(stream).into_iter::<Value>() {
        let line = line?;
        if let Some(message) = line.get("error").and_then(Value::as_str) {
            return Err(DockerError::Refused {
                status: 200,
                message: message.to_string(),
            });
        }
        lines.push(line);
    }
    Ok(lines)
}

fn loaded(stream: &[u8]) -> Result<Vec<String>, DockerError> {
    let mut references = Vec::new();
    for line in progress(stream)? {
        let text = line.get("stream").and_then(Value::as_str).unwrap_or("");
        references.extend(text.lines().filter_map(|l| {
            let reference = l
                .strip_prefix("Loaded image: ")
                .or_else(|| l.strip_prefix("Loaded image ID: "))?;
            Some(reference.trim().to_string())
        }));
    }
    Ok(references)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_load_names_tagged_and_untagged_images() {
        let stream = br#"{"stream":"Loaded image: applianceos/hello-app:2\n"}
{"stream":"Loaded image ID: sha256:0123\n"}"#;
        assert_eq!(
            loaded(stream).unwrap(),
            ["applianceos/hello-app:2", "sha256:0123"]
        );
    }

    #[test]
    fn an_error_in_a_load_fails_it() {
        let stream = br#"{"errorDetail":{"message":"no space"},"error":"no space"}"#;
        assert!(matches!(
            loaded(stream),
            Err(DockerError::Refused { message, .. }) if message == "no space"
        ));
    }

    #[test]
    fn a_refusal_carries_the_engines_message_and_304_is_already_so() {
        let refused = succeeded(StatusCode::CONFLICT, Bytes::from(r#"{"message":"in use"}"#));
        assert!(matches!(
            refused,
            Err(DockerError::Refused { status: 409, message }) if message == "in use"
        ));
        let plain = succeeded(StatusCode::INTERNAL_SERVER_ERROR, Bytes::from("broken"));
        assert!(matches!(plain, Err(DockerError::Refused { message, .. }) if message == "broken"));
        assert!(succeeded(StatusCode::NOT_MODIFIED, Bytes::new()).is_ok());
    }

    #[test]
    fn a_name_cannot_change_the_path_it_lands_in() {
        for good in [
            "app-hello",
            "app_hello.1",
            "sha256:0123",
            "ghcr.io/a/b:1.0",
            "10.0.2.2:5443/tests/hello@sha256:0123",
        ] {
            assert!(named(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "x?force=true",
            "x#y",
            "a b",
            "a%2Fb",
            "../containers/x",
            "a/../b",
            "a//b",
            "/a",
            "a/",
            ".",
        ] {
            assert!(matches!(named(bad), Err(DockerError::Name(_))), "{bad:?}");
        }
    }
}
