//! A product's [`Service`] served on the installer's layout in a temporary
//! directory, one endpoint per role. Install a rustls provider first.
//!
//! On unix each endpoint's directory keeps the group it was created with; on
//! Windows each pipe is this process's user's and granted to no group. The OS
//! trust store is never read, so an unpinned dial trusts the installed
//! authorities alone.

use std::path::Path;
use std::time::Duration;

pub use wslib_appliance_core::testing::{body_json, body_text};

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::task::JoinHandle;
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;

use crate::{CancellationToken, LocalBootstrap, LocalEndpoint, LocalError, Service};

const BIND_WAIT: Duration = Duration::from_secs(5);
/// Past a bundle's key derivation, under a loaded test run.
const ANSWER_WAIT: Duration = Duration::from_secs(15);

/// The layout, before anything is served on it.
pub struct HarnessBuilder {
    _dir: TempDir,
    bootstrap: LocalBootstrap,
}

impl HarnessBuilder {
    pub fn bootstrap(&self) -> &LocalBootstrap {
        &self.bootstrap
    }

    /// Serve `service` in the background; returns once every endpoint answers,
    /// and panics if the service stops first or one does not answer in time.
    pub async fn serve(self, service: Service) -> Harness {
        let stop = CancellationToken::new();
        let store = service.chassis.store().clone();
        let serving = tokio::spawn({
            let bootstrap = self.bootstrap.clone();
            let stopped = stop.clone().cancelled_owned();
            let service = Service {
                chassis: service.chassis.without_os_store(),
            };
            async move { service.serve_local(&bootstrap, stopped).await }
        });
        let mut harness = Harness {
            store,
            stop,
            serving,
            layout: self,
        };
        let answering = async {
            for endpoint in &harness.layout.bootstrap.endpoints {
                drop(connected(&endpoint.path).await);
            }
        };
        tokio::select! {
            ended = &mut harness.serving => panic!("the service stopped before it answered: {ended:?}"),
            answered = tokio::time::timeout(BIND_WAIT, answering) => {
                answered.unwrap_or_else(|_| panic!("an endpoint did not answer within {BIND_WAIT:?}"));
            }
        }
        harness
    }
}

/// A [`Service`] serving. Dropped without [`stop`](Self::stop), it is aborted
/// and its directory removed as far as open files allow.
pub struct Harness {
    store: Store,
    stop: CancellationToken,
    serving: JoinHandle<Result<(), LocalError>>,
    /// Last, so the directory goes once the rest has dropped.
    layout: HarnessBuilder,
}

impl Harness {
    /// A new directory, laid out to pass `serve_local`'s checks.
    pub fn builder() -> HarnessBuilder {
        // A macOS socket path is at most 103 bytes, and `$TMPDIR` is long.
        let dir = tempfile::Builder::new()
            .prefix("appliance-svc")
            .tempdir()
            .expect("a directory for the harness");
        let bootstrap = laid_out(dir.path());
        HarnessBuilder {
            _dir: dir,
            bootstrap,
        }
    }

    pub fn bootstrap(&self) -> &LocalBootstrap {
        self.layout.bootstrap()
    }

    pub fn get(&self, role: Role, path: &str) -> Req<'_> {
        self.request(role, "GET", path)
    }

    pub fn request(&self, role: Role, method: &'static str, path: &str) -> Req<'_> {
        let endpoint = &self
            .bootstrap()
            .endpoints
            .iter()
            .find(|endpoint| endpoint.ceiling == role)
            .expect("an endpoint per role")
            .path;
        Req {
            endpoint,
            role,
            method,
            path: path.to_string(),
            body: None,
        }
    }

    /// Stop the service, close its store (every clone included) and remove the
    /// directory; a connection still checked out holds the store up to 5 s, and
    /// on Windows keeps the directory. Panics if `serve_local` fails or hangs.
    pub async fn stop(mut self) {
        self.stop.cancel();
        tokio::time::timeout(ANSWER_WAIT, &mut self.serving)
            .await
            .unwrap_or_else(|_| panic!("the service did not stop within {ANSWER_WAIT:?}"))
            .expect("did not panic")
            .expect("served");
        self.store.close().await;
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// One request, built up and sent over an endpoint.
pub struct Req<'a> {
    endpoint: &'a Path,
    role: Role,
    method: &'static str,
    path: String,
    body: Option<String>,
}

impl Req<'_> {
    /// Sent as `application/json`. A large body to a route that refuses early
    /// may fail to send.
    pub fn json(mut self, value: serde_json::Value) -> Self {
        self.body = Some(value.to_string());
        self
    }

    /// The response, its body read whole unless it is a feed's; panics if it is
    /// not answered in time, or a body other than a feed's is chunked.
    pub async fn send(self) -> Response {
        let (method, path, role) = (self.method, self.path.clone(), self.role);
        tokio::time::timeout(ANSWER_WAIT, async {
            let stream = connected(self.endpoint).await;
            self.exchange(stream).await
        })
        .await
        .unwrap_or_else(|_| {
            panic!("{method} {path} at {role} was not answered within {ANSWER_WAIT:?}")
        })
    }

    async fn exchange(self, mut stream: impl AsyncRead + AsyncWrite + Unpin) -> Response {
        let mut request = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
            self.method, self.path
        );
        if self.body.is_some() {
            request += "Content-Type: application/json\r\n";
        }
        let body = self.body.unwrap_or_default();
        request += &format!("Content-Length: {}\r\n\r\n{body}", body.len());
        stream.write_all(request.as_bytes()).await.expect("sent");

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("a status line");
        let status: StatusCode = line
            .split(' ')
            .nth(1)
            .and_then(|status| status.parse().ok())
            .unwrap_or_else(|| panic!("a status line: {line:?}"));
        let mut response = Response::builder().status(status);
        let (mut length, mut feed, mut chunked) = (None, false, false);
        loop {
            line.clear();
            reader.read_line(&mut line).await.expect("a header");
            let Some((name, value)) = line.trim_end().split_once(':') else {
                break;
            };
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = Some(value.parse().expect("a length")),
                "content-type" => feed = value.starts_with("text/event-stream"),
                "transfer-encoding" => {
                    chunked = value
                        .rsplit(',')
                        .next()
                        .is_some_and(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
                }
                _ => {}
            }
            response = response.header(name, value);
        }
        let bodiless = self.method == "HEAD"
            || status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED;
        let mut body = Vec::new();
        if !(bodiless || feed) {
            assert!(
                !chunked,
                "{} {} answered with a chunked body",
                self.method, self.path
            );
            match length {
                Some(length) => {
                    body.resize(length, 0);
                    reader.read_exact(&mut body).await.expect("the body");
                }
                None => {
                    reader.read_to_end(&mut body).await.expect("the body");
                }
            }
        }
        response.body(Body::from(body)).expect("a response")
    }
}

fn socket_roles() -> impl Iterator<Item = Role> {
    Role::LADDER
        .into_iter()
        .filter(|&role| Role::Admin.allows(role))
}

#[cfg(unix)]
pub(crate) fn laid_out(dir: &Path) -> LocalBootstrap {
    use std::os::unix::fs::PermissionsExt;

    let made = |name: &str, mode: u32| {
        let path = dir.join(name);
        std::fs::create_dir(&path).expect("a directory of the layout");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("the layout's mode");
        path
    };
    let state_dir = made("state", 0o700);
    let endpoints = socket_roles()
        .map(|role| {
            let run = made(role.as_str(), 0o750);
            LocalEndpoint {
                path: run.join("s.sock"),
                ceiling: role,
                group: wslib_appliance_core::testing::group_of(&run),
            }
        })
        .collect();
    LocalBootstrap {
        db: state_dir.join("service.db"),
        state_dir,
        endpoints,
        ui: None,
        log_file: dir.join("service.log"),
    }
}

#[cfg(windows)]
pub(crate) fn laid_out(dir: &Path) -> LocalBootstrap {
    let state_dir = dir.join("state");
    std::fs::create_dir(&state_dir).expect("the state directory");
    wslib_file_atomic::owner_only(&state_dir).expect("the state directory's DACL");
    let unique = dir.file_name().expect("a name").to_string_lossy();
    let endpoints = socket_roles()
        .map(|role| LocalEndpoint {
            path: format!(r"\\.\pipe\{unique}-{role}").into(),
            ceiling: role,
            group: String::new(),
        })
        .collect();
    LocalBootstrap {
        db: state_dir.join("service.db"),
        state_dir,
        endpoints,
        ui: None,
        log_file: dir.join("service.log"),
        service: None,
    }
}

#[cfg(unix)]
async fn connected(socket: &Path) -> tokio::net::UnixStream {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    loop {
        match tokio::net::UnixStream::connect(socket).await {
            Ok(stream) => return stream,
            Err(e) if matches!(e.kind(), NotFound | ConnectionRefused) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => panic!("{}: {e}", socket.display()),
        }
    }
}

#[cfg(windows)]
async fn connected(pipe: &Path) -> tokio::net::windows::named_pipe::NamedPipeClient {
    const ERROR_PIPE_BUSY: i32 = 231;
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(pipe) {
            Ok(client) => return client,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(ERROR_PIPE_BUSY) =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => panic!("{}: {e}", pipe.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wslib_appliance_types::Branding;

    #[tokio::test]
    async fn each_endpoint_answers_as_its_ceiling_and_the_service_stops() {
        let builder = Harness::builder();
        let store = builder.bootstrap().open_store(None).await.expect("store");
        let harness = builder
            .serve(Service::new(
                store.clone(),
                Branding::unbranded(),
                "0.0.0",
                crate::logs(&[]),
            ))
            .await;

        let cert_pem = wslib_appliance_core::testing::Authority::new("Test Root").pem;
        for role in socket_roles() {
            let session = body_json(harness.get(role, "/api/session").send().await).await;
            assert_eq!(session["role"], role.as_str(), "{session}");
            let inspected = harness
                .request(role, "POST", "/api/tls/cas/inspect")
                .json(serde_json::json!({ "cert_pem": cert_pem }))
                .send()
                .await;
            let expected = if role == Role::Admin { 200 } else { 403 };
            assert_eq!(inspected.status(), expected, "at {role}");
        }
        let dir = harness.bootstrap().state_dir.clone();
        harness.stop().await;
        assert!(store.begin().await.is_err(), "the store is closed");
        assert!(
            !dir.exists(),
            "the directory went with it, though the test holds a store"
        );
    }
}
