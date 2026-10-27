//! A console's stand-in on a developer's machine, so an app runs with no box
//! OS: plain HTTP on loopback, every request proxied to the app socket with one
//! chosen identity asserted in place of any the client sent.
//!
//! **It runs as the uid the app was given as `<PREFIX>_CONSOLE_UID`**, which
//! is the developer's own: the app hears the header from no other.

use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::DateTime;
use http_body_util::{Either, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, UnixStream};
use wslib_appliance_types::Role;
use wslib_appliance_types::console::{ConsoleIdentity, IDENTITY_HEADER};

#[derive(Debug, clap::Args)]
pub(crate) struct DevConsole {
    /// The app's socket, as its `<PREFIX>_APP_SOCKET` names it.
    #[arg(long, value_name = "PATH")]
    app_socket: PathBuf,

    /// Where a browser, or vite's dev proxy, connects; loopback only.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// The account asserted on every request, also its id.
    #[arg(long, default_value = "admin")]
    user: String,

    #[arg(long, default_value = "admin", value_parser = |s: &str| s.parse::<Role>())]
    role: Role,

    /// Stamp `reauth=` with each request's time, as a console does for a
    /// caller who has just re-entered their password.
    #[arg(long)]
    reauthenticated: bool,
}

pub(crate) fn run(args: DevConsole) -> Result<(), Box<dyn Error>> {
    if !args.listen.ip().is_loopback() {
        return Err(format!(
            "{} is not a loopback address, and the stand-in vouches for whoever connects",
            args.listen
        )
        .into());
    }
    let identity = Asserted::new(&args.user, args.role, args.reauthenticated)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = TcpListener::bind(args.listen).await?;
        eprintln!(
            "http://{} -> {}, as {} ({})",
            args.listen,
            args.app_socket.display(),
            args.user,
            args.role
        );
        Ok(serve(listener, args.app_socket.into(), identity).await?)
    })
}

/// Who every request is asserted as.
#[derive(Clone)]
struct Asserted {
    identity: ConsoleIdentity,
    reauthenticated: bool,
}

impl Asserted {
    /// `user` at `role`, refused here rather than by the app on every request.
    fn new(user: &str, role: Role, reauthenticated: bool) -> Result<Self, Box<dyn Error>> {
        let identity = ConsoleIdentity {
            id: user.to_string(),
            username: user.to_string(),
            role,
            reauthenticated_at: None,
        };
        identity.to_string().parse::<ConsoleIdentity>()?;
        let asserted = Self {
            identity,
            reauthenticated,
        };
        asserted.header()?;
        Ok(asserted)
    }

    /// The header for a request sent now.
    fn header(&self) -> Result<HeaderValue, hyper::header::InvalidHeaderValue> {
        let now = || {
            let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
            DateTime::from_timestamp(i64::try_from(since.as_secs()).ok()?, 0)
        };
        let identity = ConsoleIdentity {
            reauthenticated_at: self.reauthenticated.then(now).flatten(),
            ..self.identity.clone()
        };
        HeaderValue::try_from(identity.to_string())
    }
}

async fn serve(
    listener: TcpListener,
    socket: Arc<Path>,
    identity: Asserted,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let (socket, identity) = (Arc::clone(&socket), identity.clone());
        tokio::spawn(async move {
            let service =
                service_fn(move |request| forward(request, Arc::clone(&socket), identity.clone()));
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn forward(
    mut request: Request<Incoming>,
    socket: Arc<Path>,
    identity: Asserted,
) -> Result<Response<Either<Incoming, Full<Bytes>>>, hyper::Error> {
    if let Some(refused) = not_from_this_machine(request.headers()) {
        return Ok(answer(
            StatusCode::FORBIDDEN,
            format!("the {refused} is not loopback, and only loopback is vouched for\n"),
        ));
    }
    let identity = identity.header().expect("`Asserted::new` wrote it once");
    request.headers_mut().insert(IDENTITY_HEADER, identity);
    Ok(match send(request, &socket).await {
        Ok(response) => response.map(Either::Left),
        Err(why) => answer(
            StatusCode::BAD_GATEWAY,
            format!("the app at {} did not answer: {why}\n", socket.display()),
        ),
    })
}

fn answer(status: StatusCode, body: String) -> Response<Either<Incoming, Full<Bytes>>> {
    let mut response = Response::new(Either::Right(Full::from(body)));
    *response.status_mut() = status;
    response
}

/// A page from elsewhere can still reach a loopback listener, by a name it
/// rebinds to `127.0.0.1` or by a cross-origin request, so the stand-in vouches
/// only for a request whose `Host`, and `Origin` if any, name loopback; this is
/// the header that did not.
fn not_from_this_machine(headers: &hyper::HeaderMap) -> Option<&'static str> {
    let named = |name| headers.get(name).and_then(|value| value.to_str().ok());
    if !named(hyper::header::HOST).is_some_and(is_loopback_authority) {
        return Some("Host");
    }
    let origin_ok = named(hyper::header::ORIGIN).is_none_or(|origin| {
        origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .is_some_and(is_loopback_authority)
    });
    (!origin_ok).then_some("Origin")
}

/// `localhost` or a loopback literal, `[::1]` bracketed, with or without a port.
fn is_loopback_authority(authority: &str) -> bool {
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once(']') {
            Some((v6, rest)) => (v6, rest),
            None => return false,
        },
        None => authority
            .find(':')
            .map_or((authority, ""), |at| authority.split_at(at)),
    };
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.parse::<u16>().is_ok());
    let host_ok = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    port_ok && host_ok
}

async fn send(
    request: Request<Incoming>,
    socket: &Path,
) -> Result<Response<Incoming>, Box<dyn Error + Send + Sync>> {
    let stream = UnixStream::connect(socket).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(connection);
    Ok(sender.send_request(request).await?)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use wslib_appliance_server::testing::Harness;

    use super::*;

    /// `request`, sent through a stand-in asserting `user` at `role` in front
    /// of `socket`, and the whole answer.
    async fn through(socket: &Path, user: &str, role: Role, request: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let identity = Asserted::new(user, role, false).unwrap();
        tokio::spawn(serve(listener, socket.into(), identity));
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        answer
    }

    /// An app served on its socket, with this process as its console.
    async fn app() -> (Harness, PathBuf) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let app = Harness::new().await;
        let uid = std::fs::metadata(app.dir()).unwrap().uid();
        let socket = app.serve_app_socket(uid).await;
        (app, socket)
    }

    #[tokio::test]
    async fn the_app_hears_the_stand_ins_identity_and_none_the_client_sent() {
        let (_app, socket) = app().await;
        let answer = through(
            &socket,
            "Zoë",
            Role::Operator,
            "GET /api/session HTTP/1.1\r\nHost: localhost\r\n\
             APPLIANCE-IDENTITY: v1; id=x; user=root; role=hostadmin\r\n\
             appliance-identity: v1; id=y; user=root; role=admin\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(
            answer.ends_with(r#"{"id":"Zoë","username":"Zoë","role":"operator"}"#),
            "{answer}"
        );
    }

    #[test]
    fn reauthenticated_stamps_each_request_with_its_own_time() {
        let reauth = |reauthenticated| {
            let asserted = Asserted::new("admin", Role::Admin, reauthenticated).unwrap();
            let header = asserted.header().unwrap();
            header
                .to_str()
                .unwrap()
                .parse::<ConsoleIdentity>()
                .unwrap()
                .reauthenticated_at
        };
        assert_eq!(reauth(false), None);
        let at = reauth(true).expect("stamped");
        assert!((chrono::Utc::now() - at).num_seconds().abs() <= 1, "{at}");
    }

    #[tokio::test]
    async fn an_app_that_is_not_there_is_a_bad_gateway() {
        let dir = tempfile::TempDir::new().unwrap();
        let request = "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let answer = through(&dir.path().join("app.sock"), "admin", Role::Admin, request).await;
        assert!(answer.starts_with("HTTP/1.1 502"), "{answer}");
    }

    /// A 403 rather than the 502 an app that is not there gives: refused
    /// before anything is forwarded.
    #[tokio::test]
    async fn a_rebound_host_or_a_foreign_origin_is_refused_before_forwarding() {
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("app.sock");
        for (headers, refused) in [
            ("Host: attacker.example:8080\r\n", "Host"),
            ("Host: 127.0.0.1.attacker.example\r\n", "Host"),
            ("Host: localhost:8080@attacker.example\r\n", "Host"),
            ("", "Host"),
            (
                "Host: localhost:8080\r\nOrigin: http://attacker.example\r\n",
                "Origin",
            ),
            (
                "Host: localhost:8080\r\nOrigin: https://attacker.example\r\n",
                "Origin",
            ),
            ("Host: localhost:8080\r\nOrigin: null\r\n", "Origin"),
        ] {
            let request = format!("GET /healthz HTTP/1.1\r\n{headers}Connection: close\r\n\r\n");
            let answer = through(&socket, "admin", Role::Admin, &request).await;
            assert!(answer.starts_with("HTTP/1.1 403"), "{headers:?}: {answer}");
            assert!(
                answer.contains(&format!("the {refused} is not loopback")),
                "{headers:?}: {answer}"
            );
        }
    }

    #[tokio::test]
    async fn a_loopback_host_with_its_own_origin_or_none_is_forwarded() {
        let (_app, socket) = app().await;
        for headers in [
            "Host: localhost\r\n",
            "Host: 127.0.0.1:8080\r\n",
            "Host: [::1]:8080\r\n",
            "Host: LOCALHOST:8080\r\nOrigin: http://localhost:5173\r\n",
            "Host: 127.0.0.1:8080\r\nOrigin: http://[::1]\r\n",
            "Host: localhost:8080\r\nOrigin: https://localhost:8080\r\n",
        ] {
            let request = format!("GET /healthz HTTP/1.1\r\n{headers}Connection: close\r\n\r\n");
            let answer = through(&socket, "admin", Role::Admin, &request).await;
            assert!(answer.starts_with("HTTP/1.1 200"), "{headers:?}: {answer}");
        }
    }

    #[test]
    fn it_listens_on_loopback_alone_and_asserts_only_what_the_app_would_read() {
        let args = |listen: &str, user: &str| DevConsole {
            app_socket: "app.sock".into(),
            listen: listen.parse().unwrap(),
            user: user.to_string(),
            role: Role::Admin,
            reauthenticated: false,
        };
        for listen in ["0.0.0.0:8080", "[::]:8080", "192.168.1.2:8080"] {
            let refused = run(args(listen, "admin")).unwrap_err().to_string();
            assert!(
                refused.contains("not a loopback address"),
                "{listen}: {refused}"
            );
        }
        for user in ["", " admin", "a\nb"] {
            let refused = run(args("127.0.0.1:0", user)).unwrap_err().to_string();
            assert!(refused.contains("malformed"), "{user:?}: {refused}");
        }
    }
}
