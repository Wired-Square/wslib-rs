//! A fake tailscaled for tests, answering the LocalAPI on a Unix socket.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// The enrolled node's DNS name, without its trailing dot.
pub const NAME: &str = "box-1.example.ts.net";
/// The node's host name, enrolled or not.
pub const HOST_NAME: &str = "box-1";
/// The enrolled node's Tailscale addresses.
pub const ADDRESSES: [&str; 2] = ["100.64.0.7", "fd7a:115c:a1e0::7"];
/// The control server the prefs name.
pub const CONTROL_URL: &str = "https://control.example.com";

/// The node the fake reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeNode {
    Enrolled,
    LoggedOut,
}

/// How the fake answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answering {
    /// As tailscaled does.
    Normally,
    /// Accepts and reads a request, then never answers.
    Silently,
    /// With `status` and `body` to every request.
    Refusing { status: u16, body: String },
}

/// A fake tailscaled at a socket path; clones share its state.
///
/// A logout moves the node to [`FakeNode::LoggedOut`]; reset-auth succeeds
/// and any other unknown path is 404.
#[derive(Debug, Clone)]
pub struct FakeTailscaled {
    socket: PathBuf,
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    node: FakeNode,
    answering: Answering,
    heard: Vec<String>,
    serving: Option<JoinHandle<()>>,
}

impl FakeTailscaled {
    /// A fake for `socket` reporting `node`, not yet listening.
    pub fn new(socket: impl Into<PathBuf>, node: FakeNode) -> Self {
        Self {
            socket: socket.into(),
            state: Arc::new(Mutex::new(State {
                node,
                answering: Answering::Normally,
                heard: Vec::new(),
                serving: None,
            })),
        }
    }

    /// Binds the socket and answers on it until [`stop`](Self::stop); needs a tokio runtime.
    pub fn start(&self) -> io::Result<()> {
        let listener = UnixListener::bind(&self.socket)?;
        let state = self.state.clone();
        let serving = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, state.clone()));
            }
        });
        if let Some(old) = lock(&self.state).serving.replace(serving) {
            old.abort();
        }
        Ok(())
    }

    /// Stops listening and removes the socket, as a tailscaled that exits.
    pub fn stop(&self) {
        if let Some(serving) = lock(&self.state).serving.take() {
            serving.abort();
        }
        drop(std::fs::remove_file(&self.socket));
    }

    /// The socket it listens on.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The node it reports now.
    pub fn node(&self) -> FakeNode {
        lock(&self.state).node
    }

    /// Reports `node` from the next request.
    pub fn set_node(&self, node: FakeNode) {
        lock(&self.state).node = node;
    }

    /// Answers as `answering` from the next request.
    pub fn set_answering(&self, answering: Answering) {
        lock(&self.state).answering = answering;
    }

    /// Each request line heard so far, without its HTTP version, such as `POST /localapi/v0/logout`.
    pub fn heard(&self) -> Vec<String> {
        lock(&self.state).heard.clone()
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn serve(mut stream: UnixStream, state: Arc<Mutex<State>>) {
    let mut request = vec![0; 4096];
    let Ok(read) = stream.read(&mut request).await else {
        return;
    };
    let line = String::from_utf8_lossy(&request[..read])
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end_matches(" HTTP/1.0")
        .to_string();
    // Bound first, so the guard drops before a silent answer waits forever.
    let answer = answer(&mut lock(&state), line);
    match answer {
        Some(answer) => drop(stream.write_all(answer.as_bytes()).await),
        None => std::future::pending().await,
    }
}

fn answer(state: &mut State, line: String) -> Option<String> {
    state.heard.push(line.clone());
    let (status, body) = match &state.answering {
        Answering::Silently => return None,
        Answering::Refusing { status, body } => (*status, body.clone()),
        Answering::Normally => match line.as_str() {
            "GET /localapi/v0/status?peers=false" => (200, status(state.node)),
            "GET /localapi/v0/prefs" => (200, json!({"ControlURL": CONTROL_URL}).to_string()),
            "POST /localapi/v0/logout" => {
                state.node = FakeNode::LoggedOut;
                (200, String::new())
            }
            "POST /localapi/v0/reset-auth" => (200, String::new()),
            _ => (404, "not found\n".to_string()),
        },
    };
    Some(format!("HTTP/1.0 {status} Fake\r\n\r\n{body}"))
}

fn status(node: FakeNode) -> String {
    match node {
        FakeNode::Enrolled => json!({
            "BackendState": "Running",
            "TailscaleIPs": ADDRESSES,
            "Health": null,
            "Self": {"DNSName": format!("{NAME}."), "HostName": HOST_NAME},
        }),
        FakeNode::LoggedOut => json!({
            "BackendState": "NeedsLogin",
            "TailscaleIPs": null,
            "Self": {"DNSName": "", "HostName": HOST_NAME},
        }),
    }
    .to_string()
}
