//! The control sockets, the only listeners whose requests carry local authority,
//! each up to its own endpoint's ceiling and naming the account that connected;
//! and what the listeners share: [`ServeError`] and [`GRACE`].
//! On Windows a control socket is a named pipe.

#[cfg(windows)]
mod pipe;
#[cfg(unix)]
pub(crate) mod socket;
#[cfg(any(windows, test))]
mod windows_account;

#[cfg(windows)]
use pipe::{same_endpoint, serve_endpoint};

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use axum::Router;
use tokio_util::sync::CancellationToken;
use wslib_appliance_types::Role;

/// How long an in-flight request has to finish once shutdown starts; it must
/// stay inside the service manager's own stop deadline or the process is killed.
pub const GRACE: Duration = Duration::from_secs(10);

/// The [`Daemon`](wslib_service::Daemon) to serve an appliance under, with a
/// grace of 22 s that outlasts the listeners' drain and the registered tasks';
/// a container's stop timeout or a launchd `ExitTimeOut` must exceed it.
pub fn daemon(name: &str) -> wslib_service::Daemon {
    wslib_service::Daemon::new(name).grace(GRACE * 2 + Duration::from_secs(2))
}

/// How many connections each control endpoint, the app socket and the hooks
/// socket hold at once; past it a socket's clients wait in the kernel's backlog;
/// a pipe's next client waits on the spare instance, and the rest are refused
/// `ERROR_PIPE_BUSY`.
const CONNECTIONS: usize = 32;

/// How long a control connection may take to send a request head, or sit idle
/// between requests.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Why the appliance could not start listening. A variant about a file or a
/// listener names its path or address.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    #[error("the TLS certificate ({}) or key ({}) could not be loaded: {because}", cert.display(), key.display())]
    Tls {
        cert: PathBuf,
        key: PathBuf,
        because: String,
    },

    #[error("could not listen on {address}: {because}")]
    Bind { address: String, because: String },

    #[error("the socket at {} could not be created: {because}", path.display())]
    Socket { path: PathBuf, because: String },

    #[error(
        "something may be listening on the socket at {}, or this user may not connect to it; remove it if nothing is",
        path.display()
    )]
    SocketInUse { path: PathBuf },

    /// Not necessarily an appliance: any local account may create a pipe name.
    #[cfg(windows)]
    #[error("another process already holds the control pipe {}", name.display())]
    PipeInUse { name: PathBuf },

    #[error("could not read what this appliance trusts for outbound connections: {0}")]
    Trust(String),

    #[error("serving: {0}")]
    Serving(String),

    /// A programming error.
    #[error("routes for a backend with no accounts were mounted on one whose callers are accounts")]
    LocalRoutesWithResolver,

    /// A programming error.
    #[error(
        "no rustls crypto provider is installed: install one with `CryptoProvider::install_default`"
    )]
    NoCryptoProvider,
}

/// The control sockets' routes, which only [`serve_control`] serves, and in
/// tests `Req::local`.
#[derive(Clone)]
pub struct ControlRouter(Router);

impl ControlRouter {
    pub(crate) fn new(router: Router) -> Self {
        Self(router)
    }

    #[cfg(any(test, feature = "testing"))]
    #[doc(hidden)]
    pub fn empty() -> Self {
        Self(Router::new())
    }

    /// Through the one function that makes the marker, so tests cannot pass
    /// against a listener that never sets one.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn with_local_authority(self, ceiling: Role) -> Router {
        with_local_authority(self.0, ceiling)
    }

    /// As [`with_local_authority`](Self::with_local_authority), on a connection
    /// whose peer credentials name `uid`.
    #[cfg(all(test, unix))]
    pub(crate) fn with_local_peer(self, ceiling: Role, uid: u32) -> Router {
        with_local_authority(self.0, ceiling).layer(axum::Extension(axum::extract::ConnectInfo(
            peer::PeerCredentials::new(Some(uid)),
        )))
    }
}

/// Tag every request on this router as from a control socket at `ceiling`,
/// naming the peer's account when its credentials resolve.
///
/// **The only place the marker is created**, and applied to the control sockets
/// alone: that is what makes it mean what [`extract`](crate::extract) says.
fn with_local_authority(router: Router, ceiling: Role) -> Router {
    use crate::extract::LocalAuthority;
    use axum::extract::Request;

    let ceiling = ceiling.min(Role::Admin);
    router.layer(axum::middleware::map_request(
        move |mut request: Request| async move {
            let peer = peer::actor_of(&request).await;
            request
                .extensions_mut()
                .insert(LocalAuthority { ceiling, peer });
            request
        },
    ))
}

/// The account at the other end of a control-socket connection.
mod peer {
    #![cfg_attr(
        unix,
        allow(clippy::clone_on_copy, reason = "`Key` is a SID on Windows")
    )]

    use std::sync::Arc;
    use std::time::Duration;

    use axum::extract::connect_info::Connected;
    use axum::extract::{ConnectInfo, Request};
    use axum::serve::Listener;
    use tokio::sync::{OnceCell, Semaphore};

    use crate::bounded::Bounded;

    #[cfg(windows)]
    use super::pipe::{account_name, rendered};
    #[cfg(unix)]
    use super::socket::{account_name, rendered};
    #[cfg(windows)]
    pub(super) use wslib_host::Sid as Key;
    #[cfg(unix)]
    pub(super) type Key = u32;

    const LOOKUP_DEADLINE: Duration = Duration::from_secs(1);
    static LOOKUP_SLOTS: Semaphore = Semaphore::const_new(8);

    /// The peer's uid or SID as read at accept; the name is looked up on the
    /// first request, because a stalled directory would stall the accept loop.
    #[derive(Clone)]
    pub(super) struct PeerCredentials {
        key: Option<Key>,
        actor: Arc<OnceCell<String>>,
    }

    impl PeerCredentials {
        pub(super) fn new(key: Option<Key>) -> Self {
            Self {
                key,
                actor: Arc::default(),
            }
        }

        async fn actor(&self) -> Option<String> {
            let key = self.key.as_ref()?;
            let actor = self
                .actor
                .get_or_init(|| {
                    resolved(
                        Key::clone(key),
                        LOOKUP_DEADLINE,
                        &LOOKUP_SLOTS,
                        account_name,
                    )
                })
                .await;
            Some(actor.clone())
        }
    }

    impl<L: Listener<Addr = Option<Key>>> Connected<Bounded<L>> for PeerCredentials {
        fn connect_info(peer: Bounded<L>) -> Self {
            Self::new(peer.address)
        }
    }

    pub(super) fn actor_of(
        request: &Request,
    ) -> impl Future<Output = Option<String>> + Send + use<> {
        let credentials = request
            .extensions()
            .get::<ConnectInfo<PeerCredentials>>()
            .map(|ConnectInfo(credentials)| credentials.clone());
        async move { credentials?.actor().await }
    }

    /// Past `deadline`, or with no slot free, the request goes ahead in the uid
    /// (or SID) form for the connection's life; a stalled lookup keeps its slot.
    pub(super) async fn resolved(
        key: Key,
        deadline: Duration,
        slots: &'static Semaphore,
        lookup: impl FnOnce(Key) -> Option<String> + Send + 'static,
    ) -> String {
        let Ok(slot) = slots.try_acquire() else {
            return rendered(key, None);
        };
        let looked_up = {
            let key = Key::clone(&key);
            tokio::task::spawn_blocking(move || {
                let _slot = slot;
                lookup(key)
            })
        };
        let account = tokio::time::timeout(deadline, looked_up)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        rendered(key, account)
    }
}

/// A control socket's path, or on Windows its pipe name (`\\.\pipe\…`), and the
/// highest role a request on it satisfies. The ceiling bounds what a socket
/// grants, not who can reach it: that is for its directory's permissions or its
/// pipe's group.
pub struct ControlEndpoint {
    path: PathBuf,
    ceiling: Role,
    #[cfg(windows)]
    group: Option<String>,
    #[cfg(windows)]
    service: Option<String>,
}

impl ControlEndpoint {
    /// A `ceiling` above Admin is Admin: no socket reaches HostAdmin.
    pub fn new(path: impl Into<PathBuf>, ceiling: Role) -> Self {
        Self {
            path: path.into(),
            ceiling: ceiling.min(Role::Admin),
            #[cfg(windows)]
            group: None,
            #[cfg(windows)]
            service: None,
        }
    }
}

#[cfg(windows)]
impl ControlEndpoint {
    /// Let members of the local group open the pipe, but not create an instance
    /// of it; without one only SYSTEM and the pipe's owner can.
    pub fn granted_to(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Make the pipe's owner `NT SERVICE\<service>` rather than this process's
    /// user, so `wslib-appliance-client` can tell the service's pipe from another's;
    /// serving fails if `service` is not one installed service's own account,
    /// or this process may not assign that owner.
    pub fn owned_by_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }
}

/// One socket per endpoint, each satisfying roles up to its ceiling; the first
/// to fail stops them all, and two endpoints naming one path are refused before
/// anything binds. Every endpoint is listening, or serving has failed, once the
/// future is first polled. A missing socket directory fails serving.
///
/// On unix a socket is `0660`: membership of the appliance's group is the grant,
/// so the database beside it must stay `0600`.
/// On Windows each is a named pipe refusing remote clients, open to SYSTEM, its
/// owner and its endpoint's group alone, so an Administrator outside the group is
/// refused.
pub async fn serve_control(
    router: ControlRouter,
    endpoints: Vec<ControlEndpoint>,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    for (i, endpoint) in endpoints.iter().enumerate() {
        if endpoints[..i]
            .iter()
            .any(|earlier| same_endpoint(&earlier.path, &endpoint.path))
        {
            return Err(ServeError::Socket {
                path: endpoint.path.clone(),
                because: "more than one control endpoint names it".to_string(),
            });
        }
    }
    futures_util::future::try_join_all(
        endpoints
            .into_iter()
            .map(|endpoint| serve_endpoint(router.0.clone(), endpoint, stop.clone())),
    )
    .await?;
    Ok(())
}

#[cfg(unix)]
fn same_endpoint(a: &Path, b: &Path) -> bool {
    a == b
}

#[cfg(unix)]
async fn serve_endpoint(
    router: Router,
    ControlEndpoint { path, ceiling }: ControlEndpoint,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    use std::os::unix::fs::PermissionsExt;

    let path = path.as_path();
    let (listener, _unlink) = bind_socket(path)?;
    // Read back rather than assumed: a socket takes its directory's group on
    // macOS, and on Linux the process's unless the directory is setgid.
    let bound = std::fs::metadata(path).map_err(|e| socket_error(path, &e))?;
    tracing::info!(
        path = %path.display(),
        %ceiling,
        gid = std::os::unix::fs::MetadataExt::gid(&bound),
        mode = %format_args!("{:04o}", bound.permissions().mode() & 0o7777),
        "control socket listening"
    );
    serve_bounded(socket::Peers(listener), router, ceiling, stop).await
}

#[cfg(unix)]
fn socket_error(path: &Path, e: &std::io::Error) -> ServeError {
    ServeError::Socket {
        path: path.to_path_buf(),
        because: e.to_string(),
    }
}

/// A `0660` Unix socket bound at `path`, after clearing one an earlier run left
/// there, and the guard that unlinks it.
#[cfg(unix)]
pub(crate) fn bind_socket(
    path: &Path,
) -> Result<(tokio::net::UnixListener, Unlink<'_>), ServeError> {
    use std::os::unix::fs::PermissionsExt;

    clear_stale_socket(path)?;
    let listener = tokio::net::UnixListener::bind(path).map_err(|e| socket_error(path, &e))?;
    let unlink = Unlink::new(path);
    // A world-writable socket hands its listener's authority to any local account.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| socket_error(path, &e))?;
    Ok((listener, unlink))
}

/// Serve one endpoint's listener, held to [`CONNECTIONS`] and
/// [`HEADER_READ_TIMEOUT`], until `stop` and the grace after it.
async fn serve_bounded<L>(
    listener: L,
    router: Router,
    ceiling: Role,
    stop: CancellationToken,
) -> Result<(), ServeError>
where
    L: axum::serve::Listener<Addr = Option<peer::Key>>,
{
    serve_http1::<L, peer::PeerCredentials>(
        listener,
        with_local_authority(router, ceiling),
        HEADER_READ_TIMEOUT,
        stop,
    )
    .await
}

/// Serve `router` on `listener`, held to [`CONNECTIONS`] and `head`, until
/// `stop` and the grace after it, handing each request its connection's `C`.
///
/// http/1.1 only: a cleartext h2 connection's preface is read against no
/// deadline.
pub(crate) async fn serve_http1<L, C>(
    listener: L,
    router: Router,
    head: Duration,
    stop: CancellationToken,
) -> Result<(), ServeError>
where
    L: axum::serve::Listener,
    L::Addr: Clone + Send + Sync + 'static,
    C: axum::extract::connect_info::Connected<crate::bounded::Bounded<L>>
        + Clone
        + Send
        + Sync
        + 'static,
{
    use crate::bounded::{Bounded, BoundedListener, head_within, until_stopped};

    let handle = axum_server::Handle::<Bounded<L>>::new();
    let mut server =
        axum_server::Server::from_listener(BoundedListener::new(listener, CONNECTIONS))
            .http1_only()
            .handle(handle.clone());
    head_within(server.http_builder(), head);
    let serving = server.serve(router.into_make_service_with_connect_info::<C>());
    until_stopped(serving, handle, stop, GRACE)
        .await
        .map_err(|e| ServeError::Serving(crate::redact::foreign(&e)))
}

/// Removes a socket this process bound however serving ends, including when the
/// future is dropped because another listener failed — but only while the path
/// is still that socket, by device and inode, not whatever replaced it.
#[cfg(unix)]
pub(crate) struct Unlink<'a> {
    path: &'a Path,
    bound: Option<(u64, u64)>,
}

#[cfg(unix)]
impl<'a> Unlink<'a> {
    fn new(path: &'a Path) -> Self {
        Self {
            path,
            bound: file_identity(path),
        }
    }
}

#[cfg(unix)]
impl Drop for Unlink<'_> {
    fn drop(&mut self) {
        if self.bound.is_some() && file_identity(self.path) == self.bound {
            std::fs::remove_file(self.path).ok();
        }
    }
}

#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

/// Remove a socket file left behind by a process that is no longer there.
///
/// **Not an unconditional `remove_file`**: a bind over a live socket steals it
/// from a running appliance. Only a refused connection means nobody is home;
/// anything else at the path is left alone.
#[cfg(unix)]
fn clear_stale_socket(path: &Path) -> Result<(), ServeError> {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    use std::os::unix::fs::FileTypeExt;

    let refused = |because: String| ServeError::Socket {
        path: path.to_path_buf(),
        because,
    };
    let Ok(found) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !found.file_type().is_socket() {
        return Err(refused(
            "something that is not a socket is already there".to_string(),
        ));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Err(e) if e.kind() == NotFound => Ok(()),
        Err(e) if e.kind() == ConnectionRefused => {
            tracing::warn!(
                path = %path.display(),
                "removing a socket left behind by an earlier run"
            );
            std::fs::remove_file(path).map_err(|e| refused(e.to_string()))
        }
        _ => Err(ServeError::SocketInUse {
            path: path.to_path_buf(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::probe::{NAMELESS_UID, Probe, WHO};

    #[tokio::test]
    async fn every_endpoint_is_listening_once_serving_is_first_polled() {
        let probe = crate::probe::Probe::new().await;
        #[cfg(unix)]
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let (paths, listening) = (
            Role::LADDER.map(|role| dir.path().join(format!("{role}.sock"))),
            Path::exists,
        );
        #[cfg(windows)]
        let (paths, listening) = (
            Role::LADDER.map(|role| {
                PathBuf::from(format!(
                    r"\\.\pipe\appliance-core-polled-{}-{role}",
                    std::process::id()
                ))
            }),
            |path: &PathBuf| pipe::open_client(path, pipe::CLIENT_ACCESS).is_ok(),
        );
        let endpoints = paths
            .iter()
            .zip(Role::LADDER)
            .map(|(path, role)| ControlEndpoint::new(path, role))
            .collect();
        let stop = CancellationToken::new();
        let mut serving = std::pin::pin!(serve_control(
            probe.control.clone(),
            endpoints,
            stop.clone()
        ));

        let first =
            std::future::poll_fn(|cx| std::task::Poll::Ready(Future::poll(serving.as_mut(), cx)))
                .await;
        assert!(first.is_pending(), "{first:?}");
        for path in &paths {
            assert!(listening(path), "{}", path.display());
        }
        stop.cancel();
        serving.await.expect("served");
    }

    async fn get_on(
        mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        path: &str,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("writes");
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.expect("reads");
        answer
    }

    #[cfg(unix)]
    async fn get_over(socket: &Path, path: &str) -> String {
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .expect("connects");
        get_on(stream, path).await
    }

    #[cfg(unix)]
    async fn status_over(socket: &Path, path: &str) -> String {
        get_over(socket, path).await[9..12].to_string()
    }

    #[cfg(unix)]
    async fn until_bound(socket: &Path) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the socket bound");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_request_names_the_account_that_connected() {
        let probe = Probe::new().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let stop = CancellationToken::new();
        let serving = tokio::spawn(serve_control(
            probe.control.clone(),
            vec![ControlEndpoint::new(&socket, Role::Viewer)],
            stop.clone(),
        ));
        until_bound(&socket).await;

        // SAFETY: `geteuid` reads this process's own credentials and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let expected = socket::rendered(uid, socket::account_name(uid));
        let answer = get_over(&socket, WHO).await;
        assert!(answer.ends_with(&format!("\r\n\r\n{expected}")), "{answer}");

        stop.cancel();
        serving.await.expect("did not panic").expect("served");
    }

    #[cfg(unix)]
    async fn serving_one(
        router: ControlRouter,
        socket: &Path,
    ) -> (
        CancellationToken,
        tokio::task::JoinHandle<Result<(), ServeError>>,
    ) {
        let stop = CancellationToken::new();
        let serving = tokio::spawn(serve_control(
            router,
            vec![ControlEndpoint::new(socket, Role::Viewer)],
            stop.clone(),
        ));
        until_bound(socket).await;
        (stop, serving)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_control_connection_past_the_cap_waits_until_one_ends() {
        let probe = Probe::new().await;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let (stop, serving) = serving_one(probe.control.clone(), &socket).await;

        let mut held = Vec::new();
        for _ in 0..CONNECTIONS {
            held.push(
                tokio::net::UnixStream::connect(&socket)
                    .await
                    .expect("connects"),
            );
        }
        let past = {
            let socket = socket.clone();
            tokio::spawn(
                async move { status_over(&socket, &crate::probe::rung(Role::Viewer)).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!past.is_finished(), "a connection past the cap was served");

        held.pop();
        let status = tokio::time::timeout(Duration::from_secs(5), past)
            .await
            .expect("the slot comes back with the connection")
            .expect("did not panic");
        assert_eq!(status, "200");

        drop(held);
        stop.cancel();
        serving.await.expect("did not panic").expect("served");
    }

    /// Still open a moment after connecting: a connection task with no timer
    /// panics, which hangs up at once.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_control_connection_that_sends_no_head_is_hung_up_on_at_the_deadline() {
        use tokio::io::AsyncReadExt;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let (stop, serving) = serving_one(ControlRouter::empty(), &socket).await;

        let mut peer = tokio::net::UnixStream::connect(&socket)
            .await
            .expect("connects");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peer.read(&mut [0u8; 1]))
                .await
                .is_err(),
            "hung up before its deadline"
        );
        let mut rest = Vec::new();
        tokio::time::timeout(
            HEADER_READ_TIMEOUT + Duration::from_secs(5),
            peer.read_to_end(&mut rest),
        )
        .await
        .expect("a connection that sent no head is hung up on")
        .expect("reads");

        stop.cancel();
        serving.await.expect("did not panic").expect("served");
    }

    #[cfg(unix)]
    #[test]
    fn a_uid_with_no_account_is_audited_by_number() {
        assert_eq!(socket::account_name(NAMELESS_UID), None);
        assert_eq!(
            socket::rendered(NAMELESS_UID, None),
            format!("control-socket:uid={NAMELESS_UID}")
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_a_plain_account_name_reaches_the_actor() {
        for plain in ["operator", "svc-backup", "first.last", "_www", "host01$"] {
            assert!(socket::is_plain_account_name(plain), "{plain:?}");
        }
        for refused in ["", "$", "uid=1000", "a:b", "two words", "a\nb", "a$$", "é"] {
            assert!(!socket::is_plain_account_name(refused), "{refused:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_lookup_past_its_deadline_goes_ahead_in_the_uid_form() {
        static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let (release, stalled) = std::sync::mpsc::channel::<()>();
        let actor = tokio::time::timeout(
            Duration::from_secs(5),
            peer::resolved(
                NAMELESS_UID,
                Duration::from_millis(20),
                &SLOTS,
                stalled_lookup(stalled),
            ),
        )
        .await
        .expect("the deadline, not the lookup, decides");
        release.send(()).ok();
        assert_eq!(actor, format!("control-socket:uid={NAMELESS_UID}"));
    }

    #[cfg(unix)]
    fn stalled_lookup(
        stalled: std::sync::mpsc::Receiver<()>,
    ) -> impl FnOnce(u32) -> Option<String> + Send + 'static {
        move |_| {
            stalled.recv().ok();
            Some("late".to_string())
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn with_every_slot_held_by_a_stalled_lookup_the_next_is_not_attempted() {
        static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
        let mut releases = Vec::new();
        for _ in 0..2 {
            let (release, stalled) = std::sync::mpsc::channel::<()>();
            releases.push(release);
            peer::resolved(
                NAMELESS_UID,
                Duration::from_millis(1),
                &SLOTS,
                stalled_lookup(stalled),
            )
            .await;
        }
        assert_eq!(
            SLOTS.available_permits(),
            0,
            "a timed-out lookup keeps its slot"
        );

        let attempted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = attempted.clone();
        let actor = peer::resolved(NAMELESS_UID, Duration::from_secs(5), &SLOTS, move |_| {
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
            Some("attempted".to_string())
        })
        .await;
        assert_eq!(actor, format!("control-socket:uid={NAMELESS_UID}"));
        assert!(!attempted.load(std::sync::atomic::Ordering::SeqCst));

        drop(releases);
        tokio::time::timeout(Duration::from_secs(5), async {
            while SLOTS.available_permits() < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a finished lookup gives its slot back");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn one_call_serves_a_socket_per_endpoint_each_at_its_own_ceiling_and_unlinks_both() {
        use crate::probe::rung;
        use std::os::unix::fs::PermissionsExt;

        let probe = Probe::new().await;
        let dir = tempfile::tempdir().unwrap();
        let viewer = dir.path().join("viewer.sock");
        let admin = dir.path().join("admin.sock");
        let stop = CancellationToken::new();
        let serving = tokio::spawn(serve_control(
            probe.control.clone(),
            vec![
                ControlEndpoint::new(&viewer, Role::Viewer),
                ControlEndpoint::new(&admin, Role::Admin),
            ],
            stop.clone(),
        ));

        until_bound(&viewer).await;
        until_bound(&admin).await;

        assert_eq!(status_over(&viewer, &rung(Role::Viewer)).await, "200");
        assert_eq!(status_over(&viewer, &rung(Role::Operator)).await, "403");
        assert_eq!(status_over(&admin, &rung(Role::Admin)).await, "200");
        for socket in [&viewer, &admin] {
            let mode = std::fs::metadata(socket)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o660, "{}", socket.display());
        }

        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("stops")
            .expect("did not panic")
            .expect("served");
        assert!(!viewer.exists() && !admin.exists(), "both unlinked");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn two_endpoints_naming_one_path_are_refused_before_anything_binds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let served = serve_control(
            ControlRouter::empty(),
            vec![
                ControlEndpoint::new(&path, Role::Viewer),
                ControlEndpoint::new(&path, Role::Admin),
            ],
            CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(&served, Err(ServeError::Socket { path: named, .. }) if *named == path),
            "{served:?}"
        );
        assert!(!path.exists(), "nothing bound");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_sibling_that_cannot_bind_fails_the_call_and_unlinks_the_socket_that_did() {
        let dir = tempfile::tempdir().unwrap();
        let bound = dir.path().join("control.sock");
        let blocked = dir.path().join("not-a-directory");
        std::fs::write(&blocked, "").expect("write");
        let served = tokio::time::timeout(
            Duration::from_secs(5),
            serve_control(
                ControlRouter::empty(),
                vec![
                    ControlEndpoint::new(&bound, Role::Admin),
                    ControlEndpoint::new(blocked.join("control.sock"), Role::Viewer),
                ],
                CancellationToken::new(),
            ),
        )
        .await
        .expect("fails rather than serving");
        assert!(
            matches!(served, Err(ServeError::Socket { .. })),
            "{served:?}"
        );
        assert!(!bound.exists(), "the socket that bound is unlinked");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_whose_directory_is_missing_is_refused_and_the_directory_not_made() {
        let dir = tempfile::tempdir().unwrap();
        let removed = dir.path().join("gone");
        let served = tokio::time::timeout(
            Duration::from_secs(5),
            serve_control(
                ControlRouter::empty(),
                vec![ControlEndpoint::new(removed.join("c.sock"), Role::Admin)],
                CancellationToken::new(),
            ),
        )
        .await;
        assert!(!removed.exists(), "nothing remade the directory");
        assert!(
            matches!(served, Ok(Err(ServeError::Socket { .. }))),
            "{served:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_file_that_is_not_a_socket_is_refused_and_left_where_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");
        std::fs::write(&path, b"rows").expect("writes");

        let refused = bind_socket(&path).map(|_| ());

        assert!(
            matches!(refused, Err(ServeError::Socket { .. })),
            "{refused:?}"
        );
        assert_eq!(std::fs::read(&path).expect("survives"), b"rows");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_live_socket_this_uid_may_not_connect_to_is_left_listening() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.sock");
        let _theirs = std::os::unix::net::UnixListener::bind(&path).expect("binds");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let refused = std::os::unix::net::UnixStream::connect(&path).map(|_| ());
        if refused.is_ok() {
            // Root connects whatever the mode says.
            return;
        }

        let bound = bind_socket(&path).map(|_| ());

        assert!(
            matches!(bound, Err(ServeError::SocketInUse { .. })),
            "{bound:?}"
        );
        assert!(path.exists(), "the live socket is left where it is");
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_replaced_at_its_path_is_left_to_whatever_replaced_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let _ours = std::os::unix::net::UnixListener::bind(&path).expect("binds");
        let unlink = Unlink::new(&path);

        std::fs::remove_file(&path).expect("unlinks");
        let _theirs = std::os::unix::net::UnixListener::bind(&path).expect("rebinds");
        drop(unlink);

        assert!(path.exists(), "the replacement survives");
    }

    #[cfg(windows)]
    mod pipes {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::path::{Path, PathBuf};
        use std::ptr::null_mut;

        use tokio::net::windows::named_pipe::{NamedPipeClient, ServerOptions};
        use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, ImpersonateLoggedOnUser, RevertToSelf, SID_AND_ATTRIBUTES,
            TOKEN_DUPLICATE, TOKEN_QUERY,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        use super::*;
        use crate::control::pipe::{
            self, CLIENT_ACCESS, LOCAL_SYSTEM, Readback, Security, open_client, read_security,
        };
        use crate::probe::{Probe, WHO, rung};

        const AUTHENTICATED_USERS: &str = "S-1-5-11";

        fn pipe_name(test: &str) -> PathBuf {
            PathBuf::from(format!(
                r"\\.\pipe\appliance-core-{test}-{}",
                std::process::id()
            ))
        }

        async fn until_open(
            open: impl Fn() -> std::io::Result<NamedPipeClient>,
        ) -> NamedPipeClient {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match open() {
                        Ok(client) => return client,
                        Err(e)
                            if [ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY]
                                .map(|code| Some(code as i32))
                                .contains(&e.raw_os_error()) =>
                        {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(e) => panic!("opening the pipe: {e}"),
                    }
                }
            })
            .await
            .expect("the pipe is served")
        }

        /// Opened as a member of the endpoint's group would, once an instance
        /// is free.
        async fn connected(name: &Path) -> NamedPipeClient {
            until_open(|| open_client(name, CLIENT_ACCESS)).await
        }

        /// By SID, past `granted_to`, which refuses well-known groups; a test
        /// cannot create a local one without administrator rights.
        fn serve_to_authenticated_users(
            router: ControlRouter,
            name: &Path,
            ceiling: Role,
            stop: CancellationToken,
        ) -> tokio::task::JoinHandle<Result<(), ServeError>> {
            let owner = wslib_host::current_user().expect("this process's user");
            let group = AUTHENTICATED_USERS
                .parse::<wslib_host::Sid>()
                .expect(AUTHENTICATED_USERS);
            let security = Security::granting(&owner, Some(&group)).expect("the descriptor");
            tokio::spawn(pipe::serve_secured(
                router.0,
                name.to_path_buf(),
                ceiling,
                security,
                stop,
            ))
        }

        /// This process's token with its user SID made deny-only, so the owner's
        /// ACE and implicit rights grant it nothing.
        fn without_the_owner() -> OwnedHandle {
            let user = wslib_host::current_user().expect("this process's user");
            let mut token = null_mut();
            let mut restricted = null_mut();
            // SAFETY: the pseudo-handle is always valid; each token is owned once
            // made, and `disabled` points at a SID that outlives the call.
            unsafe {
                let access = TOKEN_DUPLICATE | TOKEN_QUERY;
                assert_ne!(OpenProcessToken(GetCurrentProcess(), access, &mut token), 0);
                let token = OwnedHandle::from_raw_handle(token);
                let disabled = SID_AND_ATTRIBUTES {
                    Sid: user.as_psid(),
                    Attributes: 0,
                };
                let made = CreateRestrictedToken(
                    token.as_raw_handle(),
                    0,
                    1,
                    &disabled,
                    0,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut restricted,
                );
                assert_ne!(made, 0, "{}", std::io::Error::last_os_error());
                OwnedHandle::from_raw_handle(restricted)
            }
        }

        async fn stopped(serving: tokio::task::JoinHandle<Result<(), ServeError>>) {
            tokio::time::timeout(GRACE + Duration::from_secs(5), serving)
                .await
                .expect("stops within the grace period")
                .expect("did not panic")
                .expect("served");
        }

        #[tokio::test]
        async fn a_pipe_request_is_served_at_its_ceiling_and_names_the_account_that_connected() {
            let probe = Probe::new().await;
            let name = pipe_name("served");
            let stop = CancellationToken::new();
            let serving = serve_to_authenticated_users(
                probe.control.clone(),
                &name,
                Role::Viewer,
                stop.clone(),
            );

            let user = wslib_host::current_user().expect("this process's user");
            let account = pipe::account_name(user).expect("the user has a plain name");
            let answer = get_on(connected(&name).await, WHO).await;
            assert!(
                answer.ends_with(&format!("\r\n\r\ncontrol-socket:{account}")),
                "{answer}"
            );
            let refused = get_on(connected(&name).await, &rung(Role::Operator)).await;
            assert_eq!(&refused[9..12], "403", "{refused}");

            stop.cancel();
            stopped(serving).await;
        }

        /// The group's ACE admits a member who is not the owner: the client's
        /// user SID is deny-only while it opens the pipe.
        #[tokio::test]
        async fn a_member_of_the_group_who_is_not_the_owner_is_served() {
            let probe = Probe::new().await;
            let name = pipe_name("member");
            let stop = CancellationToken::new();
            let serving = serve_to_authenticated_users(
                probe.control.clone(),
                &name,
                Role::Viewer,
                stop.clone(),
            );

            let restricted = without_the_owner();
            let client = until_open(|| {
                // SAFETY: the token is live; this thread reverts before returning.
                unsafe {
                    assert_ne!(ImpersonateLoggedOnUser(restricted.as_raw_handle()), 0);
                    let opened = open_client(&name, CLIENT_ACCESS);
                    assert_ne!(RevertToSelf(), 0);
                    opened
                }
            })
            .await;
            let answer = get_on(client, &rung(Role::Viewer)).await;
            assert_eq!(&answer[9..12], "200", "{answer}");

            stop.cancel();
            stopped(serving).await;
        }

        #[tokio::test]
        async fn a_pipe_name_already_held_is_refused_as_in_use() {
            let name = pipe_name("held");
            let serve = |stop: CancellationToken| {
                serve_control(
                    ControlRouter::empty(),
                    vec![ControlEndpoint::new(&name, Role::Admin)],
                    stop,
                )
            };

            let squatter = ServerOptions::new().create(&name).expect("squats");
            let served = serve(CancellationToken::new()).await;
            assert!(
                matches!(&served, Err(ServeError::PipeInUse { name: held }) if *held == name),
                "{served:?}"
            );
            drop(squatter);

            let stop = CancellationToken::new();
            let first = tokio::spawn(serve(stop.clone()));
            drop(connected(&name).await);
            let second = serve(CancellationToken::new()).await;
            assert!(
                matches!(&second, Err(ServeError::PipeInUse { .. })),
                "{second:?}"
            );

            stop.cancel();
            stopped(first).await;
        }

        #[tokio::test]
        async fn a_pipe_has_a_protected_dacl_for_system_its_owner_and_its_group_alone() {
            let name = pipe_name("dacl");
            let stop = CancellationToken::new();
            let serving = serve_to_authenticated_users(
                ControlRouter::empty(),
                &name,
                Role::Admin,
                stop.clone(),
            );

            let user = wslib_host::current_user()
                .expect("this process's user")
                .to_string();
            let allowed = ACCESS_ALLOWED_ACE_TYPE as u8;
            let mut aces = vec![(allowed, FILE_ALL_ACCESS, LOCAL_SYSTEM.to_string())];
            if user != LOCAL_SYSTEM {
                aces.push((allowed, FILE_ALL_ACCESS, user.clone()));
            }
            aces.push((allowed, CLIENT_ACCESS, AUTHENTICATED_USERS.to_string()));

            let client = connected(&name).await;
            let found = read_security(client.as_raw_handle()).expect("reads the pipe's security");
            assert_eq!(
                found,
                Readback {
                    owner: user,
                    protected: true,
                    aces
                }
            );

            drop(client);
            stop.cancel();
            stopped(serving).await;
        }

        #[tokio::test]
        async fn two_endpoints_naming_one_pipe_in_any_case_are_refused_before_anything_is_created()
        {
            let name = pipe_name("twice");
            let shouted = PathBuf::from(name.to_str().expect("UTF-8").to_uppercase());
            let served = serve_control(
                ControlRouter::empty(),
                vec![
                    ControlEndpoint::new(&name, Role::Viewer),
                    ControlEndpoint::new(&shouted, Role::Admin),
                ],
                CancellationToken::new(),
            )
            .await;
            assert!(
                matches!(&served, Err(ServeError::Socket { path, .. }) if *path == shouted),
                "{served:?}"
            );
            let absent = open_client(&name, CLIENT_ACCESS).expect_err("nothing was created");
            assert_eq!(absent.raw_os_error(), Some(ERROR_FILE_NOT_FOUND as i32));
        }
    }
}
