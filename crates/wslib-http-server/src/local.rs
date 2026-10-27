use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum_server::{AddrListener, Address, Handle, Server};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use wslib_host::PeerCredentials;

use crate::bounded::{Bounds, Permitted, backed_off, made_bound, permit};
use crate::{app, head_within, until_stopped};

/// A bound Unix socket held to its [`Bounds`]. One [`bind`](Self::bind) made is
/// unlinked when it is dropped, as serving does when it ends, while the path
/// still holds that socket.
pub struct LocalSocket {
    listener: UnixListener,
    path: PathBuf,
    bound: Option<(u64, u64)>,
    permits: Arc<Semaphore>,
    pub(crate) bounds: Bounds,
}

impl LocalSocket {
    /// Bind `path` with permissions `mode`, first removing a socket there that
    /// nobody answers on. Anything else at `path`, or a live server, is refused.
    /// The socket is never at `path` with any other permissions.
    pub fn bind(path: impl AsRef<Path>, mode: u32, bounds: Bounds) -> io::Result<Self> {
        let path = path.as_ref();
        if path.as_os_str().as_bytes().first().is_none_or(|&b| b == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a local socket is bound at a non-empty path, not in the abstract namespace",
            ));
        }
        clear_stale_socket(path)?;

        // Bound in a private directory and linked into place, so the socket is
        // never reachable with the umask's permissions, and the link fails
        // rather than replace whatever got to `path` first.
        let staging = Staging::beside(path)?;
        let staged = staging.0.join("s");
        let listener = UnixListener::bind(&staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))?;
        std::fs::hard_link(&staged, path)?;
        Ok(Self::holding(
            listener,
            path.to_path_buf(),
            identity(path),
            bounds,
        ))
    }

    /// Hold a socket the caller bound at a path; it is never unlinked here.
    pub fn from_listener(listener: UnixListener, bounds: Bounds) -> io::Result<Self> {
        let path = listener
            .local_addr()?
            .as_pathname()
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the socket is bound at no path",
                )
            })?;
        Ok(Self::holding(listener, path, None, bounds))
    }

    fn holding(
        listener: UnixListener,
        path: PathBuf,
        bound: Option<(u64, u64)>,
        bounds: Bounds,
    ) -> Self {
        Self {
            listener,
            path,
            bound,
            permits: Arc::new(Semaphore::new(bounds.connections)),
            bounds,
        }
    }

    /// The path bound.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LocalSocket {
    fn drop(&mut self) {
        if self.bound.is_some() && identity(&self.path) == self.bound {
            std::fs::remove_file(&self.path).ok();
        }
    }
}

fn identity(path: &Path) -> Option<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

// Only a refused connection means nobody is home: binding over a live socket
// would steal it from the server answering there.
fn clear_stale_socket(path: &Path) -> io::Result<()> {
    let found = match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        found => found?,
    };
    if !found.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "something that is not a socket is at the path",
        ));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "a server is answering on the socket",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            tracing::warn!(path = %path.display(), "removing a socket nobody answers on");
            std::fs::remove_file(path)
        }
        Err(e) => Err(e),
    }
}

/// A `0700` directory beside a socket's path, removed with what is in it.
struct Staging(PathBuf);

impl Staging {
    fn beside(path: &Path) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let mut taken = io::Error::from(io::ErrorKind::AlreadyExists);
        for _ in 0..64 {
            let next = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = path.with_file_name(format!(".{}.{next}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(Self(dir)),
                // One a killed process of the same pid left behind.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => taken = e,
                Err(e) => return Err(e),
            }
        }
        Err(taken)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// A local peer: who connected, as the kernel recorded it.
#[derive(Clone)]
pub struct Credentialled(PeerCredentials);

impl Address for Credentialled {
    type Stream = Permitted<UnixStream>;
    type Listener = LocalSocket;
}

impl axum::extract::connect_info::Connected<Credentialled> for PeerCredentials {
    fn connect_info(peer: Credentialled) -> Self {
        peer.0
    }
}

impl AddrListener<Permitted<UnixStream>, Credentialled> for LocalSocket {
    async fn bind_to(_: Credentialled) -> io::Result<Self> {
        Err(made_bound())
    }

    async fn accept_stream(&self) -> io::Result<(Permitted<UnixStream>, Credentialled)> {
        let permit = permit(&self.permits).await?;
        loop {
            match self.listener.accept().await {
                Ok((stream, _)) => match wslib_host::peer_credentials(&stream) {
                    Ok(peer) => return Ok((Permitted { stream, permit }, Credentialled(peer))),
                    Err(e) => {
                        tracing::warn!("closed a peer whose credentials were unreadable: {e}")
                    }
                },
                Err(e) => backed_off(e).await,
            }
        }
    }

    fn get_local_addr(&self) -> io::Result<Credentialled> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a local socket is named by its path",
        ))
    }
}

/// Serve `router` over http/1.1 on `socket` until `stop` completes and it has
/// drained. Handlers get `ConnectInfo<PeerCredentials>`.
pub async fn serve_local(
    socket: LocalSocket,
    router: Router,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let bounds = socket.bounds;
    tracing::info!(path = %socket.path().display(), "listening");
    let handle = Handle::<Credentialled>::new();
    let mut server = Server::from_listener(socket)
        .http1_only()
        .handle(handle.clone());
    head_within(server.http_builder(), bounds.head);
    let serving = server.serve(app::<PeerCredentials>(router));
    until_stopped(serving, handle, stop, bounds.grace).await
}
