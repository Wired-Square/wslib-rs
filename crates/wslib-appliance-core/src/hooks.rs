//! The console's own calls into a proxied app under `/v1`, on a socket beside the app socket.
//!
//! **Only the console's uid is served**: any other peer is closed at accept,
//! before a byte of HTTP. The router answers only behind [`HookArrival`], so
//! mounted anywhere else it is a 404; it is never merged into `/api` or a
//! control socket. An `Appliance-Identity` header names a person in the audit
//! log and grants nothing.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, FromRef, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use wslib_appliance_store::Store;
use wslib_appliance_types::console::{ConsoleIdentity, IDENTITY_HEADER, MalformedIdentity};
use wslib_appliance_types::hooks::{AppAbout, HookIndex, NetworkNotes, NotesAsked};
use wslib_appliance_types::host::AddressConfig;

use crate::audit::Actor;
use crate::{ApiError, ApplianceState};

const NOTES_BODY: usize = 16 * 1024;

/// The longest Linux interface name, without its NUL.
const MAX_INTERFACE_LEN: usize = 15;

const HOOKS_ACTOR: &str = "console:hooks";

/// What a product knows about the box's network that the console does not; handed to `Server::notes`.
pub trait Notes: Send + Sync + 'static {
    /// A sentence shown beside `interface`, or nothing.
    fn note(&self, _interface: &str) -> Option<String> {
        None
    }

    /// One sentence per thing `change` on `interface` will break. Asked perhaps
    /// for a change never made, so it must change nothing.
    fn warnings(
        &self,
        _store: &Store,
        _interface: &str,
        _change: &AddressConfig,
    ) -> impl Future<Output = Vec<String>> + Send {
        async { Vec::new() }
    }
}

pub(crate) trait ErasedNotes: Send + Sync {
    fn note(&self, interface: &str) -> Option<String>;

    fn warnings<'a>(
        &'a self,
        store: &'a Store,
        interface: &'a str,
        change: &'a AddressConfig,
    ) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>>;
}

impl<N: Notes> ErasedNotes for N {
    fn note(&self, interface: &str) -> Option<String> {
        Notes::note(self, interface)
    }

    fn warnings<'a>(
        &'a self,
        store: &'a Store,
        interface: &'a str,
        change: &'a AddressConfig,
    ) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>> {
        Box::pin(Notes::warnings(self, store, interface, change))
    }
}

/// A product's backup hooks, for `Server::backup_hooks`; deliberately not
/// convertible into a [`Mount`](crate::Mount).
#[derive(Clone)]
pub struct BackupHooks(Arc<dyn Fn(ApplianceState) -> Router<ApplianceState> + Send + Sync>);

#[derive(Default)]
pub(crate) struct Hooks {
    pub(crate) notes: Option<Box<dyn ErasedNotes>>,
    pub(crate) backup: Option<BackupHooks>,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks")
            .field("notes", &self.notes.is_some())
            .field("backup", &self.backup.is_some())
            .finish()
    }
}

/// Proof that a request arrived on the hooks socket; `pub(crate)` for the reason `LocalAuthority` is.
#[derive(Clone)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct HookArrival;

/// Backup routes, nested under `/v1/backup`, on a state of the product's own.
pub fn backup_hooks<S, F>(routes: Router<S>, state: F) -> BackupHooks
where
    ApplianceState: FromRef<S>,
    S: Clone + Send + Sync + 'static,
    F: Fn(ApplianceState) -> S + Send + Sync + 'static,
{
    BackupHooks(Arc::new(move |chassis| {
        routes.clone().with_state(state(chassis))
    }))
}

pub fn hooks(state: &ApplianceState) -> Router {
    let mut routes = Router::new()
        .route("/v1", get(index))
        .route("/v1/about", get(about));
    if state.hooks.notes.is_some() {
        routes = routes.route(
            "/v1/notes",
            post(notes).layer(DefaultBodyLimit::max(NOTES_BODY)),
        );
    }
    if let Some(BackupHooks(backup)) = &state.hooks.backup {
        routes = routes.nest("/v1/backup", backup(state.clone()));
    }
    routes
        .method_not_allowed_fallback(crate::routes::method_not_allowed)
        .fallback(|uri: Uri| async move { no_such_hook(uri.path()) })
        .layer(axum::middleware::from_fn(arrived))
        .with_state(state.clone())
}

/// The only place [`HookArrival`] is created.
#[cfg(any(unix, test, feature = "testing"))]
pub(crate) fn marked(router: Router) -> Router {
    router.layer(axum::Extension(HookArrival))
}

async fn arrived(request: Request, next: Next) -> Response {
    match request.extensions().get::<HookArrival>() {
        Some(HookArrival) => next.run(request).await,
        None => no_such_hook(request.uri().path()).into_response(),
    }
}

fn no_such_hook(path: &str) -> ApiError {
    ApiError::NotFound(format!("no such hook: {path}"))
}

async fn index(State(app): State<ApplianceState>) -> Json<HookIndex> {
    let mut index = HookIndex::default();
    index.notes = app.hooks.notes.is_some();
    index.backup = app.hooks.backup.is_some();
    Json(index)
}

async fn about(State(app): State<ApplianceState>) -> Json<AppAbout> {
    let rows = app.about.rows(&app.store).await;
    let mut about = AppAbout::default();
    about.product = app.about.product.clone();
    about.version = app.about.version.clone();
    about.facts = rows.facts;
    about.subsystems = rows.subsystems;
    Json(about)
}

async fn notes(
    State(app): State<ApplianceState>,
    Json(asked): Json<NotesAsked>,
) -> Result<Json<NetworkNotes>, ApiError> {
    let Some(product) = &app.hooks.notes else {
        return Err(no_such_hook("/v1/notes"));
    };
    if !is_interface_name(&asked.interface) {
        return Err(ApiError::BadRequest(format!(
            "an interface is named by 1 to {MAX_INTERFACE_LEN} visible ASCII characters, with \
             no `/` or `:`, and is not `.` or `..`"
        )));
    }
    let mut answer = NetworkNotes::default();
    answer.note = product.note(&asked.interface);
    if let Some(change) = &asked.change {
        change.validate().map_err(ApiError::BadRequest)?;
        answer.warnings = product.warnings(&app.store, &asked.interface, change).await;
    }
    Ok(Json(answer))
}

fn is_interface_name(name: &str) -> bool {
    (1..=MAX_INTERFACE_LEN).contains(&name.len())
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b':')
}

/// Refused when malformed, sent twice or a reserved name.
pub(crate) fn asserted(headers: &HeaderMap) -> Result<Option<ConsoleIdentity>, ApiError> {
    let mut values = headers.get_all(IDENTITY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let refused = |e: MalformedIdentity| ApiError::BadRequest(e.to_string());
    let malformed = |why| refused(MalformedIdentity::because(why));
    if values.next().is_some() {
        return Err(malformed("sent more than once"));
    }
    let identity = value
        .to_str()
        .map_err(|_| malformed("not visible ASCII"))?
        .parse::<ConsoleIdentity>()
        .map_err(refused)?;
    if wslib_appliance_auth::is_reserved_username(&identity.username) {
        return Err(malformed("a user name reserved for the appliance"));
    }
    Ok(Some(identity))
}

/// Who a hook's audit row names: the person in `IDENTITY_HEADER`, read only on
/// the hooks socket, or `console:hooks`. Not a rung: it authorises nothing.
#[derive(Debug, Clone)]
pub struct HookCaller {
    actor: String,
    actor_id: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for HookCaller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        let named = match parts.extensions.get::<HookArrival>() {
            Some(HookArrival) => asserted(&parts.headers)?,
            None => None,
        };
        Ok(match named {
            Some(who) => Self {
                actor: who.username,
                actor_id: Some(format!("console:{}", who.id)),
            },
            None => Self {
                actor: HOOKS_ACTOR.to_string(),
                actor_id: None,
            },
        })
    }
}

impl Actor for HookCaller {
    fn actor(&self) -> &str {
        &self.actor
    }

    fn actor_id(&self) -> Option<&str> {
        self.actor_id.as_deref()
    }
}

#[cfg(unix)]
pub use listener::serve_hooks_socket;

#[cfg(unix)]
mod listener {
    use std::path::PathBuf;

    use axum::Router;
    use axum::extract::connect_info::Connected;
    use axum::serve::Listener;
    use tokio::net::UnixStream;
    use tokio_util::sync::CancellationToken;

    use crate::ServeError;
    use crate::bounded::Bounded;
    use crate::console::{HEADER_READ_TIMEOUT, refuse_unusable};
    use crate::control::socket::Peers;
    use crate::control::{bind_socket, serve_http1};

    /// Serve `hooks` to `console_uid` alone; `path`'s directory is not created,
    /// and the overflow uid is refused.
    pub async fn serve_hooks_socket(
        hooks: Router,
        path: PathBuf,
        console_uid: u32,
        stop: CancellationToken,
    ) -> Result<(), ServeError> {
        refuse_unusable(&path, console_uid)?;
        let (listener, _unlink) = bind_socket(&path)?;
        tracing::info!(path = %path.display(), console_uid, "hooks socket listening");
        let console = ConsoleOnly {
            peers: Peers(listener),
            console_uid,
        };
        serve_http1::<ConsoleOnly, FromConsole>(
            console,
            super::marked(hooks),
            HEADER_READ_TIMEOUT,
            stop,
        )
        .await
    }

    struct ConsoleOnly {
        peers: Peers,
        console_uid: u32,
    }

    #[derive(Clone)]
    struct FromConsole;

    impl Connected<Bounded<ConsoleOnly>> for FromConsole {
        fn connect_info(_: Bounded<ConsoleOnly>) -> Self {
            Self
        }
    }

    impl Listener for ConsoleOnly {
        type Io = UnixStream;
        type Addr = ();

        async fn accept(&mut self) -> (UnixStream, ()) {
            loop {
                let (stream, uid) = Listener::accept(&mut self.peers).await;
                if uid == Some(self.console_uid) {
                    return (stream, ());
                }
                tracing::debug!(
                    ?uid,
                    "closed a hooks connection from a peer not the console"
                );
            }
        }

        fn local_addr(&self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a hooks socket is named by its path",
            ))
        }
    }
}
