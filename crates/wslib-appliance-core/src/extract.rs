//! Authorisation as extractors, so the access a route needs is in its signature: the rungs
//! [`Viewer`], [`Operator`], [`Admin`], [`SessionAdmin`] and [`HostAdmin`] are the only way
//! to an [`Identity`]. A control socket's [`LocalAuthority`], inserted only by its listener,
//! satisfies every *role* up to its ceiling but not every *rung*: [`SessionAdmin`] and
//! [`HostAdmin`] refuse it, and no resolver is asked about it. `LocalAuthority` is not
//! exported: a consumer naming it could layer it onto its routes and void every check.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use wslib_appliance_store::Store;
use wslib_appliance_store::sqlx::{Sqlite, Transaction};
use wslib_appliance_types::{Role, User};

use crate::audit::Actor;
use crate::state::{ApplianceState, SessionRows};
use crate::{AboveAdmin, ApiError};

/// The session cookie, one name for every product. Two appliances on one origin whose
/// base paths nest are unsupported: the inner one is sent both values and answers 401.
pub const SESSION_COOKIE: &str = "appliance_session";

/// The audit actor for [`Identity::Local`] and a socket peer without credentials; a
/// named peer is `control-socket:<account>` or a `uid=`/`sid=` form. Never a username.
pub const LOCAL_ACTOR: &str = "control-socket";

/// Proof a request arrived over a control socket; a consumer asks [`Identity::is_local`].
#[derive(Clone, Debug)]
pub(crate) struct LocalAuthority {
    pub(crate) ceiling: Role,
    pub(crate) peer: Option<String>,
}

/// An account a [`ResolveCaller`] vouches for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// Permanent and never empty. Only a `Callers::resolved_from_store` resolver may
    /// return a store id: both share the audit log's `actor_id`.
    pub id: String,
    /// The current name, for display and audit text only.
    pub username: String,
    pub role: Role,
    /// When the account last proved its password, if the resolver knows; see
    /// [`reauthenticate`](crate::reauthenticate).
    pub reauthenticated_at: Option<DateTime<Utc>>,
}

/// Who a request comes from, asked once per rung; never asked about a control socket.
pub trait ResolveCaller: Send + Sync + 'static {
    /// The account behind `request`, `None` for nobody, or the refusal. Peer credentials
    /// are whatever the serving listener put in `request.extensions`; this crate adds none.
    fn resolve(
        &self,
        request: &Parts,
    ) -> impl Future<Output = Result<Option<Principal>, ApiError>> + Send;
}

type Resolving<'a> = Pin<Box<dyn Future<Output = Result<Option<Principal>, ApiError>> + Send + 'a>>;

/// [`ResolveCaller`], object-safe.
trait Resolve: Send + Sync {
    fn resolve<'a>(&'a self, request: &'a Parts) -> Resolving<'a>;
}

impl<R: ResolveCaller> Resolve for R {
    fn resolve<'a>(&'a self, request: &'a Parts) -> Resolving<'a> {
        Box::pin(ResolveCaller::resolve(self, request))
    }
}

#[derive(Clone)]
pub(crate) struct Resolver(Arc<dyn Resolve>);

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolver")
    }
}

/// How a backend identifies callers off the socket: the session cookie, a resolver, or not at all.
#[doc(hidden)]
pub struct Callers {
    pub(crate) sessions: SessionRows,
    pub(crate) resolver: Option<Resolver>,
    pub(crate) vouches: Vouches,
}

/// Whose accounts a resolver's principals are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Vouches {
    Unsaid,
    /// The store's `users` rows, so their count says whether the box is claimed.
    StoreAccounts,
    Console,
    Ingress,
}

impl Callers {
    pub fn nobody() -> Self {
        Self {
            sessions: SessionRows::default(),
            resolver: None,
            vouches: Vouches::Unsaid,
        }
    }

    /// The session cookie, whose every account is one of the store's.
    #[cfg(feature = "sessions")]
    pub fn sessions(sessions: wslib_appliance_auth::Sessions) -> Self {
        Self {
            sessions: SessionRows(Some(sessions)),
            vouches: Vouches::StoreAccounts,
            ..Self::nobody()
        }
    }

    /// Callers a host resolves itself. A host whose principals are the store's accounts
    /// takes [`resolved_from_store`](Self::resolved_from_store).
    /// [`reauthenticate`](crate::reauthenticate) takes its callers' recent
    /// `reauthenticated_at` as proof, though never for a change of second factors.
    pub fn resolved_by(resolver: impl ResolveCaller) -> Self {
        Self {
            resolver: Some(Resolver(Arc::new(resolver))),
            ..Self::nobody()
        }
    }

    /// [`resolved_by`](Self::resolved_by), vouching only for the store's `users` rows, so
    /// the backend offers [`Unclaimed`] until the first exists. The host promises every
    /// principal is an enabled row whose session postdates its `sessions_valid_from` and
    /// whose password hash is the one the account signs in with, which re-authentication
    /// proves against. Its first-account write re-checks the count
    /// (`Store::create_first_user`, or [`Unclaimed::hold`]); break either and the
    /// first-run restore stays open.
    pub fn resolved_from_store(resolver: impl ResolveCaller) -> Self {
        Self {
            vouches: Vouches::StoreAccounts,
            ..Self::resolved_by(resolver)
        }
    }
}

/// Who is asking. Read it through its methods rather than a match: it may grow.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Identity {
    /// A signed-in account, re-read from the database on this request.
    Session(User),
    /// An account a [`ResolveCaller`] vouched for on this request.
    Resolved(Principal),
    /// The product acting as itself under the control socket's name, for a
    /// task or an audit row; a request over a socket is [`Socket`](Self::Socket).
    Local,
    /// As [`Local`](Self::Local), under the actor a socket's peer is named by.
    LocalPeer(String),
    /// A request over a control socket, with its ceiling and its peer's audit actor.
    #[non_exhaustive]
    Socket { ceiling: Role, peer: Option<String> },
}

impl Identity {
    /// What the audit log records as having done this.
    pub fn actor(&self) -> &str {
        match self {
            Self::Session(user) => &user.username,
            Self::Resolved(principal) => &principal.username,
            Self::Local | Self::Socket { peer: None, .. } => LOCAL_ACTOR,
            Self::LocalPeer(actor)
            | Self::Socket {
                peer: Some(actor), ..
            } => actor,
        }
    }

    /// The account's permanent id; the control socket has none.
    pub fn account_id(&self) -> Option<&str> {
        match self {
            Self::Session(user) => Some(&user.id),
            Self::Resolved(principal) => Some(&principal.id),
            Self::Local | Self::LocalPeer(_) | Self::Socket { .. } => None,
        }
    }

    /// The store account behind a session, never a resolver's. Not a rung, so a route
    /// can answer 404 ("not anybody") rather than [`SessionAdmin`]'s 403.
    pub fn user(&self) -> Option<&User> {
        match self {
            Self::Session(user) => Some(user),
            Self::Resolved(_) | Self::Local | Self::LocalPeer(_) | Self::Socket { .. } => None,
        }
    }

    fn role(&self) -> Option<Role> {
        match self {
            Self::Session(user) => Some(user.role),
            Self::Resolved(principal) => Some(principal.role),
            Self::Local | Self::LocalPeer(_) | Self::Socket { .. } => None,
        }
    }

    /// Never the socket, and nobody under [`AboveAdmin::Absent`].
    pub fn is_host_admin(&self) -> bool {
        self.role() == Some(Role::HostAdmin)
    }

    /// Whether the Viewer, Operator, Admin or HostAdmin rung would admit this caller, the
    /// product acting as itself held as an Admin-ceiling socket. For [`SessionAdmin`] ask
    /// `satisfies(Role::Admin) && !is_local()`. Raised routes are not considered.
    pub fn satisfies(&self, role: Role) -> bool {
        let held = match self {
            Self::Session(User { role, .. }) | Self::Resolved(Principal { role, .. }) => *role,
            Self::Socket { ceiling, .. } => *ceiling,
            Self::Local | Self::LocalPeer(_) => Role::Admin,
        };
        held.allows(role)
    }

    /// The store account behind a session, or 404: anybody else is not being refused.
    pub(crate) fn signed_in(&self) -> Result<&User, ApiError> {
        self.user().ok_or_else(|| {
            ApiError::NotFound(match self {
                Self::Resolved(_) => "this caller has no session on this box".to_string(),
                _ => "the control socket is not signed in as anybody".to_string(),
            })
        })
    }

    /// A control socket, or the product acting as itself. It implies no role.
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local | Self::LocalPeer(_) | Self::Socket { .. })
    }
}

impl Actor for Identity {
    fn actor(&self) -> &str {
        Identity::actor(self)
    }

    fn actor_id(&self) -> Option<&str> {
        self.account_id()
    }
}

/// The account behind a request off the socket, held as Admin at most under [`AboveAdmin::Absent`].
async fn account(parts: &Parts, app: &ApplianceState) -> Result<Identity, ApiError> {
    let mut identity = unclamped(parts, app).await?;
    if app.above_admin == AboveAdmin::Absent {
        match &mut identity {
            Identity::Session(User { role, .. }) | Identity::Resolved(Principal { role, .. }) => {
                *role = (*role).min(Role::Admin);
            }
            Identity::Local | Identity::LocalPeer(_) | Identity::Socket { .. } => {}
        }
    }
    Ok(identity)
}

async fn unclamped(parts: &Parts, app: &ApplianceState) -> Result<Identity, ApiError> {
    let Some(Resolver(resolver)) = &app.resolver else {
        return session_user(parts, app).await.map(Identity::Session);
    };
    let principal = resolver
        .resolve(parts)
        .await?
        .ok_or(ApiError::Unauthenticated)?;
    if principal.id.is_empty() {
        return Err(ApiError::internal(
            "resolve the caller",
            &"the resolver vouched for an account with no id",
        ));
    }
    Ok(Identity::Resolved(principal))
}

#[cfg(feature = "sessions")]
async fn session_user(parts: &Parts, app: &ApplianceState) -> Result<User, ApiError> {
    const COOKIE: wslib_auth::SessionCookie = wslib_auth::SessionCookie::new(SESSION_COOKIE);

    let sessions = app.sessions.get().ok_or(ApiError::Unauthenticated)?;
    let token = COOKIE
        .token_in(&parts.headers)
        .ok_or(ApiError::Unauthenticated)?;
    Ok(sessions.resolve(&app.store, &token).await?)
}

#[cfg(not(feature = "sessions"))]
async fn session_user(_parts: &Parts, _app: &ApplianceState) -> Result<User, ApiError> {
    Err(ApiError::Unauthenticated)
}

/// A rung's stance on the control socket, declared per rung so none is added without one.
#[derive(Clone, Copy)]
enum Socket {
    /// When its ceiling allows the role, even on a box with no accounts.
    Satisfies,
    Refused,
}

/// The one place the socket's authority over the ladder is decided; [`Unclaimed`]
/// refuses the marker on its own.
async fn authorise<S>(
    parts: &mut Parts,
    state: &S,
    needed: Role,
    socket: Socket,
) -> Result<Identity, ApiError>
where
    ApplianceState: FromRef<S>,
    S: Send + Sync,
{
    let (needed, socket) = match parts.extensions.get::<HostAdminOnly>() {
        Some(_) => (needed.max(Role::HostAdmin), Socket::Refused),
        None => (needed, socket),
    };
    // Before the cookie or the resolver, which are never asked about the socket.
    if let Some(&LocalAuthority { ceiling, ref peer }) = parts.extensions.get() {
        return match socket {
            Socket::Refused => Err(ApiError::Forbidden(
                "this operation needs an account behind it, which the control socket \
                 does not have."
                    .to_string(),
            )),
            Socket::Satisfies if ceiling.allows(needed) => Ok(Identity::Socket {
                ceiling,
                peer: peer.clone(),
            }),
            Socket::Satisfies => Err(ApiError::Forbidden(format!(
                "this needs {needed}, and this control socket goes no higher than {ceiling}"
            ))),
        };
    }

    let identity = account(parts, &ApplianceState::from_ref(state)).await?;
    let role = identity.role().ok_or(ApiError::Unauthenticated)?;
    if role.allows(needed) {
        Ok(identity)
    } else {
        Err(ApiError::Forbidden(format!(
            "this needs {needed}, and {} is {role}",
            identity.actor()
        )))
    }
}

/// Declares one rung of the ladder as an extractor.
macro_rules! rung {
    ($(#[$doc:meta])* $name:ident => $needed:expr, socket: $socket:expr) => {
        $(#[$doc])*
        ///
        /// Yields the [`Identity`], for a handler that needs to know who.
        #[derive(Clone, Debug)]
        pub struct $name(pub Identity);

        impl<S> FromRequestParts<S> for $name
        where
            ApplianceState: FromRef<S>,
            S: Send + Sync,
        {
            type Rejection = ApiError;

            async fn from_request_parts(
                parts: &mut Parts,
                state: &S,
            ) -> Result<Self, Self::Rejection> {
                authorise(parts, state, $needed, $socket).await.map(Self)
            }
        }
    };
}

rung! {
    /// Signed in at all. The floor for anything that is not public.
    Viewer => Role::Viewer, socket: Socket::Satisfies
}

rung! {
    /// A Viewer who can acknowledge, and nothing else; configuration is [`Admin`].
    Operator => Role::Operator, socket: Socket::Satisfies
}

rung! {
    /// An administrator, **or** a control socket whose ceiling is Admin.
    Admin => Role::Admin, socket: Socket::Satisfies
}

rung! {
    /// An administrator with an account, and **never** the control socket, whatever its
    /// ceiling: group membership grants a way in, not stopping the box or reading the
    /// database. It withholds a request, not the capability: a socket can reset an
    /// administrator's password and sign in, leaving an audit row. On a backend with
    /// neither sessions nor a [`ResolveCaller`], nobody satisfies it.
    SessionAdmin => Role::Admin, socket: Socket::Refused
}

rung! {
    /// A host administrator with an account, and **never** the control socket,
    /// for the same reason as [`SessionAdmin`]: the socket's ceiling is Admin.
    HostAdmin => Role::HostAdmin, socket: Socket::Refused
}

/// Raises every rung on `routes`, fallback included, to [`HostAdmin`]. A route with no
/// rung is not touched, so keep public and [`Unclaimed`] routes out of `routes`.
pub fn host_admin_only<S>(routes: axum::Router<S>) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    routes.layer(axum::Extension(HostAdminOnly))
}

/// Private, so it can only raise a rung.
#[derive(Clone, Copy)]
struct HostAdminOnly;

/// A box nobody has claimed, reached from the network; not a rung. Refuses the control
/// socket, a backend without onboarding or whose callers are not the store's accounts
/// (403), and a claimed box (409).
/// Two browsers can both pass it, so a write re-checks inside itself:
/// `Store::create_first_user`, or [`Unclaimed::hold`].
#[derive(Debug)]
pub struct Unclaimed(pub(crate) ());

impl Unclaimed {
    /// The audit actor for a write on a box with no accounts, the same on every product.
    pub fn actor(&self) -> &'static str {
        "onboarding"
    }

    /// Begin the write under `BEGIN IMMEDIATE` and re-check, under that lock, that nobody
    /// claimed the box in between; 409 if somebody did.
    pub async fn hold<'a>(&self, store: &'a Store) -> Result<Transaction<'a, Sqlite>, ApiError> {
        let mut tx = store.begin().await?;
        if Store::user_count_in(&mut tx).await? > 0 {
            return Err(claimed());
        }
        Ok(tx)
    }
}

impl Actor for Unclaimed {
    fn actor(&self) -> &str {
        Unclaimed::actor(self)
    }
}

impl<S> FromRequestParts<S> for Unclaimed
where
    ApplianceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if parts.extensions.get::<LocalAuthority>().is_some() {
            return Err(ApiError::Forbidden(
                "this is for a browser reaching a box that has no accounts, not the control \
                 socket"
                    .to_string(),
            ));
        }
        let app = ApplianceState::from_ref(state);
        if !app.onboarding {
            return Err(ApiError::Forbidden(
                "this appliance does not offer its first account to a browser".to_string(),
            ));
        }
        if app.store.user_count().await? > 0 {
            return Err(claimed());
        }
        Ok(Self(()))
    }
}

/// What a box that already has an account says to a route for one that has none.
pub fn claimed() -> ApiError {
    ApiError::Conflict("this appliance already has an account; sign in instead".to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::backend::LogsRung;
    use crate::probe::{
        IS_HOST_ADMIN, Probe, RAISED, SESSION_ADMIN, UNCLAIMED, WHO, rung, satisfies,
    };
    use crate::testing::{body_json, body_text};
    use axum::http::StatusCode;

    #[test]
    fn a_socket_is_audited_as_itself_or_its_peer_never_an_appliance_username() {
        let named = "control-socket:operator".to_string();
        let socket = |peer| Identity::Socket {
            ceiling: Role::Admin,
            peer,
        };
        let identities = [
            Identity::Local,
            Identity::LocalPeer(named.clone()),
            socket(None),
            socket(Some(named.clone())),
        ];
        let actors: Vec<&str> = identities.iter().map(Identity::actor).collect();
        assert_eq!(actors, [LOCAL_ACTOR, &named, LOCAL_ACTOR, &named]);
        for identity in identities {
            assert!(identity.is_local());
            assert_eq!(identity.account_id(), None);
        }
    }

    #[test]
    fn no_new_account_may_take_a_name_that_passes_for_a_socket() {
        for reserved in [
            LOCAL_ACTOR.to_string(),
            LOCAL_ACTOR.to_uppercase(),
            format!("{LOCAL_ACTOR}:root"),
            format!("{LOCAL_ACTOR}\u{ff1a}root"),
            "site:admin".to_string(),
        ] {
            assert!(
                wslib_appliance_auth::is_reserved_username(&reserved),
                "{reserved:?}"
            );
        }
        for allowed in ["admin", "socket-operator", "control", "é-control-socket"] {
            assert!(
                !wslib_appliance_auth::is_reserved_username(allowed),
                "{allowed:?}"
            );
        }
    }

    #[test]
    fn no_new_account_may_take_the_unclaimed_actor() {
        assert!(wslib_appliance_auth::is_reserved_username(
            Unclaimed(()).actor()
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_socket_with_peer_credentials_is_audited_as_them_and_one_without_as_the_socket() {
        let probe = Probe::new().await;
        let mut actors = Vec::new();
        for response in probe.local(Role::Viewer, WHO).await {
            actors.push(body_text(response).await);
        }
        assert_eq!(
            actors,
            [
                LOCAL_ACTOR.to_string(),
                format!("{LOCAL_ACTOR}:uid={}", crate::probe::NAMELESS_UID)
            ]
        );
    }

    /// A backend that tells callers apart and one that does not.
    async fn with_and_without_callers() -> [Probe; 2] {
        [
            Probe::new().await,
            Probe::callerless(LogsRung::SessionAdmin).await,
        ]
    }

    #[tokio::test]
    async fn a_socket_satisfies_every_role_up_to_its_ceiling() {
        for probe in with_and_without_callers().await {
            for ceiling in Role::LADDER {
                for needed in socket_roles().filter(|&n| ceiling.allows(n)) {
                    for response in probe.local(ceiling, &rung(needed)).await {
                        assert_eq!(
                            response.status(),
                            StatusCode::OK,
                            "{ceiling} socket, {needed}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn a_socket_is_refused_every_role_above_its_ceiling_and_told_the_ceiling() {
        for probe in with_and_without_callers().await {
            for ceiling in Role::LADDER {
                for needed in socket_roles().filter(|&n| !ceiling.allows(n)) {
                    for response in probe.local(ceiling, &rung(needed)).await {
                        assert_eq!(
                            response.status(),
                            StatusCode::FORBIDDEN,
                            "{ceiling} socket, {needed}"
                        );
                        let error = body_json(response).await["error"].to_string();
                        assert!(
                            error.contains(&format!(
                                "needs {needed}, and this control socket goes no higher than {ceiling}"
                            )),
                            "{error}"
                        );
                    }
                }
            }
        }
    }

    /// The roles whose rungs take a socket at all.
    fn socket_roles() -> impl Iterator<Item = Role> {
        Role::LADDER.into_iter().filter(|&n| Role::Admin.allows(n))
    }

    #[tokio::test]
    async fn session_admin_and_host_admin_are_refused_to_a_socket_whatever_its_ceiling() {
        let host_admin = rung(Role::HostAdmin);
        for probe in with_and_without_callers().await {
            for ceiling in Role::LADDER {
                for path in [SESSION_ADMIN, &host_admin, RAISED] {
                    for response in probe.local(ceiling, path).await {
                        assert_eq!(
                            response.status(),
                            StatusCode::FORBIDDEN,
                            "{ceiling} socket, {path}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn only_a_host_admin_reaches_the_host_admin_rung_or_a_raised_route() {
        let probe = Probe::new().await;
        let host_admin = rung(Role::HostAdmin);
        for path in [host_admin.as_str(), RAISED] {
            assert_eq!(
                probe.https(path, None).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let admin = probe.token(Role::Admin).await;
        let owner = probe.token(Role::HostAdmin).await;
        for path in [host_admin.as_str(), RAISED] {
            let refused = probe.https(path, Some(&admin)).await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
            let error = body_json(refused).await["error"].to_string();
            assert!(error.contains("needs hostadmin"), "{error}");
            assert_eq!(
                probe.https(path, Some(&owner)).await.status(),
                StatusCode::OK,
                "{path}"
            );
        }
        assert_eq!(
            probe.https(&rung(Role::Admin), Some(&owner)).await.status(),
            StatusCode::OK,
            "a host admin is at least an admin"
        );
    }

    /// Admin routes on raisable mounts, one on a plain mount, and an empty raisable mount.
    async fn raisable_probe(above_admin: AboveAdmin) -> Probe {
        use crate::Mount;
        use axum::routing::get;

        let router = |name: &str| {
            axum::Router::new().route(&format!("/probe/{name}"), get(|_: Admin| async {}))
        };
        let mount = |name: &str| Mount::from(router(name));
        let fallback = Mount::from(router("raisable").fallback(|_: Admin| async {}));
        Probe::hosting(
            above_admin,
            vec![
                mount("host-raisable").raisable(),
                Mount::from(axum::Router::new()).raisable(),
            ],
            |chassis| {
                chassis
                    .api(mount("api-raisable").raisable())
                    .api(mount("plain"))
                    .route("/prefixed", fallback.raisable())
            },
        )
        .await
    }

    const RAISABLE: [&str; 4] = [
        "/api/probe/host-raisable",
        "/api/probe/api-raisable",
        "/prefixed/probe/raisable",
        "/prefixed/anything-else",
    ];
    const PLAIN: &str = "/api/probe/plain";

    #[tokio::test]
    async fn raising_puts_every_raisable_mount_at_host_admin_and_nothing_else() {
        let probe = raisable_probe(AboveAdmin::Raising).await;
        let admin = probe.token(Role::Admin).await;
        let owner = probe.token(Role::HostAdmin).await;
        let raisable = RAISABLE.map(|path| (path, StatusCode::FORBIDDEN));
        for (path, admin_status) in [(PLAIN, StatusCode::OK)].into_iter().chain(raisable) {
            assert_eq!(
                probe.https(path, Some(&admin)).await.status(),
                admin_status,
                "{path}"
            );
            assert_eq!(
                probe.https(path, Some(&owner)).await.status(),
                StatusCode::OK,
                "{path}"
            );
            // The control socket serves `/api` alone.
            if path.starts_with("/api/") {
                for response in probe.local(Role::Admin, path).await {
                    assert_eq!(response.status(), admin_status, "{path} over the socket");
                }
            }
        }
    }

    #[tokio::test]
    async fn present_and_absent_raise_no_mount() {
        for above_admin in [AboveAdmin::Present, AboveAdmin::Absent] {
            let probe = raisable_probe(above_admin).await;
            let admin = probe.token(Role::Admin).await;
            for path in RAISABLE.into_iter().chain([PLAIN]) {
                assert_eq!(
                    probe.https(path, Some(&admin)).await.status(),
                    StatusCode::OK,
                    "{above_admin:?} {path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn absent_holds_a_stored_host_admin_as_admin() {
        let probe = Probe::hosting(AboveAdmin::Absent, Vec::new(), std::convert::identity).await;
        let owner = probe.token(Role::HostAdmin).await;
        assert_eq!(
            probe.https(&rung(Role::Admin), Some(&owner)).await.status(),
            StatusCode::OK
        );
        for path in [rung(Role::HostAdmin).as_str(), RAISED] {
            let refused = probe.https(path, Some(&owner)).await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
            let error = body_json(refused).await["error"].to_string();
            assert!(error.contains("and hostadmin is admin"), "{error}");
            for response in probe.local(Role::Admin, path).await {
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{path} over the socket"
                );
            }
        }
        assert_eq!(
            body_text(probe.https(IS_HOST_ADMIN, Some(&owner)).await).await,
            "false"
        );

        let present = Probe::new().await;
        let owner = present.token(Role::HostAdmin).await;
        assert_eq!(
            body_text(present.https(IS_HOST_ADMIN, Some(&owner)).await).await,
            "true"
        );
    }

    #[tokio::test]
    async fn absent_holds_a_resolvers_host_admin_as_admin() {
        let (resolver, _) = vouching(|| Ok(Some(principal(Role::HostAdmin))));
        let probe = Probe::resolving_under(AboveAdmin::Absent, resolver).await;
        for path in [rung(Role::HostAdmin).as_str(), RAISED] {
            assert_eq!(
                probe.https(path, None).await.status(),
                StatusCode::FORBIDDEN,
                "{path}"
            );
        }
        assert_eq!(
            body_text(probe.https(IS_HOST_ADMIN, None).await).await,
            "false"
        );
    }

    #[derive(Debug)]
    enum Caller<'a> {
        Socket(Role),
        Https(Option<&'a str>),
    }

    /// For every role, what its rung answers `caller` and what `satisfies`
    /// says to the same caller behind the Viewer rung.
    async fn rung_and_satisfies(probe: &Probe, caller: Caller<'_>, case: &str) {
        for needed in Role::LADDER {
            let (rungs, says) = match caller {
                Caller::Socket(ceiling) => (
                    probe.local(ceiling, &rung(needed)).await,
                    probe.local(ceiling, &satisfies(needed)).await,
                ),
                Caller::Https(account) => (
                    vec![probe.https(&rung(needed), account).await],
                    vec![probe.https(&satisfies(needed), account).await],
                ),
            };
            for (rung, says) in rungs.into_iter().zip(says) {
                let admitted = rung.status() == StatusCode::OK;
                assert_eq!(
                    body_text(says).await,
                    admitted.to_string(),
                    "{case}, {caller:?}, {needed}"
                );
            }
        }
    }

    #[tokio::test]
    async fn satisfies_agrees_with_the_rungs_for_every_caller_role_and_mode() {
        for above_admin in [AboveAdmin::Absent, AboveAdmin::Present, AboveAdmin::Raising] {
            let probe = Probe::hosting(above_admin, Vec::new(), std::convert::identity).await;
            let vouched = Arc::new(std::sync::Mutex::new(Role::Viewer));
            let held = Arc::clone(&vouched);
            let (resolver, _) = vouching(move || Ok(Some(principal(*held.lock().unwrap()))));
            let resolved = Probe::resolving_under(above_admin, resolver).await;
            let case = format!("{above_admin:?}");
            for role in Role::LADDER {
                rung_and_satisfies(&probe, Caller::Socket(role), &case).await;

                let account = probe.token(role).await;
                rung_and_satisfies(&probe, Caller::Https(Some(&account)), &case).await;

                *vouched.lock().unwrap() = role;
                let case = format!("{above_admin:?}, a resolver's principal at {role}");
                rung_and_satisfies(&resolved, Caller::Https(None), &case).await;
            }
        }
    }

    #[test]
    fn a_product_acting_as_itself_satisfies_every_role_but_host_admin() {
        for who in [Identity::Local, Identity::LocalPeer("task".to_string())] {
            for role in Role::LADDER {
                assert_eq!(
                    who.satisfies(role),
                    role != Role::HostAdmin,
                    "{who:?}, {role}"
                );
            }
        }
    }

    #[tokio::test]
    async fn unclaimed_is_refused_to_a_socket_whatever_its_ceiling() {
        for probe in with_and_without_callers().await {
            for ceiling in Role::LADDER {
                for response in probe.local(ceiling, UNCLAIMED).await {
                    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{ceiling} socket");
                }
            }
        }
    }

    #[tokio::test]
    async fn only_a_chassis_whose_callers_are_the_stores_accounts_offers_an_unclaimed_box() {
        let stores = Probe::new().await;
        assert_eq!(stores.https(UNCLAIMED, None).await.status(), StatusCode::OK);
        let callerless = Probe::callerless(LogsRung::SessionAdmin).await;
        assert_eq!(
            callerless.https(UNCLAIMED, None).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// Answers every request with what `answer` says, counting the requests.
    struct Vouching<F> {
        answer: F,
        asked: Arc<AtomicUsize>,
    }

    impl<F> ResolveCaller for Vouching<F>
    where
        F: Fn() -> Result<Option<Principal>, ApiError> + Send + Sync + 'static,
    {
        async fn resolve(&self, _: &Parts) -> Result<Option<Principal>, ApiError> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            (self.answer)()
        }
    }

    fn principal(role: Role) -> Principal {
        Principal {
            id: format!("console:{role}"),
            username: format!("asserted-{role}"),
            role,
            reauthenticated_at: None,
        }
    }

    fn vouching<F>(answer: F) -> (Vouching<F>, Arc<AtomicUsize>) {
        let asked = Arc::<AtomicUsize>::default();
        let resolver = Vouching {
            answer,
            asked: Arc::clone(&asked),
        };
        (resolver, asked)
    }

    async fn resolving(
        answer: impl Fn() -> Result<Option<Principal>, ApiError> + Send + Sync + 'static,
    ) -> (Probe, Arc<AtomicUsize>) {
        let (resolver, asked) = vouching(answer);
        (Probe::resolving(resolver).await, asked)
    }

    /// Every rung, the raised route and the identity route.
    fn every_rung() -> Vec<String> {
        Role::LADDER
            .map(rung)
            .into_iter()
            .chain([SESSION_ADMIN, RAISED, WHO].map(String::from))
            .collect()
    }

    #[tokio::test]
    async fn a_resolvers_account_is_held_against_the_ladder_as_a_signed_in_one_is() {
        for role in Role::LADDER {
            let (probe, _) = resolving(move || Ok(Some(principal(role)))).await;
            for needed in Role::LADDER {
                let response = probe.https(&rung(needed), None).await;
                if role.allows(needed) {
                    assert_eq!(response.status(), StatusCode::OK, "{role}, {needed}");
                } else {
                    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{role}, {needed}");
                    let error = body_json(response).await["error"].to_string();
                    assert!(
                        error.contains(&format!("needs {needed}, and asserted-{role} is {role}")),
                        "{error}"
                    );
                }
            }
            for (path, needed) in [(SESSION_ADMIN, Role::Admin), (RAISED, Role::HostAdmin)] {
                let expected = match role.allows(needed) {
                    true => StatusCode::OK,
                    false => StatusCode::FORBIDDEN,
                };
                assert_eq!(
                    probe.https(path, None).await.status(),
                    expected,
                    "{role}, {path}"
                );
            }
            let who = probe.https(WHO, None).await;
            assert_eq!(body_text(who).await, format!("asserted-{role}"));
        }
    }

    #[tokio::test]
    async fn a_resolver_vouching_for_nobody_is_refused_by_every_rung() {
        let (probe, asked) = resolving(|| Ok(None)).await;
        for path in every_rung() {
            assert_eq!(
                probe.https(&path, None).await.status(),
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
        }
        assert_eq!(asked.load(Ordering::SeqCst), every_rung().len());
    }

    #[tokio::test]
    async fn a_resolver_error_is_a_refusal_never_a_pass() {
        let (failing, _) = resolving(|| {
            Err(ApiError::internal(
                "resolve the caller",
                &"the identity channel is down",
            ))
        })
        .await;
        let (no_id, _) = resolving(|| {
            Ok(Some(Principal {
                id: String::new(),
                ..principal(Role::HostAdmin)
            }))
        })
        .await;
        for probe in [failing, no_id] {
            for path in every_rung() {
                assert_eq!(
                    probe.https(&path, None).await.status(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "{path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_resolver_is_never_asked_about_the_socket_so_it_cannot_raise_one() {
        let (probe, asked) = resolving(|| Ok(Some(principal(Role::HostAdmin)))).await;
        let host_admin = rung(Role::HostAdmin);
        for ceiling in Role::LADDER {
            for needed in socket_roles() {
                let expected = match ceiling.allows(needed) {
                    true => StatusCode::OK,
                    false => StatusCode::FORBIDDEN,
                };
                for response in probe.local(ceiling, &rung(needed)).await {
                    assert_eq!(response.status(), expected, "{ceiling} socket, {needed}");
                }
            }
            for path in [SESSION_ADMIN, &host_admin, RAISED, UNCLAIMED] {
                for response in probe.local(ceiling, path).await {
                    assert_eq!(
                        response.status(),
                        StatusCode::FORBIDDEN,
                        "{ceiling} socket, {path}"
                    );
                }
            }
        }
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_resolver_not_declared_to_vouch_for_the_stores_accounts_offers_no_first_account() {
        let (probe, asked) = resolving(|| Ok(None)).await;
        assert_eq!(
            probe.https(UNCLAIMED, None).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    async fn resolving_from_store(onboarding: bool) -> (Probe, Arc<AtomicUsize>) {
        let (resolver, asked) = vouching(|| Ok(None));
        let callers = Callers::resolved_from_store(resolver);
        (Probe::with_callers(callers, onboarding).await, asked)
    }

    #[tokio::test]
    async fn a_resolver_over_the_stores_accounts_offers_the_box_until_the_first_one_exists() {
        let (probe, asked) = resolving_from_store(true).await;
        assert_eq!(probe.https(UNCLAIMED, None).await.status(), StatusCode::OK);
        probe.admin_token().await;
        assert_eq!(
            probe.https(UNCLAIMED, None).await.status(),
            StatusCode::CONFLICT
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_resolver_over_the_stores_accounts_offers_nothing_without_browser_onboarding() {
        let (probe, asked) = resolving_from_store(false).await;
        assert_eq!(
            probe.https(UNCLAIMED, None).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_resolver_over_the_stores_accounts_still_refuses_the_socket_an_unclaimed_box() {
        let (probe, asked) = resolving_from_store(true).await;
        for ceiling in Role::LADDER {
            for response in probe.local(ceiling, UNCLAIMED).await {
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{ceiling} socket");
            }
        }
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_session_route_finds_no_session_for_a_resolvers_caller() {
        let (probe, _) = resolving(|| Ok(Some(principal(Role::Admin)))).await;
        assert_eq!(
            probe.https("/api/session", None).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn a_resolvers_account_has_its_id_and_the_socket_none() {
        let resolved = Identity::Resolved(principal(Role::HostAdmin));
        assert_eq!(resolved.account_id(), Some("console:hostadmin"));
        assert_eq!(resolved.actor(), "asserted-hostadmin");
        assert!(resolved.is_host_admin());
        assert!(!resolved.is_local());
        for socket in [
            Identity::Local,
            Identity::LocalPeer("control-socket:root".into()),
            Identity::Socket {
                ceiling: Role::Admin,
                peer: None,
            },
            Identity::Socket {
                ceiling: Role::Admin,
                peer: Some("control-socket:root".into()),
            },
        ] {
            assert_eq!(socket.account_id(), None);
            assert!(!socket.is_host_admin());
        }
    }
}
