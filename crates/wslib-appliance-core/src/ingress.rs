//! An app behind Home Assistant's ingress proxy: the gate every request passes
//! before routing, the caller the proxy asserts, and the base path it names.
//!
//! **The headers are read only behind `wslib_homeassistant`'s arrival proof**,
//! which the gate sets on a request whose connection's peer, canonicalised, is
//! a trusted one; any other peer is answered 403 on every path but `/healthz`.
//! The proxy names the caller in `X-Remote-User-Id`, `-Name` and
//! `-Display-Name`; the role is the store's `asserted_roles` row for that id,
//! made on first sight from the product's rule, and a caller whose row holds
//! none is 403. The proof is process-wide, set by any `wslib_homeassistant`
//! `gate` or `recognise`, so a product must pass no router of its own to
//! either.
//!
//! **A trusted loopback address trusts every process in the container**, and on
//! an add-on with `host_network` every process on the host, so loopback is
//! trusted only when a product says so.

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wslib_appliance_config::BasePath;
use wslib_appliance_store::Store;
use wslib_appliance_types::Role;
use wslib_homeassistant::ingress::{self as ha, Caller, Peers};

use crate::control::serve_http1;
use crate::extract::{Callers, Principal, ResolveCaller, Vouches};
use crate::state::ApplianceState;
use crate::{ApiError, ServeError};

/// Longer than the proxy keeps an idle connection pooled, so it is the proxy
/// that closes one and never a request it has just sent.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Answered to any peer: it names nobody and says only that the store answers.
const HEALTHZ: &str = "/healthz";

/// The `source` of the ingress front door's callers in the store's
/// `asserted_roles`, and with a colon the principal's id prefix, which keeps
/// the proxy's ids apart from the store's in the audit log.
pub const INGRESS_SOURCE: &str = "ingress";
pub(crate) const ID_PREFIX: &str = "ingress:";

/// `router` answering only `peers`, except on `/healthz`.
pub fn gate(router: Router, peers: Peers) -> Router {
    let peers = peers
        .exempt(HEALTHZ)
        .refusal("this appliance answers its ingress proxy alone");
    // The refusal is outside the router's own `as_page`.
    ha::gate(router, &peers).layer(axum::middleware::from_fn(crate::error::as_page))
}

/// Serve `router` on `listener` until `stop` and the grace after it, answering
/// any peer outside `peers` 403.
pub async fn serve_ingress(
    router: Router,
    listener: TcpListener,
    peers: Peers,
    stop: CancellationToken,
) -> Result<(), ServeError> {
    tracing::info!(address = ?listener.local_addr().ok(), ?peers, "ingress listening");
    serve_http1::<TcpListener, SocketAddr>(listener, gate(router, peers), HEADER_READ_TIMEOUT, stop)
        .await
}

/// A header refusal from `wslib_homeassistant`, every one of which is a 400.
fn refused(error: wslib_http_error::ApiError) -> ApiError {
    ApiError::BadRequest(error.to_string())
}

struct Asserted<F> {
    store: Store,
    first_sight: F,
}

impl<F> ResolveCaller for Asserted<F>
where
    F: Fn(&str) -> Option<Role> + Send + Sync + 'static,
{
    async fn resolve(&self, request: &Parts) -> Result<Option<Principal>, ApiError> {
        let Some(Caller {
            id,
            name: username,
            display_name,
        }) = ha::caller(request).map_err(refused)?
        else {
            return Ok(None);
        };
        if wslib_appliance_auth::is_reserved_username(&username) {
            return Err(ApiError::BadRequest(format!(
                "{} is a user name reserved for the appliance",
                ha::USER_NAME
            )));
        }
        let first_sight = (self.first_sight)(&username);
        let role = self
            .store
            .asserted_role(
                INGRESS_SOURCE,
                &id,
                &username,
                display_name.as_deref(),
                first_sight,
            )
            .await?
            .ok_or_else(|| {
                ApiError::Forbidden(format!("{username} has no role on this appliance"))
            })?;
        Ok(Some(Principal {
            id: format!("{ID_PREFIX}{id}"),
            username,
            role,
            reauthenticated_at: None,
        }))
    }
}

impl Callers {
    /// The caller the ingress proxy asserts, on a request from a trusted peer.
    /// Its role is the store's for its id, kept from the first time
    /// `first_sight` gave its user name one.
    pub fn asserted_by_ingress(
        store: Store,
        first_sight: impl Fn(&str) -> Option<Role> + Send + Sync + 'static,
    ) -> Self {
        Self {
            vouches: Vouches::Ingress,
            ..Self::resolved_by(Asserted { store, first_sight })
        }
    }
}

/// The base path the browser reached this request under, for a link or a
/// `Location` it follows: `X-Ingress-Path` through the ingress front door,
/// else `Bootstrap::base_path`. An `X-Ingress-Path` that is not a base path is
/// a 400.
#[derive(Clone, Debug)]
pub struct RequestBase(pub BasePath);

impl<S> FromRequestParts<S> for RequestBase
where
    ApplianceState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let named = ha::spa_base(parts).map_err(refused)?;
        Ok(Self(named.unwrap_or_else(|| {
            ApplianceState::from_ref(state).base_path
        })))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::extract::ConnectInfo;
    use wslib_homeassistant::ingress::{DISPLAY_NAME, INGRESS_PATH, USER_ID, USER_NAME};

    use super::*;
    use crate::probe::{BASE, Probe, SESSION_ADMIN, WHO, rung};
    use crate::testing::{Req, body_json, body_text};
    use axum::http::StatusCode;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PROXY: &str = "172.30.32.2:40000";
    const INGRESS: &str = "/api/hassio_ingress/Tk-9_x";

    /// `admin` is an editor while `editing` holds, and so Admin on first sight.
    async fn probe(editing: Arc<AtomicBool>) -> Probe {
        Probe::ingress(
            move |name| (name == "admin" && editing.load(Ordering::SeqCst)).then_some(Role::Admin),
            std::convert::identity,
        )
        .await
    }

    async fn admin_editing() -> Probe {
        probe(Arc::new(AtomicBool::new(true))).await
    }

    fn loopback() -> Peers {
        Peers::new([]).with_loopback()
    }

    fn from(probe: &Probe, peer: &str) -> Router {
        trusting(probe, Peers::home_assistant(), peer)
    }

    fn trusting(probe: &Probe, peers: Peers, peer: &str) -> Router {
        let peer: SocketAddr = peer.parse().expect("a peer");
        gate(probe.https.clone(), peers).layer(axum::Extension(ConnectInfo(peer)))
    }

    fn naming(router: Router, path: &str, id: &str, name: &str) -> Req {
        Req::new(router, "GET", path)
            .header(USER_ID, id)
            .header(USER_NAME, name)
            .header(DISPLAY_NAME, "Admin")
    }

    #[tokio::test]
    async fn a_peer_outside_the_trusted_list_is_answered_on_healthz_alone_whatever_it_asserts() {
        let probe = admin_editing().await;
        let untrusted = [
            from(&probe, "172.30.32.3:40000"),
            from(&probe, "127.0.0.1:1"),
            gate(probe.https.clone(), Peers::home_assistant()),
        ];
        for router in untrusted {
            for path in [WHO, "/api/branding", "/", "/api/nope", "/healthz/"] {
                let response = naming(router.clone(), path, "a1", "admin").send().await;
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
            }
            let health = naming(router, HEALTHZ, "a1", "admin").send().await;
            assert_eq!(health.status(), StatusCode::OK);
        }
        assert!(
            probe
                .store()
                .asserted_callers(INGRESS_SOURCE)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_trusted_peer_naming_nobody_is_signed_out() {
        let probe = admin_editing().await;
        let bare = Req::new(from(&probe, PROXY), "GET", WHO).send().await;
        assert_eq!(bare.status(), StatusCode::UNAUTHORIZED);
        let empty = naming(from(&probe, PROXY), WHO, "", "admin").send().await;
        assert_eq!(empty.status(), StatusCode::UNAUTHORIZED);
        let public = Req::new(from(&probe, PROXY), "GET", "/healthz")
            .send()
            .await;
        assert_eq!(public.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_malformed_or_reserved_assertion_is_a_bad_request() {
        let probe = admin_editing().await;
        let twice = naming(from(&probe, PROXY), WHO, "a1", "admin").header(USER_ID, "a2");
        assert_eq!(twice.send().await.status(), StatusCode::BAD_REQUEST);
        for name in ["control-socket", "a:b", "onboarding"] {
            let response = naming(from(&probe, PROXY), WHO, "a1", name).send().await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        }
    }

    #[tokio::test]
    async fn a_user_refused_on_first_sight_is_kept_with_no_role_until_given_one() {
        let probe = admin_editing().await;
        let request = || naming(from(&probe, PROXY), WHO, "b1", "member");
        assert_eq!(request().send().await.status(), StatusCode::FORBIDDEN);
        let kept = probe
            .store()
            .asserted_callers(INGRESS_SOURCE)
            .await
            .unwrap();
        assert_eq!(
            kept.iter()
                .map(|c| (c.id.as_str(), c.role))
                .collect::<Vec<_>>(),
            [("b1", None)]
        );

        probe
            .store()
            .set_asserted_role(INGRESS_SOURCE, "b1", Role::Viewer)
            .await
            .unwrap();
        let admitted = request().send().await;
        assert_eq!(admitted.status(), StatusCode::OK);
        let operator = naming(from(&probe, PROXY), &rung(Role::Operator), "b1", "member");
        assert_eq!(operator.send().await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn fixing_the_first_sight_rule_admits_a_caller_it_refused() {
        let editing = Arc::new(AtomicBool::new(false));
        let probe = probe(Arc::clone(&editing)).await;
        let request = || naming(from(&probe, PROXY), &rung(Role::Admin), "a1", "admin");
        assert_eq!(request().send().await.status(), StatusCode::FORBIDDEN);

        editing.store(true, Ordering::SeqCst);
        assert_eq!(request().send().await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_editors_first_sight_is_admin_and_the_kept_role_outlives_the_editors_list() {
        let editing = Arc::new(AtomicBool::new(true));
        let probe = probe(Arc::clone(&editing)).await;
        let admin = rung(Role::Admin);
        let first = naming(from(&probe, PROXY), &admin, "a1", "admin")
            .send()
            .await;
        assert_eq!(first.status(), StatusCode::OK);

        editing.store(false, Ordering::SeqCst);
        let later = naming(from(&probe, PROXY), &admin, "a1", "admin")
            .send()
            .await;
        assert_eq!(later.status(), StatusCode::OK, "the kept role wins");
        let kept = probe
            .store()
            .asserted_callers(INGRESS_SOURCE)
            .await
            .unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(
            (
                kept[0].id.as_str(),
                kept[0].display_name.as_deref(),
                kept[0].role
            ),
            ("a1", Some("Admin"), Some(Role::Admin))
        );
    }

    #[tokio::test]
    async fn a_v4_mapped_v6_peer_is_its_v4_address_and_loopback_is_trusted_only_when_named() {
        let probe = admin_editing().await;
        let mapped = naming(from(&probe, "[::ffff:172.30.32.2]:1"), WHO, "a1", "admin");
        assert_eq!(mapped.send().await.status(), StatusCode::OK);
        for peer in ["127.0.0.1:1", "[::1]:1", "[::ffff:127.0.0.1]:1"] {
            let by_default = naming(from(&probe, peer), WHO, "a1", "admin").send().await;
            assert_eq!(by_default.status(), StatusCode::FORBIDDEN, "{peer}");
            let named = naming(trusting(&probe, loopback(), peer), WHO, "a1", "admin");
            assert_eq!(named.send().await.status(), StatusCode::OK, "{peer}");
        }
    }

    #[tokio::test]
    async fn the_session_route_answers_an_ingress_caller_as_the_console_shape() {
        let probe = admin_editing().await;
        let response = naming(from(&probe, PROXY), "/api/session", "a1", "admin")
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            serde_json::json!({ "id": "a1", "username": "admin", "role": "admin" })
        );
    }

    #[tokio::test]
    async fn an_ingress_callers_kept_role_is_held_against_the_ladder() {
        let probe = admin_editing().await;
        for role in [Role::Viewer, Role::Operator, Role::Admin] {
            naming(from(&probe, PROXY), WHO, "a1", "admin").send().await;
            assert!(
                probe
                    .store()
                    .set_asserted_role(INGRESS_SOURCE, "a1", role)
                    .await
                    .unwrap()
            );
            for needed in Role::LADDER {
                let response = naming(from(&probe, PROXY), &rung(needed), "a1", "admin")
                    .send()
                    .await;
                let expected = match role.allows(needed) {
                    true => StatusCode::OK,
                    false => StatusCode::FORBIDDEN,
                };
                assert_eq!(response.status(), expected, "{role}, {needed}");
            }
            let session_admin = naming(from(&probe, PROXY), SESSION_ADMIN, "a1", "admin")
                .send()
                .await;
            assert_eq!(
                session_admin.status() == StatusCode::OK,
                role == Role::Admin,
                "{role}"
            );
        }
    }

    /// An ingress probe serving a bundle whose page is `<head></head>`.
    async fn with_page(bundle: &TempDir) -> Probe {
        std::fs::write(bundle.path().join("index.html"), "<head></head>").unwrap();
        let dir = bundle.path().to_path_buf();
        Probe::ingress(|_| Some(Role::Viewer), move |chassis| chassis.ui(Some(dir))).await
    }

    #[tokio::test]
    async fn the_page_carries_the_ingress_path_as_its_base() {
        let bundle = tempfile::tempdir().unwrap();
        let probe = with_page(&bundle).await;
        for path in ["/", "/widgets/1", "/index.html"] {
            let page = Req::new(from(&probe, PROXY), "GET", path)
                .header(INGRESS_PATH, INGRESS)
                .send()
                .await;
            assert_eq!(page.status(), StatusCode::OK, "{path}");
            assert_eq!(
                body_text(page).await,
                format!("<head><base href=\"{INGRESS}/\"></head>"),
                "{path}"
            );
        }
        let unnamed = Req::new(from(&probe, PROXY), "GET", "/").send().await;
        assert_eq!(body_text(unnamed).await, "<head><base href=\"/\"></head>");
    }

    #[tokio::test]
    async fn an_ingress_path_that_is_not_a_base_path_refuses_the_page_but_not_a_file() {
        let bundle = tempfile::tempdir().unwrap();
        std::fs::create_dir(bundle.path().join("assets")).unwrap();
        std::fs::write(bundle.path().join("assets/app-1a2b.js"), "app").unwrap();
        std::fs::write(bundle.path().join("robots.txt"), "robots").unwrap();
        let probe = with_page(&bundle).await;
        for value in ["/api/../admin", "/a\"b", "/a b/"] {
            for (path, status) in [
                ("/", StatusCode::BAD_REQUEST),
                ("/widgets/1", StatusCode::BAD_REQUEST),
                (BASE, StatusCode::BAD_REQUEST),
                ("/assets/app-1a2b.js", StatusCode::OK),
                ("/robots.txt", StatusCode::OK),
            ] {
                let response = naming(from(&probe, PROXY), path, "a1", "admin")
                    .header(INGRESS_PATH, value)
                    .send()
                    .await;
                assert_eq!(response.status(), status, "{value:?} {path}");
            }
        }
    }

    #[tokio::test]
    async fn the_request_base_is_the_ingress_path_through_the_front_door_only() {
        let probe = admin_editing().await;
        let request = || naming(from(&probe, PROXY), BASE, "a1", "admin");
        let through = request().header(INGRESS_PATH, INGRESS).send().await;
        assert_eq!(body_text(through).await, format!("{INGRESS}/"));
        assert_eq!(body_text(request().send().await).await, "/");

        let under = |chassis: crate::Chassis| chassis.base_path("/apps/x/".parse().unwrap());
        let https = Probe::hosting(crate::AboveAdmin::Present, Vec::new(), under).await;
        let admin = https.admin_token().await;
        let response = Req::new(https.https.clone(), "GET", "/apps/x/api/probe/base")
            .header(crate::probe::ACCOUNT, &admin)
            .header(INGRESS_PATH, INGRESS)
            .send()
            .await;
        assert_eq!(body_text(response).await, "/apps/x/");

        let console = Probe::build(
            |_| Callers::asserted_by_console(),
            crate::backend::LogsRung::SessionAdmin,
            crate::AboveAdmin::Absent,
            Vec::new(),
            under,
            true,
        )
        .await;
        let response = Req::new(console.https.clone(), "GET", "/apps/x/api/probe/base")
            .on_app_socket()
            .header(
                wslib_appliance_types::console::IDENTITY_HEADER,
                "v1; id=1; user=ops; role=viewer",
            )
            .header(INGRESS_PATH, INGRESS)
            .send()
            .await;
        assert_eq!(body_text(response).await, "/apps/x/");
    }

    /// A raw http/1.1 exchange with `address`, as the proxy would send it.
    async fn exchange(address: SocketAddr) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(
                format!(
                    "GET {WHO} HTTP/1.1\r\nhost: addon\r\n{USER_ID}: a1\r\n{USER_NAME}: admin\r\n\
                     connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.expect("read");
        answer
    }

    async fn listening(probe: &Probe, peers: Peers, stop: &CancellationToken) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (router, stop) = (probe.https.clone(), stop.clone());
        tokio::spawn(async move { serve_ingress(router, listener, peers, stop).await });
        address
    }

    #[tokio::test]
    async fn the_listener_answers_a_trusted_peer_over_a_real_socket_and_refuses_another() {
        let probe = admin_editing().await;
        let stop = CancellationToken::new();
        let trusted = listening(&probe, loopback(), &stop).await;
        let answer = exchange(trusted).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("admin"), "{answer}");

        let proxy_only = listening(&probe, Peers::home_assistant(), &stop).await;
        let answer = exchange(proxy_only).await;
        assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
        stop.cancel();
    }
}
