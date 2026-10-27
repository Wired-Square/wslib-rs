//! What this appliance trusts when it dials out: hosts pinned under `/tls/pins`
//! and authorities under `/tls/cas`, all [`Admin`], or `HostAdmin` under
//! `AboveAdmin::Raising`. Each write reloads [`Outbound`](crate::tls::Outbound).
//!
//! Parameters sit under a literal segment, never at `/tls/{name}`, which would
//! swallow an appliance's own `/tls/…` routes at merge. `POST /tls/pins`
//! connects again and refuses unless the host still presents the fingerprint
//! the caller confirmed from `POST /tls/pins/inspect`.

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use wslib_appliance_types::tls::{CertificateReport, MAX_PEM_LEN};
use wslib_appliance_types::trust::{CaCertificate, InspectPeer, Peer, PinPeer};
use wslib_appliance_types::{TrustedCa, TrustedCert};

use crate::extract::Admin;
use crate::state::ApplianceState;
use crate::tls::outbound::{canonical_sha256, normalise_host};
use crate::tls::read_authority;
use crate::{ApiError, audit};

pub(crate) fn routes() -> Router<ApplianceState> {
    Router::new()
        .route("/tls/pins", get(pins).post(pin))
        .route("/tls/pins/inspect", post(inspect_peer))
        .route("/tls/pins/{host}", delete(unpin))
        .route("/tls/cas", get(authorities).post(trust_authority))
        .route("/tls/cas/inspect", post(inspect_authority))
        .route("/tls/cas/{sha256}", delete(distrust_authority))
        // Derived from the parser's ceiling, and tighter than axum's 2 MiB default.
        .layer(DefaultBodyLimit::max(2 * MAX_PEM_LEN + 4096))
}

async fn pins(
    Admin(_): Admin,
    State(app): State<ApplianceState>,
) -> Result<Json<Vec<TrustedCert>>, ApiError> {
    Ok(Json(app.store.trusted_certs().await?))
}

/// Look at what a host presents, trusting nothing.
async fn inspect_peer(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Json(body): Json<InspectPeer>,
) -> Result<Json<Peer>, ApiError> {
    let peer = app.outbound.inspect(&body.url).await?;
    audit!(
        &app, &who, "looked at a host's certificate",
        "host" => &peer.host,
        "port" => &peer.port.to_string(),
        "sha256" => &peer.certificate.sha256,
    )
    .await;
    Ok(Json(peer))
}

/// Trust the certificate a host presents, having looked again.
async fn pin(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Json(body): Json<PinPeer>,
) -> Result<Json<TrustedCert>, ApiError> {
    let expected = canonical_sha256(&body.expect_sha256).map_err(ApiError::BadRequest)?;
    let peer = app.outbound.inspect(&body.url).await?;
    if peer.certificate.sha256 != expected {
        audit!(
            &app, &who, "refused to pin a host whose certificate had changed",
            "host" => &peer.host,
            "presented" => &peer.certificate.sha256,
            "confirmed" => &expected,
        )
        .await;
        return Err(ApiError::Conflict(format!(
            "{} is presenting sha256:{} now, not the sha256:{} that was confirmed — look at \
             it again before trusting it",
            peer.host, peer.certificate.sha256, expected
        )));
    }

    let pinned = TrustedCert {
        host: peer.host,
        sha256: peer.certificate.sha256,
        subject: peer.certificate.subject,
        issuer: peer.certificate.issuer,
        not_before: peer.certificate.not_before,
        not_after: peer.certificate.not_after,
        added_at: wslib_appliance_store::now(),
        added_by: who.actor().to_string(),
    };
    app.outbound.pin(&app.store, &pinned).await?;
    audit!(
        &app, &who, "trusted a host's certificate by fingerprint",
        "host" => &pinned.host,
        "sha256" => &pinned.sha256,
    )
    .await;
    Ok(Json(pinned))
}

async fn unpin(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(host): Path<String>,
) -> Result<StatusCode, ApiError> {
    let host = normalise_host(&host);
    if !app.outbound.unpin(&app.store, &host).await? {
        return Err(ApiError::NotFound(format!("{host} is not pinned")));
    }
    audit!(&app, &who, "stopped trusting a host's certificate", "host" => &host).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn authorities(
    Admin(_): Admin,
    State(app): State<ApplianceState>,
) -> Result<Json<Vec<TrustedCa>>, ApiError> {
    Ok(Json(app.store.trusted_cas().await?))
}

/// Read an authority's certificate and say what is odd about it, keeping
/// nothing — refusing what [`trust_authority`] would refuse.
async fn inspect_authority(
    Admin(_): Admin,
    Json(body): Json<CaCertificate>,
) -> Result<Json<CertificateReport>, ApiError> {
    let (_, report) = read_authority(&body.cert_pem, wslib_appliance_store::now())?;
    Ok(Json(report))
}

/// Trust an authority for the connections this appliance makes.
async fn trust_authority(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Json(body): Json<CaCertificate>,
) -> Result<Json<TrustedCa>, ApiError> {
    let now = wslib_appliance_store::now();
    let (pem, report) = read_authority(&body.cert_pem, now)?;
    let certificate = report.certificate;
    let trusted = TrustedCa {
        sha256: certificate.sha256,
        subject: certificate.subject,
        not_before: certificate.not_before,
        not_after: certificate.not_after,
        added_at: now,
        added_by: who.actor().to_string(),
        pem,
    };
    app.outbound.trust(&app.store, &trusted).await?;
    audit!(
        &app, &who, "trusted an authority for outbound connections",
        "sha256" => &trusted.sha256,
        "subject" => &trusted.subject,
        "warnings" => &report.warnings.join(" "),
    )
    .await;
    Ok(Json(trusted))
}

async fn distrust_authority(
    Admin(who): Admin,
    State(app): State<ApplianceState>,
    Path(sha256): Path<String>,
) -> Result<StatusCode, ApiError> {
    let not_found = || ApiError::NotFound(format!("no authority is named {sha256}"));
    let sha256 = canonical_sha256(&sha256).map_err(|_| not_found())?;
    if !app.outbound.distrust(&app.store, &sha256).await? {
        return Err(not_found());
    }
    audit!(
        &app, &who, "stopped trusting an authority for outbound connections",
        "sha256" => &sha256,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use wslib_appliance_types::Role;

    use super::*;
    use crate::AboveAdmin;
    use crate::probe::Probe;
    use crate::testing::body_text;

    const NO_JSON: &str = "Content-Type: application/json";

    /// Each route, and what its own handler answers an admitted caller who
    /// sends no body: a fallback's 404 body matches none of them.
    const ROUTES: [(&str, &str, StatusCode, &str); 8] = [
        ("GET", "/api/tls/pins", StatusCode::OK, "[]"),
        (
            "POST",
            "/api/tls/pins",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            NO_JSON,
        ),
        (
            "POST",
            "/api/tls/pins/inspect",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            NO_JSON,
        ),
        (
            "DELETE",
            "/api/tls/pins/example.test",
            StatusCode::NOT_FOUND,
            "example.test is not pinned",
        ),
        ("GET", "/api/tls/cas", StatusCode::OK, "[]"),
        (
            "POST",
            "/api/tls/cas",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            NO_JSON,
        ),
        (
            "POST",
            "/api/tls/cas/inspect",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            NO_JSON,
        ),
        (
            "DELETE",
            "/api/tls/cas/00",
            StatusCode::NOT_FOUND,
            "no authority is named 00",
        ),
    ];

    async fn probe(above_admin: AboveAdmin) -> Probe {
        Probe::hosting(above_admin, Vec::new(), std::convert::identity).await
    }

    /// `method path` as the account `token`, then over each Admin-ceiling
    /// socket, as `(status, body)` labelled by listener.
    async fn on_both_listeners(
        probe: &Probe,
        token: &str,
        method: &'static str,
        path: &str,
    ) -> Vec<(&'static str, StatusCode, String)> {
        let https = probe.https_with(method, path, Some(token)).await;
        let local = probe.local_with(Role::Admin, method, path).await;
        let mut answers = Vec::new();
        for (listener, response) in
            std::iter::once(("https", https)).chain(local.into_iter().map(|r| ("socket", r)))
        {
            answers.push((listener, response.status(), body_text(response).await));
        }
        answers
    }

    #[tokio::test]
    async fn absent_and_present_keep_the_trust_routes_at_admin_on_both_listeners() {
        for above_admin in [AboveAdmin::Absent, AboveAdmin::Present] {
            let probe = probe(above_admin).await;
            let admin = probe.token(Role::Admin).await;
            let operator = probe.token(Role::Operator).await;
            for (method, path, status, body) in ROUTES {
                for (listener, got, text) in on_both_listeners(&probe, &admin, method, path).await {
                    let at = format!("{above_admin:?} {method} {path} over {listener}");
                    assert_eq!(got, status, "{at}: {text}");
                    assert!(text.contains(body), "{at}: {text}");
                }
                assert_eq!(
                    probe
                        .https_with(method, path, Some(&operator))
                        .await
                        .status(),
                    StatusCode::FORBIDDEN,
                    "{above_admin:?} {method} {path} as an operator"
                );
                for response in probe.local_with(Role::Operator, method, path).await {
                    let at = format!("{above_admin:?} {method} {path} over an Operator socket");
                    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{at}");
                    let text = body_text(response).await;
                    assert!(text.contains("goes no higher than"), "{at}: {text}");
                }
            }
        }
    }

    #[tokio::test]
    async fn raising_puts_the_trust_routes_at_host_admin_and_refuses_the_socket() {
        let probe = probe(AboveAdmin::Raising).await;
        let admin = probe.token(Role::Admin).await;
        let owner = probe.token(Role::HostAdmin).await;
        for (method, path, status, body) in ROUTES {
            for (listener, got, text) in on_both_listeners(&probe, &admin, method, path).await {
                assert_eq!(
                    got,
                    StatusCode::FORBIDDEN,
                    "{method} {path} over {listener}"
                );
                let refusal = match listener {
                    "https" => "needs hostadmin",
                    _ => "control socket",
                };
                assert!(
                    text.contains(refusal),
                    "{method} {path} over {listener}: {text}"
                );
            }
            let admitted = probe.https_with(method, path, Some(&owner)).await;
            assert_eq!(admitted.status(), status, "{method} {path}");
            assert!(body_text(admitted).await.contains(body), "{method} {path}");
        }
    }

    #[tokio::test]
    async fn raising_leaves_a_products_own_tls_route_at_admin() {
        let product = axum::Router::new().route("/tls/x", get(|_: Admin| async {}));
        let probe = Probe::hosting(AboveAdmin::Raising, Vec::new(), |chassis| {
            chassis.api(product)
        })
        .await;
        let admin = probe.token(Role::Admin).await;
        for (listener, got, text) in on_both_listeners(&probe, &admin, "GET", "/api/tls/x").await {
            assert_eq!(got, StatusCode::OK, "over {listener}: {text}");
        }
    }

    #[tokio::test]
    async fn an_unknown_trust_path_is_still_a_404_under_every_above_admin() {
        const UNKNOWN: &str = "/api/tls/zzz";
        for above_admin in [AboveAdmin::Absent, AboveAdmin::Present, AboveAdmin::Raising] {
            let probe = probe(above_admin).await;
            let admin = probe.token(Role::Admin).await;
            assert_eq!(
                probe.https(UNKNOWN, Some(&admin)).await.status(),
                StatusCode::NOT_FOUND,
                "{above_admin:?}"
            );
            for response in probe.local(Role::Admin, UNKNOWN).await {
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{above_admin:?}");
            }
        }
    }
}
