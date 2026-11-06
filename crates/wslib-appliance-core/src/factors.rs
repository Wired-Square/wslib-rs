//! Second factors over HTTP: the sign-in code step, passkey sign-in and the
//! account screen's TOTP, recovery codes and passkeys, as one `Router` a backend
//! nests where it likes. The password step stays the backend's, handed on to
//! [`password_proved`]; every session is issued on a [`Proof`] begun before that
//! step's own check, and the code limiter is keyed by account, never by the request.
//! No code, key, token or credential id reaches a log line or an audit row. No
//! path here names `/api` or a base path, and `GET /session` is the backend's.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use wslib_appliance_auth::{AuthError, Awaiting, Sessions};
use wslib_appliance_store::{Account, Store};
use wslib_appliance_types::passkey::{
    AssertionCredential, CreationOptions, PasskeyHost, PasskeyRegistration, PasskeyRename,
    PasskeyView, RequestOptions,
};
use wslib_appliance_types::session::{
    Enrolled, EnrolmentConfirm, PendingEnrolment, Reauthentication, SecondStep, SignInCode,
    SignInMethod,
};
use wslib_appliance_types::totp::{
    ClockSkew, FactorProof, RecoveryCodes, TotpConfirm, TotpEnrolment, TotpView,
};
use wslib_appliance_types::{Availability, User};
use wslib_auth::{Proof, SessionCookie, SessionToken};
use wslib_secret::Secret;

use crate::audit::Actor;
use crate::extract::{Identity, SESSION_COOKIE, Vouches};
use crate::reauth::wrong_password;
use crate::{ApiError, ApplianceState, Reached, Viewer, audit, reauthenticate};

#[cfg(test)]
mod tests;

/// The largest body these routes, and a backend's that take a [`FactorProof`], read.
pub const MAX_BODY: usize = 16 * 1024;

const UNKNOWN_PASSKEY: &str = "passkey:unknown";

/// The sessions of the backend that mounts these routes, which never keep their own.
pub trait HostSessions: Clone + Send + Sync + 'static {
    /// A session for `account` signed in on `proof`, as its `Set-Cookie` value;
    /// refused if, once stored, the account is disabled or its `sessions_valid_from` has moved.
    fn issue(
        &self,
        app: &ApplianceState,
        account: &Account,
        proof: Proof,
    ) -> impl Future<Output = Result<HeaderValue, ApiError>> + Send;
}

/// The `appliance_session` cookie at the backend's base path: `Secure`, `HttpOnly`,
/// `SameSite=Strict`, and no `Max-Age`, as the session's row expires.
pub fn session_cookie(app: &ApplianceState) -> SessionCookie {
    SessionCookie::new(SESSION_COOKIE).path(app.base_path.as_str().to_owned())
}

/// The token in a request's `appliance_session` cookie, for a resolver built before its state.
pub fn session_token_in(headers: &HeaderMap) -> Option<SessionToken> {
    const COOKIE: SessionCookie = SessionCookie::new(SESSION_COOKIE);
    COOKIE.token_in(headers)
}

/// A session for `user`, whose cutoff read `valid_from` and whose credential check
/// began at `proof`, as the `Set-Cookie` value [`session_cookie`] carries it in.
pub async fn issue_session(
    app: &ApplianceState,
    user: &User,
    valid_from: DateTime<Utc>,
    proof: Proof,
) -> Result<HeaderValue, ApiError> {
    let token = Sessions::new(&app.store)
        .issue(&app.store, user, valid_from, proof)
        .await?;
    Ok(session_cookie(app).set(&token))
}

/// The sessions of a backend whose resolver reports
/// [`Principal::reauthenticated_at`](crate::Principal::reauthenticated_at),
/// a window in which a recent proof stands in for the password; never for a
/// store account, so it serves only what the backend passes on.
pub trait ReauthenticationWindow: Clone + Send + Sync + 'static {
    /// The session `headers` carries has just proved its account again, on `proof`.
    fn mark_reauthenticated(
        &self,
        app: &ApplianceState,
        headers: &HeaderMap,
        proof: Proof,
    ) -> impl Future<Output = Result<(), ApiError>> + Send;
}

/// The second-factor routes, under `/session`, issuing sessions through `sessions`.
pub fn second_factor_routes<H: HostSessions>(sessions: H) -> Router<ApplianceState> {
    Router::new()
        .route("/session/code", post(code_step::<H>))
        .route("/session/enrolment", post(enrolment))
        .route("/session/enrolment/confirm", post(enrolment_confirm::<H>))
        .route("/session/passkey/availability", get(passkey_availability))
        .route("/session/passkey/hosts", get(box_passkey_hosts))
        .route("/session/passkey/options", post(passkey_options))
        .route("/session/passkey", post(passkey_sign_in::<H>))
        .route(
            "/session/reauthentication/options",
            post(reauthentication_options),
        )
        .route("/session/totp", get(totp_view).post(enrol))
        .route("/session/totp/confirm", post(confirm))
        .route("/session/totp/off", post(turn_off))
        .route("/session/recovery-codes", post(new_recovery_codes))
        .route("/session/passkeys", get(passkeys).post(register))
        .route("/session/passkeys/options", post(registration_options))
        .route("/session/passkeys/hosts", get(hosts))
        .route("/session/passkeys/{id}", delete(remove))
        .route("/session/passkeys/{id}/name", put(rename))
        .layer(Extension(sessions))
        .layer(DefaultBodyLimit::max(MAX_BODY))
}

/// `POST /session/reauthenticate`, for a backend with a
/// [`ReauthenticationWindow`]: the caller's password or a passkey again,
/// marking its session.
pub fn reauthentication_route<W: ReauthenticationWindow>(window: W) -> Router<ApplianceState> {
    Router::new()
        .route("/session/reauthenticate", post(reauthenticated::<W>))
        .layer(Extension(window))
        .layer(DefaultBodyLimit::max(MAX_BODY))
}

/// What a backend's sign-in answers once `account`'s password was right: 200
/// with a session, or 202 with a [`SecondStep`] held against this password hash.
/// `proof` must have been begun before the password was checked.
pub async fn password_proved(
    app: &ApplianceState,
    sessions: &impl HostSessions,
    account: Account,
    proof: Proof,
) -> Result<Response, ApiError> {
    let user = &account.user;
    let (awaiting, step) = if totp_on(&app.store, &user.id).await? {
        (Awaiting::Code, "code")
    } else if app.store.totp_required(&user.id).await? {
        (Awaiting::Enrolment, "TOTP enrolment")
    } else {
        return session(app, sessions, account, proof, SignInMethod::Password, None).await;
    };
    let begun = app
        .pending
        .begin(&user.id, account.password_hash.expose(), awaiting)?;
    let method = SignInMethod::Password.as_str();
    if begun.others > 0 {
        tracing::warn!(
            name: "audit",
            actor = %user.username,
            user_id = %user.id,
            method,
            "password accepted while another sign-in waits for its {step}, a sign the \
             password is known"
        );
    }
    let message = match awaiting {
        Awaiting::Code => "password accepted; waiting for a code",
        Awaiting::Enrolment => "password accepted; waiting for TOTP enrolment",
    };
    audit!(app, &Tried(user), message, "user_id" => &user.id, "method" => method).await;
    let pending = begun.token;
    let next = match awaiting {
        Awaiting::Code => SecondStep::Code { pending },
        Awaiting::Enrolment => SecondStep::Enrol { pending },
    };
    Ok((StatusCode::ACCEPTED, Json(next)).into_response())
}

async fn session(
    app: &ApplianceState,
    sessions: &impl HostSessions,
    account: Account,
    proof: Proof,
    method: SignInMethod,
    passkey_id: Option<&str>,
) -> Result<Response, ApiError> {
    let cookie = signed_in(app, sessions, &account, proof, method, passkey_id).await?;
    Ok(([(header::SET_COOKIE, cookie)], Json(account.user)).into_response())
}

async fn signed_in(
    app: &ApplianceState,
    sessions: &impl HostSessions,
    account: &Account,
    proof: Proof,
    method: SignInMethod,
    passkey_id: Option<&str>,
) -> Result<HeaderValue, ApiError> {
    let cookie = sessions.issue(app, account, proof).await?;
    let user = &account.user;
    app.store.stamp_login(&user.id).await?;
    let method = method.as_str();
    tracing::info!(username = %user.username, user_id = %user.id, method, "signed in");
    let who = SignedIn(user);
    match passkey_id {
        Some(id) => audit!(app, &who, "signed in", "method" => method, "passkey_id" => id).await,
        None => audit!(app, &who, "signed in", "method" => method).await,
    }
    Ok(cookie)
}

struct SignedIn<'a>(&'a User);

impl Actor for SignedIn<'_> {
    fn actor(&self) -> &str {
        &self.0.username
    }

    fn actor_id(&self) -> Option<&str> {
        Some(&self.0.id)
    }
}

/// An account part way through signing in: no actor id, since who is typing is not yet known.
struct Tried<'a>(&'a User);

impl Actor for Tried<'_> {
    fn actor(&self) -> &str {
        &self.0.username
    }
}

async fn totp_on(store: &Store, user_id: &str) -> Result<bool, ApiError> {
    Ok(store.totp(user_id).await?.is_some_and(|t| t.confirmed))
}

/// Past what a `SystemTime` holds is as far from the box's clock as a clock can be.
fn browser_time(millis: u64) -> Result<SystemTime, AuthError> {
    UNIX_EPOCH
        .checked_add(Duration::from_millis(millis))
        .ok_or(AuthError::ClockSkew(ClockSkew { minutes: i32::MIN }))
}

async fn totp(
    app: &ApplianceState,
    user_id: &str,
    code: &Secret,
    millis: u64,
) -> Result<(), AuthError> {
    let at = browser_time(millis)?;
    wslib_appliance_auth::verify_totp(&app.store, &app.codes, user_id, code.expose(), at).await
}

fn no_browser_time() -> ApiError {
    ApiError::BadRequest("a TOTP code needs the browser's time beside it".to_string())
}

/// `signed_in` names the caller as the account too.
fn code_refused(user: &User, during: &'static str, signed_in: bool, e: AuthError) -> ApiError {
    let why = match &e {
        AuthError::CodeRefused => "the code is wrong",
        AuthError::CodeUsed => "the code was already used",
        AuthError::ClockSkew(_) => "the code is wrong and the clocks disagree",
        AuthError::TooManyCodes(_) => "too many wrong codes, so the password is likely known",
        _ => return e.into(),
    };
    match signed_in {
        true => tracing::warn!(
            name: "audit",
            actor = %user.username,
            actor_id = %user.id,
            user_id = %user.id,
            "{during} refused: {why}"
        ),
        false => tracing::warn!(
            name: "audit",
            actor = %user.username,
            user_id = %user.id,
            "{during} refused: {why}"
        ),
    }
    e.into()
}

/// **Public**: the code half of a sign-in whose password was right.
async fn code_step<H: HostSessions>(
    State(app): State<ApplianceState>,
    Extension(sessions): Extension<H>,
    Json(body): Json<SignInCode>,
) -> Result<Response, ApiError> {
    let proof = Proof::begin();
    let (pending, account) = waiting(&app, &body.pending, Awaiting::Code).await?;
    let user = &account.user;
    let (method, during, checked) = if body.recovery {
        let code = body.code.expose();
        let used = wslib_appliance_auth::use_recovery_code(&app.store, &app.codes, &user.id, code);
        let during = "sign-in with a recovery code";
        (SignInMethod::RecoveryCode, during, used.await)
    } else {
        let millis = body.browser_time.ok_or_else(no_browser_time)?;
        let checked = totp(&app, &user.id, &body.code, millis).await;
        (
            SignInMethod::PasswordTotp,
            "sign-in with a TOTP code",
            checked,
        )
    };
    checked.map_err(|e| code_refused(user, during, false, e))?;
    pending.spend();
    session(&app, &sessions, account, proof, method, None).await
}

/// The waiting sign-in `token` names and its account; 401, ending it, once its
/// account is gone, disabled or has had its password changed since.
async fn waiting(
    app: &ApplianceState,
    token: &Secret,
    awaiting: Awaiting,
) -> Result<(wslib_appliance_auth::Pending, Account), ApiError> {
    let pending = app
        .pending
        .take(token, awaiting)
        .ok_or(ApiError::Unauthenticated)?;
    let account = app
        .store
        .user_by_id(pending.user_id())
        .await?
        .filter(|account| account.user.enabled)
        .filter(|account| pending.began_under(account.password_hash.expose()));
    let still = match (&account, awaiting) {
        (None, _) => false,
        (Some(_), Awaiting::Code) => totp_on(&app.store, pending.user_id()).await?,
        (Some(_), Awaiting::Enrolment) => app.store.totp_required(pending.user_id()).await?,
    };
    match account {
        Some(account) if still => Ok((pending, account)),
        _ => {
            pending.spend();
            Err(ApiError::Unauthenticated)
        }
    }
}

/// **Public**: begin the TOTP enrolment an administrator requires; the sign-in
/// waits on for [`enrolment_confirm`].
async fn enrolment(
    State(app): State<ApplianceState>,
    Json(body): Json<PendingEnrolment>,
) -> Result<Json<TotpEnrolment>, ApiError> {
    let (_pending, Account { user, .. }) =
        waiting(&app, &body.pending, Awaiting::Enrolment).await?;
    let enrolment = wslib_appliance_auth::enrol_totp(&app.store, &user, &app.about.product).await?;
    audit!(
        &app, &Tried(&user), "TOTP enrolment begun",
        "user_id" => &user.id, "method" => SignInMethod::Password.as_str(),
    )
    .await;
    Ok(Json(enrolment))
}

/// **Public**: confirm that enrolment, issuing the session and the recovery codes, once.
async fn enrolment_confirm<H: HostSessions>(
    State(app): State<ApplianceState>,
    Extension(sessions): Extension<H>,
    Json(body): Json<EnrolmentConfirm>,
) -> Result<Response, ApiError> {
    let proof = Proof::begin();
    let (pending, account) = waiting(&app, &body.pending, Awaiting::Enrolment).await?;
    let user = &account.user;
    let during = "sign-in enrolling TOTP";
    let confirmed = async {
        let (code, at) = (body.code.expose(), browser_time(body.browser_time)?);
        wslib_appliance_auth::confirm_totp(&app.store, &app.codes, &user.id, code, at).await
    };
    let recovery_codes = confirmed
        .await
        .map_err(|e| code_refused(user, during, false, e))?;
    pending.spend();
    audit!(&app, &SignedIn(user), "turned TOTP on").await;
    let method = SignInMethod::PasswordTotp;
    let cookie = signed_in(&app, &sessions, &account, proof, method, None).await?;
    let enrolled = Enrolled {
        user: account.user,
        recovery_codes,
    };
    Ok(([(header::SET_COOKIE, cookie)], Json(enrolled)).into_response())
}

/// **Public**: whether a passkey can run on the name and port this request reached.
async fn passkey_availability(reached: Reached) -> Json<Availability> {
    Json(match reached.relying_party() {
        Ok(rp) => Availability::ready(rp.id()),
        Err(refused) => Availability::unsupported(refused.to_string()),
    })
}

/// **Public**: the names any of the box's passkeys were made on; no counts.
async fn box_passkey_hosts(
    State(app): State<ApplianceState>,
) -> Result<Json<Vec<String>>, ApiError> {
    let hosts = app.store.passkey_hosts(None).await?;
    Ok(Json(hosts.into_iter().map(|h| h.host).collect()))
}

/// **Public**.
async fn passkey_options(
    State(app): State<ApplianceState>,
    reached: Reached,
) -> Result<Json<RequestOptions>, ApiError> {
    Ok(Json(app.passkeys.begin_sign_in(&reached.relying_party()?)?))
}

/// **Public**: asks for no TOTP after it, since the passkey verified its user.
async fn passkey_sign_in<H: HostSessions>(
    State(app): State<ApplianceState>,
    Extension(sessions): Extension<H>,
    reached: Reached,
    Json(credential): Json<AssertionCredential>,
) -> Result<Response, ApiError> {
    let rp = reached.relying_party()?;
    let proof = Proof::begin();
    match app
        .passkeys
        .finish_sign_in(&app.store, &rp, &credential)
        .await
    {
        Ok(signed) => {
            let passkey_id = Some(signed.passkey_id.as_str());
            session(
                &app,
                &sessions,
                signed.account,
                proof,
                SignInMethod::Passkey,
                passkey_id,
            )
            .await
        }
        Err(e) => Err(passkey_refused(&app.store, &credential, e).await),
    }
}

/// Audited under the account its unverified `userHandle` claims, or [`UNKNOWN_PASSKEY`].
async fn passkey_refused(
    store: &Store,
    credential: &AssertionCredential,
    e: AuthError,
) -> ApiError {
    let why = match &e {
        AuthError::PasskeyRefused(_) => "the passkey was not accepted",
        AuthError::PasskeyCounterDidNotMove(_) => {
            "the passkey's counter did not move, so it may have been cloned"
        }
        _ => return e.into(),
    };
    let claimed = match wslib_appliance_auth::claimed_user_id(credential) {
        Some(id) => store.user_by_id(&id).await.ok().flatten(),
        None => None,
    };
    match claimed.map(|account| account.user) {
        Some(user) => tracing::warn!(
            name: "audit",
            actor = %user.username,
            user_id = %user.id,
            named_by = "an unverified user handle",
            method = SignInMethod::Passkey.as_str(),
            "sign-in refused: {why}"
        ),
        None => tracing::warn!(
            name: "audit",
            actor = UNKNOWN_PASSKEY,
            method = SignInMethod::Passkey.as_str(),
            "sign-in refused: {why}"
        ),
    }
    e.into()
}

/// The caller's own store account, re-read; 404 for the control socket.
async fn own_account(app: &ApplianceState, who: &Identity) -> Result<User, ApiError> {
    match who {
        Identity::Resolved(principal) if app.vouches == Vouches::StoreAccounts => app
            .store
            .user_by_id(&principal.id)
            .await?
            .map(|account| account.user)
            .ok_or(ApiError::Unauthenticated),
        _ => who.signed_in().cloned(),
    }
}

async fn reauthentication_options(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    reached: Reached,
) -> Result<Json<RequestOptions>, ApiError> {
    let user = own_account(&app, &who).await?;
    let rp = reached.relying_party()?;
    let options = app
        .passkeys
        .begin_reauthentication(&app.store, &rp, &user.id)
        .await?;
    Ok(Json(options))
}

/// Only a proof made here marks the session.
async fn reauthenticated<W: ReauthenticationWindow>(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    Extension(window): Extension<W>,
    reached: Reached,
    headers: HeaderMap,
    Json(proof): Json<Reauthentication>,
) -> Result<StatusCode, ApiError> {
    own_account(&app, &who).await?;
    let began = Proof::begin();
    if reauthenticate(&app, &who, &reached, proof, "re-authentication")
        .await?
        .is_none()
    {
        return Err(ApiError::Forbidden("the password is incorrect".to_string()));
    }
    window.mark_reauthenticated(&app, &headers, began).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn totp_view(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
) -> Result<Json<TotpView>, ApiError> {
    let user = own_account(&app, &who).await?;
    let left = app.store.recovery_codes_left(&user.id).await?;
    Ok(Json(TotpView {
        on: totp_on(&app.store, &user.id).await?,
        recovery_codes_left: u32::try_from(left).unwrap_or(u32::MAX),
    }))
}

/// The fresh proof a change to `user`'s second factors takes; a recent proof
/// never stands in, even for a resolver's store account.
async fn prove_factor_change(
    app: &ApplianceState,
    who: &Identity,
    user: &User,
    reached: &Reached,
    proof: FactorProof,
    what: &'static str,
) -> Result<&'static str, ApiError> {
    let again = |password| Reauthentication {
        password,
        passkey: proof.passkey.clone(),
    };
    let proved_here = |proved: Option<SignInMethod>| {
        let refused = || wrong_password(&user.username, &user.id, what);
        proved.map(SignInMethod::as_str).ok_or_else(refused)
    };
    if !totp_on(&app.store, &user.id).await? {
        return proved_here(reauthenticate(app, who, reached, again(proof.password), what).await?);
    }
    let method = match (&proof.code, proof.recovery) {
        (Some(code), true) => {
            let used = wslib_appliance_auth::use_recovery_code(
                &app.store,
                &app.codes,
                &user.id,
                code.expose(),
            );
            used.await.map_err(|e| code_refused(user, what, true, e))?;
            SignInMethod::RecoveryCode.as_str()
        }
        (Some(code), false) => {
            let millis = proof.browser_time.ok_or_else(no_browser_time)?;
            let checked = totp(app, &user.id, code, millis).await;
            checked.map_err(|e| code_refused(user, what, true, e))?;
            "totp"
        }
        (None, _) if proof.passkey.is_some() => {
            return proved_here(reauthenticate(app, who, reached, again(None), what).await?);
        }
        (None, _) => {
            return Err(ApiError::Forbidden(
                "while TOTP is on, this needs a code from the authenticator app, a recovery \
                 code or a passkey"
                    .to_string(),
            ));
        }
    };
    audit!(app, who, "re-authenticated", "what" => what, "method" => method).await;
    Ok(method)
}

/// A key already on is a 409 before any proof is spent.
async fn enrol(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(proof): Json<FactorProof>,
) -> Result<Json<TotpEnrolment>, ApiError> {
    let user = own_account(&app, &who).await?;
    if totp_on(&app.store, &user.id).await? {
        return Err(AuthError::TotpAlreadyOn.into());
    }
    prove_factor_change(&app, &who, &user, &reached, proof, "turning TOTP on").await?;
    let enrolment = wslib_appliance_auth::enrol_totp(&app.store, &user, &app.about.product).await?;
    Ok(Json(enrolment))
}

async fn confirm(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    Json(body): Json<TotpConfirm>,
) -> Result<Json<RecoveryCodes>, ApiError> {
    let user = own_account(&app, &who).await?;
    let confirmed = async {
        let (code, at) = (body.code.expose(), browser_time(body.browser_time)?);
        wslib_appliance_auth::confirm_totp(&app.store, &app.codes, &user.id, code, at).await
    };
    let codes = confirmed
        .await
        .map_err(|e| code_refused(&user, "turning TOTP on", true, e))?;
    audit!(&app, &who, "turned TOTP on").await;
    Ok(Json(codes))
}

async fn turn_off(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(proof): Json<FactorProof>,
) -> Result<StatusCode, ApiError> {
    let user = own_account(&app, &who).await?;
    let what = "turning TOTP off";
    let method = prove_factor_change(&app, &who, &user, &reached, proof, what).await?;
    if !app.store.clear_totp(&user.id).await? {
        return Err(AuthError::TotpNotEnrolled.into());
    }
    audit!(&app, &who, "turned TOTP off", "method" => method).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn new_recovery_codes(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(proof): Json<FactorProof>,
) -> Result<Json<RecoveryCodes>, ApiError> {
    let user = own_account(&app, &who).await?;
    let what = "new recovery codes";
    prove_factor_change(&app, &who, &user, &reached, proof, what).await?;
    let codes = wslib_appliance_auth::issue_recovery_codes(&app.store, &user.id).await?;
    audit!(&app, &who, "made new recovery codes").await;
    Ok(Json(codes))
}

async fn passkeys(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
) -> Result<Json<Vec<PasskeyView>>, ApiError> {
    let user = own_account(&app, &who).await?;
    let passkeys = app.store.passkeys(&user.id).await?;
    Ok(Json(
        passkeys.iter().map(|passkey| passkey.view()).collect(),
    ))
}

async fn hosts(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
) -> Result<Json<Vec<PasskeyHost>>, ApiError> {
    let user = own_account(&app, &who).await?;
    Ok(Json(app.store.passkey_hosts(Some(&user.id)).await?))
}

async fn registration_options(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(proof): Json<FactorProof>,
) -> Result<Json<CreationOptions>, ApiError> {
    let user = own_account(&app, &who).await?;
    let rp = reached.relying_party()?;
    prove_factor_change(&app, &who, &user, &reached, proof, "adding a passkey").await?;
    let options = app
        .passkeys
        .begin_registration(&app.store, &rp, &user, &app.about.product)
        .await?;
    Ok(Json(options))
}

async fn register(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    reached: Reached,
    Json(body): Json<PasskeyRegistration>,
) -> Result<(StatusCode, Json<PasskeyView>), ApiError> {
    let user = own_account(&app, &who).await?;
    let rp = reached.relying_party()?;
    let passkey = app
        .passkeys
        .finish_registration(&app.store, &rp, &user.id, &body.name, &body.credential)
        .await?;
    audit!(
        &app, &who, "added a passkey",
        "passkey_id" => &passkey.id, "name" => &passkey.name, "host" => &passkey.host,
    )
    .await;
    Ok((StatusCode::CREATED, Json(passkey)))
}

async fn rename(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
    Json(body): Json<PasskeyRename>,
) -> Result<StatusCode, ApiError> {
    let user = own_account(&app, &who).await?;
    let name = wslib_appliance_auth::passkey_name(&body.name)?;
    if !app.store.rename_passkey(&user.id, &id, &name).await? {
        return Err(no_such_passkey());
    }
    audit!(&app, &who, "renamed a passkey", "passkey_id" => &id, "name" => &name).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove(
    Viewer(who): Viewer,
    State(app): State<ApplianceState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let user = own_account(&app, &who).await?;
    let passkey = app
        .store
        .remove_passkey(&user.id, &id)
        .await?
        .ok_or_else(no_such_passkey)?;
    audit!(
        &app, &who, "removed a passkey",
        "passkey_id" => &passkey.id, "name" => &passkey.name, "host" => &passkey.rp_id,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Clear account `user_id`'s TOTP and recovery codes and require it to enrol at
/// its next password sign-in; the guards are [`remove_account_passkey`]'s.
pub async fn require_totp_enrolment(
    app: &ApplianceState,
    who: &Identity,
    reached: &Reached,
    user_id: &str,
    proof: FactorProof,
) -> Result<(), ApiError> {
    refuse_own_account(who, user_id)?;
    let store = store_for(app, who);
    store.writable(user_id).await?;
    prove_acting_admin(app, who, reached, proof, "requiring TOTP enrolment").await?;
    store.require_totp(user_id).await?;
    audit!(app, who, "required TOTP re-enrolment", "user_id" => user_id).await;
    Ok(())
}

/// Remove account `user_id`'s passkey as an administrator `who`, never on its own
/// account; a host admin's only by a host admin. The target is checked before
/// [`prove_acting_admin`], so a refused change spends no code.
pub async fn remove_account_passkey(
    app: &ApplianceState,
    who: &Identity,
    reached: &Reached,
    user_id: &str,
    passkey_id: &str,
    proof: FactorProof,
) -> Result<(), ApiError> {
    refuse_own_account(who, user_id)?;
    let store = store_for(app, who);
    store.writable(user_id).await?;
    let passkeys = store.passkeys(user_id).await?;
    if !passkeys.iter().any(|passkey| passkey.id == passkey_id) {
        return Err(no_such_passkey());
    }
    prove_acting_admin(app, who, reached, proof, "removing a passkey").await?;
    let passkey = store
        .remove_passkey_of(user_id, passkey_id)
        .await?
        .ok_or_else(no_such_passkey)?;
    audit!(
        app, who, "removed a passkey",
        "user_id" => user_id, "passkey_id" => &passkey.id,
        "name" => &passkey.name, "host" => &passkey.rp_id,
    )
    .await;
    Ok(())
}

/// The caller's fresh proof of its own account, audited with `what`. A store
/// account's recent proof never stands in; a resolver's caller outside the store
/// stands on its recent proof, as [`reauthenticate`] has it.
pub async fn prove_caller(
    app: &ApplianceState,
    who: &Identity,
    reached: &Reached,
    proof: FactorProof,
    what: &'static str,
) -> Result<&'static str, ApiError> {
    if matches!(who, Identity::Resolved(_)) && app.vouches != Vouches::StoreAccounts {
        let again = Reauthentication {
            password: proof.password,
            passkey: proof.passkey,
        };
        let proved = reauthenticate(app, who, reached, again, what).await?;
        return Ok(proved.map_or("a recent proof", SignInMethod::as_str));
    }
    let user = own_account(app, who).await?;
    prove_factor_change(app, who, &user, reached, proof, what).await
}

/// An administrator's fresh proof before changing another account. Check the
/// target first: a refused change after this has spent the proof.
pub async fn prove_acting_admin(
    app: &ApplianceState,
    who: &Identity,
    reached: &Reached,
    proof: FactorProof,
    what: &'static str,
) -> Result<(), ApiError> {
    if who.is_local() {
        return Ok(());
    }
    prove_caller(app, who, reached, proof, what).await.map(drop)
}

fn refuse_own_account(who: &Identity, user_id: &str) -> Result<(), ApiError> {
    if who.account_id() == Some(user_id) {
        return Err(ApiError::Forbidden(
            "this is for another account; your own is changed from your account screen".to_string(),
        ));
    }
    Ok(())
}

/// The store for `who`'s writes on another account, sparing host admins' unless `who` is one.
pub fn store_for(app: &ApplianceState, who: &Identity) -> Store {
    if who.is_host_admin() {
        app.store.clone()
    } else {
        app.store.sparing_host_admins()
    }
}

fn no_such_passkey() -> ApiError {
    ApiError::NotFound("this account has no such passkey".to_string())
}
