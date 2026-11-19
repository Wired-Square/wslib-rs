//! Verifies OIDC ID tokens (RS256) against an issuer's JWKS. Keys are cached;
//! a token signed by a key the cache doesn't hold refetches the JWKS, at most
//! once per [`Verifier::with_refetch_after`] window whether the fetch worked
//! or not, so a rotation is picked up and a flood of bad tokens or a failing
//! issuer isn't hammered.
//!
//! ```no_run
//! # async fn run(token: &str) -> Result<(), wslib_auth_oidc::Error> {
//! #[derive(serde::Deserialize)]
//! struct Claims {
//!     sub: String,
//!     email: Option<String>,
//! }
//!
//! let verifier = wslib_auth_oidc::Verifier::cognito(
//!     reqwest::Client::new(),
//!     "ap-southeast-2",
//!     "ap-southeast-2_EXAMPLE",
//!     "the-app-client-id",
//! );
//! let claims: Claims = verifier.verify(token).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Signatures are checked by jsonwebtoken with the crypto backend the app
//! picks: exactly one of the `rust-crypto` and `aws-lc-rs` features, or a
//! jsonwebtoken `CryptoProvider` the app installs. Without one, or with both,
//! the first verify panics.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use tokio::sync::{Mutex, RwLock};

/// Checks ID tokens from one issuer for one audience. Share one per issuer:
/// each holds its own key cache.
pub struct Verifier {
    http: reqwest::Client,
    jwks_url: String,
    validation: Validation,
    token_use: Option<String>,
    timeout: Duration,
    refetch_after: Duration,
    max_key_age: Duration,
    keys: RwLock<Keys>,
    fetching: Mutex<()>,
}

#[derive(Default)]
struct Keys {
    by_kid: HashMap<String, Arc<DecodingKey>>,
    fetched_at: Option<Instant>,
    attempted_at: Option<Instant>,
    failure: Option<Error>,
}

impl Verifier {
    /// Tokens must carry `iss` = `issuer` and `aud` = `audience`. Keys come from
    /// `<issuer>/.well-known/jwks.json` unless [`Self::with_jwks_url`] says
    /// otherwise. The app builds `http`, which is where its TLS provider and
    /// roots come from.
    pub fn new(
        http: reqwest::Client,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        let issuer = issuer.into();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&issuer]);
        validation.set_audience(&[audience.into()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_nbf = true;
        Self {
            http,
            jwks_url: format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')),
            validation,
            token_use: None,
            timeout: Duration::from_secs(5),
            refetch_after: Duration::from_secs(30),
            max_key_age: Duration::from_secs(60 * 60),
            keys: RwLock::default(),
            fetching: Mutex::default(),
        }
    }

    /// An Amazon Cognito user pool's ID tokens for one app client. Access
    /// tokens are refused: Cognito tells them apart only by `token_use`.
    pub fn cognito(
        http: reqwest::Client,
        region: &str,
        user_pool_id: &str,
        client_id: impl Into<String>,
    ) -> Self {
        let issuer = format!("https://cognito-idp.{region}.amazonaws.com/{user_pool_id}");
        Self::new(http, issuer, client_id).with_token_use("id")
    }

    pub fn with_jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = url.into();
        self
    }

    /// Refuses a token whose `token_use` claim is absent or different.
    pub fn with_token_use(mut self, token_use: impl Into<String>) -> Self {
        self.token_use = Some(token_use.into());
        self
    }

    /// How long one JWKS fetch may take. 5 s by default.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The least time between two fetches a token can cause, after a success
    /// or a failure. 30 s by default.
    pub fn with_refetch_after(mut self, refetch_after: Duration) -> Self {
        self.refetch_after = refetch_after;
        self
    }

    /// How long fetched keys are trusted before the next token refetches
    /// them, so a key the issuer withdraws stops verifying. If that fetch
    /// fails the old keys are kept. 1 h by default.
    pub fn with_max_key_age(mut self, max_key_age: Duration) -> Self {
        self.max_key_age = max_key_age;
        self
    }

    /// The token's claims, once its signature, `iss`, `aud`, `exp`, `nbf` and
    /// any required `token_use` check out.
    pub async fn verify<C: DeserializeOwned>(&self, token: &str) -> Result<C, Error> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| Error::rejected_by("its header does not decode", e))?;
        let kid = header
            .kid
            .ok_or_else(|| Error::rejected("the token names no key (kid)"))?;
        let key = self.key(&kid).await?;
        let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &self.validation)
            .map_err(|e| Error::rejected_by("it does not verify", e))?
            .claims;
        if let Some(expected) = &self.token_use {
            let found = claims.get("token_use").and_then(Value::as_str);
            if found != Some(expected) {
                return Err(Error::rejected(format!(
                    "token_use is {found:?}, not {expected:?}"
                )));
            }
        }
        serde_json::from_value(Value::Object(claims))
            .map_err(|e| Error::rejected_by("the claims don't fit", e))
    }

    /// Fetches the JWKS now, whatever the cache holds: to warm it at start-up,
    /// or from a timer. A failure keeps the keys already held.
    pub async fn refresh(&self) -> Result<(), Error> {
        let _fetching = self.fetching.lock().await;
        self.fetch().await
    }

    async fn key(&self, kid: &str) -> Result<Arc<DecodingKey>, Error> {
        {
            let keys = self.keys.read().await;
            let fresh = keys
                .fetched_at
                .is_some_and(|at| at.elapsed() < self.max_key_age);
            if let (true, Some(key)) = (fresh, keys.by_kid.get(kid)) {
                return Ok(key.clone());
            }
        }
        self.refresh_if_due().await;
        let keys = self.keys.read().await;
        match (keys.by_kid.get(kid), &keys.failure) {
            (Some(key), _) => Ok(key.clone()),
            (None, Some(failure)) => Err(failure.clone()),
            (None, None) => Err(Error::rejected(format!(
                "the issuer's JWKS has no key {kid:?}"
            ))),
        }
    }

    async fn refresh_if_due(&self) {
        let _fetching = self.fetching.lock().await;
        let due = self
            .keys
            .read()
            .await
            .attempted_at
            .is_none_or(|at| at.elapsed() >= self.refetch_after);
        if due {
            let _ = self.fetch().await;
        }
    }

    async fn fetch(&self) -> Result<(), Error> {
        let outcome = self.download().await;
        let mut keys = self.keys.write().await;
        let now = Instant::now();
        keys.attempted_at = Some(now);
        match outcome {
            Ok(by_kid) => {
                keys.by_kid = by_kid;
                keys.fetched_at = Some(now);
                keys.failure = None;
                Ok(())
            }
            Err(failure) => {
                keys.failure = Some(failure.clone());
                Err(failure)
            }
        }
    }

    async fn download(&self) -> Result<HashMap<String, Arc<DecodingKey>>, Error> {
        let url = &self.jwks_url;
        let answer = self
            .http
            .get(url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| Error::unavailable(url, "the request failed", Some(Arc::new(e))))?;
        let status = answer.status();
        if !status.is_success() {
            return Err(Error::unavailable(url, format!("HTTP {status}"), None));
        }
        let body = answer
            .bytes()
            .await
            .map_err(|e| Error::unavailable(url, "the body did not arrive", Some(Arc::new(e))))?;
        signing_keys(url, &body)
    }
}

/// Keys of other types or uses are skipped rather than refused, so an issuer
/// adding one doesn't break verification.
fn signing_keys(url: &str, jwks: &[u8]) -> Result<HashMap<String, Arc<DecodingKey>>, Error> {
    let jwks: Value = serde_json::from_slice(jwks)
        .map_err(|e| Error::unavailable(url, "it is not JSON", Some(Arc::new(e))))?;
    let Some(Value::Array(entries)) = jwks.get("keys") else {
        return Err(Error::unavailable(url, "it has no `keys` list", None));
    };
    let keys: HashMap<_, _> = entries
        .iter()
        .filter_map(|entry| serde_json::from_value::<Jwk>(entry.clone()).ok())
        .filter(is_rs256_signing)
        .filter_map(|jwk| {
            let key = DecodingKey::from_jwk(&jwk).ok()?;
            Some((jwk.common.key_id?, Arc::new(key)))
        })
        .collect();
    if keys.is_empty() {
        return Err(Error::unavailable(
            url,
            "it has no RS256 signing key with a kid",
            None,
        ));
    }
    Ok(keys)
}

fn is_rs256_signing(jwk: &Jwk) -> bool {
    matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
        && matches!(jwk.common.key_algorithm, None | Some(KeyAlgorithm::RS256))
        && matches!(
            jwk.common.public_key_use,
            None | Some(PublicKeyUse::Signature)
        )
}

/// Why a token wasn't accepted, for the log; show users a fixed message.
///
/// `why` is this crate's sentence; `source` is the error of jsonwebtoken,
/// serde_json or reqwest behind it, where there is one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// The token is bad: malformed, signed by an unknown key, expired, or for
    /// another issuer, audience or use.
    Rejected {
        why: String,
        source: Option<Arc<dyn StdError + Send + Sync>>,
    },
    /// The token's key isn't cached and the issuer's JWKS at `url` couldn't
    /// be fetched, so the token may be good.
    Unavailable {
        url: String,
        why: String,
        source: Option<Arc<dyn StdError + Send + Sync>>,
    },
}

impl Error {
    fn rejected(why: impl Into<String>) -> Self {
        Self::Rejected {
            why: why.into(),
            source: None,
        }
    }

    fn rejected_by(why: &str, source: impl StdError + Send + Sync + 'static) -> Self {
        Self::Rejected {
            why: why.into(),
            source: Some(Arc::new(source)),
        }
    }

    fn unavailable(
        url: &str,
        why: impl Into<String>,
        source: Option<Arc<dyn StdError + Send + Sync>>,
    ) -> Self {
        Self::Unavailable {
            url: url.into(),
            why: why.into(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { why, .. } => write!(f, "token rejected: {why}"),
            Self::Unavailable { url, why, .. } => {
                write!(f, "the issuer's keys at {url} are unavailable: {why}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Rejected { source, .. } | Self::Unavailable { source, .. } => {
                source.as_deref().map(|e| e as &(dyn StdError + 'static))
            }
        }
    }
}
