# wslib-auth-oidc

Verifies OIDC ID tokens (RS256) against an issuer's JWKS, and hands back the
claims as the caller's type. Keys are cached and refetched when a token names
one the cache doesn't hold, so a rotation is picked up, without letting a flood
of bad tokens or a failing issuer cause a fetch per request.

```rust
#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
}

let verifier = wslib_auth_oidc::Verifier::cognito(http, "ap-southeast-2", pool_id, client_id);
match verifier.verify::<Claims>(token).await {
    Ok(claims) => { /* signed in as claims.sub */ }
    Err(wslib_auth_oidc::Error::Unavailable(why)) => { /* 503: the issuer can't be reached */ }
    Err(wslib_auth_oidc::Error::Rejected(why)) => { /* 401 */ }
    Err(_) => { /* 401 */ }
}
```

## Setting it up

- **The crypto backend is the app's.** Enable exactly one of the
  `rust-crypto` and `aws-lc-rs` features (they pick jsonwebtoken's), or
  install a jsonwebtoken `CryptoProvider`. Without one, or with both, the
  first verify panics.
- **So is the HTTP client.** Pass a `reqwest::Client` (0.13) built with the
  app's TLS provider and roots. An app still on reqwest 0.12 carries both.
- **One `Verifier` per issuer, shared** (in an `Arc` or app state): each holds
  its own key cache. Call `refresh` at start-up to warm it, if the first
  sign-in shouldn't wait on a fetch.

## What's here

- **`Verifier::new(http, issuer, audience)`**: the token's `iss` must equal
  `issuer`, its `aud` must be `audience`, and `exp`, `iss` and `aud` must be
  present; `exp` and `nbf` are checked with jsonwebtoken's 60 s leeway. Keys
  come from `<issuer>/.well-known/jwks.json`; `with_jwks_url` names another.
- **`Verifier::cognito(http, region, user_pool_id, client_id)`**: the user
  pool's issuer, and `token_use` must be `id`. Cognito access tokens carry
  `client_id` rather than `aud` and are refused anyway; `token_use` makes it
  explicit.
- **`with_token_use`**: refuses tokens whose `token_use` claim is absent or
  different.
- **`verify::<C>(token)`**: the claims as any `DeserializeOwned` type, once the
  checks pass. Claims that don't fit `C` are `Rejected`.
- **The key cache.** A token whose `kid` isn't cached refetches the JWKS, at
  most once per `with_refetch_after` window (30 s), counted from the last
  attempt whether it worked or not; concurrent misses wait on one fetch. Keys
  older than `with_max_key_age` (1 h) are refetched on the next token, so a key
  the issuer withdraws stops verifying; if that fetch fails, the held keys stay
  in use. A fetch that fails, or brings no usable key, keeps the keys already
  held. Each fetch times out after `with_timeout` (5 s).
- **Keys used:** RSA keys with a `kid`, whose `alg` is RS256 or absent and whose
  `use` is `sig` or absent. Others are skipped, not refused.
- **`Error`**: `Rejected` (malformed, unknown key, bad signature, wrong
  issuer, audience or use, expired, or claims that don't fit) and
  `Unavailable` (the key isn't cached and the JWKS couldn't be fetched, so the
  token may be good). Both carry text for the log, `Unavailable`'s naming the
  JWKS URL; show users a fixed message.
  Nothing is logged.

## What isn't

OIDC discovery (`/.well-known/openid-configuration`): the JWKS URL is the
issuer's `/.well-known/jwks.json` or one you name. Algorithms other than
RS256. Access tokens, refresh tokens, sign-in flows and sessions. Roles,
groups and what a claim means to the app.
