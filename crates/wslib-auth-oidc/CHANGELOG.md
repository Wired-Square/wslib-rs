# Changelog

## 0.1.0

- `Verifier`: checks RS256 ID tokens for one issuer and audience (signature,
  `iss`, `aud`, `exp`, `nbf`, and `token_use` when asked) and deserialises the
  claims into the caller's type. `Verifier::cognito` builds the issuer from a
  region and user pool and refuses access tokens.
- Keys from the issuer's JWKS, cached. A token whose key isn't cached refetches
  at most once per 30 s window, after a success or a failure, and concurrent
  misses share the fetch. Keys older than 1 h are refetched on the next token;
  a failed fetch keeps the keys held. Fetches time out after 5 s. All settable.
- Non-RS256 and non-signing keys in the JWKS are skipped.
- `Error` keeps `Rejected` (a bad token) and `Unavailable` (keys couldn't be
  fetched) apart. No logging.
- The app builds the `reqwest::Client` and picks jsonwebtoken's crypto backend.
