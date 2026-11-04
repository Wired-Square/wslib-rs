# Changelog

## 0.1.3

- `Sessions::resolve_bound` documents that a session never bound resolves
  without a secret, so a host moving its own bound secrets here copies them
  first.
- Floor: `wslib-auth` 0.1.5, whose bound secrets survive a clock step back
  and are read with their session in one query.

## 0.1.2

- `Sessions::bind` mints a secret bound to a session that resolves, kept in
  the store's `SESSION_SECRETS_TABLE` (newest 16), and
  `Sessions::resolve_bound` resolves as `resolve_with_reauthenticated_at`
  but answers `AuthError::NoSession` when the session has a bound secret and
  is not given one of them. A session never bound resolves without one. The
  secrets end with the session's row.
- Floors: `wslib-auth` 0.1.3 and `wslib-appliance-store` 0.1.3, for the
  bound secrets and their table.

## 0.1.1

- Dependency floors: `wslib-secret`, `wslib-appliance-store` and
  `wslib-appliance-types` 0.1.1 (were 0.1.0), the floors the rest of the
  family takes. No change to the API.

## 0.1.0

Moved from `appliance-auth` 0.17.1 in wslib-appliance-rs; what differs:

- `ring` is gone. A pending sign-in's token comes from the OS through
  `getrandom`, and the password-hash digest it keeps from `sha2`, the same
  SHA-256. No crypto provider is needed.
- The `sessions` feature is gone, and `Sessions` is always built: the store
  already carries `wslib-auth`'s session store. A manifest naming the feature
  fails to resolve; drop it.
- Events, the `audit` refusals included, are logged under the
  `wslib_appliance_auth` target (was `appliance_auth`): a subscriber or log
  capture filtering on `appliance_*` no longer sees them, and nothing fails.
- `CodeAttempts` is built on `wslib-auth`'s `Attempts`, at the same five
  wrong codes per fifteen minutes, with the same `TooManyCodes` message.
- `secrets_match` is gone: `wslib_secret::Secret::matches` is the same
  constant-time comparison.
