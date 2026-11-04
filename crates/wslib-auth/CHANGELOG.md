# Changelog

## 0.1.4

- `Sessions::bind` answers `None` when the session is removed while its
  secret is stored, where on PostgreSQL it failed with a foreign-key error.

## 0.1.3

- Secrets bound to a session: `Sessions::bind` mints one beside the cookie's
  token, and `Sessions::lookup_bound` refuses a session that has any unless
  it is given one of them. A session keeps its newest `BOUND_SECRETS_KEPT`
  (16); a session with none is found as by `lookup`. Kept by a new
  `BoundSecretStore` trait over `SessionStore`, so a store of your own is
  unchanged until it binds.
- `SqlSessionStore::with_bound_secrets` names the secrets' table, which
  cascades from the sessions table; the README carries its DDL.

## 0.1.2

- chrono's floor is 0.4.39.

## 0.1.1

- `SqlSessionStore::remove_user_in`: a user's sessions removed inside the
  caller's transaction.

## 0.1.0

- `Sessions` over a `SessionStore`: issue, look up, re-stamp, end one, end a
  user's, purge expired, all failing with one `SessionError`. Opaque 32-byte
  tokens, only their SHA-256 at rest; 12-hour lifetime by default.
- `Proof`, begun before a credential check and required to issue or re-stamp
  a session; `Session::proved_at` and `proved_since`, so a sign-in that raced
  a password change is refused.
- `SqliteSessionStore` and `PgSessionStore` behind `sqlite` and `postgres`,
  in a table the caller names with a `TableName` checked at compile time.
- `stamp` and `parse_stamp` for the stores' time format, with no feature.
- `SessionCookie`, constructible in a `const`: `Set-Cookie` values to set and clear, and the token read
  from the request's `Cookie` headers, refused when two values share its name.
- `Session::reauthenticated_within` and `REAUTHENTICATION_WINDOW` (5 minutes).
- `Attempts`: an in-memory limit on wrong attempts per key per window,
  shared by its clones; an `Attempt` can move into a task.
