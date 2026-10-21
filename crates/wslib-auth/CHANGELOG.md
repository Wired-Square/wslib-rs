# Changelog

## 0.1.0

- `Sessions` over a `SessionStore`: issue, look up, re-stamp, end one, end a
  user's, purge expired, all failing with one `SessionError`. Opaque 32-byte
  tokens, only their SHA-256 at rest; 12-hour lifetime by default.
- `Proof`, begun before a credential check and required to issue or re-stamp
  a session; `Session::proved_at` and `proved_since`, so a sign-in that raced
  a password change is refused.
- `SqliteSessionStore` and `PgSessionStore` behind `sqlite` and `postgres`,
  in a table the caller names with a `TableName` checked at compile time;
  `stamp` and `parse_stamp` for the stored time format.
- `SessionCookie`: `Set-Cookie` values to set and clear, and the token read
  from the request's `Cookie` headers, the last of its name winning.
- `Session::reauthenticated_within` and `REAUTHENTICATION_WINDOW` (5 minutes).
- `Attempts`: an in-memory limit on wrong attempts per key per window,
  shared by its clones; an `Attempt` can move into a task.
