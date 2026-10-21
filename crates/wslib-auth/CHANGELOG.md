# Changelog

## 0.1.0

- `Sessions` over a `SessionStore`: issue, look up, re-stamp, end one, end a
  user's, purge expired. Opaque 32-byte tokens, only their SHA-256 at rest;
  12-hour lifetime by default.
- `SqliteSessionStore` and `PgSessionStore` behind `sqlite` and `postgres`,
  in a table the caller names.
- `SessionCookie`: `Set-Cookie` values to set and clear, and the token read
  from the request's `Cookie` headers.
- `Session::reauthenticated_within` and `REAUTHENTICATION_WINDOW` (5 minutes).
- `Attempts`: an in-memory limit on wrong attempts per key per window.
