# wslib-auth

Browser sessions kept server-side. A session is a row keyed by the SHA-256 of
an opaque token (32 random bytes, unpadded base64url) that only the cookie
carries, so signing out ends one browser and a password change ends them all.
Also the session cookie, the re-authentication window, and an in-memory limit
on wrong attempts.

```rust
use wslib_auth::{Attempts, SessionCookie, Sessions, SqliteSessionStore, REAUTHENTICATION_WINDOW};

let sessions = Sessions::new(SqliteSessionStore::<String>::new(pool, "app_sessions")?);
let cookie = SessionCookie::new("app_session").path("/app");
let password_attempts = Attempts::<String>::default(); // 5 wrong per 15 minutes

// Sign-in:
let attempt = password_attempts.admit(username.clone())?;   // TooManyAttempts
/* verify the password; a wrong one drops `attempt`, which stays counted */
attempt.succeeded();
let (token, _) = sessions.issue(user_id).await?;
response.headers_mut().append(SET_COOKIE, cookie.set(&token));

// Each request:
let session = match cookie.token_in(request.headers()) {
    Some(token) => sessions.lookup(&token).await?,
    None => None,
};
// Then the app's own checks: the account exists, is enabled, and
// `session.created_at` is not before its sessions were invalidated.

// A sensitive action:
session.reauthenticated_within(REAUTHENTICATION_WINDOW, wslib_auth::now());
// after the password is proved again: sessions.reauthenticated(&token)

// Sign-out, and a password change:
sessions.end(&token).await?;            // with cookie.clear() in Set-Cookie
sessions.end_all(&user_id).await?;
```

## What's here

- **`Sessions<S>`** over a `SessionStore`: `issue` (purges expired rows
  first), `lookup` (unexpired only), `reauthenticated`, `end`, `end_all`,
  `purge_expired`. Lifetime 12 hours from issue, absolute;
  `with_lifetime` to change it. A `Session` is `user_id`, `created_at`,
  `expires_at` and `reauthenticated_at`, as `chrono::DateTime<Utc>` at
  microsecond precision (`wslib_auth::now()`).
- **`SessionStore`**: an async trait (native `impl Future + Send`) with the
  user id as an associated type, for a store of your own.
- **`SqliteSessionStore<U>`** and **`PgSessionStore<U>`**, features `sqlite`
  and `postgres` (sqlx 0.8, no TLS). The table is yours, named at
  construction (a plain identifier). `U` is stored as its `Display` and read
  with `FromStr`; times as fixed-width RFC 3339 text, which sorts in time
  order.
- **`SessionCookie`**: name, path (`/`), `SameSite` (`Strict`) and `Secure`
  (on) are yours; `HttpOnly` always; `max_age` for a cookie that outlives the
  browser session. `set(token)` and `clear()` give `Set-Cookie` values;
  `token_in(headers)` reads the first non-empty value across every `Cookie`
  header.
- **`Session::reauthenticated_within(window, now)`**: re-authenticated no
  longer ago than `window` and not in the future. `REAUTHENTICATION_WINDOW`
  is 5 minutes.
- **`Attempts<K>`**: N wrong attempts per key per sliding window (5 per 15
  minutes by default). `admit(key)` counts the attempt as wrong up front;
  `succeeded()` clears the key, `uncounted()` withdraws that one attempt.
  `TooManyAttempts` carries `retry_after`.
- **`TokenHash`** compares in constant time, for a store that compares in Rust.

## The table

The app runs this in its own migrations, with the table name it passes to
the store. A foreign key to its users table is its choice.

SQLite:

```sql
CREATE TABLE app_sessions (
    token_hash          TEXT PRIMARY KEY NOT NULL,
    user_id             TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    reauthenticated_at  TEXT NOT NULL
) STRICT;

CREATE INDEX app_sessions_by_user ON app_sessions (user_id);
```

PostgreSQL:

```sql
CREATE TABLE app_sessions (
    token_hash          TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    created_at          TEXT COLLATE "C" NOT NULL,
    expires_at          TEXT COLLATE "C" NOT NULL,
    reauthenticated_at  TEXT COLLATE "C" NOT NULL
);

CREATE INDEX app_sessions_by_user ON app_sessions (user_id);
```

## What isn't

Accounts, roles, sign-in providers, API tokens and framework extractors.
Password hashing is `wslib-auth-password`.
