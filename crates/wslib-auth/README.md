# wslib-auth

Browser sessions kept server-side. A session is a row keyed by the SHA-256 of
an opaque token (32 random bytes, unpadded base64url) that only the cookie
carries, so signing out ends one browser and a password change ends them all.
Also the session cookie, the re-authentication window, and an in-memory limit
on wrong attempts.

```rust
use wslib_auth::{
    Attempts, Proof, REAUTHENTICATION_WINDOW, SessionCookie, Sessions, SqliteSessionStore,
    TableName,
};

const SESSIONS: TableName = TableName::new("app_sessions"); // checked at compile time
let sessions = Sessions::new(SqliteSessionStore::<String>::new(pool, SESSIONS));
let cookie = SessionCookie::new("app_session").path("/app");
let password_attempts = Attempts::<String>::default(); // 5 wrong per 15 minutes

// Sign-in:
let attempt = password_attempts.admit(username.clone())?;   // TooManyAttempts
let proof = Proof::begin();                                  // before reading the account
/* read the account and verify the password; a wrong one drops `attempt`, which stays counted */
attempt.succeeded();
let (token, _) = sessions.issue(user_id, proof).await?;
response.headers_mut().append(SET_COOKIE, cookie.set(&token));

// Each request:
let session = match cookie.token_in(request.headers()) {
    Some(token) => sessions.lookup(&token).await?,
    None => None,
};
// Then the app's own checks: the account exists, is enabled, and
// session.proved_since(account.sessions_valid_from).

// A sensitive action:
session.reauthenticated_within(REAUTHENTICATION_WINDOW, wslib_auth::now());
// with a Proof begun before the password is checked again:
sessions.reauthenticated(&token, proof).await?;

// Sign-out, and a password change, which then moves sessions_valid_from to
// wslib_auth::now() taken after the new password is committed:
sessions.end(&token).await?;            // with cookie.clear() in Set-Cookie
sessions.end_all(&user_id).await?;
```

A sign-in that checks the old password just before a password change, and
issues its session just after that change's `end_all`, would otherwise survive
the change. `proved_since` compares the instant the check began, not when the
session was issued, so that sign-in is refused; in a two-step sign-in, begin
the `Proof` at the step that re-reads the account. Where the request itself
moves the cutoff (a password change, a first account), begin it after that
write, or the new session is refused at once. Stamp the cutoff itself after
the new credential is committed: a check that begins between an earlier stamp
and the commit still reads the old one.

## What's here

- **`Sessions<S>`** over a `SessionStore`: `issue(user_id, proof)` (purges
  expired rows first), `lookup` (unexpired only), `reauthenticated(token,
  proof)`, `end`, `end_all`, `purge_expired`. `end`, `end_all` and
  `reauthenticated` say whether there was a session. Every call fails with
  `SessionError<E>` (the random source, or the store's `E`), which `?`
  carries into `anyhow` or a boxed error. Lifetime 12 hours from issue,
  absolute; `with_lifetime` to change it.
- **`Session`**: `user_id`, `created_at`, `expires_at`, `proved_at` and
  `reauthenticated_at`, as `chrono::DateTime<Utc>` at microsecond precision
  (`wslib_auth::now()`; `stamp`/`parse_stamp` give the stores' text form, with
  no feature needed). `proved_since(cutoff)` for the app's invalidation
  check.
- **`Proof`**: `Proof::begin()` before any credential check (password,
  passkey, code); `Copy`, so a pending second step can hold one.
- **`SessionStore`**: an async trait (native `impl Future + Send`) with the
  user id as an associated type, for a store of your own.
- **`SqliteSessionStore<U>`** and **`PgSessionStore<U>`**, features `sqlite`
  and `postgres` (sqlx 0.8, no TLS). The table is yours, named by a
  `TableName`: `TableName::new` in a const refuses a bad literal at compile
  time, and `TableName::parse` takes a name known at run time. `U` is stored
  as its `Display` and read with `FromStr`; times as `stamp`s, fixed-width
  RFC 3339 text that sorts in time order (`parse_stamp` reads one back, for
  tests). A row that won't decode fails with `ColumnDecode` naming
  `table.column`.
- **`SessionCookie`**: name, path (`/`), `SameSite` (`Strict`) and `Secure`
  (on) are yours; `HttpOnly` always; `max_age` for a cookie that outlives the
  browser session. `set(token)` and `clear()` give `Set-Cookie` values;
  `token_in(headers)` reads the value across every `Cookie` header, and
  refuses two different values under the name: browsers order same-name
  cookies by path, so either pick could be a cookie a script planted. A
  planted duplicate signs that browser out wherever its path reaches, rather
  than slipping in another session. Apps sharing an origin give their cookies
  distinct names.
- **`Session::reauthenticated_within(window, now)`**: re-authenticated no
  longer ago than `window` and not in the future. `REAUTHENTICATION_WINDOW`
  is 5 minutes.
- **`Attempts<K>`**: N wrong attempts per key per sliding window (5 per 15
  minutes by default). `admit(key)` counts the attempt as wrong up front;
  `succeeded()` clears the key, `uncounted()` withdraws that one attempt.
  `TooManyAttempts` carries `retry_after`. Lockouts are in memory and reset
  on restart. `Attempts` is `Send + Sync` and cheap to clone (clones share
  the count), and an `Attempt` owns what it needs, so it can move into a
  task.
- **`TokenHash`** compares in constant time, for a store that compares in Rust.

## The table

The app runs this in its own migrations, with the table name it passes to
the store.

SQLite:

```sql
CREATE TABLE app_sessions (
    token_hash          TEXT PRIMARY KEY NOT NULL,
    user_id             TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    proved_at           TEXT NOT NULL,
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
    proved_at           TEXT COLLATE "C" NOT NULL,
    reauthenticated_at  TEXT COLLATE "C" NOT NULL
);

CREATE INDEX app_sessions_by_user ON app_sessions (user_id);
```

A table made without `proved_at` takes the column, backfilled from
`created_at`:

```sql
-- SQLite
ALTER TABLE app_sessions ADD COLUMN proved_at TEXT NOT NULL DEFAULT '';
UPDATE app_sessions SET proved_at = created_at;

-- PostgreSQL
ALTER TABLE app_sessions ADD COLUMN proved_at TEXT COLLATE "C";
UPDATE app_sessions SET proved_at = created_at;
ALTER TABLE app_sessions ALTER COLUMN proved_at SET NOT NULL;
```

A foreign key to the users table, and `ON DELETE CASCADE`, are the app's
choice. Under a cascade, a restore that deletes and re-inserts users ends
every session.

`issue` purges expired rows and inserts in two statements, not one
transaction: the purge is housekeeping, and a failure between them leaves
only rows the next purge takes. Expired rows are purged only on `issue`, so
call `purge_expired` on a schedule if quiet periods should not keep them.
`lookup` trusts the clock: if it steps back, a row that expired but has not
been purged is found again, so a scheduled purge also keeps that set small.

## What isn't

Accounts, roles, sign-in providers, API tokens and framework extractors.
Password hashing is `wslib-auth-password`.
