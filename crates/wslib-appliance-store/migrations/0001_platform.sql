-- The four tables every appliance has: accounts, settings, the audit log, and
-- the certificates this box trusts by fingerprint.
--
-- ---------------------------------------------------------------------------
-- THIS FILE IS FROZEN THE MOMENT IT LANDS ANYWHERE.
--
-- sqlx checksums the *file*, not the statements, so correcting a word of prose
-- in here stops every deployed appliance at startup — not a degraded daemon,
-- one that does not start. Corrections go in a later migration, never here.
--
-- Versions 1-999 belong to the platform; an app numbers its own from 1000.
-- ---------------------------------------------------------------------------
--
-- Every table is STRICT, so a column declared TEXT cannot quietly hold an
-- integer. Every timestamp is TEXT holding a fixed-width RFC 3339 instant in
-- UTC — see `stamp()` in lib.rs for why the width is fixed rather than
-- whatever `to_rfc3339` felt like emitting.
--
-- `INTEGER PRIMARY KEY` without AUTOINCREMENT throughout: AUTOINCREMENT
-- additionally reads and rewrites a `sqlite_sequence` row on every insert, and
-- buys only the promise that a rowid is never reused, which nothing here needs.

CREATE TABLE users (
    id                  TEXT PRIMARY KEY NOT NULL,

    -- NOCASE on the column, so the uniqueness constraint and every lookup are
    -- case-insensitive together. Folding on write instead would lose the
    -- capitalisation the operator chose, and folding only at the lookup would
    -- let `Admin` and `admin` both be created.
    username            TEXT NOT NULL COLLATE NOCASE UNIQUE,

    -- argon2id PHC string: algorithm, parameters and salt all travel with the
    -- hash, so raising the cost later re-hashes on next sign-in rather than
    -- needing a migration.
    password_hash       TEXT NOT NULL,

    -- 'viewer' | 'operator' | 'admin', matching `Role::as_str`.
    role                TEXT NOT NULL,

    -- Read on every request rather than only at sign-in, so disabling an
    -- account takes effect immediately instead of whenever its token expires.
    enabled             INTEGER NOT NULL DEFAULT 1,

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,

    -- When they last signed in. NULL means never, which is the answer worth
    -- having: an account nobody has touched since commissioning is otherwise
    -- indistinguishable from one in daily use.
    --
    -- **Written only by the sign-in path.** The session resolver reads this row
    -- on every single request, and stamping here would turn a read into a write
    -- per request, forever, on an SD card.
    last_login_at       TEXT,

    -- Sessions issued before this instant are refused.
    --
    -- **In the first migration, deliberately.** Without it a cookie taken
    -- before a password rotation goes on working for the whole session
    -- lifetime — which is precisely the case somebody rotating a leaked
    -- password believes they are fixing. Adding it later would mean every
    -- appliance deployed in between shipped with that hole.
    sessions_valid_from TEXT NOT NULL
) STRICT;

-- No index beyond the two constraints above. `id` is the primary key and
-- `username` is UNIQUE, which is an index; a third would cost a write per
-- insert to serve a query nobody runs.

CREATE TABLE settings (
    key        TEXT PRIMARY KEY NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

-- Durable record of what a human asked this daemon to do. See the module doc on
-- `appliance_types::AuditRecord` for why this is not the general
-- logs-in-SQLite design.
CREATE TABLE audit (
    id      INTEGER PRIMARY KEY,
    at      TEXT NOT NULL,
    level   TEXT NOT NULL,
    actor   TEXT NOT NULL,
    target  TEXT NOT NULL,
    message TEXT NOT NULL,
    -- The event's remaining fields as a JSON array of [name, value] pairs,
    -- carried verbatim rather than given columns: what an audit line says about
    -- itself differs per call site, and a schema that tried to model that would
    -- need a migration every time somebody added a field to a warning.
    fields  TEXT NOT NULL
) STRICT;

-- The one query this table has, and the one the retention sweep uses: newest
-- first, cursor-paged over the pair. Composite, so the index is seeked into
-- rather than filtered after. `id` breaks the tie between rows written in the
-- same instant, which is exactly what happens during the storm somebody is
-- reading.
CREATE INDEX audit_at ON audit (at DESC, id DESC);

CREATE TABLE trusted_certs (
    -- The host is the key: one pin per host, so rotating a certificate is a
    -- re-pin rather than a second row nobody can choose between.
    host       TEXT PRIMARY KEY NOT NULL,
    sha256     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    issuer     TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after  TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    added_by   TEXT NOT NULL
) STRICT;
