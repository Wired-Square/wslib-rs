-- The seventh to tenth platform tables: an account's second factors, beside
-- its password in `users`, and whether it must enrol TOTP. Each row goes with
-- its account.
--
-- Frozen the moment it lands anywhere, like 0001 — see its header.

CREATE TABLE totp (
    user_id   TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The shared key, as text.
    secret    TEXT NOT NULL,
    -- 0 while an enrolment waits for its first code, which is when it takes effect.
    confirmed INTEGER NOT NULL DEFAULT 0,
    -- The newest time step a code was accepted for; no code at or below it is.
    last_step INTEGER
) STRICT;

CREATE TABLE recovery_codes (
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Lowercase hex SHA-256 of the code; a used code's row is deleted.
    sha256  TEXT NOT NULL,
    PRIMARY KEY (user_id, sha256)
) STRICT;

CREATE TABLE passkeys (
    id            TEXT PRIMARY KEY NOT NULL,
    user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    -- The credential's COSE_Key, as the authenticator gave it.
    public_key    BLOB NOT NULL,
    sign_count    INTEGER NOT NULL,
    name          TEXT NOT NULL,
    -- The host it was registered on, which is the only one it signs for.
    rp_id         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
) STRICT;

CREATE INDEX passkeys_user ON passkeys (user_id);

-- An account an administrator has required to enrol TOTP before its next
-- password sign-in; the row goes when a key is confirmed.
CREATE TABLE totp_required (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users (id) ON DELETE CASCADE
) STRICT;
