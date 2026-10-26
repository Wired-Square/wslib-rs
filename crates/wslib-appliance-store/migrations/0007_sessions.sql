-- The twelfth platform table: a signed-in browser, keyed by the SHA-256 of the
-- token only its cookie carries. It belongs to this box: the chassis's backup
-- does not carry it, and a restore of the accounts or a factory reset empties it.
--
-- Frozen the moment it lands anywhere, like 0001 — see its header.

CREATE TABLE platform_sessions (
    token_hash         TEXT PRIMARY KEY NOT NULL,
    user_id            TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    -- When the sign-in's credential check began; a session proved before the
    -- account's `sessions_valid_from` is refused.
    proved_at          TEXT NOT NULL,
    reauthenticated_at TEXT NOT NULL
) STRICT;

CREATE INDEX platform_sessions_by_user ON platform_sessions (user_id);

-- The key that signed the tokens these rows replace.
DELETE FROM settings WHERE key = 'secret.session_signing';
