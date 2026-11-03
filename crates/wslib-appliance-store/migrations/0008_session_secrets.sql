-- The thirteenth platform table: the secrets bound to a session beside its
-- cookie, each kept as its SHA-256, which go with the session's row.
--
-- Frozen the moment it lands anywhere, like 0001 — see its header.

CREATE TABLE platform_session_secrets (
    session_hash TEXT NOT NULL REFERENCES platform_sessions (token_hash) ON DELETE CASCADE,
    secret_hash  TEXT NOT NULL,
    issued_at    TEXT NOT NULL,
    PRIMARY KEY (session_hash, secret_hash)
) STRICT;
