-- The fifth platform table: authorities this box trusts for the connections
-- it makes, beside the hosts it trusts by fingerprint in `trusted_certs`.
--
-- Frozen the moment it lands anywhere, like 0001 — see its header.

CREATE TABLE trusted_cas (
    -- Lowercase hex SHA-256 of the DER, so the same authority cannot be
    -- installed twice and a row is named by the thing it is.
    sha256     TEXT PRIMARY KEY NOT NULL,
    subject    TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after  TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    added_by   TEXT NOT NULL,
    -- The certificate itself, as one PEM section: a root store is built from
    -- the bytes, and text is what a JSON bundle carries.
    pem        TEXT NOT NULL
) STRICT;
