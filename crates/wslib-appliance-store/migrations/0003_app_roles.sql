-- The sixth platform table: each account's role in each app the box runs,
-- beside its role on the box in `users.role`, which from here may also be
-- 'hostadmin'.
--
-- Frozen the moment it lands anywhere, like 0001 — see its header.

CREATE TABLE app_roles (
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    app     TEXT NOT NULL,
    -- No 'hostadmin': a host admin is Admin in every app without a row.
    role    TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    PRIMARY KEY (user_id, app)
) STRICT;
