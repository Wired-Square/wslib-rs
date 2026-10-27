-- A stand-in for a product's first migration; its foreign key into `users`
-- resolves only if the platform's chain ran first.
CREATE TABLE app_widgets (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL,
    owner   TEXT NOT NULL REFERENCES users (id)
) STRICT;

-- Acts at the statement, so a restore that re-inserted an account would blank it.
CREATE TABLE app_notes (
    id     INTEGER PRIMARY KEY,
    title  TEXT NOT NULL,
    author TEXT REFERENCES users (id) ON DELETE SET NULL
) STRICT;
