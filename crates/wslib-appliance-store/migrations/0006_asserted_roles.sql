-- The eleventh platform table: the role of each caller a front door asserts
-- by an id of its own, given the first time it is seen and kept from then on.
-- It belongs to this box: the chassis's backup does not carry it.
--
-- Frozen the moment it lands anywhere, like 0001 — see its header.

CREATE TABLE asserted_roles (
    -- Whose ids these are, such as 'ingress'.
    source       TEXT NOT NULL,
    id           TEXT NOT NULL,
    -- The latest name the front door gave, for display only.
    username     TEXT NOT NULL,
    display_name TEXT,
    -- NULL for a caller the first-sight rule refused, until it is given one.
    role         TEXT CHECK (role IN ('viewer', 'operator', 'admin')),
    first_seen   TEXT NOT NULL,
    PRIMARY KEY (source, id)
) STRICT;
