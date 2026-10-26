-- The permanent id of the account an audit row's actor names, so a rename keeps
-- the trail; NULL for an actor that is no account, for a row from a `tracing`
-- event, and for every row written before this.
--
-- Frozen the moment it lands anywhere, like 0001 — see its header.

ALTER TABLE audit ADD COLUMN actor_id TEXT;
