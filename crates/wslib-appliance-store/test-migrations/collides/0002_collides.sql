-- An app that numbered its migrations from 1, which is the natural thing to do
-- and collides with the platform's range for as long as the platform keeps
-- adding to it.
--
-- Never applied. It exists so the refusal has something to refuse.
CREATE TABLE app_widgets (id INTEGER PRIMARY KEY) STRICT;
