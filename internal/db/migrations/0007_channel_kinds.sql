-- Channels gain the kinds webhook, ntfy, slack and discord. The CHECK on kind
-- in 0001 only knew smtp and telegram, and SQLite cannot alter a constraint,
-- so the table is rebuilt without it; the kinds are checked by the
-- application. Migrate runs this with foreign keys off, so dropping the old
-- table does not cascade into target_channels and alerts, which keep
-- referring to "channels" by name.
CREATE TABLE channels_new (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL UNIQUE,
	kind         TEXT NOT NULL,
	min_severity TEXT NOT NULL DEFAULT 'warning' CHECK (min_severity IN ('info', 'warning', 'critical')),
	settings     BLOB NOT NULL,
	destination  TEXT NOT NULL DEFAULT '',
	enabled      INTEGER NOT NULL DEFAULT 1,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
);
INSERT INTO channels_new SELECT id, name, kind, min_severity, settings, destination, enabled, created_at, updated_at FROM channels;
DROP TABLE channels;
ALTER TABLE channels_new RENAME TO channels;
