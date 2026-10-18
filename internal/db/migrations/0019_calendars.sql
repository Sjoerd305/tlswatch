-- Calendar feeds (see the specification, "Alerting"): a secret ICS URL
-- per feed, the token stored as a SHA-256 hash like a session's, optionally
-- limited to the targets with one tag. Deleting the user deletes them.
CREATE TABLE calendars (
	id           INTEGER PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	hash         TEXT NOT NULL UNIQUE,
	tag          TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL DEFAULT 0
);
