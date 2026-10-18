-- API tokens for the public REST API under /api/v2 (see the
-- specification, "REST API"). A token is shown once and stored as a
-- SHA-256 hash like a session's; prefix is its first characters, so the
-- list can tell tokens apart. role is no higher than the user's when it is
-- made, and never more than the user's current role when it is used.
-- expires_at 0 is no expiry (admins only). Deleting the user deletes them.
CREATE TABLE api_tokens (
	id         INTEGER PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name       TEXT NOT NULL,
	hash       TEXT NOT NULL UNIQUE,
	prefix     TEXT NOT NULL,
	role       TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
	expires_at INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	last_used  INTEGER NOT NULL DEFAULT 0,
	last_ip    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX api_tokens_user ON api_tokens(user_id);
