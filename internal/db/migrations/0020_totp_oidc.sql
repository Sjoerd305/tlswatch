-- TOTP and generic OpenID Connect (see the specification, "Users,
-- authentication and authorisation"). Users gain the login method oidc,
-- which the CHECK on method in 0001 does not allow; SQLite cannot alter a
-- constraint, so the table is rebuilt (with foreign keys off, as Migrate
-- runs it, so sessions, tokens and calendars keep referring to "users").
-- The TOTP secret is sealed under the secret key; totp_since is when it
-- was set up (0 = none) and totp_last_step the last time step accepted, so
-- a code cannot be used twice.
CREATE TABLE users_new (
	id             INTEGER PRIMARY KEY,
	email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
	name           TEXT NOT NULL DEFAULT '',
	role           TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
	method         TEXT NOT NULL CHECK (method IN ('local', 'google', 'oidc')),
	password_hash  TEXT NOT NULL DEFAULT '',
	enabled        INTEGER NOT NULL DEFAULT 1,
	failed_count   INTEGER NOT NULL DEFAULT 0,
	locked_until   INTEGER NOT NULL DEFAULT 0,
	theme          TEXT NOT NULL DEFAULT 'system',
	last_login     INTEGER NOT NULL DEFAULT 0,
	created_at     INTEGER NOT NULL,
	totp_sealed    BLOB,
	totp_since     INTEGER NOT NULL DEFAULT 0,
	totp_last_step INTEGER NOT NULL DEFAULT 0
);
INSERT INTO users_new (id, email, name, role, method, password_hash, enabled, failed_count, locked_until, theme, last_login, created_at)
	SELECT id, email, name, role, method, password_hash, enabled, failed_count, locked_until, theme, last_login, created_at FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Single-use recovery codes, stored as SHA-256 hashes like the one-time
-- links.
CREATE TABLE recovery_codes (
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	hash    TEXT NOT NULL,
	used_at INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (user_id, hash)
);
