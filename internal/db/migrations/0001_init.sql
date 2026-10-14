-- tlswatch schema, version 1. Timestamps are Unix seconds (UTC).

CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE users (
	id            INTEGER PRIMARY KEY,
	email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
	name          TEXT NOT NULL DEFAULT '',
	role          TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
	method        TEXT NOT NULL CHECK (method IN ('local', 'google')),
	password_hash TEXT NOT NULL DEFAULT '',
	enabled       INTEGER NOT NULL DEFAULT 1,
	failed_count  INTEGER NOT NULL DEFAULT 0,
	locked_until  INTEGER NOT NULL DEFAULT 0,
	theme         TEXT NOT NULL DEFAULT 'system',
	last_login    INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL
);

-- One-time links: first-admin setup, invitations, password resets.
CREATE TABLE tokens (
	hash       TEXT PRIMARY KEY,
	kind       TEXT NOT NULL CHECK (kind IN ('setup', 'invite')),
	user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL,
	used_at    INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
	hash       TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE ca_bundles (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL UNIQUE,
	pem          TEXT NOT NULL,
	fingerprints TEXT NOT NULL DEFAULT '[]',
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
);

-- settings is AES-GCM encrypted JSON (see internal/secret); destination is a
-- redacted, human-readable summary for the channel table.
CREATE TABLE channels (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL UNIQUE,
	kind         TEXT NOT NULL CHECK (kind IN ('smtp', 'telegram')),
	min_severity TEXT NOT NULL DEFAULT 'warning' CHECK (min_severity IN ('info', 'warning', 'critical')),
	settings     BLOB NOT NULL,
	destination  TEXT NOT NULL DEFAULT '',
	enabled      INTEGER NOT NULL DEFAULT 1,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
);

CREATE TABLE targets (
	id               INTEGER PRIMARY KEY,
	name             TEXT NOT NULL,
	host             TEXT NOT NULL,
	port             INTEGER NOT NULL,
	protocol         TEXT NOT NULL DEFAULT 'tls',
	servername       TEXT NOT NULL DEFAULT '',
	trust_mode       TEXT NOT NULL DEFAULT 'system' CHECK (trust_mode IN ('system', 'bundle', 'self-signed')),
	bundle_id        INTEGER REFERENCES ca_bundles(id) ON DELETE SET NULL,
	renewal_managed  INTEGER NOT NULL DEFAULT 0,
	renewal_set      INTEGER NOT NULL DEFAULT 0, -- 1 once a person chose the flag; otherwise derived from the issuer
	expected_issuer  TEXT NOT NULL DEFAULT '',
	-- NULL means "follow the global default".
	warn_days        INTEGER,
	crit_days        INTEGER,
	interval_s       INTEGER,
	timeout_s        INTEGER,
	retries          INTEGER,
	debounce         INTEGER,
	remind_warn_s    INTEGER,
	remind_crit_s    INTEGER,
	all_addresses    INTEGER NOT NULL DEFAULT 1,
	all_channels     INTEGER NOT NULL DEFAULT 1,
	tags             TEXT NOT NULL DEFAULT '',
	notes            TEXT NOT NULL DEFAULT '',
	enabled          INTEGER NOT NULL DEFAULT 1,
	created_at       INTEGER NOT NULL,
	created_by       TEXT NOT NULL DEFAULT '',
	updated_at       INTEGER NOT NULL,
	-- Current state, kept regardless of retention.
	status           TEXT NOT NULL DEFAULT 'pending',
	pinned_fp        TEXT NOT NULL DEFAULT '',
	current_fp       TEXT NOT NULL DEFAULT '',
	not_after        INTEGER NOT NULL DEFAULT 0,
	tls_version      TEXT NOT NULL DEFAULT '',
	address_count    INTEGER NOT NULL DEFAULT 0,
	last_check       INTEGER NOT NULL DEFAULT 0,
	last_error       TEXT NOT NULL DEFAULT '',
	fail_streak      INTEGER NOT NULL DEFAULT 0,
	ok_streak        INTEGER NOT NULL DEFAULT 0,
	dns_fail_streak  INTEGER NOT NULL DEFAULT 0,
	dns_ok_streak    INTEGER NOT NULL DEFAULT 0,
	next_check       INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX targets_endpoint ON targets(host, port, protocol, servername);

CREATE TABLE target_channels (
	target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
	channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
	PRIMARY KEY (target_id, channel_id)
);

CREATE TABLE certificates (
	fingerprint TEXT PRIMARY KEY,
	subject     TEXT NOT NULL,
	subject_cn  TEXT NOT NULL,
	issuer      TEXT NOT NULL,
	issuer_cn   TEXT NOT NULL,
	issuer_org  TEXT NOT NULL,
	serial      TEXT NOT NULL,
	not_before  INTEGER NOT NULL,
	not_after   INTEGER NOT NULL,
	sans        TEXT NOT NULL DEFAULT '[]',
	key_type    TEXT NOT NULL,
	key_bits    INTEGER NOT NULL,
	sig_alg     TEXT NOT NULL,
	is_ca       INTEGER NOT NULL,
	self_signed INTEGER NOT NULL,
	pem         TEXT NOT NULL,
	first_seen  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL
);
CREATE INDEX certificates_not_after ON certificates(not_after);


CREATE TABLE observations (
	id           INTEGER PRIMARY KEY,
	target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
	check_id     TEXT NOT NULL,
	address      TEXT NOT NULL,
	checked_at   INTEGER NOT NULL,
	status       TEXT NOT NULL,
	tls_version  TEXT NOT NULL DEFAULT '',
	cipher       TEXT NOT NULL DEFAULT '',
	leaf_fp      TEXT NOT NULL DEFAULT '',
	chain        TEXT NOT NULL DEFAULT '[]',
	verified     INTEGER NOT NULL DEFAULT 0,
	verify_error TEXT NOT NULL DEFAULT '',
	error        TEXT NOT NULL DEFAULT '',
	duration_ms  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX observations_target ON observations(target_id, checked_at);
CREATE INDEX observations_leaf ON observations(leaf_fp);
CREATE INDEX observations_checked ON observations(checked_at);

CREATE TABLE findings (
	id            INTEGER PRIMARY KEY,
	target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
	kind          TEXT NOT NULL,
	severity      TEXT NOT NULL,
	opened_at     INTEGER NOT NULL,
	resolved_at   INTEGER NOT NULL DEFAULT 0,
	details       TEXT NOT NULL DEFAULT '',
	fingerprint   TEXT NOT NULL DEFAULT '',
	days_left     INTEGER,
	ack_by        TEXT NOT NULL DEFAULT '',
	ack_at        INTEGER NOT NULL DEFAULT 0,
	ack_until     INTEGER NOT NULL DEFAULT 0,
	ack_comment   TEXT NOT NULL DEFAULT '',
	last_alert_at INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX findings_open ON findings(target_id, kind) WHERE resolved_at = 0;
CREATE INDEX findings_resolved ON findings(resolved_at);

-- The outbox and the alert log in one table.
CREATE TABLE alerts (
	id           INTEGER PRIMARY KEY,
	finding_id   INTEGER REFERENCES findings(id) ON DELETE CASCADE,
	channel_id   INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
	event        TEXT NOT NULL CHECK (event IN ('open', 'escalate', 'remind', 'recover', 'test', 'digest')),
	batch        TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sent', 'failed')),
	attempts     INTEGER NOT NULL DEFAULT 0,
	next_attempt INTEGER NOT NULL,
	sent_at      INTEGER NOT NULL DEFAULT 0,
	error        TEXT NOT NULL DEFAULT '',
	subject      TEXT NOT NULL DEFAULT '',
	body         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX alerts_pending ON alerts(state, next_attempt);
CREATE INDEX alerts_finding ON alerts(finding_id);
CREATE INDEX alerts_created ON alerts(created_at);

CREATE TABLE audit (
	id         INTEGER PRIMARY KEY,
	at         INTEGER NOT NULL,
	user_email TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL,
	object     TEXT NOT NULL DEFAULT '',
	details    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_at ON audit(at);
