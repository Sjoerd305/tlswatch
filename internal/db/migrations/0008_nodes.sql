-- Nodes: probe workers inside another network, enrolled with the server and
-- reached only by their own outbound connections. A node moves through the
-- states enrolling (an install token is out, no credential yet), pending
-- (enrolled, waiting for an admin to confirm the reported facts) and
-- confirmed. The install token is kept sealed under the secret key while it
-- is unspent, so the Add node screen can show its command again; the
-- credential is kept as a hash only.
CREATE TABLE nodes (
	id               INTEGER PRIMARY KEY,
	name             TEXT NOT NULL DEFAULT '',
	state            TEXT NOT NULL CHECK (state IN ('enrolling', 'pending', 'confirmed')),
	credential_hash  TEXT NOT NULL DEFAULT '',
	token_hash       TEXT NOT NULL DEFAULT '',
	token_sealed     BLOB,
	token_expires    INTEGER NOT NULL DEFAULT 0,
	created_at       INTEGER NOT NULL,
	created_by       TEXT NOT NULL DEFAULT '',
	enrolled_at      INTEGER NOT NULL DEFAULT 0,
	confirmed_at     INTEGER NOT NULL DEFAULT 0,
	confirmed_by     TEXT NOT NULL DEFAULT '',
	last_seen        INTEGER NOT NULL DEFAULT 0,
	version          TEXT NOT NULL DEFAULT '',
	protocol         INTEGER NOT NULL DEFAULT 0,
	address          TEXT NOT NULL DEFAULT '',
	pool_size        INTEGER NOT NULL DEFAULT 4,
	enabled          INTEGER NOT NULL DEFAULT 1,
	notes            TEXT NOT NULL DEFAULT '',
	-- The system facts as last reported (JSON), and when.
	facts            TEXT NOT NULL DEFAULT '{}',
	facts_at         INTEGER NOT NULL DEFAULT 0,
	-- Self-update: the update asked for by an admin, the one running now,
	-- and the last one that failed with its reason.
	update_requested INTEGER NOT NULL DEFAULT 0,
	update_started   INTEGER NOT NULL DEFAULT 0,
	update_from      TEXT NOT NULL DEFAULT '',
	update_to        TEXT NOT NULL DEFAULT '',
	update_failed    TEXT NOT NULL DEFAULT '',
	updated_at       INTEGER NOT NULL
);
CREATE UNIQUE INDEX nodes_credential ON nodes(credential_hash) WHERE credential_hash != '';
CREATE UNIQUE INDEX nodes_token ON nodes(token_hash) WHERE token_hash != '';
CREATE TRIGGER nodes_ins AFTER INSERT ON nodes BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER nodes_del AFTER DELETE ON nodes BEGIN UPDATE changes SET n = n + 1; END;
-- last_seen moves with every poll; the live pages follow everything else.
CREATE TRIGGER nodes_upd AFTER UPDATE OF name, state, enabled, facts_at, version, update_started, update_failed, update_requested ON nodes
	BEGIN UPDATE changes SET n = n + 1; END;

-- NULL: probed from the server. Deleting a node is refused while targets
-- use it.
ALTER TABLE targets ADD COLUMN node_id INTEGER REFERENCES nodes(id);
CREATE INDEX targets_node ON targets(node_id);
-- The vantage point of each observation, so history stays right when a
-- target moves between nodes.
ALTER TABLE observations ADD COLUMN node_id INTEGER REFERENCES nodes(id) ON DELETE SET NULL;

-- A finding is on a target or, for node_offline, on a node. target_id was
-- NOT NULL in 0001 and SQLite cannot drop a constraint, so the table is
-- rebuilt; Migrate runs with foreign keys off, so alerts keep referring to
-- "findings" by name. The indexes and triggers go with the old table and
-- are created again.
CREATE TABLE findings_new (
	id            INTEGER PRIMARY KEY,
	target_id     INTEGER REFERENCES targets(id) ON DELETE CASCADE,
	node_id       INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
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
	last_alert_at INTEGER NOT NULL DEFAULT 0,
	CHECK ((target_id IS NULL) != (node_id IS NULL))
);
INSERT INTO findings_new(id, target_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left,
	ack_by, ack_at, ack_until, ack_comment, last_alert_at)
	SELECT id, target_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left,
	ack_by, ack_at, ack_until, ack_comment, last_alert_at FROM findings;
DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;
CREATE UNIQUE INDEX findings_open ON findings(target_id, kind) WHERE resolved_at = 0 AND target_id IS NOT NULL;
CREATE UNIQUE INDEX findings_node_open ON findings(node_id, kind) WHERE resolved_at = 0 AND node_id IS NOT NULL;
CREATE INDEX findings_resolved ON findings(resolved_at);
CREATE INDEX findings_target ON findings(target_id, resolved_at);
CREATE INDEX findings_node ON findings(node_id, resolved_at);
CREATE TRIGGER findings_ins AFTER INSERT ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_upd AFTER UPDATE ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_del AFTER DELETE ON findings BEGIN UPDATE changes SET n = n + 1; END;
