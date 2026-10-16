-- Certificate Transparency watching (see the specification, "Certificate
-- Transparency watching"). A domain watch follows what the public logs
-- publish for a name; its issuances are matched against the certificates
-- the targets serve, and one that no target serves is a finding on the
-- watch.
CREATE TABLE domains (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL UNIQUE,
	subdomains   INTEGER NOT NULL DEFAULT 1,
	tags         TEXT NOT NULL DEFAULT '',
	notes        TEXT NOT NULL DEFAULT '',
	all_channels INTEGER NOT NULL DEFAULT 1,
	enabled      INTEGER NOT NULL DEFAULT 1,
	-- The source's cursor for this watch; '' before the first poll.
	cursor       TEXT NOT NULL DEFAULT '',
	polled_at    INTEGER NOT NULL DEFAULT 0,
	polled_ok    INTEGER NOT NULL DEFAULT 0,
	poll_error   TEXT NOT NULL DEFAULT '',
	-- When the polls started failing, 0 while they succeed.
	fail_since   INTEGER NOT NULL DEFAULT 0,
	created_at   INTEGER NOT NULL,
	created_by   TEXT NOT NULL DEFAULT '',
	updated_at   INTEGER NOT NULL
);
CREATE TABLE domain_channels (
	domain_id  INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
	channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
	PRIMARY KEY (domain_id, channel_id)
);

-- One certificate for a watched domain as the logs published it. The
-- issuer CN and the serial identify it: a precertificate and the
-- certificate it became share both, and a served certificate is matched on
-- them. names is a JSON array.
CREATE TABLE issuances (
	id         INTEGER PRIMARY KEY,
	domain_id  INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
	source_id  TEXT NOT NULL DEFAULT '',
	issuer_cn  TEXT NOT NULL DEFAULT '',
	issuer_org TEXT NOT NULL DEFAULT '',
	serial     TEXT NOT NULL,
	names      TEXT NOT NULL DEFAULT '[]',
	not_before INTEGER NOT NULL DEFAULT 0,
	not_after  INTEGER NOT NULL DEFAULT 0,
	log_url    TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	state      TEXT NOT NULL CHECK (state IN ('known', 'pending', 'unexpected', 'acknowledged')),
	-- The served certificate it was matched to, '' while none.
	matched_fp TEXT NOT NULL DEFAULT '',
	ack_by     TEXT NOT NULL DEFAULT '',
	ack_at     INTEGER NOT NULL DEFAULT 0,
	ack_comment TEXT NOT NULL DEFAULT '',
	UNIQUE (domain_id, issuer_cn, serial)
);
CREATE INDEX issuances_domain ON issuances(domain_id, first_seen);
CREATE INDEX issuances_state ON issuances(state);
CREATE INDEX issuances_serial ON issuances(serial);

-- A finding is on a target, a node, or now a domain watch. The table is
-- rebuilt as in 0008, since the check constraint names the columns; the
-- indexes and triggers go with the old table and are created again. For a
-- domain finding, fingerprint holds the issuance id, so one finding can
-- be open per issuance.
CREATE TABLE findings_new (
	id            INTEGER PRIMARY KEY,
	target_id     INTEGER REFERENCES targets(id) ON DELETE CASCADE,
	node_id       INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
	domain_id     INTEGER REFERENCES domains(id) ON DELETE CASCADE,
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
	CHECK ((target_id IS NOT NULL) + (node_id IS NOT NULL) + (domain_id IS NOT NULL) = 1)
);
INSERT INTO findings_new(id, target_id, node_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left,
	ack_by, ack_at, ack_until, ack_comment, last_alert_at)
	SELECT id, target_id, node_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left,
	ack_by, ack_at, ack_until, ack_comment, last_alert_at FROM findings;
DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;
CREATE UNIQUE INDEX findings_open ON findings(target_id, kind) WHERE resolved_at = 0 AND target_id IS NOT NULL;
CREATE UNIQUE INDEX findings_node_open ON findings(node_id, kind) WHERE resolved_at = 0 AND node_id IS NOT NULL;
CREATE UNIQUE INDEX findings_domain_open ON findings(domain_id, kind, fingerprint) WHERE resolved_at = 0 AND domain_id IS NOT NULL;
CREATE INDEX findings_resolved ON findings(resolved_at);
CREATE INDEX findings_target ON findings(target_id, resolved_at);
CREATE INDEX findings_node ON findings(node_id, resolved_at);
CREATE INDEX findings_domain ON findings(domain_id, resolved_at);
CREATE TRIGGER findings_ins AFTER INSERT ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_upd AFTER UPDATE ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_del AFTER DELETE ON findings BEGIN UPDATE changes SET n = n + 1; END;

-- The live pages follow the watches and their issuances too.
CREATE TRIGGER domains_ins AFTER INSERT ON domains BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER domains_upd AFTER UPDATE ON domains BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER domains_del AFTER DELETE ON domains BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER issuances_ins AFTER INSERT ON issuances BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER issuances_upd AFTER UPDATE ON issuances BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER issuances_del AFTER DELETE ON issuances BEGIN UPDATE changes SET n = n + 1; END;
