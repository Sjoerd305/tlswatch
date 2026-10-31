-- Scheduled discovery (see the specification, "Discovery"): a scan
-- definition that repeats daily or weekly, each run an ordinary scan, and
-- a finding per endpoint a run found that no target covers.
CREATE TABLE scan_schedules (
	id          INTEGER PRIMARY KEY,
	name        TEXT NOT NULL DEFAULT '',   -- a label; the ranges when empty
	ranges      TEXT NOT NULL,              -- the CIDRs, comma separated
	ports       TEXT NOT NULL,              -- comma separated
	rate        INTEGER NOT NULL,           -- connects per second
	node_id     INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
	every       TEXT NOT NULL,              -- day or week
	weekday     INTEGER NOT NULL DEFAULT 1, -- 0 Sunday to 6 Saturday, for week
	hour        INTEGER NOT NULL,           -- 0 to 23 in the instance's time zone
	enabled     INTEGER NOT NULL DEFAULT 1,
	created_at  INTEGER NOT NULL,
	created_by  TEXT NOT NULL,
	updated_at  INTEGER NOT NULL,
	last_run    INTEGER NOT NULL DEFAULT 0, -- when the last run started, or was skipped
	last_scan_id INTEGER,                   -- the scan of the last run, while it is kept
	last_note   TEXT NOT NULL DEFAULT ''    -- why the last slot ran no scan
);
CREATE TRIGGER scan_schedules_ins AFTER INSERT ON scan_schedules BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER scan_schedules_upd AFTER UPDATE ON scan_schedules BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER scan_schedules_del AFTER DELETE ON scan_schedules BEGIN UPDATE changes SET n = n + 1; END;

-- A scan knows the schedule it ran for; a one-off scan has none.
ALTER TABLE scans ADD COLUMN schedule_id INTEGER REFERENCES scan_schedules(id) ON DELETE SET NULL;

-- A finding is on a target, a node, a domain watch, or now a scan schedule.
-- Rebuilt as in 0010, since the check constraint names the columns. For a
-- schedule finding, fingerprint holds the endpoint as address:port, so one
-- finding can be open per endpoint.
CREATE TABLE findings_new (
	id            INTEGER PRIMARY KEY,
	target_id     INTEGER REFERENCES targets(id) ON DELETE CASCADE,
	node_id       INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
	domain_id     INTEGER REFERENCES domains(id) ON DELETE CASCADE,
	schedule_id   INTEGER REFERENCES scan_schedules(id) ON DELETE CASCADE,
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
	CHECK ((target_id IS NOT NULL) + (node_id IS NOT NULL) + (domain_id IS NOT NULL) + (schedule_id IS NOT NULL) = 1)
);
INSERT INTO findings_new(id, target_id, node_id, domain_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left,
	ack_by, ack_at, ack_until, ack_comment, last_alert_at)
	SELECT id, target_id, node_id, domain_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left,
	ack_by, ack_at, ack_until, ack_comment, last_alert_at FROM findings;
DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;
CREATE UNIQUE INDEX findings_open ON findings(target_id, kind) WHERE resolved_at = 0 AND target_id IS NOT NULL;
CREATE UNIQUE INDEX findings_node_open ON findings(node_id, kind) WHERE resolved_at = 0 AND node_id IS NOT NULL;
CREATE UNIQUE INDEX findings_domain_open ON findings(domain_id, kind, fingerprint) WHERE resolved_at = 0 AND domain_id IS NOT NULL;
CREATE UNIQUE INDEX findings_schedule_open ON findings(schedule_id, kind, fingerprint) WHERE resolved_at = 0 AND schedule_id IS NOT NULL;
CREATE INDEX findings_resolved ON findings(resolved_at);
CREATE INDEX findings_target ON findings(target_id, resolved_at);
CREATE INDEX findings_node ON findings(node_id, resolved_at);
CREATE INDEX findings_domain ON findings(domain_id, resolved_at);
CREATE INDEX findings_schedule ON findings(schedule_id, resolved_at);
CREATE TRIGGER findings_ins AFTER INSERT ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_upd AFTER UPDATE ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_del AFTER DELETE ON findings BEGIN UPDATE changes SET n = n + 1; END;
