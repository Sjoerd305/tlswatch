-- Discovery scans (see the specification, "Discovery"): a scan of address
-- ranges and ports, from this server (node_id NULL) or a node, and the TLS
-- endpoints it found. Results are kept 7 days and are not inventory: the
-- leaf is described here and not stored in certificates.
CREATE TABLE scans (
	id          INTEGER PRIMARY KEY,
	created_at  INTEGER NOT NULL,
	created_by  TEXT NOT NULL,
	node_id     INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
	node_name   TEXT NOT NULL DEFAULT '',
	ranges      TEXT NOT NULL,           -- the CIDRs as entered, comma separated
	ports       TEXT NOT NULL,           -- comma separated
	rate        INTEGER NOT NULL,        -- connects per second
	state       TEXT NOT NULL,           -- running, done, failed
	total       INTEGER NOT NULL,        -- connects planned: addresses × ports
	probed      INTEGER NOT NULL DEFAULT 0,
	refused     INTEGER NOT NULL DEFAULT 0, -- addresses refused without a connect
	error       TEXT NOT NULL DEFAULT '',
	finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX scans_created ON scans(created_at);

CREATE TABLE scan_results (
	id          INTEGER PRIMARY KEY,
	scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
	address     TEXT NOT NULL,
	port        INTEGER NOT NULL,
	protocol    TEXT NOT NULL,
	tls_version TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	subject_cn  TEXT NOT NULL,
	sans        TEXT NOT NULL,           -- JSON array
	issuer      TEXT NOT NULL,
	not_after   INTEGER NOT NULL,
	self_signed INTEGER NOT NULL
);
CREATE INDEX scan_results_scan ON scan_results(scan_id);

-- A scan's progress and findings change the live pages' stamp, so the scan
-- page and Discover follow a running scan.
CREATE TRIGGER scans_ins AFTER INSERT ON scans BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER scans_upd AFTER UPDATE ON scans BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER scans_del AFTER DELETE ON scans BEGIN UPDATE changes SET n = n + 1; END;
