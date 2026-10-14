-- The check that produced each target's current state, so "the latest
-- observations of every target" is a join instead of a correlated
-- subquery per observation row.
ALTER TABLE targets ADD COLUMN last_check_id TEXT NOT NULL DEFAULT '';
UPDATE targets SET last_check_id = COALESCE(
	(SELECT check_id FROM observations o WHERE o.target_id = targets.id ORDER BY o.id DESC LIMIT 1), '');
CREATE INDEX observations_check ON observations(check_id);

-- Indexes for per-target and per-channel lookups and cascading deletes.
CREATE INDEX findings_target ON findings(target_id, resolved_at);
CREATE INDEX alerts_channel ON alerts(channel_id, state);
CREATE INDEX target_channels_channel ON target_channels(channel_id);

-- A counter bumped by every change the live pages show, so their poll reads
-- one row instead of aggregating whole tables.
CREATE TABLE changes (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	n  INTEGER NOT NULL
);
INSERT INTO changes(id, n) VALUES (1, 0);
CREATE TRIGGER targets_ins AFTER INSERT ON targets BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER targets_upd AFTER UPDATE ON targets BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER targets_del AFTER DELETE ON targets BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_ins AFTER INSERT ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_upd AFTER UPDATE ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER findings_del AFTER DELETE ON findings BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER alerts_ins AFTER INSERT ON alerts BEGIN UPDATE changes SET n = n + 1; END;
CREATE TRIGGER alerts_upd AFTER UPDATE OF state ON alerts BEGIN UPDATE changes SET n = n + 1; END;
