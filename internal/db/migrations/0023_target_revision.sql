-- A revision counter per target, raised by every configuration change, so a
-- check that started before a change is recognised as stale even when the
-- change falls in the same second as the read.
ALTER TABLE targets ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
