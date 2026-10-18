-- Thresholds as a share of the leaf's lifetime remaining, next to the days
-- (see the specification, "Thresholds and defaults"), and the renewal
-- point after which renewal_overdue opens. NULL follows Settings ›
-- Defaults (or, for the renewal point, the built-in 75 %); a percentage
-- of 0 means days only.
ALTER TABLE targets ADD COLUMN warn_pct INTEGER;
ALTER TABLE targets ADD COLUMN crit_pct INTEGER;
ALTER TABLE targets ADD COLUMN renewal_pct INTEGER;
