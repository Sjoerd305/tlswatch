-- Recipients refused for good on an attempt that was retried for others,
-- so the alert still names them once the retry succeeds.
ALTER TABLE alerts ADD COLUMN refused TEXT NOT NULL DEFAULT '';
