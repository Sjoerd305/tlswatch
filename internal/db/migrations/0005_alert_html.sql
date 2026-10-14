-- The HTML part of an alert's mail, rendered when the alert is queued like
-- its subject and plain-text body. Empty for transports without HTML and
-- for alerts queued before this column existed.
ALTER TABLE alerts ADD COLUMN html TEXT NOT NULL DEFAULT '';
