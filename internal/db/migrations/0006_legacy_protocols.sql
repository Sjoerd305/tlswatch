-- The test for TLS 1.0 and 1.1: whether it runs for the target, when it last
-- reached a verdict, and the versions an address accepted then (comma
-- separated, empty when none).
ALTER TABLE targets ADD COLUMN legacy_check INTEGER NOT NULL DEFAULT 1;
ALTER TABLE targets ADD COLUMN legacy_checked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE targets ADD COLUMN legacy_accepted TEXT NOT NULL DEFAULT '';
