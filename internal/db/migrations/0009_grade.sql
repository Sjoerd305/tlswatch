-- The TLS configuration grade. The daily test for TLS 1.0 and 1.1 now also
-- offers each weak cipher suite class on its own (see the specification,
-- "TLS configuration grade"); the per-address verdicts are kept as JSON
-- (ip, grade, reasons, versions, classes, suite names), the target's
-- grade is the lowest of them, and grade_rules names the rules version it
-- was given under, so a tightened rule set re-grades on the next test.
ALTER TABLE targets ADD COLUMN grade TEXT NOT NULL DEFAULT '';
ALTER TABLE targets ADD COLUMN grade_reasons TEXT NOT NULL DEFAULT '';
ALTER TABLE targets ADD COLUMN grade_rules INTEGER NOT NULL DEFAULT 0;
ALTER TABLE targets ADD COLUMN config_test TEXT NOT NULL DEFAULT '';
