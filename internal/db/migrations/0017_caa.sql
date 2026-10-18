-- CAA monitoring (see the specification, "Certificate Transparency
-- watching"): the relevant CAA record set of each watched domain, looked
-- up on every poll, and per issuance whether that set permits its issuer.
ALTER TABLE domains ADD COLUMN caa TEXT NOT NULL DEFAULT '';          -- JSON record set and the name it was found at
ALTER TABLE domains ADD COLUMN caa_checked_at INTEGER NOT NULL DEFAULT 0; -- last lookup that answered; 0: never
ALTER TABLE domains ADD COLUMN caa_error TEXT NOT NULL DEFAULT '';    -- why the last lookup failed

-- '' not judged (backlog, expired, or from before CAA monitoring),
-- permitted, violation, acknowledged, unknown_issuer (CAA not evaluated),
-- lookup_failed.
ALTER TABLE issuances ADD COLUMN caa TEXT NOT NULL DEFAULT '';
ALTER TABLE issuances ADD COLUMN caa_detail TEXT NOT NULL DEFAULT '';
ALTER TABLE issuances ADD COLUMN caa_table INTEGER NOT NULL DEFAULT 0;
