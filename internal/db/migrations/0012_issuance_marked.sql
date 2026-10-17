-- An issuance marked unexpected by hand stays unexpected until it is
-- acknowledged, even when a target serves its certificate.
ALTER TABLE issuances ADD COLUMN marked INTEGER NOT NULL DEFAULT 0;
