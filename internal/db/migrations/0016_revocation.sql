-- Revocation (see the specification, "Checks, findings and severity"):
-- the CRLs named by served leaves, fetched at most once a day per URL and
-- verified against the leaf's issuer, with the serials they list. A CRL
-- no served leaf has named for a week is pruned.
CREATE TABLE crls (
	id           INTEGER PRIMARY KEY,
	url          TEXT NOT NULL UNIQUE,
	issuer_key   TEXT NOT NULL DEFAULT '', -- hex SHA-256 of the SPKI it was verified against
	this_update  INTEGER NOT NULL DEFAULT 0,
	next_update  INTEGER NOT NULL DEFAULT 0,
	fetched_at   INTEGER NOT NULL DEFAULT 0, -- last fetch that verified; 0: never
	attempted_at INTEGER NOT NULL DEFAULT 0,
	fail_streak  INTEGER NOT NULL DEFAULT 0, -- failed daily fetches in a row
	error        TEXT NOT NULL DEFAULT '',
	entries      INTEGER NOT NULL DEFAULT 0,
	size         INTEGER NOT NULL DEFAULT 0, -- bytes
	node_id      INTEGER REFERENCES nodes(id) ON DELETE SET NULL -- fetched by this node; NULL: the server
);

CREATE TABLE crl_entries (
	crl_id     INTEGER NOT NULL REFERENCES crls(id) ON DELETE CASCADE,
	serial     TEXT NOT NULL, -- uppercase hex, as certificates.serial
	revoked_at INTEGER NOT NULL,
	reason     TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (crl_id, serial)
) WITHOUT ROWID;

-- The OCSP response an address stapled: '' none, good, revoked, unknown,
-- invalid.
ALTER TABLE observations ADD COLUMN ocsp TEXT NOT NULL DEFAULT '';
