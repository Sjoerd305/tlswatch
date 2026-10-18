-- Post-quantum key exchange (see the specification, "TLS configuration
-- grade"): whether the target negotiates X25519MLKEM768 ('' untested, yes,
-- no), from the daily configuration test, and the group each observed
-- handshake negotiated.
ALTER TABLE targets ADD COLUMN pq TEXT NOT NULL DEFAULT '';
ALTER TABLE observations ADD COLUMN kex_group TEXT NOT NULL DEFAULT '';
