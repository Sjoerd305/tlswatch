-- Cert Spotter issuances were linked to a viewer page that does not exist;
-- the link now opens the certificate on crt.sh. Stored links are dropped,
-- and the page falls back to the domain's crt.sh listing while empty.
UPDATE issuances SET log_url = '' WHERE log_url LIKE 'https://sslmate.com/caadb/cert/%';
