# Security

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security → Advisories) on this repository, not in a public issue. You will get an answer within a week.

Supported versions: the latest release.

Scope notes: tlswatch stores alert channel credentials encrypted under a key file that never enters the database, refuses loopback and link-local targets unless allowed, and sends no telemetry. Outbound connections go only to your targets, your SMTP relay, `api.telegram.org` and Google's OAuth endpoints.
