# Security

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security → Advisories) on this repository, not in a public issue. You will get an answer within a week.

Supported versions: the latest release.

Scope notes: tlswatch stores alert channel credentials encrypted under a key file that never enters the database, refuses loopback and link-local targets unless allowed, and sends no telemetry. Outbound connections from the server go only to your targets, your SMTP relay, `api.telegram.org`, the Slack, Discord, ntfy and webhook URLs an admin configured, Google's OAuth endpoints, and, on a release build, the GitHub release checksums when a node on another platform downloads its binary. A node connects out to the server, to the targets it is given, and to GitHub only for a binary the server cannot serve itself.
