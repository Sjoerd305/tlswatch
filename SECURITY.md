# Security

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security → Advisories) on this repository, not in a public issue. You will get an answer within a week.

Supported versions: the latest release.

Scope notes: tlswatch stores alert channel credentials encrypted under a key file that never enters the database, refuses loopback and link-local targets unless allowed, and sends no telemetry. Outbound connections from the server go only to your targets, your SMTP relay, `api.telegram.org`, the Slack, Discord, ntfy and webhook URLs an admin configured, the Certificate Transparency source chosen under Settings (`api.certspotter.com` or `crt.sh`, which receive the watched domain names), Google's OAuth endpoints, and, on a release build, the signed release checksums on GitHub when a node downloads a binary. A node connects out to the server, to the targets it is given, and to GitHub only for a binary the server cannot serve itself. Nodes replace their binary only with a release signed by the tlswatch release key, so a compromised server cannot run code on them.

Release binaries are signed: `SHA256SUMS.sig` on every release is an Ed25519 signature over `SHA256SUMS` by the key whose public half is in `internal/node/release.go`; `go run ./scripts/releasesign -verify SHA256SUMS SHA256SUMS.sig` checks it.

HTTP logging masks node installation and calendar feed credentials in URL paths, including error and panic logs. Free-form diagnostics on credential-bearing URLs are withheld; ordinary errors retain their details. Reverse-proxy, tracing and log-collector capture must be configured separately. See [credential URLs and logs](docs/operations.md#credential-urls-and-logs) for upstream masking and replacing credentials exposed in older logs.
