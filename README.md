# tlswatch

tlswatch watches the TLS certificates that are actually served on your hostnames and IP addresses. It checks expiry, the chain of trust, the hostname and signature strength, notices when a certificate changes, and alerts by e-mail and Telegram before something expires. It is one self-hosted Go binary with a web UI and a SQLite file; nothing else to run.

- Any port, implicit TLS or STARTTLS (SMTP, IMAP, POP3, FTP, PostgreSQL).
- Every address behind a name is probed, so the one stale node behind a load balancer is caught.
- System store, private CA bundles, or pinned self-signed certificates.
- Let's Encrypt and other ACME renewals are recognised and not alerted.
- Alerts on transitions, with reminders, recovery notices, acknowledgements and an optional weekly digest.
- Roles (viewer, operator, admin), local accounts and Google sign-in, an audit log.
- **Configured in the browser**: SMTP relays, Telegram bots, Google sign-in, thresholds and the public URL all live under Settings.

## Quick start

```sh
make build                     # or download a release binary
./tlswatch serve               # creates ./data/ and a secret key on first start
open http://127.0.0.1:8080/    # create your admin account, then add targets and channels
```

With Docker, from this checkout: `docker compose up --build -d` and open http://127.0.0.1:8080/. Once a release is published you can switch `compose.yaml` to `ghcr.io/sjoerd305/tlswatch`.

On first start, before any account exists, tlswatch shows a setup screen where you create the first admin with your own e-mail and password. Do that right away, before exposing the port beyond localhost.

Try an endpoint from the command line first, no server needed:

```sh
tlswatch check portal.example.nl                 # exit code 0 ok, 1 warning, 2 critical
tlswatch check mail.example.nl:587 -protocol smtp
tlswatch check 10.0.0.5:443 -servername portal.example.nl -ca-file internal-ca.pem
```

## Configuration

Everything an operator changes is in the UI. The process itself needs at most these environment variables, all optional:

| Variable | Default |
| --- | --- |
| `TLSWATCH_LISTEN` | `127.0.0.1:8080` |
| `TLSWATCH_DB` | `./data/tlswatch.db` |
| `TLSWATCH_SECRET_KEY_FILE` | `secret.key` next to the database, generated on first start |
| `TLSWATCH_LOG_JSON` | `true` |

Settings that can also be pinned by environment (for containers and GitOps) are shown read-only in the UI. See [docs/operations.md](docs/operations.md) and the [specification](docs/specification.md).

Back up the database **and** the secret key: stored SMTP passwords and Telegram tokens are encrypted with it.

## Development

```sh
make test     # node --test for the TypeScript helpers, go test -race for the rest
make run      # a throw-away instance with demo targets (badssl.com and friends)
make lint     # gofmt, go vet, govulncheck, gosec
```

The frontend is server-rendered `html/template` with small dependency-free TypeScript modules compiled by `tsc` (the only npm dependency). The compiled JavaScript in `web/static/js` is committed so `go build` works without Node.

## Licence

MIT. IBM Plex fonts are under the SIL Open Font License, see `web/static/fonts/OFL.txt`.
