# Operations guide

## First start

`tlswatch serve` needs no configuration. On first start it creates the data directory and generates `secret.key` (mode 0600) next to the database. While no account exists, every page leads to a setup screen where you create the first admin with your own e-mail address and password; you are signed in right after. Do this before the port is reachable by others: until then, whoever opens tlswatch first becomes admin. For scripted installs, `tlswatch create-admin -email you@example.org` creates the admin from the command line and shows a one-time password link on the terminal instead (`-out FILE` writes it to a file, mode 0600, for a script that captures stdout).

Then, in the browser:

1. **Settings › General**: the public URL (used in alert links and as the Google redirect), the time zone, and "behind a reverse proxy" when one terminates TLS in front of tlswatch.
2. **Settings › Channels**: an SMTP relay (host, port, STARTTLS / implicit TLS / none, username, password, sender, recipients) and/or a Telegram bot (token from @BotFather, chat IDs). Under "More types": a Slack incoming webhook (Mattermost and Rocket.Chat take the same), a Discord channel webhook, an ntfy topic (server, topic, optional access token), or a webhook of your own (URL, optional signing secret). Use **Test** on each.
3. **Settings › Sign-in** (optional): Google client ID and secret, and a Workspace domain. Register the redirect URI shown there.
4. **Settings › Users**: invite people. Password users get a one-time link (mailed through the first SMTP channel when there is one); Google users just sign in.
5. **Targets › Add target**.

## Environment overrides

Only `TLSWATCH_LISTEN`, `TLSWATCH_DB`, `TLSWATCH_SECRET_KEY_FILE`, `TLSWATCH_LOG_JSON`, `TLSWATCH_DEBUG`, `TLSWATCH_ACCEPT_NEW_KEY` (below), `TLSWATCH_DEMO` (see Running a public demo) and, in the image, `TLSWATCH_CONTAINER` are read before the database opens. These override a UI setting and make it read-only there:

| Variable | UI setting |
| --- | --- |
| `TLSWATCH_BASE_URL` | General › Public URL |
| `TLSWATCH_BEHIND_PROXY` | General › Behind a reverse proxy |
| `TLSWATCH_ALLOW_LOCAL` | General › Allow loopback and link-local targets |
| `TLSWATCH_METRICS` | General › Serve Prometheus metrics |
| `TLSWATCH_METRICS_TOKEN` | General › Metrics token (16 characters at least) |
| `TZ` | General › Time zone |
| `TLSWATCH_WORKERS` | Defaults › Concurrent probes |
| `TLSWATCH_RETENTION_DAYS` | Defaults › History retention |
| `TLSWATCH_GOOGLE_CLIENT_ID`, `TLSWATCH_GOOGLE_SECRET_FILE`, `TLSWATCH_GOOGLE_DOMAIN` | Sign-in › Google |

Values are checked against the same ranges as the UI (retention 7 to 3650 days, workers 1 to 256, booleans `true` or `false`, an absolute base URL, a readable secret file). An invalid value stops tlswatch at start with a message naming the variable. `TZ` is the exception: it is shared with the rest of the system, so an unknown zone is ignored.

## Backups and upgrades

- `tlswatch backup /backups/tlswatch-$(date +%F).db` writes a consistent copy while the server runs (SQLite `VACUUM INTO`). Run it daily from cron. It does not migrate or otherwise change the database it copies.
- Keep `secret.key` with the backups. Without it the database still works, but stored SMTP passwords, Telegram tokens, webhook URLs and secrets, the Google secret and the Cert Spotter API key must be entered again. A channel whose credentials cannot be decrypted is marked on Settings › Channels; its alerts fail until its credentials are entered again, and the other channels keep working. A Google secret or CT key that cannot be decrypted is marked on its settings page.
- A server that finds its database but not its key file refuses to start: that is a volume that did not mount, not a first start, and a fresh key would leave every stored credential unreadable. Mount the volume with the key; only when the key is really lost, start once with `TLSWATCH_ACCEPT_NEW_KEY=true` and enter the credentials again. A key file readable by other users is reported at start; make it mode 0600.
- To replace the key (for example after it was exposed), stop tlswatch and run `tlswatch rotate-key`. It re-encrypts the stored credentials, the sealed settings and the node install tokens under a new key in one transaction, then swaps the key file and keeps the old one as `secret.key.old-<time>`; keep that file as long as backups made with it, then delete it. The command refuses to run while tlswatch answers on `TLSWATCH_LISTEN`.
- Settings › Backup downloads the whole instance as one file encrypted with a passphrase: targets, history, findings, channels with their credentials, CA bundles, users, settings and the audit log. The secret key is not in it; the credentials inside are sealed under the passphrase. Keep the passphrase apart from the file.
- To restore, upload the file under Settings › Backup, or on the setup screen of a fresh installation (before any account exists), so moving to a new host needs no throwaway admin. The restore replaces everything in place while tlswatch runs, re-encrypts the credentials under the instance's own key and signs everyone out; sign in with an account from the backup. A copy written by `tlswatch backup` restores the same way without a passphrase, but its credentials are readable only when the instance has the `secret.key` it was made with. A backup from a newer tlswatch is refused; an older one is migrated.
- Upgrades are a binary swap. Migrations run at start, are forward only, and a binary refuses a database written by a newer version.
- `tlswatch version` (and `tlswatch_build_info` on `/metrics`) names the commit a build came from, also for an image built with `docker compose up --build`: `2026.10.15-5efacf7` while the repository has no tag, `v0.2.0-5-g5efacf7` five commits past one, `v0.2.0` on a release, and `-dirty` when the build had uncommitted changes. So "which version runs there?" is answered by that command on every instance.

## Monitoring tlswatch

`GET /healthz` answers 200 with JSON (`database`, `scheduler_running`, `last_check`, `backlog`, `overdue_s`) and 503 when the database is unreachable, the scheduler stalled, or the oldest due check has waited more than an hour (`overdue_s` > 3600: workers stuck or too few). `tlswatch healthcheck` calls it on `TLSWATCH_LISTEN` and exits non-zero when it is not 200; the Docker image uses it as its `HEALTHCHECK`.

With *Serve Prometheus metrics* on (Settings › General, or `TLSWATCH_METRICS=true`), `GET /metrics` with `Authorization: Bearer <token>` (the token is shown under Settings › General once metrics are on, or set by `TLSWATCH_METRICS_TOKEN`; in Prometheus: `authorization: { credentials: <token> }`) returns `tlswatch_targets{status}`, `tlswatch_findings_open{severity}`, `tlswatch_alerts{state}`, `tlswatch_certificate_not_after_seconds{target,endpoint}`, `tlswatch_targets_by_grade{grade}`, `tlswatch_target_grade{target,endpoint,grade}`, `tlswatch_ct_issuances_total{state}`, `tlswatch_ct_last_poll_timestamp_seconds{domain}`, `tlswatch_checks_total`, `tlswatch_scheduler_backlog`, `tlswatch_scheduler_overdue_seconds`, `tlswatch_scheduler_running`, `tlswatch_last_check_seconds` and `tlswatch_build_info{version}`. It names every target and its weaknesses, which is why it takes the token and not, like `/healthz`, anyone who can reach it. Example alert: `tlswatch_alerts{state="failed"} > 0` (a channel gave up).

Logs are JSON lines on stdout; set `TLSWATCH_LOG_JSON=false` for text and `TLSWATCH_DEBUG=true` for debug logging. Every response carries an `X-Request-ID`, which the log lines of that request repeat. Requests are logged at info level when they fail (status 400 or higher) or take more than 2 seconds, otherwise at debug level. On shutdown tlswatch waits up to 15 seconds for running checks and alert deliveries.

### Why did (or didn't) an alert go out?

Every check logs one `checked` line with the target, its `check_id` (also stored on the observations), the resulting `status`, and what changed: the findings `opened`, `escalated` and `resolved`, informational `events` (such as an automatic renewal), the kinds still `waiting` for the debounce, `alerts_queued`, the alerts held back because the finding is `below_floor` of a channel, and how many `channels` the target alerts to. Delivery logs `alert delivered`, `alert delivery failed, will retry` or, after 24 hours, `alert delivery given up`, each with the channel and the alert IDs. A delivered alert records how it went out: the SMTP `Message-ID` (to find it in the relay's logs), for Telegram `chat:message_id` per chat, for Discord and ntfy the message ID they returned, and for a webhook the `ref` the payload carried; Slack returns nothing to record. The finding's timeline shows it when you hover the delivery state.

## Networks

tlswatch probes from where it runs. Internal addresses must be reachable from that host, through a route or from a node (below). Hosts without an IPv6 route skip AAAA records (noted on the target, not reported as unreachable).

## Certificate Transparency

Domain watches (Domains in the navigation) ask an index of the Certificate Transparency logs what was issued for a name. The source is chosen under Settings › Certificate Transparency: Cert Spotter (api.certspotter.com; works without a key within its public rate limit, an API key raises it) or crt.sh. What leaves the server is the watched domain names, over HTTPS, to that service, and nothing else; the polls go from the server, never from a node. The default interval is an hour: both services are free and shared with everyone. Polls go one at a time, two seconds apart, spread over the interval; a failed poll (crt.sh answers 502 when it is busy) is retried after 15 minutes, or after what a 429 asked for. A source that answers nothing for a day opens one `ct_source_failed` finding per watch; the watch's page shows the last error. An unexpected certificate (one no target serves, or a renewal nobody deployed within two days) opens `unexpected_certificate` on the watch; acknowledge it on the Findings page or the domain page, or add the target that serves it, which resolves the finding on its next check.

Each poll also looks up the watched domain's CAA record, by asking the name servers in `/etc/resolv.conf` directly (Go's resolver has no CAA queries). In a container that is the container's resolver; if it does not answer CAA queries, the domain page shows the lookup error and issuances are marked "CAA lookup failed" instead of being judged.

Revocation is checked through CRLs. Before a target's checks, the server fetches the CRL its certificate names (an `http://` URL on the CA's host, such as `http://r11.c.lencr.org/7.crl`) at most once a day per URL, so the server needs outbound HTTP, and HTTPS for the CAs that use it, to the CRL hosts of the certificates it watches; it uses `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` like its other outbound connections. A CRL that cannot be fetched for three days records `revocation_unknown` (info, never alerted) on the target, and its page shows the last error under Revocation. For a node target verified against a CA bundle the node fetches the CRL instead, inside its network, and the server verifies it: such a private CA's CRL needs to be reachable from the node, not from the server. Cached CRLs take room in the database by the number of revoked serials (a few MB for a large public CA, about 60 bytes per serial); one no certificate names for a week is pruned.

## Nodes

A node is `tlswatch node` on a host inside a network the server cannot reach. It connects out to the server and is never connected to; the schedule, results, findings and alerts stay on the server. Where the network allows a route in (a WireGuard or Tailscale subnet router, an SSH tunnel), that needs no node at all and is the first thing to try.

**The one firewall rule.** The node needs outbound HTTPS to the server's public URL (Settings › General), nothing else. It honours `HTTPS_PROXY` and `NO_PROXY`. The server must answer on that URL over HTTPS with a certificate the node's host trusts; for a server on a private CA, add that CA to the host's trust store. The reverse proxy in front of the server needs no WebSocket or upgrade settings: a node's poll is an ordinary request held for up to 55 seconds, under the common 60-second proxy and load-balancer timeouts. An idle node uses a few megabytes a day.

> [!IMPORTANT]
> If a reverse proxy or load balancer in front of the server has a read or idle timeout under 60 seconds, raise it before you deploy a version with the 55-second poll, or polls will be cut off and nodes will keep reconnecting. For example: nginx `proxy_read_timeout 75s;`, HAProxy `timeout server 75s`, or the idle timeout of an AWS load balancer. Cloudflare's 100 seconds is enough.

**Installing.** The binary download on the server takes a node's credential or an unspent install token, so a machine needs the install command, not just the URL. Settings › Nodes › Add node shows one command to run as root on a host with systemd; it installs `/var/lib/tlswatch-node/bin/tlswatch` (linked from `/usr/local/bin/tlswatch`), `/etc/tlswatch-node.env`, the unit `tlswatch-node.service` and the system user `tlswatch-node`. The same screen has a Docker command and a manual one for hosts without systemd or root. The command holds a one-time token valid for an hour. Once the machine enrolled, the screen shows what it reported (hostname, system, addresses); confirm it and name it, and it can take targets ("Probe from" on the target form).

**Settings on the node** are flags or environment variables, read from `/etc/tlswatch-node.env` by the unit:

| Variable | Flag | Default | Purpose |
| --- | --- | --- | --- |
| `TLSWATCH_NODE_SERVER` | `-server` | | The server's public URL; `https://` unless `-insecure` |
| `TLSWATCH_NODE_DATA` | `-data` | `/var/lib/tlswatch-node` (`/data` in the image) | Directory of the credential file |
| `TLSWATCH_NODE_WORKERS` | `-workers` | `4` | Probes at once |
| `TLSWATCH_NODE_ALLOW` | `-allow` | empty: any | CIDRs the node may probe; whatever the server asks, others are refused |
| `TLSWATCH_NODE_ALLOW_LOCAL` | `-allow-local` | `false` | Allow loopback and link-local addresses (Settings › General must allow them too) |
| `TLSWATCH_NODE_TOKEN` | `-token` | | Install token: without a credential, enrol with it first (Docker) |
| `TLSWATCH_NODE_NO_UPDATE` | `-no-self-update` | `false` | Never replace the binary; the server shows "update failed" with that reason |
| `TLSWATCH_NODE_ALLOW_UNSIGNED_UPDATE` | `-allow-unsigned-update` | `false` | Also follow a development build of the server, which has no signed checksums |

Booleans take `true`/`false`, `1`/`0` or `yes`/`no`; a value that does not parse stops the node with a message naming the variable.

The allowlist and the local-address switch are the only probing settings that live on the node, so that whoever controls the server cannot widen them. The node page shows them read-only under Probe limits, with the file or flag they were read from on that node; the install script writes both commented out in `/etc/tlswatch-node.env`. After `systemctl restart tlswatch-node` the page shows the new list within a few minutes, and the change is in the audit log.

**When a node shows offline.** On the node: `systemctl status tlswatch-node` and `journalctl -u tlswatch-node` (one line per job, and why a poll failed). Typical causes: the service is stopped, the host cannot reach the server or does not trust its certificate, a proxy is needed, or the credential was revoked ("credential not accepted": rotate it on the node page and run the new command). The node's targets keep their last state and show "Waiting for node"; nothing alerts per target. After 10 minutes one `node_offline` finding opens, critical once a target is overdue by more than its interval, and it resolves with a recovery notice when the node polls again.

**Updates.** Nodes update themselves to the server's version, one at a time, and roll back when the new version does not reach the server within five minutes. A node takes only a release whose `SHA256SUMS` is signed by the tlswatch release key built into it; the server passes the signed list on and serves its own binary only when it is the released one, otherwise the node is sent to the GitHub release asset, which that machine must then reach. A node on a plain-http server (`-insecure`) or with `TLSWATCH_NODE_NO_UPDATE=true` never replaces its binary; a download that fails (a development server serving another platform, for example) is reported on the next poll and shown on the node row at once; this is automatic for release builds and can be switched off under Settings › Nodes. A node in a container is updated by pulling the image tag of the server's version.

**Removing.** `sudo tlswatch node uninstall` on the machine, or, when the binary is gone, `curl -fsSL https://<server>/agent/v1/uninstall | sudo sh`. Delete the node under Settings › Nodes too; a node with targets offers to move them to the server.

## Running a public demo

`TLSWATCH_DEMO=/path/to/demo.json tlswatch serve` runs tlswatch as a public demo: nobody signs in, every visitor sees the targets, domains, certificates and findings read-only, and the sign-in, setup, account and settings pages lead back to the overview. On the first start the demo file fills the empty database; later starts leave the database as it is, so the history builds up. To start over, stop tlswatch, delete the database and start again.

The repository's `demo/demo.json` watches public endpoints only: healthy sites, mail and FTP over STARTTLS and implicit TLS, an IP address with a server name, a private CA through a CA bundle, a pinned self-signed certificate, the badssl.com hosts that are broken on purpose, a disabled target and a Certificate Transparency watch for badssl.com. `demo/compose.yaml` runs it:

```sh
cd demo && docker compose up -d     # http://127.0.0.1:8082/
```

Put the same reverse proxy with TLS in front as for any instance; a demo needs no channels, no public URL and no backups. Give the demo a database of its own: demo mode refuses to start on a database that has user accounts, so it cannot publish a real instance by mistake.

## Releasing

A release is a tag `vX.Y.Z` pushed to GitHub: the workflow builds the binaries, signs `SHA256SUMS` with the release key and publishes them with the image. The signing key is the repository secret `RELEASE_SIGNING_KEY` (the 64-hex-character Ed25519 seed); its public half is in `internal/node/release.go`, so every node checks what it is about to run against it. To make a new key pair, run `go run ./scripts/releasesign -keygen`, put the private key in the secret and the public key in that file in the same release; nodes on older builds then no longer accept releases signed with the new key and need a reinstall, so rotate the key only when it may have leaked.
