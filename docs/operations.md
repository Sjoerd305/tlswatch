# Operations guide

## First start

`tlswatch serve` needs no configuration. On first start it creates the data directory and generates `secret.key` (mode 0600) next to the database. While no account exists, every page leads to a setup screen where you create the first admin with your own e-mail address and password; you are signed in right after. Do this before the port is reachable by others: until then, whoever opens tlswatch first becomes admin. For scripted installs, `tlswatch create-admin -email you@example.org` creates the admin from the command line and prints a password link instead.

Then, in the browser:

1. **Settings › General**: the public URL (used in alert links and as the Google redirect), the time zone, and "behind a reverse proxy" when one terminates TLS in front of tlswatch.
2. **Settings › Channels**: an SMTP relay (host, port, STARTTLS / implicit TLS / none, username, password, sender, recipients) and/or a Telegram bot (token from @BotFather, chat IDs). Under "More types": a Slack incoming webhook (Mattermost and Rocket.Chat take the same), a Discord channel webhook, an ntfy topic (server, topic, optional access token), or a webhook of your own (URL, optional signing secret). Use **Test** on each.
3. **Settings › Sign-in** (optional): Google client ID and secret, and a Workspace domain. Register the redirect URI shown there.
4. **Settings › Users**: invite people. Password users get a one-time link (mailed through the first SMTP channel when there is one); Google users just sign in.
5. **Targets › Add target**, or `tlswatch seed` for a few public demo targets.

## Environment overrides

Only `TLSWATCH_LISTEN`, `TLSWATCH_DB`, `TLSWATCH_SECRET_KEY_FILE` and `TLSWATCH_LOG_JSON` are read before the database opens. These override a UI setting and make it read-only there:

| Variable | UI setting |
| --- | --- |
| `TLSWATCH_BASE_URL` | General › Public URL |
| `TLSWATCH_BEHIND_PROXY` | General › Behind a reverse proxy |
| `TLSWATCH_ALLOW_LOCAL` | General › Allow loopback and link-local targets |
| `TLSWATCH_METRICS` | General › Serve Prometheus metrics |
| `TZ` | General › Time zone |
| `TLSWATCH_WORKERS` | Defaults › Concurrent probes |
| `TLSWATCH_RETENTION_DAYS` | Defaults › History retention |
| `TLSWATCH_GOOGLE_CLIENT_ID`, `TLSWATCH_GOOGLE_SECRET_FILE`, `TLSWATCH_GOOGLE_DOMAIN` | Sign-in › Google |

Values are checked against the same ranges as the UI (retention 7 to 3650 days, workers 1 to 256, booleans `true` or `false`, an absolute base URL, a readable secret file). An invalid value stops tlswatch at start with a message naming the variable. `TZ` is the exception: it is shared with the rest of the system, so an unknown zone is ignored.

## Backups and upgrades

- `tlswatch backup /backups/tlswatch-$(date +%F).db` writes a consistent copy while the server runs (SQLite `VACUUM INTO`). Run it daily from cron. It does not migrate or otherwise change the database it copies.
- Keep `secret.key` with the backups. Without it the database still works, but stored SMTP passwords, Telegram tokens, webhook URLs and secrets and the Google secret must be entered again. A channel whose credentials cannot be decrypted is marked on Settings › Channels; its alerts fail until its credentials are entered again, and the other channels keep working.
- To replace the key (for example after it was exposed), stop tlswatch and run `tlswatch rotate-key`. It re-encrypts the stored credentials under a new key in one transaction, then swaps the key file and keeps the old one as `secret.key.old-<time>`; keep that file as long as backups made with it, then delete it. The command refuses to run while tlswatch answers on `TLSWATCH_LISTEN`.
- Settings › Backup downloads the whole instance as one file encrypted with a passphrase: targets, history, findings, channels with their credentials, CA bundles, users, settings and the audit log. The secret key is not in it; the credentials inside are sealed under the passphrase. Keep the passphrase apart from the file.
- To restore, upload the file under Settings › Backup, or on the setup screen of a fresh installation (before any account exists), so moving to a new host needs no throwaway admin. The restore replaces everything in place while tlswatch runs, re-encrypts the credentials under the instance's own key and signs everyone out; sign in with an account from the backup. A copy written by `tlswatch backup` restores the same way without a passphrase, but its credentials are readable only when the instance has the `secret.key` it was made with. A backup from a newer tlswatch is refused; an older one is migrated.
- Upgrades are a binary swap. Migrations run at start, are forward only, and a binary refuses a database written by a newer version.
- `tlswatch version` (and `tlswatch_build_info` on `/metrics`) names the commit a build came from, also for an image built with `docker compose up --build`: `2026.10.15-5efacf7` while the repository has no tag, `v0.2.0-5-g5efacf7` five commits past one, `v0.2.0` on a release, and `-dirty` when the build had uncommitted changes. So "which version runs there?" is answered by that command on every instance.

## Monitoring tlswatch

`GET /healthz` answers 200 with JSON (`database`, `scheduler_running`, `last_check`, `backlog`, `overdue_s`) and 503 when the database is unreachable, the scheduler stalled, or the oldest due check has waited more than an hour (`overdue_s` > 3600: workers stuck or too few). `tlswatch healthcheck` calls it on `TLSWATCH_LISTEN` and exits non-zero when it is not 200; the Docker image uses it as its `HEALTHCHECK`.

With *Serve Prometheus metrics* on (Settings › General, or `TLSWATCH_METRICS=true`), `GET /metrics` returns `tlswatch_targets{status}`, `tlswatch_findings_open{severity}`, `tlswatch_alerts{state}`, `tlswatch_certificate_not_after_seconds{target,endpoint}`, `tlswatch_checks_total`, `tlswatch_scheduler_backlog`, `tlswatch_scheduler_overdue_seconds`, `tlswatch_scheduler_running`, `tlswatch_last_check_seconds` and `tlswatch_build_info{version}`. Like `/healthz` it needs no sign-in, and it names every target, so let only the monitoring system reach it. Example alert: `tlswatch_alerts{state="failed"} > 0` (a channel gave up).

Logs are JSON lines on stdout; set `TLSWATCH_LOG_JSON=false` for text and `TLSWATCH_DEBUG=true` for debug logging. Every response carries an `X-Request-ID`, which the log lines of that request repeat. Requests are logged at info level when they fail (status 400 or higher) or take more than 2 seconds, otherwise at debug level. On shutdown tlswatch waits up to 15 seconds for running checks and alert deliveries.

### Why did (or didn't) an alert go out?

Every check logs one `checked` line with the target, its `check_id` (also stored on the observations), the resulting `status`, and what changed: the findings `opened`, `escalated` and `resolved`, informational `events` (such as an automatic renewal), the kinds still `waiting` for the debounce, `alerts_queued`, the alerts held back because the finding is `below_floor` of a channel, and how many `channels` the target alerts to. Delivery logs `alert delivered`, `alert delivery failed, will retry` or, after 24 hours, `alert delivery given up`, each with the channel and the alert IDs. A delivered alert records how it went out: the SMTP `Message-ID` (to find it in the relay's logs), for Telegram `chat:message_id` per chat, for Discord and ntfy the message ID they returned, and for a webhook the `ref` the payload carried; Slack returns nothing to record. The finding's timeline shows it when you hover the delivery state.

## Networks

tlswatch probes from where it runs. Internal addresses must be reachable from that host, through a route or from a node (below). Hosts without an IPv6 route skip AAAA records (noted on the target, not reported as unreachable).

## Nodes

A node is `tlswatch node` on a host inside a network the server cannot reach. It connects out to the server and is never connected to; the schedule, results, findings and alerts stay on the server. Where the network allows a route in (a WireGuard or Tailscale subnet router, an SSH tunnel), that needs no node at all and is the first thing to try.

**The one firewall rule.** The node needs outbound HTTPS to the server's public URL (Settings › General), nothing else. It honours `HTTPS_PROXY` and `NO_PROXY`. The server must answer on that URL over HTTPS with a certificate the node's host trusts; for a server on a private CA, add that CA to the host's trust store. The reverse proxy in front of the server needs no WebSocket or upgrade settings: a node's poll is an ordinary request held for up to 55 seconds, under the common 60-second proxy and load-balancer timeouts. An idle node uses a few megabytes a day.

> [!IMPORTANT]
> If a reverse proxy or load balancer in front of the server has a read or idle timeout under 60 seconds, raise it before you deploy a version with the 55-second poll, or polls will be cut off and nodes will keep reconnecting. For example: nginx `proxy_read_timeout 75s;`, HAProxy `timeout server 75s`, or the idle timeout of an AWS load balancer. Cloudflare's 100 seconds is enough.

**Installing.** Settings › Nodes › Add node shows one command to run as root on a host with systemd; it installs `/var/lib/tlswatch-node/bin/tlswatch` (linked from `/usr/local/bin/tlswatch`), `/etc/tlswatch-node.env`, the unit `tlswatch-node.service` and the system user `tlswatch-node`. The same screen has a Docker command and a manual one for hosts without systemd or root. The command holds a one-time token valid for an hour. Once the machine enrolled, the screen shows what it reported (hostname, system, addresses); confirm it and name it, and it can take targets ("Probe from" on the target form).

**Settings on the node** are flags or environment variables, read from `/etc/tlswatch-node.env` by the unit:

| Variable | Flag | Default | Purpose |
| --- | --- | --- | --- |
| `TLSWATCH_NODE_SERVER` | `-server` | | The server's public URL; `https://` unless `-insecure` |
| `TLSWATCH_NODE_DATA` | `-data` | `/var/lib/tlswatch-node` (`/data` in the image) | Directory of the credential file |
| `TLSWATCH_NODE_WORKERS` | `-workers` | `4` | Probes at once |
| `TLSWATCH_NODE_ALLOW` | `-allow` | empty: any | CIDRs the node may probe; whatever the server asks, others are refused |
| `TLSWATCH_NODE_ALLOW_LOCAL` | `-allow-local` | `false` | Allow loopback and link-local addresses (Settings › General must allow them too) |
| `TLSWATCH_NODE_TOKEN` | `-token` | | Install token: without a credential, enrol with it first (Docker) |

**When a node shows offline.** On the node: `systemctl status tlswatch-node` and `journalctl -u tlswatch-node` (one line per job, and why a poll failed). Typical causes: the service is stopped, the host cannot reach the server or does not trust its certificate, a proxy is needed, or the credential was revoked ("credential not accepted": rotate it on the node page and run the new command). The node's targets keep their last state and show "Waiting for node"; nothing alerts per target. After 10 minutes one `node_offline` finding opens, critical once a target is overdue by more than its interval, and it resolves with a recovery notice when the node polls again.

**Updates.** Nodes update themselves to the server's version, one at a time, and roll back when the new version does not reach the server within five minutes; this is automatic for release builds and can be switched off under Settings › Nodes. A node in a container is updated by pulling the image tag of the server's version.

**Removing.** `sudo tlswatch node uninstall` on the machine, or, when the binary is gone, `curl -fsSL https://<server>/agent/v1/uninstall | sudo sh`. Delete the node under Settings › Nodes too; a node with targets offers to move them to the server.
