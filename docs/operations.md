# Operations guide

## First start

`tlswatch serve` needs no configuration. On first start it creates the data directory and generates `secret.key` (mode 0600) next to the database. While no account exists, every page leads to a setup screen where you create the first admin with your own e-mail address and password; you are signed in right after. Do this before the port is reachable by others: until then, whoever opens tlswatch first becomes admin. For scripted installs, `tlswatch create-admin -email you@example.org` creates the admin from the command line and prints a password link instead.

Then, in the browser:

1. **Settings › General**: the public URL (used in alert links and as the Google redirect), the time zone, and "behind a reverse proxy" when one terminates TLS in front of tlswatch.
2. **Settings › Channels**: an SMTP relay (host, port, STARTTLS / implicit TLS / none, username, password, sender, recipients) and/or a Telegram bot (token from @BotFather, chat IDs). Use **Test** on each.
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
| `TZ` | General › Time zone |
| `TLSWATCH_WORKERS` | Defaults › Concurrent probes |
| `TLSWATCH_RETENTION_DAYS` | Defaults › History retention |
| `TLSWATCH_GOOGLE_CLIENT_ID`, `TLSWATCH_GOOGLE_SECRET_FILE`, `TLSWATCH_GOOGLE_DOMAIN` | Sign-in › Google |

## Backups and upgrades

- `tlswatch backup /backups/tlswatch-$(date +%F).db` writes a consistent copy while the server runs (SQLite `VACUUM INTO`). Run it daily from cron.
- Keep `secret.key` with the backups. Without it the database still works, but stored SMTP passwords, Telegram tokens and the Google secret must be entered again.
- Upgrades are a binary swap. Migrations run at start, are forward only, and a binary refuses a database written by a newer version.

## Monitoring tlswatch

`GET /healthz` answers 200 with JSON (`database`, `scheduler_running`, `last_check`, `backlog`) and 503 when the database is unreachable or the scheduler stalled. Logs are JSON lines on stdout; set `TLSWATCH_LOG_JSON=false` for text.

## Networks

tlswatch probes from where it runs. Internal addresses must be reachable from that host; for an isolated network, run a second instance inside it. Hosts without an IPv6 route skip AAAA records (noted on the target, not reported as unreachable).
