# Specification – tlswatch

Version 0.1 (draft) · 14 October 2026 · Sjoerd van Dijk

Working title: tlswatch. The living copy of this document is in Claude Docs; this file is the exported snapshot kept with the code.

## Purpose and scope

The tool monitors the certificates that are actually served on a list of hostnames and IP addresses, judges whether they are valid, and alerts by e-mail and Telegram before they expire or when something changes. It is a single self-hosted Go binary with a web UI, built for 10 to 100 endpoints in a small operations team but designed to scale to thousands.

In scope for version 1:

- Probing TLS endpoints by hostname or IP address, on any port, including STARTTLS protocols.
- Checking expiry (leaf and intermediates), chain of trust, hostname match, and signature strength, with self-signed and private-CA certificates as expected states.
- Detecting a changed certificate, with an exception for endpoints whose certificate is renewed automatically (Let's Encrypt and other ACME clients).
- A certificate inventory: every certificate seen, where it is served, when it expires.
- Alerts on SMTP and Telegram, with reminders, recovery notices and acknowledgement.
- Users with the roles admin, operator and viewer; local login and Google sign-in.
- A daily check per target by default, 180 days of history.

Out of scope for version 1 (listed under open points as candidates for later): certificate issuance or renewal, remote probe agents inside customer networks, a public REST API, Prometheus metrics, bulk import, OCSP and CRL checks, Certificate Transparency monitoring, TLS configuration grading, and uptime monitoring.

The tool does not manage certificates. It only observes what is served and reports on it.

## Terms and data model

The certificate is the primary entity; a target is where it is observed. One certificate served on many hosts is one record with many endpoints, which is what makes the inventory useful.

| Entity | What it is | Key fields |
| --- | --- | --- |
| Target | One endpoint to probe: a hostname or IP address, a port and a protocol | name, host, port, protocol, servername (SNI), trust mode, CA bundle, renewal managed (yes/no), expected issuer, thresholds, interval, tags, notes, channels, enabled |
| Observation | The result of one probe of one target at one resolved address | target, address, checked at, status, TLS version, cipher, leaf certificate, chain, error, duration |
| Certificate | One X.509 certificate, keyed by SHA-256 fingerprint | fingerprint, subject, issuer, serial, not before, not after, SANs, key type and size, signature algorithm, PEM, first seen, last seen |
| Finding | A problem on a target that is open until it resolves | target, kind, severity, opened at, resolved at, acknowledged by and until, details |
| Alert | One delivery of a finding or recovery to one channel | finding, channel, sent at, result |
| Channel | A delivery route: an SMTP recipient list or a Telegram chat | kind, settings, minimum severity |
| CA bundle | A PEM bundle of private roots and intermediates, uploaded by an admin | name, PEM, fingerprints |
| User | A person who signs in | e-mail, name, role, login method, password hash, enabled |
| Audit entry | Who changed what in the tool itself (targets, users, settings, acknowledgements) | when, user, action, object, details |

A finding is opened when a check first fails and resolved when a later check passes. The same problem does not open twice; an alert fires on the transition, reminders on a schedule, a recovery notice on resolution.

## Targets and probing

A target is `host:port` plus a protocol. The host is a DNS name or an IPv4/IPv6 address; the port defaults from the protocol and can be anything.

**Protocols**

| Protocol | Default port | Handshake |
| --- | --- | --- |
| `tls` | 443 | Implicit TLS on connect; covers HTTPS, SIP-TLS (5061), LDAPS (636), IMAPS, SMTPS, any custom port |
| `smtp` | 587 | STARTTLS after EHLO |
| `imap` | 143 | STARTTLS |
| `pop3` | 110 | STLS |
| `ftp` | 21 | AUTH TLS |
| `postgres` | 5432 | SSLRequest |

A STARTTLS server that stops offering STARTTLS is reported (`tls_unavailable`); this also catches STARTTLS stripping.

**Name versus address.** The server name sent in SNI and used for hostname verification is a separate field, `servername`, which defaults to the host when the host is a DNS name and is empty when the host is an IP. This allows probing `10.0.0.5:443` while verifying `portal.example.nl`, for a service behind a bastion or not yet in DNS. An IP target without a servername is checked for expiry and chain, not for hostname.

**Multiple addresses.** A DNS name may resolve to several A/AAAA records (a load balancer, anycast, dual-stack). The prober resolves the name at every check and probes every address, up to 8, in parallel. Each address yields its own observation. The target's status is the worst of its addresses, and a finding `inconsistent` opens when addresses serve different certificates. This catches the common failure where one node behind a balancer was never updated. Per target this can be set to "first address only". If the probing host has no IPv6 route, AAAA records are skipped and noted, not reported as unreachable.

**Trust mode** per target:

- `system` (default): verify against the operating system's root store.
- `bundle`: verify against an uploaded CA bundle, for internal PKI.
- `self-signed`: no chain verification; the first observed fingerprint is pinned, and a different certificate later opens a `certificate_changed` finding.

**Scheduling.** Default interval is 24 hours; per target it can be lowered to a minimum of 1 hour. Checks are spread over the day with a per-target jitter so that a restart does not fire every probe at once. Operators can run "Check now" on a target. A worker pool (default 8 concurrent probes) with a 10-second connect timeout and 2 retries keeps a run of 1,000 targets under a few minutes.

**Network reach.** The tool probes from where it runs. Internal addresses must be reachable from that host; for isolated customer networks a second instance is the version-1 answer, remote probe agents a later one. Probes accept TLS 1.0 and up so that old appliances and embedded management interfaces can still be monitored; the negotiated version is recorded and shown.

## Checks, findings and severity

Every observation runs the full set of checks; each failed check is a finding of one kind with one severity. Three severities: `info` (shown, never alerted by default), `warning`, `critical`.

| Kind | Opens when | Severity | Notes |
| --- | --- | --- | --- |
| `expiring` | The earliest NotAfter in the presented chain is within the warning or critical threshold | warning / critical | Counts whole days; escalates from warning to critical as the date nears |
| `expired` | Any certificate in the presented chain has expired | critical | |
| `chain_untrusted` | The chain does not verify against the trust mode (system store or bundle) | critical | Missing intermediate, unknown root, broken signature; not raised for `self-signed` targets |
| `self_signed` | A self-signed leaf on a target whose trust mode is not `self-signed` | critical | The fix is either the server or switching the target to `self-signed` |
| `hostname_mismatch` | The servername is not covered by the CN/SANs | critical | Skipped when servername is empty (plain IP target) |
| `weak_signature` | A chain certificate is signed with SHA-1 or MD5, or has an RSA key under 2048 bits | warning | Expiry is still reported |
| `certificate_changed` | The leaf fingerprint differs from the previous observation | info or warning | See change detection below |
| `issuer_changed` | The issuer differs from the previous certificate or from the configured expected issuer | warning | A Let's Encrypt name suddenly served by another CA is worth a look |
| `inconsistent` | Different addresses of one name serve different certificates | warning | One node behind a load balancer not updated |
| `tls_unavailable` | A STARTTLS server did not offer STARTTLS | critical | |
| `unreachable` | Connect or handshake failed after retries, on all addresses | critical | Debounced: needs 2 consecutive failing checks to open and 2 passing to close |
| `dns_failed` | The name did not resolve | critical | Debounced like `unreachable` |

**Change detection.** A new leaf certificate is normal on an ACME-managed endpoint and suspicious on a manually managed one. A target carries the flag *renewal managed* (default on when the issuer is a known ACME CA such as Let's Encrypt, ZeroSSL or Google Trust Services, off otherwise; always editable).

- Renewal managed: a new certificate with the same issuer organisation and the same or a superset of SANs is recorded as `info` and not alerted. Any other change is a warning.
- Not renewal managed: any new leaf is a `warning` finding, so an operator confirms the replacement was intended. Acknowledging it resolves the finding.
- `self-signed` targets: pinned fingerprint; any change is a warning.

Fact findings (`expired`, `chain_untrusted`, `hostname_mismatch`, `weak_signature`, `expiring`) are raised on the first observation that shows them: there is no network noise in a certificate that is read successfully. Only the network-shaped findings are debounced.

The negotiated TLS version and cipher suite, the key type and size, and the full chain are stored with every observation and shown in the UI, without a finding attached. Grading them is a later feature.

## Thresholds and defaults

Every threshold lives on the target, pre-filled from the global defaults an admin can change under Settings. Changing a default later does not touch targets that already have a value; a target field left empty follows the default.

| Setting | Default, manually managed | Default, renewal managed | Range |
| --- | --- | --- | --- |
| Warning, days before expiry | 30 | 10 | 1 to 365 |
| Critical, days before expiry | 7 | 3 | 1 to warning minus 1 |
| Check interval | 24 h | 24 h | 1 h to 7 d |
| Addresses probed | all (max 8) | all (max 8) | all / first |
| Connect timeout | 10 s | 10 s | 2 to 60 s |
| Retries before `unreachable` | 2 | 2 | 0 to 5 |
| Debounce, consecutive checks | 2 | 2 | 1 to 5 |
| Reminder interval, warning | 7 d | 7 d | 1 d to never |
| Reminder interval, critical | 1 d | 1 d | 1 h to never |
| Channels | all enabled | all enabled | subset |

The lower defaults for renewal-managed targets follow from ACME clients renewing at about two-thirds of the certificate lifetime: on a 90-day Let's Encrypt certificate a renewal normally lands with 30 days left, so a 30-day warning would fire on every healthy endpoint. With lifetimes shortening in the coming years these two defaults are the ones most likely to need tuning, which is why they are a global setting and not a constant.

A threshold fires when strictly fewer than N whole days remain, so "warning 30" alerts on the first check that sees 29 days or less. The number of days shown in the UI and in alerts uses the same truncation.

## Alerting

Alerts fire on state transitions, not on every check, so a daily check never produces a daily e-mail for the same problem. Specified behaviour:

1. **Open**: one alert when a finding opens, to every channel attached to the target whose minimum severity is met.
2. **Escalate**: one alert when a finding's severity rises (warning to critical).
3. **Remind**: a repeat at the target's reminder interval while the finding stays open, with the same message plus "still open since". Acknowledged findings are not reminded.
4. **Recover**: one notice when the finding resolves, so the receiver knows it is done. Recovery is sent to the channels that received the open alert.
5. **Acknowledge**: an operator acknowledges a finding in the UI, optionally until a date (snooze). Acknowledging suppresses reminders, never the escalation or recovery notice. An acknowledgement on `certificate_changed` resolves it; on other kinds it expires when the finding resolves or the date passes.
6. **Digest**: an optional weekly e-mail (day and hour configurable) listing open findings, certificates expiring in the next 30 days, and targets that failed their last check. Off by default.

**Channels** are configured globally by an admin; each target selects which of them apply (default: all). A channel has a minimum severity: a Telegram chat can take only `critical` while the mailbox takes everything.

| Channel | Transport | Settings |
| --- | --- | --- |
| SMTP | Go standard library over STARTTLS or implicit TLS, with optional PLAIN/LOGIN auth | host, port, user, password, from, recipients, minimum severity |
| Telegram | HTTPS call to `api.telegram.org/bot<token>/sendMessage`, no library | bot token, chat IDs, minimum severity |

One message per finding; a run that opens many findings at once (a new bundle of targets, an outage) is collapsed into one message per channel listing them, capped at 50 lines.

**Message content**: target name and `host:port`, finding kind and severity, days left and the expiry date, issuer and subject CN, fingerprint (short), the address that failed, and a link to the target in the UI. Telegram messages are plain text with the same fields on separate lines. The subject line starts with the severity in brackets so mail rules can route it: `[critical] portal.example.nl:443 expires in 6 days`.

**Delivery** is queued in SQLite and retried with backoff (1 min, 5 min, 30 min, then hourly for 24 hours); a channel that is down does not block another. A test button per channel sends a sample message. Every delivery and its result is kept in the alert log for 180 days.

## Inventory and user interface

The UI is an operations console: the home screen answers "what needs attention now" before anything else, lists are dense and sorted by expiry, and colour means status only. All text in English. Navigation: **Overview**, **Targets**, **Certificates**, **Findings**, **Settings** (admin only), with live counts, plus the account menu. The design canvas in `design/` is the reference for every screen below.

**Grouping** is by free-form tags (`customer:contoso`, `site:amsterdam`, `sip`), shown as badges, filterable, and usable as a column to group the targets list. Tags are enough for 10 to 100 targets and scale by convention; a fixed group hierarchy is deliberately left out. Every target has a notes field for owner, ticket number or renewal procedure.

| Screen | Role | Content |
| --- | --- | --- |
| Sign in | all | One card: e-mail and password, "Sign in with Google" below. Neutral error messages. |
| Overview | viewer+ | Four status tiles (critical, warning, healthy, unreachable), "Expiring next" with a lifetime bar per certificate, open findings, recent changes, and the last run's summary (targets and addresses probed, failures, alerts sent). |
| Targets | viewer+ | Dense table: status, name, `host:port`, days left, lifetime bar, expiry date, issuer, TLS version, tags, last check. Filter field plus chips for status and tag with counts; sorted by expiry by default. Page-head buttons: Add target (operator+), Check all (operator+). |
| Target detail | viewer+ | Leads with the certificate: countdown, lifetime bar, subject, issuer, SANs, key, serial, fingerprint with copy/PEM. Then the chain as a vertical stack with the weak link marked, per-address results of the last check, history of certificates seen on the target. Side column: configuration, findings on this target, alerts sent. Buttons: Check now, Edit, Disable (operator+). |
| Target form | operator+ | Fields in order: host, port, protocol, name, servername; trust mode (system / bundle / self-signed) and bundle, renewal managed, expected issuer; thresholds, interval, addresses; tags, channels, notes. "Test without saving" runs a probe and shows the result in a side panel. |
| Certificates | viewer+ | The inventory: one row per unique certificate: subject, issuer, days left, lifetime bar, not after, key, number of targets serving it, short fingerprint, first seen. Filter chips for expiry window, issuer, key type. Row expands to full fingerprint, SANs, chain and the targets and addresses where it is served. |
| Findings | viewer+ | Open findings first, sorted by severity then days left; each row: severity, kind with detail, target, since, last alert, acknowledgement. The acknowledge form (until-date, comment) and the alert timeline open in a side panel (operator+). Chips for open/resolved, severity and kind. |
| Settings: General | admin | Public base URL, proxy trust, local targets; values set by environment shown read-only. |
| Settings: Channels | admin | SMTP and Telegram channels with severity floor, last delivery, Test button, edit form below the table: SMTP host, port, encryption, username, password, from, recipients; Telegram bot token and chat IDs. |
| Settings: Sign-in | admin | Google client ID, client secret, Workspace domain, redirect URI to register. |
| Settings: CA bundles | admin | Upload PEM, list of the certificates inside with validity. |
| Settings: Defaults | admin | The global thresholds table, digest schedule, probe concurrency. |
| Settings: Users | admin | Table: name, e-mail, login method, role, status; invite by e-mail, edit, disable. |
| Settings: Audit log | admin | Who changed what, filterable, export CSV. |
| Account | all | Name, theme (system, light, dark), change password for local accounts. |

The healthy state is the common one and must read as good news: "14 targets, nothing due within 30 days, last run 04:17". Empty states say what to do next ("No targets yet — add one or run `tlswatch check host`"). Below 760 px tables fall back to cards. Status colours are used identically everywhere: green healthy, amber warning, red critical and expired, grey disabled or unreachable, blue only for informational changes.

## Users, authentication and authorisation

Three roles, one per user, no organisations or tenants: the tool is single-tenant by design.

| Action | Viewer | Operator | Admin |
| --- | --- | --- | --- |
| View targets, certificates, findings, history | yes | yes | yes |
| Add, edit, disable, delete targets; check now | | yes | yes |
| Acknowledge findings | | yes | yes |
| Settings: general, sign-in, channels, CA bundles, defaults, digest | | | yes |
| Users and roles | | | yes |
| Audit log | | | yes |

**Local login**: e-mail and password. An admin creates the account; the user receives a one-time link (7 days valid) to set a password of at least 12 characters, checked against a local list of leaked passwords. Password hashes use Argon2id. Five failed attempts block the account for 15 minutes; the error message does not reveal whether the e-mail exists.

**Google sign-in**: OpenID Connect with Authorization Code and PKCE, implemented against the standard library plus `golang.org/x/oauth2`. Sign-in is only possible for an e-mail address an admin has already added (allowlist); there is no self-registration. Optionally restricted to one Workspace domain. The login method is per user: a Google user has no password.

**TOTP** as second factor for local accounts is not in version 1 (open point); the tool holds no secrets beyond its own channel credentials.

**Sessions**: server-side session store in SQLite, cookie `HttpOnly; Secure; SameSite=Lax`, 8 hours idle timeout, CSRF token on every state-changing form and JSON call. While no account exists, every page redirects to a setup screen where the first admin is created with their own e-mail address and password and signed in directly; the screen disappears once an account exists. The check and the insert are one transaction, so concurrent attempts create one admin only. Scripted installs can use the `create-admin` subcommand, which prints a one-time password link.

**Authorisation** is one decision function role × action, called by every handler and covered by a negative test suite (every role tried against every action it must not have).

## Architecture

One Go binary, one SQLite file, no other services. The frontend is server-rendered with `html/template` and embedded in the binary together with the CSS, fonts and compiled TypeScript; the scheduler and alert dispatcher run as goroutines in the same process.

```
 Browser ◄──► ┌─────────────────────────────────────────────────┐
              │ One Go binary                                   │
              │                                                 │
              │  Web UI + JSON API       Scheduler              │
              │  templates, TypeScript   daily, jitter, pool    │
              │                               │                 │
 Google  ◄─── │  Authentication          Prober ──────────────► │ ──► Targets
 sign-in      │  local, OIDC, roles      TLS, STARTTLS, chains  │     (TLS endpoints)
              │        ┌───────────────────────┘                │
              │        ▼                                        │
              │  Checker ───────────────► Notifier ───────────► │ ──► SMTP relay,
              │  findings, thresholds     outbox, retries       │     Telegram
              │                                                 │
              │  ┌───────────────────────────────────────────┐  │
              │  │ SQLite, one file: targets, certificates,  │  │
              │  │ observations, findings, outbox, users     │  │
              │  └───────────────────────────────────────────┘  │
              └─────────────────────────────────────────────────┘
```

The scheduler hands targets to the prober, the checker turns each observation into findings, and the notifier delivers them; every component reads and writes the one SQLite file, and the web UI shows what is in it.

**Backend layout**:

| Package | Responsibility |
| --- | --- |
| `cmd/tlswatch` | main; subcommands `serve`, `create-admin`, `migrate`, `backup`, `check` (one-off probe of a host, prints JSON, exit code by severity) |
| `internal/probe` | TLS and STARTTLS dialers, chain capture, verification against system store or bundle; no database access, so it can later be reused by a remote agent |
| `internal/check` | Turns an observation into findings: thresholds, change detection, debounce |
| `internal/core` | Domain: targets, certificates, findings, acknowledgements, state transitions |
| `internal/sched` | Scheduler: per-target next-run with jitter, worker pool, Check now queue |
| `internal/notify` | Channels, message rendering, outbox with retry |
| `internal/auth`, `internal/authz` | Passwords, sessions, OIDC; the role × action decision |
| `internal/db` | SQLite access and embedded migrations, run at start |
| `internal/web` | HTTP handlers, pages, the internal JSON API under `/api/v1` used by the TypeScript |
| `web/` | templates, `static/css`, self-hosted fonts, `ts/` sources compiled to `static/js` |

**Database**: SQLite in WAL mode through `modernc.org/sqlite` (pure Go, so the binary is static and cross-compiles without cgo). One writer goroutine serialises writes; reads are concurrent. Certificates are stored once by fingerprint with the PEM; observations reference them. Expected size at 100 targets with daily checks and 180 days retention: under 50 MB.

**Retention**: observations, findings, alert log and audit entries older than 180 days (configurable) are pruned hourly. Certificates are kept while any observation references them. The current state of every target is always kept regardless of age.

**Scale**: the schedule is a priority queue by next-run time, so 10,000 targets cost memory, not CPU, between runs. Probing is bounded by the worker pool; SQLite handles the write rate of daily checks on thousands of targets with margin. The single-process design is a deliberate limit: one instance, scaled up, not out.

**Dependencies** (Go): standard library, `modernc.org/sqlite`, `golang.org/x/crypto` (Argon2id), `golang.org/x/oauth2`. Nothing else without a reason written in the pull request.

## Frontend

The frontend is pages rendered server-side with Go `html/template`, and TypeScript only where a page cannot work as a plain form. Every page works without JavaScript; the API endpoints answer JSON to the TypeScript and a redirect to a form.

**TypeScript without dependencies.** `tsc` alone compiles `web/ts` to plain ES modules in `web/static/js`, loaded with `<script type="module">`. No bundler, no framework, no runtime package. The dev dependency tree is `typescript` only, enforced in CI by a `check-deps` script. The `tsconfig.json` settings: ES2022, `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`.

Where TypeScript is used in version 1:

- The target form's Test button (probe without saving, render the result).
- Check now and Check all, with the row updating in place when the probe returns.
- Table row expand/collapse, copy-to-clipboard for fingerprints and PEM, filter chips.
- The acknowledge panel (until-date, comment).
- Live filtering on the targets and certificates tables.

Everything else is a form. Shared helpers (`$`, `api()`, `ApiError`, `onReady`) live in `common.ts`; error messages come from one `messages` map, in English.

**Styling** follows the design canvas (`design/` in the repository), which is an operations console, not a workflow portal. The rules: colour carries status and nothing else — green, amber, red and grey mean healthy, warning, critical and off, and appear nowhere else; actions use one neutral accent (slate blue); the chrome is a 48 px dark graphite bar with live counts in the navigation; content is light by default with a full dark token set, the theme chosen as in Share (system preference, manual override stored server-side in a cookie, no flash). Type is IBM Plex Sans at 13 px for the UI and IBM Plex Mono for host:port, fingerprints, serials, dates and counts, both self-hosted under their OFL licences. Lists are dense: 8 px row padding, uppercase 11 px column heads, status as a dot plus a word, a lifetime bar per certificate showing the share of validity already used, filter chips with counts instead of dropdowns, sorted by expiry by default. Notices are bars, not toasts; the acknowledge form is a side panel, not a modal. All colours are CSS custom properties on `:root`; no colour is hard-coded below the token blocks. The token values are listed in `design/README.md`.

**Wordmark.** An inline-SVG shield-with-check mark in the accent colour next to "tlswatch" in Plex Sans 600, 15 px in the bar and 22 px on the sign-in card. No company branding anywhere in the open-source project.

**Principles**: server-rendered pages with small TypeScript modules, light and dark from day one via tokens, real forms that work without JavaScript, notices as bars, the mono convention for identifiers, tables that fall back to cards below 760 px, and the `tsc`-only toolchain.

**Build and test tooling**: `npm ci && npx tsc -p tsconfig.json` to build; `node --test web/test/*.test.mjs` on the compiled output for the few pure functions worth testing (days-left truncation, fingerprint formatting, tag parsing); Go `testing` with `-race` for everything else, including handler tests against an in-memory SQLite. No test framework beyond what Node and Go ship.

## Configuration, deployment and operations

**Everything is configured in the UI, as far as possible.** Only what the process needs before it can open its database stays outside it: the listen address, the database path and the secret key. All the rest lives in the database and is edited under Settings by an admin: the SMTP relays (host, port, encryption, username, password, sender, recipients), the Telegram bot token and chat IDs, Google sign-in (client ID, client secret, Workspace domain), the public base URL, probe concurrency, retention, proxy trust and local-target policy, thresholds and the digest.

Secrets entered in the UI (SMTP passwords, Telegram bot tokens, the Google client secret) are stored encrypted with AES-256-GCM under the secret key. They are never shown back; a password field left empty keeps the stored value. A copy of the database alone does not leak them.

**Zero-configuration start.** `tlswatch serve` with no environment works. The data directory is created. A 32-byte secret key is generated into `data/secret.key` (mode 0600) when no key file exists. When no users exist yet, the server shows a setup screen at the first visit where the first admin creates their account and password; the log prints the URL. Because the default bind is loopback, nobody else can reach that screen before the admin exists. `create-admin` remains for scripted installs.

**Environment variables are optional overrides**, for container and GitOps deployments. A setting supplied by the environment wins over the database value and is shown in the UI as read-only with the note "set by environment".

| Variable | Default | Where else | Purpose |
| --- | --- | --- | --- |
| `TLSWATCH_LISTEN` | `127.0.0.1:8080` | bootstrap only | Bind address; put a reverse proxy in front for TLS |
| `TLSWATCH_DB` | `./data/tlswatch.db` | bootstrap only | SQLite file; the directory is created |
| `TLSWATCH_SECRET_KEY_FILE` | `<db dir>/secret.key` | bootstrap only | 32 random bytes, generated if missing; encrypts secrets at rest and signs sessions |
| `TLSWATCH_LOG_JSON` | `true` | bootstrap only | JSON log lines on stdout |
| `TLSWATCH_BASE_URL` | empty | Settings › General | Public URL for links in alerts and the OIDC redirect; while empty, derived from the request and a notice bar asks an admin to set it |
| `TLSWATCH_BEHIND_PROXY` | `false` | Settings › General | Trust `X-Forwarded-For` and `X-Forwarded-Proto` from one hop |
| `TLSWATCH_ALLOW_LOCAL` | `false` | Settings › General | Allow loopback and link-local targets |
| `TLSWATCH_WORKERS` | `8` | Settings › Defaults | Concurrent probes |
| `TLSWATCH_RETENTION_DAYS` | `180` | Settings › Defaults | History retention |
| `TLSWATCH_GOOGLE_CLIENT_ID` / `_SECRET_FILE` / `_DOMAIN` | empty | Settings › Sign-in | Google sign-in; off while no client ID is set |

Settings pages added for this: **General** (base URL, proxy trust, local targets) and **Sign-in** (Google client ID, secret, domain, with the redirect URI to register shown read-only). Channels gain the SMTP encryption choice (STARTTLS, implicit TLS, none) and username/password as in the mockup; Telegram channels take the bot token and one or more chat IDs. Every change is audited, secrets redacted.

**Packaging**: `go build` produces one static binary with the frontend embedded via `embed`; releases ship binaries for linux/amd64, linux/arm64 and darwin/arm64, plus a Docker image from `scratch` with CA certificates, published to GitHub Container Registry. The compose file in the repository runs the image with one volume for `data/`; TLS termination is left to the user's proxy.

**Subcommands**: `serve`, `create-admin -email`, `migrate` (also runs at start), `backup <path>` (SQLite `VACUUM INTO`, safe while running), `check <host[:port]> [-protocol -servername -ca-file -insecure]` for scripts and CI, exit code 0/1/2 by severity.

**Operations**: `/healthz` reports database reachability and scheduler progress (last run, backlog); structured logs; a daily backup is the `backup` subcommand on a cron. Upgrades are a binary swap; migrations are forward-only and refuse to run a database written by a newer version.

**Development**: `make build`, `make test`, `make frontend`, `make run` with a throw-away database; a seed subcommand that adds a few public targets (expired.badssl.com, self-signed.badssl.com, a Let's Encrypt site) so the UI shows every state immediately.

## Security

The tool holds a list of hosts, their certificates (public data) and the credentials of its own alert channels. The risks are the UI being reached by the wrong people, the probe being used as a scanner from inside the network, and the alert credentials leaking.

- **Transport**: the binary listens on loopback by default and expects a reverse proxy for TLS; `BEHIND_PROXY` must be set explicitly before forwarded headers are trusted. HSTS and `Secure` cookies when the base URL is https.
- **Headers**: `Content-Security-Policy: default-src 'self'` with no inline scripts or styles (all CSS in `app.css`, all JS in modules), `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `frame-ancestors 'none'`.
- **Sessions and CSRF**: as in Users above; one CSRF token per session, checked on every POST and on every JSON call via the `X-CSRF-Token` header.
- **Passwords**: Argon2id, 12-character minimum, leaked-password list, rate limit per account and per IP.
- **Probe as scanner**: only operators and admins can add targets, and every addition is in the audit log. Targets are probed with one TLS handshake and no application traffic beyond the STARTTLS preamble. Loopback and link-local addresses are refused as targets unless `TLSWATCH_ALLOW_LOCAL=true`; private ranges are allowed because monitoring internal addresses is the point.
- **Secrets at rest**: channel credentials and the Google client secret are encrypted with AES-256-GCM under the secret key file; the key is never in the database. Logs redact tokens and passwords.
- **Outbound connections** are limited to the targets, the SMTP server, `api.telegram.org` and Google's OIDC endpoints. No telemetry, no update check.
- **Input**: hostnames validated as DNS names or IP literals, ports 1 to 65535, PEM bundles parsed and rejected when they contain private keys, tags limited to 40 characters.
- **Audit log**: every change to targets, users, channels, bundles, defaults and every acknowledgement, with user and timestamp; readable by admins, exportable as CSV, pruned with the retention.
- **Supply chain**: Go dependencies pinned in `go.sum`, `govulncheck` and `gosec` in CI, the npm tree limited to `typescript`, releases built in CI from a tagged commit with checksums published.

## Open source: repository, licence, CI, versioning

The project lives in a public repository under a personal GitHub account; company-specific material (logos, customer names, internal addresses) never enters it.

**Licence**: MIT, recommended. It is the shortest, matches Go and TypeScript community norms, and the tool has no patent surface that would argue for Apache-2.0. The fonts carry their own OFL licence files in `web/static/fonts`.

**Repository layout**

```
cmd/tlswatch/        main and subcommands
internal/...         packages as in Architecture
web/                 templates, css, fonts, ts, test
docs/                this specification, operations guide
design/              design canvas: README with tokens, mockups/*.dc.html
.github/workflows/   ci.yml, release.yml
Dockerfile, compose.yaml, Makefile, go.mod, package.json, tsconfig.json
LICENSE, README.md, CONTRIBUTING.md, SECURITY.md, CHANGELOG.md
```

**CI** on GitHub Actions:

1. Frontend: `npm ci`, `npm audit --audit-level=low`, `check-deps` (typescript only), `tsc`, `node --test`.
2. Backend: `gofmt -l`, `go vet`, `go test -race ./...`, `govulncheck`, `gosec`.
3. Build: binaries for the three platforms and the Docker image, pushed to `ghcr.io` on a tag.
4. Renovate or Dependabot for pinned dependencies and action digests.

**Versioning**: semantic versions from `v0.1.0`; `v1.0.0` when the scope in this document is complete and the database schema is considered stable. `CHANGELOG.md` kept by hand, one line per change, newest first.

**Community files**: README with a screenshot, a three-command quick start and the `check` one-liner; CONTRIBUTING with the dependency rule (no new runtime dependency without a written reason in the pull request) and the test expectation; SECURITY with a private reporting address; issue templates for bug and feature; the specification itself in `docs/` so decisions are traceable.

**Name**: tlswatch. Candidates checked and rejected: `certlens` and `certscope` are taken (a Python package and a Firefox extension), `certwatch` is CertLight's former name, `certview` is a Qualys product. Check the GitHub name, the Go module path and Docker Hub before the first release.

## Decisions taken, assumptions and open points

Where the requirements said "not sure" or "what do you recommend", this document takes a position. Each one is reversible before the first line of code.

| Topic | Decision in this document | Why |
| --- | --- | --- |
| Multiple A/AAAA records | Probe all addresses, up to 8; `inconsistent` finding when they differ; per-target switch to first-only | The one stale node behind a load balancer is the failure a single probe misses |
| Grouping | Free-form tags plus a notes field, no fixed hierarchy | Enough at 100 targets; a hierarchy adds screens and migrations |
| Alert behaviour | Transition alerts, severity-based reminders, recovery notices, acknowledge with snooze, optional weekly digest | Daily checks must not become daily mail |
| Severities | Three: info, warning, critical | Four levels invite routing rules nobody maintains |
| Change detection | `renewal managed` flag per target, auto-set for known ACME issuers | Let's Encrypt churn would otherwise drown real changes |
| Frontend | Server-rendered templates plus small TypeScript modules, not a single-page app; the look is an operations console (status-only colour, dense lists, overview home), not a workflow-portal style | Smallest dependency footprint; a workflow-portal style does not fit a monitor |
| Tooling | `tsc` only, `node --test`, Go `testing`, GitHub Actions, Renovate | Small, standard and reproducible |
| SQLite driver | `modernc.org/sqlite` (pure Go) | Static binary, cross-compiles without cgo |
| Licence | MIT | Simplest; no patent concern |
| Internal networks | One instance per network in v1; probe package kept database-free so an agent can follow | Keeps v1 to one binary |

**Assumptions**

- The tool runs on a host that can reach the public internet and the internal addresses it monitors.
- A reverse proxy handles TLS for the UI itself.
- E-mail goes through an SMTP relay that already exists; the tool is not a mail server.
- The fonts are OFL and can be redistributed with an MIT-licensed project.

**Open points**

- [ ] Confirm MIT, or prefer Apache-2.0.
- [ ] Confirm "all addresses" as the default, or "first only".
- [ ] TOTP for local accounts: v1 or later.
- [ ] Whether `info` findings (expected ACME renewals) should appear in the weekly digest.
- [ ] Which public hosts to use in the seed data and README screenshot.

**Later versions**, in rough priority: Prometheus `/metrics`; a public REST API with tokens; bulk import and export of targets as YAML; remote probe agents for isolated networks; OCSP and CRL checks; Certificate Transparency monitoring for own domains; TLS configuration grading; webhook and ntfy channels; ticket creation in a service desk on critical findings.
