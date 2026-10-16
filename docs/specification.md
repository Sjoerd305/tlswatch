# Specification – tlswatch

This is the maintained specification of tlswatch: it describes how the tool behaves and is updated in the same change as the code, so the version of the code is the version of this document.

## Purpose and scope

The tool monitors the certificates that are actually served on a list of hostnames and IP addresses, judges whether they are valid, and alerts by e-mail, Telegram, Slack, Discord, ntfy or a webhook before they expire or when something changes. It is a single self-hosted Go binary with a web UI, built for 10 to 100 endpoints in a small operations team but designed to scale to thousands.

In scope for version 1:

- Probing TLS endpoints by hostname or IP address, on any port, including STARTTLS protocols.
- Checking expiry (leaf and intermediates), chain of trust, hostname match, and signature strength, with self-signed and private-CA certificates as expected states.
- Detecting a changed certificate, with an exception for endpoints whose certificate is renewed automatically (Let's Encrypt and other ACME clients).
- A certificate inventory: every certificate seen, where it is served, when it expires.
- Alerts on SMTP, Telegram, Slack, Discord, ntfy and generic webhooks, with reminders, recovery notices and acknowledgement.
- Users with the roles admin, operator and viewer; local login and Google sign-in.
- A daily check per target by default, 180 days of history.
- A TLS configuration grade per target (A to F) from the protocol versions, cipher suites and key the server accepts, tested once a day next to the legacy TLS test.
- Certificate Transparency watching: every certificate publicly issued for a watched domain is matched against what the targets serve, and one that no target serves is reported.

Out of scope for version 1 (listed under open points as candidates for later): certificate issuance or renewal, a public REST API, OCSP and CRL checks, and uptime monitoring.

The tool does not manage certificates. It only observes what is served and reports on it.

## Terms and data model

The certificate is the primary entity; a target is where it is observed. One certificate served on many hosts is one record with many endpoints, which is what makes the inventory useful.

| Entity | What it is | Key fields |
| --- | --- | --- |
| Target | One endpoint to probe: a hostname or IP address, a port and a protocol | name, host, port, protocol, servername (SNI), trust mode, CA bundle, renewal managed (yes/no), expected issuer, thresholds, interval, configuration test (on/off), tags, notes, channels, enabled, node |
| Observation | The result of one probe of one target at one resolved address | target, address, checked at, status, TLS version, cipher, leaf certificate, chain, error, duration, node |
| Configuration test | The result of the daily test of one target at one address: which legacy versions and which weak cipher suite classes the server accepted, and the grade that follows (see TLS configuration grade) | target, address, tested at, versions accepted, suite classes accepted, grade, reasons |
| Domain watch | A domain whose public certificate issuance is followed in Certificate Transparency logs (see Certificate Transparency watching) | name, subdomains included (yes/no), tags, notes, channels, enabled, last polled, cursor |
| Issuance | One certificate for a watched domain as published in the logs | domain watch, issuer, serial, names, not before, not after, log entry, first seen, state (pending, known, unexpected, acknowledged), matched certificate |
| Node | A probe worker inside another network, enrolled with the server and reached only by its own outbound connections (see Nodes) | name, state, credential hash, last seen, version, address, pool size, system facts, enabled, notes |
| Certificate | One X.509 certificate, keyed by SHA-256 fingerprint | fingerprint, subject, issuer, serial, not before, not after, SANs, key type and size, signature algorithm, PEM, first seen, last seen |
| Finding | A problem on a target, a node or a domain watch that is open until it resolves | target or node or domain watch, kind, severity, opened at, resolved at, acknowledged by and until, details |
| Alert | One delivery of a finding or recovery to one channel | finding, channel, sent at, result |
| Channel | A delivery route: an SMTP recipient list, a Telegram chat, a Slack or Discord webhook, an ntfy topic or a webhook URL | kind, settings, minimum severity |
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

**Network reach.** The tool probes from where it runs. Internal addresses must be reachable from that host; for isolated customer networks a node inside the network (see Nodes below) probes from there, or a route into the network makes the addresses reachable. Probes accept TLS 1.0 and up so that old appliances and embedded management interfaces can still be monitored; the negotiated version is recorded and shown. Accepting a version to read the certificate is separate from reporting that the server still offers it: see `legacy_protocol` and the TLS configuration grade below.

## Nodes: probing from inside another network

A node is the same binary started as `tlswatch node`, running on a host inside a network the server cannot reach. It holds no database, no settings and no schedule. It opens outbound HTTPS connections to the server, waits for probe jobs, performs each probe with the `internal/probe` package exactly as the server would, and sends the result back. The server keeps the schedule, the data, the checks and the alerts; a target is simply marked as probed from a node instead of from the server. To the rest of the application a node target is an ordinary target whose handshake happened elsewhere.

**Why a node and not something else.** A network route (a WireGuard or Tailscale subnet router, an SSH tunnel) needs no code and is the first thing to try when the customer allows a route in; the operations guide names it. A second instance works today but splits the inventory, the users and the alert rules. A cron job running `tlswatch check` and pushing JSON would move the schedule out of the UI, lose Check now and Test without saving, and give no node health; it is rejected. The node keeps one inventory and one schedule, and the customer network needs one outbound rule: HTTPS to the server.

**Transport.** The node is never connected to; every byte travels over a connection the node opened. It long-polls: `GET /agent/v1/jobs?wait=55s` is held open by the server until a job exists for this node or the ceiling passes, then answered with zero or more jobs; the node sends the next poll at once and runs the jobs in its own small pool. Results go up in a separate `POST /agent/v1/jobs/{id}/result`, so a slow handshake never delays the next command. The connection is kept alive between calls, so an idle node costs one small request and answer per ceiling and no new TLS handshake. Every poll answer carries `Accept-Encoding: gzip` (RFC 7694); a node that saw it on its last poll sends its results and facts gzipped (`Content-Encoding: gzip`), which shrinks the base64 chains, the more so when a host's addresses present the same chain. A server that does not advertise it gets plain bodies, so nodes and servers of different versions keep working. The server caps a body at 4 MB as sent and again after inflating. The held request is also the heartbeat: "last seen" is the time of the node's last request. A job that becomes due while the node's request is pending is delivered within one network round trip, so Check now from the UI reaches the node in milliseconds; the ceiling only decides when an empty answer goes out. A WebSocket was considered and rejected: on a link that carries one real message every half hour (daily checks spread by jitter), it would buy nothing measurable and cost a dependency, a reconnect state machine and an upgrade caveat for every reverse proxy in front of the server. The protocol is a set of commands and replies in its own package, with the transport behind a small interface, so a socket can replace the long-poll later without touching the messages.

| Setting | Value | Why |
| --- | --- | --- |
| Poll ceiling | 55 s | Under the common 60 s proxy and load-balancer timeouts (nginx `proxy_read_timeout`, AWS ALB idle), Cloudflare's 100 s and the server's own (write 150 s, idle 120 s); about two requests a minute from an idle node. The server holds a poll for the shorter of the node's `wait` and its own ceiling |
| Node client timeout | 70 s | A dead connection is noticed one hold after it breaks |
| Node offline | no request for 165 s | Three missed polls; Check now then fails fast instead of waiting |
| `node_offline` finding | offline 10 min | Rides out a reboot or an image pull without an alert |
| Jobs per poll | up to the node's pool size, default 4 | The server never leases more than the node can run |
| Reconnect backoff | 1 s doubling to 60 s | Reset on the first successful poll |
| Job timeout | target timeout × (retries + 1) + 30 s | After it the job is re-queued once, then given up as "no result from the node": the check is logged as failed, nothing is stored, and it is tried again after the scheduler's retry delay |

**Protocol** (`/agent/v1`, JSON, bearer credential, outside session authentication and CSRF, versioned in the path; a server refuses a protocol version it does not know):

| Call | Purpose |
| --- | --- |
| `GET /agent/v1/install/{token}` | The install script for one enrolment token, with the server URL and the token embedded; served without sign-in while the token is unspent and unexpired, otherwise 404 |
| `GET /agent/v1/uninstall` | The uninstall script; the same for every node, so it needs no token, and it works when the node's binary is gone or broken |
| `GET /agent/v1/download/{os}/{arch}` | The node binary: the server's own executable when the platform matches, else a redirect to the release asset of the server's version (a release build only); the SHA-256 in the `X-Tlswatch-Sha256` header either way |
| `POST /agent/v1/enrol` | Exchange a one-time enrolment token for the node's credential; carries the node's pool size and its system facts (see below). Rate limited per IP like sign-in |
| `GET /agent/v1/jobs?wait=55s` | The long-poll. Every call updates last seen, the node's version (`X-Tlswatch-Version`) and its address |
| `POST /agent/v1/facts` | The system facts, at every start of the node and then once an hour |
| `POST /agent/v1/jobs/{id}/result` | The result of one job; an unknown or expired job id is acknowledged and discarded |

A job is an envelope with an id and a kind. Version 1 has three kinds: `probe`, `cancel` and `update` (see Updating nodes). The envelope exists so that later kinds (refresh a bundle, rotate the credential, report what a name resolves to from inside) need no new transport. A `probe` job carries the probe request without the Go-only fields: host, port, protocol, server name, trust mode, first-only, timeout, retries, allow-local, the legacy test flag, and the server's current time. The node resolves the host with its own resolver, so an internal or split-horizon name resolves as seen from inside the network; that, with reachability, is what the node is for. The node verifies with the server's time, so a node with a wrong clock does not produce false verdicts; the server stamps "checked at" itself when the result arrives. The result is the probe result with the chains as DER in base64: per address the TLS version, cipher, chain, verification outcome, hostname check, error kind and text, duration and the legacy verdicts, plus the DNS error and the skipped IPv6 addresses. A pending or disabled node receives no jobs of any kind.

**CA bundles stay on the server.** Trust is managed in one place, Settings › CA bundles, and no bundle ever travels to a node. For trust mode `bundle` the node only captures the chain and the server verifies it against the bundle when the result arrives, so a replaced bundle takes effect on the next check of every node target without touching a node. For trust mode `system` the node verifies against its own operating system root store, which is what a network whose hosts already trust an internal root wants; when that store lacks the root, the answer is to upload it as a bundle in the UI and set the target to `bundle`, not to change the node. Hostname, expiry and signature findings are computed on the server from the chain as today. The node's own connection to the server is the one trust decision that cannot be central, because the node must trust the server before it can receive anything from it, the install script included: the node uses its host's operating system store for that, as `curl` does. A server on a private CA therefore needs that CA in the trust store of the node's host, which a network with its own PKI already has; the install script says so when the first download fails on the certificate.

**Scheduling is unchanged, the pool is not shared.** The scheduler's queue, jitter, interval and Check now work as for every target. When a due target is assigned to a node, the scheduler hands it to that node's queue instead of to a local worker; the node's lease count (its pool size) bounds how many run at once, and the local pool stays free for local probes. A Check all on a node with a hundred targets therefore drains through that node four at a time while the server's own targets are probed as usual. If the node has not polled within the offline window the dispatcher fails at once, so an offline node holds nothing. Nothing about leased jobs is persisted: after a server restart the queue is rebuilt from the database as it is now and due targets are dispatched again; a node that cannot deliver a result drops it, and the server asks again. Node targets keep the per-target jitter; there is no reason to batch a node's targets into one daily burst. Changing a target's "Probe from" is treated like changing its host: the legacy test is forgotten, the debounce streaks reset, and the target is checked soon, because a new vantage point is a new view of the service.

**Offline nodes do not look like unreachable hosts.** A target whose node is offline keeps its last state and shows "Waiting for node" with the time of its last check; its next check is held, no `unreachable` opens and no alert fires per target. Instead one `node_offline` finding opens on the node after 10 minutes, warning, escalating to critical when a target under it is overdue by more than its own interval. It is delivered on every enabled channel whose severity floor allows it and resolves with a recovery notice when the node polls again. When the node returns, its overdue targets are checked right away, spread over a few minutes. The offline clock starts fresh at server start: last seen is in the database, but after a server outage every node needs its reconnect backoff before it can be judged, so no node is offline during the first 165 seconds after start and no finding opens during the first 10 minutes.

**Installing a node is one command.** Nobody creates keys or edits files on the node. Settings › Nodes › Add node generates a one-time enrolment token, valid for one hour, and shows one command to run as root on the machine inside the network:

```
curl -fsSL https://tlswatch.example.nl/agent/v1/install/<token> | sudo sh
```

The server generates that script per token with its own URL and the token embedded, so the command is complete as shown. The screen also offers a Docker command (`docker run -d --restart unless-stopped -v tlswatch-node:/data ghcr.io/sjoerd305/tlswatch node -server … -token …`) and a manual variant (download the binary, run `tlswatch node enrol`, then `tlswatch node`) for hosts without systemd or without root. Add node is refused with a pointer to Settings › General while the public base URL is not set, because the script needs it. The screen also says which platforms the server can serve from its own binary and that any other needs the node host to reach GitHub, so an air-gapped network with a different architecture learns this before the script fails.

The script, which is embedded in the server binary and served without sign-in, does the following and nothing else, printing each step:

1. Checks that it runs as root, that `curl` or `wget` and `systemd` are present, and detects the operating system and architecture (Linux amd64, arm64 and armv7; an ARMv6 machine such as a first Raspberry Pi is refused by name, because the ARM build needs ARMv7).
2. Downloads the binary from `GET /agent/v1/download/<os>/<arch>` on the same server, with the SHA-256 the server sends alongside, and verifies it. The server serves its own executable when the platform matches its own, so a same-architecture network, including an air-gapped one, needs nothing from the internet; for another platform it redirects to the release asset of its own version on GitHub and sends that asset's checksum. Node and server are therefore always the same version at install time.
3. Creates a system user `tlswatch-node` with no shell and `/var/lib/tlswatch-node` (mode 0700, owned by it), installs the binary as `/var/lib/tlswatch-node/bin/tlswatch` owned by that user so it can update itself (see Updating nodes), links it from `/usr/local/bin/tlswatch`, and writes `/etc/tlswatch-node.env` with the server URL.
4. Runs `tlswatch node enrol`, which exchanges the token for the credential, writes it to `/var/lib/tlswatch-node/credential` (0600), and reports the system facts below. The token is now spent.
5. Installs and starts a systemd unit `tlswatch-node.service` (restart always, the system user, `ProtectSystem=strict` with the data directory as the only writable path, no new privileges) and prints "Connected to https://tlswatch.example.nl as <hostname>; finish in the UI".

Running the script again re-enrols the same machine with a new token. Removing a node from its machine is one command too: `sudo tlswatch node uninstall`, or, when the binary is gone or broken, `curl -fsSL https://tlswatch.example.nl/agent/v1/uninstall | sudo sh`, a second script served by the instance that needs no token. Both stop and disable the unit and remove the unit, the settings file, the link, the data directory with the credential and the system user, nothing else, and tell the admin to delete the node in the UI; the node's page shows both commands. The tests run both scripts with `sh` against a test server, with the system commands (`id`, `uname`, `systemctl`, `useradd`, `userdel`, `chown`) stubbed and every path under a temporary root (`TLSWATCH_INSTALL_ROOT`, which only the tests set), and check the checksum refusal, the files, their modes, the unit and the removal.

**The Add node screen watches the node arrive.** After showing the command the screen says "Waiting for the node to connect…" and polls the change stamp like the live pages. The moment the enrolment call lands, the screen swaps to the node's reported facts: hostname, operating system and version, kernel, architecture, container or not, tlswatch version, every non-loopback interface with its IPv4 and IPv6 addresses, the address the server sees the node from, whether it has an IPv6 route, and its clock offset from the server. The admin checks that this is the machine they ran the command on, enters a name (pre-filled with the hostname) and saves. Done. Until it is confirmed the node is *pending*: it polls and is shown, but no target can be assigned to it. A pending node that is not confirmed within an hour is deleted together with its credential, and "Reject" on the screen does the same at once. This confirmation is what makes a token in a URL acceptable: the token is one-time and expires in an hour, and should anyone else use it first, the admin sees the wrong hostname and addresses and rejects it, which revokes that credential.

**System facts** are reported at enrolment, at every start of the node and then once an hour (`POST /agent/v1/facts`): hostname, operating system name and version (from `/etc/os-release` or `uname`), kernel, architecture, container (yes/no), tlswatch version, interfaces with addresses, IPv6 route, and the time, from which the server computes the clock offset. The node page shows them with "reported 12 min ago". A changed hostname or address set is recorded in the audit log with the old and new values, so a node that moved or was cloned is visible. The facts are for identification and for support ("the node cannot reach 10.0.3.5 because it has no address in that subnet"); they are never sent anywhere else.

**Identity.** The credential is 32 random bytes that the server stores as a hash, as sessions are, and that the node keeps in its credential file next to nothing else; it is the node's only state. The credential is revoked by deleting the node, and disabling it stops all jobs. Rotate credential on the node page revokes the current credential at once (for a suspected leak) and shows a fresh install command; running it re-enrols the machine, which then waits for confirmation as a new node does, keeping its name and targets. Because the hash is in the database, a restored backup on the same URL keeps every node enrolled. Enrolment, confirmation, rejection, rotation, disabling and deletion are in the audit log.

**Node-side configuration** is deliberately small, as the UI-first rule asks: the node needs the server URL and the credential, and the server owns the name, the enabled state and which targets use the node. Only what the server must not be able to change stays on the node: an optional allowlist of CIDRs it may probe (an address outside it is refused like a local one), and whether loopback and link-local addresses are allowed there; such an address is probed only when both the node and Settings › General allow it. Flags or environment, read from `/etc/tlswatch-node.env` by the unit: `-server` / `TLSWATCH_NODE_SERVER`, `-data` / `TLSWATCH_NODE_DATA` (the directory of the credential file, default `/var/lib/tlswatch-node`, `/data` in the image), `-workers` / `TLSWATCH_NODE_WORKERS` (default 4), `-allow` / `TLSWATCH_NODE_ALLOW` (CIDRs, empty means any), `-allow-local`. `tlswatch node enrol -server -token` is the one-off exchange the script runs; `tlswatch node` with a token flag (or `TLSWATCH_NODE_TOKEN`) performs it itself at first start, retrying while the network comes up, for the Docker command. The image sets `TLSWATCH_CONTAINER=1`, from which the node knows it runs in a container (Docker's `/.dockerenv`, Podman's `/run/.containerenv` and Kubernetes count too) and keeps its credential in `/data`. The node honours `HTTPS_PROXY` and refuses a plain `http://` server unless `-insecure` is given, for a lab. It needs no volume beyond the credential file and runs in the same `scratch` image. It logs as the server does, JSON lines on stdout (the journal under systemd), one line per job with the target and the outcome, and never the credential. The operations guide gets a Nodes chapter: the one firewall rule, the proxy variables, the route alternative, and what to check when a node shows offline.

**Updating nodes.** Nodes update themselves from the server; nobody logs in to them. The rule is that a node converges on the server's binary: the download route serves what the server itself runs, so after a server upgrade every node follows, and after a server rollback they follow that too. Every poll carries the node's version. When it differs from the server's and the node is not in a container, the server sends an `update` job. The node finishes the probes it is running, takes no new ones, downloads the binary from `GET /agent/v1/download/<os>/<arch>`, verifies the SHA-256, writes it next to the running one, renames it into place keeping the old one as `tlswatch.prev`, writes a marker file with the old version, and starts the new binary in its own process (exec; should that fail it exits and systemd's `Restart=always` starts it), which polls and reports its new version. If the new binary has not completed a poll within five minutes of starting and the marker is present, it renames `tlswatch.prev` back and restarts; a node that comes back with its old version after an update is marked "update failed" on Settings › Nodes with the reason it reported (the old binary sends it in `X-Tlswatch-Update-Error` until a poll succeeds), or with "did not come back within five minutes" when it stays away, and is not updated again until an admin presses Update on it. The marker is removed after the first successful poll.

- **One at a time.** The server updates one node at a time, waits for it to come back with the new version (five minutes at most; a node whose download or swap fails reports why on its next poll, so the wait ends at once with that reason), then takes the next, so a bad release never takes every network down at once. Settings › Nodes shows "updating 2 of 5" while this runs.
- **Automatic by default.** Settings › Nodes has one switch, "Keep nodes on the server's version", on by default; off, the page shows "update available" per node with Update and Update all buttons, and nothing happens on its own. Per node, Update is available whenever its version differs from the server's, whatever the switch. Every update is in the audit log with the versions.
- **Containers are pulled, not patched.** A node that reports container = yes is never sent an `update` job, because a replaced binary would be lost on the next container start and the image would stay old. Its row says "update by pulling the image", with the tag matching the server's version; the Docker command on the Add node screen pins that tag so the compose or Watchtower routine the customer already has does the rest.
- **The protocol outlives the binary.** `update` is part of protocol v1 from the first release, so any node ever shipped can be brought to the current version. The server keeps the previous protocol version working for one minor release alongside the current one. A poll on a protocol the server does not speak, older or newer (the server was rolled back), is answered with a fixed reply that every node version understands: the server's version and "update". The node then updates itself over the download route as above, in either direction, so no node ever needs a reinstall for a version mismatch.
- **Only releases update automatically.** The comparison is on the version string, and automatic updates run only when the server's is a release tag (`vX.Y.Z` exactly). A development build (`2026.10.15-5efacf7`, `v0.2.0-5-g5efacf7`, anything `-dirty` or `dev`) never updates nodes on its own, so a half-finished build on a development server is not pushed into customer networks; Update on a node still works by hand and fetches whatever the server runs.

The self-update is why the binary belongs to the node's user: a compromise of that user already runs arbitrary code as that user, so a writable binary adds no privilege, and `NoNewPrivileges` in the unit keeps it there. The install script therefore puts the binary under the node's data directory and links it from `/usr/local/bin` for people and for `uninstall`.

**Data model.**

- `nodes`: id, name, state (enrolling, pending, confirmed), credential hash, install token hash, sealed copy and expiry (while unspent; the copy, sealed under the secret key, lets the Add node screen show its command again after a reload, and is unreadable on another instance), created at and by, confirmed at and by, last seen, version, protocol version, address as seen by the server (following the proxy-trust rule, as sign-in addresses do), pool size, enabled, notes, and the system facts as reported (hostname, OS, kernel, architecture, container, interfaces and addresses, IPv6 route, clock offset) with the time they were reported, and the update state (requested, started, from and to, the last failure).
- `targets.node_id`, nullable: null means probed from the server. `observations.node_id`, nullable, so history stays right when a target moves between nodes.
- `findings.target_id` becomes nullable and `findings.node_id` is added, for `node_offline`; exactly one of the two is set, and each has its own unique index on open findings.
- Deleting a node is refused while targets are assigned to it; the confirmation page lists them and offers to move them to the server. Disabling is allowed at any time and holds its targets as when offline, without a finding.

**UI.** Settings › Nodes: a table with status dot, name, hostname, last seen, version (with "update available", "updating", "update failed" or "update by pulling the image"), address, IPv6 yes/no, number of targets, with pending nodes at the top; the "Keep nodes on the server's version" switch and Update all; Add node with the command screen and the arrival screen above; a node page with the system facts, the targets assigned, the install command for re-enrolment and the uninstall command; per node edit (name, notes), rotate credential, disable, delete. The target form gains "Probe from" (This server, or a node by name) directly under the protocol. The targets list gains a node column and a filter chip per node; the target page shows the node in its configuration column and "Waiting for node" in place of the status while the node is offline. The overview shows a notice bar while a node is offline. Test without saving works through the node when one is selected, with the same timeout as a job. Findings and the overview list a `node_offline` finding under the node's name, linked to its page for admins. `/metrics` gains `tlswatch_nodes{state}` (online, offline), `tlswatch_node_last_seen_seconds{node}`, `tlswatch_node_jobs_total{node,result}` (completed, failed), and the scheduler's `tlswatch_scheduler_node_checks` and `tlswatch_scheduler_held`.

**Backup and restore.** The nodes table is in the backup with the credential hashes, so a restore keeps every node enrolled as long as the instance keeps its base URL; on a new URL the nodes must be re-enrolled with a fresh install command. During a restore the node dispatcher pauses with the scheduler: pending polls are answered empty, leased jobs are dropped and their results discarded, and the queues are rebuilt with the schedule afterwards.

**Security.** Only hostnames and certificate chains leave the customer network; the node performs one handshake and the STARTTLS preamble, reads no application data and returns nothing else. The node is told what to probe by the server, so a compromised server could aim it at internal addresses; the allowlist and the local-address rule on the node bound that, and every target assignment is in the audit log. The agent endpoints accept the bearer credential only, never a session cookie, and are rate limited. TLS to the server is required. The node credential is never logged and never shown back. The enrolment token travels in the install URL and lands in shell history and proxy logs; it is one-time, expires in an hour, and a node enrolled with it is useless until an admin confirms the reported hostname and addresses, so a stolen token yields a pending node that is rejected. The install and uninstall scripts and the binary download are the only unauthenticated routes besides sign-in and `/healthz`; the download serves the server's own executable, which is public code, the install script is a fixed template with the URL and token filled in and is served only for an unspent token, and the uninstall script carries only the URL. Failed enrolments and rejected credentials count against the address like failed sign-ins: 20 in 15 minutes block it. The script is run as root by the customer, so it is short, does nothing outside the paths it names, and is readable before running (`curl … | less`).

**Not in this design**: several nodes per target (probing one host from inside and outside, which would make split-horizon differences an `inconsistent` finding), node-side scheduling or buffering during a server outage, and streaming from the node to the UI. The command envelope and the transport interface leave room for all three.

## Checks, findings and severity

Every observation runs the full set of checks (the test for legacy TLS versions once a day, see below); each failed check is a finding of one kind with one severity. Three severities: `info` (shown, never alerted by default), `warning`, `critical`.

| Kind | Opens when | Severity | Notes |
| --- | --- | --- | --- |
| `expiring` | The earliest NotAfter in the presented chain is within the warning or critical threshold | warning / critical | Counts whole days; escalates from warning to critical as the date nears |
| `expired` | Any certificate in the presented chain has expired | critical | |
| `chain_untrusted` | The chain does not verify against the trust mode (system store or bundle) | critical | Missing intermediate, unknown root, broken signature, a certificate not valid for server authentication (for example client-only); not raised for `self-signed` targets |
| `self_signed` | A self-signed leaf on a target whose trust mode is not `self-signed` | critical | The fix is either the server or switching the target to `self-signed` |
| `hostname_mismatch` | The servername is not covered by the CN/SANs | critical | Skipped when servername is empty (plain IP target) |
| `weak_signature` | A chain certificate is signed with SHA-1 or MD5, or has an RSA key under 2048 bits | warning | Expiry is still reported |
| `legacy_protocol` | An address completes a handshake at TLS 1.0 or TLS 1.1 (deprecated by RFC 8996) | warning | Tested daily, not on every check; see legacy TLS versions below. The details name the versions, and the addresses when not all of them accept them |
| `weak_configuration` | An address accepts a cipher suite class the grade counts as weak: RC4, 3DES, or key exchange without forward secrecy (see TLS configuration grade) | warning | Tested daily with the legacy versions. The details name the classes and the suites that were accepted, and the addresses when not all of them accept them. Versions are `legacy_protocol`'s business and are not repeated here |
| `certificate_changed` | The leaf fingerprint differs from the previous observation | info or warning | See change detection below |
| `issuer_changed` | The issuer differs from the previous certificate or from the configured expected issuer | warning | A Let's Encrypt name suddenly served by another CA is worth a look |
| `inconsistent` | Different addresses of one name serve different certificates | warning | One server behind a load balancer not updated |
| `tls_unavailable` | A STARTTLS server did not offer STARTTLS | critical | |
| `unreachable` | Connect or handshake failed after retries, on all addresses | critical | Debounced: needs 2 consecutive failing checks to open and 2 passing to close. The target's status shows Unreachable from the first failing check; only the finding and its alert wait. A protocol that does not fit a well-known port (implicit TLS on 587, STARTTLS on 465) adds a hint to the error |
| `dns_failed` | The name did not resolve | critical | Debounced like `unreachable` |
| `node_offline` | A node has not polled for 10 minutes (see Nodes) | warning / critical | Opened on the node, not on a target; critical once a target under it is overdue by more than its interval. Its targets show "Waiting for node" and open nothing themselves |
| `unexpected_certificate` | A certificate for a watched domain was published in a Certificate Transparency log and no target serves it (see Certificate Transparency watching) | warning | Opened on the domain watch, one per issuance. Resolves when a target serves the certificate or when acknowledged |
| `ct_source_failed` | The Certificate Transparency source has answered no poll for a domain watch for 24 hours | warning | Opened on the domain watch; resolves on the next successful poll |

**Change detection.** A new leaf certificate is normal on an ACME-managed endpoint and suspicious on a manually managed one. A target carries the flag *renewal managed* (default on when the issuer is a known ACME CA such as Let's Encrypt, ZeroSSL or Google Trust Services, off otherwise; always editable).

- Renewal managed: a new certificate with the same issuer organisation and the same or a superset of SANs is recorded as `info` and not alerted. Any other change is a warning.
- Not renewal managed: any new leaf is a `warning` finding, so an operator confirms the replacement was intended. Acknowledging it resolves the finding.
- `self-signed` targets: pinned fingerprint; any change is a warning.

A `certificate_changed` or `issuer_changed` warning (without an expected issuer) stays open until acknowledged or until an automatic renewal (the `info` case above) confirms the certificate is back on its normal cycle; that renewal resolves it without an acknowledgement. Any other new leaf leaves it open: a new `certificate_changed` warning replaces the old one's details, and an open `issuer_changed` stays as it is, so whoever acknowledges the new certificate still sees that the issuer moved.

**Legacy TLS versions.** The normal probe offers every version from TLS 1.0 to 1.3, so the server picks its highest and a server on TLS 1.3 says nothing about whether it would still accept TLS 1.0. To find out, each address that answered gets one more handshake per legacy version, TLS 1.0 and TLS 1.1, with the client pinned to exactly that version. The negotiated version settles some without a handshake: a server that negotiated TLS 1.0 accepts it and cannot accept 1.1. A completed handshake means accepted; a refused one (an alert or a closed connection) means refused; a connect failure, a STARTTLS failure or a timeout gives no verdict for that address.

- The test runs on the first check of a target and then on the first check at least 23 hours after the last test that reached a verdict, so about once a day whatever the interval. Check now and Test without saving always run it. Changing the target's host, port, protocol or server name, or switching the test off and on, forgets the last test so the next check runs it. The cipher suite handshakes of the configuration grade below run in the same test, on the same schedule, under the same switch.
- Between tests `legacy_protocol` keeps its state; a test that finds both versions refused on every answering address resolves it. A test where some address got no verdict and none accepted leaves the finding as it is and is repeated on the next check.
- TLS 1.2 next to 1.3 is normal and not reported. SSL 3.0 is not tested: Go has no client for it. A server that offers TLS 1.0 only with cipher suites Go does not implement (DHE key exchange, for example) shows as refused.
- Per target the test can be switched off ("Configuration test: Do not test" under Probe and reminder settings), for an appliance where the old versions and ciphers are known and cannot be changed. Switching it off resolves an open `legacy_protocol` and `weak_configuration` at the next check and leaves the target without a grade.
- The target page shows the result below the per-address table of the last check ("TLS 1.0 and 1.1 · refused · tested 3 h ago", or the versions accepted); the configuration column shows whether the test runs.

**TLS configuration grade.** The legacy test says whether old versions are still accepted; the grade says the same about the cipher suites and the key, and sums both up in one letter, A to F, per address and per target, so a list of a hundred targets can be sorted by how well they are configured. The grade is about the server's configuration only. Certificate validity (expiry, trust, hostname) has its own findings and does not enter the grade, so an expired certificate on a well-configured server is an A with a critical finding, not an F twice.

*What is tested.* The normal probe records the negotiated version and suite, which only shows the server's preference. In the daily test, after the two legacy handshakes, each answering address gets up to four more handshakes pinned to TLS 1.2, each offering one class of suites and nothing else, so a completed handshake proves the class is accepted:

| Class | Suites offered | Why it matters |
| --- | --- | --- |
| RC4 | `TLS_RSA_WITH_RC4_128_SHA`, `TLS_ECDHE_RSA_WITH_RC4_128_SHA`, `TLS_ECDHE_ECDSA_WITH_RC4_128_SHA` | Broken cipher, prohibited by RFC 7465 |
| 3DES | `TLS_RSA_WITH_3DES_EDE_CBC_SHA`, `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA` | 64-bit blocks (Sweet32) |
| No forward secrecy | The `TLS_RSA_WITH_*` suites with AES: key exchange by RSA encryption | A leaked key decrypts recorded traffic |
| CBC with SHA-1 | The `TLS_ECDHE_*_WITH_AES_*_CBC_SHA` suites | Not AEAD; padding-oracle history. Common and not weak on its own, so it costs one step, not two |

A refused handshake (an alert or a closed connection) means the class is not accepted; a connect failure, a STARTTLS failure or a timeout gives no verdict for that address and the test is repeated on the next check, as for the legacy versions. A server that negotiates only TLS 1.3 refuses every pinned 1.2 handshake and is graded on that. Go's client offers no export, NULL, anonymous or DES suites, so those cannot be detected; the Go-specific suites a server accepts beyond the classes above are not a reason for a lower grade. Six handshakes per address per day is the cost, and a target with the test switched off pays none.

*The rules.* Each address starts at A and takes the lowest grade any rule gives it; the target's grade is the lowest of its addresses. Every rule that fires is a reason, and the reasons are stored and shown with the grade, so "B" is never shown without "accepts TLS_RSA_WITH_AES_128_GCM_SHA256 (no forward secrecy)" next to it.

| Grade | A rule that gives it |
| --- | --- |
| F | Accepts RC4. An RSA or DSA key under 1024 bits anywhere in the chain. The highest version the server negotiates is TLS 1.0 or 1.1 |
| C | Accepts TLS 1.0 or 1.1 next to a newer version (the `legacy_protocol` case). Accepts 3DES. An RSA key under 2048 bits or an EC key under 256 bits. A SHA-1 or MD5 signature in the chain (the `weak_signature` case) |
| B | Accepts a suite without forward secrecy. Accepts a CBC suite with SHA-1. The highest version is TLS 1.2 and no TLS 1.3 is offered |
| A | None of the above: TLS 1.2 or 1.3 only, every accepted suite forward secret, AES or ChaCha20 (CBC-SHA1 refused), keys of 2048 or 256 bits and more, SHA-2 signatures |

There is no A+ and no D: four grades are enough to sort a list and to argue with a vendor, and finer steps invite disputes about scoring instead of fixes. The rules are a table in the code with the version of the rules stored next to every grade, so a later tightening (TLS 1.2 without 1.3 moving to C, say) re-grades on the next test and the history shows which rules a grade was given under.

*Findings.* One finding per cause, so that nothing is reported twice: `legacy_protocol` for the versions, `weak_signature` for the signature and the key size, and the new `weak_configuration` (warning) for the suite classes RC4, 3DES and no forward secrecy. CBC with SHA-1 and a missing TLS 1.3 lower the grade to B but open no finding: they are worth seeing in a list, not worth an alert. `weak_configuration` keeps its state between tests like `legacy_protocol`, resolves when a test finds every weak class refused on every answering address, and is left as it is by a test without a full verdict. A grade that changes between two tests is recorded as an `info` event (`grade_changed`, "grade B → C: accepts 3DES"), shown under recent changes on the overview and among the target's findings, without an alert of its own; the finding that caused a drop alerts. The drops of the week are listed in the digest.

*Where it shows.* The targets list gets a grade column (a letter badge, sortable; the first column to drop on narrow windows after TLS and last check) and a grade chip group in the filter bar. The target page shows the grade next to the countdown with its reasons as a list, per address when the addresses differ, and the configuration test result below the per-address table. Test without saving and `tlswatch check` report the grade and the reasons per address (`grade`, `grade_reasons`, and `weak_suites_accepted` next to `legacy_accepted`); `check` exits 1 for grade C and below unless `-no-config-test` is given, which also skips the legacy test (`-no-legacy` stays as an alias). The Prometheus endpoint exports `tlswatch_targets_by_grade` (enabled targets per grade) and `tlswatch_target_grade` per target with the grade as a label and its rank as the value (4 for A down to 1 for F). The weekly digest lists targets whose grade dropped during the week. A node runs the same handshakes: the probe request carries the test flags, and the node reports what was accepted; the grade itself is computed on the server, so a rule change needs no node update.

Fact findings (`expired`, `chain_untrusted`, `hostname_mismatch`, `weak_signature`, `legacy_protocol`, `weak_configuration`, `expiring`) are raised on the first observation that shows them: there is no network noise in a certificate that is read successfully, nor in a handshake that completed. Only the network-shaped findings are debounced.

The negotiated TLS version and cipher suite, the key type and size, and the full chain are stored with every observation and shown in the UI; the daily configuration test adds what else the server would accept, and the grade sums it up.

## Certificate Transparency watching

Every publicly trusted certificate is published in Certificate Transparency logs before browsers accept it (RFC 6962; Chrome and Safari require it). That makes the logs the one place where a certificate for your domain shows up even when it was issued to the wrong person, by a CA you never used, or for a name you forgot existed. A target watches what a server serves; a domain watch watches what the world issues for a name, and tlswatch reports the difference: an issuance that no target serves.

**Domain watches.** A domain watch is a registrable name (`example.nl`) with "include subdomains" on by default, so one watch covers `portal.example.nl`, `*.example.nl` and everything below. Watches have tags, notes, channels and an enabled flag like targets, and are created, edited and deleted by operators under **Domains** in the navigation. There is no automatic creation from targets: an operator decides which domains are theirs, because a target on `portal.customer.example` does not make the customer's domain yours to watch.

**Source.** tlswatch does not tail the logs itself: the logs hold billions of entries and following them is a service, not a feature of a one-binary monitor. It asks an index of the logs for the issuances of one domain since the last poll. Two sources are supported, chosen once under Settings › Certificate Transparency: **Cert Spotter** (api.certspotter.com, the default; works without a key within its public rate limit, an optional API key raises it; the entries come with the certificate itself, so issuer and serial are read from it) and **crt.sh** (no key, no cursor, slower and rate limited by goodwill; the apex and `%.domain` are two queries, and the highest entry id seen is kept as the cursor). The source is a small interface (`Issuances(domain, cursor) ([]Issuance, cursor, error)`) with one implementation per service, so a third can be added, including a self-hosted index for an installation that must not talk to either. The settings page says in plain words what leaves the server: the watched domain names and nothing else, over HTTPS, to the chosen service. Polling goes from the server, never from a node, since the logs are public and the server already reaches the internet.

**Polling.** Every enabled watch is polled once an hour (interval configurable from 15 minutes to 24 hours, global; the housekeeping loop looks every minute for watches that are due), spread with jitter like checks, through the same outbound rules as the channels (a named connection, no credentials in the URL, the API key in a header). Adding a watch polls it at once, and Poll now on its page polls it by hand. A source answer is a list of issuances newer than the cursor, each with issuer, serial, names, validity and the log entry; the cursor is stored with the watch so a restart continues where it stopped. The first poll of a new watch takes the issuances of the last 90 days and records them without findings, so a new watch does not open one finding per existing certificate; an operator sees them on the domain page and can mark one unexpected by hand. Watches are polled one at a time, two seconds apart, and spread over the interval by a per-watch jitter, so a run over many watches never lands on the source as a burst. A poll that fails (crt.sh answers 502 when it is busy) is retried after 15 minutes, or after what a source answering 429 asked for; after 24 hours of failures `ct_source_failed` opens on the watch. A free source is shared with every other tlswatch installation, so the default interval is an hour, not a minute, and a watch that is disabled is not polled.

**Matching.** Logs publish precertificates, which differ from the certificate the server will serve only by the poison and SCT extensions, so a fingerprint match is not possible; an issuance is matched to a served certificate by issuer CN and serial number, which are the same in both, and the match is stored. Matching happens at every poll, in the hourly sweep, and the moment a check stores a certificate the target did not serve before. An issuance is in one of four states:

| State | Meaning | How it gets there |
| --- | --- | --- |
| `known` | A target serves this certificate | Matched by issuer and serial to a certificate in the inventory, at the poll or when a later check lands; the first poll's backlog starts here too |
| `pending` | Probably a renewal on its way to a target | Every name in it is covered by an enabled target (a wildcard covers the names under it), and the issuer is the issuer that target serves today. Held for 48 hours, the time an ACME client needs at most to deploy what it just obtained |
| `unexpected` | No target serves it and nothing says one will | A name no target covers, an issuer no covered target serves, or a pending issuance still unserved after 48 hours. Opens `unexpected_certificate` (warning) on the watch with the names, the issuer, the date and a link to the log entry |
| `acknowledged` | An operator looked and it is fine | Acknowledging the finding, which resolves it; the issuance keeps the acknowledgement and the comment ("staging cert, Alex, 16 Oct") |

A `pending` issuance that a target serves within the hold becomes `known` and is recorded as an `info` event (`certificate_issued`) under recent changes, so an ordinary Let's Encrypt renewal shows up once, as a line, and never as an alert. An `unexpected` issuance that a target serves later resolves its finding with a recovery notice, as any finding does: the certificate turned out to be yours after all, deployed late. An issuance whose certificate has expired is closed silently, whatever its state. Names in an issuance that do not belong to the watched domain (a certificate for `example.nl` and `example.com` together) are shown but not judged.

**What it catches**, in the words of the alert: "a certificate for `admin.example.nl` was issued by Sectigo on 14 Oct and no target serves it", which is a forgotten host, a colleague's experiment, a hosting provider's automatic certificate, or an attacker with a validation foothold; and "a certificate for `portal.example.nl` was issued by Google Trust Services, while the target serves Let's Encrypt", which is a CA change nobody announced. Both are things an inventory of served certificates cannot see.

**Where it shows.** The Domains page lists the watches with status, name, issuances in the last 30 days, open findings and last poll; the domain page lists the issuances newest first with state, names, issuer, validity and the matched target when there is one, filterable by state. Issuances are not inventory entries: the Certificates page stays the inventory of what is served, and an issuance appears there only once a target serves it. The overview counts open `unexpected_certificate` findings in its tiles like any warning, and the Findings page shows them with the domain in the target column. The weekly digest gets a section "Issued for your domains this week" with the known and the unexpected ones. Issuances follow the retention of observations, except that an issuance with an open finding is kept while the finding is open. Prometheus exports `tlswatch_ct_issuances_total` by state and `tlswatch_ct_last_poll_timestamp_seconds` per enabled watch. The navigation shows the number of watches next to Domains. Domain watches are in the backup and in the audit log like targets.

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
| Configuration test (TLS 1.0/1.1 and cipher suites) | daily | daily | daily / off |
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
6. **Digest**: an optional weekly e-mail (day and hour configurable) listing open findings, certificates expiring in the next 30 days, targets that failed their last check, targets whose grade dropped, and the certificates issued for watched domains that week. Off by default. `info` findings (expected ACME renewals) are recorded as already resolved and are not in it: they show under recent changes on the overview and nowhere else.

**Channels** are configured globally by an admin; each target selects which of them apply (default: all). A channel has a minimum severity: a Telegram chat can take only `critical` while the mailbox takes everything.

| Channel | Transport | Settings |
| --- | --- | --- |
| SMTP | Go standard library over STARTTLS or implicit TLS, with optional PLAIN/LOGIN auth | host, port, user, password, from, recipients, minimum severity |
| Telegram | HTTPS call to `api.telegram.org/bot<token>/sendMessage`, no library | bot token, chat IDs, minimum severity |
| Slack | JSON `{"text"}` POST to an incoming webhook; `&`, `<`, `>` escaped. Mattermost and Rocket.Chat incoming webhooks take the same message | webhook URL (the credential), minimum severity |
| Discord | JSON `{"content"}` POST to a channel webhook with `wait=true`, so Discord returns the message ID; messages cut at 2000 characters | webhook URL (the credential), minimum severity |
| ntfy | JSON POST to the server root: topic, title (the subject without its tag), message (cut at 4000 characters), priority 5/4/3 for critical/warning/other, one tag per severity; optional bearer token | server (default `https://ntfy.sh`), topic, access token, minimum severity |
| Webhook | JSON POST `{source, ref, severity, subject, text, sent_at}` with `X-TLSWatch-Ref` and `X-TLSWatch-Severity` headers; with a secret, `X-TLSWatch-Signature: sha256=<hex HMAC-SHA256 of the body>` | URL, signing secret, minimum severity |

Every HTTP transport treats a 429, or a 503 with Retry-After, as a request to wait: the retry is postponed by at least the time asked. Other non-2xx statuses are failures retried with the normal backoff. Errors never contain the credential, also when the URL itself is the credential: connection errors are reported without the URL, and the URL and its path are redacted from any other text. URLs must be `http://` or `https://` without embedded credentials; an admin chooses them, and there is no other restriction on the host, since self-hosted services on private names are the common case.

One message per finding; a run that opens many findings at once (a new bundle of targets, an outage) is collapsed into one message per channel listing them, capped at 50 lines.

**Message content**: target name and `host:port`, finding kind and severity, days left and the expiry date, issuer and subject CN, fingerprint (short), the address that failed, and a link to the target in the UI. A finding on a domain watch names the domain, the issued names, the issuer, the issue date and the log entry instead, with a link to the domain page. Mail is `multipart/alternative`: a plain-text part and an HTML part styled like the UI (the dark top bar with the shield mark and the wordmark, a white card, a status pill, a large countdown for expiry, uppercase labels with mono identifiers, an "Open in tlswatch" button; dark tokens for clients that support `prefers-color-scheme`; inline styles, system fonts). The shield mark of the UI and favicon is a PNG carried in the mail itself (`multipart/related`, referenced by Content-ID), because most mail clients do not show inline SVG and many block remote images. Batches, the weekly digest (stat tiles and three lists) and the channel test message use the same layout. Telegram, Slack and Discord messages are plain text with the same fields on separate lines, the subject first; ntfy gets the subject as the title and the fields as the message; a webhook gets the subject and the plain text in its JSON document. The subject line starts with the severity in brackets so mail rules can route it: `[critical] portal.example.nl:443 expires in 6 days`.

**Delivery** is queued in SQLite and retried with backoff (1 min, 5 min, 30 min, then hourly for 24 hours), or later when the transport asks for it (a Telegram rate limit, a 429 from a webhook); after 24 hours the alert is marked failed and logged as given up. A channel that is down does not block another. A Telegram channel with several chats tries every chat; a retry goes only to the chats that did not get the message yet. A test button per channel sends a sample message. Every delivery and its result is kept in the alert log for 180 days.

## Inventory and user interface

The UI is an operations console: the home screen answers "what needs attention now" before anything else, lists are dense and sorted by expiry, and colour means status only. All text in English. Navigation: **Overview**, **Targets**, **Domains**, **Certificates**, **Findings**, **Settings** (admin only), with live counts, plus the account menu. The design canvas in `design/` is the reference for every screen below.

**Grouping** is by free-form tags (`customer:contoso`, `site:amsterdam`, `sip`), shown as badges, filterable, and usable as a column to group the targets list. Tags are enough for 10 to 100 targets and scale by convention; a fixed group hierarchy is deliberately left out. Every target has a notes field for owner, ticket number or renewal procedure.

| Screen | Role | Content |
| --- | --- | --- |
| Sign in | all | One card: e-mail and password, "Sign in with Google" below. Neutral error messages. |
| Overview | viewer+ | Four status tiles (critical, warning, healthy, unreachable), "Expiring next" with every enabled target that serves a certificate, soonest first, and a lifetime bar per certificate (ten shown, the rest behind "Show all"; the unfolded state is in the URL as `?all=1`, so it works without JavaScript and survives the live refresh), open findings (each opens its finding), recent changes, and the last run's summary (targets and addresses probed, failures, alerts sent). |
| Targets | viewer+ | Dense table: status, name, `host:port`, days left, lifetime bar, expiry date, issuer, TLS version, grade, tags, last check. Filter field plus chips for status, grade, tag and node with counts, all chips flowing on one wrapping line so a long group fills the line rather than dropping whole to the next; a row's tags stay on one line, up to three, or the first two and a "+N" tag listing the rest on hover; a tag in a row filters on that tag; on narrower windows columns drop out in a fixed order (TLS and last check below 1520px, grade below 1450, lifetime below 1380, expiry date below 1240, issuer below 1140, node below 960, tags below 890) so rows stay on one line without a sideways scrollbar; grouping by tag. Sorted by expiry by default; every column head sorts the list (a second click reverses it), and the order is part of the URL (`?sort=name&dir=desc`), so a reload, a shared link and the live refresh keep it, with or without JavaScript. Per row: Check, or Enable for a disabled target (operator+). Bulk edit (operator+): a checkbox per row and "select all shown"; a bar with the count leads to the bulk edit form for the selection. Page-head buttons: Add target, Add many and Check all (operator+). |
| Target detail | viewer+ | Leads with the certificate: countdown with the grade badge and its reasons next to it, lifetime bar, subject, issuer, SANs, key, serial, fingerprint with copy/PEM. Then the chain as a vertical stack with the weak link marked, per-address results of the last check with the result of the configuration test below them (versions and suite classes accepted, grade per address when they differ), history of certificates seen on the target and of grade changes. Side column: configuration, findings on this target (with a link to all of them on the Findings page), alerts sent. Buttons: Check now, Edit, Disable or Enable, Delete (operator+). Delete goes to a confirmation page that shows what is removed and offers Disable instead. |
| Target form | operator+ | Fields in order: host, port, protocol, name, servername; trust mode (system / bundle / self-signed) and bundle, renewal managed, expected issuer; thresholds, interval, addresses; under "Probe and reminder settings" timeout, retries, debounce, the configuration test (test daily / do not test) and reminders; tags, channels, notes. The port follows the protocol while it is empty or still the previous protocol's default. "Test without saving" runs a probe and shows the result in a side panel. |
| Add many (bulk add) | operator+ | One form for several endpoints: a text area with one host per line (a host, `host:port` or a URL, followed by an optional name; `#` lines are skipped; a port left out is the protocol's default, the name defaults to the host and the server name follows a DNS host), then the settings they share: protocol, node, trust, renewal, expected issuer, thresholds, interval, addresses, probe and reminder settings, tags, channels and notes. Nothing is saved while any line or field has a problem; line problems are listed under the text area by line number, and a line that repeats another is refused. An endpoint that already exists is skipped and counted in the notice. Each target is audited as `target.create` with `bulk=true` and checked right away. |
| Edit many (bulk edit) | operator+ | Opened from the selection bar on the targets list, with the selection in the URL (`/targets/bulk-edit?id=…`). The selected targets are listed as tags. Checks (leave / enable / disable) and tags to add and to remove are always offered; every other setting has a "change" box and is written only when it is ticked: node, trust mode and bundle, renewal, expected issuer, addresses, warning and critical days, interval, timeout, retries and debounce, the configuration test, reminders, channels and notes. An empty value in a ticked field means the default (thresholds, interval, probe settings, reminders) or none (expected issuer, notes). The values are validated against every selected target and nothing is saved while one fails; the message names the target. Disabling closes findings as the single Disable does; a new trust mode or node queues a check. Each target is audited as `target.update` with `bulk=true changed=…`. The bar and the boxes work without JavaScript. |
| Domains | viewer+ | Domain watches: status, name, subdomains included, issuances in the last 30 days, open findings, tags, last poll. Filter field and chips for status and tag. Add domain, Edit, Disable or Enable, Delete (operator+, delete after a confirmation that shows the issuances and findings removed). Page-head note when no source is configured or the last poll failed. |
| Domain detail | viewer+ | The watch's settings in a side column; the issuances newest first: state badge (known, pending, unexpected, acknowledged), names, issuer, not before and not after, the matched target or "not served", a link to the log entry. Chips by state; "Mark unexpected" on a known or backlog issuance and "Acknowledge" on an unexpected one (operator+). Findings on this watch and alerts sent, as on a target. Poll now (operator+). |
| Certificates | viewer+ | The inventory: one row per unique certificate: subject, issuer, days left, lifetime bar, not after, key, number of targets serving it, short fingerprint, first seen. Filter field and chips for expiry window, issuer, key type (above eight issuers the chips become a select); a switch to include or hide certificates no longer served. Every column sorts, as on the targets page. Row expands to full fingerprint, SANs, chain and the targets and addresses where it is served. Export as CSV. |
| Findings | viewer+ | Open findings first, sorted by severity then days left; each row: severity, kind with detail, target, since, last alert, acknowledgement. The acknowledge form (until-date, comment) and the alert timeline open in a side panel (operator+), closed with × or Escape. Filter field (target, host, finding), a target filter linked from the target page, and chips for open/resolved, severity and kind. Every column sorts, as on the targets page, and the list can be grouped by kind. Bulk acknowledgement (operator+): a checkbox per open finding and "select all shown"; a bar with one until-date and comment acknowledges the selection. Certificate changes in it are confirmed and resolved, as when acknowledged one by one. |
| Settings: General | admin | Public base URL, time zone, proxy trust, local targets; values set by environment shown read-only. |
| Settings: Channels | admin | Channels of every kind with severity floor, destination, last delivery, Test button; "Add SMTP", "Add Telegram" and a "More types" menu for Slack, Discord, ntfy and Webhook. Edit form below the table: SMTP host, port (following the encryption), encryption, username, password, from, recipients; Telegram bot token and chat IDs; Slack or Discord webhook URL; ntfy server, topic and access token; webhook URL and signing secret. Credentials, including webhook URLs that grant posting rights, are never shown back; left empty they keep the stored value. The destination column shows the host only for Slack and Discord, and the URL without its query for a webhook. Deleting a channel asks first. |
| Settings: Sign-in | admin | Google client ID, client secret, Workspace domain, redirect URI to register. |
| Settings: Certificate Transparency | admin | Source (Cert Spotter or crt.sh), API key (never shown back), poll interval, and the sentence that says what is sent where. "Test" polls one watched domain and shows the answer. |
| Settings: Nodes | admin | Nodes with status dot, name, hostname, last seen, version and update note, address, IPv6, target count. Add node shows one install command (and Docker and manual variants), waits for the node to connect, then shows the machine's facts (hostname, OS, addresses, version, clock offset) for the admin to confirm and name. "Keep nodes on the server's version" switch (default on) and Update all; nodes update themselves one at a time, containers are pulled instead. Node page with the facts, assigned targets, the re-enrol command after a rotation and the two uninstall commands. Per node: edit name and notes, Update, rotate credential, disable, delete (refused while targets are assigned; the confirmation page lists them and offers to move them to the server). See Nodes. |
| Settings: CA bundles | admin | Upload PEM, list of the certificates inside with validity; replace a bundle; delete one no target uses, after a confirmation. |
| Settings: Defaults | admin | The global thresholds table, digest schedule and channels, "Send digest now", probe concurrency, retention. |
| Settings: Users | admin | Table: name, e-mail, login method, role, status (active, disabled, or locked until a time after failed sign-ins), last sign-in. Add or invite a user: with an SMTP channel by an e-mailed one-time link, without one by a password the admin sets (or a link to pass on). Edit, new password link (or, without SMTP, set a new password), unlock, disable, delete. |
| Settings: Audit log | admin | Who changed what, filterable, export CSV. Domain watches and acknowledgements of issuances are in it like targets and findings. |
| Settings: Backup | admin | Download a backup of the whole instance, encrypted with a passphrase (12 characters or more, entered twice). Restore one: passphrase, a confirmation checkbox, the file. A plain database copy from the `backup` subcommand restores too, without a passphrase. |
| Account | all | Name, theme (system, light, dark; also switchable from the account menu on every page), change password for local accounts. |

**Interaction.** A row in a list is clickable as a whole and follows its primary link (the target, the finding, the certificate, the user or channel to edit). Cmd/Ctrl-click or a middle click opens it in a new tab, and selecting text in a row does not navigate. Every row still holds a real link, so keyboard and no-JavaScript use are unchanged. "/" focuses the page's filter field. Past expiry is shown as "expired", not as negative days. Deleting a target, channel, bundle or user asks for confirmation; disabling does not, because it is reversible. A form disables its buttons while it is being sent, so a slow action (a channel test, a save) is not sent twice.

**Live pages.** Overview, Targets, a target's page, Certificates and Findings keep themselves current. They poll a small change stamp (`/api/v1/stamp`): every 4 seconds while checks are queued or running, a target has never been checked, or a node is enrolling or waiting for confirmation (so the Add node screen shows the machine within seconds of its enrolment), otherwise every minute, and not at all while the browser tab is hidden. When the stamp changes, a fresh render of the same URL is swapped in. The filter, the expanded certificate and the selected finding are part of the URL and survive. A refresh is skipped while the user is typing, has text selected, has unsaved input or ticked checkboxes, or has a menu open. These background requests do not count as activity for the session idle timeout.

The healthy state is the common one and must read as good news: "14 targets, nothing due within 30 days, last run 04:17". Empty states say what to do next ("No targets yet — add one or run `tlswatch check host`"). Below 760 px tables fall back to cards: the main lists (targets, expiring next, certificates, findings) to compact ones of a few cells (status, name, host, days left), the settings tables to one labelled line per column. The reminder to set the public URL is shown on the overview only. Status colours are used identically everywhere: green healthy, amber warning, red critical and expired, grey disabled or unreachable, blue only for informational changes.

## Users, authentication and authorisation

Three roles, one per user, no organisations or tenants: the tool is single-tenant by design.

| Action | Viewer | Operator | Admin |
| --- | --- | --- | --- |
| View targets, certificates, findings, history | yes | yes | yes |
| Add, edit, disable, delete targets; check now | | yes | yes |
| Acknowledge findings, one by one or in bulk | | yes | yes |
| Settings: general, sign-in, channels, CA bundles, defaults, digest | | | yes |
| Users and roles: add or invite, edit, set a password (without SMTP), unlock, disable, delete | | | yes |
| Audit log | | | yes |

**Local login**: e-mail and password. An admin creates the account. When an enabled SMTP channel exists, the user receives a one-time link (7 days valid) by e-mail and chooses their own password; the link is also shown to the admin in case the mail does not arrive. Without an SMTP channel, the admin sets the first password in the form (or creates a one-time link to pass on), and can later set a new one for a local user; that also ends the user's sessions and clears a lockout. With SMTP, admins cannot set passwords: they send a new link instead. Users change their own password under Account. Every password is at least 12 characters, checked against a local list of leaked passwords. Password hashes use Argon2id. Five failed attempts block the account for 15 minutes, except from the address it last signed in from, so failures from elsewhere cannot keep its owner out (the per-address limit of 20 failures in 15 minutes still applies there); the error message does not reveal whether the e-mail exists, and an address without an account locks the same way. Admins see a locked account in the user list and can unlock it; setting a new password through a one-time link also clears the lock.

**Google sign-in**: OpenID Connect with Authorization Code and PKCE, implemented against the standard library plus `golang.org/x/oauth2`. Sign-in is only possible for an e-mail address an admin has already added (allowlist); there is no self-registration. Optionally restricted to one Workspace domain. The login method is per user: a Google user has no password.

**Removing users.** Disabling a user ends their sessions and keeps the account for later; deleting removes the account with its sessions and one-time links for good. The audit log keeps their entries, which record the e-mail address. Nobody can delete their own account, and the last enabled admin can be neither deleted, disabled nor demoted.

**TOTP** as second factor for local accounts is a later version (see Later versions); the tool holds no secrets beyond its own channel credentials.

**Sessions**: server-side session store in SQLite, cookie `HttpOnly; Secure; SameSite=Lax`, 8 hours idle timeout (the live-page polling does not count as activity, so an open tab does not keep a session alive) and a 7-day maximum age after sign-in, CSRF token on every state-changing form and JSON call. While no account exists, every page redirects to a setup screen where the first admin is created with their own e-mail address and password and signed in directly; the screen disappears once an account exists. The setup screen also restores a backup (see Backup and restore), so a new installation takes over from an old one without a throwaway admin; that too is refused once an account exists, checked on the writer connection in the same step as the restore. The check and the insert are one transaction, so concurrent attempts create one admin only. Scripted installs can use the `create-admin` subcommand, which prints a one-time password link.

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
| `internal/probe` | TLS and STARTTLS dialers, chain capture, verification against system store or bundle, the pinned handshakes of the configuration test (legacy versions and suite classes); no database access, so the node reuses it unchanged |
| `internal/node` | The agent protocol: job and result messages, the server-side dispatcher and `/agent/v1` handlers, and the node client loop run by `tlswatch node`; transport behind an interface |
| `internal/check` | Turns an observation into findings: thresholds, change detection, debounce; the grade rules as a versioned table |
| `internal/ct` | Certificate Transparency: the source interface with the Cert Spotter and crt.sh clients, the hourly poller, issuance matching by issuer and serial, and the pending hold |
| `internal/core` | Domain: targets, certificates, findings, acknowledgements, state transitions |
| `internal/sched` | Scheduler: per-target next-run with jitter, worker pool, Check now queue |
| `internal/notify` | Channels, message rendering, outbox with retry |
| `internal/auth`, `internal/authz` | Passwords, sessions, OIDC; the role × action decision |
| `internal/db` | SQLite access and embedded migrations, run at start; online backup and in-place restore |
| `internal/backup` | The encrypted backup file of the UI: writing it, and checking, migrating and re-sealing an upload before it is restored |
| `internal/web` | HTTP handlers, pages, the internal JSON API under `/api/v1` used by the TypeScript (check, check all, test probe, finding panel, change stamp) |
| `web/` | templates, `static/css`, self-hosted fonts, `ts/` sources compiled to `static/js` |

**Database**: SQLite in WAL mode through `modernc.org/sqlite` (pure Go, so the binary is static and cross-compiles without cgo). One writer goroutine serialises writes; reads are concurrent. Certificates are stored once by fingerprint with the PEM; observations reference them. Expected size at 100 targets with daily checks and 180 days retention: under 50 MB.

**Backup and restore**: the UI backup (Settings › Backup) is a `VACUUM INTO` copy in a temporary directory next to the database, in a tar archive with a manifest (format, tlswatch version, schema, time), encrypted as a stream of 64 KiB AES-256-GCM chunks under a key derived from the passphrase with Argon2id (64 MiB, 3 passes; parameters and salt in the file header). The chunk counter is the nonce and the header and a last-chunk flag are the additional data, so a wrong passphrase, an altered file and a cut-off download all fail. Inside the copy, channel credentials and the Google client secret are re-sealed from the instance key under a second key derived from the passphrase: the file restores on any instance, and the instance key never leaves the server. An upload (1 GB at most, read as a stream, so nothing is buffered in memory or spilled to /tmp) is written to a temporary directory, checked (`integrity_check`, a tlswatch schema no newer than the binary, at least one enabled admin), migrated, its credentials re-sealed under the instance key, and its sessions deleted. Then the scheduler stops starting checks and housekeeping and waits for the running ones, the outbox waits for a running delivery (the node dispatcher pauses first and drops its queued and leased jobs, so the node checks end at once), and SQLite's backup API copies the file over the live database through the writer connection in one step; readers see the old database or the new one. The settings and CA bundle caches and the remembered sign-in addresses are dropped, the schedule is rebuilt as at startup, and the restore is written to the restored audit log. Everyone is signed out and signs in again with an account from the backup. A plain database copy from the `backup` subcommand restores the same way without a passphrase; its credentials are assumed to be sealed under this instance's key, and a channel that cannot be decrypted is marked as after a lost key.

**Retention**: observations, findings, alert log and audit entries older than 180 days (configurable) are pruned hourly. Certificates are kept while any observation references them. The current state of every target is always kept regardless of age.

**Scale**: the schedule is a priority queue by next-run time, so 10,000 targets cost memory, not CPU, between runs. Probing is bounded by the worker pool; SQLite handles the write rate of daily checks on thousands of targets with margin. The single-process design is a deliberate limit: one instance, scaled up, not out.

**Dependencies** (Go): standard library, `modernc.org/sqlite`, `golang.org/x/crypto` (Argon2id), `golang.org/x/oauth2`. Nothing else without a reason written in the pull request.

## Frontend

The frontend is pages rendered server-side with Go `html/template`, and TypeScript only where a page cannot work as a plain form. Every page works without JavaScript; the API endpoints answer JSON to the TypeScript and a redirect to a form.

**TypeScript without dependencies.** `tsc` alone compiles `web/ts` to plain ES modules in `web/static/js`, loaded with `<script type="module">`. No bundler, no framework, no runtime package. The dev dependency tree is `typescript` only, enforced in CI by a `check-deps` script. The `tsconfig.json` settings: ES2022, `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`.

Where TypeScript is used in version 1:

- The target form's Test button (probe without saving, render the result), and the port following the protocol.
- Check now and Check all, with the row updating in place when the probe returns.
- Live pages: polling the change stamp and swapping in a fresh render (see Inventory and user interface).
- Clickable rows, table row expand/collapse, copy-to-clipboard for fingerprints and PEM, filter chips, and tags that act as chips.
- The acknowledge panel (until-date, comment, close with Escape), and the bulk selection on the findings and targets lists.
- Live filtering on the targets, certificates and findings tables, the "/" shortcut (shown as a key hint in the filter field), and links that carry the current filter.
- Column sorting on the same three tables: a click on a head re-orders the rendered rows from their `data-sort-*` values the way the server would, and writes `sort` and `dir` into the URL.
- Confirmation before deleting, and disabling a form's buttons while it is sent.

Everything else is a form, and every one of these works as a plain link or form without JavaScript (the bulk bar shows through CSS alone). Shared helpers (`$`, `api()`, `ApiError`, `onReady`) live in `common.ts`; error messages come from one `messages` map, in English.

**Styling** follows the design canvas (`design/` in the repository), which is an operations console, not a workflow portal. The rules: colour carries status and nothing else — green, amber, red and grey mean healthy, warning, critical and off, and appear nowhere else; actions use one neutral accent (slate blue); the chrome is a 48 px dark graphite bar with live counts in the navigation; content is light by default with a full dark token set, the theme chosen as in Share (system preference, manual override stored server-side in a cookie, no flash). Type is IBM Plex Sans at 13 px for the UI and IBM Plex Mono for host:port, fingerprints, serials, dates and counts, both self-hosted under their OFL licences. Every page is at most 1680 px wide; forms are at most 760 px wide whatever the page, filter fields 300 px, lifetime bars in lists 110 px, and an empty state with a title is centred. Lists are dense: 8 px row padding, uppercase 11 px column heads, status as a dot plus a word, a lifetime bar per certificate showing the share of validity already used, filter chips with counts instead of dropdowns, sorted by expiry by default. Notices are bars, not toasts; the acknowledge form is a side panel, not a modal. All colours are CSS custom properties on `:root`; no colour is hard-coded below the token blocks. The token values are listed in `design/README.md`.

**Wordmark.** An inline-SVG shield-with-check mark in the accent colour next to "tlswatch" in Plex Sans 600, 15 px in the bar and 22 px on the sign-in card. No company branding anywhere in the open-source project.

**Principles**: server-rendered pages with small TypeScript modules, light and dark from day one via tokens, real forms that work without JavaScript, notices as bars, the mono convention for identifiers, tables that fall back to cards below 760 px, and the `tsc`-only toolchain.

**Build and test tooling**: `npm ci && npx tsc -p tsconfig.json` to build; `node --test web/test/*.test.mjs` on the compiled output for the few pure functions worth testing (days-left truncation, fingerprint formatting, tag parsing); Go `testing` with `-race` for everything else, including handler tests against an in-memory SQLite. No test framework beyond what Node and Go ship.

## Configuration, deployment and operations

**Everything is configured in the UI, as far as possible.** Only what the process needs before it can open its database stays outside it: the listen address, the database path and the secret key. All the rest lives in the database and is edited under Settings by an admin: the SMTP relays (host, port, encryption, username, password, sender, recipients), the Telegram bot token and chat IDs, the Slack, Discord and webhook URLs, the ntfy server and topic, Google sign-in (client ID, client secret, Workspace domain), the public base URL, probe concurrency, retention, proxy trust and local-target policy, thresholds and the digest.

Secrets entered in the UI (SMTP passwords, Telegram bot tokens, Slack and Discord webhook URLs, ntfy access tokens, webhook signing secrets, the Google client secret) are stored encrypted with AES-256-GCM under the secret key. They are never shown back; a password field left empty keeps the stored value. A copy of the database alone does not leak them. The `rotate-key` subcommand re-encrypts them under a new key while the server is stopped.

**Zero-configuration start.** `tlswatch serve` with no environment works. The data directory is created. A 32-byte secret key is generated into `data/secret.key` (mode 0600) when no key file exists. When no users exist yet, the server shows a setup screen at the first visit where the first admin creates their account and password; the log prints the URL. Because the default bind is loopback, nobody else can reach that screen before the admin exists. `create-admin` remains for scripted installs.

**Environment variables are optional overrides**, for container and GitOps deployments. A setting supplied by the environment wins over the database value and is shown in the UI as read-only with the note "set by environment". Values are validated like the UI fields; an invalid one stops startup with a message naming the variable (except `TZ`, which is ignored when unknown).

| Variable | Default | Where else | Purpose |
| --- | --- | --- | --- |
| `TLSWATCH_LISTEN` | `127.0.0.1:8080` | bootstrap only | Bind address; put a reverse proxy in front for TLS |
| `TLSWATCH_DB` | `./data/tlswatch.db` | bootstrap only | SQLite file; the directory is created |
| `TLSWATCH_SECRET_KEY_FILE` | `<db dir>/secret.key` | bootstrap only | 32 random bytes, generated if missing; encrypts secrets at rest and signs sessions |
| `TLSWATCH_LOG_JSON` | `true` | bootstrap only | JSON log lines on stdout |
| `TLSWATCH_BASE_URL` | empty | Settings › General | Public URL for links in alerts and the OIDC redirect; while empty, derived from the request and a notice bar asks an admin to set it |
| `TLSWATCH_BEHIND_PROXY` | `false` | Settings › General | Trust `X-Forwarded-For` and `X-Forwarded-Proto` from one hop |
| `TLSWATCH_ALLOW_LOCAL` | `false` | Settings › General | Allow loopback and link-local targets |
| `TLSWATCH_METRICS` | `false` | Settings › General | Serve Prometheus metrics at `/metrics` |
| `TLSWATCH_WORKERS` | `8` | Settings › Defaults | Concurrent probes |
| `TLSWATCH_RETENTION_DAYS` | `180` | Settings › Defaults | History retention |
| `TLSWATCH_GOOGLE_CLIENT_ID` / `_SECRET_FILE` / `_DOMAIN` | empty | Settings › Sign-in | Google sign-in; off while no client ID is set |

Settings pages added for this: **General** (base URL, proxy trust, local targets, metrics) and **Sign-in** (Google client ID, secret, domain, with the redirect URI to register shown read-only). Channels gain the SMTP encryption choice (STARTTLS, implicit TLS, none) and username/password as in the mockup; Telegram channels take the bot token and one or more chat IDs. Slack, Discord, ntfy and Webhook channels (added later, not in the mockups) follow the same form layout with their own fields. Every change is audited, secrets redacted.

**Packaging**: `go build` produces one static binary with the frontend embedded via `embed`; releases ship binaries for linux/amd64, linux/arm64, linux/arm (32-bit ARMv7, named after `GOARCH` alone because that is what a node asks for), darwin/amd64 and darwin/arm64, plus a Docker image from `scratch` with CA certificates for linux/amd64, linux/arm64 and linux/arm/v7, published to GitHub Container Registry. The image's build stages run on the builder's platform and cross-compile, so a multi-platform build does not run Go under emulation. The compose file in the repository runs the image with one volume for `data/`; TLS termination is left to the user's proxy.

**Subcommands**: `serve`, `create-admin -email`, `migrate` (also runs at start), `backup <path>` (SQLite `VACUUM INTO`, safe while running, never migrates), `healthcheck` (for the container), `rotate-key` (re-encrypts stored secrets under a new key; server stopped), `check <host[:port]> [-protocol -servername -ca-file -insecure -no-legacy]` for scripts and CI, exit code 0/1/2 by severity. It tests TLS 1.0 and 1.1 unless `-no-legacy` is given; each address in the JSON lists the old versions it accepted under `legacy_accepted`, absent when untested or without a verdict. `node [-server -data -workers -allow -allow-local -token -insecure]` runs the binary as a probe node inside another network, `node enrol -server -token` exchanges an install token for the credential, and `node uninstall` removes what the install script put in place (see Nodes).

**Operations**: `/healthz` reports database reachability and scheduler progress (last run, backlog, how long the oldest due check has waited); when enabled under Settings › General, `/metrics` serves Prometheus gauges without sign-in (targets by status, open findings by severity, alerts pending and given up, each target's certificate expiry, scheduler backlog and checks, checks running on nodes and targets held; nodes online and offline, seconds since each node was seen, jobs completed and failed per node); structured logs with request IDs and one line per check; a daily backup is the `backup` subcommand on a cron, and Settings › Backup downloads and restores an encrypted backup of the whole instance. Upgrades are a binary swap; migrations are forward-only and refuse to run a database written by a newer version.

**Development**: `make build`, `make test`, `make frontend`, `make run` with a throw-away database. There is no seed subcommand: test data does not ship in the binary. The README screenshot shows letsencrypt.org and the badssl.com hosts (expired, self-signed, wrong host, untrusted root, tls-v1-0.badssl.com:1010), added through the UI.

## Security

The tool holds a list of hosts, their certificates (public data) and the credentials of its own alert channels. The risks are the UI being reached by the wrong people, the probe being used as a scanner from inside the network, and the alert credentials leaking.

- **Transport**: the binary listens on loopback by default and expects a reverse proxy for TLS; `BEHIND_PROXY` must be set explicitly before forwarded headers are trusted. HSTS and `Secure` cookies when the base URL is https.
- **Headers**: `Content-Security-Policy: default-src 'self'` with no inline scripts or styles (all CSS in `app.css`, all JS in modules), `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `frame-ancestors 'none'`.
- **Sessions and CSRF**: as in Users above; one CSRF token per session, checked on every POST and on every JSON call via the `X-CSRF-Token` header.
- **Passwords**: Argon2id, 12-character minimum, leaked-password list, rate limit per account and per IP.
- **Probe as scanner**: only operators and admins can add targets, and every addition is in the audit log. Targets are probed with one TLS handshake and no application traffic beyond the STARTTLS preamble. Loopback and link-local addresses are refused as targets unless `TLSWATCH_ALLOW_LOCAL=true`; private ranges are allowed because monitoring internal addresses is the point.
- **Secrets at rest**: channel credentials and the Google client secret are encrypted with AES-256-GCM under the secret key file; the key is never in the database or in a backup. Logs redact tokens and passwords.
- **Outbound connections** are limited to the targets, the SMTP server, `api.telegram.org`, the Slack, Discord, ntfy and webhook URLs an admin configured, Google's OIDC endpoints, and, on a release build, the GitHub release checksums when a node on another platform downloads its binary. No telemetry, no update check.
- **Nodes**: a node makes outbound HTTPS connections to the server only and is never connected to; it sends back hostnames, chains and handshake metadata and nothing else. Its credential is stored hashed on the server and in a 0600 file on the node; the agent endpoints take that bearer credential only and are rate limited. A node-side allowlist of CIDRs bounds what a server can make it probe. See Nodes.
- **Input**: hostnames validated as DNS names or IP literals, ports 1 to 65535, PEM bundles parsed and rejected when they contain private keys, tags limited to 40 characters.
- **Backups**: a UI backup holds everything, including password hashes and the alert credentials, so it is encrypted with the admin's passphrase; downloads and restores are in the audit log. A restore needs the admin role, or happens on the setup screen while no account exists, with the same trust as creating the first admin there.
- **Audit log**: every change to targets, users (including unlocks and deletions), channels, bundles, defaults, backup downloads and restores, and every acknowledgement (bulk ones marked as such), with user and timestamp; readable by admins, exportable as CSV, pruned with the retention.
- **Supply chain**: Go dependencies pinned in `go.sum`, `govulncheck` and `gosec` in CI, the npm tree limited to `typescript`, releases built in CI from a tagged commit with checksums published.

## Open source: repository, licence, CI, versioning

The project lives in a public repository under a personal GitHub account; company-specific material (logos, customer names, internal addresses) never enters it.

**Licence**: MIT. It is the shortest, matches Go and TypeScript community norms, and the tool has no patent surface that would argue for Apache-2.0. The fonts carry their own OFL licence files in `web/static/fonts`.

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
3. Build: binaries for the three platforms and the Docker image, pushed to `ghcr.io` on a tag. The release workflow runs the same frontend and backend jobs on the tagged commit first and publishes nothing when they fail; the release notes are generated from the commits since the previous tag. A `v0.0.x` tag is a test release: marked as a prerelease and not moving the image's `latest` tag.
4. Renovate or Dependabot for pinned dependencies and action digests.

**Versioning**: semantic versions from `v0.1.0`; `v1.0.0` when the scope in this document is complete and the database schema is considered stable. `CHANGELOG.md` kept by hand, one line per change, newest first.

Nobody chooses a version for a build by hand. `scripts/version.sh` derives it from the checkout, and the Makefile and the Dockerfile both use it, so `make build` and `docker compose up --build` report the same thing: the tag when built exactly on one (`v0.2.0`), the tag with the distance and hash past it (`v0.2.0-5-g5efacf7`), and while no tag exists the commit date and hash (`2026.10.15-5efacf7`); `-dirty` is appended when the working tree had uncommitted changes, and `dev` is the fallback outside a git checkout. The release workflow passes the tag explicitly. The `.git` directory is in the Docker build context for this. A build without a release tag is a development build: its static files are not cached for good, and it does not update nodes automatically (see Updating nodes).

**Community files**: README with a screenshot, a three-command quick start and the `check` one-liner; CONTRIBUTING with the dependency rule (no new runtime dependency without a written reason in the pull request) and the test expectation; SECURITY with a private reporting address; issue templates for bug and feature; the specification itself in `docs/` so decisions are traceable.

**Name**: tlswatch. Candidates checked and rejected: `certlens` and `certscope` are taken (a Python package and a Firefox extension), `certwatch` is CertLight's former name, `certview` is a Qualys product. Check the GitHub name, the Go module path and Docker Hub before the first release.

## Decisions taken, assumptions and open points

Where the requirements said "not sure" or "what do you recommend", this document takes a position. The table records why, so a later change knows what it reverses.

| Topic | Decision in this document | Why |
| --- | --- | --- |
| Legacy TLS versions | Test TLS 1.0 and 1.1 once a day per address with pinned handshakes; `legacy_protocol` warning; per-target switch to turn it off | Compliance baselines (PCI DSS, NCSC, BSI) require them off, and a firmware update or a reset load balancer profile can turn them back on unnoticed; daily is enough for a setting that rarely changes, and the switch keeps unfixable appliances from becoming noise |
| Multiple A/AAAA records | Probe all addresses, up to 8; `inconsistent` finding when they differ; per-target switch to first-only | The one stale node behind a load balancer is the failure a single probe misses |
| Grouping | Free-form tags plus a notes field, no fixed hierarchy | Enough at 100 targets; a hierarchy adds screens and migrations |
| Alert behaviour | Transition alerts, severity-based reminders, recovery notices, acknowledge with snooze, optional weekly digest | Daily checks must not become daily mail |
| Severities | Three: info, warning, critical | Four levels invite routing rules nobody maintains |
| Change detection | `renewal managed` flag per target, auto-set for known ACME issuers | Let's Encrypt churn would otherwise drown real changes |
| Frontend | Server-rendered templates plus small TypeScript modules, not a single-page app; the look is an operations console (status-only colour, dense lists, overview home), not a workflow-portal style | Smallest dependency footprint; a workflow-portal style does not fit a monitor |
| Tooling | `tsc` only, `node --test`, Go `testing`, GitHub Actions, Renovate | Small, standard and reproducible |
| SQLite driver | `modernc.org/sqlite` (pure Go) | Static binary, cross-compiles without cgo |
| Licence | MIT | Simplest; no patent concern |
| Internal networks | A node inside the network, the same binary as the server; the probe package is database-free so the node runs it unchanged (see Nodes) | One inventory and one binary; a second instance would split the inventory, users and alert rules |
| Node: who schedules | The server owns the schedule, the data and the checks; the node is stateless apart from its credential and runs one probe at a time per worker | One inventory and one schedule; a node holds nothing worth backing up or losing |
| Node: transport | Outbound HTTPS long-poll with a 55 s ceiling; no WebSocket | The node is never connected to, so one outbound firewall rule suffices; a held request delivers a job within one round trip; no dependency, no proxy upgrade configuration, and on a link carrying one job every half hour a socket would buy nothing |
| Node: trust | CA bundles stay on the server, which verifies `bundle` chains itself; `system` uses the node's host store; the node's own connection to the server uses the host store too | Trust is managed in one place; a changed bundle needs no node update; the node cannot receive a CA from a server it does not yet trust |
| Node: install | One command from the UI, a script served by the instance with a one-time token in its URL; the admin confirms the reported hostname and addresses before the node can take targets | No keys made by hand; a token in shell history is harmless because an unconfirmed node is inert and a stranger's machine is rejected on sight |
| Node: binary source | The server serves its own executable for its own platform, redirects to its release asset otherwise | Node and server are always the same version; a same-architecture network needs no internet |
| Node: updates | Automatic by default, converging on the server's version in both directions, one node at a time, rollback after five minutes without a poll; containers are pulled, not patched; `dev` builds update by hand | Nobody logs in to a node; a bad release reaches one network before it reaches the rest; a replaced binary in a container would be lost on restart |
| Node: binary ownership | The binary belongs to the node's user, under its data directory, with `NoNewPrivileges` | Self-update needs a writable binary; a compromise of that user already runs code as that user, so this adds no privilege |
| Node: offline | Targets keep their state and show "Waiting for node"; one `node_offline` finding per node after 10 minutes, critical once a target is overdue | A dead node is one problem, not fifty unreachable hosts |
| TLS grade: four grades, rules in a versioned table | A, B, C, F from pinned handshakes per suite class, the lowest address counts, every grade carries its reasons; no A+ and no D; certificate validity stays out of the grade | A letter sorts a list and settles a discussion with a vendor; finer steps invite arguments about scoring; a grade without reasons is a verdict nobody can act on; an expired certificate already has a critical finding and must not be counted twice |
| TLS grade: one finding per cause | Versions stay `legacy_protocol`, signature and key size stay `weak_signature`, suite classes get `weak_configuration`; B-grade causes open no finding | Nothing alerts twice for one fix; CBC and a missing TLS 1.3 are worth a column, not a page |
| CT: an index, not the logs | Issuances come from Cert Spotter or crt.sh through a source interface, polled hourly per domain from the server | Tailing the logs is a service in itself; an interface keeps the choice open, including a self-hosted index |
| CT: match by issuer and serial, hold renewals 48 hours | A precertificate has no usable fingerprint; an issuance whose names and issuer match a target waits 48 hours before it is unexpected | ACME renewals appear in the logs hours before they are deployed and must show up as one quiet line, not as a warning followed by a recovery |
| CT: watches are explicit | Operators add domains; nothing is derived from targets; the first poll's backlog opens no finding | A target on a customer's host does not make that domain yours; a new watch must not open fifty findings on day one |

**Assumptions**

- The tool runs on a host that can reach the public internet and the internal addresses it monitors.
- A reverse proxy handles TLS for the UI itself.
- E-mail goes through an SMTP relay that already exists; the tool is not a mail server.
- The fonts are OFL and can be redistributed with an MIT-licensed project.

**Open points settled.** The questions the first draft left open were decided on 16 October 2026 and are recorded in the sections above: MIT as the licence; all addresses as the default; TOTP as a later version; `info` findings outside the weekly digest; and letsencrypt.org plus the badssl.com hosts as the screenshot data. No open point remains for version 1.

**Later versions**, in rough priority: a public REST API with tokens; bulk import and export of targets as YAML; TOTP as a second factor for local accounts; OCSP and CRL checks; a self-hosted Certificate Transparency index as a third source; a stricter grade rule set (TLS 1.2 without 1.3 to C) once the installed base allows it; Microsoft Teams, PagerDuty and Matrix channels; ticket creation in a service desk on critical findings.
