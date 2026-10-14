# Changelog

Newest first, one line per change.

## Unreleased

- Fix: a check that was running while its target was disabled, or moved to another host, port, protocol, server name or trust setting, is discarded. Before, it re-opened the findings that disabling resolved, or stored the old endpoint's certificate and raised a false certificate change on the next check.
- Fix: the scheduler's one-minute refresh no longer undoes Check all or the spread of overdue checks after a restart. A check that cannot be stored (for example a full disk) is retried after 1, 2, 4 … minutes, up to an hour, instead of straight away. `/healthz` reports `overdue_s` and answers 503 when a due check has waited more than an hour.
- Fix: a channel whose settings cannot be decrypted (for example after the secret key changed) no longer stops every check from being stored. It is marked on the Channels page, its alerts fail with a visible error, and the other channels keep working. Delivery logs name the channel ID and the alert IDs, and giving up after 24 hours is logged as an error.
- Change detection: an open certificate or issuer change is resolved without an acknowledgement only by an automatic renewal. A manually replaced certificate no longer resolves an open issuer change.
- Users without SMTP: when no SMTP channel is set up, the admin sets a new user's first password (or creates a link to pass on) and can set a new password for a local user later. With SMTP, users get an e-mailed invite link and choose their own password, as before.
- Live pages: Overview, Targets, a target, Certificates and Findings update themselves when checks land or findings change (every 4 s while checks run, otherwise every minute; paused in background tabs, never while you type or have unsaved input). The background polling does not extend the session idle timeout.
- Findings: acknowledge several at once (checkboxes and a bulk bar); filter by text and by target, linked from the target page.
- Users: locked-out accounts show as locked with an Unlock button; users can be deleted (not yourself, not the last admin); the audit log keeps their entries.
- Forms disable their buttons while they are sent, so slow actions such as a channel test cannot be sent twice. The "certificates no longer served" switch now works both ways and keeps the filters.
- UI: rows in lists are clickable as a whole (targets, overview, findings, channels, users, certificate and history tables); cmd/ctrl or middle click opens a new tab. Tags in the targets table filter the list; the findings panel has a close button and closes on Escape; "/" focuses the filter; past expiry dates show "expired" instead of negative days; deleting a channel or CA bundle asks first; Disable is no longer styled as a destructive action.
- Targets can be deleted from the target page and the edit form, after a confirmation page that shows what is removed.
- Target status is Unreachable as soon as a check reaches no address (the finding and alert stay debounced); a protocol that does not fit a well-known port gets a hint; the port follows the protocol in the target form and the SMTP encryption in the channel form.
- First-run setup screen: the first admin creates their own account and password in the browser; no setup link or seeding needed.
- First version: probing (TLS and STARTTLS), checks and findings, alerts on SMTP and Telegram, inventory, web UI with roles, Google sign-in, and configuration through the UI.
