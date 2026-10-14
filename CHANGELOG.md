# Changelog

Newest first, one line per change.

## Unreleased

- Targets can be deleted from the target page and the edit form, after a confirmation page that shows what is removed.
- Target status is Unreachable as soon as a check reaches no address (the finding and alert stay debounced); a protocol that does not fit a well-known port gets a hint; the port follows the protocol in the target form and the SMTP encryption in the channel form.
- First-run setup screen: the first admin creates their own account and password in the browser; no setup link or seeding needed.
- First version: probing (TLS and STARTTLS), checks and findings, alerts on SMTP and Telegram, inventory, web UI with roles, Google sign-in, and configuration through the UI.
