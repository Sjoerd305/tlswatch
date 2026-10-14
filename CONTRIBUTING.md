# Contributing

Thanks for helping. A few rules keep tlswatch small and easy to run.

- **Dependencies.** Runtime Go dependencies are the standard library, `modernc.org/sqlite`, `golang.org/x/crypto` and `golang.org/x/oauth2`. Do not add another one without a written reason in the pull request. The npm tree is `typescript` only; `npm run check-deps` enforces that.
- **Tests.** New behaviour comes with tests: Go `testing` (run with `-race`), handler tests against an in-memory SQLite, and `node --test` for pure TypeScript helpers. Authorisation changes extend the negative suite in `internal/web/web_test.go`.
- **Frontend.** Pages must work without JavaScript. No inline styles or scripts (the Content-Security-Policy forbids them); colours only through the tokens in `app.css`. Commit the compiled `web/static/js` together with the `web/ts` change.
- **Configuration.** New settings belong in the UI (Settings) and the database, not in new required environment variables. Secrets are stored encrypted.
- **Style.** `gofmt`, `go vet`, and the existing naming. One line per change in `CHANGELOG.md`.

Run `make lint test` before opening a pull request.
