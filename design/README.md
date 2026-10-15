# tlswatch – frontend design

Version 1 · 14 October 2026 · belongs to `docs/specification.md`

The clickable design is a Claude Design canvas (private; share from the page's Share menu). The screens are in `mockups/`, one `.dc.html` per screen; `canvas.json` is the canvas layout. The mockups load `./support.js` from the design canvas and render only there, not stand-alone in a browser. They are a design, not portal code: the frontend is server-rendered with Go `html/template` and TypeScript without a framework, as the specification says.

## Direction

tlswatch is an operations console, not a workflow portal. You open it to see at a glance whether anything needs attention, scan a list of up to a few hundred hosts, and only occasionally fill in a form. That drives every rule below.

1. **Colour means status, nothing else.** Green, amber, red and grey mean healthy, warning, critical and off/unreachable, and appear nowhere else. Actions use one neutral accent (slate blue). On a healthy day the page looks calm; a red row is the only saturated thing on it.
2. **The home screen answers "what needs attention now".** Status tiles, the next expiries with a lifetime bar, open findings, recent changes, the last run. The targets table is the second screen.
3. **Dense lists.** 13 px type, 8 px row padding, uppercase 11 px column heads, status as a dot plus a word, right-aligned numbers, filter chips with counts instead of dropdowns, sorted by expiry by default.
4. **Lifetime bar.** Every certificate shows the share of its validity already used, coloured by status. 98 % red reads faster than "5 days".
5. **The certificate leads on the detail page**, not the configuration: countdown, lifetime bar, chain as a vertical stack with the weak link marked, per-address results; configuration folded into the side column.
6. **No explanation in the UI.** Labels, data, statuses, actions. Help text under a field only when needed to fill it in.
7. **Light and dark from day one.** One layout, two token sets. No colour is hard-coded; everything references a token. The theme follows `prefers-color-scheme`, with a manual choice in the account menu stored server-side in a cookie so pages render without a flash.
8. **Mono for identifiers.** `host:port`, fingerprints, serials, dates, times and counts are set in Plex Mono with tabular numerals.
9. **Notices are bars, not toasts.** The acknowledge form is a side panel next to the list, not a modal.
10. **Healthy and empty states are designed.** "14 targets, nothing due within 30 days, last run 04:17" is the most common screen and must read as good news. An empty state says what to do next.

## Type

| Use | Face | Size |
| --- | --- | --- |
| UI text | IBM Plex Sans 400/500/600 | 13 px body, 12 px help, 11 px column heads and pills (uppercase, +4 % tracking) |
| Page title | IBM Plex Sans 600 | 20 px |
| Stat tile number | IBM Plex Sans 600 | 28 px |
| Countdown on detail page | IBM Plex Sans 600 | 34 px |
| Identifiers, dates, counts | IBM Plex Mono 400/500 | 13 px, 12 px in dense cells |
| Wordmark | IBM Plex Sans 600 | 15 px in the bar, 22 px on sign-in |

Both faces are OFL and self-hosted in `web/static/fonts`. The mockups load them from Google Fonts only because the canvas cannot host files.

## Colour tokens

| Token | Use | Light | Dark |
| --- | --- | --- | --- |
| `bg` | Page background | `#f5f6f7` | `#0f141a` |
| `surface` | Cards, tables, forms | `#ffffff` | `#171d25` |
| `surface-2` | Table heads, expanded rows, secondary buttons (dark) | `#f0f2f4` | `#1e2630` |
| `ink` | Text | `#1a2330` | `#e6ebf0` |
| `muted` | Help text, column heads, secondary values | `#5c6b7a` | `#97a3b1` |
| `line` / `line-soft` | Borders / row separators | `#dde2e7` / `#eaeef1` | `#2a3442` / `#222b36` |
| `input-line` / `input-bg` | Inputs, chips, secondary buttons | `#b9c2cc` / `#ffffff` | `#3a4656` / `#121820` |
| `acc` / `acc-hover` / `on-acc` | Primary button, active tab, links, wordmark | `#2f6fd1` / `#275bb0` / `#ffffff` | `#6ea0ec` / `#8ab4f2` / `#0f141a` |
| `ok` / `ok-bg` | Healthy, recovered, sent | `#1f8a4c` / `#e3f3ea` | `#4cc27a` / `#15301f` |
| `warn` / `warn-bg` | Warning, changed, inconsistent | `#a86400` / `#fdf1dc` | `#f0b84d` / `#332a12` |
| `crit` / `crit-bg` | Critical, expired, failed | `#c62828` / `#fde8e8` | `#f06565` / `#3a1b1b` |
| `off` / `off-bg` | Disabled, resolved, acknowledged | `#6b7785` / `#e9ecef` | `#8e9aa8` / `#262e38` |
| `info` / `info-bg` | Informational change, selected row | `#2f6fd1` / `#e6eefb` | `#6ea0ec` / `#17273d` |
| `chrome` / `chrome-fg` / `chrome-muted` / `chrome-line` | Top bar | `#1c2430` / `#e8edf2` / `#95a2b1` / `#2c3745` | `#0b0f14` / `#e6ebf0` / `#8793a1` / `#232c37` |
| `track` | Lifetime bar background | `#e4e8ec` | `#2a3442` |
| `overlay` / `shadow` | Behind and under a dialog | black 50 % / 25 % | black 60 % / 50 % |

Rules for the build:

- Tokens are CSS custom properties on `:root`; the dark set lives under `@media (prefers-color-scheme: dark)` guarded by `:root:not([data-theme="light"])` and again under `:root[data-theme="dark"]`.
- Status tokens (`ok`, `warn`, `crit`, `off`, `info`) are only used by status components: the status dot, pills, lifetime bar fill, the countdown, coloured numbers, notice bars, nav counts. Never for decoration.
- Every text-on-background pair meets 4.5:1 in both themes; `warn` on `surface` is the tightest pair and was darkened for that reason.
- Icons inherit `currentColor`; the wordmark's shield is `stroke: var(--acc)`.
- A new colour is a new token pair in both themes, with a stated meaning.

## Building blocks

- **Top bar** (48 px, `chrome`): shield mark + "tlswatch", navigation Overview · Targets · Certificates · Findings · Settings with live counts (a red count on Findings when something is critical), last/next run in mono on the right, user with a small role tag.
- **Page head**: title 20 px with a one-line summary in `muted` under it, primary action on the right.
- **Filter row**: a filter field (with a `/` key hint), then chips with counts (status, tags, issuer, expiry window); the active chip is inverted. No dropdowns for things with fewer than eight values; above that (issuers on a large fleet) a select with the same counts.
- **Status**: a dot plus a word (`Healthy`, `Warning`, `Critical`, `Changed`, `Disabled`) in lists; uppercase pills (`crit`, `warn`, `ack`, `new`, `fixed`) in compact lists and timelines.
- **Lifetime bar**: 6 px track, fill = share of validity used, colour by status; 110–140 px wide in tables, full width on the detail page with issued and expiry dates under it.
- **Tables**: in a card, `surface-2` head row, 7–8 px cell padding, `line-soft` separators, hover highlights the row, selected row in `info-bg`. Column heads sort on click; the active column is in `ink` with a small arrow, the others stay `muted`. Expanded rows use `surface-2` and may contain a nested table; the expand control is a chevron that turns when the row is open. Grouped lists (targets by tag, findings by kind) put a head row with the group name and count above each section.
- **Stat tiles**: status word above a 28 px number, one line of context under it; four across on the overview.
- **Cards and sections**: 6 px radius, 1 px `line` border, a section head row with an uppercase 12 px title and a right-aligned link or meta value.
- **Forms**: 32 px inputs, 12 px uppercase labels in `muted`, 12 px help text, segmented control for a three-way choice (trust mode), section rules between groups, footer with the primary button first and Cancel pushed right.
- **Buttons**: primary `acc`, secondary `surface` with `input-line` border, danger = secondary with `crit` text; `xs` (24–26 px) inside table rows.
- **Side panel**: a card in the right column for the acknowledge form, test result or configuration; never a modal.
- **Notice bar**: coloured background and text in the status pair, icon left, at the top of the content.
- **Mobile**: below 1100 px the navigation gets its own row; below 760 px tables fall back to cards and side panels stack under the main column. The main lists become compact cards: status, name and days left on the first line, `host:port` on the second, tags and the action on the third; the lifetime bar, issuer, TLS version and timestamps are left to the detail page. The settings tables keep one labelled line per column.

## Screens

| File | Screen | Shows |
| --- | --- | --- |
| `Login.dc.html` | Sign in | Local login and Google, one card |
| `Main.dc.html` | Overview | Home: tiles, expiring next with lifetime bars, open findings, recent changes, last run |
| `Targets.dc.html` | Targets | Dense table sorted by expiry, filter chips, Check buttons per row |
| `Target.dc.html` | Target detail | Countdown and lifetime bar, certificate facts, chain stack, per-address results, history; configuration, findings and alerts in the side column |
| `Certificates.dc.html` | Certificates | Inventory by fingerprint with an expanded row showing where a certificate is served; a "stale node" case |
| `Findings.dc.html` | Findings | Open findings with the acknowledge side panel and alert timeline |
| `TargetForm.dc.html` | Add target | The form with trust mode, thresholds and channels, and the "Test without saving" result panel |
| `Channels.dc.html` | Settings · Channels | Settings sub-navigation, channel table with severity floor and delivery state, SMTP edit form |
| `Main-Dark.dc.html` | Overview (dark) | The same overview with the dark token set |

Not drawn yet, to be built in the same blocks: Settings › CA bundles, Defaults, Users, Audit log; Account; error and empty pages.

## Open points

- [ ] Dark-first chrome everywhere (current) versus a light bar on light pages.
- [ ] Lifetime bar in the targets table: keep, or show only on the overview and detail page.
- [ ] Whether the filter field should also accept query syntax (`tag:sip issuer:sectigo days<30`).
- [ ] Shield mark: keep, or text wordmark only.
