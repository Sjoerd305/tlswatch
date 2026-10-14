// Page behaviours, wired by data attributes through event delegation so that
// HTML swapped in from the server works without re-binding. Every behaviour
// is an enhancement: the same links and forms work without JavaScript.
//
// Contract with the templates:
//
//   [data-copy="text"]                 button copies the text
//   [data-copy-url="/path"]            button fetches the URL (text) and copies it
//   input[data-filter="#table"]        live text filter over tbody tr[data-search]
//   [data-chip-group="#table"]         chip container for that table; chips are
//     .chip[data-chip-key][data-chip-value] (<a href="?key=value"> for no-JS);
//     one active (.on) chip per group, value "" means all. A row matches when
//     its data-<key> attribute (space-separated tokens) contains the value.
//   [data-count-for="#table"]          receives "N of M" (+ data-count-noun)
//   tr[data-expand]                    toggles the next tr.detail; .expander ▸/▾
//   [data-load-url="/api/v1/..."]      inside a detail row: loads { html } into
//                                      the element the first time the row opens
//   form[data-api="/api/v1/..."]       submitted with fetch; JSON reply
//     { html?, notice?, notice_kind?, redirect? }; html replaces the element
//     named by data-replace ("row" = closest tr, else a selector)
//   a[data-panel="#panel"][data-panel-url="/api/v1/..."]
//                                      loads { html } into the panel, marks row .sel
//   [data-panel-close]                 hides the closest .panel and clears the row .sel
//   button[data-test-url="/api/v1/..."] posts its form, puts { html } in #test-result
//   a[data-row-link]                   the primary link of its tr or .li: a click
//                                      anywhere else in that row follows it
//   a[data-chip-for="#table"][data-chip-key][data-chip-value]
//                                      selects the matching chip of that table
//   form[data-confirm="question"]      asks before submitting
//   form[method=post] (not data-api)   submit buttons are disabled while it is
//                                      sent, so a slow action is not sent twice
//   [data-keep-filter="a b"]           links inside carry the page's current
//                                      query (the live filter text, chips) except
//                                      the parameters listed, which the link sets
//   [data-select-all="#table"]         checks the shown rows' input[name=id];
//                                      [data-bulk-count] shows how many
//   meta[name=tlswatch-stamp]          a live page: it polls /api/v1/stamp and
//                                      swaps in a fresh render when data changed
//   "/" key                            focuses the page's filter field
//   details.menu                       closes on outside click and Escape

import { $, $$, api, ApiError, messages, onReady } from "./common.js";

interface ApiReply {
  html?: string;
  notice?: string;
  notice_kind?: "ok" | "warn" | "crit" | "info";
  redirect?: string;
}

// ---------- Notices ----------

function showNotice(text: string, kind: "ok" | "warn" | "crit" | "info" = "crit"): void {
  const page = $(".page");
  if (page === null) return;
  $("[data-js-notice]", page)?.remove();
  const bar = document.createElement("div");
  bar.className = `notice ${kind}`;
  bar.setAttribute("role", kind === "crit" ? "alert" : "status");
  bar.dataset["jsNotice"] = "";
  const body = document.createElement("div");
  body.textContent = text;
  bar.append(body);
  page.prepend(bar);
}

function errorText(err: unknown): string {
  return err instanceof ApiError ? err.message : messages.unknown;
}

function setBusy(el: HTMLElement | null, busy: boolean): void {
  if (el === null) return;
  el.setAttribute("aria-busy", busy ? "true" : "false");
  if (el instanceof HTMLButtonElement) el.disabled = busy;
}

// ---------- Copy ----------

async function copyText(text: string): Promise<void> {
  if (navigator.clipboard !== undefined) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.className = "sr-only";
  document.body.append(area);
  area.select();
  const ok = document.execCommand("copy");
  area.remove();
  if (!ok) throw new Error("copy failed");
}

function flashLabel(btn: HTMLElement, text: string): void {
  const original = btn.dataset["label"] ?? btn.textContent ?? "";
  btn.dataset["label"] = original;
  btn.textContent = text;
  window.setTimeout(() => {
    btn.textContent = original;
  }, 1200);
}

async function handleCopy(btn: HTMLElement): Promise<void> {
  try {
    let text = btn.dataset["copy"];
    const url = btn.dataset["copyUrl"];
    if (url !== undefined) {
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) throw new Error(String(res.status));
      text = await res.text();
    }
    await copyText(text ?? "");
    flashLabel(btn, messages.copied);
  } catch {
    flashLabel(btn, messages.copyFailed);
  }
}

// ---------- Live filter and chips ----------

function tableRows(table: Element): HTMLTableRowElement[] {
  return $$<HTMLTableRowElement>("tbody > tr[data-search]", table);
}

function rowHasToken(row: HTMLElement, key: string, value: string): boolean {
  const attr = row.getAttribute(`data-${key}`);
  if (attr === null) return false;
  return attr.split(/\s+/).includes(value);
}

function applyFilter(tableSel: string, updateUrl: boolean): void {
  const table = $(tableSel);
  if (table === null) return;
  const input = $<HTMLInputElement>(`input[data-filter="${tableSel}"]`);
  const query = (input?.value ?? "").trim().toLowerCase();

  const active: Array<[string, string]> = [];
  for (const group of $$(`[data-chip-group="${tableSel}"]`)) {
    for (const chip of $$(".chip.on[data-chip-key]", group)) {
      const key = chip.dataset["chipKey"] ?? "";
      const value = chip.dataset["chipValue"] ?? "";
      if (key !== "" && value !== "") active.push([key, value]);
    }
  }

  const rows = tableRows(table);
  let shown = 0;
  for (const row of rows) {
    const text = (row.dataset["search"] ?? "").toLowerCase();
    const match = (query === "" || text.includes(query)) && active.every(([k, v]) => rowHasToken(row, k, v));
    row.hidden = !match;
    if (match) shown++;
    const next = row.nextElementSibling;
    if (next instanceof HTMLTableRowElement && next.classList.contains("detail")) {
      next.hidden = !match || row.getAttribute("aria-expanded") !== "true";
    }
  }

  const counter = $(`[data-count-for="${tableSel}"]`);
  if (counter !== null) {
    const noun = counter.dataset["countNoun"];
    counter.textContent = `${shown} of ${rows.length}${noun !== undefined ? ` ${noun}` : ""}`;
  }
  const empty = $(`[data-empty-for="${tableSel}"]`);
  if (empty !== null) empty.hidden = shown > 0;
  updateBulk(tableSel);

  if (updateUrl) {
    const url = new URL(window.location.href);
    for (const group of $$(`[data-chip-group="${tableSel}"]`)) {
      for (const chip of $$("[data-chip-key]", group)) url.searchParams.delete(chip.dataset["chipKey"] ?? "");
    }
    for (const [k, v] of active) url.searchParams.set(k, v);
    if (query !== "") url.searchParams.set("q", query);
    else url.searchParams.delete("q");
    window.history.replaceState(null, "", url.toString());
  }
}

function handleChip(chip: HTMLElement): void {
  const group = chip.closest<HTMLElement>("[data-chip-group]");
  if (group === null) return;
  const tableSel = group.dataset["chipGroup"] ?? "";
  const key = chip.dataset["chipKey"] ?? "";
  const wasOn = chip.classList.contains("on");
  for (const other of $$("[data-chip-key]", group)) {
    if ((other.dataset["chipKey"] ?? "") === key || (other.dataset["chipValue"] ?? "") === "") {
      other.classList.remove("on");
      other.removeAttribute("aria-current");
    }
  }
  const value = chip.dataset["chipValue"] ?? "";
  let target: HTMLElement = chip;
  if (wasOn && value !== "") {
    // Clicking the active chip again clears it and selects "All" in the group.
    target = $$(`[data-chip-key][data-chip-value=""]`, group)[0] ?? chip;
    if (target === chip) {
      applyFilter(tableSel, true);
      return;
    }
  }
  target.classList.add("on");
  target.setAttribute("aria-current", "true");
  applyFilter(tableSel, true);
}

// ---------- Row expand ----------

function toggleRow(row: HTMLTableRowElement): void {
  const detail = row.nextElementSibling;
  if (!(detail instanceof HTMLTableRowElement) || !detail.classList.contains("detail")) return;
  const open = row.getAttribute("aria-expanded") !== "true";
  row.setAttribute("aria-expanded", open ? "true" : "false");
  detail.hidden = !open;
  const cell = $(".expander", row);
  const link = cell !== null ? $<HTMLAnchorElement>("a", cell) : null;
  const glyph = link ?? cell;
  if (glyph !== null) glyph.textContent = open ? "▾" : "▸";
  // The open row is part of the URL, so a reload or live refresh keeps it.
  const key = link !== null ? new URL(link.href).searchParams.get("open") : null;
  if (key !== null) {
    const url = new URL(window.location.href);
    if (open) url.searchParams.set("open", key);
    else if (url.searchParams.get("open") === key) url.searchParams.delete("open");
    window.history.replaceState(null, "", url.toString());
  }
  if (open) {
    for (const el of $$<HTMLElement>("[data-load-url]", detail)) void loadInto(el);
  }
}

// loadInto fills an element of a detail row from its data-load-url, once.
async function loadInto(el: HTMLElement): Promise<void> {
  const url = el.dataset["loadUrl"];
  if (url === undefined) return;
  delete el.dataset["loadUrl"];
  try {
    const reply = await api<ApiReply>("GET", url);
    el.innerHTML = reply.html ?? "";
    el.classList.remove("muted");
  } catch {
    el.textContent = "could not be loaded";
    el.dataset["loadUrl"] = url;
  }
}

// ---------- API forms, panels, test probe ----------

function applyReply(reply: ApiReply | null, origin: HTMLElement, replace: string | undefined): void {
  if (reply === null) return;
  if (reply.redirect !== undefined && reply.redirect !== "") {
    window.location.assign(reply.redirect);
    return;
  }
  if (reply.html !== undefined && replace !== undefined && replace !== "") {
    const target = replace === "row" ? origin.closest("tr") : $(replace);
    if (target !== null) {
      target.outerHTML = reply.html;
      // A replaced table body may need its filters re-applied.
      for (const input of $$<HTMLInputElement>("input[data-filter]")) applyFilter(input.dataset["filter"] ?? "", false);
    }
  }
  if (reply.notice !== undefined && reply.notice !== "") showNotice(reply.notice, reply.notice_kind ?? "ok");
}

async function submitApiForm(form: HTMLFormElement, submitter: HTMLElement | null): Promise<void> {
  const url = form.dataset["api"] ?? "";
  const button = submitter ?? $<HTMLButtonElement>('button[type="submit"], button:not([type])', form);
  setBusy(button, true);
  form.setAttribute("aria-busy", "true");
  try {
    const data = new FormData(form);
    if (submitter instanceof HTMLButtonElement && submitter.name !== "") data.set(submitter.name, submitter.value);
    const reply = await api<ApiReply | null>("POST", url, data);
    applyReply(reply, form, form.dataset["replace"]);
    // A row updated in place is current; anything else (Check all) shows up
    // through a quick live refresh.
    if (reply?.html !== undefined) void adoptStamp();
    else schedulePoll(fastPoll);
  } catch (err) {
    showNotice(errorText(err));
  } finally {
    if (button !== null && button.isConnected) setBusy(button, false);
    form.removeAttribute("aria-busy");
  }
}

async function openPanel(link: HTMLAnchorElement): Promise<void> {
  const panel = $(link.dataset["panel"] ?? "");
  const url = link.dataset["panelUrl"];
  if (panel === null || url === undefined) {
    window.location.assign(link.href);
    return;
  }
  link.setAttribute("aria-busy", "true");
  try {
    const here = window.location.pathname + window.location.search;
    const reply = await api<ApiReply>("GET", `${url}?next=${encodeURIComponent(here)}`);
    panel.innerHTML = reply.html ?? "";
    panel.hidden = false;
    // Only the selection changes; the list's filters stay in the URL.
    const sel = new URL(link.href).searchParams.get("sel");
    const loc = new URL(window.location.href);
    if (sel !== null) loc.searchParams.set("sel", sel);
    window.history.replaceState(null, "", loc.toString());
    const row = link.closest("tr");
    if (row !== null) {
      for (const other of $$("tr.sel", row.parentElement ?? document)) other.classList.remove("sel");
      row.classList.add("sel");
    }
    $<HTMLElement>("input:not([type=hidden]), textarea, select, button", panel)?.focus({ preventScroll: false });
  } catch {
    window.location.assign(link.href);
  } finally {
    link.removeAttribute("aria-busy");
  }
}

async function runTest(btn: HTMLButtonElement): Promise<void> {
  const form = btn.form;
  const out = $("#test-result");
  const url = btn.dataset["testUrl"];
  if (form === null || out === null || url === undefined) return;
  setBusy(btn, true);
  try {
    const reply = await api<ApiReply>("POST", url, new FormData(form));
    out.innerHTML = reply.html ?? "";
    out.hidden = false;
  } catch (err) {
    showNotice(errorText(err));
  } finally {
    setBusy(btn, false);
  }
}

// ---------- Bulk selection ----------

function bulkBoxes(table: Element): HTMLInputElement[] {
  return $$<HTMLInputElement>('tbody > tr input[type="checkbox"][name="id"]', table);
}

function updateBulk(tableSel: string): void {
  const table = $(tableSel);
  const all = $<HTMLInputElement>(`[data-select-all="${tableSel}"]`);
  if (table === null || all === null) return;
  let shown = 0;
  let checked = 0;
  for (const box of bulkBoxes(table)) {
    // A row hidden by the filter is never acted on unseen.
    if (box.closest("tr")?.hidden === true) {
      box.checked = false;
      continue;
    }
    shown++;
    if (box.checked) checked++;
  }
  all.checked = checked > 0 && checked === shown;
  all.indeterminate = checked > 0 && checked < shown;
  const count = $("[data-bulk-count]");
  if (count !== null) count.textContent = `${checked} selected`;
}

function selectAll(box: HTMLInputElement): void {
  const tableSel = box.dataset["selectAll"] ?? "";
  const table = $(tableSel);
  if (table === null) return;
  for (const row of bulkBoxes(table)) {
    if (row.closest("tr")?.hidden !== true) row.checked = box.checked;
  }
  updateBulk(tableSel);
}

// ---------- Links that keep the current filter ----------

function keepFilter(link: HTMLAnchorElement): void {
  const scope = link.closest<HTMLElement>("[data-keep-filter]");
  if (scope === null || link.getAttribute("href") === null) return;
  const own = (scope.dataset["keepFilter"] ?? "").split(/\s+/).filter((k) => k !== "");
  const current = new URL(window.location.href).searchParams;
  const url = new URL(link.href);
  for (const key of Array.from(url.searchParams.keys())) {
    if (!own.includes(key) && !current.has(key)) url.searchParams.delete(key);
  }
  for (const [key, value] of current) {
    if (!own.includes(key)) url.searchParams.set(key, value);
  }
  link.href = url.toString();
}

// ---------- Busy forms ----------

// Disables the submit buttons of a plain form once it is on its way. It runs
// after the submit event, because a button disabled before it would drop its
// own name and value from the submission.
function markSubmitting(form: HTMLFormElement, submitter: HTMLElement | null): void {
  form.setAttribute("aria-busy", "true");
  const buttons = $$<HTMLButtonElement>('button[type="submit"], button:not([type])', form);
  if (form.id !== "") buttons.push(...$$<HTMLButtonElement>(`button[form="${CSS.escape(form.id)}"]`));
  if (submitter instanceof HTMLButtonElement && !buttons.includes(submitter)) buttons.push(submitter);
  window.setTimeout(() => {
    for (const btn of buttons) {
      if (btn.disabled) continue;
      btn.dataset["busyDisabled"] = "";
      btn.disabled = true;
    }
    if (submitter !== null) submitter.setAttribute("aria-busy", "true");
  }, 0);
}

// A page restored from the back/forward cache comes back usable.
function clearSubmitting(): void {
  for (const form of $$("form[aria-busy]")) form.removeAttribute("aria-busy");
  for (const btn of $$<HTMLButtonElement>("button[data-busy-disabled]")) {
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    delete btn.dataset["busyDisabled"];
  }
}

// ---------- Live pages ----------

const fastPoll = 4000;
const slowPoll = 60000;
let pollTimer = 0;

function currentStamp(): string | null {
  return $<HTMLMetaElement>('meta[name="tlswatch-stamp"]')?.content ?? null;
}

function setStamp(stamp: string): void {
  const meta = $<HTMLMetaElement>('meta[name="tlswatch-stamp"]');
  if (meta !== null) meta.content = stamp;
}

function schedulePoll(ms: number): void {
  if (currentStamp() === null) return;
  window.clearTimeout(pollTimer);
  pollTimer = window.setTimeout(() => void poll(), ms);
}

// A refresh must never throw away what the user is doing: typing, a
// selection, an open menu, a request in flight or unsaved input.
function canRefresh(): boolean {
  if ($("details.menu[open]") !== null || $('[aria-busy="true"]') !== null) return false;
  const sel = window.getSelection();
  if (sel !== null && !sel.isCollapsed) return false;
  const active = document.activeElement;
  if (active instanceof HTMLElement && active.closest("input, textarea, select") !== null && active.closest("#main") !== null) return false;
  for (const el of $$<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>("#main input, #main textarea, #main select")) {
    if (el.form === null || el.form.method !== "post") continue;
    if (el instanceof HTMLSelectElement) {
      if (Array.from(el.options).some((o) => o.selected !== o.defaultSelected)) return false;
    } else if (el instanceof HTMLInputElement && (el.type === "checkbox" || el.type === "radio")) {
      if (el.checked !== el.defaultChecked) return false;
    } else if (el.value !== el.defaultValue) {
      return false;
    }
  }
  return true;
}

async function poll(): Promise<void> {
  if (document.hidden) return; // resumed by visibilitychange
  let busy = false;
  try {
    const reply = await api<{ stamp: string; busy: boolean }>("GET", "/api/v1/stamp");
    busy = reply.busy;
    if (reply.stamp !== currentStamp()) {
      if (canRefresh()) await refreshPage();
      else busy = true; // try again soon
    }
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      window.location.reload(); // the session ended: show the sign-in page
      return;
    }
  }
  schedulePoll(busy ? fastPoll : slowPoll);
}

// refreshPage swaps in a fresh render of the current URL (which carries the
// live filter, the open row and the selected finding). The request is marked
// so it does not count as activity for the session idle timeout.
async function refreshPage(): Promise<void> {
  let res: Response;
  try {
    res = await fetch(window.location.href, { credentials: "same-origin", headers: { Accept: "text/html", "X-Tlswatch-Refresh": "1" } });
  } catch {
    return; // offline for a moment; the next poll tries again
  }
  if (!res.ok || res.redirected) {
    window.location.reload();
    return;
  }
  const doc = new DOMParser().parseFromString(await res.text(), "text/html");
  const main = doc.querySelector("#main");
  const top = doc.querySelector("header.top");
  const stamp = doc.querySelector<HTMLMetaElement>('meta[name="tlswatch-stamp"]')?.content;
  const curMain = $("#main");
  const curTop = $("header.top");
  if (main === null || top === null || stamp === undefined || curMain === null || curTop === null) {
    window.location.reload();
    return;
  }
  curTop.replaceWith(document.adoptNode(top));
  // Snapshot first: adopting a node removes it from the live childNodes list.
  const nodes = Array.from(main.childNodes);
  curMain.replaceChildren(...nodes.map((n) => document.adoptNode(n)));
  document.title = doc.title;
  setStamp(stamp);
  initPage();
}

async function adoptStamp(): Promise<void> {
  try {
    const reply = await api<{ stamp: string; busy: boolean }>("GET", "/api/v1/stamp");
    setStamp(reply.stamp);
    schedulePoll(reply.busy ? fastPoll : slowPoll);
  } catch {
    // The next regular poll catches up.
  }
}

// ---------- Clickable rows ----------

// The row a row link belongs to: its own tr or list item, never a row of an
// outer table (the certificate detail row holds a nested table).
function linkRowOf(el: Element): HTMLElement | null {
  return el.closest<HTMLElement>("tr, .li");
}

function rowLink(row: HTMLElement): HTMLAnchorElement | null {
  return $$<HTMLAnchorElement>("a[data-row-link]", row).find((a) => linkRowOf(a) === row) ?? null;
}

// Selecting text in a row (a fingerprint, a host name) is not a click on it.
function selectingIn(row: HTMLElement): boolean {
  const sel = window.getSelection();
  return sel !== null && !sel.isCollapsed && sel.anchorNode !== null && row.contains(sel.anchorNode);
}

function followRowLink(link: HTMLAnchorElement, newTab: boolean): void {
  if (newTab) {
    window.open(link.href, "_blank", "noopener");
    return;
  }
  link.click();
}

function closePanel(panel: HTMLElement): void {
  panel.hidden = true;
  panel.innerHTML = "";
  for (const row of $$("tr.sel")) row.classList.remove("sel");
  for (const btn of $$("a[data-panel].btn-primary")) btn.classList.remove("btn-primary");
  const url = new URL(window.location.href);
  url.searchParams.delete("sel");
  window.history.replaceState(null, "", url.toString());
}

// A field the user has changed; Escape must not throw that input away.
function isEdited(el: EventTarget | null): boolean {
  return (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) && el.value !== el.defaultValue;
}

function isTyping(el: EventTarget | null): boolean {
  return el instanceof HTMLElement && (el.isContentEditable || el.closest("input, textarea, select") !== null);
}

// ---------- Wiring ----------

function isInteractive(el: Element | null): boolean {
  return el !== null && el.closest("a, button, input, select, textarea, label, summary, form") !== null;
}

onReady(() => {
  document.addEventListener("click", (ev) => {
    const target = ev.target;
    if (!(target instanceof Element)) return;

    const copyBtn = target.closest<HTMLElement>("[data-copy], [data-copy-url]");
    if (copyBtn !== null) {
      ev.preventDefault();
      void handleCopy(copyBtn);
      return;
    }

    const kept = target.closest<HTMLAnchorElement>("[data-keep-filter] a[href], a[href][data-keep-filter]");
    if (kept !== null) keepFilter(kept);

    const chip = target.closest<HTMLElement>("[data-chip-group] [data-chip-key]");
    if (chip !== null && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey) {
      ev.preventDefault();
      handleChip(chip);
      return;
    }

    const panelLink = target.closest<HTMLAnchorElement>("a[data-panel]");
    if (panelLink !== null && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey) {
      ev.preventDefault();
      void openPanel(panelLink);
      return;
    }

    const testBtn = target.closest<HTMLButtonElement>("button[data-test-url]");
    if (testBtn !== null) {
      ev.preventDefault();
      void runTest(testBtn);
      return;
    }

    const closer = target.closest<HTMLElement>("[data-panel-close]");
    const panel = closer?.closest<HTMLElement>(".panel");
    if (closer !== null && panel !== null && panel !== undefined && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey) {
      ev.preventDefault();
      closePanel(panel);
      return;
    }

    const chipFor = target.closest<HTMLAnchorElement>("a[data-chip-for]");
    if (chipFor !== null && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey) {
      const key = CSS.escape(chipFor.dataset["chipKey"] ?? "");
      const value = CSS.escape(chipFor.dataset["chipValue"] ?? "");
      const match = $<HTMLElement>(`[data-chip-group="${chipFor.dataset["chipFor"] ?? ""}"] [data-chip-key="${key}"][data-chip-value="${value}"]`);
      if (match !== null) {
        ev.preventDefault();
        if (!match.classList.contains("on")) handleChip(match);
        return;
      }
    }

    const linkRow = linkRowOf(target);
    if (linkRow !== null && !isInteractive(target) && !selectingIn(linkRow)) {
      const link = rowLink(linkRow);
      if (link !== null) {
        followRowLink(link, ev.metaKey || ev.ctrlKey || ev.shiftKey);
        return;
      }
    }

    const row = target.closest<HTMLTableRowElement>("tr[data-expand]");
    if (row !== null && !isInteractive(target)) {
      toggleRow(row);
    }

    for (const menu of $$<HTMLDetailsElement>("details.menu[open]")) {
      if (!menu.contains(target)) menu.open = false;
    }
  });

  // Middle click on a row opens its link in a new tab, as on a link.
  document.addEventListener("auxclick", (ev) => {
    const target = ev.target;
    if (ev.button !== 1 || !(target instanceof Element)) return;
    const kept = target.closest<HTMLAnchorElement>("[data-keep-filter] a[href], a[href][data-keep-filter]");
    if (kept !== null) keepFilter(kept);
    if (isInteractive(target)) return;
    const row = linkRowOf(target);
    const link = row !== null ? rowLink(row) : null;
    if (link !== null) {
      ev.preventDefault();
      followRowLink(link, true);
    }
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      const menus = $$<HTMLDetailsElement>("details.menu[open]");
      for (const menu of menus) {
        menu.open = false;
        $("summary", menu)?.focus();
      }
      // A side panel closes too, unless the focused field holds unsaved input.
      const panel = $<HTMLElement>(".panel:not([hidden]):has([data-panel-close])");
      if (menus.length === 0 && panel !== null && !isEdited(ev.target)) closePanel(panel);
      return;
    }
    if (ev.key === "/" && !ev.metaKey && !ev.ctrlKey && !ev.altKey && !isTyping(ev.target)) {
      const filter = $<HTMLInputElement>("input[data-filter], form[role=search] input[type=search]");
      if (filter !== null) {
        ev.preventDefault();
        filter.focus();
        filter.select();
      }
      return;
    }
    const target = ev.target;
    if ((ev.key === "Enter" || ev.key === " ") && target instanceof HTMLTableRowElement && target.dataset["expand"] !== undefined) {
      ev.preventDefault();
      toggleRow(target);
    }
  });

  document.addEventListener("submit", (ev) => {
    const form = ev.target;
    if (!(form instanceof HTMLFormElement)) return;
    const question = form.dataset["confirm"];
    if (question !== undefined && !window.confirm(question)) {
      ev.preventDefault();
      return;
    }
    const submitter = ev.submitter instanceof HTMLElement ? ev.submitter : null;
    // Return to the list as it is filtered now, without a selected row.
    const next = $<HTMLInputElement>('input[name="next"][data-follow-url]', form);
    if (next !== null) {
      const here = new URL(window.location.href);
      here.searchParams.delete("sel");
      next.value = here.pathname + here.search;
    }
    if (form.dataset["api"] === undefined) {
      if (form.method !== "post") return;
      if (form.getAttribute("aria-busy") === "true") {
        ev.preventDefault(); // already on its way
        return;
      }
      markSubmitting(form, submitter);
      return;
    }
    ev.preventDefault();
    void submitApiForm(form, submitter);
  });

  window.addEventListener("pageshow", (ev) => {
    if (ev.persisted) clearSubmitting();
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) schedulePoll(0);
  });

  // The port follows the protocol: a port that is empty or still the old
  // protocol's default changes to the new default; a custom port is kept.
  document.addEventListener("change", (ev) => {
    const sel = ev.target;
    if (!(sel instanceof HTMLSelectElement) || sel.dataset["portFor"] === undefined) return;
    const port = $<HTMLInputElement>(sel.dataset["portFor"]);
    const next = sel.selectedOptions[0]?.dataset["port"];
    if (port === null || next === undefined) return;
    const prev = sel.dataset["prevPort"] ?? "";
    if (port.value.trim() === "" || port.value.trim() === prev) port.value = next;
    port.placeholder = next;
    sel.dataset["prevPort"] = next;
  });

  document.addEventListener("change", (ev) => {
    const box = ev.target;
    if (!(box instanceof HTMLInputElement) || box.type !== "checkbox") return;
    if (box.dataset["selectAll"] !== undefined) {
      selectAll(box);
      return;
    }
    const table = box.name === "id" ? box.closest<HTMLElement>("table[id]") : null;
    if (table !== null) updateBulk(`#${table.id}`);
  });

  document.addEventListener("input", (ev) => {
    const input = ev.target;
    if (input instanceof HTMLInputElement && input.dataset["filter"] !== undefined) {
      applyFilter(input.dataset["filter"], true);
    }
  });

  initPage();
  schedulePoll(2000);
});

// initPage sets up what the server-rendered content needs; it runs again
// after a live refresh swapped the content.
function initPage(): void {
  for (const sel of $$<HTMLSelectElement>("select[data-port-for]")) {
    sel.dataset["prevPort"] = sel.selectedOptions[0]?.dataset["port"] ?? "";
  }

  // Expandable rows are keyboard reachable.
  for (const row of $$<HTMLTableRowElement>("tr[data-expand]")) {
    row.tabIndex = 0;
    if (!row.hasAttribute("aria-expanded")) {
      const detail = row.nextElementSibling;
      row.setAttribute("aria-expanded", detail instanceof HTMLElement && !detail.hidden ? "true" : "false");
    }
  }

  // Apply the server-rendered chip selection and filter text.
  const tables = new Set<string>();
  for (const el of $$("input[data-filter]")) tables.add(el.dataset["filter"] ?? "");
  for (const el of $$("[data-chip-group]")) tables.add(el.dataset["chipGroup"] ?? "");
  for (const el of $$("[data-select-all]")) tables.add(el.dataset["selectAll"] ?? "");
  for (const sel of tables) if (sel !== "") applyFilter(sel, false);
}
