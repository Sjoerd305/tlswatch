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
//   form[data-api="/api/v1/..."]       submitted with fetch; JSON reply
//     { html?, notice?, notice_kind?, redirect? }; html replaces the element
//     named by data-replace ("row" = closest tr, else a selector)
//   a[data-panel="#panel"][data-panel-url="/api/v1/..."]
//                                      loads { html } into the panel, marks row .sel
//   button[data-test-url="/api/v1/..."] posts its form, puts { html } in #test-result
//   details.menu                       closes on outside click and Escape
import { $, $$, api, ApiError, messages, onReady } from "./common.js";
// ---------- Notices ----------
function showNotice(text, kind = "crit") {
    const page = $(".page");
    if (page === null)
        return;
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
function errorText(err) {
    return err instanceof ApiError ? err.message : messages.unknown;
}
function setBusy(el, busy) {
    if (el === null)
        return;
    el.setAttribute("aria-busy", busy ? "true" : "false");
    if (el instanceof HTMLButtonElement)
        el.disabled = busy;
}
// ---------- Copy ----------
async function copyText(text) {
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
    if (!ok)
        throw new Error("copy failed");
}
function flashLabel(btn, text) {
    const original = btn.dataset["label"] ?? btn.textContent ?? "";
    btn.dataset["label"] = original;
    btn.textContent = text;
    window.setTimeout(() => {
        btn.textContent = original;
    }, 1200);
}
async function handleCopy(btn) {
    try {
        let text = btn.dataset["copy"];
        const url = btn.dataset["copyUrl"];
        if (url !== undefined) {
            const res = await fetch(url, { credentials: "same-origin" });
            if (!res.ok)
                throw new Error(String(res.status));
            text = await res.text();
        }
        await copyText(text ?? "");
        flashLabel(btn, messages.copied);
    }
    catch {
        flashLabel(btn, messages.copyFailed);
    }
}
// ---------- Live filter and chips ----------
function tableRows(table) {
    return $$("tbody > tr[data-search]", table);
}
function rowHasToken(row, key, value) {
    const attr = row.getAttribute(`data-${key}`);
    if (attr === null)
        return false;
    return attr.split(/\s+/).includes(value);
}
function applyFilter(tableSel, updateUrl) {
    const table = $(tableSel);
    if (table === null)
        return;
    const input = $(`input[data-filter="${tableSel}"]`);
    const query = (input?.value ?? "").trim().toLowerCase();
    const active = [];
    for (const group of $$(`[data-chip-group="${tableSel}"]`)) {
        for (const chip of $$(".chip.on[data-chip-key]", group)) {
            const key = chip.dataset["chipKey"] ?? "";
            const value = chip.dataset["chipValue"] ?? "";
            if (key !== "" && value !== "")
                active.push([key, value]);
        }
    }
    const rows = tableRows(table);
    let shown = 0;
    for (const row of rows) {
        const text = (row.dataset["search"] ?? "").toLowerCase();
        const match = (query === "" || text.includes(query)) && active.every(([k, v]) => rowHasToken(row, k, v));
        row.hidden = !match;
        if (match)
            shown++;
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
    if (empty !== null)
        empty.hidden = shown > 0;
    if (updateUrl) {
        const url = new URL(window.location.href);
        for (const group of $$(`[data-chip-group="${tableSel}"]`)) {
            for (const chip of $$("[data-chip-key]", group))
                url.searchParams.delete(chip.dataset["chipKey"] ?? "");
        }
        for (const [k, v] of active)
            url.searchParams.set(k, v);
        if (query !== "")
            url.searchParams.set("q", query);
        else
            url.searchParams.delete("q");
        window.history.replaceState(null, "", url.toString());
    }
}
function handleChip(chip) {
    const group = chip.closest("[data-chip-group]");
    if (group === null)
        return;
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
    let target = chip;
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
function toggleRow(row) {
    const detail = row.nextElementSibling;
    if (!(detail instanceof HTMLTableRowElement) || !detail.classList.contains("detail"))
        return;
    const open = row.getAttribute("aria-expanded") !== "true";
    row.setAttribute("aria-expanded", open ? "true" : "false");
    detail.hidden = !open;
    const glyph = $(".expander", row);
    if (glyph !== null)
        glyph.textContent = open ? "▾" : "▸";
}
// ---------- API forms, panels, test probe ----------
function applyReply(reply, origin, replace) {
    if (reply === null)
        return;
    if (reply.redirect !== undefined && reply.redirect !== "") {
        window.location.assign(reply.redirect);
        return;
    }
    if (reply.html !== undefined && replace !== undefined && replace !== "") {
        const target = replace === "row" ? origin.closest("tr") : $(replace);
        if (target !== null) {
            target.outerHTML = reply.html;
            // A replaced table body may need its filters re-applied.
            for (const input of $$("input[data-filter]"))
                applyFilter(input.dataset["filter"] ?? "", false);
        }
    }
    if (reply.notice !== undefined && reply.notice !== "")
        showNotice(reply.notice, reply.notice_kind ?? "ok");
}
async function submitApiForm(form, submitter) {
    const url = form.dataset["api"] ?? "";
    const button = submitter ?? $('button[type="submit"], button:not([type])', form);
    setBusy(button, true);
    form.setAttribute("aria-busy", "true");
    try {
        const data = new FormData(form);
        if (submitter instanceof HTMLButtonElement && submitter.name !== "")
            data.set(submitter.name, submitter.value);
        const reply = await api("POST", url, data);
        applyReply(reply, form, form.dataset["replace"]);
    }
    catch (err) {
        showNotice(errorText(err));
    }
    finally {
        if (button !== null && button.isConnected)
            setBusy(button, false);
        form.removeAttribute("aria-busy");
    }
}
async function openPanel(link) {
    const panel = $(link.dataset["panel"] ?? "");
    const url = link.dataset["panelUrl"];
    if (panel === null || url === undefined) {
        window.location.assign(link.href);
        return;
    }
    link.setAttribute("aria-busy", "true");
    try {
        const reply = await api("GET", url);
        panel.innerHTML = reply.html ?? "";
        panel.hidden = false;
        const row = link.closest("tr");
        if (row !== null) {
            for (const other of $$("tr.sel", row.parentElement ?? document))
                other.classList.remove("sel");
            row.classList.add("sel");
        }
        $("input:not([type=hidden]), textarea, select, button", panel)?.focus({ preventScroll: false });
    }
    catch {
        window.location.assign(link.href);
    }
    finally {
        link.removeAttribute("aria-busy");
    }
}
async function runTest(btn) {
    const form = btn.form;
    const out = $("#test-result");
    const url = btn.dataset["testUrl"];
    if (form === null || out === null || url === undefined)
        return;
    setBusy(btn, true);
    try {
        const reply = await api("POST", url, new FormData(form));
        out.innerHTML = reply.html ?? "";
        out.hidden = false;
    }
    catch (err) {
        showNotice(errorText(err));
    }
    finally {
        setBusy(btn, false);
    }
}
// ---------- Wiring ----------
function isInteractive(el) {
    return el !== null && el.closest("a, button, input, select, textarea, label, summary, form") !== null;
}
onReady(() => {
    document.addEventListener("click", (ev) => {
        const target = ev.target;
        if (!(target instanceof Element))
            return;
        const copyBtn = target.closest("[data-copy], [data-copy-url]");
        if (copyBtn !== null) {
            ev.preventDefault();
            void handleCopy(copyBtn);
            return;
        }
        const chip = target.closest("[data-chip-group] [data-chip-key]");
        if (chip !== null && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey) {
            ev.preventDefault();
            handleChip(chip);
            return;
        }
        const panelLink = target.closest("a[data-panel]");
        if (panelLink !== null && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey) {
            ev.preventDefault();
            void openPanel(panelLink);
            return;
        }
        const testBtn = target.closest("button[data-test-url]");
        if (testBtn !== null) {
            ev.preventDefault();
            void runTest(testBtn);
            return;
        }
        const row = target.closest("tr[data-expand]");
        if (row !== null && !isInteractive(target)) {
            toggleRow(row);
        }
        for (const menu of $$("details.menu[open]")) {
            if (!menu.contains(target))
                menu.open = false;
        }
    });
    document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape") {
            for (const menu of $$("details.menu[open]")) {
                menu.open = false;
                $("summary", menu)?.focus();
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
        if (!(form instanceof HTMLFormElement) || form.dataset["api"] === undefined)
            return;
        ev.preventDefault();
        const submitter = ev.submitter instanceof HTMLElement ? ev.submitter : null;
        void submitApiForm(form, submitter);
    });
    // The port follows the protocol: a port that is empty or still the old
    // protocol's default changes to the new default; a custom port is kept.
    document.addEventListener("change", (ev) => {
        const sel = ev.target;
        if (!(sel instanceof HTMLSelectElement) || sel.dataset["portFor"] === undefined)
            return;
        const port = $(sel.dataset["portFor"]);
        const next = sel.selectedOptions[0]?.dataset["port"];
        if (port === null || next === undefined)
            return;
        const prev = sel.dataset["prevPort"] ?? "";
        if (port.value.trim() === "" || port.value.trim() === prev)
            port.value = next;
        port.placeholder = next;
        sel.dataset["prevPort"] = next;
    });
    document.addEventListener("input", (ev) => {
        const input = ev.target;
        if (input instanceof HTMLInputElement && input.dataset["filter"] !== undefined) {
            applyFilter(input.dataset["filter"], true);
        }
    });
    for (const sel of $$("select[data-port-for]")) {
        sel.dataset["prevPort"] = sel.selectedOptions[0]?.dataset["port"] ?? "";
    }
    // Expandable rows are keyboard reachable.
    for (const row of $$("tr[data-expand]")) {
        row.tabIndex = 0;
        if (!row.hasAttribute("aria-expanded")) {
            const detail = row.nextElementSibling;
            row.setAttribute("aria-expanded", detail instanceof HTMLElement && !detail.hidden ? "true" : "false");
        }
    }
    // Initial state: apply the server-rendered chip selection and filter text.
    const tables = new Set();
    for (const el of $$("input[data-filter]"))
        tables.add(el.dataset["filter"] ?? "");
    for (const el of $$("[data-chip-group]"))
        tables.add(el.dataset["chipGroup"] ?? "");
    for (const sel of tables)
        if (sel !== "")
            applyFilter(sel, false);
});
