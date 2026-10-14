import { test } from "node:test";
import assert from "node:assert/strict";
import { loadInto, loadFailed } from "../static/js/load.js";

function element(url) {
  const classes = new Set(["muted"]);
  return {
    dataset: url === undefined ? {} : { loadUrl: url },
    innerHTML: "…",
    textContent: "…",
    classList: { remove: (c) => classes.delete(c), has: (c) => classes.has(c) },
  };
}

test("loadInto fills the element once from its URL", async () => {
  const el = element("/api/v1/certificates/ab/chain");
  const calls = [];
  const fetchHTML = async (url) => {
    calls.push(url);
    return { html: "R11 → ISRG Root X1" };
  };
  await loadInto(el, fetchHTML);
  assert.equal(el.innerHTML, "R11 → ISRG Root X1");
  assert.equal(el.classList.has("muted"), false);
  assert.equal(el.dataset.loadUrl, undefined);
  await loadInto(el, fetchHTML); // expanding again does not refetch
  assert.deepEqual(calls, ["/api/v1/certificates/ab/chain"]);
});

test("loadInto keeps the URL after a failure so a retry is possible", async () => {
  const el = element("/api/v1/certificates/ab/chain");
  await loadInto(el, async () => {
    throw new Error("offline");
  });
  assert.equal(el.textContent, loadFailed);
  assert.equal(el.dataset.loadUrl, "/api/v1/certificates/ab/chain");
  await loadInto(el, async () => ({ html: "ok" }));
  assert.equal(el.innerHTML, "ok");
});

test("loadInto ignores elements without a URL", async () => {
  const el = element(undefined);
  await loadInto(el, async () => assert.fail("fetched"));
  assert.equal(el.innerHTML, "…");
});
