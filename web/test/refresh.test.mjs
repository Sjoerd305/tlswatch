import { test } from "node:test";
import assert from "node:assert/strict";
import { refresh } from "../static/js/refresh.js";

// A fake browser: the fetch resolves when the test says so, so the test can
// act "during the request".
function browser(opts = {}) {
  let release;
  const state = {
    url: opts.url ?? "/targets?status=warning",
    swapped: [],
    reloads: 0,
    searchMismatch: false,
    page: "page" in opts ? opts.page : { ok: true, redirected: false, html: "<main id=main>fresh</main>" },
  };
  const io = {
    url: () => state.url,
    fetchPage: () => new Promise((resolve) => (release = () => resolve(state.page))),
    searchMismatch: () => state.searchMismatch,
    swap: (html) => {
      state.swapped.push(html);
      return true;
    },
    reload: () => state.reloads++,
  };
  return { io, state, arrive: () => release() };
}

// Wait until the pending fetch has been awaited, so release() lands in the
// awaiting code.
const settle = () => new Promise((r) => setTimeout(r, 0));

test("a render that arrives while nothing changed is swapped in", async () => {
  const b = browser();
  const done = refresh(b.io, () => true);
  await settle();
  b.arrive();
  assert.equal(await done, "swapped");
  assert.deepEqual(b.state.swapped, ["<main id=main>fresh</main>"]);
});

test("a selection made while the render was in flight is kept: the render is dropped", async () => {
  const b = browser();
  let ticked = false;
  const safe = () => !ticked;
  assert.equal(safe(), true); // the caller's check before fetching passes
  const done = refresh(b.io, safe);
  await settle();
  ticked = true; // the user ticks a target's checkbox during the round trip
  b.arrive();
  assert.equal(await done, "skipped");
  assert.deepEqual(b.state.swapped, []);
  assert.equal(b.state.reloads, 0);
});

test("a render for an older URL or filter text is dropped", async () => {
  const b = browser();
  const done = refresh(b.io, () => true);
  await settle();
  b.state.url = "/targets?status=critical";
  b.arrive();
  assert.equal(await done, "skipped");

  const c = browser();
  const done2 = refresh(c.io, () => true);
  await settle();
  c.state.searchMismatch = true;
  c.arrive();
  assert.equal(await done2, "skipped");
  assert.deepEqual(c.state.swapped, []);
});

test("a failed or redirected render reloads the page; an unreachable server waits for the next poll", async () => {
  const b = browser({ page: { ok: false, redirected: false, html: "" } });
  const done = refresh(b.io, () => true);
  await settle();
  b.arrive();
  assert.equal(await done, "reloaded");
  assert.equal(b.state.reloads, 1);

  const c = browser({ page: null });
  const done2 = refresh(c.io, () => true);
  await settle();
  c.arrive();
  assert.equal(await done2, "skipped");
  assert.equal(c.state.reloads, 0);
});
