import { test } from "node:test";
import assert from "node:assert/strict";
import { daysLeft, shortFingerprint, formatFingerprint, parseTags, lifetimePercent } from "../static/js/format.js";

const DAY = 86_400_000;
const now = new Date("2026-10-14T04:17:00Z");

test("daysLeft truncates to whole days", () => {
  assert.equal(daysLeft(new Date(now.getTime() + 30 * DAY), now), 30);
  assert.equal(daysLeft(new Date(now.getTime() + 30 * DAY - 1000), now), 29);
  assert.equal(daysLeft(new Date(now.getTime() + DAY - 1), now), 0);
  assert.equal(daysLeft(now, now), 0);
});

test("daysLeft is negative once expired", () => {
  assert.equal(daysLeft(new Date(now.getTime() - 1000), now), -1);
  assert.equal(daysLeft(new Date(now.getTime() - 3 * DAY), now), -3);
});

test("shortFingerprint takes 8 lowercase hex characters", () => {
  assert.equal(shortFingerprint("7F3B92A10C4E5D6F"), "7f3b92a1");
  assert.equal(shortFingerprint("7F:3B:92:A1:0C:4E"), "7f3b92a1");
  assert.equal(shortFingerprint(""), "");
});

test("formatFingerprint pairs uppercase hex with colons", () => {
  assert.equal(formatFingerprint("7f3b92a1"), "7F:3B:92:A1");
  assert.equal(formatFingerprint("7f3"), "7F:3");
  assert.equal(formatFingerprint(""), "");
});

test("parseTags splits, lowercases, dedupes and drops long tags", () => {
  assert.deepEqual(parseTags("customer:Example-Co, internal  sip,internal"), ["customer:example-co", "internal", "sip"]);
  assert.deepEqual(parseTags(" , ,"), []);
  assert.deepEqual(parseTags("a".repeat(40) + " " + "b".repeat(41)), ["a".repeat(40)]);
});

test("lifetimePercent clamps to 0..100", () => {
  const nb = new Date(now.getTime() - 90 * DAY);
  const na = new Date(now.getTime() + 10 * DAY);
  assert.equal(lifetimePercent(nb, na, now), 90);
  assert.equal(lifetimePercent(now, na, new Date(now.getTime() - DAY)), 0);
  assert.equal(lifetimePercent(nb, na, new Date(na.getTime() + DAY)), 100);
  assert.equal(lifetimePercent(na, nb, now), 100);
});
