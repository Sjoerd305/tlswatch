import { test } from "node:test";
import assert from "node:assert/strict";
import { compareValues, order, nextSort, setSortParams } from "../static/js/sort.js";

test("compareValues orders numbers by value and texts case-insensitively", () => {
  assert.ok(compareValues("9", "10", true, false) < 0);
  assert.ok(compareValues("9", "10", false, false) > 0);
  assert.equal(compareValues("Sectigo", "sectigo", false, false), 0);
  assert.ok(compareValues("badssl", "Let's Encrypt", false, false) < 0);
});

test("compareValues reverses for descending but keeps missing values last", () => {
  assert.ok(compareValues("1", "2", true, true) > 0);
  assert.ok(compareValues(null, "2", true, false) > 0);
  assert.ok(compareValues(null, "2", true, true) > 0);
  assert.ok(compareValues("2", null, true, true) < 0);
  assert.equal(compareValues(null, null, true, true), 0);
});

test("order keeps equal rows in their rendered order", () => {
  assert.deepEqual(order(["48", null, "728", "48", "-1"], true, false), [4, 0, 3, 2, 1]);
  assert.deepEqual(order(["48", null, "728", "48", "-1"], true, true), [2, 0, 3, 4, 1]);
  assert.deepEqual(order(["b", "A", "a"], false, false), [1, 2, 0]);
});

test("nextSort flips the active column and starts another ascending", () => {
  assert.deepEqual(nextSort({ key: "days", desc: false }, "days"), { key: "days", desc: true });
  assert.deepEqual(nextSort({ key: "days", desc: true }, "days"), { key: "days", desc: false });
  assert.deepEqual(nextSort({ key: "days", desc: true }, "name"), { key: "name", desc: false });
});

test("setSortParams leaves the default order without parameters", () => {
  const p = new URLSearchParams("q=badssl&sort=name&dir=desc");
  setSortParams(p, { key: "days", desc: false }, "days");
  assert.equal(p.toString(), "q=badssl");
  setSortParams(p, { key: "days", desc: true }, "days");
  assert.equal(p.toString(), "q=badssl&sort=days&dir=desc");
  setSortParams(p, { key: "name", desc: false }, "days");
  assert.equal(p.toString(), "q=badssl&sort=name");
});
