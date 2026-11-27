import assert from "node:assert/strict";
import test from "node:test";
import { MASK, maskSecret, stamp, truncate } from "../src/plain.ts";

test("truncate keeps short text and shortens long text", () => {
  assert.equal(truncate("abc", 10), "abc");
  assert.equal(truncate("abcdefghij", 5), "abcd…");
});

test("maskSecret returns the shared mask", () => {
  assert.equal(maskSecret(), MASK);
  assert.equal(MASK, "••••••");
});

test("stamp renders an ISO-8601 UTC timestamp as a column stamp", () => {
  assert.equal(stamp("2026-11-27T08:15:30.123456+00:00"), "2026-11-27 08:15:30");
  assert.equal(stamp(""), "—");
  assert.equal(stamp(undefined), "—");
});
