import assert from "node:assert/strict";
import test from "node:test";
import { MASK, maskSecret, truncate } from "../src/plain.ts";

test("truncate keeps short text and shortens long text", () => {
  assert.equal(truncate("abc", 10), "abc");
  assert.equal(truncate("abcdefghij", 5), "abcd…");
});

test("maskSecret returns the shared mask", () => {
  assert.equal(maskSecret(), MASK);
  assert.equal(MASK, "••••••");
});
