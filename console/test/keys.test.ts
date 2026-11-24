import assert from "node:assert/strict";
import test from "node:test";
import {
  KeyFormError,
  auditQuery,
  credentialAbout,
  expiryLabel,
  mintKeyBody,
  revealBlocker,
  tokenExpiryBody,
} from "../src/keys.ts";

test("revealBlocker refuses legacy and expired rows, allows live ones", () => {
  const future = new Date(Date.now() + 86400_000).toISOString();
  const past = new Date(Date.now() - 86400_000).toISOString();
  assert.equal(revealBlocker({ has_secret: true, expires_at: future }), undefined);
  assert.equal(revealBlocker({ has_secret: true, expires_at: null }), undefined);
  assert.match(revealBlocker({ has_secret: false, expires_at: future }) ?? "", /not recoverable/);
  assert.match(revealBlocker({ has_secret: true, expires_at: past }) ?? "", /expired/);
  // legacy wins over expired (both refuse; the reason is the storage gap)
  assert.match(revealBlocker({ has_secret: false, expires_at: past }) ?? "", /not recoverable/);
});

test("expiryLabel keeps revoked/expired/date/never distinct", () => {
  const future = new Date(Date.now() + 86400_000).toISOString();
  const past = new Date(Date.now() - 86400_000).toISOString();
  assert.equal(expiryLabel({ revoked_at: "2026-01-01T00:00:00Z", expires_at: future }), "revoked");
  assert.equal(expiryLabel({ expires_at: past }), "expired");
  assert.equal(expiryLabel({ expires_at: future }), future.slice(0, 10));
  assert.equal(expiryLabel({ expires_at: null }), "never");
});

test("credentialAbout is one formatter for mint and reveal queue identity", () => {
  assert.equal(credentialAbout({ label: "l", key_id: "abcdef012345" }), "l · abcdef012345");
});

test("mintKeyBody carries only label (+ optional expiry): full-authority keys", () => {
  const body = mintKeyBody({ label: "cu-test-agent", expiresAt: "" });
  assert.deepEqual(body, { label: "cu-test-agent" });
});

test("mintKeyBody never emits mode or scopes (rev 38)", () => {
  const body = mintKeyBody({ label: "x", expiresAt: "" });
  assert.equal("mode" in body, false);
  assert.equal("scopes" in body, false);
});

test("mintKeyBody rejects a blank label", () => {
  assert.throws(() => mintKeyBody({ label: " ", expiresAt: "" }), KeyFormError);
});

test("mintKeyBody normalizes an expiry to ISO", () => {
  const body = mintKeyBody({ label: "x", expiresAt: "2027-01-01T00:00:00Z" });
  assert.equal(body.expires_at, "2027-01-01T00:00:00.000Z");
});

test("mintKeyBody rejects a past expiry", () => {
  assert.throws(
    () => mintKeyBody({ label: "x", expiresAt: "2020-01-01T00:00:00Z" }),
    KeyFormError,
  );
});

test("tokenExpiryBody rejects a past expiry and an over-long label", () => {
  assert.throws(
    () =>
      tokenExpiryBody({
        label: "x",
        allowSensitive: false,
        expiresAt: "2020-01-01T00:00:00Z",
      }),
    KeyFormError,
  );
  assert.throws(
    () =>
      tokenExpiryBody({
        label: "x".repeat(201),
        allowSensitive: false,
        expiresAt: "2099-01-01T00:00:00Z",
      }),
    KeyFormError,
  );
});

test("tokenExpiryBody requires an expiry", () => {
  assert.throws(() => tokenExpiryBody({ label: "x", allowSensitive: false, expiresAt: "" }), KeyFormError);
});

test("auditQuery only includes non-empty filters", () => {
  assert.equal(
    auditQuery({ actor: "abc", action: "", item: "  ", from: "", to: "", limit: 50 }),
    "actor=abc&limit=50",
  );
  const withCursor = auditQuery({ action: "key.mint", limit: 100, cursor: "c1" });
  assert.equal(withCursor, "action=key.mint&limit=100&cursor=c1");
});
