import assert from "node:assert/strict";
import test from "node:test";
import {
  KeyFormError,
  auditQuery,
  credentialAbout,
  expiryLabel,
  mintKeyBody,
  revealBlocker,
  scopeSummary,
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
  assert.equal(
    credentialAbout({ label: "l", mode: "read", key_id: "abcdef012345" }),
    "l · read · abcdef012345",
  );
  assert.equal(credentialAbout({ label: "l", key_id: "abcdef012345" }), "l · abcdef012345");
});

test("mintKeyBody splits scopes and omits blank expiry", () => {
  const body = mintKeyBody({
    label: "cu-test-agent",
    mode: "read-write",
    scopes: "aliyun  stock-*,db-*",
    expiresAt: "",
  });
  assert.deepEqual(body, {
    label: "cu-test-agent",
    mode: "read-write",
    scopes: ["aliyun", "stock-*", "db-*"],
  });
});

test("mintKeyBody accepts an empty scope list as no access", () => {
  const body = mintKeyBody({ label: "x", mode: "read", scopes: "  ", expiresAt: "" });
  assert.deepEqual(body.scopes, []);
});

test("mintKeyBody rejects a blank label", () => {
  assert.throws(() => mintKeyBody({ label: " ", mode: "read", scopes: "*", expiresAt: "" }), KeyFormError);
});

test("mintKeyBody normalizes an expiry to ISO", () => {
  const body = mintKeyBody({
    label: "x",
    mode: "read",
    scopes: "*",
    expiresAt: "2027-01-01T00:00:00Z",
  });
  assert.equal(body.expires_at, "2027-01-01T00:00:00.000Z");
});

test("mintKeyBody rejects a past expiry", () => {
  assert.throws(
    () => mintKeyBody({ label: "x", mode: "read", scopes: "*", expiresAt: "2020-01-01T00:00:00Z" }),
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

test("scopeSummary handles wildcard, empty, and lists", () => {
  assert.equal(scopeSummary({ scopes: ["*"] }), "*");
  assert.equal(scopeSummary({ scopes: [] }), "no access");
  assert.equal(scopeSummary({ scopes: ["a", "b-*"] }), "a, b-*");
});
