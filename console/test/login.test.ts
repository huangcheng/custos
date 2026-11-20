import assert from "node:assert/strict";
import test from "node:test";
import {
  LoginInputError,
  deviceCodeFromHash,
  loginPayload,
  displayTransferCode,
  setupPayload,
} from "../src/login.ts";

test("loginPayload never sends both TOTP and recovery code", () => {
  assert.throws(
    () => loginPayload({ username: "u", password: "p", totp: "123456", recoveryCode: "ABCD" }),
    LoginInputError,
  );
});

test("loginPayload omits empty factors", () => {
  assert.deepEqual(loginPayload({ username: "u", password: "p" }), {
    username: "u",
    password: "p",
  });
});

test("loginPayload carries one factor and the turnstile token", () => {
  assert.deepEqual(
    loginPayload({ username: "u", password: "p", totp: "123456", turnstile: "tt" }),
    { username: "u", password: "p", totp: "123456", turnstile: "tt" },
  );
  assert.deepEqual(loginPayload({ username: "u", password: "p", recoveryCode: "CODE" }), {
    username: "u",
    password: "p",
    recovery_code: "CODE",
  });
});

test("deviceCodeFromHash parses and rejects", () => {
  assert.equal(deviceCodeFromHash("#abc123"), "abc123");
  assert.equal(deviceCodeFromHash("#"), null);
  assert.equal(deviceCodeFromHash(""), null);
  assert.equal(deviceCodeFromHash("#   "), null);
  assert.equal(deviceCodeFromHash("abc"), "abc");
});

test("displayTransferCode never alters a base64url code", () => {
  // '-' and '_' are real characters: any formatting must preserve them.
  const code = "ab-cd_efghij";
  assert.equal(displayTransferCode(code), code);
  assert.equal(displayTransferCode(""), "");
});

test("setupPayload names the setup code field", () => {
  assert.deepEqual(setupPayload("op", "cu-test-password-12ch", "sc"), {
    username: "op",
    password: "cu-test-password-12ch",
    setup_code: "sc",
  });
});
