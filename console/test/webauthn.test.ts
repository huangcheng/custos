import assert from "node:assert/strict";
import test from "node:test";

import {
  decodeCreateOptions,
  decodeRequestOptions,
  encodeAssertion,
  encodeAttestation,
} from "../src/webauthn.ts";

const b64u = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64url");

const buf = (...bytes: number[]): ArrayBuffer => new Uint8Array(bytes).buffer;

test("decodeRequestOptions maps challenge and allowCredentials to binary", () => {
  const opts = decodeRequestOptions({
    challenge: b64u(new Uint8Array([1, 2, 3])),
    allowCredentials: [{ id: b64u(new Uint8Array([9, 8])), type: "public-key" }],
    userVerification: "required",
    rpId: "localhost",
    timeout: 60000,
  });
  assert.deepEqual(new Uint8Array(opts.challenge as ArrayBuffer), new Uint8Array([1, 2, 3]));
  assert.deepEqual(
    new Uint8Array(opts.allowCredentials![0]!.id as ArrayBuffer),
    new Uint8Array([9, 8]),
  );
  assert.equal(opts.userVerification, "required");
  assert.equal(opts.rpId, "localhost");
  assert.equal(opts.timeout, 60000);
});

test("decodeCreateOptions decodes user.id and excludeCredentials, keeps rp", () => {
  const opts = decodeCreateOptions({
    challenge: b64u(new Uint8Array([4, 5])),
    rp: { name: "Custos", id: "localhost" },
    user: { id: b64u(new Uint8Array([7])), name: "operator", displayName: "operator" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    excludeCredentials: [{ id: b64u(new Uint8Array([6])), type: "public-key" }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  assert.deepEqual(new Uint8Array(opts.challenge as ArrayBuffer), new Uint8Array([4, 5]));
  assert.deepEqual(new Uint8Array(opts.user.id as ArrayBuffer), new Uint8Array([7]));
  assert.equal(opts.user.name, "operator");
  assert.deepEqual(opts.rp, { name: "Custos", id: "localhost" });
  assert.deepEqual(
    new Uint8Array(opts.excludeCredentials![0]!.id as ArrayBuffer),
    new Uint8Array([6]),
  );
  assert.equal(opts.authenticatorSelection?.residentKey, "required");
});

test("encodeAttestation round-trips binary fields and optional transports", () => {
  const cred = {
    id: "cred-id",
    rawId: buf(1, 2),
    type: "public-key",
    response: {
      clientDataJSON: buf(3, 4),
      attestationObject: buf(5, 6),
      getTransports: () => ["usb"],
    },
  } as unknown as PublicKeyCredential;
  const out = encodeAttestation(cred) as {
    id: string;
    rawId: string;
    response: { clientDataJSON: string; attestationObject: string; transports?: string[] };
  };
  assert.equal(out.id, "cred-id");
  assert.equal(out.rawId, b64u(new Uint8Array([1, 2])));
  assert.equal(out.response.clientDataJSON, b64u(new Uint8Array([3, 4])));
  assert.equal(out.response.attestationObject, b64u(new Uint8Array([5, 6])));
  assert.deepEqual(out.response.transports, ["usb"]);
  // no getTransports → no transports key (older authenticators)
  const bare = {
    id: "x",
    rawId: buf(1),
    type: "public-key",
    response: { clientDataJSON: buf(2), attestationObject: buf(3) },
  } as unknown as PublicKeyCredential;
  const bareOut = encodeAttestation(bare) as { response: Record<string, unknown> };
  assert.equal("transports" in bareOut.response, false);
});

test("encodeAssertion round-trips signature and optional userHandle", () => {
  const cred = {
    id: "a",
    rawId: buf(1),
    type: "public-key",
    response: {
      clientDataJSON: buf(2),
      authenticatorData: buf(3),
      signature: buf(4),
      userHandle: buf(5),
    },
  } as unknown as PublicKeyCredential;
  const out = encodeAssertion(cred) as { response: Record<string, string> };
  assert.equal(out.response.signature, b64u(new Uint8Array([4])));
  assert.equal(out.response.userHandle, b64u(new Uint8Array([5])));
  const noHandle = {
    id: "a",
    rawId: buf(1),
    type: "public-key",
    response: { clientDataJSON: buf(2), authenticatorData: buf(3), signature: buf(4) },
  } as unknown as PublicKeyCredential;
  const out2 = encodeAssertion(noHandle) as { response: Record<string, unknown> };
  assert.equal("userHandle" in out2.response, false);
});