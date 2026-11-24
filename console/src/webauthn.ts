// WebAuthn JSON ⇄ binary helpers (the server speaks JSON). React-free and
// shared by the Login (assertion) and Settings (registration) screens.

export type PublicKeyCredentialRequestOptionsJSON = {
  challenge: string;
  allowCredentials?: { id: string; type: "public-key" }[];
  userVerification?: UserVerificationRequirement;
  rpId?: string;
  timeout?: number;
};

export type PublicKeyCredentialCreationOptionsJSON = {
  challenge: string;
  rp: { name: string; id?: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  excludeCredentials?: { id: string; type: "public-key" }[];
  timeout?: number;
  // `attestation` / `hints` / `extensions` are also emitted by the server's
  // options_to_json_dict; intentionally not forwarded — the server always
  // requests attestation="none" and sets no hints/extensions (rev 37).
};

function b64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const raw = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToB64url(bytes: ArrayBuffer): string {
  const view = new Uint8Array(bytes);
  let raw = "";
  for (const byte of view) raw += String.fromCharCode(byte);
  return btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function decodeRequestOptions(
  json: PublicKeyCredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: b64urlToBytes(json.challenge),
    ...(json.allowCredentials
      ? {
          allowCredentials: json.allowCredentials.map((c) => ({
            id: b64urlToBytes(c.id),
            type: c.type,
          })),
        }
      : {}),
    ...(json.userVerification ? { userVerification: json.userVerification } : {}),
    ...(json.rpId ? { rpId: json.rpId } : {}),
    ...(json.timeout ? { timeout: json.timeout } : {}),
  };
}

export function decodeCreateOptions(
  json: PublicKeyCredentialCreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  return {
    challenge: b64urlToBytes(json.challenge),
    rp: json.rp,
    user: { ...json.user, id: b64urlToBytes(json.user.id) },
    pubKeyCredParams: json.pubKeyCredParams,
    ...(json.authenticatorSelection
      ? { authenticatorSelection: json.authenticatorSelection }
      : {}),
    ...(json.excludeCredentials
      ? {
          excludeCredentials: json.excludeCredentials.map((c) => ({
            id: b64urlToBytes(c.id),
            type: c.type,
          })),
        }
      : {}),
    ...(json.timeout ? { timeout: json.timeout } : {}),
  };
}

export function encodeAttestation(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(response.clientDataJSON),
      attestationObject: bytesToB64url(response.attestationObject),
      ...(typeof response.getTransports === "function"
        ? { transports: response.getTransports() }
        : {}),
    },
  };
}

export function encodeAssertion(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(response.clientDataJSON),
      authenticatorData: bytesToB64url(response.authenticatorData),
      signature: bytesToB64url(response.signature),
      ...(response.userHandle
        ? { userHandle: bytesToB64url(response.userHandle) }
        : {}),
    },
  };
}