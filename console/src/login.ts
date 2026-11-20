// Login logic kept free of React so it can be unit-tested under node:test
// (§5: at most one second factor; a TOTP code supplied while TOTP is disabled
// is ignored by the server, but the console never sends both).

export class LoginInputError extends Error {}

export type LoginForm = {
  username: string;
  password: string;
  totp?: string;
  recoveryCode?: string;
  turnstile?: string;
};

export function loginPayload(form: LoginForm): Record<string, string> {
  if (form.totp && form.recoveryCode) {
    throw new LoginInputError("use either a TOTP code or a recovery code");
  }
  const body: Record<string, string> = {
    username: form.username,
    password: form.password,
  };
  if (form.totp) body.totp = form.totp;
  if (form.recoveryCode) body.recovery_code = form.recoveryCode;
  if (form.turnstile) body.turnstile = form.turnstile;
  return body;
}

/** `/device#<code>` → the code, or null. Never mutates the argument. */
export function deviceCodeFromHash(hash: string): string | null {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const code = raw.trim();
  return code.length > 0 ? code : null;
}

/** Display form for a transfer code. Deliberately verbatim: the code is
 *  base64url, so `-` and `_` are real characters and no inserted separator
 *  can be distinguished from one. The operator copies it, never retypes it. */
export function displayTransferCode(code: string): string {
  return code;
}

export function setupPayload(
  username: string,
  password: string,
  setupCode: string,
): Record<string, string> {
  return { username, password, setup_code: setupCode };
}