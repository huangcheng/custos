// Thin fetch wrapper (design §3): the session cookie rides automatically, the
// CSRF token lives in module memory only (never localStorage), and a 401
// recovers the token from GET /api/auth/status exactly once.
//
// Deliberate: no retry loop. A second 401 is surfaced so the caller can send
// the operator back to login instead of spinning.

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

import type { AuthStatus } from "./types";

let csrfToken = "";

export function setCsrf(token: string): void {
  csrfToken = token;
}

/** In-memory CSRF token; empty when there is no live session (§3: never
 *  persisted — a reload recovers it from auth/status instead). */
export function getCsrf(): string {
  return csrfToken;
}

export type RequestOptions = {
  ifMatch?: string;
  stepUpToken?: string;
  signal?: AbortSignal;
};

async function raw(
  method: string,
  path: string,
  body: unknown,
  opts: RequestOptions,
): Promise<Response> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["x-csrf-token"] = csrfToken;
  if (opts.ifMatch) headers["if-match"] = `"${opts.ifMatch.replaceAll('"', "")}"`;
  if (opts.stepUpToken) headers["x-step-up-token"] = opts.stepUpToken;
  return fetch(path, {
    method,
    headers,
    credentials: "same-origin", // never "include": no cross-origin use exists
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: opts.signal,
  });
}

async function toError(res: Response): Promise<ApiError> {
  let code = "error";
  let message = res.statusText || "request failed";
  try {
    const data = (await res.json()) as { code?: unknown; message?: unknown };
    if (typeof data.code === "string") code = data.code;
    if (typeof data.message === "string") message = data.message;
  } catch {
    // non-JSON body: keep the status text, never echo the body
  }
  return new ApiError(res.status, code, message);
}

export async function refreshCsrf(): Promise<string> {
  const res = await raw("GET", "/api/auth/status", undefined, {});
  if (!res.ok) throw await toError(res);
  const data = (await res.json()) as { csrf_token?: unknown };
  // No token means no live session: clear the stale one so a later write does
  // not replay it and so boot() cannot mistake it for an authenticated state.
  csrfToken =
    typeof data.csrf_token === "string" && data.csrf_token.length > 0
      ? data.csrf_token
      : "";
  return csrfToken;
}

// A 401 is only recoverable when it is a CSRF rejection. The console cannot
// tell that from the status alone (a wrong password is also 401), so every
// mutation carries the CSRF header and the retry is restricted to responses
// that are NOT credential verdicts. `unauthorized` with `x-csrf-token` already
// present means the token was stale; `step_up_required` means a step-up was
// missing (retrying replays the same single-use token).
const CREDENTIAL_ENDPOINTS = new Set([
  "/api/auth/login",
  "/api/auth/setup",
  "/api/auth/passkeys/assert/options",
  "/api/auth/passkeys/assert/verify",
  "/api/auth/device-exchange",
]);

export async function api<T>(
  method: string,
  path: string,
  body?: unknown,
  opts: RequestOptions = {},
): Promise<T> {
  let res = await raw(method, path, body, opts);
  if (res.status === 401 && method !== "GET") {
    const first = await toError(res);
    // A missing step-up is not a CSRF problem, and retrying it would replay the
    // same single-use token.
    if (first.code === "step_up_required") throw first;
    if (CREDENTIAL_ENDPOINTS.has(path)) {
      // These answer a WRONG PASSWORD with the same 401 `unauthorized` a stale
      // CSRF token produces, so the request must not be replayed (that would
      // burn another lockout/audit row). Refresh the token for the NEXT try and
      // surface the error as-is.
      await refreshCsrf().catch(() => undefined);
      throw first;
    }
    try {
      await refreshCsrf();
    } catch {
      throw first;
    }
    // no token means the session is gone: report the ORIGINAL error
    if (!csrfToken) throw first;
    res = await raw(method, path, body, opts);
  }
  if (!res.ok) throw await toError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// Step-up returns a single-use token (§5). The console asks for the password
// (and TOTP when enabled) through the ConfirmStepUp modal and passes it here.
export async function stepUp(
  password: string,
  factor?: { totp?: string; recoveryCode?: string },
): Promise<string> {
  const body: Record<string, string> = { password };
  if (factor?.totp) body.totp = factor.totp;
  if (factor?.recoveryCode) body.recovery_code = factor.recoveryCode;
  const data = await api<{ step_up_token: string }>("POST", "/api/auth/step-up", body);
  return data.step_up_token;
}

export async function status(): Promise<AuthStatus> {
  const data = await api<AuthStatus>("GET", "/api/auth/status");
  // A live session already returns the CSRF token here: store it so boot needs
  // exactly one request (§3 reload recovery), instead of a second status call.
  csrfToken =
    typeof data.csrf_token === "string" && data.csrf_token.length > 0
      ? data.csrf_token
      : "";
  return data;
}

export async function logout(): Promise<void> {
  await api("POST", "/api/auth/logout");
  csrfToken = "";
}