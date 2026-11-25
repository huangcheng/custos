// Key-mint form ⇄ API body (§6, rev 38). Kept React-free for unit tests.
// Every key has full item-plane authority: no mode, no scopes.

export type KeyForm = {
  label: string;
  expiresAt: string;
};

export class KeyFormError extends Error {}

function futureIso(raw: string, what: string): string {
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) throw new KeyFormError(`${what} is not a valid date`);
  // Reject a past date client-side: the server's expiry gate runs AFTER the
  // single-use step-up is consumed, so a typo would cost a password prompt.
  if (parsed.getTime() <= Date.now()) throw new KeyFormError(`${what} must be in the future`);
  return parsed.toISOString();
}

export function mintKeyBody(form: KeyForm): Record<string, unknown> {
  const label = form.label.trim();
  if (label.length === 0) throw new KeyFormError("label is required");
  if (label.length > 200) throw new KeyFormError("label must be 200 characters or fewer");
  const body: Record<string, unknown> = { label };
  const expires = form.expiresAt.trim();
  if (expires) body.expires_at = futureIso(expires, "expiry");
  return body;
}

// Shared credential-row display logic (Keys + Settings tokens): one source
// for enablement, tooltip, and the expiry cell so they cannot drift.
export const isExpired = (expiresAt: string | null | undefined): boolean =>
  typeof expiresAt === "string" && new Date(expiresAt).getTime() <= Date.now();

export function credentialAbout(c: { label: string; key_id: string }): string {
  return `${c.label} · ${c.key_id}`;
}


export function revealBlocker(row: {
  has_secret?: boolean;
  expires_at: string | null;
}): string | undefined {
  if (row.has_secret === false) return "not recoverable — revoke and re-mint";
  if (isExpired(row.expires_at)) return "expired — revoke and re-mint";
  return undefined;
}

export function expiryLabel(row: {
  revoked_at?: string | null;
  expires_at: string | null;
}): string {
  if (row.revoked_at) return "revoked";
  if (typeof row.expires_at !== "string") return "never";
  return isExpired(row.expires_at) ? "expired" : row.expires_at.slice(0, 10);
}

export function tokenExpiryBody(form: { label: string; allowSensitive: boolean; expiresAt: string }): Record<string, unknown> {
  const label = form.label.trim();
  if (label.length === 0) throw new KeyFormError("label is required");
  if (!form.expiresAt.trim()) throw new KeyFormError("operator tokens require an expiry");
  if (label.length > 200) throw new KeyFormError("label must be 200 characters or fewer");
  return {
    label,
    allow_sensitive: form.allowSensitive,
    expires_at: futureIso(form.expiresAt, "expiry"),
  };
}

export type AuditFilters = {
  actor?: string;
  action?: string;
  item?: string;
  from?: string;
  to?: string;
  cursor?: string | null;
  limit?: number;
};

export function auditQuery(filters: AuditFilters): string {
  const query = new URLSearchParams();
  for (const key of ["actor", "action", "item", "from", "to"] as const) {
    const value = filters[key]?.trim();
    if (value) query.set(key, value);
  }
  query.set("limit", String(filters.limit ?? 50));
  if (filters.cursor) query.set("cursor", filters.cursor);
  return query.toString();
}