// Key-mint form ⇄ API body (§6). Kept React-free for unit tests.

export type KeyForm = {
  label: string;
  mode: "read" | "read-write";
  scopes: string;
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
  const scopes = form.scopes
    .split(/[\s,]+/)
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
  const body: Record<string, unknown> = {
    label,
    mode: form.mode,
    scopes, // empty array means "no access" (fail closed, §5)
  };
  const expires = form.expiresAt.trim();
  if (expires) body.expires_at = futureIso(expires, "expiry");
  return body;
}

export function scopeSummary(key: { scopes: string[] }): string {
  if (key.scopes.length === 0) return "no access";
  if (key.scopes.includes("*")) return "*";
  return key.scopes.join(", ");
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