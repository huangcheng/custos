// API response types (design §6). Field shapes mirror the server exactly —
// the console renders only what the API returns (no invented telemetry).

export type AuthStatus = {
  setup_required: boolean;
  totp_required: boolean;
  turnstile_sitekey: string | null;
  /** WebAuthn configured AND ≥1 registered credential — the login shortcut
   *  can succeed; gate "Use a passkey" on this, never on configuration. */
  passkey_available: boolean;
  /** WebAuthn configured (regardless of registrations) — gates the Settings
   *  management section so the first passkey can be registered. */
  passkey_configured: boolean;
  /** ≥1 unconsumed recovery code — gates the recovery fallback/toggle. */
  recovery_available: boolean;
  csrf_token?: string;
};

export type Field = {
  name: string;
  secret: boolean;
  value?: string;
  unavailable?: boolean;
};

export type Item = {
  name: string;
  notes: string;
  revision: number;
  fields: Field[];
  deleted?: boolean;
  created?: boolean;
};

export type ListRow = {
  name: string;
  notes: string;
  revision: number;
  updated_at: string;
  fields: { name: string; secret: boolean }[];
  deleted?: boolean;
};

export type Page<T> = { items: T[]; next_cursor: string | null };

export type HistoryRow = {
  id: string;
  name: string;
  secret: boolean;
  superseded_at: string;
  superseded_by: string;
  actor_label: string;
};

export type HistorySnapshot = {
  id: string;
  name: string;
  secret: boolean;
  value: string;
  superseded_at: string;
};

export type KeyRow = {
  key_id: string;
  label: string;
  mode: "read" | "read-write";
  scopes: string[];
  expires_at: string | null;
  revoked_at?: string | null;
  created_at?: string;
  has_secret?: boolean;
};

export type MintedKey = KeyRow & { token: string };

export type TokenRow = {
  key_id: string;
  label: string;
  allow_sensitive: boolean;
  expires_at: string;
  revoked_at?: string | null;
  created_at?: string;
  has_secret?: boolean;
};

export type MintedToken = TokenRow & { token: string };

export type AuditRow = {
  id: number;
  ts: string;
  actor_kind: string;
  actor_id: string | null;
  actor_label: string;
  action: string;
  item_name: string | null;
  ok: boolean;
  detail: Record<string, unknown>;
};

export type RetentionCounts = Record<string, number>;

export type RekeyResult = {
  remaining: number;
  skipped: number;
  run_token?: string;
  cursor?: string;
};

export type VerifyResult = {
  remaining: number;
  unreadable: {
    fields: number;
    history: number;
    operator: number;
    agent_keys: number;
    operator_tokens: number;
  };
  run_token?: string;
  cursor?: string;
};

export type PasskeyRow = { id: string; label: string; created_at?: string };