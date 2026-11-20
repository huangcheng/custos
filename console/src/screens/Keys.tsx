import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { Button, Notice, TextField } from "../components/Field";
import { ConfirmStepUp } from "../components/ConfirmStepUp";
import { KeyFormError, mintKeyBody, scopeSummary, type KeyForm } from "../keys";
import { truncate } from "../plain";
import type { KeyRow, MintedKey } from "../types";

const BLANK: KeyForm = { label: "", mode: "read", scopes: "*", expiresAt: "" };

export function Keys({ onSignOut }: { onSignOut: () => void }) {
  const [rows, setRows] = useState<KeyRow[]>([]);
  const [form, setForm] = useState<KeyForm>(BLANK);
  const [minted, setMinted] = useState<MintedKey | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [totpRequired, setTotpRequired] = useState(false);
  const [pending, setPending] = useState<null | ((token: string) => Promise<void>)>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api<{ keys: KeyRow[] }>("GET", "/api/admin/keys");
      setRows(data.keys);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onSignOut();
        return;
      }
      setError(err instanceof ApiError ? err.message : "cannot load keys");
    }
  }, [onSignOut]);

  useEffect(() => {
    void load();
    void api<{ totp_required: boolean }>("GET", "/api/auth/status")
      .then((st) => setTotpRequired(st.totp_required))
      .catch(() => undefined);
  }, [load]);

  const mint = () => {
    setError("");
    try {
      const body = mintKeyBody(form);
      setPending(() => async (token: string) => {
        setBusy(true);
        try {
          const data = await api<MintedKey>("POST", "/api/admin/keys", body, {
            stepUpToken: token,
          });
          setMinted(data);
          setForm(BLANK);
          await load();
        } finally {
          setBusy(false);
        }
      });
    } catch (err) {
      setError(err instanceof KeyFormError ? err.message : "invalid form");
    }
  };

  const revoke = (keyId: string) => {
    setPending(() => async (token: string) => {
      await api("DELETE", `/api/admin/keys/${keyId}`, undefined, { stepUpToken: token });
      await load();
    });
  };

  return (
    <>
      <h1 className="page-title">Keys</h1>
      <p className="page-sub">
        Agent credentials. The full token is shown once — store it before you close this page.
      </p>
      {error ? <Notice kind="error">{error}</Notice> : null}
      {minted ? (
        <div className="card stack">
          <Notice kind="warn">
            This is the only time the token is shown. Copy it now.
          </Notice>
          <label>
            <span>{minted.label} · {minted.mode}</span>
            <input className="mono" readOnly value={minted.token} />
          </label>
          <div className="row">
            <Button
              label={copied ? "Copied" : "Copy token"}
              variant="primary"
              onClick={() => {
                // clipboard is undefined outside a secure context: the throw is
                // synchronous, so it never reaches .catch
                const clipboard = navigator.clipboard;
                if (!clipboard) {
                  setError("clipboard unavailable — select the text and copy");
                  return;
                }
                clipboard
                  .writeText(minted.token)
                  .then(() => setCopied(true))
                  .catch(() => setError("clipboard unavailable — select the text and copy"));
              }}
            />
            <Button
              label="Done"
              variant="ghost"
              onClick={() => {
                setMinted(null);
                setCopied(false);
              }}
            />
          </div>
        </div>
      ) : null}
      <div className="card stack">
        <h2 className="page-sub" style={{ margin: 0 }}>
          Mint a key
        </h2>
        <div className="row">
          <TextField
            label="Label"
            value={form.label}
            onChange={(next) => setForm((prev) => ({ ...prev, label: next }))}
          />
          <label>
            <span>Mode</span>
            <select
              value={form.mode}
              onChange={(event) =>
                setForm((prev) => ({ ...prev, mode: event.target.value as KeyForm["mode"] }))
              }
            >
              <option value="read">read</option>
              <option value="read-write">read-write</option>
            </select>
          </label>
        </div>
        <TextField
          label="Scopes"
          value={form.scopes}
          onChange={(next) => setForm((prev) => ({ ...prev, scopes: next }))}
          hint="Space or comma separated patterns, e.g. aliyun stock-* — empty means no access"
        />
        <TextField
          label="Expires (optional)"
          value={form.expiresAt}
          onChange={(next) => setForm((prev) => ({ ...prev, expiresAt: next }))}
          hint="ISO 8601 or a date input; blank means no expiry"
        />
        <div className="row">
          <Button label="Mint key" variant="primary" onClick={mint} disabled={busy} />
        </div>
      </div>
      <div className="card" style={{ padding: 0, marginTop: 16 }}>
        {rows.length === 0 ? (
          <div className="empty">No keys yet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Key ID</th>
                <th>Mode</th>
                <th>Scopes</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key_id}>
                  <td title={row.label}>{truncate(row.label, 28)}</td>
                  <td className="mono">{row.key_id}</td>
                  <td>
                    <span className={`pill ${row.mode === "read-write" ? "accent" : ""}`}>
                      {row.mode}
                    </span>
                  </td>
                  <td className="mono">{scopeSummary(row)}</td>
                  <td className="mono muted">
                    {row.revoked_at ? "revoked" : (row.expires_at?.slice(0, 10) ?? "never")}
                  </td>
                  <td>
                    {row.revoked_at ? null : (
                      <Button
                        label="Revoke"
                        variant="danger"
                        onClick={() => revoke(row.key_id)}
                        disabled={busy}
                      />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {pending ? (
        <ConfirmStepUp
          totpRequired={totpRequired}
          onCancel={() => setPending(null)}
          onToken={async (token) => {
            const run = pending;
            setPending(null);
            try {
              await run(token);
            } catch (err) {
              setError(err instanceof ApiError ? err.message : "action failed");
            }
          }}
        />
      ) : null}
    </>
  );
}