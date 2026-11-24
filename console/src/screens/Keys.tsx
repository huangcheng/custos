import { useCallback, useEffect, useState } from "react";
import { ApiError, api, status } from "../api";
import { useOneTime } from "../onetime";
import { Button, Notice, TextField } from "../components/Field";
import { ConfirmStepUp } from "../components/ConfirmStepUp";
import {
  KeyFormError,
  credentialAbout,
  expiryLabel,
  mintKeyBody,
  revealBlocker,
  type KeyForm,
} from "../keys";
import { truncate } from "../plain";
import type { KeyRow, MintedKey } from "../types";

const BLANK: KeyForm = { label: "", expiresAt: "" };

export function Keys({ onSignOut }: { onSignOut: () => void }) {
  const [rows, setRows] = useState<KeyRow[]>([]);
  const [form, setForm] = useState<KeyForm>(BLANK);

  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [totpRequired, setTotpRequired] = useState(false);
  const [pending, setPending] = useState<null | ((token: string) => Promise<void>)>(null);
  const [confirm, setConfirm] = useState<null | { title: string; message: string }>(null);
  const oneTime = useOneTime();

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
    void status()
      .then((st) => setTotpRequired(st.totp_required))
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "cannot read auth status");
      });
  }, [load]);

  const mint = () => {
    setError("");
    setConfirm(null);
    try {
      const body = mintKeyBody(form);
      setPending(() => async (token: string) => {
        setBusy(true);
        try {
          const data = await api<MintedKey>("POST", "/api/admin/keys", body, {
            stepUpToken: token,
          });
          // store it above the screens: a sidebar click must not destroy it;
          // key_id in `about` keeps distinct mints from colliding in the queue
          oneTime.show({
            kind: "agent-key",
            value: data.token,
            about: credentialAbout(data),
            retrievable: true,
          });
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
    setConfirm({
      title: "Delete key",
      message:
        "This permanently destroys the key and its sealed secret. Any agent using it " +
        "loses access immediately, and the only way back is to mint a new key.",
    });
    setPending(() => async (token: string) => {
      await api("DELETE", `/api/admin/keys/${keyId}`, undefined, { stepUpToken: token });
      await load();
    });
  };

  const reveal = (row: KeyRow) => {
    setConfirm(null);
    setError("");
    setPending(() => async (token: string) => {
      setBusy(true);
      try {
        const data = await api<{ token: string }>(
          "GET", `/api/admin/keys/${row.key_id}/reveal`, undefined, { stepUpToken: token },
        );
        oneTime.show({
          kind: "agent-key",
          value: data.token,
          about: credentialAbout(row),
          retrievable: true,
        });
      } finally {
        setBusy(false);
      }
    });
  };

  return (
    <>
      <h1 className="page-title">Keys</h1>
      <p className="page-sub">
        Agent credentials. The full token is shown at mint and can be re-revealed later with a
        step-up.
      </p>
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="card stack">
        <h2 className="page-sub" style={{ margin: 0 }}>
          Mint a key
        </h2>
        <TextField
          label="Label"
          value={form.label}
          onChange={(next) => setForm((prev) => ({ ...prev, label: next }))}
          hint="Every key can read and modify all items — mint sparingly and set an expiry."
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
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const blocker = revealBlocker(row);
                return (
                <tr key={row.key_id}>
                  <td title={row.label}>{truncate(row.label, 28)}</td>
                  <td className="mono">{row.key_id}</td>
                  <td className="mono muted" title={row.expires_at ?? undefined}>
                    {expiryLabel(row)}
                  </td>
                  <td>
                    {/* the span carries the tooltip: disabled buttons get no pointer events */}
                    <span title={blocker}>
                      <Button
                        label="Reveal"
                        onClick={() => reveal(row)}
                        disabled={busy || blocker !== undefined}
                      />
                    </span>{" "}
                    <Button
                      label="Delete"
                      variant="danger"
                      onClick={() => revoke(row.key_id)}
                      disabled={busy}
                    />
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {pending ? (
        <ConfirmStepUp
          totpRequired={totpRequired}
          title={confirm?.title}
          message={confirm?.message}
          onCancel={() => {
            setPending(null);
            setConfirm(null);
          }}
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