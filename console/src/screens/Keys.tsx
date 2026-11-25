import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, status } from "../api";
import { revealCredential, showCredential } from "../onetime";
import { Button, Notice, TextField } from "../components/Field";
import { ConfirmStepUp } from "../components/ConfirmStepUp";
import { Drawer } from "../components/Drawer";
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
  // mint-form errors live only inside the drawer; page-level `error` stays
  // for inventory/status/step-up failures so the two never masquerade
  const [mintError, setMintError] = useState("");
  const [busy, setBusy] = useState(false);
  // the mint form lives in a drawer opened from the page header button
  const [minting, setMinting] = useState(false);
  // read-at-failure-time view of the same fact: a mint that fails AFTER the
  // operator closed the drawer must surface on the page, not inside it
  const drawerOpen = useRef(false);
  const [mintBusy, setMintBusy] = useState(false);
  const [totpRequired, setTotpRequired] = useState(false);
  const [pending, setPending] = useState<null | ((token: string) => Promise<void>)>(null);
  const [confirm, setConfirm] = useState<null | { title: string; message: string }>(null);
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

  // mint and reveal trust the login (rev 39): no step-up, just the session.
  // `mintBusy` is deliberately separate from the row-action `busy`: a mint
  // left in flight after the drawer closes must not disable the inventory.
  const mint = async () => {
    setMintError("");
    setError("");
    let body: Record<string, unknown>;
    try {
      body = mintKeyBody(form);
    } catch (err) {
      setMintError(err instanceof KeyFormError ? err.message : "invalid form");
      return;
    }
    setMintBusy(true);
    try {
      const data = await api<MintedKey>("POST", "/api/admin/keys", body);
      // store it above the screens: a sidebar click must not destroy it;
      // key_id in `about` keeps distinct mints from colliding in the queue
      showCredential("agent-key", { token: data.token, about: credentialAbout(data) });
      setForm(BLANK);
      setMintError("");
      drawerOpen.current = false; // dismissed programmatically: keep the ref honest
      setMinting(false);
      await load();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "mint failed";
      // the drawer may have been closed while the request was in flight
      if (drawerOpen.current) setMintError(message);
      else setError(message);
    } finally {
      setMintBusy(false);
    }
  };

  const closeMint = () => {
    // closing mid-flight is safe: the result lands in the global one-time
    // panel regardless of this drawer (a failure then surfaces on the page)
    drawerOpen.current = false;
    setMintError("");
    setMinting(false);
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

  const reveal = async (row: KeyRow) => {
    // never touch `confirm`: a Delete step-up may be armed, and wiping its
    // title/message would hide what the password prompt is about to do
    setError("");
    setBusy(true);
    try {
      await revealCredential("agent-key", row.key_id, credentialAbout(row));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "reveal failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="row">
        <div>
          <h1 className="page-title">Keys</h1>
          <p className="page-sub">
            Agent credentials. The full token is shown at mint and can be re-revealed from the
            inventory.
          </p>
        </div>
        <span className="row-end" />
        <Button
          label="Mint key"
          variant="primary"
          disabled={mintBusy || minting || pending !== null}
          onClick={() => {
            setForm(BLANK);
            setMintError("");
            setError("");
            drawerOpen.current = true;
            setMinting(true);
          }}
        />
      </div>
      {error ? <Notice kind="error">{error}</Notice> : null}
      {minting ? (
        <Drawer
          title="Mint a key"
          meta="Full-authority agent credential"
          onClose={closeMint}
        >
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              void mint();
            }}
          >
            {mintError ? <Notice kind="error">{mintError}</Notice> : null}
            <TextField
              label="Label"
              value={form.label}
              onChange={(next) => setForm((prev) => ({ ...prev, label: next }))}
              hint="Every key can read and modify all items — mint sparingly and set an expiry."
              disabled={mintBusy}
              autoFocus
            />
            <TextField
              label="Expires (optional)"
              value={form.expiresAt}
              onChange={(next) => setForm((prev) => ({ ...prev, expiresAt: next }))}
              hint="ISO 8601 or a date input; blank means no expiry"
              disabled={mintBusy}
            />
            <div className="row">
              <Button label="Mint key" variant="primary" type="submit" disabled={mintBusy} />
              <Button label="Cancel" variant="ghost" onClick={closeMint} />
            </div>
          </form>
        </Drawer>
      ) : null}
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
                        onClick={() => void reveal(row)}
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