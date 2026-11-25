import { useCallback, useEffect, useState } from "react";
import { ApiError, api, status } from "../api";
import { useOneTime } from "../onetime";
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
  const [totpRequired, setTotpRequired] = useState(false);
  const [pending, setPending] = useState<null | ((token: string) => Promise<void>)>(null);
  // where a pending step-up's failure must land — carried with the operation
  // at issue time, never inferred from which drawer happens to be open
  const [pendingSink, setPendingSink] = useState<"mint" | null>(null);
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
    setMintError("");
    setConfirm(null);
    try {
      const body = mintKeyBody(form);
      setPendingSink("mint");
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
          setMintError("");
          setMinting(false);
          await load();
        } finally {
          setBusy(false);
        }
      });
    } catch (err) {
      setMintError(err instanceof KeyFormError ? err.message : "invalid form");
    }
  };

  const closeMint = () => {
    setMintError("");
    setMinting(false);
    // an open step-up belongs to the drawer that launched it: closing the
    // drawer cancels it (ConfirmStepUp's unmount flag withholds any token)
    setPending(null);
    setPendingSink(null);
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
      <div className="row">
        <div>
          <h1 className="page-title">Keys</h1>
          <p className="page-sub">
            Agent credentials. The full token is shown at mint and can be re-revealed later with a
            step-up.
          </p>
        </div>
        <span className="row-end" />
        <Button
          label="Mint key"
          variant="primary"
          disabled={busy || minting}
          onClick={() => {
            setForm(BLANK);
            setMintError("");
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
          {/* the whole form goes inert while a step-up is open: neither dialog
              traps focus, so a live form behind the overlay could re-run mint
              with a label edited behind the prompt */}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void mint();
            }}
          >
            <fieldset className="stack" disabled={pending !== null}>
            {mintError ? <Notice kind="error">{mintError}</Notice> : null}
            <TextField
              label="Label"
              value={form.label}
              onChange={(next) => setForm((prev) => ({ ...prev, label: next }))}
              hint="Every key can read and modify all items — mint sparingly and set an expiry."
              autoFocus
            />
            <TextField
              label="Expires (optional)"
              value={form.expiresAt}
              onChange={(next) => setForm((prev) => ({ ...prev, expiresAt: next }))}
              hint="ISO 8601 or a date input; blank means no expiry"
            />
            <div className="row">
              <Button label="Mint key" variant="primary" type="submit" disabled={busy} />
              <Button label="Cancel" variant="ghost" onClick={closeMint} />
            </div>
            </fieldset>
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
            setPendingSink(null);
            setConfirm(null);
          }}
          onToken={async (token) => {
            const run = pending;
            const sink = pendingSink;
            setPending(null);
            setPendingSink(null);
            try {
              await run(token);
            } catch (err) {
              // the sink is decided at issue time: a mint failure lands in the
              // drawer it came from, everything else is a page-level notice
              const message = err instanceof ApiError ? err.message : "action failed";
              if (sink === "mint") setMintError(message);
              else setError(message);
            }
          }}
        />
      ) : null}
    </>
  );
}