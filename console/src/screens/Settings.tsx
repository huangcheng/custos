import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { revealCredential, showCredential, useOneTime } from "../onetime";
import { Button, Notice, TextField } from "../components/Field";
import { ConfirmStepUp } from "../components/ConfirmStepUp";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { IconKeys } from "../components/icons";
import {
  KeyFormError,
  credentialAbout,
  expiryLabel,
  revealBlocker,
  tokenExpiryBody,
} from "../keys";
import { decodeCreateOptions, encodeAttestation, type PublicKeyCredentialCreationOptionsJSON } from "../webauthn";
import { truncate } from "../plain";
import { QrCode } from "../components/QrCode";
import type {
  AuthStatus,
  MintedToken,
  PasskeyRow,
  RekeyResult,
  RetentionCounts,
  TokenRow,
  VerifyResult,
} from "../types";

type Tab = "account" | "tokens" | "maintenance";

const TABS: { id: Tab; label: string }[] = [
  { id: "account", label: "Account" },
  { id: "tokens", label: "Operator tokens" },
  { id: "maintenance", label: "Maintenance" },
];

export function Settings({
  status,
  onSignOut,
  onStatusChanged,
}: {
  status: AuthStatus;
  onSignOut: () => void;
  /** Re-fetch auth/status after a TOTP/passkey change (the banners and the
   *  step-up prompt both depend on totp_required). */
  onStatusChanged: () => void;
}) {
  const [tab, setTab] = useState<Tab>("account");
  return (
    <>
      <PageHeader
        kicker="Operator"
        title="Settings"
        lede="Account security, operator tokens, and maintenance."
      />
      <div className="segment" role="group" aria-label="Settings section">
        {TABS.map(({ id, label }) => (
          <button key={id} type="button" aria-pressed={tab === id} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>
      {tab === "account" ? (
        <Account
          status={status}
          onSignOut={onSignOut}
          onStatusChanged={onStatusChanged}
        />
      ) : null}
      {tab === "tokens" ? <Tokens totpRequired={status.totp_required} /> : null}
      {tab === "maintenance" ? (
        <Maintenance totpRequired={status.totp_required} />
      ) : null}
    </>
  );
}

function Account({
  status,
  onSignOut,
  onStatusChanged,
}: {
  status: AuthStatus;
  onSignOut: () => void;
  onStatusChanged: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const oneTime = useOneTime();
  const [passkeys, setPasskeys] = useState<PasskeyRow[]>([]);
  // two-phase registration (mirrors TOTP setup/confirm): each server call
  // consumes its own single-use step-up token
  const [pkCred, setPkCred] = useState<PublicKeyCredential | null>(null);
  const [pkLabel, setPkLabel] = useState("");
  const [pending, setPending] = useState<null | ((token: string) => Promise<void>)>(null);
  const [totpSecret, setTotpSecret] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [totpCode, setTotpCode] = useState("");

  // GET /api/auth/passkeys is step-up gated, so listing is an explicit action
  // (one token) rather than a mount-time fetch that would always 401.
  const loadPasskeys = useCallback((token: string) => {
    if (!status.passkey_configured) return;
    void api<{ passkeys: PasskeyRow[] }>("GET", "/api/auth/passkeys", undefined, {
      stepUpToken: token,
    })
      .then((data) => setPasskeys(data.passkeys))
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "cannot load passkeys");
      });
  }, [status.passkey_configured]);



  const changePassword = () => {
    setError("");
    setMessage("");
    // A full session needs a step-up token on password change (§5).
    setPending(() => async (token: string) => {
      const data = await api<{ recovery_codes?: string[] }>(
        "POST",
        "/api/auth/password-change",
        { current_password: current, new_password: next },
        { stepUpToken: token },
      );
      setCurrent("");
      setNext("");
      setMessage("Password changed. All other sessions were signed out.");
      if (data.recovery_codes) {
        // promotion issues fresh codes: they must survive a route change
        oneTime.show({
          kind: "recovery-codes",
          value: data.recovery_codes,
          about: "account promotion",
        });
      }
      onStatusChanged();
    });
  };

  return (
    <div className="stack">
      {error ? <Notice kind="error">{error}</Notice> : null}
      {message ? <Notice kind="ok">{message}</Notice> : null}
      <div className="card stack">
        <h2 className="card-title">Password</h2>
        <div className="form-grid cols-2">
          <TextField
            label="Current password"
            name="current-password"
            value={current}
            onChange={setCurrent}
            type="password"
            autoComplete="current-password"
          />
          <TextField
            label="New password"
            name="new-password"
            value={next}
            onChange={setNext}
            type="password"
            autoComplete="new-password"
            hint="At least 12 characters."
          />
        </div>
        <div className="form-actions">
          <Button
            label="Change password"
            variant="primary"
            onClick={() => void changePassword()}
            disabled={!current || next.length < 12}
          />
        </div>
      </div>
      <div className="card stack">
        <div className="card-head">
          <h2 className="card-title">Authenticator</h2>
          <p className="card-desc">
            {status.totp_required
              ? "TOTP is enabled. Disabling it requires a step-up."
              : "TOTP is not enabled — step-up is password-only until you enable it."}
          </p>
          <div className="row">
            <Button
              label={status.totp_required ? "Disable TOTP" : "Enable TOTP"}
              onClick={() =>
                setPending(() => async (token: string) => {
                  if (status.totp_required) {
                    await api("POST", "/api/auth/totp/disable", undefined, { stepUpToken: token });
                    setMessage("TOTP disabled.");
                    onStatusChanged();
                    return;
                  }
                  const started = await api<{ provisioning_uri: string; secret: string }>(
                    "POST",
                    "/api/auth/totp/setup",
                    undefined,
                    { stepUpToken: token },
                  );
                  oneTime.show({
                    kind: "totp-secret",
                    value: started.secret,
                    about: "Custos TOTP",
                  });
                  setTotpSecret(started.secret);
                  setTotpUri(started.provisioning_uri);
                  setMessage("Scan the QR with your authenticator, then confirm below.");
                })
              }
            />
            <Button
              label="Regenerate recovery codes"
              variant="ghost"
              onClick={() =>
                setPending(() => async (token: string) => {
                  const data = await api<{ recovery_codes: string[] }>(
                    "POST",
                    "/api/auth/recovery/regen",
                    undefined,
                    { stepUpToken: token },
                  );
                  oneTime.show({
                    kind: "recovery-codes",
                    value: data.recovery_codes,
                    about: "regenerated",
                  });
                })
              }
            />
          </div>
        </div>
        {totpSecret ? (
          <div className="panel enrol">
            {totpUri ? <QrCode value={totpUri} /> : null}
            <div className="stack">
              <p className="muted">
                Can’t scan? Enter this key manually:
              </p>
              <code className="secret-value">{totpSecret}</code>
              <TextField
                label="First code from your authenticator"
                name="totp-code"
                value={totpCode}
                onChange={setTotpCode}
                inputMode="numeric"
                autoComplete="one-time-code"
              />
              <div className="form-actions">
                <Button
                  label="Confirm and enable"
                  variant="primary"
                  disabled={totpCode.trim().length === 0}
                  onClick={() =>
                    setPending(() => async (token: string) => {
                      const data = await api<{ recovery_codes: string[] }>(
                        "POST",
                        "/api/auth/totp/confirm",
                        { code: totpCode.trim() },
                        { stepUpToken: token },
                      );
                      oneTime.show({
                        kind: "recovery-codes",
                        value: data.recovery_codes,
                        about: "TOTP enable",
                      });
                      setTotpSecret("");
                      setTotpUri("");
                      setTotpCode("");
                      setMessage("TOTP enabled.");
                      onStatusChanged();
                    })
                  }
                />
              </div>
            </div>
          </div>
        ) : null}
      </div>
      {status.passkey_configured ? (
        <div className="card stack">
          <div className="card-head">
            <h2 className="card-title">Passkeys</h2>
            <p className="card-desc">
              Register a passkey to sign in without a password; listing and removing needs a step-up.
            </p>
            <div className="row">
              <Button
                label="Register a passkey"
                onClick={() =>
                  setPending(() => async (token: string) => {
                    setError("");
                    setMessage("");
                    const options = await api<PublicKeyCredentialCreationOptionsJSON>(
                      "POST", "/api/auth/passkeys/register/options", {},
                      { stepUpToken: token },
                    );
                    let credential: PublicKeyCredential | null = null;
                    try {
                      credential = (await navigator.credentials.create({
                        publicKey: decodeCreateOptions(options),
                      })) as PublicKeyCredential | null;
                    } catch (err) {
                      const name = err instanceof Error ? err.name : "error";
                      setError(`Passkey registration failed (${name}). Try again.`);
                      return;
                    }
                    if (!credential) {
                      setError("Passkey registration was cancelled.");
                      return;
                    }
                    setPkCred(credential);
                    setMessage("Confirm the registration below (needs a fresh step-up).");
                  })
                }
              />
              <Button
                label="Show registered passkeys"
                variant="ghost"
                onClick={() =>
                  setPending(() => async (token: string) => {
                    loadPasskeys(token);
                  })
                }
              />
            </div>
          </div>
          {pkCred ? (
            <div className="panel stack">
              <TextField
                label="Passkey label"
                name="passkey-label"
                value={pkLabel}
                onChange={setPkLabel}
                hint="Shown in the list so you can tell passkeys apart."
              />
              <div className="form-actions">
                <Button
                  label="Cancel"
                  variant="ghost"
                  onClick={() => {
                    setPkCred(null);
                    setPkLabel("");
                    setMessage("");
                  }}
                />
                <Button
                  label="Confirm registration"
                  variant="primary"
                  onClick={() =>
                    setPending(() => async (token: string) => {
                      try {
                        await api(
                          "POST", "/api/auth/passkeys/register/verify",
                          {
                            ...encodeAttestation(pkCred),
                            // the server rejects labels > 100 chars AFTER
                            // consuming the single-use challenge: clamp here
                            // so a created credential is never thrown away
                            label: pkLabel.trim().slice(0, 100) || "passkey",
                          },
                          { stepUpToken: token },
                        );
                      } catch (err) {
                        // the challenge is single-use / 120 s TTL: a failed
                        // verify can never be retried with the same credential
                        setPkCred(null);
                        setPkLabel("");
                        setMessage("");
                        setError(
                          err instanceof ApiError
                            ? `${err.message} — start the registration again.`
                            : "registration failed — start again.",
                        );
                        return;
                      }
                      setPkCred(null);
                      setPkLabel("");
                      setError("");
                      setMessage("Passkey registered. Show registered passkeys to refresh.");
                      onStatusChanged();
                    })
                  }
                />
              </div>
            </div>
          ) : null}
          {passkeys.length === 0 ? (
            <p className="muted">
              No passkeys loaded (listing requires a step-up).
            </p>
          ) : (
            <ul className="list">
              {passkeys.map((pk) => (
                <li key={pk.id} className="row">
                  <span className="mono cell-main" title={pk.label}>
                    {truncate(pk.label, 32)}
                  </span>
                  <span className="row-end" />
                  <Button
                    label="Remove"
                    variant="danger"
                    onClick={() =>
                      setPending(() => async (token: string) => {
                        await api("DELETE", `/api/auth/passkeys/${pk.id}`, undefined, {
                          stepUpToken: token,
                        });
                        // the token is spent: drop the row locally instead of
                        // re-fetching with a token the server already consumed
                        setPasskeys((prev) => prev.filter((row) => row.id !== pk.id));
                      })
                    }
                  />
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
      <div className="card">
        <div className="card-head">
          <h2 className="card-title">Session</h2>
          <p className="card-desc">Signing out ends the session in this browser.</p>
          <div className="row">
            <Button label="Log out" variant="danger" onClick={onSignOut} />
          </div>
        </div>
      </div>
      {pending ? (
        <ConfirmStepUp
          totpRequired={status.totp_required}
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
    </div>
  );
}

function Tokens({ totpRequired }: { totpRequired: boolean }) {
  const [rows, setRows] = useState<TokenRow[]>([]);
  // an empty inventory and a not-yet-loaded one must not look the same, and a
  // failed fetch must not read as an empty one
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [label, setLabel] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [allowSensitive, setAllowSensitive] = useState(false);
  const [error, setError] = useState("");
  // `busy` belongs to the per-row reveal/revoke actions; a mint in flight
  // must not disable them (and vice versa)
  const [busy, setBusy] = useState(false);
  const [minting, setMinting] = useState(false);
  const [pending, setPending] = useState<null | ((token: string) => Promise<void>)>(null);

  const load = useCallback(async () => {
    try {
      const data = await api<{ tokens: TokenRow[] }>("GET", "/api/admin/tokens");
      setLoadFailed(false);
      setRows(data.tokens);
    } catch (err) {
      setLoadFailed(true);
      setError(err instanceof ApiError ? err.message : "cannot load tokens");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // rev 39: mint and reveal trust the login — no step-up
  const mint = async () => {
    setError("");
    let body: Record<string, unknown>;
    try {
      body = tokenExpiryBody({ label, allowSensitive, expiresAt });
    } catch (err) {
      setError(err instanceof KeyFormError ? err.message : "invalid form");
      return;
    }
    setMinting(true);
    try {
      const data = await api<MintedToken>("POST", "/api/admin/tokens", body);
      showCredential("operator-token", { token: data.token, about: credentialAbout(data) });
      setLabel("");
      setExpiresAt("");
      setAllowSensitive(false);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "mint failed");
    } finally {
      setMinting(false);
    }
  };

  const reveal = async (row: TokenRow) => {
    setError("");
    setBusy(true);
    try {
      await revealCredential("operator-token", row.key_id, credentialAbout(row));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "reveal failed");
    } finally {
      setBusy(false);
    }
  };

  // an inventory that has not loaded yet must never read as empty
  const emptyInventory = () => {
    if (loading) return <EmptyState title="Loading tokens…" />;
    if (loadFailed) return <EmptyState title="Cannot load operator tokens" />;
    return <EmptyState mark={<IconKeys size={22} />} title="No operator tokens" />;
  };

  return (
    <div className="stack">
      {error ? <Notice kind="error">{error}</Notice> : null}
      {/* inert while the mint POST is in flight: the form resets on success,
          and nothing typed behind the request should be silently dropped */}
      <fieldset className="stack" disabled={minting}>
        <div className="card stack">
          <h2 className="card-title">Mint an operator token</h2>
          <div className="form-grid cols-2">
            <TextField label="Label" name="token-label" value={label} onChange={setLabel} />
            <TextField
              label="Expires"
              name="token-expires"
              value={expiresAt}
              onChange={setExpiresAt}
              hint="Required. Max 30 days when sensitive."
            />
          </div>
          <label className="check">
            <input
              type="checkbox"
              name="token-sensitive"
              checked={allowSensitive}
              onChange={(event) => setAllowSensitive(event.target.checked)}
            />
            <span>allow sensitive operations</span>
          </label>
          <div className="form-actions">
            <Button
              label="Mint token"
              variant="primary"
              disabled={minting}
              onClick={() => void mint()}
            />
          </div>
        </div>
      </fieldset>
      <div className="card flush">
        {rows.length === 0 ? (
          emptyInventory()
        ) : (
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Key ID</th>
                <th>Sensitive</th>
                <th>Expires</th>
                <th className="actions-cell" aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const blocker = revealBlocker(row);
                return (
                  <tr key={row.key_id}>
                    <td data-label="Label">
                      <span className="cell-main" title={row.label}>
                        {truncate(row.label, 28)}
                      </span>
                    </td>
                    <td data-label="Key ID">
                      <span className="mono">{row.key_id}</span>
                    </td>
                    <td data-label="Sensitive">
                      <span className={`pill ${row.allow_sensitive ? "accent" : ""}`}>
                        {row.allow_sensitive ? "yes" : "no"}
                      </span>
                    </td>
                    <td data-label="Expires">
                      <span className="mono muted" title={row.expires_at}>
                        {expiryLabel(row)}
                      </span>
                    </td>
                    <td className="actions-cell" data-label="">
                      {row.revoked_at ? (
                        <span className="pill">revoked</span>
                      ) : (
                        <span className="actions">
                          {/* the span carries the tooltip: disabled buttons get no pointer events */}
                          <span title={blocker}>
                            <Button
                              label="Reveal"
                              disabled={busy || blocker !== undefined}
                              onClick={() => void reveal(row)}
                            />
                          </span>
                          <Button
                            label="Revoke"
                            variant="danger"
                            disabled={busy}
                            onClick={() =>
                              setPending(() => async (token: string) => {
                                await api("DELETE", `/api/admin/tokens/${row.key_id}`, undefined, {
                                  stepUpToken: token,
                                });
                                await load();
                              })
                            }
                          />
                        </span>
                      )}
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
    </div>
  );
}

function Maintenance({ totpRequired }: { totpRequired: boolean }) {
  const [audit, setAudit] = useState<null | {
    versions: Record<string, Record<string, number>>;
    affected: Record<string, string[]>;
    newest: number;
  }>(null);
  const [counts, setCounts] = useState<RetentionCounts | null>(null);
  const [rekey, setRekey] = useState<RekeyResult | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [error, setError] = useState("");
  const [pending, setPending] = useState<null | ((token: string) => Promise<void>)>(null);

  const loadAudit = useCallback(async () => {
    try {
      const data = await api<{
        versions: Record<string, Record<string, number>>;
        affected: Record<string, string[]>;
        newest: number;
      }>("GET", "/api/admin/rekey/audit");
      setAudit(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "cannot load the rekey audit");
    }
  }, []);

  useEffect(() => {
    void loadAudit();
  }, [loadAudit]);

  const runRekey = () => {
    setPending(() => async (token: string) => {
      setError("");
      let cursor: string | undefined;
      let runToken: string | undefined = token;
      let total = 0;
      for (let i = 0; i < 200; i += 1) {
        const body: Record<string, unknown> = {};
        if (cursor) body.cursor = cursor;
        const data: RekeyResult = await api<RekeyResult>(
          "POST",
          "/api/admin/rekey",
          body,
          { stepUpToken: runToken },
        );
        total += data.skipped;
        if (data.run_token) runToken = data.run_token;
        if (data.remaining === 0) {
          setRekey({ remaining: 0, skipped: total });
          break;
        }
        // a batch that reports work left but no cursor would loop forever
        if (!data.cursor) {
          setError("rekey did not return a cursor to continue");
          break;
        }
        cursor = data.cursor;
      }
      await loadAudit();
    });
  };

  const olderRows = audit
    ? Object.values(audit.affected).reduce((total, names) => total + names.length, 0)
    : 0;
  // one sum feeds both the verdict and the sentence, so they cannot disagree
  const unreadableTotal = verify
    ? verify.unreadable.fields +
      verify.unreadable.history +
      verify.unreadable.operator +
      verify.unreadable.agent_keys +
      verify.unreadable.operator_tokens
    : 0;

  return (
    <div className="stack">
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="card stack">
        <div className="card-head">
          <h2 className="card-title">Key versions</h2>
          <p className="card-desc">
            Every encrypted row carries the keyring version it was sealed with. A rekey moves
            older rows to the newest version and reports the rows it could not read.
          </p>
          <div className="row">
            <Button label="Verify all rows" onClick={() =>
              setPending(() => async (token: string) => {
                // verify is a paged sweep: one call checks only `limit` rows
                let runToken: string | undefined = token;
                let cursor: string | undefined;
                let totals: VerifyResult["unreadable"] = {
                  fields: 0, history: 0, operator: 0, agent_keys: 0, operator_tokens: 0,
                };
                for (let i = 0; i < 500; i += 1) {
                  const body: Record<string, unknown> = {};
                  if (cursor) body.cursor = cursor;
                  const data: VerifyResult = await api<VerifyResult>(
                    "POST",
                    "/api/admin/rekey/verify",
                    body,
                    { stepUpToken: runToken },
                  );
                  totals = {
                    fields: totals.fields + data.unreadable.fields,
                    history: totals.history + data.unreadable.history,
                    operator: totals.operator + data.unreadable.operator,
                    agent_keys: totals.agent_keys + data.unreadable.agent_keys,
                    operator_tokens: totals.operator_tokens + data.unreadable.operator_tokens,
                  };
                  if (data.run_token) runToken = data.run_token;
                  if (data.remaining === 0) {
                    setVerify({ remaining: 0, unreadable: totals });
                    break;
                  }
                  if (!data.cursor) {
                    setError("verify did not return a cursor to continue");
                    break;
                  }
                  cursor = data.cursor;
                }
              })
            } />
            <Button label="Run rekey" variant="primary" onClick={runRekey} />
          </div>
        </div>
        {audit ? (
          <>
            <dl className="stats">
              <div className="stat">
                <dt>Newest version</dt>
                <dd>k{audit.newest}</dd>
              </div>
              <div className="stat">
                <dt>Domains</dt>
                <dd>{Object.keys(audit.versions).length}</dd>
              </div>
              <div className="stat">
                <dt>Items on an older version</dt>
                <dd>{olderRows}</dd>
              </div>
            </dl>
            <div className="table-inset">
              <table>
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Rows per version</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(audit.versions).map(([domain, versions]) => (
                    <tr key={domain}>
                      <td data-label="Domain">
                        <span className="mono">{domain}</span>
                      </td>
                      <td data-label="Rows per version">
                        <span className="mono">
                          {Object.keys(versions).length === 0
                            ? "—"
                            : Object.entries(versions)
                                .map(([version, count]) => `k${version}: ${count}`)
                                .join(" · ")}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {olderRows > 0 ? (
              <div className="panel stack">
                <span className="group-label">Items still under an older version</span>
                {Object.entries(audit.affected).map(([version, names]) => (
                  <p key={version} className="mono">
                    k{version}: {names.slice(0, 8).join(", ")}
                    {names.length > 8 ? ` +${names.length - 8} more` : ""}
                  </p>
                ))}
              </div>
            ) : (
              <p className="muted">
                Every row is under the newest version.
              </p>
            )}
          </>
        ) : (
          <EmptyState title={error ? "Cannot load key versions" : "Loading key versions…"} />
        )}
        {rekey ? (
          <Notice kind={rekey.skipped > 0 ? "warn" : "ok"}>
            Rekey finished: {rekey.skipped} skipped (unreadable) rows.
          </Notice>
        ) : null}
        {verify ? (
          <>
            <Notice kind={unreadableTotal > 0 ? "warn" : "ok"}>
              Verify finished: {unreadableTotal} unreadable rows.
            </Notice>
            <dl className="stats">
              <div className="stat">
                <dt>Fields</dt>
                <dd>{verify.unreadable.fields}</dd>
              </div>
              <div className="stat">
                <dt>History</dt>
                <dd>{verify.unreadable.history}</dd>
              </div>
              <div className="stat">
                <dt>Operator</dt>
                <dd>{verify.unreadable.operator}</dd>
              </div>
              <div className="stat">
                <dt>Agent keys</dt>
                <dd>{verify.unreadable.agent_keys}</dd>
              </div>
              <div className="stat">
                <dt>Operator tokens</dt>
                <dd>{verify.unreadable.operator_tokens}</dd>
              </div>
            </dl>
          </>
        ) : null}
      </div>
      <div className="card stack">
        <div className="card-head">
          <h2 className="card-title">Retention</h2>
          <p className="card-desc">
            Prunes history older than the retention window, keeping the 20 most
            recent snapshots per field. Never touches live sessions or recovery codes.
          </p>
          <div className="row">
            <Button
              label="Run retention"
              variant="danger"
              onClick={() =>
                setPending(() => async (token: string) => {
                  const data = await api<RetentionCounts>(
                    "POST",
                    "/api/admin/retention",
                    undefined,
                    { stepUpToken: token },
                  );
                  setCounts(data);
                })
              }
            />
          </div>
        </div>
        {counts ? (
          <dl className="stats">
            {Object.entries(counts).map(([table, count]) => (
              <div key={table} className="stat">
                <dt>{table}</dt>
                <dd>{count}</dd>
              </div>
            ))}
          </dl>
        ) : null}
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
    </div>
  );
}