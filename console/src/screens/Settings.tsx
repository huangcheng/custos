import { useCallback, useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { revealCredential, showCredential, useOneTime } from "../onetime";
import { Button, Notice, TextField } from "../components/Field";
import { ConfirmStepUp } from "../components/ConfirmStepUp";
import {
  KeyFormError,
  credentialAbout,
  expiryLabel,
  revealBlocker,
  tokenExpiryBody,
} from "../keys";
import { decodeCreateOptions, encodeAttestation, type PublicKeyCredentialCreationOptionsJSON } from "../webauthn";
import { truncate } from "../plain";
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
      <h1 className="page-title">Settings</h1>
      <p className="page-sub">Account security, operator tokens, and maintenance.</p>
      <div className="row" style={{ marginBottom: 16 }}>
        <Button
          label="Account"
          variant={tab === "account" ? "primary" : "ghost"}
          onClick={() => setTab("account")}
        />
        <Button
          label="Operator tokens"
          variant={tab === "tokens" ? "primary" : "ghost"}
          onClick={() => setTab("tokens")}
        />
        <Button
          label="Maintenance"
          variant={tab === "maintenance" ? "primary" : "ghost"}
          onClick={() => setTab("maintenance")}
        />
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
        <h2 className="page-sub" style={{ margin: 0 }}>
          Password
        </h2>
        <TextField
          label="Current password"
          value={current}
          onChange={setCurrent}
          type="password"
          autoComplete="current-password"
        />
        <TextField
          label="New password"
          value={next}
          onChange={setNext}
          type="password"
          autoComplete="new-password"
          hint="At least 12 characters."
        />
        <div className="row">
          <Button
            label="Change password"
            variant="primary"
            onClick={() => void changePassword()}
            disabled={!current || next.length < 12}
          />
        </div>
      </div>
      <div className="card stack">
        <h2 className="page-sub" style={{ margin: 0 }}>
          Authenticator
        </h2>
        <p className="muted" style={{ margin: 0 }}>
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
                setMessage("Add this secret to your authenticator, then confirm below.");
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
        {totpSecret ? (
          <div className="card stack">
            <p className="mono" style={{ margin: 0 }}>
              secret: {totpSecret}
            </p>
            <TextField
              label="First code from your authenticator"
              value={totpCode}
              onChange={setTotpCode}
              inputMode="numeric"
              autoComplete="one-time-code"
            />
            <div className="row">
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
                    setTotpCode("");
                    setMessage("TOTP enabled.");
                    onStatusChanged();
                  })
                }
              />
            </div>
          </div>
        ) : null}
      </div>
      {status.passkey_configured ? (
        <div className="card stack">
          <h2 className="page-sub" style={{ margin: 0 }}>
            Passkeys
          </h2>
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
              onClick={() =>
                setPending(() => async (token: string) => {
                  loadPasskeys(token);
                })
              }
            />
          </div>
          {pkCred ? (
            <div className="stack">
              <TextField
                label="Passkey label"
                value={pkLabel}
                onChange={setPkLabel}
                hint="Shown in the list so you can tell passkeys apart."
              />
              <div className="row">
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
                <Button
                  label="Cancel"
                  variant="ghost"
                  onClick={() => {
                    setPkCred(null);
                    setPkLabel("");
                    setMessage("");
                  }}
                />
              </div>
            </div>
          ) : null}
          {passkeys.length === 0 ? (
            <p className="muted" style={{ margin: 0 }}>
              No passkeys loaded (listing requires a step-up).
            </p>
          ) : (
            <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {passkeys.map((pk) => (
                <li key={pk.id} className="row">
                  <span className="mono">{truncate(pk.label, 32)}</span>
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
      <div className="card stack">
        <h2 className="page-sub" style={{ margin: 0 }}>
          Session
        </h2>
        <div className="row">
          <Button label="Log out" variant="danger" onClick={onSignOut} />
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
      setRows(data.tokens);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "cannot load tokens");
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

  return (
    <div className="stack">
      {error ? <Notice kind="error">{error}</Notice> : null}
      {/* inert while the mint POST is in flight: the form resets on success,
          and nothing typed behind the request should be silently dropped */}
      <fieldset className="stack" disabled={minting}>
        <div className="card stack">
          <h2 className="page-sub" style={{ margin: 0 }}>
            Mint an operator token
          </h2>
          <div className="row">
            <TextField label="Label" value={label} onChange={setLabel} />
            <TextField
              label="Expires"
              value={expiresAt}
              onChange={setExpiresAt}
              hint="Required. Max 30 days when sensitive."
            />
            <label className="row" style={{ alignItems: "center", gap: 8 }}>
              <input
                type="checkbox"
                checked={allowSensitive}
                onChange={(event) => setAllowSensitive(event.target.checked)}
                style={{ width: 18, minHeight: 18 }}
              />
              <span>allow sensitive operations</span>
            </label>
          </div>
          <div className="row">
            <Button
              label="Mint token"
              variant="primary"
              disabled={minting}
              onClick={() => void mint()}
            />
          </div>
        </div>
      </fieldset>
      <div className="card" style={{ padding: 0 }}>
        {rows.length === 0 ? (
          <div className="empty">No operator tokens.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Key ID</th>
                <th>Sensitive</th>
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
                  <td>
                    <span className={`pill ${row.allow_sensitive ? "accent" : ""}`}>
                      {row.allow_sensitive ? "yes" : "no"}
                    </span>
                  </td>
                  <td className="mono muted" title={row.expires_at}>
                    {expiryLabel(row)}
                  </td>
                  <td>
                    {row.revoked_at ? null : (
                      <>
                        {/* the span carries the tooltip: disabled buttons get no pointer events */}
                        <span title={blocker}>
                          <Button
                            label="Reveal"
                            disabled={busy || blocker !== undefined}
                            onClick={() => void reveal(row)}
                          />
                        </span>{" "}
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
                      </>
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

  return (
    <div className="stack">
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="card stack">
        <h2 className="page-sub" style={{ margin: 0 }}>
          Key versions
        </h2>
        {audit ? (
          <>
            <p className="muted" style={{ margin: 0 }}>
              Newest version: <span className="mono">k{audit.newest}</span>
            </p>
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
                    <td className="mono">{domain}</td>
                    <td className="mono">
                      {Object.keys(versions).length === 0
                        ? "—"
                        : Object.entries(versions)
                            .map(([version, count]) => `k${version}: ${count}`)
                            .join(" · ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {Object.keys(audit.affected).length > 0 ? (
              <div className="stack">
                <span className="muted">Items still under an older version</span>
                {Object.entries(audit.affected).map(([version, names]) => (
                  <p key={version} className="mono" style={{ margin: 0 }}>
                    k{version}: {names.slice(0, 8).join(", ")}
                    {names.length > 8 ? ` +${names.length - 8} more` : ""}
                  </p>
                ))}
              </div>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                Every row is under the newest version.
              </p>
            )}
          </>
        ) : (
          <p className="muted">Loading…</p>
        )}
        <div className="row">
          <Button label="Run rekey" variant="primary" onClick={runRekey} />
          <Button
            label="Verify all rows"
            onClick={() =>
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
            }
          />
        </div>
        {rekey ? (
          <Notice kind={rekey.skipped > 0 ? "warn" : "ok"}>
            Rekey finished: {rekey.skipped} skipped (unreadable) rows.
          </Notice>
        ) : null}
        {verify ? (
          <Notice
            kind={
              verify.unreadable.fields +
                verify.unreadable.history +
                verify.unreadable.operator +
                verify.unreadable.agent_keys +
                verify.unreadable.operator_tokens >
              0
                ? "warn"
                : "ok"
            }
          >
            Verify: fields {verify.unreadable.fields}, history {verify.unreadable.history},
            operator {verify.unreadable.operator}, agent keys {verify.unreadable.agent_keys},
            operator tokens {verify.unreadable.operator_tokens} unreadable.
          </Notice>
        ) : null}
      </div>
      <div className="card stack">
        <h2 className="page-sub" style={{ margin: 0 }}>
          Retention
        </h2>
        <p className="muted" style={{ margin: 0 }}>
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
        {counts ? (
          <p className="mono" style={{ margin: 0 }}>
            {Object.entries(counts)
              .map(([table, count]) => `${table}: ${count}`)
              .join(" · ")}
          </p>
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