import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import { ApiError, api } from "../api";
import { useOneTime } from "../onetime";
import { Button, Notice } from "../components/Field";
import { deviceCodeFromHash, displayTransferCode } from "../login";
type Props = {
  onNeedsLogin: (deviceCode: string) => void;
  onDone: () => void;
};

type Lookup = {
  client_ip: string;
  user_agent: string;
  expires_at: string;
};

// The device code arrives in the URL fragment (§5): out of logs, out of the
// Referer header, out of history. Strip it before any await so a screenshot,
// reload or extension cannot re-read it.
export function Device({ onNeedsLogin, onDone }: Props) {
  const [code] = useState(() => deviceCodeFromHash(window.location.hash));
  const [lookup, setLookup] = useState<Lookup | null>(null);
  const oneTime = useOneTime();
  const [transfer, setTransfer] = useState("");
  const [deadline, setDeadline] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notSignedIn, setNotSignedIn] = useState(false);

  // useLayoutEffect: strip the code BEFORE the first paint, so it is never
  // visible in the URL bar, a screenshot or a restored tab.
  useLayoutEffect(() => {
    if (window.location.hash) {
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);

  useEffect(() => {
    if (!code) {
      onNeedsLogin("");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const data = await api<Lookup>("POST", "/api/auth/device/lookup", {
          device_code: code,
        });
        if (!cancelled) setLookup(data);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) setNotSignedIn(true);
        else setError(err instanceof ApiError ? err.message : "lookup failed");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [code, onNeedsLogin]);

  const approve = useCallback(async () => {
    if (!code) return;
    setBusy(true);
    setError("");
    try {
      const data = await api<{ transfer_code: string; exchange_deadline?: string }>(
        "POST",
        "/api/auth/device/approve",
        { device_code: code },
      );
      setTransfer(data.transfer_code);
      if (data.exchange_deadline) setDeadline(data.exchange_deadline);
      // the transfer code is one-time and short-lived: keep it above the
      // screens so a navigation cannot lose it mid-entry
      oneTime.show({
        kind: "device-transfer",
        value: data.transfer_code,
        about: data.exchange_deadline
          ? `CLI hand-off, enter before ${data.exchange_deadline}`
          : "CLI hand-off",
      });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "approval failed");
    } finally {
      setBusy(false);
    }
  }, [code]);

  if (notSignedIn) {
    return (
      <div className="auth-form-wrap">
        <div className="auth-form card stack">
          <h1 className="page-title">Sign in first</h1>
          <p className="page-sub">
            Approving a CLI login needs a signed-in operator session.
          </p>
          <Button
            label="Go to sign in"
            variant="primary"
            onClick={() => onNeedsLogin(code ?? "")}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="auth-form-wrap">
      <div className="auth-form card stack">
        <div>
          <h1 className="page-title">Approve CLI login</h1>
          <p className="page-sub">
            Confirm this is your own command-line client before approving.
          </p>
        </div>
        {error ? <Notice kind="error">{error}</Notice> : null}
        {transfer ? (
          <>
            <Notice kind="warn">
              Approving hands a session to whoever runs that client. Paste the
              transfer code below into the CLI prompt now.
            </Notice>
            <label>
              <span>Transfer code</span>
              <input className="mono" readOnly value={displayTransferCode(transfer)} />
            </label>
            {deadline ? (
              <p className="muted mono">Enter it in the CLI before {deadline}</p>
            ) : null}
            <div className="row">
              <Button
                label="Copy code"
                onClick={() => {
                  void navigator.clipboard?.writeText(transfer).catch(() => undefined);
                }}
              />
            </div>
            <Button label="Done" onClick={onDone} />
          </>
        ) : lookup ? (
          <>
            <table>
              <tbody>
                <tr>
                  <th>Requesting IP</th>
                  <td className="mono">{lookup.client_ip}</td>
                </tr>
                <tr>
                  <th>Client</th>
                  <td>{lookup.user_agent}</td>
                </tr>
                <tr>
                  <th>Expires</th>
                  <td className="mono">{lookup.expires_at}</td>
                </tr>
              </tbody>
            </table>
            <Notice kind="warn">
              If you did not start a CLI login, close this page without approving
              and check the audit log. Leaving it unapproved expires in a few
              minutes.
            </Notice>
            <div className="row">
              <Button
                label="Approve this client"
                variant="primary"
                onClick={() => void approve()}
                disabled={busy}
              />
              <Button
                label="Not mine — do not approve"
                variant="ghost"
                onClick={() => onNeedsLogin(code ?? "")}
              />
            </div>
          </>
        ) : (
          <p className="muted">Looking up the request…</p>
        )}
      </div>
    </div>
  );
}