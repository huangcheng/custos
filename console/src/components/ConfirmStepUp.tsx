import { useCallback, useEffect, useRef, useState } from "react";
import { stepUp } from "../api";
import { Button, Notice, TextField } from "./Field";

// One step-up token per sensitive call (§5: single-use, presenter-bound).
// The console asks for the password (plus TOTP when enabled) right before the
// call that needs it, so a token never sits in memory unused.
export function ConfirmStepUp({
  totpRequired,
  title,
  message,
  onToken,
  onCancel,
}: {
  totpRequired: boolean;
  title?: string;
  message?: string;
  onToken: (token: string) => void | Promise<void>;
  onCancel: () => void;
}) {
  const [password, setPassword] = useState("");
  const [factor, setFactor] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // A ref, not state: the promise chain must observe a cancel that happens
  // while the request is in flight, and state captured in useCallback does not.
  const cancelled = useRef(false);

  // Any unmount — Cancel, Escape, browser Back, a nav click re-rendering the
  // screen — must kill the in-flight chain: handing a token to a gone parent
  // would perform the sensitive action invisibly.
  useEffect(() => {
    // StrictMode double-mounts in dev: reset on mount so the cleanup below
    // cannot leave the dialog permanently cancelled.
    cancelled.current = false;
    return () => {
      cancelled.current = true;
    };
  }, []);

  const needsFactor = totpRequired || useRecovery;
  const ready = password.length > 0 && (!needsFactor || factor.trim().length > 0);

  const submit = useCallback(() => {
    if (!ready || busy) return;
    setBusy(true);
    setError("");
    void stepUp(password, {
      ...(useRecovery ? { recoveryCode: factor.trim() } : {}),
      ...(!useRecovery && factor.trim() ? { totp: factor.trim() } : {}),
    })
      .then((token) => {
        // A cancel while the request was in flight must not hand the caller a
        // token: the operator already walked away.
        if (!cancelled.current) return onToken(token);
        return undefined;
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "step-up failed");
      })
      .finally(() => setBusy(false));
  }, [ready, busy, password, factor, useRecovery, onToken]);

  return (
    <div
      className="scrim"
      role="dialog"
      aria-modal="true"
      aria-label={title ?? "Confirm password"}
      onMouseDown={(event) => {
        if (event.target !== event.currentTarget) return;
        cancelled.current = true;
        onCancel();
      }}
      onKeyDown={(event) => {
        if (event.key !== "Escape") return;
        // stop here: bubbling would close the parent Drawer too and discard
        // the operator's unsaved item edits
        event.stopPropagation();
        cancelled.current = true;
        onCancel();
      }}
    >
      <form
        className="drawer"
        style={{ width: "min(420px, 100%)" }}
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <div className="drawer-head">
          <h2>{title ?? "Confirm password"}</h2>
          <div className="meta">Single-use step-up token</div>
        </div>
        <div className="drawer-body stack">
          <p className="muted" style={{ margin: 0 }}>
            {message ?? "Re-enter your operator password to continue."}
          </p>
          {error ? <Notice kind="error">{error}</Notice> : null}
          <TextField
            label="Password"
            value={password}
            onChange={(next) => {
              setPassword(next);
              setError("");
            }}
            type="password"
            autoComplete="current-password"
            autoFocus
          />
          {needsFactor ? (
            <TextField
              label={useRecovery ? "Recovery code" : "Authenticator code"}
              value={factor}
              onChange={(next) => {
                setFactor(next);
                setError("");
              }}
              inputMode={useRecovery ? "text" : "numeric"}
              autoComplete="one-time-code"
            />
          ) : null}
          <div className="row">
            <Button label="Continue" variant="primary" type="submit" disabled={!ready || busy} />
            <Button
              label="Cancel"
              variant="ghost"
              onClick={() => {
                cancelled.current = true;
                onCancel();
              }}
            />
            {totpRequired ? (
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  setUseRecovery((prev) => !prev);
                  setFactor("");
                  setError("");
                }}
              >
                {useRecovery ? "Use authenticator instead" : "Use a recovery code"}
              </button>
            ) : null}
          </div>
        </div>
      </form>
    </div>
  );
}
