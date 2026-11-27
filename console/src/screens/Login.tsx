import { Fragment, useCallback, useState } from "react";
import { ApiError, api, setCsrf, setCsrf as rememberCsrf } from "../api";
import { Button, Notice, TextField } from "../components/Field";
import { LoginInputError, loginPayload, setupPayload } from "../login";
import type { AuthStatus } from "../types";
import {
  decodeRequestOptions,
  encodeAssertion,
  type PublicKeyCredentialRequestOptionsJSON,
} from "../webauthn";

type Props = {
  status: AuthStatus;
  onAuthenticated: () => void | Promise<void>;
};

type TurnstileWindow = Window & {
  turnstile?: {
    render: (
      el: HTMLElement,
      opts: { sitekey: string; callback: (token: string) => void },
    ) => void;
  };
};

// Cloudflare's script is injected only when a sitekey is configured: an
// unconfigured deployment never phones home to a third party (§5).
function useTurnstile(sitekey: string | null) {
  const [token, setToken] = useState("");
  const attach = useCallback(
    (node: HTMLDivElement | null) => {
      if (!node || !sitekey) return;
      const w = window as TurnstileWindow;
      const render = () => {
        if (!w.turnstile) return;
        node.replaceChildren();
        w.turnstile.render(node, { sitekey, callback: setToken });
      };
      if (w.turnstile) {
        render();
        return;
      }
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
      script.async = true;
      script.onload = render;
      document.head.append(script);
    },
    [sitekey],
  );
  // A widget response is single-use. Bumping `epoch` remounts the container,
  // which re-invokes the ref callback and renders a fresh widget — clearing
  // state alone would leave the spent token gone with no widget to replace it.
  const [epoch, setEpoch] = useState(0);
  const reset = useCallback(() => {
    setToken("");
    setEpoch((prev) => prev + 1);
  }, []);
  return { token, attach, reset, epoch };
}

export function Login({ status, onAuthenticated }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [second, setSecond] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  // TOTP-enabled accounts sign in in two steps: credentials, then the
  // verification-code page (where the recovery fallback lives). The advance
  // is client-side — a password-only POST would just burn a 401/lockout row.
  const [step, setStep] = useState<"credentials" | "code">("credentials");
  const [setupCode, setSetupCode] = useState("");
  const [setupDone, setSetupDone] = useState(false);
  const setup = status.setup_required && !setupDone;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const turnstile = useTurnstile(status.turnstile_sitekey);

  const submit = useCallback(async () => {
    if (!setup && status.totp_required && step === "credentials") {
      if (!username.trim() || !password) {
        setError("Enter your username and password first.");
        return;
      }
      setStep("code");
      setError("");
      // the code step remounts the widget: never submit a token solved on
      // the credentials page after the step changed
      turnstile.reset();
      return;
    }
    if (!setup && !second.trim() && (step === "code" || useRecovery)) {
      setError(useRecovery ? "Enter a recovery code." : "Enter your authenticator code.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      if (setup) {
        // Setup creates the account but NO session (server returns
        // {"setup": "complete"}); fall through to the sign-in form.
        await api("POST", "/api/auth/setup", setupPayload(username, password, setupCode));
        setSetupDone(true);
        setPassword("");
        setSetupCode("");
        return;
      }
      const factor: { totp?: string; recoveryCode?: string } = {};
      if (useRecovery) factor.recoveryCode = second.trim();
      else if (status.totp_required) factor.totp = second.trim();
      const payload = loginPayload({
        username,
        password,
        ...factor,
        ...(turnstile.token ? { turnstile: turnstile.token } : {}),
      });
      const data = await api<{ csrf_token: string }>("POST", "/api/auth/login", payload);
      setCsrf(data.csrf_token);
      await onAuthenticated();
    } catch (err) {
      if (err instanceof LoginInputError) setError(err.message);
      else if (err instanceof ApiError) setError(err.message);
      else setError("login failed");
      // a rejected TOTP code can never become valid (window passed): clear
      // it so a second Enter cannot burn another lockout row on a stale value
      if (step === "code" && !useRecovery) setSecond("");
      // a Turnstile token is single-use server-side: drop the spent one so the
      // next attempt submits a fresh widget response instead of a dead token
      turnstile.reset();
    } finally {
      setBusy(false);
    }
  }, [
    setup,
    step,
    username,
    password,
    setupCode,
    useRecovery,
    second,
    status.totp_required,
    turnstile.token,
    turnstile.reset,
    onAuthenticated,
  ]);

  const passkey = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      // The server returns the WebAuthn options object at the TOP level
      // (options_to_json_dict), not wrapped in {publicKey}.
      const options = await api<PublicKeyCredentialRequestOptionsJSON>(
        "POST",
        "/api/auth/passkeys/assert/options",
        {},
      );
      const assertion = (await navigator.credentials.get({
        publicKey: decodeRequestOptions(options),
      })) as PublicKeyCredential | null;
      if (!assertion) throw new Error("passkey cancelled");
      const body = {
        ...encodeAssertion(assertion),
        ...(turnstile.token ? { turnstile: turnstile.token } : {}),
      };
      const data = await api<{ csrf_token: string }>(
        "POST",
        "/api/auth/passkeys/assert/verify",
        body,
      );
      rememberCsrf(data.csrf_token);
      await onAuthenticated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "passkey login failed");
      // the widget response is single-use and the server checks it on
      // assert/verify: drop the spent token so a retry has a fresh one
      turnstile.reset();
    } finally {
      setBusy(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset is stable
  }, [turnstile.token, onAuthenticated, ]);

  let title = "Sign in";
  let subtitle = "Operator credentials only.";
  if (setup) {
    title = "First-run setup";
    subtitle = "Paste the setup code from the server's data directory.";
  } else if (step === "code") {
    title = "Verification code";
    subtitle = `Second factor for ${username}.`;
  }
  let submitLabel = "Sign in";
  if (setup) {
    submitLabel = "Create account";
  } else if (status.totp_required && step === "credentials") {
    // nothing has been verified yet: this button only advances to the code step
    submitLabel = "Continue";
  }

  return (
    <div className="auth">
      <div className="auth-brand">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            C
          </span>
          <span className="brand-text">
            <span className="brand-name">Custos</span>
          </span>
        </div>
        <div className="auth-copy">
          <p className="auth-eyebrow">Operator console</p>
          <h1>Credentials your agents can actually reach.</h1>
          <p>
            Named multi-field items, encrypted at rest, scoped to the keys you
            issue. Sign in to manage what agents may read.
          </p>
        </div>
        <p className="auth-foot">AES-256-GCM at rest · scoped agent keys · audit log</p>
      </div>
      <div className="auth-form-wrap">
        <form
          className="auth-form"
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <div>
            <h2 className="auth-title">{title}</h2>
            <p className="auth-lede">{subtitle}</p>
          </div>
          {error ? <Notice kind="error">{error}</Notice> : null}
          {setupDone ? (
            <Notice kind="ok">
              Account created. Sign in below with the password you just set.
            </Notice>
          ) : null}
          {!setup && step === "code" ? (
            <Fragment key="code">
              <TextField
                label={useRecovery ? "Recovery code" : "Authenticator code"}
                name="otp"
                value={second}
                onChange={setSecond}
                inputMode={useRecovery ? "text" : "numeric"}
                autoComplete="one-time-code"
                autoFocus
              />
              <div key={turnstile.epoch} ref={turnstile.attach} />
              <Button label="Sign in" variant="primary" type="submit" disabled={busy} />
              <div className="row">
                <button
                  type="button"
                  className="ghost"
                  disabled={busy}
                  onClick={() => {
                    setStep("credentials");
                    setSecond("");
                    setUseRecovery(false);
                    setError("");
                    turnstile.reset();
                  }}
                >
                  Back
                </button>
                {status.recovery_available ? (
                  <button
                    type="button"
                    className="ghost"
                    disabled={busy}
                    onClick={() => {
                      setUseRecovery((prev) => !prev);
                      setSecond("");
                      setError("");
                    }}
                  >
                    {useRecovery ? "Use authenticator instead" : "Use a recovery code instead"}
                  </button>
                ) : null}
              </div>
            </Fragment>
          ) : (
            <Fragment key="credentials">
              <TextField
                label="Username"
                name="username"
                value={username}
                onChange={setUsername}
                autoComplete="username"
                autoFocus
              />
              <TextField
                label="Password"
                name="password"
                value={password}
                onChange={setPassword}
                type="password"
                autoComplete={setup ? "new-password" : "current-password"}
                hint={setup ? "At least 12 characters." : undefined}
              />
              {setup ? (
                <TextField
                  label="Setup code"
                  name="setup-code"
                  value={setupCode}
                  onChange={setSetupCode}
                  autoComplete="off"
                  hint="Read from the 0600 file in the data directory."
                />
              ) : null}
              {!setup && !status.totp_required && useRecovery ? (
                <TextField
                  label="Recovery code"
                  name="recovery-code"
                  value={second}
                  onChange={setSecond}
                  inputMode="text"
                  autoComplete="one-time-code"
                />
              ) : null}
              {/* the widget mounts wherever a POST can originate: the code
                  step for TOTP, the credentials step for password-only and
                  passkey logins (assert/verify also requires the token) */}
              {!setup && (!status.totp_required || status.passkey_available) ? (
                <div key={turnstile.epoch} ref={turnstile.attach} />
              ) : null}
              <Button
                label={submitLabel}
                variant="primary"
                type="submit"
                disabled={busy}
              />
              {!setup ? (
                <div className="row">
                  {/* recovery is a TOTP fallback: on the code step when TOTP is
                      enabled; inline here only in the TOTP-off recovery window */}
                  {!status.totp_required && status.recovery_available ? (
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => {
                        setUseRecovery((prev) => !prev);
                        setSecond("");
                        setError("");
                      }}
                    >
                      {useRecovery ? "Use password only" : "Use a recovery code"}
                    </button>
                  ) : null}
                  {status.passkey_available ? (
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => void passkey()}
                      disabled={busy}
                    >
                      Use a passkey
                    </button>
                  ) : null}
                </div>
              ) : null}
            </Fragment>
          )}
        </form>
      </div>
    </div>
  );
}