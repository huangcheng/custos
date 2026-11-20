import { useCallback, useState } from "react";
import { ApiError, api, setCsrf, setCsrf as rememberCsrf } from "../api";
import { Button, Notice, TextField } from "../components/Field";
import { LoginInputError, loginPayload, setupPayload } from "../login";
import type { AuthStatus } from "../types";

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
  const [setupCode, setSetupCode] = useState("");
  const [setupDone, setSetupDone] = useState(false);
  const setup = status.setup_required && !setupDone;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const turnstile = useTurnstile(status.turnstile_sitekey);

  const submit = useCallback(async () => {
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
      // a Turnstile token is single-use server-side: drop the spent one so the
      // next attempt submits a fresh widget response instead of a dead token
      turnstile.reset();
    } finally {
      setBusy(false);
    }
  }, [
    setup,
    username,
    password,
    setupCode,
    useRecovery,
    second,
    status.totp_required,
    turnstile.token,
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

  return (
    <div className="auth">
      <div className="auth-brand">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            C
          </span>
          <span>Custos</span>
        </div>
        <div>
          <h1>Credentials your agents can actually reach.</h1>
          <p>
            Named multi-field items, encrypted at rest, scoped to the keys you
            issue. Sign in to manage what agents may read.
          </p>
        </div>
      </div>
      <div className="auth-form-wrap">
        <form
          className="auth-form stack"
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <div>
            <h2 className="page-title">{setup ? "First-run setup" : "Sign in"}</h2>
            <p className="page-sub">
              {setup
                ? "Paste the setup code from the server's data directory."
                : "Operator credentials only."}
            </p>
          </div>
          {error ? <Notice kind="error">{error}</Notice> : null}
          {setupDone ? (
            <Notice kind="ok">
              Account created. Sign in below with the password you just set.
            </Notice>
          ) : null}
          <TextField
            label="Username"
            value={username}
            onChange={setUsername}
            autoComplete="username"
            autoFocus
          />
          <TextField
            label="Password"
            value={password}
            onChange={setPassword}
            type="password"
            autoComplete={setup ? "new-password" : "current-password"}
            hint={setup ? "At least 12 characters." : undefined}
          />
          {setup ? (
            <TextField
              label="Setup code"
              value={setupCode}
              onChange={setSetupCode}
              autoComplete="off"
              hint="Read from the 0600 file in the data directory."
            />
          ) : null}
          {!setup && (status.totp_required || useRecovery) ? (
            <TextField
              label={useRecovery ? "Recovery code" : "Authenticator code"}
              value={second}
              onChange={setSecond}
              inputMode={useRecovery ? "text" : "numeric"}
              autoComplete="one-time-code"
            />
          ) : null}
          {!setup ? (
            <div key={turnstile.epoch} ref={turnstile.attach} />
          ) : null}
          <Button
            label={setup ? "Create account" : "Sign in"}
            variant="primary"
            type="submit"
            disabled={busy}
          />
          {!setup ? (
            <div className="row">
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  setUseRecovery((prev) => !prev);
                  setSecond("");
                }}
              >
                {useRecovery ? "Use authenticator instead" : "Use a recovery code"}
              </button>
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
        </form>
      </div>
    </div>
  );
}

// --- WebAuthn JSON ⇄ binary helpers (the server speaks JSON) ---

type PublicKeyCredentialRequestOptionsJSON = {
  challenge: string;
  allowCredentials?: { id: string; type: "public-key" }[];
  userVerification?: UserVerificationRequirement;
  rpId?: string;
  timeout?: number;
};

function b64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const raw = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToB64url(bytes: ArrayBuffer): string {
  const view = new Uint8Array(bytes);
  let raw = "";
  for (const byte of view) raw += String.fromCharCode(byte);
  return btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeRequestOptions(
  json: PublicKeyCredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: b64urlToBytes(json.challenge),
    ...(json.allowCredentials
      ? {
          allowCredentials: json.allowCredentials.map((c) => ({
            id: b64urlToBytes(c.id),
            type: c.type,
          })),
        }
      : {}),
    ...(json.userVerification ? { userVerification: json.userVerification } : {}),
    ...(json.rpId ? { rpId: json.rpId } : {}),
    ...(json.timeout ? { timeout: json.timeout } : {}),
  };
}

export function encodeAssertion(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(response.clientDataJSON),
      authenticatorData: bytesToB64url(response.authenticatorData),
      signature: bytesToB64url(response.signature),
      ...(response.userHandle
        ? { userHandle: bytesToB64url(response.userHandle) }
        : {}),
    },
  };
}