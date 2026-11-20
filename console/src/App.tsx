import { useCallback, useEffect, useState } from "react";
import { ApiError, getCsrf, logout, status as fetchStatus } from "./api";
import { Audit } from "./screens/Audit";
import { Device } from "./screens/Device";
import { Items } from "./screens/Items";
import { Keys } from "./screens/Keys";
import { Login } from "./screens/Login";
import { Settings } from "./screens/Settings";
import { OneTimePanel } from "./components/OneTimePanel";
import { clearOneTimeForSignOut, useOneTime } from "./onetime";
import type { AuthStatus } from "./types";

type Boot =
  | { phase: "loading" }
  | { phase: "anonymous"; status: AuthStatus }
  | { phase: "ready"; status: AuthStatus }
  | { phase: "error"; message: string };

const NAV = [
  { href: "/items", label: "Items" },
  { href: "/keys", label: "Keys" },
  { href: "/audit", label: "Audit" },
  { href: "/settings", label: "Settings" },
];

export function App() {
  const [boot, setBoot] = useState<Boot>({ phase: "loading" });
  const [path, setPath] = useState(() => window.location.pathname);
  const [pendingDeviceCode, setPendingDeviceCode] = useState("");
  const oneTime = useOneTime();

  const go = useCallback((next: string, replace = false) => {
    if (replace) window.history.replaceState(null, "", next);
    else window.history.pushState(null, "", next);
    setPath(next.split("#")[0] ?? "/");
  }, []);

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const bootstrap = useCallback(async () => {
    try {
      // One request: auth/status also carries csrf_token for a live session
      // (that IS the reload recovery path, §3), which api.status() stores.
      const st = await fetchStatus();
      setBoot(
        st.setup_required || !getCsrf()
          ? { phase: "anonymous", status: st }
          : { phase: "ready", status: st },
      );
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "cannot reach the server";
      setBoot({ phase: "error", message });
    }
  }, []);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  // After signing in from the device page, go back and finish the hand-off
  // instead of dumping the operator on the item list.
  const resumeDeviceHandoff = useCallback(async () => {
    if (!pendingDeviceCode) return false;
    go(`/device#${pendingDeviceCode}`, true);
    setPendingDeviceCode("");
    return true;
  }, [pendingDeviceCode, go]);

  const onAuthenticated = useCallback(async () => {
    try {
      const st = await fetchStatus(); // stores the CSRF token for a live session
      setBoot({ phase: "ready", status: st });
      const resumed = await resumeDeviceHandoff();
      if (!resumed && window.location.pathname === "/") go("/items", true);
    } catch (err) {
      setBoot({
        phase: "error",
        message: err instanceof ApiError ? err.message : "signed in, but cannot load the console",
      });
    }
  }, [go, resumeDeviceHandoff]);

  const signOut = useCallback(async () => {
    // Session boundary: the one-time store is module-level, so a secret left
    // undismissed would survive into the next session's panel. Clear it first.
    clearOneTimeForSignOut();
    // Only claim we are signed out once the SERVER dropped the session: if the
    // logout call fails the cookie is still live, and showing the login screen
    // would be a lie that a refresh contradicts.
    try {
      await logout();
    } catch (err) {
      // a 401 means the cookie was already dead: that IS signed out
      if (!(err instanceof ApiError && err.status === 401)) {
        setBoot({
          phase: "error",
          message:
            err instanceof ApiError
              ? `sign-out failed: ${err.message}`
              : "sign-out failed; the session is still active",
        });
        return;
      }
    }
    try {
      const st = await fetchStatus();
      setBoot({ phase: "anonymous", status: st });
      go("/", true);
    } catch {
      setBoot({
        phase: "anonymous",
        status: {
          setup_required: false,
          totp_required: false,
          turnstile_sitekey: null,
          passkey_available: false,
        },
      });
      go("/", true);
    }
  }, [go]);

  if (boot.phase === "loading") {
    return <div className="empty">Loading…</div>;
  }
  if (boot.phase === "error") {
    return (
      <div className="auth-form-wrap">
        <div className="auth-form card">
          <h1 className="page-title">Cannot reach Custos</h1>
          <p className="page-sub">{boot.message}</p>
          <button type="button" onClick={() => void bootstrap()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (boot.phase === "anonymous") {
    if (path === "/device" || path === "/device/" || path.startsWith("/device/")) {
      return (
        <Device
          onNeedsLogin={(deviceCode) => {
            // signing in must not lose the hand-off: hand the code to Login
            setPendingDeviceCode(deviceCode);
            go("/", true);
          }}
          onDone={() => void bootstrap()}
        />
      );
    }
    return (
      <Login
        status={boot.status}
        onAuthenticated={onAuthenticated}
      />
    );
  }

  const renderRoute = (authStatus: AuthStatus) => {
    if (path === "/keys" || path.startsWith("/keys/")) {
      return <Keys onSignOut={() => void signOut()} />;
    }
    if (path === "/audit" || path.startsWith("/audit/")) return <Audit />;
    if (path === "/settings" || path.startsWith("/settings/")) {
      return (
        <Settings
          status={authStatus}
          onSignOut={() => void signOut()}
          onStatusChanged={() => void bootstrap()}
        />
      );
    }
    if (path === "/device" || path === "/device/" || path.startsWith("/device/")) {
      // an authenticated operator still has to be able to approve a CLI login
      return (
        <Device
          onNeedsLogin={() => go("/items", true)}
          onDone={() => go("/items", true)}
        />
      );
    }
    return <Items onSignOut={() => void signOut()} />;
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            C
          </span>
          <span>Custos</span>
        </div>
        <nav className="nav" aria-label="Sections">
          {NAV.map((entry) => (
            <a
              key={entry.href}
              href={entry.href}
              aria-current={path.startsWith(entry.href) ? "page" : undefined}
              onClick={(event) => {
                // let ctrl/cmd/shift/middle clicks open a new tab
                if (event.defaultPrevented) return;
                if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) {
                  return;
                }
                event.preventDefault();
                go(entry.href);
              }}
            >
              {entry.label}
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          <button type="button" className="ghost" onClick={() => void signOut()}>
            Log out
          </button>
        </div>
      </aside>
      <main className="workspace">
        {/* A minted secret must survive a route change: it lives above the
            screens, not inside one. */}
        {oneTime.oneTime ? (
          <OneTimePanel
            key={`${oneTime.oneTime.kind}:${oneTime.oneTime.about}`}
            oneTime={oneTime.oneTime}
            pending={oneTime.pending}
            onDismiss={oneTime.dismiss}
          />
        ) : null}
        {renderRoute(boot.status)}
      </main>
    </div>
  );
}