#!/usr/bin/env bash
# e2e_console.sh — real-browser gate for the operator console (design §8).
#
# Brings up the same throwaway stack as e2e.sh, then drives the BUILT console
# through a real browser: static contract, login, CSRF recovery after a reload,
# masked listing and drawer, session-only reveal (rev 41), If-Match conflict and
# delete/restore, key mint (token shown once, and it must authenticate), the
# key.mint audit row, the device hand-off fragment, and the DESIGN.md invariants
# measured on the rendered page (palette tokens, control metrics, header
# rhythm, filter alignment, drawer/dialog craft, phone-width layout).
#
# Requires a browser driver command in CUSTOS_BROWSER_CMD (a command that runs
# a JS driver script from stdin, e.g. `ego-browser nodejs`). With no driver the
# script stops before the browser section and says so — it never claims a pass
# it did not observe.
set -euo pipefail
cd "$(dirname "$0")/.."

# Precondition first: a missing driver must not cost a multi-minute build.
if [ -z "${CUSTOS_BROWSER_CMD:-}" ] && [ "${E2E_ALLOW_SKIP:-0}" != "1" ]; then
  echo "E2E FAIL: CUSTOS_BROWSER_CMD is unset; set E2E_ALLOW_SKIP=1 to skip the browser half deliberately" >&2
  exit 1
fi

LOG_DIR="/tmp/custos-e2e"
# refuse a squatted log root (shared guard; see scripts/e2e_common.sh)
. scripts/e2e_common.sh
harden_log_dir "$LOG_DIR"
RUN_DIR="$(mktemp -d "$LOG_DIR/console-XXXXXX")"
PROJECT="custos-e2e-console-$$"
export E2E_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
COMPOSE=(docker compose -p "$PROJECT" --env-file "$RUN_DIR/env" -f deploy/docker-compose.yml)

cleanup() {
  if [ "${E2E_KEEP:-}" = "1" ]; then
    echo "E2E_KEEP=1: stack and run dir preserved ($RUN_DIR)" >&2
    return
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [ "${E2E_FAILED:-0}" = "1" ]; then
    echo "run artifacts preserved: $RUN_DIR" >&2
  else
    rm -rf "$RUN_DIR"
  fi
}
trap cleanup EXIT

fail() { E2E_FAILED=1; echo "E2E FAIL: $1 (artifacts: $RUN_DIR)" >&2; exit 1; }
trap 'E2E_FAILED=1' ERR

echo "== generate throwaway secrets"
make_secrets_dir "$RUN_DIR"
python3 - "$RUN_DIR" <<'PYEOF'
import base64, os, secrets, subprocess, sys
run = sys.argv[1]
b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
pw = b64url(secrets.token_bytes(18))
with open(f"{run}/secrets/keyring", "w") as f: f.write(f"k1:{b64url(secrets.token_bytes(32))}\n")
with open(f"{run}/secrets/pepper", "w") as f: f.write(b64url(secrets.token_bytes(32)) + "\n")
with open(f"{run}/secrets/database-url", "w") as f:
    f.write(f"postgresql+asyncpg://custos:{pw}@db:5432/custos\n")
for name in ("keyring", "pepper", "database-url"):
    os.chmod(f"{run}/secrets/{name}", 0o600)
try:
    subprocess.run(
        ["docker", "run", "--rm", "--user", "0", "-v", f"{run}/secrets:/s",
         "alpine:3", "sh", "-c", "chown 10001:10001 /s /s/* && chmod 600 /s/* && chmod 755 /s"],
        check=True, capture_output=True,
    )
except subprocess.CalledProcessError as exc:
    sys.exit(f"secrets chown failed: {exc.stderr.decode(errors='replace')}")
with open(f"{run}/env", "w") as f:
    f.write(f"CUSTOS_DB_PASSWORD={pw}\nCUSTOS_SECRETS_DIR={run}/secrets\n"
            f"CUSTOS_TRUSTED_PROXIES=172.16.0.0/12\nCUSTOS_PORT={os.environ['E2E_PORT']}\n"
            f"CUSTOS_ALLOWED_ORIGINS=http://localhost:{os.environ['E2E_PORT']}\n"
            f"CUSTOS_WEBAUTHN_RP_ID=localhost\n")
PYEOF

echo "== start stack (console baked into the image)"
"${COMPOSE[@]}" up -d --build > "$RUN_DIR/compose.log" 2>&1 || fail "compose up (see $RUN_DIR/compose.log)"
# localhost (not 127.0.0.1): browsers reject IP-literal WebAuthn rpIds; the
# http origin is accepted because it is spelled out in CUSTOS_ALLOWED_ORIGINS
BASE="http://localhost:$E2E_PORT"
for i in $(seq 1 90); do
  curl -fsS -m 2 "http://127.0.0.1:$E2E_PORT/healthz" >/dev/null 2>&1 && break
  sleep 1
  [ "$i" = 90 ] && fail "app did not become healthy"
done

echo "== the image really serves the console"
SHELL_HTML=$(curl -fsS -m 10 "$BASE/")
printf '%s' "$SHELL_HTML" | grep -q '<div id="root">' || fail "GET / did not return the SPA shell"
printf '%s' "$SHELL_HTML" | grep -q 'default-src' && fail "CSP leaked into the HTML body"
# `|| true`: a missing header must reach the `fail` diagnostic, not abort
# the script from inside a command substitution under `set -e`.
HEADERS=$(curl -sS -m 10 -D - -o /dev/null "$BASE/" | tr -d '\r' || true)
CSP=$(printf '%s' "$HEADERS" | grep -i '^content-security-policy:' | head -1 || true)
printf '%s' "$CSP" | grep -q "frame-ancestors 'none'" || fail "missing CSP on the shell (got: ${CSP:-<none>})"
CACHE=$(printf '%s' "$HEADERS" | grep -i '^cache-control:' | head -1 || true)
printf '%s' "$CACHE" | grep -q 'no-store' || fail "shell is not no-store (got: ${CACHE:-<none>})"
ASSET=$(printf '%s' "$SHELL_HTML" | grep -o '/assets/[^"]*\.js' | head -1 || true)
[ -n "$ASSET" ] || fail "no asset referenced by the shell"
ACACHE=$(curl -sS -m 10 -D - -o /dev/null "$BASE$ASSET" | tr -d '\r' | grep -i '^cache-control:' | head -1 || true)
printf '%s' "$ACACHE" | grep -q 'immutable' || fail "asset is not immutable (got: ${ACACHE:-<none>})"
# unknown API paths stay JSON; client routes serve the shell
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$BASE/api/nope")
[ "$CODE" = "404" ] || fail "/api/nope should be 404, got $CODE"
curl -s -m 10 "$BASE/api/nope" | grep -q '"code"' || fail "/api/nope is not the JSON envelope"
curl -fsS -m 10 "$BASE/items" | grep -q '<div id="root">' || fail "/items did not serve the shell"
echo "STATIC-OK"

echo "== operator setup (browser will sign in with this)"
SETUP_CODE=$(docker exec "$PROJECT-app-1" sh -c 'cat /var/lib/custos/setup-code 2>/dev/null || true')
[ -n "$SETUP_CODE" ] || fail "setup-code file not provisioned"
curl -fsS -m 10 -X POST "$BASE/api/auth/setup" -H 'content-type: application/json' \
  -d "{\"username\":\"operator\",\"password\":\"cu-test-console-password\",\"setup_code\":\"$SETUP_CODE\"}" \
  > /dev/null || fail "setup"

echo "== browser drive"
if [ -z "${CUSTOS_BROWSER_CMD:-}" ]; then
  echo "E2E SKIP (browser) — E2E_ALLOW_SKIP=1: only the static contract was verified" >&2
  exit 0
fi

DRIVER="$RUN_DIR/driver.js"
cat > "$DRIVER" <<'JSEOF'
// Real-browser checks against the built console. Every assertion prints
// CHECK <n>: <name> so a failure names itself.
const BASE = __BASE__;
const PW = "cu-test-console-password";
const SECRET_VALUE = "cu-test-console-secret-42";
const ITEM = "cu-test-console-item";
let n = 0;
let failuresBaseline = 0;
const authFailures = () => page.evaluate(async () => {
  // keyset pages cap at 50: follow next_cursor for an exact total
  let total = 0;
  let cursor = "";
  for (let page_i = 0; page_i < 20; page_i += 1) {
    const url = "/api/admin/audit?action=auth.failure" + (cursor ? `&cursor=${cursor}` : "");
    const res = await fetch(url, { credentials: "same-origin" });
    if (res.status !== 200) throw new Error(`auth.failure audit query failed: ${res.status}`);
    const body = await res.json();
    total += body.items.length;
    if (!body.next_cursor) return total;
    cursor = body.next_cursor;
  }
  throw new Error("auth.failure audit pagination did not terminate");
});
// textContent misses <input value>, title, placeholder — exactly where a secret
// would most likely leak. This scans text AND attribute values.
const leaked = (needle) =>
  page.evaluate(({ secret }) => {
    const inText = document.body.textContent.includes(secret);
    const inValue = [...document.querySelectorAll("input,textarea")].some((el) =>
      String(el.value).includes(secret),
    );
    const inAttr = [...document.querySelectorAll("*")].some((el) =>
      ["title", "placeholder", "aria-label", "alt", "data-testid"].some((name) =>
        String(el.getAttribute(name) ?? "").includes(secret),
      ),
    );
    return inText || inValue || inAttr;
  }, { secret: needle });

const ok = (cond, name) => {
  n += 1;
  if (!cond) throw new Error(`CHECK ${n} FAILED: ${name}`);
  console.log(`CHECK ${n}: ${name}`);
};

// Poll instead of sleeping: a fixed delay is both a flake and a waste.
const until = async (fn, what, timeout = 15000) => {
  const deadline = Date.now() + timeout;
  let last;
  for (;;) {
    try {
      if (await fn()) return;
    } catch (err) {
      // a transient rejection mid-poll (a fetch racing a reload) must not
      // abort the wait: keep polling until the deadline
      last = err;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}${last ? `: ${last.message}` : ""}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
};
// fill-then-click helper shared by every section (defined here, before the
// first use in section 7): poll until the target button is enabled, then click
const clickWhenReady = (reSource, scopeSel, label) => until(() => page.evaluate(
  ({ reSource, scopeSel }) => {
    const scope = scopeSel ? document.querySelector(scopeSel) : document;
    if (!scope) return false;
    const re = new RegExp(reSource, "i");
    const b = [...scope.querySelectorAll("button")].find((x) => re.test(x.textContent));
    if (b && !b.disabled) { b.click(); return true; }
    return false;
  }, { reSource, scopeSel }), label);
const fillStepUp = (password, factor) => page.evaluate(({ password, factor }) => {
  const set = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const form = document.querySelector(".scrim form");
  if (!form) throw new Error("step-up prompt not open");
  const inputs = [...form.querySelectorAll("input")];
  const passwordInput = inputs.find((i) => i.type === "password");
  if (!passwordInput) throw new Error("step-up password field missing");
  set(passwordInput, password);
  if (factor != null) {
    const otp = inputs.find((i) => i.getAttribute("autocomplete") === "one-time-code");
    if (!otp) throw new Error("step-up factor field missing");
    set(otp, factor);
  }
}, { password, factor });

// NOTE: page.evaluate callbacks are serialized into the page, so they cannot
// close over anything here. Each callback that types defines its own setter.

const space = await taskSpace("custos-console-e2e");
const page = await space.newPage(); // newPage() takes no label

// Purge confirmation assertions shared by the list and nested-drawer entry
// points: scopeSel is ".scrim" (list) or ".scrim .scrim" (inside the drawer).
const expectPurgeConfirm = async (scopeSel, item, label) => {
  await until(() => page.evaluate(({ scopeSel }) =>
    !!document.querySelector(`${scopeSel} form`), { scopeSel }), `${label} confirmation`);
  ok(await page.evaluate(({ scopeSel, item }) => {
    const form = document.querySelector(`${scopeSel} form`);
    const copy = form ? form.textContent || "" : "";
    const active = document.activeElement;
    return !!form && !form.querySelector("input[type=password]")
      && copy.includes(item) && /cannot be undone/i.test(copy)
      && !!active && form.contains(active) && active.textContent.trim() === "Cancel";
  }, { scopeSel, item }),
  `${label} confirmation names the item, warns it is irreversible, focuses Cancel and asks for no password`);
};

const escapePurgeConfirm = async (scopeSel, label) => {
  await page.evaluate(({ scopeSel, label }) => {
    const form = document.querySelector(`${scopeSel} form`);
    if (!form) throw new Error(`${label} confirmation not open`);
    const target = document.activeElement;
    if (!(target instanceof Element) || !form.contains(target)) {
      throw new Error(`focus left the ${label} confirmation`);
    }
    target.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
  }, { scopeSel, label });
  await until(() => page.evaluate(({ scopeSel }) =>
    document.querySelector(scopeSel) === null, { scopeSel }),
    `${label} confirmation to close on Escape`);
};

// Click a button inside the row that names `item` (document-scoped Purge
// clicks would hit the wrong row if another deleted probe were left behind).
const clickRowButton = (item, reSource, label) => until(() => page.evaluate(
  ({ item, reSource }) => {
    const row = [...document.querySelectorAll("tr")]
      .find((r) => r.textContent.includes(item));
    if (!row) return false;
    const re = new RegExp(reSource, "i");
    const b = [...row.querySelectorAll("button")].find((x) => re.test(x.textContent));
    if (b && !b.disabled) { b.click(); return true; }
    return false;
  }, { item, reSource }), label);

// The drawer must stay open with its unsaved draft and the item still
// soft-deleted after Escape or Cancel closes only the nested confirmation.
const expectDrawerKept = async (item, note, label) => {
  ok(await page.evaluate(async ({ item, note }) => {
    const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      credentials: "same-origin",
    });
    const drawer = document.querySelector(".scrim .drawer");
    const area = document.querySelector(".scrim textarea");
    return drawer !== null && area !== null && area.value === note
      && res.status === 200 && (await res.json()).deleted === true;
  }, { item, note }), label);
};

// 1. login page renders, then sign in
await page.goto(`${BASE}/`);
await page.evaluate(async () => {
  // wait for React to mount
  for (let i = 0; i < 100; i += 1) {
    if (document.querySelector("form")) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("console did not mount");
});
ok(await page.evaluate(() => document.body.textContent.includes("Sign in")), "login screen renders");
// bare account (no TOTP, no live recovery codes, no passkeys): the login
// page must not offer dead-end factor shortcuts (rev 37 login-UX fix)
ok(
  await page.evaluate(() =>
    ![...document.querySelectorAll("button")].some((b) =>
      /recovery code|passkey/i.test(b.textContent))),
  "no recovery/passkey shortcuts on a bare password account",
);

await page.evaluate(async ({ pw }) => {
  const set = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll("input")];
  set(inputs[0], "operator");
  set(inputs[1], pw);
  await new Promise((r) => setTimeout(r, 50));
  [...document.querySelectorAll("button")].find((b) => /Sign in/i.test(b.textContent)).click();
}, { pw: PW });
await until(() => page.evaluate(() => location.pathname === "/items"), "the /items route");
ok(true, "signed in, landed on /items");
failuresBaseline = await authFailures();

// 2. CSRF works after a reload (in-memory token recovered from auth/status)
await page.goto(`${BASE}/items`);
await page.evaluate(async () => {
  for (let i = 0; i < 100; i += 1) {
    if (document.body.textContent.includes("Items")) return;
    await new Promise((r) => setTimeout(r, 100));
  }
});
await page.evaluate(async ({ item, secret }) => {
  const token = (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()).csrf_token;
  const res = await fetch("/api/admin/items", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", "x-csrf-token": token },
    body: JSON.stringify({ name: item, notes: "n", fields: [
      { name: "TOKEN", secret: true, value: secret },
      { name: "REGION", secret: false, value: "eu" },
    ]}),
  });
  if (res.status !== 201) throw new Error(`create after reload: ${res.status}`);
}, { item: ITEM, secret: SECRET_VALUE });
ok(true, "mutation succeeds after a reload (CSRF recovered)");

// 3. the list masks the secret: the value is nowhere in the DOM
await page.goto(`${BASE}/items`);
await until(
  () => page.evaluate(({ item }) => document.body.textContent.includes(item), { item: ITEM }),
  "the item row",
);
ok(!(await leaked(SECRET_VALUE)), "secret value absent from the list DOM (text, inputs, attributes)");

// 4. opening the drawer still masks; reveal needs only the session (rev 41)
await page.evaluate(({ item }) => {
  const row = [...document.querySelectorAll("tr")].find((r) => r.textContent.includes(item));
  if (!row) throw new Error("item row not found");
  row.querySelector("button").click();
}, { item: ITEM });
await until(() => page.evaluate(() => !!document.querySelector(".drawer")), "the drawer");
// The drawer title shows the name before the GET resolves, so waiting on the
// name would let this pass with no field rows at all. Wait for a FIELD row:
// the secret pill only exists once the fetched item is rendered.
await until(
  () =>
    page.evaluate(() => {
      const drawer = document.querySelector(".drawer");
      if (!drawer) return false;
      // a field card carries the secret/plain pill
      return !!drawer.querySelector(".pill");
    }),
  "the drawer to render its fields",
);
ok(!(await leaked(SECRET_VALUE)), "drawer masks the secret before reveal (text, inputs, attributes)");
// drawer craft: the action bar is pinned to the bottom edge and the fields
// sit in sunk panels, not in a second frame inside the card
ok(
  await page.evaluate(() => {
    const r = (el) => el.getBoundingClientRect();
    const drawer = document.querySelector(".drawer");
    const foot = document.querySelector(".drawer-foot");
    const panel = document.querySelector(".drawer .panel");
    return !!foot && !!panel
      && Math.abs(r(foot).bottom - r(drawer).bottom) <= 1
      && document.querySelectorAll(".drawer .card").length === 0
      && getComputedStyle(panel).borderRadius === "12px"
      && getComputedStyle(document.documentElement).overflow === "hidden"
      && !!document.querySelector('.drawer-close[aria-label="Close"]');
  }),
  "the item drawer pins its action bar, uses sunk panels, locks the page behind it and offers a Close control",
);
// the drawer renders before its GET resolves: wait for the Reveal button itself
await until(
  () =>
    page.evaluate(() => {
      const buttons = [...document.querySelectorAll(".drawer button")];
      const reveal = buttons.find((b) => /Reveal/i.test(b.textContent));
      if (!reveal) return false;
      reveal.click();
      return true;
    }),
  "the drawer Reveal button",
);
// rev 41: revealing a stored secret needs only the session. Wait for the
// value FIRST, then assert no prompt: checking before the async render would
// pass vacuously if a step-up regression returned.
await until(
  () =>
    page.evaluate(({ secret }) => {
      const el = document.querySelector('[data-testid="revealed-TOKEN"]');
      return !!el && el.textContent.trim() === secret;
    }, { secret: SECRET_VALUE }),
  "the revealed value in the field's revealed cell",
);
ok(
  await page.evaluate(() => {
    const reveal = [...document.querySelectorAll(".drawer button")]
      .find((b) => /Reveal/i.test(b.textContent));
    return !!reveal && !reveal.disabled;
  }),
  "the Reveal button leaves its busy state after the session-only reveal",
);
ok(
  await page.evaluate(() => !document.querySelector(".scrim form")),
  "item reveal opens no password prompt (rev 41)",
);

// 6. drop and restore the item
await page.evaluate(() => {
  [...document.querySelectorAll(".drawer button")].find((b) => /Delete/i.test(b.textContent)).click();
});
await until(
  () =>
    page.evaluate(async ({ item }) => {
      const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
        credentials: "same-origin",
      });
      return (await res.json()).deleted === true;
    }, { item: ITEM }),
  "the soft-delete to land",
);
ok(true, "delete soft-deletes the item");

// 6b. restore brings it back (a containment delete must be reversible);
// same call the drawer's Restore button makes: fresh step-up, then POST
// issue the mutation ONCE (it is not idempotent and each try burns a step-up),
// then poll the observable state
const RESTORE = await page.evaluate(async ({ item, pw }) => {
  const status = await (
    await fetch("/api/auth/status", { credentials: "same-origin" })
  ).json();
  const step = await fetch("/api/auth/step-up", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": status.csrf_token,
    },
    body: JSON.stringify({ password: pw }),
  });
  if (step.status !== 200) return `step-up ${step.status}`;
  const { step_up_token } = await step.json();
  const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}/restore`, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "x-csrf-token": status.csrf_token,
      "x-step-up-token": step_up_token,
    },
  });
  return res.status;
}, { item: ITEM, pw: PW });
ok(RESTORE === 200, `restore undeletes the item (status ${RESTORE})`);

// 6b. a soft-deleted row is removable from the LIST (no drawer, no dead end).
// Its own throwaway item: the shared ITEM must survive for later steps.
{
  const PURGE_ITEM = "zz-purge-probe";
  const csrf = await page.evaluate(async () =>
    (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()).csrf_token);
  await page.evaluate(async ({ item, csrf }) => {
    await fetch("/api/admin/items", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({ name: item, notes: "", fields: [] }),
    });
    await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      method: "DELETE", credentials: "same-origin",
      headers: { "x-csrf-token": csrf },
    });
  }, { item: PURGE_ITEM, csrf });
  await page.goto(`${BASE}/items`);
  await until(() => page.evaluate(({ item }) =>
    [...document.querySelectorAll("tr")].some((r) =>
      r.textContent.includes(item) && /deleted/.test(r.textContent)), { item: PURGE_ITEM }),
    "the soft-deleted row");
  ok(
    await page.evaluate(({ item }) => {
      const row = [...document.querySelectorAll("tr")]
        .find((r) => r.textContent.includes(item));
      return !!row && [...row.querySelectorAll("button")]
        .some((b) => /^Purge$/.test(b.textContent.trim()));
    }, { item: PURGE_ITEM }),
    "a deleted row offers Purge in the list",
  );
  await clickRowButton(PURGE_ITEM, "^Purge$", "purge the deleted row");
  await expectPurgeConfirm(".scrim", PURGE_ITEM, "purge");
  await escapePurgeConfirm(".scrim", "purge");
  ok(true, "Escape closes the purge confirmation");
  await until(() => page.evaluate(async ({ item }) => {
    const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      credentials: "same-origin",
    });
    return res.status === 200 && (await res.json()).deleted === true;
  }, { item: PURGE_ITEM }), "the item to survive an Escape-cancelled purge");
  ok(true, "Escape cancelling keeps the item");
  await clickRowButton(PURGE_ITEM, "^Purge$", "re-open the purge confirmation");
  await until(() => page.evaluate(() => !!document.querySelector(".scrim form")), "purge confirmation again");
  await clickWhenReady("^Cancel$", ".scrim form", "cancel the purge");
  await until(() => page.evaluate(() => document.querySelector(".scrim") === null),
    "the purge confirmation to close on Cancel");
  ok(true, "Cancel closes the purge confirmation");
  // failure path: the dialog stays open with the inline error and the item
  await clickRowButton(PURGE_ITEM, "^Purge$", "re-open the purge for a failure test");
  await expectPurgeConfirm(".scrim", PURGE_ITEM, "purge failure test");
  try {
    await page.evaluate(() => {
      const original = window.fetch;
      window.__custosFetch = original;
      window.fetch = (input, init) => {
        const url = typeof input === "string" ? input : input.url;
        if (init?.method === "DELETE" && url.endsWith("/purge")) {
          return new Promise((resolve) => {
            window.__custosPurgeResolve = () => resolve(new Response(
              JSON.stringify({ code: "internal_error", message: "synthetic purge failure" }),
              { status: 500, headers: { "content-type": "application/json" } },
            ));
          });
        }
        return original(input, init);
      };
    });
    await clickWhenReady("^Purge item$", ".scrim form", "attempt the failing purge");
    await page.evaluate(() => {
      const form = document.querySelector(".scrim form");
      if (!form) throw new Error("purge confirmation closed early");
      form.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
      );
    });
    ok(await page.evaluate(() => !!document.querySelector(".scrim form")),
      "Escape cannot dismiss the confirmation while the purge is in flight");
    await page.evaluate(() => {
      window.__custosPurgeResolve();
    });
    await until(() => page.evaluate(() => {
      const form = document.querySelector(".scrim form");
      return !!form && (form.textContent || "").includes("synthetic purge failure");
    }), "the inline purge error");
    ok(await page.evaluate(async ({ item }) => {
      const form = document.querySelector(".scrim form");
      const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
        credentials: "same-origin",
      });
      return !!form && res.status === 200 && (await res.json()).deleted === true;
    }, { item: PURGE_ITEM }),
    "a failed purge keeps the dialog open with the error and the item soft-deleted");
  } finally {
    await page.evaluate(() => {
      if (window.__custosFetch) {
        window.fetch = window.__custosFetch;
        delete window.__custosFetch;
      }
      delete window.__custosPurgeResolve;
    });
  }
  await clickWhenReady("^Cancel$", ".scrim form", "cancel after the failed purge");
  await until(() => page.evaluate(() => document.querySelector(".scrim") === null),
    "the failed purge dialog to close on Cancel");
  await clickRowButton(PURGE_ITEM, "^Purge$", "re-open the purge for real");
  await until(() => page.evaluate(() => !!document.querySelector(".scrim form")), "purge confirmation for the purge");
  await clickWhenReady("^Purge item$", ".scrim form", "confirm the purge");
  await until(() => page.evaluate(() => document.querySelector(".scrim") === null),
    "the purge confirmation to close after a successful purge");
  await until(() => page.evaluate(async ({ item }) => {
    const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      credentials: "same-origin",
    });
    return res.status === 404;
  }, { item: PURGE_ITEM }), "the purged item to be gone");
  await until(() => page.evaluate(({ item }) =>
    ![...document.querySelectorAll("tr")].some((r) => r.textContent.includes(item)),
    { item: PURGE_ITEM }), "the purged row to disappear from the list");
  ok(true, "the purged row leaves the list without a manual reload");
  ok(true, "Purge from the list removes the deleted item for good");
}

// 6b-2. the drawer entry point runs its own confirm inside the item Drawer
// (nested scrim): it must need no password either and close the drawer after.
{
  const PURGE_DRAWER = "zz-purge-drawer";
  const csrf = await page.evaluate(async () =>
    (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()).csrf_token);
  await page.evaluate(async ({ item, csrf }) => {
    await fetch("/api/admin/items", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({ name: item, notes: "", fields: [] }),
    });
    await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      method: "DELETE", credentials: "same-origin",
      headers: { "x-csrf-token": csrf },
    });
  }, { item: PURGE_DRAWER, csrf });
  await page.goto(`${BASE}/items`);
  await until(() => page.evaluate(({ item }) =>
    [...document.querySelectorAll("tr")].some((r) =>
      r.textContent.includes(item) && /deleted/.test(r.textContent)), { item: PURGE_DRAWER }),
    "the drawer purge-probe row");
  await page.evaluate(({ item }) => {
    const row = [...document.querySelectorAll("tr")]
      .find((r) => r.textContent.includes(item));
    if (!row) throw new Error("deleted row not found");
    const open = [...row.querySelectorAll("button")]
      .find((b) => /^Open$/.test(b.textContent.trim()));
    if (!open) throw new Error("deleted row has no Open button");
    open.click();
  }, { item: PURGE_DRAWER });
  // wait for the item to load (the Purge button only renders once it has),
  // then type into Notes: the nested confirm must not disturb drawer state
  await until(() => page.evaluate(() => {
    const drawer = document.querySelector(".scrim .drawer");
    return !!drawer && [...drawer.querySelectorAll("button")]
      .some((b) => /^Purge$/.test(b.textContent.trim()));
  }), "the deleted item to load in the drawer");
  const NOTE = "unsaved draft survives the confirmation";
  await page.evaluate(({ note }) => {
    const set = (el, v) => {
      const s = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, "value").set;
      s.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    };
    const area = document.querySelector(".scrim textarea");
    if (!area) throw new Error("drawer notes textarea missing");
    set(area, note);
  }, { note: NOTE });
  await clickWhenReady("^Purge$", ".drawer", "purge from the drawer");
  await expectPurgeConfirm(".scrim .scrim", PURGE_DRAWER, "drawer purge");
  await escapePurgeConfirm(".scrim .scrim", "drawer purge");
  await expectDrawerKept(
    PURGE_DRAWER, NOTE,
    "Escape closes only the confirmation, keeping the drawer, its unsaved edits and the item",
  );
  await clickWhenReady("^Purge$", ".drawer", "re-open the drawer purge for cancel");
  await until(() => page.evaluate(() => !!document.querySelector(".scrim .scrim form")), "drawer purge confirmation for cancel");
  await clickWhenReady("^Cancel$", ".scrim .scrim form", "cancel the drawer purge");
  await until(() => page.evaluate(() => document.querySelector(".scrim .scrim") === null),
    "the drawer purge confirmation to close on cancel");
  await expectDrawerKept(
    PURGE_DRAWER, NOTE,
    "cancelling keeps the drawer open, its unsaved edits and the item soft-deleted",
  );
  await clickWhenReady("^Purge$", ".drawer", "re-open the drawer purge");
  await until(() => page.evaluate(() => !!document.querySelector(".scrim .scrim form")), "drawer purge confirmation again");
  await clickWhenReady("^Purge item$", ".scrim .scrim form", "confirm the drawer purge");
  await until(() => page.evaluate(async ({ item }) => {
    const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      credentials: "same-origin",
    });
    return res.status === 404;
  }, { item: PURGE_DRAWER }), "the drawer-purged item to be gone");
  await until(() => page.evaluate(() => document.querySelector(".scrim") === null),
    "the drawer to close after its purge");
  await until(() => page.evaluate(({ item }) =>
    ![...document.querySelectorAll("tr")].some((r) => r.textContent.includes(item)),
    { item: PURGE_DRAWER }), "the drawer-purged row to leave the list");
  ok(true, "the drawer-purged row leaves the list without a manual reload");
  ok(true, "the drawer closes after its purge");
}

// 6c. rename from the drawer: only the name moves — the probe carries a
// note and a field so "nothing is lost" is actually tested. Its own item.
{
  const REN_OLD = "zz-rename-old";
  const REN_NEW = "zz-中文-改名";
  const csrf = await page.evaluate(async () =>
    (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()).csrf_token);
  await page.evaluate(async ({ item, csrf }) => {
    await fetch("/api/admin/items", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({
        name: item,
        notes: "rename keeps me",
        fields: [{ name: "API_KEY", secret: true, value: "cu-test-rename" }],
      }),
    });
  }, { item: REN_OLD, csrf });
  await page.goto(`${BASE}/items`);
  await until(() => page.evaluate(({ item }) =>
    [...document.querySelectorAll("tr")].some((r) => r.textContent.includes(item)),
    { item: REN_OLD }), "the rename probe row");
  await page.evaluate(({ item }) => {
    const row = [...document.querySelectorAll("tr")].find((r) => r.textContent.includes(item));
    [...row.querySelectorAll("button")].find((b) => /^Open$/.test(b.textContent.trim())).click();
  }, { item: REN_OLD });
  await until(() => page.evaluate(() => !!document.querySelector(".drawer")), "the drawer");
  await clickWhenReady("^Rename$", ".drawer", "the rename toggle");
  await until(() => page.evaluate(() =>
    [...document.querySelectorAll(".drawer input")].some(
      (i) => i.closest("label")?.textContent.startsWith("New name"))), "the rename field");
  await page.evaluate(({ name }) => {
    const set = (el, v) => {
      const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
      s.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    };
    const label = [...document.querySelectorAll(".drawer input")].find(
      (i) => i.closest("label")?.textContent.startsWith("New name"));
    set(label, name);
  }, { name: REN_NEW });
  await clickWhenReady("^Apply rename$", ".drawer", "apply the rename");
  await until(() => page.evaluate(async ({ oldName, newName }) => {
    const r = await fetch(`/api/admin/items/${encodeURIComponent(newName)}`, {
      credentials: "same-origin",
    });
    if (r.status !== 200) return false;
    const gone = await fetch(`/api/admin/items/${encodeURIComponent(oldName)}`, {
      credentials: "same-origin",
    });
    return gone.status === 404;
  }, { oldName: REN_OLD, newName: REN_NEW }), "the renamed item");
  ok(true, "Rename from the drawer accepts a Chinese name");
  // the row moved with its contents: note and field survived
  const moved = await page.evaluate(async ({ newName }) => {
    const r = await fetch(`/api/admin/items/${encodeURIComponent(newName)}`, {
      credentials: "same-origin",
    });
    const body = await r.json();
    return { notes: body.notes, fields: body.fields.map((f) => f.name) };
  }, { newName: REN_NEW });
  ok(
    moved.notes === "rename keeps me" && moved.fields.includes("API_KEY"),
    `rename preserves notes and fields (got ${JSON.stringify(moved)})`,
  );
  // the list shows the new name without a manual reload
  await until(() => page.evaluate(({ newName }) =>
    [...document.querySelectorAll("tr")].some((r) => r.textContent.includes(newName)),
    { newName: REN_NEW }), "the renamed row in the list");
  ok(true, "the list reflects the new name");
  // conflict branch: renaming onto a live name surfaces the error notice
  await page.evaluate(async ({ newName, csrf }) => {
    await fetch("/api/admin/items", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({ name: "zz-rename-blocker", notes: "", fields: [] }),
    });
  }, { newName: REN_NEW, csrf });
  await page.goto(`${BASE}/items`);
  await until(() => page.evaluate(({ item }) =>
    [...document.querySelectorAll("tr")].some((r) => r.textContent.includes(item)),
    { item: REN_NEW }), "the renamed row after reload");
  await page.evaluate(({ item }) => {
    const row = [...document.querySelectorAll("tr")].find((r) => r.textContent.includes(item));
    [...row.querySelectorAll("button")].find((b) => /^Open$/.test(b.textContent.trim())).click();
  }, { item: REN_NEW });
  await until(() => page.evaluate(() => !!document.querySelector(".drawer")), "the drawer again");
  await clickWhenReady("^Rename$", ".drawer", "the rename toggle again");
  await until(() => page.evaluate(() =>
    [...document.querySelectorAll(".drawer input")].some(
      (i) => i.closest("label")?.textContent.startsWith("New name"))), "the rename field again");
  await page.evaluate(() => {
    const set = (el, v) => {
      const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
      s.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    };
    const label = [...document.querySelectorAll(".drawer input")].find(
      (i) => i.closest("label")?.textContent.startsWith("New name"));
    set(label, "zz-rename-blocker");
  });
  await clickWhenReady("^Apply rename$", ".drawer", "apply the conflicting rename");
  await until(() => page.evaluate(() =>
    (document.querySelector(".drawer")?.textContent || "").includes("already exists")),
    "the conflict notice");
  ok(true, "renaming onto a taken name shows the conflict notice");
  // rev 48: names are display labels — the DRAWER's rename path must accept
  // uppercase + spaces (the console trims too), the old name must 404 (the row
  // moved, not copied), case is significant, and the structural rules hold
  const SPACED = "Google Map";
  await page.goto(`${BASE}/items`);
  await until(() => page.evaluate(({ item }) =>
    [...document.querySelectorAll("tr")].some((r) => r.textContent.includes(item)),
    { item: REN_NEW }), "the spaced-name probe row");
  await page.evaluate(({ item }) => {
    const row = [...document.querySelectorAll("tr")].find((r) => r.textContent.includes(item));
    [...row.querySelectorAll("button")].find((b) => /^Open$/.test(b.textContent.trim())).click();
  }, { item: REN_NEW });
  await until(() => page.evaluate(() => !!document.querySelector(".drawer")), "the drawer");
  await clickWhenReady("^Rename$", ".drawer", "the rename toggle");
  await until(() => page.evaluate(() =>
    [...document.querySelectorAll(".drawer input")].some(
      (i) => i.closest("label")?.textContent.startsWith("New name"))), "the rename field");
  await page.evaluate(({ name }) => {
    const set = (el, v) => {
      const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
      s.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    };
    const label = [...document.querySelectorAll(".drawer input")].find(
      (i) => i.closest("label")?.textContent.startsWith("New name"));
    // a trailing space must be trimmed by the client, not rejected by the server
    set(label, ` ${name} `);
  }, { name: SPACED });
  await clickWhenReady("^Apply rename$", ".drawer", "apply the spaced rename");
  // wait for the rename to land before probing: the click returns before the
  // POST does, and an immediate fetch would read the pre-rename state
  await until(() => page.evaluate(async ({ oldName, newName }) => {
    const old = await fetch(`/api/admin/items/${encodeURIComponent(oldName)}`, { credentials: "same-origin" });
    if (old.status !== 404) return false;
    const fresh = await fetch(`/api/admin/items/${encodeURIComponent(newName)}`, { credentials: "same-origin" });
    return fresh.status === 200;
  }, { oldName: REN_NEW, newName: SPACED }), "the spaced rename to land");
  const renamedSpaced = await page.evaluate(async ({ newName }) => {
    const fresh = await fetch(`/api/admin/items/${encodeURIComponent(newName)}`, { credentials: "same-origin" });
    return { status: fresh.status, name: fresh.status === 200 ? (await fresh.json()).name : null };
  }, { newName: SPACED });
  ok(
    renamedSpaced.status === 200 && renamedSpaced.name === SPACED,
    `the drawer renames to a spaced, capitalised name (trailing space trimmed) (${JSON.stringify(renamedSpaced)})`,
  );
  // case and whitespace are significant; unaddressable names are refused
  const rules = await page.evaluate(async () => {
    const token = (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()).csrf_token;
    const post = async (name) => (await fetch("/api/admin/items", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": token },
      body: JSON.stringify({ name, fields: [] }),
    })).status;
    return {
      lower: await post("google map"),
      slash: await post("Google/Map"),
      pad: await post(" Google Map"),
      dots: await post(".."),
      long: await post("x".repeat(201)),
    };
  });
  ok(
    rules.lower === 201 && rules.slash === 422 && rules.pad === 422 && rules.dots === 422 && rules.long === 422,
    `case is significant and structural rules hold (${JSON.stringify(rules)})`,
  );
  await page.goto(`${BASE}/items`);
  await until(() => page.evaluate(({ item }) =>
    [...document.querySelectorAll("tr")].some((r) => r.textContent.includes(item)),
    { item: SPACED }), "the spaced row in the list");
  ok(true, "the list shows the spaced name verbatim");
}

// 6d. rename a field from the drawer (rev 46): the sealed value and the
// history move with the field; a sibling name is refused with a notice; the
// console re-seeds its form from the server afterwards, refreshes the list
// row, and its client guards (invalid / unchanged target) hold
{
  const FIELD_NEXT = "cu-test-field-rename-v2";
  const csrf = await page.evaluate(async () =>
    (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()).csrf_token);
  await page.goto(`${BASE}/items`);
  await until(() => page.evaluate(({ item }) =>
    [...document.querySelectorAll("tr")].some((r) => r.textContent.includes(item)),
    { item: ITEM }), "the item row after reload");
  // one value change first, so TOKEN carries history under its old name —
  // a PATCH touches only that field (a PUT rebuilt from the masked shape would
  // blank every other sealed field). Remember that snapshot by id: history is
  // item-scoped, so the move is proven on that row, not on "every row".
  const probe = await page.evaluate(async ({ item, csrf, next }) => {
    const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      method: "PATCH", credentials: "same-origin",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      body: JSON.stringify({ fields: [{ name: "TOKEN", secret: true, value: next }] }),
    });
    if (res.status !== 200) throw new Error(`field probe patch: ${res.status}`);
    const revision = (await res.json()).revision;
    const hist = await (await fetch(`/api/admin/items/${encodeURIComponent(item)}/history`, {
      credentials: "same-origin",
    })).json();
    const snap = hist.items.find((r) => r.name === "TOKEN");
    if (!snap) throw new Error("the probe left no TOKEN history row");
    return { revision, snapshotId: snap.id };
  }, { item: ITEM, csrf, next: FIELD_NEXT });
  await page.evaluate(({ item }) => {
    const row = [...document.querySelectorAll("tr")].find((r) => r.textContent.includes(item));
    if (!row) throw new Error("item row not found");
    [...row.querySelectorAll("button")].find((b) => /^Open$/.test(b.textContent.trim())).click();
  }, { item: ITEM });
  await until(() => page.evaluate(() => !!document.querySelector(".drawer .panel")),
    "the item drawer with its field panels");
  const panelNames = () => page.evaluate(() =>
    [...document.querySelectorAll(".drawer .panel .cell-main")]
      .map((el) => el.textContent.trim())
      .filter((n) => /^[A-Z][A-Z0-9_]*$/.test(n)));
  const hasRenameInput = () => page.evaluate(() =>
    [...document.querySelectorAll(".drawer input")].some(
      (i) => i.closest("label")?.textContent.startsWith("New field name")));
  const drawerRevision = () => page.evaluate(() =>
    Number((document.querySelector(".drawer-kicker")?.textContent || "").replace(/\D+/g, "")));
  const openFieldRename = async (from) => {
    await page.evaluate(({ from }) => {
      const panel = [...document.querySelectorAll(".drawer .panel")]
        .find((p) => p.querySelector(".cell-main")?.textContent.trim() === from);
      if (!panel) throw new Error(`no field panel named ${from}`);
      const button = [...panel.querySelectorAll("button")]
        .find((b) => b.textContent.trim() === "Rename field");
      if (!button) throw new Error(`no Rename field button on ${from}`);
      button.click();
    }, { from });
    // only the field rename renders this input (the item rename reads "New name")
    await until(() => hasRenameInput(), "the field rename input");
  };
  const fillFieldRename = async (to) => {
    await page.evaluate(({ to }) => {
      const input = [...document.querySelectorAll(".drawer input")].find(
        (i) => i.closest("label")?.textContent.startsWith("New field name"));
      if (!input) throw new Error("the field rename input is not open");
      const s = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
      s.call(input, to);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }, { to });
  };
  // the server lists fields name-ordered, so the panel under rename is rarely
  // the first one: click inside THAT panel, never `.drawer .panel`
  const applyFieldRename = (from) => until(() => page.evaluate(({ from }) => {
    const panel = [...document.querySelectorAll(".drawer .panel")]
      .find((p) => p.querySelector(".cell-main")?.textContent.trim() === from);
    const b = panel
      && [...panel.querySelectorAll("button")].find((x) => x.textContent.trim() === "Apply field rename");
    if (b && !b.disabled) { b.click(); return true; }
    return false;
  }, { from }), `apply the field rename (${from})`);
  // client guards: an invalid target surfaces the server's notice, and an
  // UNCHANGED target neither calls the server nor re-seeds the form (typed
  // notes must survive — a re-seed would also blank every sealed field)
  await page.evaluate(() => {
    const area = document.querySelector(".drawer textarea");
    if (!area) throw new Error("notes textarea not found");
    const s = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, "value").set;
    s.call(area, "unsaved note that must survive a no-op rename");
    area.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await openFieldRename("TOKEN");
  await fillFieldRename("token");
  await applyFieldRename("TOKEN");
  await until(() => page.evaluate(() =>
    (document.querySelector(".drawer")?.textContent || "").includes("invalid field name")),
    "the invalid-name notice");
  ok((await panelNames()).includes("TOKEN"), "a lowercase field name is refused with a notice and leaves the field in place");
  await fillFieldRename("TOKEN");
  await applyFieldRename("TOKEN");
  await until(async () => !(await hasRenameInput()), "the no-op rename to close its editor");
  ok(
    (await page.evaluate(() => document.querySelector(".drawer textarea")?.value || ""))
      === "unsaved note that must survive a no-op rename"
      && (await drawerRevision()) === probe.revision,
    "an unchanged field name is a no-op: typed notes survive and the revision does not move",
  );
  // conflict branch: a sibling's name is refused, the field stays
  await openFieldRename("TOKEN");
  await fillFieldRename("REGION");
  await applyFieldRename("TOKEN");
  await until(() => page.evaluate(() =>
    (document.querySelector(".drawer")?.textContent || "").includes("already exists")),
    "the field rename conflict notice");
  ok((await panelNames()).includes("TOKEN"), "a field rename onto a sibling name is refused and leaves the field in place");
  // success branch: only the name moves
  await fillFieldRename("ACCESS_KEY");
  await applyFieldRename("TOKEN");
  await until(async () => {
    const names = await panelNames();
    return names.includes("ACCESS_KEY") && !names.includes("TOKEN");
  }, "the renamed field panel");
  ok(true, "the drawer shows the field under its new name");
  ok((await drawerRevision()) === probe.revision + 1, "the drawer's revision reflects the rename");
  // the list behind the drawer refreshes too (revision column) — polled: that
  // refresh is a second fetch which lands after the drawer re-renders
  await until(() => page.evaluate(({ item, revision }) => {
    const row = [...document.querySelectorAll("tbody tr")].find((r) => r.textContent.includes(item));
    if (!row) return false;
    const cells = [...row.querySelectorAll("td")];
    return !!document.querySelector(".drawer") && cells.length >= 3
      && cells[2].textContent.trim() === String(revision);
  }, { item: ITEM, revision: probe.revision + 1 }),
    "the list row to reflect the new revision while the drawer stays open");
  ok(true, "the list row reflects the new revision while the drawer stays open");
  const after = await page.evaluate(async ({ item, snapshotId }) => {
    const got = await (await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      credentials: "same-origin",
    })).json();
    const hist = await (await fetch(`/api/admin/items/${encodeURIComponent(item)}/history`, {
      credentials: "same-origin",
    })).json();
    const moved = hist.items.find((r) => r.id === snapshotId);
    if (!moved) throw new Error("the probe snapshot vanished after the rename");
    const revealed = await (await fetch(
      `/api/admin/items/${encodeURIComponent(item)}/history/${snapshotId}/reveal`,
      { credentials: "same-origin" },
    )).json();
    const audit = await (await fetch("/api/admin/audit?action=field.rename", {
      credentials: "same-origin",
    })).json();
    // the audit feed is oldest-first: the row just written is the last one
    const last = audit.items.at(-1);
    return {
      names: got.fields.map((f) => f.name),
      masked: got.fields.some((f) => f.name === "ACCESS_KEY" && f.secret === true && !("value" in f)),
      revision: got.revision,
      movedName: moved.name,
      snapshotValue: revealed.value,
      auditRow: last ? { item: last.item_name, detail: last.detail } : null,
    };
  }, { item: ITEM, snapshotId: probe.snapshotId });
  ok(
    after.names.includes("ACCESS_KEY") && !after.names.includes("TOKEN") && after.masked,
    `the server moved the field and still masks it (${JSON.stringify(after.names)})`,
  );
  ok(after.revision === probe.revision + 1, `the item revision bumped once (${after.revision})`);
  ok(after.movedName === "ACCESS_KEY", `the field's history snapshot followed it (${after.movedName})`);
  ok(after.snapshotValue === SECRET_VALUE, "the history snapshot still reveals its sealed value after the move");
  ok(
    !!after.auditRow && after.auditRow.item === ITEM
      && after.auditRow.detail.field === "ACCESS_KEY" && after.auditRow.detail.from === "TOKEN",
    `the rename is audited with both names (${JSON.stringify(after.auditRow)})`,
  );
  // the live sealed value survived: reveal through the drawer
  await page.evaluate(() => {
    const panel = [...document.querySelectorAll(".drawer .panel")]
      .find((p) => p.querySelector(".cell-main")?.textContent.trim() === "ACCESS_KEY");
    if (!panel) throw new Error("no ACCESS_KEY panel to reveal");
    [...panel.querySelectorAll("button")].find((b) => /^Reveal$/.test(b.textContent.trim())).click();
  });
  await until(() => page.evaluate(({ next }) =>
    document.querySelector('[data-testid="revealed-ACCESS_KEY"]')?.textContent.trim() === next,
    { next: FIELD_NEXT }), "the revealed live value under the new name");
  ok(true, "the live secret reveals under the new name — nothing was re-sealed");
  // back again: the console drops the revealed plaintext keyed by the old name
  await openFieldRename("ACCESS_KEY");
  await fillFieldRename("TOKEN");
  await applyFieldRename("ACCESS_KEY");
  await until(async () => {
    const names = await panelNames();
    return names.includes("TOKEN") && !names.includes("ACCESS_KEY");
  }, "the field renamed back");
  ok(
    await page.evaluate(() =>
      !document.querySelector('[data-testid="revealed-ACCESS_KEY"]')
      && !document.querySelector('[data-testid="revealed-TOKEN"]')
      && !!document.querySelector(".drawer .panel .secret")),
    "a rename drops revealed plaintext from the drawer",
  );
  ok(!(await leaked(SECRET_VALUE)) && !(await leaked(FIELD_NEXT)), "no secret value leaked into the DOM after the renames");
  // the audit filter offers the new action
  await page.goto(`${BASE}/audit`);
  await until(() => page.evaluate(() => !!document.querySelector(".filter-grid select")), "the audit filter");
  ok(
    await page.evaluate(() =>
      [...document.querySelectorAll(".filter-grid select option")].some((o) => o.value === "field.rename")),
    "the audit filter lists field.rename",
  );
}

// 7. key mint: a header button opens the mint drawer (the console's modal
// idiom); session only (rev 39); full-authority model (rev 38: label only)
await page.goto(`${BASE}/keys`);
await until(
  () => page.evaluate(() => document.body.textContent.includes("Mint key")),
  "the keys screen",
);
ok(
  await page.evaluate(() =>
    ![...document.querySelectorAll("input")].some(
      (i) => i.closest("label")?.textContent.startsWith("Label"))),
  "the keys page shows no inline mint form — only the Mint key button",
);
await clickWhenReady("^Mint key$", null, "open the mint drawer");
await until(() => page.evaluate(() => !!document.querySelector(".drawer form")), "the mint drawer");
// the invariants every drawer shares (the item drawer's sticky action bar is
// its own check above; this form keeps its submit inside the form by contract)
ok(
  await page.evaluate(() => {
    const r = (el) => el.getBoundingClientRect();
    const drawer = document.querySelector(".drawer");
    return drawer.querySelectorAll(".card").length === 0
      && !!drawer.querySelector('.drawer-close[aria-label="Close"]')
      && getComputedStyle(document.documentElement).overflow === "hidden"
      // the cap is min(540px, viewport): compare against that, so a regression
      // to a full-width drawer fails at any viewport
      && Math.abs(r(drawer).width - Math.min(540, document.documentElement.clientWidth)) <= 1;
  }),
  "the mint drawer nests no cards, offers a Close control, locks the page behind it and stays within 540px",
);
ok(
  await page.evaluate(() => {
    const scrim = document.querySelector(".scrim");
    return !!scrim
      && scrim.getAttribute("role") === "dialog"
      && scrim.getAttribute("aria-modal") === "true"
      && !!scrim.querySelector(".drawer form");
  }),
  "the mint form is a modal dialog",
);
ok(
  await page.evaluate(() => {
    const label = document.querySelector(".drawer form input");
    return !!label && document.activeElement === label;
  }),
  "the Label input is focused when the drawer opens (panel focus does not steal autoFocus)",
);
// client-side validation stays inside the drawer: no step-up, no page error
await clickWhenReady("^Mint key$", ".drawer form", "submit the mint form with an empty label");
await until(
  () => page.evaluate(() =>
    (document.querySelector(".drawer")?.textContent || "").includes("label is required")),
  "the empty-label validation message",
);
ok(
  await page.evaluate(() =>
    !!document.querySelector(".drawer form") && !document.querySelector("form.drawer")),
  "an empty label is rejected inside the drawer, which stays open with no step-up",
);
await page.evaluate(() => {
  const label = [...document.querySelectorAll(".drawer form input")].find(
    (i) => i.closest("label")?.textContent.startsWith("Label"),
  );
  if (!label) throw new Error("key form label input not found");
  const set = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  set(label, "cu-test-console-key");
});
await clickWhenReady("^Mint key$", ".drawer form", "submit the mint form");
// the one-time token card appears with a cu-… value, and the label is listed
const MINTED_KEY = await (async () => {
  await until(
    () =>
      page.evaluate(() => {
        const panel = document.querySelector('[data-testid="one-time-panel"]');
        if (!panel) return false;
        return [...panel.querySelectorAll("input")].some((i) => i.value.startsWith("cu-"));
      }),
    "the one-time key panel",
  );
  return page.evaluate(() => {
    const panel = document.querySelector('[data-testid="one-time-panel"]');
    return [...panel.querySelectorAll("input")].find((i) => i.value.startsWith("cu-")).value;
  });
})();
ok(MINTED_KEY.startsWith("cu-"), "mint shows the token");
// checked AFTER the panel is visible: a step-up regression would have
// opened its prompt instead of the panel, so this cannot pass vacuously
ok(
  await page.evaluate(() => !document.querySelector("form.drawer")),
  "mint needs no step-up prompt (rev 39)",
);
ok(
  await page.evaluate(
    () => !!document.querySelector('[data-testid="one-time-panel"]'),
  ),
  "the one-time panel is rendered",
);
ok(
  await page.evaluate(() => !document.querySelector(".drawer form")),
  "the mint drawer closes after a successful mint",
);

// 7b. the inventory never carries the secret (the token IS re-revealable via
// the Reveal button — rev 37 — but never embedded in list/UI state)
await page.goto(`${BASE}/keys`);
await until(
  () => page.evaluate(() => document.body.textContent.includes("Mint key")),
  "the keys screen after reload",
);
await until(
  () =>
    page.evaluate(async ({ key }) => {
      // the inventory lists the key, but never its secret
      const res = await fetch("/api/admin/keys", { credentials: "same-origin" });
      if (res.status !== 200) return false;
      const body = await res.json();
      return (
        body.keys.some((k) => k.label === "cu-test-console-key") &&
        !JSON.stringify(body).includes(key.split(".")[1])
      );
    }, { key: MINTED_KEY }),
  "the inventory to list the key without its secret",
);
ok(
  !(await leaked(MINTED_KEY.split(".")[1])),
  "the inventory/UI never embeds the secret after a reload (text, inputs, attributes)",
);

// 7c. re-reveal: the row's Reveal button returns the SAME token on the
// session alone (rev 39 — no step-up)
await page.evaluate(() => {
  const row = [...document.querySelectorAll("tr")].find((r) =>
    r.textContent.includes("cu-test-console-key"));
  if (!row) throw new Error("minted key row not found");
  const btn = [...row.querySelectorAll("button")].find((b) => /Reveal/i.test(b.textContent));
  if (!btn || btn.disabled) throw new Error("Reveal button missing or disabled");
  btn.click();
});
await until(
  () => page.evaluate(({ key }) => {
    const panel = document.querySelector('[data-testid="one-time-panel"]');
    if (!panel) return false;
    return [...panel.querySelectorAll("input")].some((i) => i.value === key);
  }, { key: MINTED_KEY }),
  "the re-revealed token panel",
);
ok(
  await page.evaluate(() => !document.querySelector("form.drawer")),
  "Reveal needs no step-up prompt (rev 39)",
);
ok(true, "Reveal returns the exact minted token");
ok(
  await page.evaluate(() => {
    const text = document.querySelector('[data-testid="one-time-panel"]').textContent ?? "";
    return text.includes("re-reveal") && !text.includes("shown once");
  }),
  "the re-revealed panel uses the retrievable copy, not the shown-once copy",
);
ok(
  await page.evaluate(async () => {
    const res = await fetch("/api/admin/audit?action=key.reveal", { credentials: "same-origin" });
    if (res.status !== 200) return false;
    const body = await res.json();
    return body.items.some((x) => x.ok);
  }),
  "the console reveal left a key.reveal audit row",
);
await page.evaluate(() => {
  const panel = document.querySelector('[data-testid="one-time-panel"]');
  [...panel.querySelectorAll("button")].find((b) => /I have stored it/i.test(b.textContent)).click();
});

// 8. that mint is in the audit trail
await page.goto(`${BASE}/audit`);
await until(() => page.evaluate(() => document.body.textContent.includes("Audit")), "the audit screen");
await until(
  () =>
    page.evaluate(async () => {
      const res = await fetch("/api/admin/audit?action=key.mint", { credentials: "same-origin" });
      if (res.status !== 200) return false;
      const body = await res.json();
      return body.items.length > 0;
    }),
  "the key.mint audit row",
);
ok(true, "audit shows the key.mint row");

// 8b. the token the console showed is the real one (agent plane accepts it)
const KEY_WORKS = await page.evaluate(async ({ key }) => {
  const res = await fetch("/api/items", {
    headers: { Authorization: `Bearer ${key}` },
  });
  return res.status === 200;
}, { key: MINTED_KEY });
ok(KEY_WORKS, "the minted token authenticates on the agent plane");

// 9. device page strips the fragment and never prints the code
await page.goto(`${BASE}/device#cu-test-device-code-xyz`);
await page.evaluate(async () => {
  for (let i = 0; i < 80; i += 1) {
    if (!location.hash) return;
    await new Promise((r) => setTimeout(r, 100));
  }
});
ok(await page.evaluate(() => location.hash === ""), "device page strips the fragment");
ok(
  await page.evaluate(() => !document.body.textContent.includes("cu-test-device-code-xyz")),
  "device code never rendered",
);

// 10. the API keeps working throughout (no catch-all swallowed it)
ok(
  await page.evaluate(async () => {
    const res = await fetch("/api/auth/status", { credentials: "same-origin" });
    return res.status === 200 && (await res.json()).setup_required === false;
  }),
  "API still reachable after SPA navigation",
);

// 10b. TOTP enrolment shows a scannable QR, not just a bare secret
await page.goto(`${BASE}/settings`);
await until(() => page.evaluate(() =>
  [...document.querySelectorAll("button")].some((b) => /Enable TOTP/i.test(b.textContent))),
  "the account settings");
// rev 47: the passkey inventory loads with the session alone — the card
// settles without any step-up prompt (this stack cannot register a passkey,
// so the settled state is the empty inventory)
await until(() => page.evaluate(() =>
  (document.body.textContent || "").includes("No passkeys registered")),
  "the passkey inventory to settle");
ok(
  await page.evaluate(() =>
    !document.querySelector(".scrim")
    && ![...document.querySelectorAll("button")].some((b) => /Show registered passkeys/i.test(b.textContent))),
  "the passkey inventory lists without a step-up prompt",
);
ok(
  await page.evaluate(async () => (await fetch("/api/auth/passkeys", { credentials: "same-origin" })).status === 200),
  "GET /api/auth/passkeys answers to the bare session",
);
await clickWhenReady("Enable TOTP", null, "start TOTP enrolment");
await until(() => page.evaluate(() => !!document.querySelector(".scrim form")), "enrolment step-up");
await fillStepUp(PW, null);
await clickWhenReady("^Continue$", ".scrim form", "enrolment step-up continue");
await until(() => page.evaluate(() => !!document.querySelector('[data-testid="totp-qr"]')),
  "the enrolment QR");
ok(
  await page.evaluate(() => {
    const svg = document.querySelector('[data-testid="totp-qr"]');
    if (!svg) return false;
    const span = Number((svg.getAttribute("viewBox") || "").split(" ")[2] || 0);
    const cells = (svg.querySelector("path")?.getAttribute("d") || "").split("M").length - 1;
    // a real QR for an otpauth URI: >=25 modules + quiet zone, many dark cells
    return span >= 33 && cells > 200;
  }),
  "the enrolment QR is a real matrix (modules + quiet zone), not a placeholder",
);
// step 11 overwrites this unconfirmed enrolment with its own /totp/setup

// 10c. design invariants (DESIGN.md, sibling parity): the accent comes from
// the token and marks the primary action + current nav; controls are the
// sibling 42px; headers are mono 10px uppercase micro-labels.
const designProbe = () => page.evaluate(() => {
  const cs = (el) => getComputedStyle(el);
  const probe = document.createElement("div");
  probe.style.backgroundColor =
    cs(document.documentElement).getPropertyValue("--accent").trim();
  document.body.appendChild(probe);
  const accent = cs(probe).backgroundColor;
  probe.remove();
  const primary = document.querySelector("button.primary");
  const nav = document.querySelector('.nav a[aria-current="page"]');
  const th = document.querySelector("table th");
  const thStyle = th ? cs(th) : null;
  // every non-ghost control carries the sibling 42px height
  const controlHeights = [...document.querySelectorAll("button")]
    .filter((b) => !b.classList.contains("ghost"))
    .map((b) => Math.round(b.getBoundingClientRect().height));
  const cardRadii = [...document.querySelectorAll(".card")]
    .map((c) => cs(c).borderRadius);
  // visible text inputs only (checkbox/radio keep native sizing)
  const textInput = [...document.querySelectorAll("input, select, textarea")]
    .find((el) => {
      if (el.type === "checkbox" || el.type === "radio") return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    });
  return {
    accent,
    primaryBg: primary ? cs(primary).backgroundColor : null,
    controlHeights,
    navBg: nav ? cs(nav).backgroundColor : null,
    thFamily: thStyle ? thStyle.fontFamily : null,
    thSize: thStyle ? thStyle.fontSize : null,
    thTransform: thStyle ? thStyle.textTransform : null,
    thTracking: thStyle ? thStyle.letterSpacing : null,
    cardRadii,
    inputHeight: textInput ? Math.round(textInput.getBoundingClientRect().height) : null,
  };
});
for (const route of ["/items", "/keys", "/audit"]) {
  await page.goto(`${BASE}${route}`);
  await until(() => page.evaluate(() => !!document.querySelector("table th")), `the ${route} table`);
  const d = await designProbe();
  // the family palette itself, not just the relationships between elements
  ok(
    d.accent === "rgb(200, 247, 81)",
    `${route}: --accent is the family chartreuse (got ${d.accent})`,
  );
  ok(
    d.primaryBg === d.accent,
    `${route}: the primary action uses the accent token (${d.primaryBg} vs ${d.accent})`,
  );
  ok(
    d.controlHeights.length > 0 && d.controlHeights.every((h) => h === 42),
    `${route}: non-ghost controls are 42px (got ${JSON.stringify(d.controlHeights)})`,
  );
  ok(d.navBg === d.accent, `${route}: the current nav item carries the accent (${d.navBg})`);
  ok(
    /Geist Mono/i.test(d.thFamily || "") && d.thSize === "10px"
      && d.thTransform === "uppercase"
      && Math.abs(parseFloat(d.thTracking) - 0.8) < 0.01,
    `${route}: headers are Geist Mono 10px uppercase (${d.thFamily} ${d.thSize} ${d.thTransform} ${d.thTracking})`,
  );
  ok(
    d.cardRadii.length > 0 && d.cardRadii.every((r) => r === "18px"),
    `${route}: cards use the sibling 18px radius (got ${JSON.stringify(d.cardRadii)})`,
  );
  ok(
    route !== "/audit" || d.inputHeight === 44,
    `${route}: visible inputs are the sibling 44px (got ${d.inputHeight})`,
  );
}

// 10d. layout craft (sibling parity): one header rhythm with the action level
// with the title, aligned filter fields, row actions flush right, a sign-out
// that reads on the ink rail, and — at phone width — a top bar that sizes to
// its content with labelled card-rows instead of a sideways-scrolling table.
const craftProbe = () => page.evaluate(() => {
  const cs = (el) => getComputedStyle(el);
  const r = (el) => el.getBoundingClientRect();
  const q = (s) => document.querySelector(s);
  const qa = (s) => [...document.querySelectorAll(s)];
  const top = (el) => Math.round(r(el).top);
  const lum = (c) => {
    const m = c.match(/\d+/g).map(Number);
    const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]);
  };
  const contrast = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, n) => n - p); return (x + 0.05) / (y + 0.05); };
  const h1 = q("h1.page-title");
  const action = q(".page-actions button");
  const signout = q(".nav-signout");
  const sidebar = q(".sidebar");
  const fields = qa(".filter-grid input, .filter-grid select").filter((el) => r(el).width > 0);
  const firstRow = qa(".card.flush tbody tr")[0];
  const lastTd = firstRow ? [...firstRow.querySelectorAll("td")].pop() : null;
  const actions = firstRow ? firstRow.querySelector(".actions") : null;
  return {
    h1Top: h1 ? top(h1) : null,
    actionTop: action ? top(action) : null,
    hasKicker: !!q(".page-kicker"),
    signoutContrast: signout ? contrast(cs(signout).color, cs(sidebar).backgroundColor) : null,
    fieldTops: fields.map(top),
    fieldHeights: fields.map((el) => Math.round(r(el).height)),
    actionsInset: actions && lastTd ? Math.round(r(lastTd).right - r(actions).right) : null,
    thActionsAlign: (() => { const th = q("th.actions-cell"); return th ? cs(th).textAlign : null; })(),
    labelled: firstRow
      ? [...firstRow.querySelectorAll("td")].every((td) => td.hasAttribute("data-label"))
      : null,
  };
});
// The craft metrics are measured at a pinned desktop size: the driver's
// default viewport is not part of the contract, and "filter fields share one
// row" only holds from ~1320px up. The CDP bridge is a driver capability —
// name it if it is missing instead of dying on an opaque TypeError.
if (typeof page.cdp !== "function") {
  throw new Error("the browser driver exposes no CDP bridge (page.cdp): the viewport-pinned checks cannot run");
}
await page.cdp("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
try {
  for (const route of ["/items", "/keys", "/audit"]) {
    await page.goto(`${BASE}${route}`);
    await until(() => page.evaluate(() => !!document.querySelector("table th")), `the ${route} table`);
    const c = await craftProbe();
    ok(c.hasKicker, `${route}: the page header carries its mono kicker`);
    if (route !== "/audit") {
      ok(
        c.actionTop !== null && Math.abs(c.actionTop - c.h1Top) <= 2,
        `${route}: the header action is level with the title's first line (${c.actionTop} vs ${c.h1Top})`,
      );
      ok(c.thActionsAlign === "right", `${route}: the actions column is right-aligned (${c.thActionsAlign})`);
      // the audit table has no action column; only inventories carry row actions
      ok(
        c.actionsInset !== null && c.actionsInset >= 0 && c.actionsInset <= 24,
        `${route}: row actions sit flush with the cell's padding edge (${c.actionsInset}px)`,
      );
    }
    ok(
      c.signoutContrast >= 4.5,
      `${route}: the sidebar sign-out meets AA on the ink rail (${c.signoutContrast?.toFixed(1)}:1)`,
    );
    ok(c.labelled === true, `${route}: every table cell carries its narrow-screen label`);
    if (route === "/audit") {
      // at 1440 the five filter fields fit on one row: they must share a top
      ok(
        c.fieldTops.length >= 3 && new Set(c.fieldTops).size === 1,
        `${route}@1440: filter fields align on one row (tops ${JSON.stringify(c.fieldTops)})`,
      );
      ok(
        c.fieldHeights.every((h) => h === 44),
        `${route}: filter fields keep the sibling 44px (${JSON.stringify(c.fieldHeights)})`,
      );
    }
  }
} finally {
  await page.cdp("Emulation.clearDeviceMetricsOverride", {});
}
// phone width: the top bar must size to its content (an implicit grid row
// once stretched it to the leftover viewport height on short pages) and the
// page must not scroll sideways
await page.cdp("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: false });
try {
  for (const route of ["/items", "/audit", "/settings"]) {
    await page.goto(`${BASE}${route}`);
    // wait for the data, not the first paint: `main .card` exists while the
    // inventory still shows its loading state (and /audit's filter form is a
    // card of its own), which would measure a half-rendered page
    const ready = route === "/settings" ? "main .card" : "table th";
    await until(() => page.evaluate((sel) => !!document.querySelector(sel), ready), `the ${route} content`);
    // `narrow`, not `n`: `n` is the driver-wide CHECK counter
    const narrow = await page.evaluate(() => {
      const de = document.documentElement;
      const sb = document.querySelector(".sidebar");
      if (!sb) throw new Error("no .sidebar on the page");
      const td = document.querySelector(".card.flush tbody td");
      const thead = document.querySelector(".card.flush thead");
      return {
        overflow: de.scrollWidth > de.clientWidth,
        sidebarH: Math.round(sb.getBoundingClientRect().height),
        tdDisplay: td ? getComputedStyle(td).display : null,
        theadDisplay: thead ? getComputedStyle(thead).display : null,
      };
    });
    ok(!narrow.overflow, `${route}@390: no horizontal page overflow`);
    // bounded both ways: a collapsed bar must not pass as "sizes to its content"
    ok(narrow.sidebarH > 0 && narrow.sidebarH <= 130, `${route}@390: the top bar sizes to its content (${narrow.sidebarH}px)`);
    if (route !== "/settings") {
      ok(
        narrow.tdDisplay === "flex" && narrow.theadDisplay === "none",
        `${route}@390: table rows are labelled cards (${narrow.tdDisplay}, thead ${narrow.theadDisplay})`,
      );
    }
  }
} finally {
  await page.cdp("Emulation.clearDeviceMetricsOverride", {});
}

// 11. TOTP two-step sign-in (rev 37 login UX): enable TOTP through the real
// API, log out, and prove the credentials→code advance is client-side (no
// password-only POST burning a 401/lockout row), the recovery fallback lives
// on the code step and actually signs in, and the empty/wrong-code guards hold.
async function totpCodeAt(secretB32, step) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const bytes = [];
  for (const ch of secretB32.toUpperCase().replace(/=+$/, "")) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`non-base32 character in TOTP secret: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  const msg = new Uint8Array(8);
  let c = step;
  for (let i = 7; i >= 0; i -= 1) { msg[i] = c & 255; c = Math.floor(c / 256); }
  const subtle = globalThis.crypto?.subtle
    ?? (await import("node:crypto")).webcrypto.subtle;
  const key = await subtle.importKey(
    "raw", new Uint8Array(bytes), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = new Uint8Array(await subtle.sign("HMAC", key, msg));
  const off = sig[sig.length - 1] & 15;
  const num = (((sig[off] & 127) << 24) | (sig[off + 1] << 16)
    | (sig[off + 2] << 8) | sig[off + 3]) % 1000000;
  return String(num).padStart(6, "0");
}
const totpCode = (secret) => totpCodeAt(secret, Math.floor(Date.now() / 1000 / 30));
// the step-up site has a per-site monotonic replay counter: two step-ups in
// the same 30 s window must use different steps. Track the last accepted
// step and advance (waiting for the next window if the ±1 bound requires it).
let lastStepupStep = -1;
async function stepupCode(secret) {
  const deadline = Date.now() + 90000; // at most a few 30 s windows
  for (;;) {
    if (Date.now() > deadline) {
      throw new Error(`no usable step-up TOTP step (last=${lastStepupStep})`);
    }
    const nowStep = Math.floor(Date.now() / 1000 / 30);
    const step = Math.max(nowStep, lastStepupStep + 1);
    if (step <= nowStep + 1) {
      lastStepupStep = step;
      return totpCodeAt(secret, step);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
}
const post = (path, body, headers) => page.evaluate(async ({ path, body, headers }) => {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}, { path, body, headers });
const csrfNow = () => page.evaluate(async () => {
  const st = await (await fetch("/api/auth/status", { credentials: "same-origin" })).json();
  if (!st.csrf_token) throw new Error("no csrf_token: session is not live");
  return st.csrf_token;
});
const stepUp = async (totp) => {
  const csrf = await csrfNow();
  const r = await post("/api/auth/step-up",
    { password: PW, ...(totp ? { totp } : {}) }, { "x-csrf-token": csrf });
  if (r.status !== 200) throw new Error(`step-up failed: ${r.status}`);
  return { csrf, su: r.json.step_up_token };
};
// fill fields then poll until the target button is enabled before clicking
// (no fixed sleeps: a click on a still-disabled button is a flake)
const fillLogin = (pairs) => page.evaluate(({ pairs }) => {
  const set = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll("form.auth-form input")];
  for (const [kind, value] of pairs) {
    const el = kind === "otp"
      ? inputs.find((i) => i.getAttribute("autocomplete") === "one-time-code")
      : kind === "password"
        ? inputs.find((i) => i.type === "password")
        : inputs.find((i) => i.getAttribute("autocomplete") === "username");
    if (!el) throw new Error(`login input not found: ${kind}`);
    set(el, value);
  }
}, { pairs });
const logout = async () => {
  const csrf = await csrfNow();
  const r = await post("/api/auth/logout", {}, { "x-csrf-token": csrf });
  if (r.status !== 200) throw new Error(`logout failed: ${r.status}`);
  await page.goto(`${BASE}/`);
  await until(() => page.evaluate(() => !!document.querySelector("form.auth-form")), "login after logout");
};
let totpSecret = "";
let recoveryCodes = [];
{
  const { csrf, su } = await stepUp();
  const setupR = await post("/api/auth/totp/setup", {}, { "x-csrf-token": csrf, "x-step-up-token": su });
  if (setupR.status !== 200) throw new Error(`totp setup failed: ${setupR.status}`);
  totpSecret = setupR.json.secret;
  if (typeof totpSecret !== "string" || !/^[A-Z2-7]+=*$/i.test(totpSecret)) {
    throw new Error(`totp setup returned no base32 secret: ${JSON.stringify(setupR.json)}`);
  }
  const fresh = await stepUp();
  const confR = await post("/api/auth/totp/confirm", { code: await totpCode(totpSecret) },
    { "x-csrf-token": fresh.csrf, "x-step-up-token": fresh.su });
  ok(confR.status === 200 && confR.json.totp === "enabled", "TOTP enabled through the real API");
  const afterEnable = await page.evaluate(async () =>
    (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()));
  ok(
    afterEnable.totp_required === true && afterEnable.recovery_available === true,
    "status reports TOTP required and live recovery codes after enable",
  );
  recoveryCodes = confR.json.recovery_codes;
  ok(
    Array.isArray(recoveryCodes) && recoveryCodes.length >= 2
      && recoveryCodes.every((c) => typeof c === "string" && c.length > 0),
    "totp confirm issues at least two recovery codes",
  );
  await logout();
  ok(
    await page.evaluate(() =>
      !document.body.textContent.includes("Authenticator code")
      && ![...document.querySelectorAll("button")].some((b) => /recovery code/i.test(b.textContent))),
    "TOTP account: credentials step shows no code field and no recovery shortcut",
  );
  await fillLogin([["username", "operator"], ["password", PW]]);
  await clickWhenReady("^Continue$", "form.auth-form", "credentials submit");
  await until(() => page.evaluate(() =>
    document.body.textContent.includes("Verification code")), "the client-side code step");
  ok(true, "Sign in advances to the verification-code page");
  ok(
    await page.evaluate(() =>
      [...document.querySelectorAll("button")].some((b) =>
        /Use a recovery code instead/i.test(b.textContent))),
    "the recovery fallback lives on the code step",
  );
  await clickWhenReady("^Back$", null, "Back to credentials");
  await until(() => page.evaluate(() =>
    document.body.textContent.includes("Operator credentials only.")), "Back returns to credentials");
  ok(true, "Back returns to the credentials step");
  // recovery branch: the fallback actually signs in (recovery_reset session)
  await fillLogin([["username", "operator"], ["password", PW]]);
  await clickWhenReady("^Continue$", "form.auth-form", "credentials submit (recovery)");
  await until(() => page.evaluate(() =>
    document.body.textContent.includes("Verification code")), "code step (recovery)");
  await clickWhenReady("Use a recovery code instead", null, "toggle to recovery");
  await until(() => page.evaluate(() =>
    [...document.querySelectorAll("form.auth-form input")].some(
      (i) => i.getAttribute("autocomplete") === "one-time-code" && i.inputMode === "text")),
    "recovery field on the code step");
  await fillLogin([["otp", recoveryCodes[0]]]);
  await clickWhenReady("^Sign in$", "form.auth-form", "recovery submit");
  await until(() => page.evaluate(() => location.pathname === "/items"), "recovery-code sign-in");
  ok(true, "a recovery code on the code step completes sign-in");
  ok(
    await page.evaluate(async () =>
      (await fetch("/api/admin/items", { credentials: "same-origin" })).status === 403),
    "a recovery-code session is refused on the admin plane (recovery_reset)",
  );
  await logout();
  // empty-code client guard: no POST, error on the code step
  await fillLogin([["username", "operator"], ["password", PW]]);
  await clickWhenReady("^Continue$", "form.auth-form", "credentials submit (guards)");
  await until(() => page.evaluate(() =>
    document.body.textContent.includes("Verification code")), "code step (guards)");
  await clickWhenReady("^Sign in$", "form.auth-form", "empty-code submit");
  await until(() => page.evaluate(() =>
    document.body.textContent.includes("Enter your authenticator code.")), "empty-code guard message");
  ok(true, "empty code is guarded client-side");
  // wrong code: server 401, operator stays on the code step
  await fillLogin([["otp", "000000"]]);
  await clickWhenReady("^Sign in$", "form.auth-form", "wrong-code submit");
  await until(() => page.evaluate(() =>
    document.body.textContent.includes("Verification code")
    && document.body.textContent.includes("authentication failed")),
    "wrong code keeps the code step with the 401 message");
  ok(true, "a wrong code stays on the code step");
  // happy path: correct TOTP completes the two-step sign-in
  await fillLogin([["otp", await totpCode(totpSecret)]]);
  await clickWhenReady("^Sign in$", "form.auth-form", "TOTP submit");
  await until(() => page.evaluate(() => location.pathname === "/items"), "TOTP sign-in completes");
  ok(true, "password + authenticator code completes the two-step sign-in");
  // delta vs the authenticated baseline: the client-side advance and the
  // empty-code guard burned nothing; the wrong code burned exactly one;
  // the successful sign-in burned nothing
  ok(
    (await authFailures()) === failuresBaseline + 1,
    "advance + empty guard + success burned no lockout rows; wrong code burned one",
  );
  // a console step-up WITH the TOTP factor: ConfirmStepUp must render the
  // authenticator field (totpRequired prop) and the destructive Delete must
  // succeed (rev 39: Delete keeps its step-up; mint/reveal do not)
  await page.goto(`${BASE}/keys`);
  await until(() => page.evaluate(() =>
    [...document.querySelectorAll("button")].some((b) => /^Delete$/i.test(b.textContent))),
    "keys inventory with Delete");
  await page.evaluate(() => {
    const row = [...document.querySelectorAll("tr")].find((r) =>
      r.textContent.includes("cu-test-console-key"));
    if (!row) throw new Error("key row not found");
    const btn = [...row.querySelectorAll("button")].find((b) => /^Delete$/.test(b.textContent));
    if (!btn || btn.disabled) throw new Error("Delete button missing or disabled");
    btn.click();
  });
  await until(() => page.evaluate(() => !!document.querySelector(".scrim form")), "delete step-up");
  await until(() => page.evaluate(() =>
    (document.querySelector(".scrim form")?.textContent || "").includes("Authenticator code")),
    "the step-up dialog to ask for the TOTP factor");
  // a confirmation is a centred question (sibling idiom), not a side panel
  ok(
    await page.evaluate(async () => {
      const r = (el) => el.getBoundingClientRect();
      const dialog = document.querySelector(".drawer.dialog");
      const scrim = document.querySelector(".scrim.center");
      if (!dialog || !scrim) return false;
      // measure once the pop animation has landed (resolves at once under
      // reduced motion) instead of sleeping a guessed duration
      await Promise.all(dialog.getAnimations({ subtree: true }).map((a) => a.finished));
      const [dx, dh] = [r(dialog).top, r(dialog).height];
      const [sx, sh] = [r(scrim).top, r(scrim).height];
      return Math.abs((dx + dh / 2) - (sx + sh / 2)) <= 2
        && Math.abs((r(dialog).left + r(dialog).width / 2) - (r(scrim).left + r(scrim).width / 2)) <= 2
        // 26rem, capped by the viewport (the scrim's 24px padding each side)
        && Math.abs(r(dialog).width - Math.min(416, r(scrim).width - 48)) <= 1;
    }),
    "the step-up confirmation is centred and compact",
  );
  ok(
    await page.evaluate(() =>
      (document.querySelector(".scrim form")?.textContent || "").includes("permanently destroys")),
    "the step-up dialog asks for the TOTP factor and carries the destructive copy",
  );
  await fillStepUp(PW, await stepupCode(totpSecret));
  await clickWhenReady("^Continue$", ".scrim form", "delete step-up continue");
  await until(() => page.evaluate(() =>
    ![...document.querySelectorAll("tr")].some((r) =>
      r.textContent.includes("cu-test-console-key"))), "the deleted key row to disappear");
  ok(true, "Delete completes with a TOTP-gated step-up and the row is gone");
}

// 12. TOTP-off recovery window: disabling TOTP leaves the issued codes live,
// so the credentials page offers the inline recovery toggle (not a code step).
// (Passkey registration/sign-in is NOT browser-gated here: ego-browser's CDP
// session cannot attach a virtual authenticator to the page — create() gets
// NotAllowedError even on a fresh page. The passkey contract is covered by
// the backend integration tests with a soft ES256 authenticator.)
{
  const { csrf, su } = await stepUp(await stepupCode(totpSecret));
  const offR = await post("/api/auth/totp/disable", {}, { "x-csrf-token": csrf, "x-step-up-token": su });
  if (offR.status !== 200) throw new Error(`totp disable failed: ${offR.status}`);
  const st = await page.evaluate(async () =>
    (await (await fetch("/api/auth/status", { credentials: "same-origin" })).json()));
  ok(st.totp_required === false && st.recovery_available === true,
    "TOTP off with live recovery codes (the recovery window)");
  await logout();
  ok(
    await page.evaluate(() =>
      [...document.querySelectorAll("button")].some((b) =>
        /^Use a recovery code$/i.test(b.textContent))),
    "the credentials page offers the inline recovery toggle in the recovery window",
  );
  await clickWhenReady("^Use a recovery code$", null, "inline recovery toggle");
  await until(() => page.evaluate(() =>
    [...document.querySelectorAll("form.auth-form input")].some(
      (i) => i.getAttribute("autocomplete") === "one-time-code")), "inline recovery field");
  await fillLogin([["username", "operator"], ["password", PW], ["otp", recoveryCodes[1]]]);
  await clickWhenReady("^Sign in$", "form.auth-form", "recovery-window submit");
  await until(() => page.evaluate(() => location.pathname === "/items"), "recovery-window sign-in");
  ok(true, "a recovery code signs in from the credentials page in the recovery window");
  ok(
    await page.evaluate(async () =>
      (await fetch("/api/admin/items", { credentials: "same-origin" })).status === 403),
    "the recovery-window session is likewise confined (recovery_reset)",
  );
}

await space.finish({ keep: [] });
console.log("CONSOLE E2E PASS");
JSEOF

python3 - "$DRIVER" "$BASE" <<'PYEOF'
import pathlib, sys
path, base = pathlib.Path(sys.argv[1]), sys.argv[2]
path.write_text(path.read_text().replace("__BASE__", repr(base)))
PYEOF

# shellcheck disable=SC2086
if ! $CUSTOS_BROWSER_CMD < "$DRIVER" > "$RUN_DIR/browser.log" 2>&1; then
  tail -30 "$RUN_DIR/browser.log" >&2
  fail "browser checks (see $RUN_DIR/browser.log)"
fi
grep -q 'CONSOLE E2E PASS' "$RUN_DIR/browser.log" || fail "browser driver did not report a pass"
grep -E '^CHECK ' "$RUN_DIR/browser.log"
echo "E2E PASS (console)"