#!/usr/bin/env bash
# e2e_console.sh — real-browser gate for the operator console (design §8).
#
# Brings up the same throwaway stack as e2e.sh, then drives the BUILT console
# through a real browser: static contract, login, CSRF recovery after a reload,
# masked listing and drawer, session-only reveal (rev 41), If-Match conflict and
# delete/restore, key mint (token shown once, and it must authenticate), the
# key.mint audit row, and the device hand-off fragment.
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
  await clickWhenReady("^Purge$", null, "purge the deleted row");
  await until(() => page.evaluate(() => !!document.querySelector(".scrim form")), "purge step-up");
  await fillStepUp(PW, null);
  await clickWhenReady("^Continue$", ".scrim form", "purge step-up continue");
  await until(() => page.evaluate(async ({ item }) => {
    const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
      credentials: "same-origin",
    });
    return res.status === 404;
  }, { item: PURGE_ITEM }), "the purged item to be gone");
  ok(true, "Purge from the list removes the deleted item for good");
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
for (const route of ["/items", "/audit"]) {
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