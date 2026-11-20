#!/usr/bin/env bash
# e2e_console.sh — real-browser gate for the operator console (design §8).
#
# Brings up the same throwaway stack as e2e.sh, then drives the BUILT console
# through a real browser: static contract, login, CSRF recovery after a reload,
# masked listing and drawer, step-up gated reveal, If-Match conflict and
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
mkdir -p "$LOG_DIR"
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
python3 - "$RUN_DIR" <<'PYEOF'
import base64, os, secrets, subprocess, sys
run = sys.argv[1]
b64url = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
os.makedirs(f"{run}/secrets", exist_ok=True)
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
            f"CUSTOS_ALLOWED_ORIGINS=http://127.0.0.1:{os.environ['E2E_PORT']}\n"
            f"CUSTOS_WEBAUTHN_RP_ID=127.0.0.1\n")
PYEOF

echo "== start stack (console baked into the image)"
"${COMPOSE[@]}" up -d --build > "$RUN_DIR/compose.log" 2>&1 || fail "compose up (see $RUN_DIR/compose.log)"
BASE="http://127.0.0.1:$E2E_PORT"
for i in $(seq 1 90); do
  curl -fsS -m 2 "$BASE/healthz" >/dev/null 2>&1 && break
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

// 4. opening the drawer still masks, and reveal is step-up gated
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
await until(() => page.evaluate(() => !!document.querySelector(".scrim form")), "the step-up prompt");
ok(
  await page.evaluate(() => document.body.textContent.includes("Confirm password")),
  "reveal demands a step-up",
);

// 5. pass the step-up: the value appears only now
await page.evaluate(async ({ pw }) => {
  const set = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const prompt = document.querySelector(".scrim form");
  set(prompt.querySelector('input[type="password"]'), pw);
  await new Promise((r) => setTimeout(r, 50));
  [...prompt.querySelectorAll("button")].find((b) => /Continue/i.test(b.textContent)).click();
}, { pw: PW });
await until(
  () =>
    page.evaluate(({ secret }) => {
      const drawer = document.querySelector(".drawer");
      return !!drawer && drawer.textContent.includes(secret);
    }, { secret: SECRET_VALUE }),
  "the revealed value",
);
ok(true, "revealed value appears after the step-up");

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
await until(
  () =>
    page.evaluate(async ({ item }) => {
      const res = await fetch(`/api/admin/items/${encodeURIComponent(item)}`, {
        credentials: "same-origin",
      });
      return (await res.json()).deleted === false;
    }, { item: ITEM }),
  "the item to be live again",
);

// 6c. If-Match is enforced: a stale revision is a 409, nothing is written
const MATCH = await page.evaluate(async ({ item, value }) => {
  const status = await (await fetch("/api/auth/status", { credentials: "same-origin" })).json();
  const created = await fetch("/api/admin/items", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", "x-csrf-token": status.csrf_token },
    body: JSON.stringify({
      name: `${item}-ifmatch`,
      notes: "",
      fields: [{ name: "V", secret: true, value }],
    }),
  });
  if (created.status !== 201) return { ok: false, why: `create ${created.status}` };
  const revision = (await created.json()).revision;
  const stale = await fetch(`/api/admin/items/${encodeURIComponent(item)}-ifmatch`, {
    method: "PUT",
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": status.csrf_token,
      "if-match": `"${revision + 5}"`,
    },
    body: JSON.stringify({ notes: "must not apply", fields: [] }),
  });
  const after = await (
    await fetch(`/api/admin/items/${encodeURIComponent(item)}-ifmatch`, {
      credentials: "same-origin",
    })
  ).json();
  return { ok: stale.status === 409 && after.notes === "", why: `stale=${stale.status}` };
}, { item: ITEM, value: SECRET_VALUE });
ok(MATCH.ok, `If-Match rejects a stale revision (${MATCH.why})`);

// 7. key mint: step-up gated, and the token is shown exactly once
await page.goto(`${BASE}/keys`);
await until(
  () => page.evaluate(() => document.body.textContent.includes("Mint a key")),
  "the keys screen",
);
await page.evaluate(() => {
  const label = [...document.querySelectorAll("input")].find(
    (i) => i.placeholder === "" && i.closest("label")?.textContent.startsWith("Label"),
  );
  const scopes = [...document.querySelectorAll("input")].find(
    (i) => i.closest("label")?.textContent.startsWith("Scopes"),
  );
  if (!label || !scopes) throw new Error("key form inputs not found");
  const set = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  set(label, "cu-test-console-key");
  set(scopes, "*");
  [...document.querySelectorAll("button")].find((b) => /Mint key/i.test(b.textContent)).click();
});
await until(() => page.evaluate(() => !!document.querySelector(".scrim form")), "the mint step-up prompt");
await page.evaluate(({ pw }) => {
  const prompt = document.querySelector(".scrim form");
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype, "value").set;
  const pwInput = prompt.querySelector('input[type="password"]');
  setter.call(pwInput, pw);
  pwInput.dispatchEvent(new Event("input", { bubbles: true }));
  [...prompt.querySelectorAll("button")].find((b) => /Continue/i.test(b.textContent)).click();
}, { pw: PW });
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
ok(
  await page.evaluate(
    () => !!document.querySelector('[data-testid="one-time-panel"]'),
  ),
  "the one-time panel is rendered",
);

// 7b. the token really is one-time: it is not retrievable again after a reload
await page.goto(`${BASE}/keys`);
await until(
  () => page.evaluate(() => document.body.textContent.includes("Mint a key")),
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
  "the token is not re-readable after a reload (text, inputs, attributes)",
);

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