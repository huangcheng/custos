import assert from "node:assert/strict";
import test from "node:test";

import { RequestError, createClient } from "../src/http.js";
import { TOOLS, TOOLS_BY_NAME } from "../src/tools.js";

const EXPECTED = [
  "custos_delete_item",
  "custos_env",
  "custos_get_item",
  "custos_list_items",
  "custos_patch_item",
  "custos_put_item",
  "custos_search",
];

test("exports exactly the seven spec tools", () => {
  assert.deepEqual(TOOLS.map((t) => t.name).sort(), EXPECTED);
  assert.equal(TOOLS_BY_NAME.size, 7);
});

test("every tool declares a schema and a builder", () => {
  for (const tool of TOOLS) {
    assert.equal(tool.inputSchema.type, "object", tool.name);
    assert.equal(typeof tool.build, "function", tool.name);
  }
});

test("put_item builds an upsert with optional if_match", () => {
  const req = TOOLS_BY_NAME.get("custos_put_item").build({
    name: "svc",
    notes: "n",
    fields: [{ name: "K", secret: true, value: "cu-test-v" }],
    if_match: "3",
  });
  assert.equal(req.method, "PUT");
  assert.equal(req.path, "/api/items/svc?upsert=1");
  assert.equal(req.ifMatch, "3");
  assert.deepEqual(req.body, { notes: "n", fields: [{ name: "K", secret: true, value: "cu-test-v" }] });
});

test("patch_item omits notes/fields that were not supplied", () => {
  // A patch with nothing to change is refused: it would bump the revision and
  // write an audit row for an empty operation.
  assert.throws(() => TOOLS_BY_NAME.get("custos_patch_item").build({ name: "svc" }));
  const withNotes = TOOLS_BY_NAME.get("custos_patch_item").build({ name: "svc", notes: "x" });
  assert.deepEqual(withNotes.body, { notes: "x" });
  const withFields = TOOLS_BY_NAME.get("custos_patch_item").build({
    name: "svc",
    fields: [{ name: "K", value: null }],
  });
  assert.deepEqual(withFields.body, { fields: [{ name: "K", value: null }] });
});

test("env requests text and never passes allow_hazardous", () => {
  const req = TOOLS_BY_NAME.get("custos_env").build({ name: "svc" });
  assert.equal(req.path, "/api/items/svc/env");
  assert.equal(req.accept, "text/plain");
  assert.equal(req.query, undefined);
  assert.ok(!req.path.includes("allow_hazardous"));
});

test("names are path-encoded", () => {
  const req = TOOLS_BY_NAME.get("custos_get_item").build({ name: "a b/c" });
  assert.equal(req.path, "/api/items/a%20b%2Fc");
});

test("list and search forward cursor and limit", () => {
  const list = TOOLS_BY_NAME.get("custos_list_items").build({ cursor: "c1", limit: 100 });
  assert.equal(list.path, "/api/items?limit=100&cursor=c1");
  const search = TOOLS_BY_NAME.get("custos_search").build({ q: "db", limit: 50 });
  assert.equal(search.path, "/api/search?q=db&limit=50");
});

function fakeFetch(status, payload) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return {
      status,
      ok: status >= 200 && status < 300,
      text: async () => (typeof payload === "string" ? payload : JSON.stringify(payload)),
    };
  };
  return { impl, calls };
}

test("client sends the bearer and normalizes a JSON body", async () => {
  const { impl, calls } = fakeFetch(200, { items: [], next_cursor: null });
  const client = createClient({ url: "http://127.0.0.1:8300/", key: "cu-test-key", fetchImpl: impl });
  const out = await client.request(TOOLS_BY_NAME.get("custos_list_items").build({}));
  assert.deepEqual(out.data, { items: [], next_cursor: null });
  assert.equal(calls[0].url, "http://127.0.0.1:8300/api/items?limit=50");
  assert.equal(calls[0].init.headers.authorization, "Bearer cu-test-key");
  assert.equal(calls[0].init.body, undefined);
});

test("error mapping keeps only code and message", async () => {
  const { impl } = fakeFetch(401, { code: "unauthorized", message: "authentication failed" });
  const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
  await assert.rejects(
    () => client.request({ method: "GET", path: "/api/items" }),
    (err) => {
      assert.ok(err instanceof RequestError);
      assert.equal(err.code, "unauthorized");
      assert.equal(err.message, "authentication failed");
      assert.ok(!err.message.includes("cu-test-key"));
      return true;
    },
  );
});

test("a non-JSON error body still yields a code and no body echo", async () => {
  const { impl } = fakeFetch(500, "<html>boom cu-test-body</html>");
  const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
  await assert.rejects(
    () => client.request({ method: "GET", path: "/api/items" }),
    (err) => {
      assert.equal(err.code, "error");
      assert.ok(!err.message.includes("cu-test-body"));
      return true;
    },
  );
});

test("transport failure names the target, never the key", async () => {
  const impl = async () => {
    throw new Error("ECONNREFUSED");
  };
  const client = createClient({ url: "http://127.0.0.1:9999", key: "cu-test-secret-key", fetchImpl: impl });
  await assert.rejects(
    () => client.request({ method: "GET", path: "/api/items" }),
    (err) => {
      assert.equal(err.code, "unreachable");
      assert.ok(!err.message.includes("cu-test-secret-key"));
      return true;
    },
  );
});

test("204 becomes ok, and if_match is quoted", async () => {
  const { impl, calls } = fakeFetch(204, "");
  const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
  const out = await client.request({
    method: "DELETE",
    path: "/api/items/svc",
    ifMatch: '"7"',
  });
  assert.equal(out.status, 204);
  // same shape the remote plane returns for custos_delete_item (§7)
  assert.deepEqual(out.data, { deleted: true });
  assert.equal(calls[0].init.headers["if-match"], '"7"');
});

test("a bodyless error is NOT reported as success", async () => {
  for (const status of [401, 403, 500, 502, 504]) {
    const { impl } = fakeFetch(status, "");
    const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
    await assert.rejects(
      () => client.request({ method: "PUT", path: "/api/items/svc" }),
      (err) => {
        assert.ok(err instanceof RequestError);
        assert.equal(err.code, "error");
        assert.match(err.message, new RegExp(String(status)));
        return true;
      },
      `status ${status} must not look like success`,
    );
  }
});

test("an unrecognized argument is rejected, not ignored", async () => {
  const { parseArgs } = await import("../src/index.js");
  assert.throws(() => parseArgs(["--urll=https://prod"]), RequestError);
  assert.throws(() => parseArgs(["--keey=cu-typo"]), RequestError);
});

test("missing config is a RequestError", () => {
  assert.throws(() => createClient({ url: "", key: "k" }), RequestError);
  assert.throws(() => createClient({ url: "http://h", key: "" }), RequestError);
  assert.throws(() => createClient({ url: "ftp://h", key: "k" }), RequestError);
});

test("parseArgs consumes a flag value and rejects a missing one", async () => {
  const { parseArgs } = await import("../src/index.js");
  assert.deepEqual(parseArgs(["--url", "http://h", "--key", "cu-k"]), {
    url: "http://h",
    key: "cu-k",
  });
  assert.deepEqual(parseArgs(["--url=http://h", "--key=k"]), { url: "http://h", key: "k" });
  // `--url --key secret` must not set url to the literal "--key"
  assert.throws(() => parseArgs(["--url", "--key", "secret"]), RequestError);
  assert.throws(() => parseArgs(["--key"]), RequestError);
});

test("missingRequired catches an absent name before any request", async () => {
  const { missingRequired } = await import("../src/index.js");
  const del = TOOLS_BY_NAME.get("custos_delete_item");
  assert.deepEqual(missingRequired(del, {}), ["name"]);
  assert.deepEqual(missingRequired(del, { name: "svc" }), []);
});

test("CUSTOS_URL must be a bare origin without credentials", () => {
  assert.throws(
    () => createClient({ url: "http://user:pass@h", key: "cu-k", fetchImpl: async () => {} }),
    RequestError,
  );
  assert.throws(
    () => createClient({ url: "http://h/?x=1", key: "cu-k", fetchImpl: async () => {} }),
    RequestError,
  );
});

test("a sub-path base is refused, not silently truncated", () => {
  // Dropping the path would send the bearer to another app on the same host.
  assert.throws(
    () => createClient({ url: "http://h:8300/some/path/", key: "cu-k", fetchImpl: async () => {} }),
    RequestError,
  );
});

test("an empty or dot-segment name never becomes a collection request", async () => {
  const { ToolInputError } = await import("../src/tools.js");
  for (const name of ["", ".", ".."]) {
    assert.throws(
      () => TOOLS_BY_NAME.get("custos_delete_item").build({ name }),
      (err) => {
        assert.ok(err instanceof ToolInputError);
        assert.equal(err.code, "invalid");
        assert.ok(!err.message.startsWith("invalid:"), "no doubled prefix");
        return true;
      },
    );
  }
});

test("an empty if_match is a guard, not a silent skip", async () => {
  const { impl, calls } = fakeFetch(200, { ok: true });
  const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
  await client.request({ method: "PATCH", path: "/api/items/s", body: {}, ifMatch: "" });
  assert.equal(calls[0].init.headers["if-match"], '""');
});

test("text/plain bodies stay text even when they look like JSON", async () => {
  const impl = async () => ({ status: 200, ok: true, text: async () => "123" });
  const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
  const out = await client.request({
    method: "GET",
    path: "/api/items/s/env",
    accept: "text/plain",
  });
  assert.deepEqual(out.data, { text: "123" });
});

test("a non-JSON answer from a JSON endpoint is a failure", async () => {
  const impl = async () => ({ status: 200, ok: true, text: async () => "not json" });
  const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
  await assert.rejects(
    () => client.request({ method: "GET", path: "/api/items" }),
    (err) => {
      assert.equal(err.code, "error");
      assert.match(err.message, /non-JSON/);
      return true;
    },
  );
});

test("a JSON null error body is handled, not a TypeError", async () => {
  const impl = async () => ({ status: 500, ok: false, text: async () => "null" });
  const client = createClient({ url: "http://h", key: "cu-test-key", fetchImpl: impl });
  await assert.rejects(
    () => client.request({ method: "GET", path: "/api/items" }),
    (err) => {
      assert.equal(err.code, "error");
      assert.match(err.message, /500/);
      return true;
    },
  );
});

test("loopback covers 127.0.0.0/8 and bracketed IPv6", async () => {
  // no cleartext warning for loopback, and the base keeps its form
  for (const url of ["http://127.0.0.5:8300", "http://[::1]:8300", "http://localhost:8300"]) {
    const client = createClient({ url, key: "cu-k", fetchImpl: async () => {} });
    assert.ok(client.base.startsWith("http://"), url);
  }
});

test("unknown argument keys are refused, not dropped", async () => {
  const { unexpectedArgs } = await import("../src/index.js");
  const put = TOOLS_BY_NAME.get("custos_put_item");
  assert.deepEqual(unexpectedArgs(put, { name: "s", notes: "", fields: [] }), []);
  // a camelCase/snake-case slip would otherwise silently drop the guard
  assert.deepEqual(unexpectedArgs(put, { name: "s", notes: "", fields: [], ifMatch: "3" }), [
    "ifMatch",
  ]);
});

test("a request is bounded by a timeout signal", async () => {
  let seen;
  const impl = async (_url, init) => {
    seen = init;
    return { status: 200, ok: true, text: async () => "{}" };
  };
  const client = createClient({ url: "http://h", key: "cu-k", fetchImpl: impl });
  await client.request({ method: "GET", path: "/api/items" });
  assert.ok(seen.signal instanceof AbortSignal);
});

test("an empty text/plain success body stays an empty export", async () => {
  const impl = async () => ({ status: 200, ok: true, text: async () => "" });
  const client = createClient({ url: "http://h", key: "cu-k", fetchImpl: impl });
  const out = await client.request({
    method: "GET",
    path: "/api/items/svc/env",
    accept: "text/plain",
  });
  assert.deepEqual(out.data, { text: "" });
});

test("search reuses the shared paging helper", () => {
  const req = TOOLS_BY_NAME.get("custos_search").build({ q: "db", cursor: "c", limit: 100 });
  assert.equal(req.path, "/api/search?q=db&limit=100&cursor=c");
});
