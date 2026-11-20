// Live handshake test: drive the REAL wrapper over stdio against a running
// server. Skipped unless CUSTOS_TEST_URL + CUSTOS_TEST_KEY are set, so the
// unit suite stays hermetic.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";

const url = process.env.CUSTOS_TEST_URL;
const key = process.env.CUSTOS_TEST_KEY;

function frames(stream, onMessage) {
  let buffer = "";
  stream.on("data", (chunk) => {
    buffer += chunk.toString();
    let index;
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      try {
        onMessage(JSON.parse(line));
      } catch {
        // ignore non-JSON noise (the SDK writes nothing else)
      }
    }
  });
}

test("live stdio handshake and tool call", { skip: !url || !key }, async () => {
  const child = spawn(process.execPath, ["src/index.js"], {
    env: { ...process.env, CUSTOS_URL: url, CUSTOS_AGENT_KEY: key },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const pending = new Map();
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  frames(child.stdout, (msg) => {
    const resolver = pending.get(msg.id);
    if (resolver) {
      pending.delete(msg.id);
      resolver(msg);
    }
  });

  const rpc = (id, method, params) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timeout on ${method}`)), 8000);
      pending.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });

  try {
    const init = await rpc(1, "initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "custos-live-test", version: "0" },
    });
    assert.equal(init.result.serverInfo.name, "custos");
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`,
    );

    const list = await rpc(2, "tools/list", {});
    const names = list.result.tools.map((t) => t.name).sort();
    assert.deepEqual(names, [
      "custos_delete_item",
      "custos_env",
      "custos_get_item",
      "custos_list_items",
      "custos_patch_item",
      "custos_put_item",
      "custos_search",
    ]);

    // A previous run may have left the name soft-deleted (names stay
    // reserved); pick a fresh name so the test is repeatable.
    const itemName = `cu-test-mcp-wrapper-${process.pid}`;

    // a real round-trip through the agent plane
    const created = await rpc(3, "tools/call", {
      name: "custos_put_item",
      arguments: {
        name: itemName,
        notes: "stdio check",
        fields: [{ name: "TOKEN", secret: true, value: "cu-test-mcp-value" }],
      },
    });
    assert.ok(!created.result.isError, JSON.stringify(created.result));

    const env = await rpc(4, "tools/call", {
      name: "custos_env",
      arguments: { name: itemName },
    });
    assert.ok(!env.result.isError);
    assert.match(env.result.content[0].text, /export TOKEN='cu-test-mcp-value'/);

    const gone = await rpc(5, "tools/call", {
      name: "custos_delete_item",
      arguments: { name: itemName },
    });
    assert.ok(!gone.result.isError);
    assert.equal(stderr.includes(key), false, "the key must never reach stderr");
  } finally {
    child.stdin.end();
    child.kill();
  }
});
