#!/usr/bin/env node
// stdio MCP server for Custos (design §7). Speaks MCP on stdin/stdout and the
// agent REST plane to CUSTOS_URL. No logging of arguments, results or bodies.
//
// Uses the low-level Server API on purpose: tools.js holds JSON Schema, which
// is exactly what MCP negotiates, so the schema has one source of truth and is
// not restated as a Zod shape that could drift from it.

import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { RequestError, createClient } from "./http.js";
import { TOOLS, TOOLS_BY_NAME } from "./tools.js";

const USAGE =
  "custos-mcp: set CUSTOS_URL and CUSTOS_AGENT_KEY " +
  "(--url/--key exist for one-off use; prefer the env vars — argv is visible " +
  "to other local users via ps)";

export function parseArgs(argv) {
  const args = {};
  const take = (index, flag) => {
    const value = argv[index + 1];
    // a missing value or a following flag (`--url -h`) is a misconfiguration
    if (value === undefined || value.startsWith("-")) {
      throw new RequestError("invalid_config", `${flag} needs a value`);
    }
    // (the value itself is never echoed: it may be a credential)
    return value;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--url") {
      args.url = take(i, "--url");
      i += 1;
    } else if (arg.startsWith("--url=")) {
      args.url = arg.slice(6);
    } else if (arg === "--key") {
      args.key = take(i, "--key");
      i += 1;
    } else if (arg.startsWith("--key=")) {
      args.key = arg.slice(6);
    } else if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else {
      // An ignored typo would silently fall back to the env and talk to a
      // different instance. Name only the FLAG: `--key=cu-…` must never be
      // echoed to stderr (it may also carry URL credentials).
      // Echo the flag only when it IS a flag: a bare positional argument may
      // be a pasted credential.
      const flag = arg.startsWith("-") ? arg.split("=")[0] : "<positional argument>";
      throw new RequestError(
        "invalid_config",
        `unrecognized argument: ${flag} (allowed: --url, --key, --help)`,
      );
    }
  }
  return args;
}

/** The low-level Server does not enforce `inputSchema.required`; a missing
 *  name would become a literal `/api/items/undefined` request. */
export function missingRequired(tool, args) {
  const required = tool.inputSchema?.required ?? [];
  return required.filter((key) => args[key] === undefined || args[key] === null);
}

/** Unknown keys are refused rather than dropped: a client that sends
 *  `ifMatch`/`if-match` instead of `if_match` would otherwise get a silent
 *  unguarded write instead of the optimistic-concurrency guard it asked for. */
export function unexpectedArgs(tool, args) {
  const known = new Set(Object.keys(tool.inputSchema?.properties ?? {}));
  return Object.keys(args).filter((key) => !known.has(key));
}

export function buildServer(client) {
  const server = new Server(
    { name: "custos", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const tool = TOOLS_BY_NAME.get(name);
    if (!tool) {
      return {
        isError: true,
        content: [{ type: "text", text: `unknown_tool: ${name}` }],
      };
    }
    const missing = missingRequired(tool, args ?? {});
    if (missing.length > 0) {
      return {
        isError: true,
        content: [
          { type: "text", text: `invalid: missing required argument(s): ${missing.join(", ")}` },
        ],
      };
    }
    const unexpected = unexpectedArgs(tool, args ?? {});
    if (unexpected.length > 0) {
      return {
        isError: true,
        content: [
          { type: "text", text: `invalid: unknown argument(s): ${unexpected.join(", ")}` },
        ],
      };
    }
    try {
      const prepared = tool.build(args ?? {});
      const result = await client.request(prepared);
      const payload =
        prepared.accept === "text/plain" && typeof result.data.text === "string"
          ? result.data.text
          : JSON.stringify(result.data, null, 2);
      return { content: [{ type: "text", text: payload }] };
    } catch (err) {
      // only the server's own code/message: never a body, never the key
      const code =
        err instanceof RequestError || typeof err?.code === "string" ? err.code : "error";
      const message = err instanceof Error ? err.message : String(err);
      return {
        isError: true,
        content: [{ type: "text", text: `${code}: ${message}` }],
      };
    }
  });

  return server;
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`custos-mcp: ${err.message}\n`);
    process.exitCode = 2;
    return;
  }
  if (args.help) {
    process.stderr.write(`${USAGE}\n`);
    return;
  }
  const url = args.url ?? process.env.CUSTOS_URL;
  const key = args.key ?? process.env.CUSTOS_AGENT_KEY;
  if (!url || !key) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  let client;
  try {
    client = createClient({ url, key });
  } catch (err) {
    process.stderr.write(`custos-mcp: ${err.message}\n`);
    process.exitCode = 2;
    return;
  }
  const server = buildServer(client);
  await server.connect(new StdioServerTransport());
}

// Only auto-start when executed, so tests can import buildServer freely.
// pathToFileURL, not string concatenation: a path with a space, '%', '#' or a
// non-ASCII character would otherwise never match and the server would exit
// silently without reading stdin.
function invokedDirectly() {
  if (process.argv[1] === undefined) return false;
  try {
    // realpath: `npx`/global installs run through a symlink in .bin while
    // import.meta.url is already resolved
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main().catch((err) => {
    // the message only: never a stack (it could carry a request body)
    process.stderr.write(`custos-mcp: failed to start: ${err?.message ?? "unknown"}\n`);
    process.exitCode = 1;
  });
}
