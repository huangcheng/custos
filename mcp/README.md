# custos-mcp

stdio MCP server for **Custos** — exposes the agent item plane to any MCP
client (Claude Desktop, Cursor, …) over stdio.

## Install

```bash
npx custos-mcp
```

## Configure

| Variable | Meaning |
|---|---|
| `CUSTOS_URL` | Base URL of your Custos server, e.g. `https://vault.example` |
| `CUSTOS_AGENT_KEY` | An agent key (`cu-…`) with the scopes you want the agent to have |

Both can also be passed as `--url` / `--key`. The key is read once at startup
and only ever sent in the `Authorization` header — it is never logged, and it
never appears in an error message.

### Client config

```json
{
  "mcpServers": {
    "custos": {
      "command": "npx",
      "args": ["-y", "custos-mcp"],
      "env": {
        "CUSTOS_URL": "https://vault.example",
        "CUSTOS_AGENT_KEY": "cu-…"
      }
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `custos_list_items` | List items visible to this key (metadata only) |
| `custos_search` | Search names, plain field names and notes |
| `custos_get_item` | Read one item's values |
| `custos_env` | Export an item as `export NAME='value'` lines |
| `custos_put_item` | Create or replace (server-side upsert) |
| `custos_patch_item` | Merge fields into an existing item |
| `custos_delete_item` | Soft-delete an item |

The table is identical to the server's remote `/mcp` surface — admin
operations (reveal, history, keys, audit) are deliberately **not** exposed
here, because an agent key must never reach the admin plane.

Omit a secret field's `value` in `custos_put_item` / `custos_patch_item` to
keep the stored ciphertext instead of overwriting it.

## Scope

Your key's scopes decide what these tools can see. An out-of-scope name is
indistinguishable from a missing one (404), by design.

## Privacy

The wrapper writes nothing to stdout except protocol frames, and nothing to
stderr except startup errors that carry no request data.
