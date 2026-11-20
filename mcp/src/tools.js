// The seven agent tools (design §7) as data, so the schema, the request
// builder and the tests all read from one place. Admin-plane endpoints are
// deliberately absent: agents never get the admin surface.

/** Validation failures raised by a builder. Carries a code so the agent sees
 *  `invalid: ...` rather than a doubled `error: invalid: ...` prefix. */
export class ToolInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "ToolInputError";
    this.code = "invalid";
  }
}

const ROUTES = {
  items: "/api/items",
  search: "/api/search",
};

/** `encodeURIComponent` leaves "" and dot segments alone, and an empty name
 *  would hit the collection route (a DELETE there is not what was asked for). */
function itemPath(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new ToolInputError("name is required");
  }
  if (name === "." || name === "..") throw new ToolInputError("name is not a path");
  return `${ROUTES.items}/${encodeURIComponent(name)}`;
}

function pageQuery({ q, cursor, limit }) {
  const query = new URLSearchParams();
  if (q !== undefined) query.set("q", String(q));
  query.set("limit", String(limit ?? 50));
  if (cursor) query.set("cursor", cursor);
  return query.toString();
}

const FIELDS_SCHEMA = {
  type: "array",
  description:
    "Fields to store. Omit `value` on a secret field to keep its stored ciphertext.",
  items: {
    type: "object",
    required: ["name"],
    properties: {
      name: { type: "string", description: "UPPER_SNAKE field name" },
      secret: { type: "boolean" },
      value: { type: ["string", "null"] },
    },
  },
};

export const TOOLS = [
  {
    name: "custos_list_items",
    description: "List credential items visible to this key (metadata only, no values).",
    inputSchema: {
      type: "object",
      properties: {
        cursor: { type: "string", description: "Opaque cursor from a previous page" },
        limit: { type: "number", enum: [50, 100] },
      },
    },
    build({ cursor, limit } = {}) {
      return { method: "GET", path: `${ROUTES.items}?${pageQuery({ cursor, limit })}` };
    },
  },
  {
    name: "custos_search",
    description: "Case-insensitive search over item names, plain field names and notes.",
    inputSchema: {
      type: "object",
      required: ["q"],
      properties: {
        q: { type: "string", description: "Search text (max 256 chars)" },
        cursor: { type: "string" },
        limit: { type: "number", enum: [50, 100] },
      },
    },
    build({ q, cursor, limit } = {}) {
      return { method: "GET", path: `${ROUTES.search}?${pageQuery({ q: String(q ?? ""), cursor, limit })}` };
    },
  },
  {
    name: "custos_get_item",
    description: "Read one item: all field values, notes and revision.",
    inputSchema: {
      type: "object",
      required: ["name"],
      properties: { name: { type: "string" } },
    },
    build({ name } = {}) {
      return { method: "GET", path: itemPath(name) };
    },
  },
  {
    name: "custos_env",
    description:
      "Export an item as shell `export NAME='value'` lines. Hazardous names are refused.",
    inputSchema: {
      type: "object",
      required: ["name"],
      properties: { name: { type: "string" } },
    },
    build({ name } = {}) {
      // No allow_hazardous: §9 makes the refusal unconditional on this plane.
      return { method: "GET", path: `${itemPath(name)}/env`, accept: "text/plain" };
    },
  },
  {
    name: "custos_put_item",
    description:
      "Create or replace an item (server-side upsert). Omit a secret field's value to keep it.",
    inputSchema: {
      type: "object",
      required: ["name", "notes", "fields"],
      properties: {
        name: { type: "string" },
        notes: { type: "string" },
        fields: FIELDS_SCHEMA,
        if_match: { type: "string", description: "Expected current revision" },
      },
    },
    build({ name, notes, fields, if_match } = {}) {
      return {
        method: "PUT",
        path: `${itemPath(name)}?upsert=1`,
        body: { notes, fields },
        ifMatch: if_match,
      };
    },
  },
  {
    name: "custos_patch_item",
    description: "Merge fields into an existing item. `value: null` removes a field.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        notes: { type: ["string", "null"] },
        fields: FIELDS_SCHEMA,
        if_match: { type: "string" },
      },
      required: ["name"],
    },
    build({ name, notes, fields, if_match } = {}) {
      const body = {};
      if (notes !== undefined) body.notes = notes;
      if (fields !== undefined) body.fields = fields;
      if (Object.keys(body).length === 0) {
        // an empty PATCH bumps the revision and writes an audit row for
        // nothing: refuse it rather than mutate on a no-op
        throw new ToolInputError("patch needs notes or fields");
      }
      return { method: "PATCH", path: itemPath(name), body, ifMatch: if_match };
    },
  },
  {
    name: "custos_delete_item",
    description: "Soft-delete an item. Its name stays reserved until restored or purged.",
    inputSchema: {
      type: "object",
      required: ["name"],
      properties: { name: { type: "string" } },
    },
    build({ name } = {}) {
      return { method: "DELETE", path: itemPath(name) };
    },
  },
];

export const TOOLS_BY_NAME = new Map(TOOLS.map((tool) => [tool.name, tool]));
