// Thin REST client for the agent plane. Nothing here logs: the wrapper must
// never write a tool argument, a result body or the key anywhere (§7).

export class RequestError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "RequestError";
    this.code = code;
  }
}

const DEFAULT_TIMEOUT_MS = 30_000;
function isLoopback(hostname) {
  if (!hostname) return false;
  const host = hostname.replace(/^\[|\]$/g, ""); // URL keeps IPv6 brackets
  if (host === "localhost" || host === "::1") return true;
  // §3 pins the whole 127.0.0.0/8 block, not just .0.1
  return /^127\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$/.test(host);
}

function assertUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new RequestError("invalid_config", "CUSTOS_URL is not a valid URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new RequestError("invalid_config", "CUSTOS_URL must be http(s)");
  }
  if (parsed.username || parsed.password) {
    throw new RequestError("invalid_config", "CUSTOS_URL must not embed credentials");
  }
  if (parsed.search || parsed.hash) {
    throw new RequestError("invalid_config", "CUSTOS_URL must be a bare origin");
  }
  if (parsed.pathname !== "/" && parsed.pathname !== "") {
    // dropping the path would send the bearer to a different app on the same
    // host; refusing is the only safe reading of a sub-path deployment
    throw new RequestError(
      "invalid_config",
      "CUSTOS_URL must not include a path — Custos serves the API at the origin root",
    );
  }
  if (parsed.protocol === "http:" && !isLoopback(parsed.hostname)) {
    process.stderr.write(
      "custos-mcp: warning: sending the agent key over cleartext http to a non-loopback host\n",
    );
  }
  // origin only: a path/query would make `${base}${path}` resolve elsewhere
  return parsed.origin;
}

export function createClient({ url, key, fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (!url) throw new RequestError("invalid_config", "CUSTOS_URL is required");
  if (!key) throw new RequestError("invalid_config", "CUSTOS_AGENT_KEY is required");
  const base = assertUrl(url);

  async function request({ method, path, body, ifMatch, accept }) {
    const headers = {
      authorization: `Bearer ${key}`,
      accept: accept ?? "application/json",
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    // `undefined` = no guard; anything else (including "") is a guard the
    // caller asked for, and the server rejects a malformed tag as 422
    if (ifMatch !== undefined && ifMatch !== null) {
      headers["if-match"] = `"${String(ifMatch).replaceAll('"', "")}"`;
    }

    let res;
    try {
      res = await fetchImpl(`${base}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        // a hung backend must surface as `unreachable`, not as a tool call
        // that never returns
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      // base is a bare origin: no key, path or query can leak here
      throw new RequestError("unreachable", `cannot reach ${base}`);
    }

    let text;
    try {
      text = await res.text();
    } catch {
      // AbortSignal.timeout also aborts the body stream: a backend that stalls
      // after the headers is `unreachable`, not a raw abort error
      throw new RequestError("unreachable", `cannot read the response from ${base}`);
    }
    if (text.length === 0) {
      // The ok-check must come FIRST: a bodyless 401/500 from a proxy would
      // otherwise be reported to the agent as success.
      if (!res.ok) {
        throw new RequestError("error", `request failed with status ${res.status}`);
      }
      if (res.status === 204) {
        // match the remote plane's delete result (§7 "identical tools both ways")
        return { ok: true, status: 204, data: { deleted: true } };
      }
      // an empty body keeps its media type: an empty `custos_env` export must
      // reach the agent as "", not as "{}"
      const wantsText = (accept ?? "").startsWith("text/");
      return {
        ok: true,
        status: res.status,
        data: wantsText ? { text: "" } : {},
      };
    }
    // The ok-check comes FIRST, before any media-type branch: a text/plain
    // error page must not reach the agent as a successful result. Custos still
    // renders AppError as JSON for a text/* request, so try the envelope.
    if (!res.ok && (accept ?? "").startsWith("text/")) {
      try {
        const envelope = JSON.parse(text);
        if (envelope && typeof envelope === "object" && typeof envelope.code === "string") {
          throw new RequestError(
            envelope.code,
            typeof envelope.message === "string"
              ? envelope.message
              : `request failed with status ${res.status}`,
          );
        }
      } catch (err) {
        if (err instanceof RequestError) throw err;
        // not JSON (a proxy's HTML error page): report the status only
      }
      throw new RequestError("error", `request failed with status ${res.status}`);
    }
    if (!res.ok) {
      let data;
      let parsed = true;
      try {
        data = JSON.parse(text);
      } catch {
        parsed = false;
      }
      const isObject = parsed && data !== null && typeof data === "object";
      const code = isObject && typeof data.code === "string" ? data.code : "error";
      const message =
        isObject && typeof data.message === "string"
          ? data.message
          : `request failed with status ${res.status}`;
      throw new RequestError(code, message);
    }
    if ((accept ?? "").startsWith("text/")) {
      return { ok: true, status: res.status, data: { text } };
    }
    let data;
    let parsed = true;
    try {
      data = JSON.parse(text);
    } catch {
      parsed = false;
    }
    const isObject = parsed && data !== null && typeof data === "object";
    if (!isObject) {
      // a JSON endpoint answering with a scalar or non-JSON is a broken
      // deployment: report it instead of handing raw bytes back as success
      throw new RequestError(
        "error",
        `${base} returned a non-JSON response (status ${res.status})`,
      );
    }
    return { ok: true, status: res.status, data };
  }

  return { request, base };
}
