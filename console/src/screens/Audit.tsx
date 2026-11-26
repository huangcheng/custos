import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import { Button, Notice, TextField } from "../components/Field";
import { auditQuery, type AuditFilters } from "../keys";
import { truncate } from "../plain";
import type { AuditRow, Page } from "../types";

const ACTIONS = [
  "",
  "list",
  "get",
  "env",
  "create",
  "put",
  "patch",
  "delete",
  "restore", "rename",
  "purge",
  "force_drop",
  "history",
  "reveal",
  "key.mint",
  "key.revoke",
  "key.list",
  "token.mint",
  "token.revoke",
  "token.list",
  "operator.login",
  "operator.logout",
  "operator.step_up",
  "operator.password_change",
  "operator.totp_change",
  "operator.passkey_change",
  "operator.recovery_regen",
  "operator.setup",
  "account.unlock",
  "rekey",
  "rekey_verify",
  "retention",
  "auth.failure",
  "device.login",
  "search",
];

export function Audit() {
  const [filters, setFilters] = useState<AuditFilters>({});
  const [draft, setDraft] = useState({ actor: "", action: "", item: "", from: "", to: "" });
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<number | null>(null);

  // Filter changes and "Load more" both fetch; a stale response must never be
  // appended to a newer filter set, so every call carries a generation stamp.
  const generation = useRef(0);

  const load = useCallback(
    async (next: string | null, active: AuditFilters) => {
      const mine = (generation.current += 1);
      setLoading(true);
      setError("");
      try {
        const page = await api<Page<AuditRow>>(
          "GET",
          `/api/admin/audit?${auditQuery({ ...active, cursor: next })}`,
        );
        if (generation.current !== mine) return; // superseded
        setRows((prev) => (next ? [...prev, ...page.items] : page.items));
        setCursor(page.next_cursor);
      } catch (err) {
        if (generation.current !== mine) return;
        setError(err instanceof ApiError ? err.message : "cannot load the audit log");
      } finally {
        if (generation.current === mine) setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void load(null, filters);
  }, [load, filters]);

  return (
    <>
      <h1 className="page-title">Audit</h1>
      <p className="page-sub">
        Metadata only — never a secret value, notes text, or search term.
      </p>
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="card stack" style={{ marginBottom: 16 }}>
        <div className="row">
          <TextField
            label="Actor ID"
            value={draft.actor}
            onChange={(next) => setDraft((prev) => ({ ...prev, actor: next }))}
            hint="Exact actor id (a 12-hex key id or the session uuid), not the label"
          />
          <TextField
            label="Item"
            value={draft.item}
            onChange={(next) => setDraft((prev) => ({ ...prev, item: next }))}
          />
          <label>
            <span>Action</span>
            <select
              value={draft.action}
              onChange={(event) => setDraft((prev) => ({ ...prev, action: event.target.value }))}
            >
              {ACTIONS.map((action) => (
                <option key={action || "any"} value={action}>
                  {action || "any"}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="row">
          <TextField
            label="From"
            value={draft.from}
            onChange={(next) => setDraft((prev) => ({ ...prev, from: next }))}
            hint="ISO 8601 with timezone"
          />
          <TextField
            label="To"
            value={draft.to}
            onChange={(next) => setDraft((prev) => ({ ...prev, to: next }))}
            hint="ISO 8601 with timezone"
          />
          <span className="row-end" />
          <Button
            label="Apply"
            variant="primary"
            onClick={() => setFilters({ ...draft })}
          />
          <Button
            label="Clear"
            variant="ghost"
            onClick={() => {
              setDraft({ actor: "", action: "", item: "", from: "", to: "" });
              setFilters({});
            }}
          />
        </div>
      </div>
      <div className="card" style={{ padding: 0 }}>
        {rows.length === 0 && !loading ? (
          <div className="empty">No entries match these filters.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Item</th>
                <th>OK</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <Fragment key={row.id}>
                  <tr
                    onClick={() => setOpen((prev) => (prev === row.id ? null : row.id))}
                    style={{ cursor: "pointer" }}
                  >
                    <td className="mono muted">{row.ts.slice(0, 19).replace("T", " ")}</td>
                    <td className="mono" title={row.actor_label}>
                      {truncate(row.actor_label, 20)}
                      <span className="muted"> · {row.actor_kind}</span>
                    </td>
                    <td className="mono">{row.action}</td>
                    <td className="mono">{row.item_name ? truncate(row.item_name, 24) : "—"}</td>
                    <td>
                      <span className={`pill ${row.ok ? "" : "danger"}`}>
                        {row.ok ? "ok" : "fail"}
                      </span>
                    </td>
                  </tr>
                  {open === row.id ? (
                    <tr>
                      <td colSpan={5}>
                        <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                          {JSON.stringify(row.detail, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {cursor ? (
        <div className="row" style={{ marginTop: 14 }}>
          <Button
            label={loading ? "Loading…" : "Load more"}
            onClick={() => void load(cursor, filters)}
            disabled={loading}
          />
        </div>
      ) : null}
    </>
  );
}