import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import { Button, Notice, SelectField, TextField } from "../components/Field";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { IconAudit, IconChevron } from "../components/icons";
import { auditQuery, type AuditFilters } from "../keys";
import { stamp, truncate } from "../plain";
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
  "restore", "rename", "field.rename",
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
  // a failed fetch must never read as a filter miss
  const [loadFailed, setLoadFailed] = useState(false);
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
        setLoadFailed(false);
        setRows((prev) => (next ? [...prev, ...page.items] : page.items));
        setCursor(page.next_cursor);
      } catch (err) {
        if (generation.current !== mine) return;
        setLoadFailed(true);
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

  // a trail that has not loaded yet must never read as "nothing matched", and
  // a failed fetch must never read as an empty trail
  const emptyState = () => {
    if (loading) return <EmptyState title="Loading entries…" />;
    if (loadFailed) return <EmptyState title="Cannot load the audit log" />;
    return (
      <EmptyState mark={<IconAudit size={22} />} title="No entries match these filters">
        Widen the time window or clear the filters to see the whole trail.
      </EmptyState>
    );
  };

  return (
    <>
      <PageHeader
        kicker="Audit trail"
        title="Audit"
        lede="Metadata only — never a secret value, notes text, or search term."
      />
      {error ? <Notice kind="error">{error}</Notice> : null}
      <form
        className="card stack"
        onSubmit={(event) => {
          event.preventDefault();
          setFilters({ ...draft });
        }}
      >
        <div className="filter-grid">
          <TextField
            label="Actor ID"
            name="actor"
            value={draft.actor}
            onChange={(next) => setDraft((prev) => ({ ...prev, actor: next }))}
            hint="Exact actor id (a 12-hex key id or the session uuid), not the label"
          />
          <TextField
            label="Item"
            name="item"
            value={draft.item}
            onChange={(next) => setDraft((prev) => ({ ...prev, item: next }))}
          />
          <SelectField
            label="Action"
            name="action"
            value={draft.action}
            options={ACTIONS.map((action) => ({ value: action, label: action || "any" }))}
            onChange={(next) => setDraft((prev) => ({ ...prev, action: next }))}
          />
          <TextField
            label="From"
            name="from"
            value={draft.from}
            onChange={(next) => setDraft((prev) => ({ ...prev, from: next }))}
            hint="ISO 8601 with timezone"
          />
          <TextField
            label="To"
            name="to"
            value={draft.to}
            onChange={(next) => setDraft((prev) => ({ ...prev, to: next }))}
            hint="ISO 8601 with timezone"
          />
        </div>
        <div className="form-actions">
          <Button
            label="Clear"
            variant="ghost"
            type="button"
            onClick={() => {
              setDraft({ actor: "", action: "", item: "", from: "", to: "" });
              setFilters({});
            }}
          />
          <Button label="Apply" variant="primary" type="submit" />
        </div>
      </form>
      <div className="card flush">
        {rows.length === 0 ? (
          emptyState()
        ) : (
          <>
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Item</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <Fragment key={row.id}>
                    <tr
                      className="clickable"
                      onClick={() => setOpen((prev) => (prev === row.id ? null : row.id))}
                    >
                      <td data-label="When">
                        {/* a real button so the disclosure works from the keyboard */}
                        <button
                          type="button"
                          className="ghost row-toggle"
                          aria-expanded={open === row.id}
                          onClick={(event) => {
                            event.stopPropagation();
                            setOpen((prev) => (prev === row.id ? null : row.id));
                          }}
                        >
                          <IconChevron size={12} />
                          {stamp(row.ts)}
                        </button>
                      </td>
                      <td data-label="Actor">
                        <div className="cell-col">
                          <span className="cell-main" title={row.actor_label}>
                            {truncate(row.actor_label, 20)}
                          </span>
                          <span className="cell-sub mono">{row.actor_kind}</span>
                        </div>
                      </td>
                      <td data-label="Action">
                        <span className="mono">{row.action}</span>
                      </td>
                      <td data-label="Item">
                        <span className="mono">{row.item_name ? truncate(row.item_name, 24) : "—"}</span>
                      </td>
                      <td data-label="Result">
                        <span className={`status ${row.ok ? "ok" : "fail"}`}>
                          {row.ok ? "ok" : "fail"}
                        </span>
                      </td>
                    </tr>
                    {open === row.id ? (
                      <tr className="detail-row">
                        <td colSpan={5}>
                          <pre className="code">{JSON.stringify(row.detail, null, 2)}</pre>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </table>
            <div className="table-foot">
              <span>{rows.length} shown{cursor ? " · more available" : ""}</span>
              {cursor ? (
                <Button
                  label={loading ? "Loading…" : "Load more"}
                  onClick={() => void load(cursor, filters)}
                  disabled={loading}
                />
              ) : null}
            </div>
          </>
        )}
      </div>
    </>
  );
}