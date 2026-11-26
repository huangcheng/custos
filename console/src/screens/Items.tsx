import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, status } from "../api";
import { Button, Notice, TextField } from "../components/Field";
import { ConfirmStepUp } from "../components/ConfirmStepUp";
import { Drawer } from "../components/Drawer";
import {
  emptyForm,
  formFromItem,
  historyLabel,
  itemEditBody,
  type FieldDraft,
  type ItemForm,
} from "../items";
import { MASK, truncate } from "../plain";
import type { HistoryRow, HistorySnapshot, Item, ListRow, Page } from "../types";

const PAGE = 50;

export function Items({ onSignOut }: { onSignOut: () => void }) {
  const [rows, setRows] = useState<ListRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // a soft-deleted row must be removable from the list itself, without
  // opening the drawer first
  const [purge, setPurge] = useState<null | { name: string }>(null);
  const [purgeTotp, setPurgeTotp] = useState(false);

  useEffect(() => {
    void status()
      .then((st) => setPurgeTotp(st.totp_required))
      .catch(() => {
        // the prompt still works password-only; never block the list on it
      });
  }, []);

  const generation = useRef(0);

  const load = useCallback(async (next?: string | null) => {
    const mine = (generation.current += 1);
    setLoading(true);
    setError("");
    try {
      const query = new URLSearchParams({ limit: String(PAGE) });
      if (next) query.set("cursor", next);
      const page = await api<Page<ListRow>>("GET", `/api/admin/items?${query}`);
      if (generation.current !== mine) return; // superseded by a refresh
      setRows((prev) => {
        const merged = next ? [...prev, ...page.items] : page.items;
        // de-dupe by name: a racing page must never duplicate a row
        const seen = new Set<string>();
        return merged.filter((row) => {
          if (seen.has(row.name)) return false;
          seen.add(row.name);
          return true;
        });
      });
      setCursor(page.next_cursor);
    } catch (err) {
      if (generation.current !== mine) return;
      if (err instanceof ApiError && err.status === 401) {
        onSignOut();
        return;
      }
      setError(err instanceof ApiError ? err.message : "cannot load items");
    } finally {
      if (generation.current === mine) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(null);
  }, [load]);

  const purgeItem = async (name: string, token: string) => {
    setError("");
    try {
      await api("DELETE", `/api/admin/items/${encodeURIComponent(name)}/purge`, undefined, {
        stepUpToken: token,
      });
      await load(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "purge failed");
    }
  };

  return (
    <>
      <h1 className="page-title">Items</h1>
      <p className="page-sub">
        Named credentials. Secret fields stay masked until you reveal them.
      </p>
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="row" style={{ margin: "16px 0" }}>
        <Button label="New item" variant="primary" onClick={() => setCreating(true)} />
        <span className="row-end muted mono">{rows.length} shown</span>
      </div>
      <div className="card" style={{ padding: 0 }}>
        {rows.length === 0 && !loading ? (
          <div className="empty">No items yet. Create one to give your agents something to read.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th className="num">Fields</th>
                <th className="num">Revision</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const secrets = row.fields.filter((f) => f.secret).length;
                return (
                  <tr key={row.name}>
                    <td>
                      <span className="mono" title={row.name}>
                        {truncate(row.name, 40)}
                      </span>
                      {row.deleted ? <span className="pill danger"> deleted</span> : null}
                    </td>
                    <td className="num">
                      {row.fields.length}
                      <span className="muted"> ({secrets} secret)</span>
                    </td>
                    <td className="num">{row.revision}</td>
                    <td className="mono muted">{row.updated_at.slice(0, 19).replace("T", " ")}</td>
                    <td>
                      <Button label="Open" variant="ghost" onClick={() => setOpen(row.name)} />
                      {row.deleted ? (
                        <>
                          {" "}
                          <Button
                            label="Purge"
                            variant="danger"
                            onClick={() => setPurge({ name: row.name })}
                          />
                        </>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {cursor ? (
        <div className="row" style={{ marginTop: 14 }}>
          <Button
            label={loading ? "Loading…" : "Load more"}
            onClick={() => void load(cursor)}
            disabled={loading}
          />
        </div>
      ) : null}
      {creating ? (
        <ItemDrawer
          existing={null}
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            void load(null);
          }}
        />
      ) : null}
      {purge ? (
        <ConfirmStepUp
          totpRequired={purgeTotp}
          title="Purge item"
          message={`Permanently deletes "${purge.name}", its fields and its whole history. This cannot be undone.`}
          onCancel={() => setPurge(null)}
          onToken={async (token) => {
            const target = purge.name;
            setPurge(null);
            await purgeItem(target, token);
          }}
        />
      ) : null}
      {open ? (
        <ItemDrawer
          key={open}
          existing={open}
          onClose={() => setOpen(null)}
          onSaved={() => {
            setOpen(null);
            void load(null);
          }}
        />
      ) : null}
    </>
  );
}

function ItemDrawer({
  existing,
  onClose,
  onSaved,
}: {
  existing: string | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [item, setItem] = useState<Item | null>(null);
  const [form, setForm] = useState<ItemForm>(emptyForm());
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  // a reveal is an audited sensitive read: serialise it so a double-click
  // cannot fire overlapping requests (and give the button a busy state)
  const [revealing, setRevealing] = useState(false);
  const [revealError, setRevealError] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [stepUpFor, setStepUpFor] = useState<null | ((token: string) => Promise<void>)>(null);
  const [totpRequired, setTotpRequired] = useState(false);

  useEffect(() => {
    void status()
      .then((st) => setTotpRequired(st.totp_required))
      .catch((err: unknown) => {
        // never silently assume TOTP is off: that would hide the code field
        setError(err instanceof ApiError ? err.message : "cannot read auth status");
      });
  }, []);

  const [history, setHistory] = useState<HistoryRow[] | null>(null);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<{ name: string; value: string } | null>(null);

  useEffect(() => {
    // Reset FIRST: a stale form + the previous item's revision must never be
    // visible (or saveable) under a different name.
    setItem(null);
    setForm(emptyForm());
    setRevealed({});
    setHistory(null);
    setSnapshot(null);
    if (!existing) return;
    let cancelled = false;
    void api<Item>("GET", `/api/admin/items/${encodeURIComponent(existing)}`)
      .then((data) => {
        if (cancelled) return;
        setItem(data);
        setForm(formFromItem(data));
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "cannot load item");
      });
    return () => {
      cancelled = true;
    };
  }, [existing]);

  const patch = (index: number, next: Partial<FieldDraft>) => {
    setForm((prev) => ({
      ...prev,
      fields: prev.fields.map((field, i) => (i === index ? { ...field, ...next } : field)),
    }));
  };

  const noteField = (name: string) => {
    setForm((prev) => ({
      ...prev,
      fields: [
        ...prev.fields,
        { name, secret: true, value: "", untouched: false },
      ],
    }));
  };

  const save = async () => {
    // A PUT replaces the whole item: saving an unloaded form would clear the
    // notes and drop every field. Refuse until the live item is in hand.
    if (existing && (!item || item.name !== existing)) {
      setError("item has not loaded yet");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const body = itemEditBody(form);
      if (!existing) {
        await api("POST", "/api/admin/items", { name: form.name, ...body });
      } else {
        await api("PUT", `/api/admin/items/${encodeURIComponent(existing)}`, body, {
          ifMatch: item ? String(item.revision) : undefined,
        });
      }
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "save failed");
    } finally {
      setBusy(false);
    }
  };

  // rev 41: revealing a stored secret needs only the session — no password.
  // One guarded wrapper for both reveal kinds: serialised (each call is an
  // audited read), and a failure never leaves stale plaintext on screen.
  const guardedReveal = async (run: () => Promise<void>, onFail: () => void) => {
    if (!existing || revealing) return;
    setRevealing(true);
    setRevealError("");
    try {
      await run();
    } catch (err) {
      onFail();
      // a reveal failure must not wipe an unrelated save/history error
      setRevealError(err instanceof Error ? err.message : "reveal failed");
    } finally {
      setRevealing(false);
    }
  };

  const reveal = (name: string) => {
    const target = existing;
    if (!target) return;
    return guardedReveal(
      async () => {
        const data = await api<Item>(
          "GET",
          `/api/admin/items/${encodeURIComponent(target)}/reveal`,
        );
        const found = data.fields.find((f) => f.name === name);
        // an unsaved field is not on the server: say so instead of showing
        // a blank "revealed" value
        if (!found) throw new Error(`field ${name} is not saved yet`);
        setRevealed((prev) => ({ ...prev, [name]: found.value ?? "" }));
      },
      () =>
        setRevealed((prev) => {
          const next = { ...prev };
          delete next[name];
          return next;
        }),
    );
  };

  const loadHistory = async (next?: string | null) => {
    if (!existing) return;
    try {
      const query = new URLSearchParams({ limit: "50" });
      if (next) query.set("cursor", next);
      const page = await api<Page<HistoryRow>>(
        "GET",
        `/api/admin/items/${encodeURIComponent(existing)}/history?${query}`,
      );
      setHistory((prev) => (next && prev ? [...prev, ...page.items] : page.items));
      setHistoryCursor(page.next_cursor);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "cannot load history");
    }
  };

  const revealSnapshot = (id: string) => {
    const target = existing;
    if (!target) return;
    return guardedReveal(
      async () => {
        const data = await api<HistorySnapshot>(
          "GET",
          `/api/admin/items/${encodeURIComponent(target)}/history/${id}/reveal`,
        );
        setSnapshot({ name: data.name, value: data.value });
      },
      () => setSnapshot(null),
    );
  };

  const remove = async (purge: boolean) => {
    if (!existing) return; // never build an //items// path
    const path = `/api/admin/items/${encodeURIComponent(existing)}${purge ? "/purge" : ""}`;
    if (purge) {
      setStepUpFor(() => async (token: string) => {
        await api("DELETE", path, undefined, { stepUpToken: token });
        onSaved();
      });
      return;
    }
    try {
      await api("DELETE", path);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "delete failed");
    }
  };

  const restore = () => {
    if (!existing) return;
    setStepUpFor(() => async (token: string) => {
      await api("POST", `/api/admin/items/${encodeURIComponent(existing)}/restore`, undefined, {
        stepUpToken: token,
      });
      onSaved();
    });
  };

  return (
    <Drawer
      title={existing ?? "New item"}
      meta={item ? `revision ${item.revision}` : "unsaved"}
      onClose={onClose}
    >
      <div className="stack">
        {error ? <Notice kind="error">{error}</Notice> : null}
        {revealError ? <Notice kind="error">{revealError}</Notice> : null}
        {item?.deleted ? <Notice kind="warn">This item is soft-deleted.</Notice> : null}
        {!existing ? (
          <TextField
            label="Name"
            value={form.name}
            onChange={(next) => setForm((prev) => ({ ...prev, name: next }))}
            hint="lowercase, digits, dot, dash, underscore"
          />
        ) : null}
        <label>
          <span>Notes</span>
          <textarea
            value={form.notes}
            onChange={(event) => setForm((prev) => ({ ...prev, notes: event.target.value }))}
          />
        </label>
        <fieldset className="stack">
          <span className="muted">Fields</span>
          {form.fields.map((field, index) => (
            <div key={`${field.name}-${index}`} className="card stack">
              <div className="row">
                <span className="mono">{field.name}</span>
                <span className={`pill ${field.secret ? "accent" : ""}`}>
                  {field.secret ? "secret" : "plain"}
                </span>
                <span className="row-end" />
                <Button
                  label="Remove"
                  variant="ghost"
                  onClick={() =>
                    setForm((prev) => ({
                      ...prev,
                      fields: prev.fields.filter((_, i) => i !== index),
                    }))
                  }
                />
              </div>
              <label>
                <span>Value</span>
                <input
                  value={field.secret && field.untouched ? "" : field.value}
                  placeholder={field.secret && field.untouched ? "unchanged (stored sealed)" : ""}
                  onChange={(event) => patch(index, { value: event.target.value, untouched: false })}
                />
              </label>
              {field.secret ? (
                <div className="row">
                  <Button
                    label="Reveal"
                    variant="ghost"
                    onClick={() => void reveal(field.name)}
                    disabled={revealing || !existing}
                  />
                  {revealed[field.name] !== undefined ? (
                    <span className="mono" data-testid={`revealed-${field.name}`}>
                      {revealed[field.name]}
                    </span>
                  ) : (
                    <span className="secret">{MASK}</span>
                  )}
                </div>
              ) : null}
            </div>
          ))}
          <div className="row">
            <input
              placeholder="new field name (UPPER_SNAKE)"
              onKeyDown={(event) => {
                if (event.key !== "Enter") return;
                event.preventDefault();
                const value = event.currentTarget.value.trim();
                if (value) {
                  noteField(value);
                  event.currentTarget.value = "";
                }
              }}
            />
            <span className="muted">Press Enter to add</span>
          </div>
        </fieldset>
        <div className="row">
          <Button
            label="Save"
            variant="primary"
            onClick={() => void save()}
            disabled={busy || (Boolean(existing) && (!item || item.name !== existing))}
          />
          {existing ? (
            <>
              <Button label="History" variant="ghost" onClick={() => void loadHistory()} />
              <Button
                label="Delete"
                variant="danger"
                onClick={() => void remove(false)}
              />
            </>
          ) : null}
          {item?.deleted ? (
            <Button label="Restore" onClick={() => void restore()} />
          ) : null}
          {item?.deleted ? (
            <Button label="Purge" variant="danger" onClick={() => void remove(true)} />
          ) : null}
        </div>
        {history ? (
          <div className="card">
            <h3 className="page-sub" style={{ margin: "0 0 10px" }}>
              History
            </h3>
            {history.length === 0 ? (
              <p className="muted">No prior values yet.</p>
            ) : (
              <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {history.map((row) => (
                  <li key={row.id} className="row">
                    <span className="mono">{historyLabel(row)}</span>
                    <span className="row-end" />
                    <Button
                      label="Reveal"
                      variant="ghost"
                      onClick={() => void revealSnapshot(row.id)}
                      disabled={revealing}
                    />
                  </li>
                ))}
              </ul>
            )}
            {snapshot ? (
              <p className="mono">
                {snapshot.name} = {snapshot.value}
              </p>
            ) : null}
            {historyCursor ? (
              <Button
                label="Load older"
                variant="ghost"
                onClick={() => void loadHistory(historyCursor)}
              />
            ) : null}
          </div>
        ) : null}
      </div>
      {stepUpFor ? (
        <ConfirmStepUp
          totpRequired={totpRequired}
          onCancel={() => setStepUpFor(null)}
          onToken={async (token) => {
            const run = stepUpFor;
            setStepUpFor(null);
            try {
              await run(token);
            } catch (err) {
              setError(err instanceof ApiError ? err.message : "action failed");
            }
          }}
        />
      ) : null}
    </Drawer>
  );
}