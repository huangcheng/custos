import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, status } from "../api";
import { Button, Notice, TextArea, TextField } from "../components/Field";
import { Confirm } from "../components/Confirm";
import { ConfirmStepUp } from "../components/ConfirmStepUp";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { IconItems } from "../components/icons";
import {
  emptyForm,
  formFromItem,
  historyLabel,
  itemEditBody,
  type FieldDraft,
  type ItemForm,
} from "../items";
import { MASK, stamp, truncate } from "../plain";
import type { HistoryRow, HistorySnapshot, Item, ListRow, Page } from "../types";

const PAGE = 50;
// one copy for the create form and the rename panel (the grammar is shared)
const NAME_HINT =
  "any display label up to 200 characters — letters, digits, spaces, punctuation (no slashes or backslashes)";

// The one purge request both entry points use, so the route cannot drift.
async function purgeRequest(name: string): Promise<void> {
  await api("DELETE", `/api/admin/items/${encodeURIComponent(name)}/purge`);
}

// One purge state machine for both entry points: busy clears before onDone
// runs, so a dialog dismissed on success never leaves the next one disabled
// while the list reloads. `running` makes a rapid second click a no-op (the
// action stays enabled so disabling it cannot throw focus out of the dialog).
function usePurge(onDone: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const running = useRef(false);
  const reset = () => setError("");
  const run = async (name: string) => {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setError("");
    try {
      await purgeRequest(name);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "purge failed");
      return;
    } finally {
      running.current = false;
      setBusy(false);
    }
    onDone();
  };
  return { busy, error, run, reset };
}

// One purge confirmation for both entry points (list row and drawer) so the
// irreversible copy cannot drift between them.
function PurgeConfirm({
  name,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  name: string;
  busy: boolean;
  error: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Confirm
      title="Purge item"
      message={`Permanently deletes "${name}", its fields and its whole history. This cannot be undone.`}
      confirmLabel="Purge item"
      destructive
      busy={busy}
      error={error}
      onCancel={onCancel}
      onConfirm={onConfirm}
    />
  );
}

export function Items({ onSignOut }: { onSignOut: () => void }) {
  const [rows, setRows] = useState<ListRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  // a failed fetch is not an empty vault: the list must not offer "New item"
  // as if nothing existed
  const [loadFailed, setLoadFailed] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  // a soft-deleted row must be removable from the list itself, without
  // opening the drawer first
  const [purge, setPurge] = useState<null | { name: string }>(null);

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
      setLoadFailed(false);
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
      setLoadFailed(true);
      setError(err instanceof ApiError ? err.message : "cannot load items");
    } finally {
      if (generation.current === mine) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(null);
  }, [load]);

  const purgeState = usePurge(() => {
    setPurge(null);
    void load(null);
  });

  // loading, empty and populated are three distinct states: a list that has
  // not loaded yet must never read as an empty vault
  const list = () => {
    if (rows.length === 0) {
      if (loading) return <EmptyState title="Loading items…" />;
      // a failed fetch must never read as an empty vault under the error notice
      if (loadFailed) return <EmptyState title="Cannot load items" />;
      return (
        <EmptyState
          mark={<IconItems size={22} />}
          title="No items yet"
          action={<Button label="New item" variant="primary" onClick={() => setCreating(true)} />}
        >
          Create one to give your agents something to read.
        </EmptyState>
      );
    }
    return (
      <>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th className="num">Fields</th>
              <th className="num">Revision</th>
              <th>Updated</th>
              <th className="actions-cell" aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const secrets = row.fields.filter((f) => f.secret).length;
              return (
                <tr key={row.name}>
                  <td data-label="Name">
                    <span className="cell-stack">
                      <span className="mono cell-main" title={row.name}>
                        {truncate(row.name, 40)}
                      </span>
                      {row.deleted ? <span className="pill danger">deleted</span> : null}
                    </span>
                  </td>
                  <td className="num" data-label="Fields">
                    <span className="cell-stack">
                      {row.fields.length}
                      <span className="muted">
                        {" "}
                        · {secrets} {secrets === 1 ? "secret" : "secrets"}
                      </span>
                    </span>
                  </td>
                  <td className="num" data-label="Revision">
                    {row.revision}
                  </td>
                  <td data-label="Updated">
                    <span className="mono muted">{stamp(row.updated_at)}</span>
                  </td>
                  <td className="actions-cell" data-label="">
                    <span className="actions">
                      <Button label="Open" variant="ghost" onClick={() => setOpen(row.name)} />
                      {row.deleted ? (
                        <Button
                          label="Purge"
                          variant="danger"
                          onClick={() => {
                            purgeState.reset();
                            setPurge({ name: row.name });
                          }}
                        />
                      ) : null}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="table-foot">
          <span>
            {rows.length} shown
            {cursor ? " · more available" : ""}
          </span>
          {cursor ? (
            <Button
              label={loading ? "Loading…" : "Load more"}
              onClick={() => void load(cursor)}
              disabled={loading}
            />
          ) : null}
        </div>
      </>
    );
  };

  return (
    <>
      <PageHeader
        kicker="Vault"
        title="Items"
        lede="Named credentials. Secret fields stay masked until you reveal them."
        actions={
          <Button label="New item" variant="primary" onClick={() => setCreating(true)} />
        }
      />
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="card flush">{list()}</div>
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
        <PurgeConfirm
          name={purge.name}
          busy={purgeState.busy}
          error={purgeState.error}
          onCancel={() => {
            if (purgeState.busy) return;
            setPurge(null);
            purgeState.reset();
          }}
          onConfirm={() => void purgeState.run(purge.name)}
        />
      ) : null}
      {open ? (
        <ItemDrawer
          key={open}
          existing={open}
          onClose={() => setOpen(null)}
          onRenamed={(name) => {
            setOpen(name);
            void load(null);
          }}
          onChanged={() => void load(null)}
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
  onRenamed,
  onChanged,
}: {
  existing: string | null;
  onClose: () => void;
  onSaved: () => void;
  onRenamed?: (name: string) => void;
  /** the item changed without closing the drawer (a field rename) */
  onChanged?: () => void;
}) {
  const [item, setItem] = useState<Item | null>(null);
  const [form, setForm] = useState<ItemForm>(emptyForm());
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  // a reveal is an audited sensitive read: serialise it so a double-click
  // cannot fire overlapping requests (and give the button a busy state)
  const [revealing, setRevealing] = useState(false);
  const [revealError, setRevealError] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [renameTo, setRenameTo] = useState("");
  // rev 46: one saved field at a time can be renamed in place
  const [fieldRename, setFieldRename] = useState<{ from: string; to: string } | null>(null);
  const [fieldRenameBusy, setFieldRenameBusy] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [stepUpFor, setStepUpFor] = useState<null | ((token: string) => Promise<void>)>(null);
  const [totpRequired, setTotpRequired] = useState(false);
  const [confirmPurge, setConfirmPurge] = useState(false);
  const purgeState = usePurge(() => {
    setConfirmPurge(false);
    onSaved();
  });

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
    // a field rename in flight bumps the revision under this drawer: a Save
    // now would race it and come back as a 409 revision mismatch
    if (fieldRenameBusy) return;
    const name = form.name.trim();
    if (!existing && !name) {
      // a whitespace-only name would collapse to "" and cost a server round
      // trip for the generic "invalid item name"
      setError("enter a name for the item");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const body = itemEditBody(form);
      if (!existing) {
        await api("POST", "/api/admin/items", { name, ...body });
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

  const remove = async () => {
    if (!existing) return; // never build an //items// path
    try {
      await api("DELETE", `/api/admin/items/${encodeURIComponent(existing)}`);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "delete failed");
    }
  };

  const rename = async () => {
    if (!existing) return;
    const target = renameTo.trim();
    if (!target) {
      setError("enter the new name");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const data = await api<{ name: string }>(
        "POST", `/api/admin/items/${encodeURIComponent(existing)}/rename`,
        { name: target },
      );
      setRenaming(false);
      onRenamed?.(data.name);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "rename failed");
    } finally {
      setBusy(false);
    }
  };

  const renameField = async (from: string) => {
    if (!existing || !item) return;
    const target = (fieldRename?.to ?? "").trim();
    if (!target) {
      setError("enter the new field name");
      return;
    }
    if (target === from) {
      // a no-op rename must not re-seed the form and drop unsaved edits
      setFieldRename(null);
      return;
    }
    setFieldRenameBusy(true);
    setError("");
    try {
      await api(
        "POST",
        `/api/admin/items/${encodeURIComponent(existing)}/fields/${encodeURIComponent(from)}/rename`,
        { name: target },
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "rename failed");
      setFieldRenameBusy(false);
      return;
    }
    // the rename committed; re-seed the form from the masked shape (unsaved
    // edits are discarded, as the hint warns) and drop any revealed plaintext
    // keyed by the old name. A failed refresh is reported as exactly that —
    // the server has the new name, so the drawer must not keep pretending
    // otherwise, and the list is refreshed regardless.
    let fresh: Item;
    try {
      fresh = await api<Item>("GET", `/api/admin/items/${encodeURIComponent(existing)}`);
    } catch (err) {
      setFieldRename(null);
      onChanged?.();
      setError(
        `field renamed, but refreshing the drawer failed (${
          err instanceof ApiError ? err.message : "network"
        }) — reopen the item`,
      );
      setFieldRenameBusy(false);
      return;
    }
    setItem(fresh);
    setForm(formFromItem(fresh));
    setRevealed((prev) => {
      const next = { ...prev };
      delete next[from];
      return next;
    });
    setHistory(null);
    setSnapshot(null);
    setHistoryCursor(null);
    setFieldRename(null);
    onChanged?.();
    setFieldRenameBusy(false);
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
      footer={
        <>
          {existing ? (
            <Button label="Delete" variant="danger" onClick={() => void remove()} />
          ) : null}
          {item?.deleted ? (
            <Button
              label="Purge"
              variant="danger"
              onClick={() => {
                purgeState.reset();
                setConfirmPurge(true);
              }}
            />
          ) : null}
          <span className="spacer" />
          {item?.deleted ? <Button label="Restore" onClick={() => void restore()} /> : null}
          {item && !item.deleted && existing ? (
            <Button
              label="Rename"
              variant="ghost"
              onClick={() => {
                setRenaming(true);
                setRenameTo(existing);
              }}
              disabled={busy}
            />
          ) : null}
          {existing ? (
            <Button label="History" variant="ghost" onClick={() => void loadHistory()} />
          ) : null}
          <Button
            label="Save"
            variant="primary"
            onClick={() => void save()}
            disabled={
              busy || fieldRenameBusy || (Boolean(existing) && (!item || item.name !== existing))
            }
          />
        </>
      }
    >
      {error ? <Notice kind="error">{error}</Notice> : null}
      {revealError ? <Notice kind="error">{revealError}</Notice> : null}
      {item?.deleted ? <Notice kind="warn">This item is soft-deleted.</Notice> : null}
      {renaming ? (
        <div className="panel stack">
          <TextField
            label="New name"
            value={renameTo}
            onChange={setRenameTo}
            hint={`${NAME_HINT} — unsaved edits below are discarded`}
            autoFocus
          />
          <div className="row">
            <Button
              label="Apply rename"
              variant="primary"
              onClick={() => void rename()}
              disabled={busy}
            />
            <Button label="Cancel" variant="ghost" onClick={() => setRenaming(false)} />
          </div>
        </div>
      ) : null}
      {!existing ? (
        <TextField
          label="Name"
          value={form.name}
          onChange={(next) => setForm((prev) => ({ ...prev, name: next }))}
          hint={NAME_HINT}
          autoFocus
        />
      ) : null}
      <TextArea
        label="Notes"
        name="notes"
        value={form.notes}
        onChange={(next) => setForm((prev) => ({ ...prev, notes: next }))}
      />
      <fieldset className="stack">
        <span className="group-label">Fields</span>
        {form.fields.map((field, index) => (
          <div key={`${field.name}-${index}`} className="panel stack">
            <div className="row">
              <span className="mono cell-main" title={field.name}>
                {field.name}
              </span>
              <span className={`pill ${field.secret ? "accent" : ""}`}>
                {field.secret ? "secret" : "plain"}
              </span>
              <span className="row-end" />
              {/* rev 46: a saved field keeps its sealed value and history when
                  renamed; an unsaved field is just edited in place above */}
              {item && !item.deleted && item.fields.some((f) => f.name === field.name) ? (
                <Button
                  label="Rename field"
                  variant="ghost"
                  disabled={fieldRenameBusy}
                  onClick={() => {
                    setError("");
                    setFieldRename({ from: field.name, to: field.name });
                  }}
                />
              ) : null}
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
            {fieldRename?.from === field.name ? (
              <div className="stack">
                <TextField
                  label="New field name"
                  value={fieldRename.to}
                  onChange={(next) => setFieldRename({ from: field.name, to: next })}
                  hint="UPPER_SNAKE, up to 64 characters — the stored value and history move with it; unsaved edits in other fields are discarded"
                  autoFocus
                />
                <div className="row">
                  <Button
                    label="Apply field rename"
                    variant="primary"
                    disabled={fieldRenameBusy}
                    onClick={() => void renameField(field.name)}
                  />
                  <Button
                    label="Cancel"
                    variant="ghost"
                    disabled={fieldRenameBusy}
                    onClick={() => setFieldRename(null)}
                  />
                </div>
              </div>
            ) : null}
            <label>
              <span className="label-text">Value</span>
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
                  <code className="secret-value" data-testid={`revealed-${field.name}`}>
                    {revealed[field.name]}
                  </code>
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
            aria-label="New field name"
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
      {history ? (
        <div className="panel stack">
          <span className="group-label">History</span>
          {history.length === 0 ? (
            <p className="muted">No prior values yet.</p>
          ) : (
            <ul className="list">
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
            <code className="secret-value">
              {snapshot.name} = {snapshot.value}
            </code>
          ) : null}
          {historyCursor ? (
            <div className="row">
              <Button
                label="Load older"
                variant="ghost"
                onClick={() => void loadHistory(historyCursor)}
              />
            </div>
          ) : null}
        </div>
      ) : null}
      {confirmPurge && existing ? (
        <PurgeConfirm
          name={existing}
          busy={purgeState.busy}
          error={purgeState.error}
          onCancel={() => {
            if (purgeState.busy) return;
            setConfirmPurge(false);
            purgeState.reset();
          }}
          onConfirm={() => void purgeState.run(existing)}
        />
      ) : null}
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