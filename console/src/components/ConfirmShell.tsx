import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

// Shared shell for the confirmation dialogs (plain confirm and step-up):
// scrim + a 420px right-hand panel (the drawer idiom, narrower) + Escape/
// backdrop close + a Tab trap. Drawer keeps its own layout and form semantics.
export function ConfirmShell({
  title,
  meta,
  descriptionId,
  onCancel,
  onSubmit,
  children,
}: {
  title: string;
  meta?: string;
  descriptionId?: string;
  onCancel: () => void;
  onSubmit: () => void;
  children: ReactNode;
}) {
  const panel = useRef<HTMLFormElement | null>(null);
  // Captured once per mounted dialog, before React applies autoFocus: the
  // element that opened the dialog is what focus returns to on cancel.
  const [returnTo] = useState<HTMLElement | null>(
    () => document.activeElement as HTMLElement | null,
  );

  // Pending deferred focus restore, cancelled when the effect re-runs.
  const restoreTimer = useRef<number | null>(null);

  // Focus the panel when no child took focus via autoFocus, so Escape works
  // from the start. Destructive dialogs autoFocus Cancel, never the action.
  useEffect(() => {
    if (restoreTimer.current !== null) {
      window.clearTimeout(restoreTimer.current);
      restoreTimer.current = null;
    }
    const el = panel.current;
    if (el && !el.contains(document.activeElement)) el.focus();
    return () => {
      // Defer the restore so StrictMode's simulated unmount (cleanup followed
      // immediately by a re-run) can cancel it instead of pulling focus back
      // to the trigger while the dialog is still open.
      restoreTimer.current = window.setTimeout(() => {
        restoreTimer.current = null;
        const target = returnTo;
        if (target instanceof HTMLElement && target !== document.body && target.isConnected) {
          target.focus();
        }
      }, 0);
    };
  }, [returnTo]);

  const onKeyDown = (event: KeyboardEvent<HTMLFormElement>) => {
    if (event.key === "Escape") {
      // stop here: bubbling would close the parent Drawer too and discard
      // the operator's unsaved item edits
      event.stopPropagation();
      onCancel();
      return;
    }
    if (event.key !== "Tab") return;
    // Trap Tab: without it, focus leaves the dialog and Escape stops working.
    const el = panel.current;
    if (!el) return;
    const focusable = [...el.querySelectorAll<HTMLElement>(
      'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )];
    if (focusable.length === 0) {
      event.preventDefault();
      panel.current?.focus();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!first || !last) return;
    if (document.activeElement === el) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
      return;
    }
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    <div
      className="scrim"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      aria-describedby={descriptionId}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <form
        className="drawer dialog"
        ref={panel}
        tabIndex={-1}
        onMouseDown={(event) => {
          // Keep Escape working when the operator clicks static copy: focus
          // the panel, but do NOT preventDefault (text stays selectable) and
          // never blur a field the operator is already typing in.
          const target = event.target as HTMLElement;
          if (
            !target.closest("button, a[href], input, select, textarea, label")
            && !panel.current?.contains(document.activeElement)
          ) {
            panel.current?.focus();
          }
        }}
        onKeyDown={onKeyDown}
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <div className="drawer-head">
          <h2>{title}</h2>
          {meta ? <div className="meta">{meta}</div> : null}
        </div>
        <div className="drawer-body stack">{children}</div>
      </form>
    </div>
  );
}
