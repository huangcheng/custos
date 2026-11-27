import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { focusPanelOnStaticClick, lockScroll, trapTab } from "./modal";

// Shared shell for the confirmation dialogs (plain confirm and step-up):
// a centred modal over a scrim + Escape/backdrop close + a Tab trap. The
// sibling idiom: a confirmation is a question, not a side panel.
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

  useEffect(() => lockScroll(), []);

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
    trapTab(event, panel.current);
  };

  return (
    <div
      className="scrim center"
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
        onMouseDown={(event) => focusPanelOnStaticClick(event, panel.current)}
        onKeyDown={onKeyDown}
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <div className="drawer-head">
          <div>
            {meta ? <div className="drawer-kicker">{meta}</div> : null}
            <h2>{title}</h2>
          </div>
        </div>
        <div className="drawer-body stack">{children}</div>
      </form>
    </div>
  );
}
