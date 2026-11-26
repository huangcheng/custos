import { useId } from "react";
import { Button, Notice } from "./Field";
import { ConfirmShell } from "./ConfirmShell";

// A plain confirmation for destructive actions that need no step-up (rev 44:
// item purge trusts the logged-in session; CSRF + session-only are enforced
// server-side). It still names the object and the irreversible effect.
export function Confirm({
  title,
  message,
  confirmLabel,
  destructive = false,
  busy = false,
  error = "",
  onConfirm,
  onCancel,
}: {
  title: string;
  message: string;
  confirmLabel: string;
  destructive?: boolean;
  busy?: boolean;
  error?: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const descriptionId = useId();
  return (
    <ConfirmShell
      title={title}
      descriptionId={descriptionId}
      onCancel={onCancel}
      // Enter while focus is on the panel must not fire a destructive action,
      // and an in-flight request must not be re-fired by implicit submission.
      onSubmit={() => {
        if (busy) return;
        if (!destructive) onConfirm();
      }}
    >
      <p className="muted dialog-copy" id={descriptionId}>
        {message}
      </p>
      {error ? <Notice kind="error">{error}</Notice> : null}
      <div className="row">
        <Button
          label={busy ? "Working…" : confirmLabel}
          variant={destructive ? "danger" : "primary"}
          onClick={() => {
            if (!busy) onConfirm();
          }}
        />
        <Button
          label="Cancel"
          variant="ghost"
          onClick={onCancel}
          autoFocus
        />
      </div>
    </ConfirmShell>
  );
}
