import { useEffect, useState } from "react";

import type { OneTime } from "../onetime";
import { Button, Notice } from "./Field";

// Rendered at the app level so a minted secret survives route changes. The
// operator must dismiss it explicitly; nothing here auto-hides.
export function OneTimePanel({
  oneTime,
  pending,
  onDismiss,
}: {
  oneTime: OneTime;
  pending: number;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const values = Array.isArray(oneTime.value) ? oneTime.value : [oneTime.value];

  // the panel instance is reused when the queued secret changes: reset the
  // button label so "Copied" never describes a different secret
  useEffect(() => {
    setCopied(false);
    setError("");
  }, [oneTime]);

  const copy = () => {
    const clipboard = navigator.clipboard;
    if (!clipboard) {
      setError("clipboard unavailable — select the text and copy it manually");
      return;
    }
    setError("");
    clipboard.writeText(values.join("\n")).then(
      () => setCopied(true),
      () => setError("clipboard refused — select the text and copy it manually"),
    );
  };

  const titles: Record<OneTime["kind"], { mint: string; revealed: string }> = {
    "agent-key": { mint: "New agent key", revealed: "Agent key" },
    "operator-token": { mint: "New operator token", revealed: "Operator token" },
    "recovery-codes": { mint: "New recovery codes", revealed: "Recovery codes" },
    "totp-secret": { mint: "Authenticator secret", revealed: "Authenticator secret" },
    "device-transfer": { mint: "CLI transfer code", revealed: "CLI transfer code" },
  };

  return (
    <div
      className="card stack"
      style={{ marginBottom: 18 }}
      data-testid="one-time-panel"
    >
      <Notice kind="warn">
        {titles[oneTime.kind][oneTime.retrievable ? "revealed" : "mint"]} for{" "}
        <span className="mono">{oneTime.about}</span>{" "}
        {oneTime.retrievable
          ? "— copy it now; you can re-reveal it later from the inventory."
          : "— shown once. Copy it now; it is not retrievable after you dismiss this panel."}
      </Notice>
      {error ? <Notice kind="error">{error}</Notice> : null}
      {values.length === 1 ? (
        <input className="mono" readOnly value={values[0]} data-testid="one-time-value" />
      ) : (
        <ul className="mono" style={{ columns: 2, margin: 0 }} data-testid="one-time-value">
          {values.map((value) => (
            <li key={value}>{value}</li>
          ))}
        </ul>
      )}
      <div className="row">
        <Button label={copied ? "Copied" : "Copy"} variant="primary" onClick={copy} />
        <Button
          label={pending > 1 ? `I have stored it (${pending - 1} more)` : "I have stored it"}
          variant="ghost"
          onClick={onDismiss}
        />
      </div>
    </div>
  );
}
