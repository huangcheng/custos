import { useEffect, useState } from "react";

import type { OneTime } from "../onetime";
import { Button, Notice } from "./Field";
import { IconCheck, IconCopy, IconShield } from "./icons";

// Rendered at the app level so a minted secret survives route changes. The
// operator must dismiss it explicitly; nothing here auto-hides. The ink
// banner is the family's signature for a one-time value: it outranks every
// card on the page.
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
    <div className="secret-banner" data-testid="one-time-panel">
      <div className="secret-banner-head">
        <span className="secret-icon" aria-hidden="true">
          <IconShield size={20} />
        </span>
        {/* the live region is the text block only (the banner replaced a
            Notice that announced itself): wrapping the whole banner would
            re-announce recovery codes on every "Copied" toggle and nest the
            error Notice's own live region inside it */}
        <div role="status">
          <span className="secret-kicker">
            {oneTime.retrievable ? "Re-revealed" : "Shown once"}
          </span>
          <strong>{titles[oneTime.kind][oneTime.retrievable ? "revealed" : "mint"]}</strong>
          <p>
            For <span className="mono">{oneTime.about}</span>{" "}
            {oneTime.retrievable
              ? "— copy it now; you can re-reveal it later from the inventory."
              : "— shown once. Copy it now; it is not retrievable after you dismiss this panel."}
          </p>
        </div>
      </div>
      {error ? <Notice kind="error">{error}</Notice> : null}
      {values.length === 1 ? (
        <input
          className="token"
          readOnly
          value={values[0]}
          data-testid="one-time-value"
          aria-label="Secret value"
        />
      ) : (
        <ul className="secret-codes" data-testid="one-time-value">
          {values.map((value) => (
            <li key={value}>{value}</li>
          ))}
        </ul>
      )}
      <div className="secret-actions">
        <Button
          label={copied ? "Copied" : "Copy"}
          variant="primary"
          onClick={copy}
          title="Copy to the clipboard"
        >
          {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
        </Button>
        <Button
          label={pending > 1 ? `I have stored it (${pending - 1} more)` : "I have stored it"}
          variant="ghost"
          onClick={onDismiss}
        />
      </div>
    </div>
  );
}
