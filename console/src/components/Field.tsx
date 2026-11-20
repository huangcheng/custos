import { useId, type ReactNode } from "react";

type ButtonProps = {
  label: string;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger" | "plain";
  type?: "button" | "submit";
  disabled?: boolean;
  title?: string;
};

export function Button({
  label,
  onClick,
  variant = "plain",
  type = "button",
  disabled,
  title,
}: ButtonProps) {
  const cls = variant === "plain" ? undefined : variant;
  return (
    <button
      type={type}
      className={cls}
      onClick={onClick}
      disabled={disabled}
      title={title}
    >
      {label}
    </button>
  );
}

type FieldProps = {
  label: string;
  value: string;
  onChange: (next: string) => void;
  type?: "text" | "password" | "email";
  placeholder?: string;
  autoFocus?: boolean;
  autoComplete?: string;
  inputMode?: "text" | "numeric";
  hint?: string;
  disabled?: boolean;
};

export function TextField({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  autoFocus,
  autoComplete,
  inputMode,
  hint,
  disabled,
}: FieldProps) {
  const hintId = useId();
  return (
    <label>
      <span>{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        autoFocus={autoFocus}
        autoComplete={autoComplete}
        inputMode={inputMode}
        disabled={disabled}
        aria-describedby={hint ? hintId : undefined}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint ? (
        // Linked by id, not hidden: guidance stays announced to screen readers
        // without becoming part of the input's accessible name.
        <span className="muted" id={hintId}>
          {hint}
        </span>
      ) : null}
    </label>
  );
}

export function TextArea({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  hint?: string;
}) {
  return (
    <label>
      <span>{label}</span>
      <textarea value={value} onChange={(event) => onChange(event.target.value)} />
      {hint ? <span className="muted" aria-hidden="true">{hint}</span> : null}
    </label>
  );
}

export function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (next: string) => void;
}) {
  return (
    <label>
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function Notice({
  kind,
  children,
}: {
  kind: "error" | "ok" | "warn";
  children: ReactNode;
}) {
  return (
    <div className={`notice ${kind}`} role={kind === "error" ? "alert" : "status"}>
      {children}
    </div>
  );
}