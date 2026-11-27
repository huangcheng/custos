import { useId, type ReactNode } from "react";

type ButtonProps = {
  label: string;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger" | "plain";
  type?: "button" | "submit";
  disabled?: boolean;
  title?: string;
  autoFocus?: boolean;
  /** Optional leading icon (aria-hidden: the label is the accessible name). */
  children?: ReactNode;
};

export function Button({
  label,
  onClick,
  variant = "plain",
  type = "button",
  disabled,
  title,
  autoFocus,
  children,
}: ButtonProps) {
  const cls = variant === "plain" ? undefined : variant;
  return (
    <button
      type={type}
      className={cls}
      onClick={onClick}
      disabled={disabled}
      title={title}
      autoFocus={autoFocus}
    >
      {children}
      {label}
    </button>
  );
}

type FieldProps = {
  label: string;
  value: string;
  onChange: (next: string) => void;
  name?: string;
  type?: "text" | "password" | "email";
  placeholder?: string;
  autoFocus?: boolean;
  autoComplete?: string;
  inputMode?: "text" | "numeric";
  hint?: string;
  disabled?: boolean;
};

// The hint sits inside the wrapping <label> (the gate reads a field by its
// label text), so the accessible name is pinned to the label span alone via
// aria-labelledby — otherwise the hint would be announced twice: once as part
// of the name and once through aria-describedby.
export function TextField({
  label,
  value,
  onChange,
  name,
  type = "text",
  placeholder,
  autoFocus,
  autoComplete,
  inputMode,
  hint,
  disabled,
}: FieldProps) {
  const labelId = useId();
  const hintId = useId();
  return (
    <label>
      <span className="label-text" id={labelId}>
        {label}
      </span>
      <input
        name={name}
        type={type}
        value={value}
        placeholder={placeholder}
        autoFocus={autoFocus}
        autoComplete={autoComplete}
        inputMode={inputMode}
        disabled={disabled}
        aria-labelledby={labelId}
        aria-describedby={hint ? hintId : undefined}
        onChange={(event) => onChange(event.target.value)}
      />
      {/* the slot is always present so grid-aligned fields share one height */}
      {hint ? (
        <span className="hint" id={hintId}>
          {hint}
        </span>
      ) : (
        <span className="hint" aria-hidden="true" />
      )}
    </label>
  );
}

export function TextArea({
  label,
  value,
  onChange,
  hint,
  name,
}: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  hint?: string;
  name?: string;
}) {
  const labelId = useId();
  const hintId = useId();
  return (
    <label>
      <span className="label-text" id={labelId}>
        {label}
      </span>
      <textarea
        name={name}
        value={value}
        aria-labelledby={labelId}
        aria-describedby={hint ? hintId : undefined}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint ? (
        <span className="hint" id={hintId}>
          {hint}
        </span>
      ) : (
        <span className="hint" aria-hidden="true" />
      )}
    </label>
  );
}

export function SelectField({
  label,
  value,
  options,
  onChange,
  name,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (next: string) => void;
  name?: string;
}) {
  const labelId = useId();
  return (
    <label>
      <span className="label-text" id={labelId}>
        {label}
      </span>
      <select
        name={name}
        value={value}
        aria-labelledby={labelId}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      <span className="hint" aria-hidden="true" />
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
