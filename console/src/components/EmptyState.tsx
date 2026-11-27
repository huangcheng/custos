import type { ReactNode } from "react";

// An empty state is a destination, not a grey line: mark, title, what to do,
// and the action that does it. `mark` is omitted for transient (loading or
// failed) states so they do not announce themselves as a real empty vault;
// those carry role="status" so the in-flight request is announced.
export function EmptyState({
  mark,
  title,
  children,
  action,
}: {
  mark?: ReactNode;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty" role={mark ? undefined : "status"}>
      {mark ? <span className="empty-mark">{mark}</span> : null}
      <strong>{title}</strong>
      {children ? <p>{children}</p> : null}
      {action ? <div className="row">{action}</div> : null}
    </div>
  );
}
