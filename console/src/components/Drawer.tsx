import { useEffect, useRef, type ReactNode } from "react";

export function Drawer({
  title,
  meta,
  onClose,
  children,
}: {
  title: string;
  meta?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const panel = useRef<HTMLDivElement | null>(null);

  // The dialog is rendered on open, so focusing the panel makes Escape work
  // even when no child is auto-focused (keydown only bubbles from focus).
  useEffect(() => {
    panel.current?.focus();
  }, []);

  return (
    <div
      className="scrim"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className="drawer"
        ref={panel}
        tabIndex={-1}
        onKeyDown={(event) => {
          if (event.key === "Escape") onClose();
        }}
      >
        <div className="drawer-head">
          <h2>{title}</h2>
          {meta ? <div className="meta">{meta}</div> : null}
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
  );
}
