import { useEffect, useRef, type ReactNode } from "react";
import { IconClose } from "./icons";
import { focusPanelOnStaticClick, lockScroll, trapTab } from "./modal";

export function Drawer({
  title,
  meta,
  onClose,
  children,
  footer,
}: {
  title: string;
  meta?: string;
  onClose: () => void;
  children: ReactNode;
  /** Sticky action bar pinned to the drawer's bottom edge. */
  footer?: ReactNode;
}) {
  const panel = useRef<HTMLDivElement | null>(null);

  // The page behind the drawer must not scroll, and Tab must stay inside.
  useEffect(() => lockScroll(), []);

  // The dialog is rendered on open, so focusing the panel makes Escape work
  // even when no child is auto-focused (keydown only bubbles from focus).
  // Do not steal focus from a child that already took it via autoFocus: the
  // mount effect runs after React applies autoFocus during commit.
  useEffect(() => {
    const el = panel.current;
    if (el && !el.contains(document.activeElement)) el.focus();
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
        onMouseDown={(event) => focusPanelOnStaticClick(event, panel.current)}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            onClose();
            return;
          }
          trapTab(event, panel.current);
        }}
      >
        <div className="drawer-head">
          <div>
            {meta ? <div className="drawer-kicker">{meta}</div> : null}
            <h2>{title}</h2>
          </div>
          <button type="button" className="drawer-close" onClick={onClose} aria-label="Close">
            <IconClose size={16} />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer ? <div className="drawer-foot">{footer}</div> : null}
      </div>
    </div>
  );
}
