import type { KeyboardEvent, MouseEvent } from "react";

const FOCUSABLE =
  'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Keep Tab inside a modal panel: without it focus leaves the dialog and
// Escape (which only bubbles from focus) stops working.
export function trapTab(event: KeyboardEvent<HTMLElement>, container: HTMLElement | null) {
  if (event.key !== "Tab" || !container) return;
  const focusable = [...container.querySelectorAll<HTMLElement>(FOCUSABLE)];
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (!first || !last) {
    event.preventDefault();
    container.focus();
    return;
  }
  if (document.activeElement === container) {
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
}

// A click on the panel's static copy would leave focus on <body>, where the
// Escape handler never fires and the Tab trap has nothing to hold. Focus the
// panel instead — but never steal it from a control, a label or a field the
// operator is already typing in. Shared by Drawer and ConfirmShell so the
// control list lives in one place.
export function focusPanelOnStaticClick(
  event: MouseEvent<HTMLElement>,
  panel: HTMLElement | null,
) {
  const target = event.target as HTMLElement;
  if (
    target.closest("button, a[href], input, select, textarea, label")
    || panel?.contains(document.activeElement)
  ) {
    return;
  }
  panel?.focus();
}

let locks = 0;
let overflowBeforeLock = "";
let paddingBeforeLock = "";

// Lock the page behind a modal. Counted, so a confirmation opened over a
// drawer only unlocks when BOTH close (and StrictMode's double-run is a
// lock/unlock pair that cancels itself out). The first lock remembers the
// document's previous inline overflow/padding and the last release puts them
// back. Hiding the scrollbar would shift the layout by its width, so the
// gutter is compensated with padding while locked (overlay scrollbars report
// a gutter of 0 and get none).
export function lockScroll() {
  locks += 1;
  if (locks === 1) {
    const root = document.documentElement;
    overflowBeforeLock = root.style.overflow;
    paddingBeforeLock = root.style.paddingRight;
    const gutter = window.innerWidth - root.clientWidth;
    root.style.overflow = "hidden";
    if (gutter > 0) root.style.paddingRight = `${gutter}px`;
  }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    locks -= 1;
    if (locks === 0) {
      const root = document.documentElement;
      root.style.overflow = overflowBeforeLock;
      root.style.paddingRight = paddingBeforeLock;
    }
  };
}
