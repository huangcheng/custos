// One-time secrets (minted key/token, recovery codes, TOTP setup secret) are
// destroyed by navigation if they live in a screen's state — and the UI tells
// the operator they are shown ONCE, so losing one forces a revoke/re-mint or,
// for recovery codes, can leave them without stored codes. `useOneTime` keeps
// them in a module-level store that survives route changes and is cleared only
// when the operator explicitly dismisses it.
import { useCallback, useSyncExternalStore } from "react";

export type OneTime = {
  /** short kind tag, used to scope the visible panel */
  kind:
    | "agent-key"
    | "operator-token"
    | "recovery-codes"
    | "totp-secret"
    | "device-transfer";
  /** the secret material */
  value: string | string[];
  /** what it belongs to (label, key id) */
  about: string;
};

// A QUEUE, not a slot: minting a second secret must never destroy the first
// one the operator has not stored yet. `current` is always the head.
let queue: OneTime[] = [];
const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function setOneTime(next: OneTime): void {
  // replace a pending secret of the SAME kind+about (a re-mint of the same
  // label); otherwise queue it so nothing is lost
  queue = [...queue.filter((i) => !(i.kind === next.kind && i.about === next.about)), next];
  emit();
}

export function clearOneTime(): void {
  queue = [];
  emit();
}

/** Session boundary: never leave secret material in module memory. */
export function clearOneTimeForSignOut(): void {
  clearOneTime();
}

export function useOneTime(): {
  oneTime: OneTime | null;
  pending: number;
  show: (next: OneTime) => void;
  dismiss: () => void;
} {
  const snapshot = useSyncExternalStore(
    subscribe,
    () => queue[0] ?? null,
    () => queue[0] ?? null,
  );
  const show = useCallback((next: OneTime) => setOneTime(next), []);
  // dismiss ONE: the rest of the queue stays until it is acknowledged too
  const dismiss = useCallback(() => {
    queue = queue.slice(1);
    emit();
  }, []);
  const pending = useSyncExternalStore(
    subscribe,
    () => queue.length,
    () => queue.length,
  );
  return { oneTime: snapshot, pending, show, dismiss };
}
