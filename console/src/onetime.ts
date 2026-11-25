// One-time secrets (minted key/token, recovery codes, TOTP setup secret) are
// destroyed by navigation if they live in a screen's state — and the UI tells
// the operator they are shown ONCE, so losing one forces a revoke/re-mint or,
// for recovery codes, can leave them without stored codes. `useOneTime` keeps
// them in a module-level store that survives route changes and is cleared only
// when the operator explicitly dismisses it.
import { useCallback, useSyncExternalStore } from "react";

import { api } from "./api";

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
  /** true for re-revealed credentials: the panel copy must not claim "shown once" */
  retrievable?: boolean;
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

/** Minted and re-revealed credentials share one panel shape. Both are
 *  retrievable — re-reveal needs only the session (rev 39) — so this is the
 *  single place that decides the panel's kind/metadata policy (it writes the
 *  module store directly: no caller-supplied sink can bypass it). */
export function showCredential(
  kind: "agent-key" | "operator-token",
  credential: { token: string; about: string },
): void {
  setOneTime({ kind, value: credential.token, about: credential.about, retrievable: true });
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

/** One fetch for both credential screens (rev 39: session alone, no step-up).
 *  Lives here, next to the panel policy it feeds, so the React-free form/body
 *  module stays free of the UI store. Errors propagate: each screen decides
 *  where its notice belongs. */
export async function revealCredential(
  kind: "agent-key" | "operator-token",
  keyId: string,
  about: string,
): Promise<void> {
  const path = kind === "agent-key" ? "keys" : "tokens";
  const data = await api<{ token: string }>(
    "GET",
    `/api/admin/${path}/${encodeURIComponent(keyId)}/reveal`,
  );
  showCredential(kind, { token: data.token, about });
}
