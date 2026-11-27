// Plain-text rendering contract (design §3): every item/field/notes string is
// rendered as a React text child. This module exists so the rule has a name
// and one place to check: never build markup from agent-authored content.
//
// There is deliberately no HTML helper here — if you need one, the answer is
// "no" (§3 forbids dangerouslySetInnerHTML and markdown-to-HTML).

/** Long identifiers truncate for display but keep the full value in `title`. */
export function truncate(text: string, max = 48): string {
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(0, max - 1))}…`;
}

/** Mask a secret for display. The real value only ever arrives from a reveal
 *  response and is rendered by the component that asked for it. */
export const MASK = "••••••";

export function maskSecret(): string {
  return MASK;
}

/** A server ISO-8601 UTC timestamp as the console's column stamp. The API
 *  always speaks UTC ISO-8601 (`…+00:00`), so the fixed format is
 *  unambiguous (and one place to change if the console ever localises); a
 *  missing value renders as an em dash rather than a blank cell. */
export function stamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.slice(0, 19).replace("T", " ");
}

/** Containers that must never be rendered through an HTML sink. */
export const PLAIN_ONLY =
  "item names, field names, field values, notes and audit detail render as text";
