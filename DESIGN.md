# Custos console — visual system

The subject is a **credential vault**: a single operator's ledger of sealed
values. The interface is a reading surface, not a dashboard of decoration.
Direction: **ledger and seal** — cool paper, hairline rules, one verdigris
accent, type that does the work.

## Tokens

| Token | Value | Use |
|---|---|---|
| `--ink` | `#14181d` | sidebar frame |
| `--ink-raised` | `#1c222a` | active nav row |
| `--ink-accent` | `#4fa192` | 2px active-nav bar on ink |
| `--workspace` | `#f2f4f5` | page background |
| `--surface` | `#ffffff` | cards |
| `--surface-sunk` | `#f7f9fa` | table head, row hover |
| `--line` / `--line-soft` | `#dde2e6` / `#ebeff2` | card border / row rule |
| `--text` / `--text-dim` | `#171d22` / `#5c6871` | body / secondary |
| `--accent` / `--accent-strong` / `--accent-soft` | `#1f6f63` / `#185a50` / `#e6f0ee` | primary action, focus of attention |
| `--danger` | `#b3261e` | destructive only |

Contrast: every text pair clears WCAG AA (body 17:1, secondary 5.2–5.7:1,
white on accent 5.98:1). Accent is used for exactly three things: the primary
button, the active-nav bar, and the success notice. Nothing else.

## Type

One family (Geist), one mono (Geist Mono) for identifiers and codes.
Scale, fixed pixels — no `vw`, no half-pixels: **28 / 14 / 13 / 12**.
Headings use `text-wrap: balance`; prose caps at 78ch with
`text-wrap: pretty`. Table headers are sentence case at 13px — all-caps
micro-labels are a generated-default tell, not a choice.

## Layout

- The work surface fills the window (operator directive, 2026-11-26). No
  max-width on `.workspace`; prose keeps its own measure.
- Grid tracks are `minmax(0, 1fr)` so a wide table scrolls **inside** its
  card instead of widening the page.
- One elevated surface per page: the data table. Everything else is a
  hairline on white.
- Rhythm is 4-based: 8 / 12 / 16 / 24 / 32. Controls share one height (36px min-height, 37px rendered with borders).
- Wide content scrolls in its container; the page never scrolls sideways.

## Rules

1. Don't decorate. A border, rule or divider must encode structure.
2. One accent, three uses. If a fourth appears, something is wrong.
3. Numbers are tabular; identifiers are mono; prose is sans.
4. Empty states invite the next action and say what it does.
5. Destructive actions are confirmed; the confirmation names the object.
6. Motion only answers an action (open, confirm, reveal) and honours
   `prefers-reduced-motion`.
7. Verify by measurement — computed styles and DOM geometry — not by eye.