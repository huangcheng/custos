# Custos console — visual system

Custos shares the sibling projects' visual language (Portunus `DESIGN.md`,
Janus): **deep-ink structural frame, cool-gray workspace, near-white
surfaces, one chartreuse accent, Geist type**. The palette is family
property, not a local choice — do not retheme it.

## Tokens

| Token | Value | Use |
|---|---|---|
| `--ink` | `#10151a` | sidebar frame, drawer identity, secret banner, code blocks |
| `--ink-raised` | `#171e25` | active nav row, token box on ink |
| `--workspace` | `#eef1f3` | page background |
| `--surface` | `#fbfcfc` | cards |
| `--surface-sunk` | `#f7f9fa` | table head, sunk panels |
| `--line` / `--line-soft` | `#d7dde1` / `#eceff1` | card border / row rule |
| `--text` / `--text-dim` | `#131a20` / `#5b6a75` | body / secondary |
| `--text-label` | `#3e4a54` | form labels |
| `--accent` | `#c8f751` chartreuse | primary action, current nav, focus of attention |
| `--accent-soft` | `#f2fcd9` | accent pill / success notice fill |
| `--secondary` | `#e6eaed` | segmented-control track |
| `--danger` | `#b3261e` | destructive only |

WCAG AA on every text pair, including the ink rail (sign-out and nav copy
use `--text-on-ink-dim`, 8:1). The accent is for primary actions and the
current page — never decoration.

## Type

Geist Variable for interface, Geist Mono Variable for ids, counts and
micro-labels. Page titles fluid `clamp(30px, 3vw, 42px)` at line-height
1.05 / 660; lede 14.5px; card titles 17px / 650; body 14; supporting
13/12. **Table headers are mono 10px uppercase with 0.08em tracking**
(sibling convention); the page kicker above every title is mono 9px
uppercase 0.13em behind a 22px rule. Tabular numerals for counts;
identifiers truncate with `title`.

## Controls (ported from the siblings)

- Buttons **42px** tall, 0 17px padding, radius 10, weight 600, 13px,
  inline-flex with 8px gap.
- Primary carries an inset bottom hairline and a soft accent glow; hover
  lifts 1px and deepens the glow; **press scales to 0.98**; disabled 0.45.
- Ghost is 36px / 12.5px with no border; destructive is an outline that
  tints on hover. Hover states apply on pointer devices only.
- Inputs 44px, radius 10, focus ring is a 3px halo (no outline jump); the
  sign-in card uses 48px inputs and a full-width 48px primary.
- Forms lay out in `.form-grid` columns (2–3, collapsing to one at 680px);
  every field reserves its hint line so inputs align. Actions right-align.
- Section switcher is a segmented control: 34px items in an 11px-radius
  `--secondary` track; the current item is ink with accent text.
- Transitions 160–180ms on the standard ease; honours reduced motion.

## Layout

- Work surface fills the window (operator directive); prose keeps 78ch.
- Every screen opens with the same header: kicker, title, lede, and the
  primary action level with the title's first line; the first card sits
  24px under the lede.
- Grid tracks are `minmax(0, 1fr)`; wide tables scroll **inside** the card.
- Cards radius 18, hairline border, one soft shadow; grouping inside a card
  or drawer is a sunk **panel** (radius 12), never a nested card.
- Table rhythm 12/18 head, 15/18 rows, accent-tinted hover on pointer
  devices only; row actions are right-aligned; a table foot carries the
  row count and *Load more*. At 680px and below, inventory rows become
  labelled cards (`data-label` on every cell).
- Sidebar 248px: filled accent mark, line icons in the nav, the sign-out
  styled as a nav item. At 900px it becomes a top bar that sizes to its
  content; at 680px the nav takes its own full-width row.
- 4-based spacing (8/12/16/24/32).

## Components

- **Drawer** (540px): ink header with a mono kicker, an explicit Close
  control, sunk panels, and a sticky action bar — destructive on the left,
  primary at the right end. The page behind is scroll-locked; Tab stays inside.
- **Confirmation**: a centred 26rem modal, never a side panel; destructive
  confirmations focus Cancel.
- **One-time value**: the ink secret banner with an accent token box — it
  outranks every card on the page.
- **Empty state**: mark, title, one line of copy, and the action that
  resolves it. A loading inventory says so instead of showing an empty state.
- **Badges** mono 10.5px in a 6px radius; audit results use status dots
  (`ok` / `fail`), never colour alone.
- **Audit detail** renders as an ink code block behind a keyboard-reachable
  row toggle.
- **Stats** sit in a labelled grid (`dl.stats`), counts in tabular numerals.

## Rules

1. Palette is family property; polish layout and controls, don't retheme.
2. The accent marks action and location. Nothing else.
3. Numbers tabular, identifiers mono, prose sans.
4. Destructive actions confirm, and the confirmation names the object.
5. Motion answers an action only.
6. Verify by measurement — computed styles and geometry — not by eye;
   `scripts/e2e_console.sh` asserts the metrics above on the rendered page.
