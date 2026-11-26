# Custos console — visual system

Custos shares the sibling projects' visual language (Portunus `DESIGN.md`,
Janus): **deep-ink structural frame, cool-gray workspace, near-white
surfaces, one chartreuse accent, Geist type**. The palette is family
property, not a local choice — do not retheme it.

## Tokens

| Token | Value | Use |
|---|---|---|
| `--ink` | `#10151a` | sidebar frame, drawer identity |
| `--ink-raised` | `#171e25` | active nav row |
| `--workspace` | `#eef1f3` | page background |
| `--surface` | `#fbfcfc` | cards |
| `--surface-sunk` | `#f7f9fa` | table head |
| `--line` / `--line-soft` | `#d7dde1` / `#eceff1` | card border / row rule |
| `--text` / `--text-dim` | `#131a20` / `#5b6a75` | body / secondary |
| `--accent` | `#c8f751` chartreuse | primary action, current nav, focus of attention |
| `--accent-soft` | `#f2fcd9` | accent pill / success notice fill |
| `--danger` | `#b3261e` | destructive only |

WCAG AA on every text pair. The accent is for primary actions and the
current page — never decoration.

## Type

Geist Variable for interface, Geist Mono Variable for ids, counts and
micro-labels. Page titles fluid `clamp(30px, 3vw, 42px)`; body 14;
supporting 13/12; **table headers are mono 10px uppercase with 0.08em
tracking** (sibling convention). Tabular numerals for counts; identifiers
truncate with `title`.

## Controls (ported from the siblings)

- Buttons **42px** tall, 0 17px padding, radius 10, weight 600, 13px,
  inline-flex with 8px gap.
- Primary carries an inset bottom hairline and a soft accent glow; hover
  lifts 1px and deepens the glow; **press scales to 0.98**; disabled 0.45.
- Ghost is 36px / 12.5px with no border; destructive is an outline that
  tints on hover.
- Inputs 44px, radius 10, focus ring is a 3px halo (no outline jump).
- Transitions 160–180ms on the standard ease; honours reduced motion.

## Layout

- Work surface fills the window (operator directive); prose keeps 78ch.
- Grid tracks are `minmax(0, 1fr)`; wide tables scroll **inside** the card.
- Cards radius 18, hairline border, one soft shadow.
- Table rhythm 12/16 head, 15/16 rows, accent-tinted hover on pointer
  devices only.
- 4-based spacing (8/12/16/24/32).

## Rules

1. Palette is family property; polish layout and controls, don't retheme.
2. The accent marks action and location. Nothing else.
3. Numbers tabular, identifiers mono, prose sans.
4. Destructive actions confirm, and the confirmation names the object.
5. Motion answers an action only.
6. Verify by measurement — computed styles and geometry — not by eye.
