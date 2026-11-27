"""Name grammars shared by validation, the ORM CHECK, and migrations.

Item names are **display labels**, not identifiers (rev 48): the database key
is `items.id` (uuid); the name is a unique, human-chosen alias used in URLs.
So the grammar is structural — 1-200 characters, no leading/trailing
whitespace, printable text only (control and zero-width/format characters are
rejected; any Unicode space is fine), and no path separators (the name is one
URL path segment). Case is significant: "Google Map", "googlemap" and "谷歌地图"
are three different items. Operator usernames keep the ASCII-only grammar.
"""

import unicodedata

ITEM_NAME_MAX = 200
# Postgres backstop (SQL dialect, not Python `re`): ASCII control characters
# and path separators only. The app's category check is the stricter layer;
# this pattern is never compiled by Python.
ITEM_NAME_SQL_PATTERN = r"^[^[:cntrl:]/\\]+$"
ITEM_NAME_CHECK = (
    f"char_length(name) BETWEEN 1 AND {ITEM_NAME_MAX}"
    f" AND name = btrim(name) AND name ~ '{ITEM_NAME_SQL_PATTERN}'"
    " AND name NOT IN ('.', '..')"
)
# Unicode general categories that make a name unreadable or unaddressable:
# controls, format (zero-width), surrogates, private use, unassigned, and the
# two line/paragraph separators. Space separators (Zs, e.g. NBSP, U+3000) stay
# allowed — they are visible text, and the trim rule catches them at the edges.
UNPRINTABLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def has_unprintable(name: str) -> bool:
    return any(unicodedata.category(ch) in UNPRINTABLE_CATEGORIES for ch in name)


USERNAME_BODY = r"[a-z0-9][a-z0-9._-]{0,199}"
