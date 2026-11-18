"""Scope matching (design §5): Python fnmatch.fnmatchcase semantics, pinned.

Case-sensitive; ``*`` matches any characters including dots (item names have
no ``/``). Empty scopes = no access (fail closed).
"""

from __future__ import annotations

from fnmatch import fnmatchcase


def scope_allows(scopes: list[str], name: str) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in scopes)
