"""Name grammars shared by validation, the ORM CHECK, and migrations.

Item names: lowercase ASCII, digits, dot/dash/underscore, plus Han ideographs
(U+3400-U+4DBF Ext A, U+4E00-U+9FFF Unified; rev 45). Operator usernames keep
the ASCII-only grammar.
"""

_CJK = "\u3400-\u4dbf\u4e00-\u9fff"
ITEM_NAME_BODY = "[a-z0-9" + _CJK + "][a-z0-9" + _CJK + "._-]{0,199}"
ITEM_NAME_PATTERN = "^" + ITEM_NAME_BODY + "$"  # Postgres CHECK
USERNAME_BODY = r"[a-z0-9][a-z0-9._-]{0,199}"
