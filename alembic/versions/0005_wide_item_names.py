"""rev 48: item names are display labels

Item names stop being a narrow allow-list and become structural: 1-200
characters, no leading/trailing whitespace, printable only, no path
separators. `items.id` remains the primary key; the name is a unique alias
used in URLs (so spaces/uppercase/any script are fine, case is significant).
The app additionally rejects non-printable/format characters; this CHECK is
the database backstop (ASCII control characters and slashes).

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

NAME_PATTERN = r"^[^[:cntrl:]/\\]+$"
NAME_CHECK = (
    "char_length(name) BETWEEN 1 AND 200"
    " AND name = btrim(name)"
    f" AND name ~ '{NAME_PATTERN}'"
    " AND name NOT IN ('.', '..')"
)
LEGACY_PATTERN = "^[a-z0-9\u3400-\u4dbf\u4e00-\u9fff][a-z0-9\u3400-\u4dbf\u4e00-\u9fff._-]{0,199}$"


def upgrade() -> None:
    op.drop_constraint("ck_items_name", "items", type_="check")
    op.create_check_constraint("ck_items_name", "items", NAME_CHECK)


def downgrade() -> None:
    # fails if a name outside the rev-45 grammar exists — rename or delete it
    op.drop_constraint("ck_items_name", "items", type_="check")
    op.create_check_constraint("ck_items_name", "items", f"name ~ '{LEGACY_PATTERN}'")
