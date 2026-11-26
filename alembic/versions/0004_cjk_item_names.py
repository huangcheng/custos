"""rev 45: CJK item names

Item names may use Han ideographs (U+3400-U+4DBF Ext A, U+4E00-U+9FFF
Unified) in addition to the existing lowercase ASCII grammar. Operator
usernames keep the ASCII rule (validated in the app; no DB constraint).

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_CJK = "\u3400-\u4dbf\u4e00-\u9fff"
NAME_PATTERN = "^[a-z0-9" + _CJK + "][a-z0-9" + _CJK + "._-]{0,199}$"
LEGACY_PATTERN = "^[a-z0-9][a-z0-9._-]{0,199}$"


def upgrade() -> None:
    op.drop_constraint("ck_items_name", "items", type_="check")
    op.create_check_constraint("ck_items_name", "items", f"name ~ '{NAME_PATTERN}'")


def downgrade() -> None:
    # fails if a CJK-named row exists — rename or delete it first
    op.drop_constraint("ck_items_name", "items", type_="check")
    op.create_check_constraint("ck_items_name", "items", f"name ~ '{LEGACY_PATTERN}'")
