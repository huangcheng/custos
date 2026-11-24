"""rev 38: full-authority agent keys + hard-delete revocation

Every agent key has full item-plane authority (Janus/Portunus parity), so the
per-key mode/scopes columns disappear; revocation now deletes the row, so
revoked_at disappears too. Digests and the revealable sealed copies are
untouched.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # rev 38 semantics: revocation is a hard delete. Rows revoked under the
    # old model must not survive the drop as live full-authority credentials.
    op.execute("DELETE FROM agent_keys WHERE revoked_at IS NOT NULL")
    op.drop_constraint("ck_agent_keys_mode", "agent_keys", type_="check")
    op.drop_column("agent_keys", "mode")
    op.drop_column("agent_keys", "scopes")
    op.drop_column("agent_keys", "revoked_at")


def downgrade() -> None:
    # historical rows cannot be reconstructed: recreated keys default to a
    # read-only, scope-empty shape (previous semantics) and stay live
    op.add_column(
        "agent_keys",
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "agent_keys",
        sa.Column("scopes", sa.ARRAY(sa.Text()), nullable=False, server_default="{}"),
    )
    op.add_column(
        "agent_keys",
        sa.Column("mode", sa.Text(), nullable=False, server_default="read"),
    )
    # the defaults exist only to backfill; the 0002 shape has none
    op.alter_column(
        "agent_keys", "scopes", server_default=None, existing_type=sa.ARRAY(sa.Text())
    )
    op.alter_column("agent_keys", "mode", server_default=None, existing_type=sa.Text())
    op.create_check_constraint(
        "ck_agent_keys_mode", "agent_keys", "mode IN ('read', 'read-write')"
    )
