"""revealable token secrets

Revision ID: 0002
Revises: 0001

Agent keys and operator tokens gain an optional sealed copy of the full
token (design §5, revealable credentials): AES-256-GCM under the keyring,
AAD domains key:<key_id>|<version> / token:<key_id>|<version>. NULL for
rows minted before this revision — those remain digest-only forever.
The digest column stays the sole authentication primitive.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_keys", sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=True))
    op.add_column("agent_keys", sa.Column("secret_key_version", sa.Integer(), nullable=True))
    op.create_check_constraint(
        "ck_agent_keys_secret_xor",
        "agent_keys",
        "(secret_ciphertext IS NULL) = (secret_key_version IS NULL)",
    )
    op.add_column("operator_tokens", sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=True))
    op.add_column("operator_tokens", sa.Column("secret_key_version", sa.Integer(), nullable=True))
    op.create_check_constraint(
        "ck_operator_tokens_secret_xor",
        "operator_tokens",
        "(secret_ciphertext IS NULL) = (secret_key_version IS NULL)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_operator_tokens_secret_xor", "operator_tokens", type_="check")
    op.drop_column("operator_tokens", "secret_key_version")
    op.drop_column("operator_tokens", "secret_ciphertext")
    op.drop_constraint("ck_agent_keys_secret_xor", "agent_keys", type_="check")
    op.drop_column("agent_keys", "secret_key_version")
    op.drop_column("agent_keys", "secret_ciphertext")
