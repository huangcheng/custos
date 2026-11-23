"""ORM models for the design §4 schema (initial migration mirrors these).

Conventions: uuid PKs default client-side; timestamps are timestamptz with
server defaults; enums are text + CHECK for migration simplicity. Secret
material lives only in ``ciphertext``/digest/hash columns — never in audit.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

ITEM_NAME_RE = r"^[a-z0-9][a-z0-9._-]{0,199}$"
FIELD_NAME_RE = r"^[A-Z][A-Z0-9_]{0,63}$"


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid.uuid4)


def _created_at() -> Mapped[datetime]:
    return mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)


class Item(Base):
    __tablename__ = "items"
    __table_args__ = (CheckConstraint(f"name ~ '{ITEM_NAME_RE}'", name="ck_items_name"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    deleted_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class Field(Base):
    __tablename__ = "fields"
    __table_args__ = (
        UniqueConstraint("item_id", "name", name="uq_fields_item_name"),
        CheckConstraint(f"name ~ '{FIELD_NAME_RE}'", name="ck_fields_name"),
        CheckConstraint(
            "(secret AND value IS NULL AND ciphertext IS NOT NULL AND key_version IS NOT NULL)"
            " OR (NOT secret AND value IS NOT NULL AND ciphertext IS NULL"
            " AND key_version IS NULL)",
            name="ck_fields_value_xor",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    item_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    secret: Mapped[bool] = mapped_column(Boolean, nullable=False)
    value: Mapped[str | None] = mapped_column(Text)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_version: Mapped[int | None] = mapped_column(Integer, index=True)


class FieldHistory(Base):
    __tablename__ = "field_history"
    __table_args__ = (
        Index("ix_field_history_item_name", "item_id", "name"),
        Index("ix_field_history_key_version", "key_version"),
        CheckConstraint(
            "(secret AND value IS NULL AND ciphertext IS NOT NULL AND key_version IS NOT NULL)"
            " OR (NOT secret AND value IS NOT NULL AND ciphertext IS NULL"
            " AND key_version IS NULL)",
            name="ck_field_history_value_xor",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    # Plain uuids, no FK: snapshots survive field/item deletion until purge/retention.
    field_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    item_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    secret: Mapped[bool] = mapped_column(Boolean, nullable=False)
    value: Mapped[str | None] = mapped_column(Text)
    ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_version: Mapped[int | None] = mapped_column(Integer)
    # clock_timestamp(): statement time, not transaction start — serialized
    # writers must produce monotonic snapshot ordering for budget eviction.
    superseded_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.clock_timestamp(), nullable=False
    )
    superseded_by: Mapped[str] = mapped_column(Text, nullable=False)
    actor_label: Mapped[str] = mapped_column(Text, nullable=False)


class AgentKey(Base):
    __tablename__ = "agent_keys"
    __table_args__ = (
        CheckConstraint("mode IN ('read', 'read-write')", name="ck_agent_keys_mode"),
        CheckConstraint(
            "(secret_ciphertext IS NULL) = (secret_key_version IS NULL)",
            name="ck_agent_keys_secret_xor",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    key_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    digest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # revealable secret (§5): the full token sealed under the keyring, AAD
    # domain "key:<key_id>|<version>". NULL for keys minted before revealable
    # storage existed — those stay digest-only and can never be revealed.
    secret_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    secret_key_version: Mapped[int | None] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    mode: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = _created_at()


class OperatorToken(Base):
    __tablename__ = "operator_tokens"
    __table_args__ = (
        CheckConstraint("expires_at IS NOT NULL", name="ck_operator_tokens_expiry_required"),
        CheckConstraint(
            "(secret_ciphertext IS NULL) = (secret_key_version IS NULL)",
            name="ck_operator_tokens_secret_xor",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    key_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    digest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # revealable secret (§5): AAD domain "token:<key_id>|<version>"; NULL for
    # tokens minted before revealable storage existed (never revealable).
    secret_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    secret_key_version: Mapped[int | None] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    allow_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = _created_at()


class OperatorAccount(Base):
    __tablename__ = "operator_account"
    __table_args__ = (CheckConstraint("id = 1", name="ck_operator_account_single_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    totp_secret: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_key_version: Mapped[int | None] = mapped_column(Integer)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    totp_last_step_login: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    totp_last_step_stepup: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    totp_last_step_confirm: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class OperatorSession(Base):
    __tablename__ = "operator_sessions"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('full', 'recovery_reset')", name="ck_operator_sessions_purpose"
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    csrf_token: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    idle_ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=43200)
    created_at: Mapped[datetime] = _created_at()
    last_seen_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    absolute_expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class StepUpToken(Base):
    __tablename__ = "step_up_tokens"
    __table_args__ = (
        CheckConstraint(
            "(session_id IS NOT NULL)::int + (operator_token_id IS NOT NULL)::int = 1",
            name="ck_step_up_tokens_one_principal",
        ),
        CheckConstraint("kind IN ('single', 'rekey_run')", name="ck_step_up_tokens_kind"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("operator_sessions.id"))
    operator_token_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("operator_tokens.id"))
    nonce_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = _created_at()


class DeviceCode(Base):
    __tablename__ = "device_codes"

    id: Mapped[uuid.UUID] = _uuid_pk()
    code_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    transfer_hash: Mapped[bytes | None] = mapped_column(LargeBinary)
    approved_by_session: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operator_sessions.id")
    )
    approved_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    exchange_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    client_ip: Mapped[str] = mapped_column(Text, nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = _created_at()
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class LockoutSuppression(Base):
    __tablename__ = "lockout_suppressions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scope: Mapped[str] = mapped_column(Text, nullable=False)  # ip:<addr> | ip:* | account
    suppressed_until_events_ts: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = _created_at()


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id: Mapped[uuid.UUID] = _uuid_pk()
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    label: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = _created_at()


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: Mapped[uuid.UUID] = _uuid_pk()
    digest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = _created_at()


class AuthEvent(Base):
    __tablename__ = "auth_events"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('login_password', 'login_totp', 'login_passkey', 'login_recovery',"
            " 'step_up', 'agent_auth', 'setup')",
            name="ck_auth_events_kind",
        ),
        Index("ix_auth_events_ip_ts", "ip", "ts"),
        Index("ix_auth_events_kind_ts", "kind", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ip: Mapped[str] = mapped_column(Text, nullable=False)
    peer_ip: Mapped[str] = mapped_column(Text, nullable=False)
    ts: Mapped[datetime] = _created_at()


class AuditRow(Base):
    __tablename__ = "audit"
    __table_args__ = (
        CheckConstraint(
            "actor_kind IN ('agent', 'operator_session', 'operator_token', 'anonymous',"
            " 'local_process')",
            name="ck_audit_actor_kind",
        ),
        Index("ix_audit_ts", "ts"),
        Index("ix_audit_item_name", "item_name"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = _created_at()
    actor_kind: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[str | None] = mapped_column(Text)
    actor_label: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    item_name: Mapped[str | None] = mapped_column(Text)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    detail: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)


class WebAuthnChallenge(Base):
    __tablename__ = "webauthn_challenges"
    __table_args__ = (
        CheckConstraint("purpose IN ('register', 'assert')", name="ck_webauthn_challenges_purpose"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    challenge: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("operator_sessions.id"))
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    created_at: Mapped[datetime] = _created_at()
