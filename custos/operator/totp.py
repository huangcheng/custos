"""TOTP (design §5): pyotp, issuer Custos, ±1 step, per-site monotonic
replay counters (login/stepup/confirm) with guarded UPDATEs. The secret is
sealed under the operator AAD domain at the newest keyring version.
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime

import pyotp
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from custos.crypto import UnreadableError, Vault
from custos.db.models import OperatorAccount
from custos.errors import AppError

_SITE_COLUMNS = {
    "login": OperatorAccount.totp_last_step_login,
    "stepup": OperatorAccount.totp_last_step_stepup,
    "confirm": OperatorAccount.totp_last_step_confirm,
}


def _unseal(vault: Vault, acct: OperatorAccount) -> str:
    if acct.totp_secret is None or acct.totp_key_version is None:
        raise AppError("key_unavailable", "totp secret unavailable")
    try:
        raw = vault.open("operator:totp", "", acct.totp_secret, acct.totp_key_version)
    except UnreadableError as exc:
        raise AppError("key_unavailable", "totp secret unavailable") from exc
    return raw.decode()


async def begin_totp_setup(session: AsyncSession, vault: Vault) -> tuple[str, str]:
    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one()
    secret = pyotp.random_base32()
    blob, version = vault.seal("operator:totp", "", secret.encode())
    acct.totp_secret = blob
    acct.totp_key_version = version
    acct.totp_enabled = False  # activated only on confirm
    uri = pyotp.TOTP(secret).provisioning_uri(name=acct.username, issuer_name="Custos")
    return secret, uri


async def confirm_totp(session: AsyncSession, vault: Vault, code: str) -> None:
    # confirm is a verification site too: guarded monotonic replay counter
    if not await verify_totp(session, vault, code, site="confirm"):
        raise AppError("invalid", "totp code rejected")
    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one()
    acct.totp_enabled = True


async def disable_totp(session: AsyncSession) -> None:
    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one()
    acct.totp_enabled = False
    acct.totp_secret = None
    acct.totp_key_version = None


async def verify_totp(session: AsyncSession, vault: Vault, code: str, *, site: str) -> bool:
    if site not in _SITE_COLUMNS:
        raise ValueError(f"unknown totp site {site!r}")
    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one()
    secret = _unseal(vault, acct)  # raises key_unavailable on corrupt/missing blob
    totp = pyotp.TOTP(secret)
    now_step = int(datetime.now(UTC).timestamp()) // 30
    # find which step (within ±1) the code matches
    matched: int | None = None
    for step in (now_step - 1, now_step, now_step + 1):
        if hmac.compare_digest(totp.at(step * 30), code):
            matched = step
            break
    if matched is None:
        return False
    column = _SITE_COLUMNS[site]
    # guarded monotonic UPDATE: reject step <= stored, exactly one winner
    result = await session.execute(
        update(OperatorAccount)
        .where(OperatorAccount.id == 1, column < matched)
        .values({column.key: matched})
    )
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]
