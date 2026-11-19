"""Passkeys / WebAuthn (design §5): registration + assertion via the
`webauthn` library, single-use challenges (2-min TTL), UV required, and
the WebAuthn-correct sign-count rule (reject only when both stored and
asserted counters are non-zero and asserted <= stored).
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.options_to_json_dict import options_to_json_dict
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from custos.config import Settings
from custos.db.models import OperatorAccount, PasskeyCredential, WebAuthnChallenge
from custos.errors import AppError

_CHALLENGE_TTL = 120


def _origins(settings: Settings) -> list[str]:
    origins = list(settings.allowed_origins)
    if settings.insecure_dev:
        origins += ["http://localhost", "http://127.0.0.1"]
    return origins or ["http://localhost"]


def _expected_origin(settings: Settings, client_origin: str) -> list[str]:
    """In dev, accept any loopback http origin (browsers carry a port); the
    library compares exact strings, so validate the presented origin here."""
    if settings.insecure_dev:
        import re

        if re.fullmatch(r"http://(localhost|127\.0\.0\.1)(:\d+)?", client_origin):
            return [client_origin]
    return _origins(settings)


def _rp_id(settings: Settings) -> str:
    return settings.webauthn_rp_id or "localhost"


async def _new_challenge(session: AsyncSession, purpose: str,
                         session_id: Any = None) -> bytes:
    challenge = secrets.token_bytes(32)
    session.add(
        WebAuthnChallenge(
            challenge=challenge, purpose=purpose, session_id=session_id,
            expires_at=datetime.now(UTC) + timedelta(seconds=_CHALLENGE_TTL),
        )
    )
    await session.flush()
    return challenge


async def _consume_challenge(session: AsyncSession, challenge: bytes,
                             purpose: str, session_id: Any = None) -> None:
    stmt = update(WebAuthnChallenge).where(
        WebAuthnChallenge.challenge == challenge,
        WebAuthnChallenge.purpose == purpose,
        WebAuthnChallenge.consumed_at.is_(None),
        WebAuthnChallenge.expires_at > datetime.now(UTC),
    )
    if purpose == "register":
        stmt = stmt.where(WebAuthnChallenge.session_id == session_id)
    result = await session.execute(stmt.values(consumed_at=datetime.now(UTC)))
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise AppError("invalid", "challenge expired or already used")


async def registration_options(session: AsyncSession, settings: Settings,
                               session_id: Any) -> dict[str, Any]:
    acct = (
        await session.execute(select(OperatorAccount).where(OperatorAccount.id == 1))
    ).scalar_one()
    challenge = await _new_challenge(session, "register", session_id)
    existing = list(
        (await session.execute(select(PasskeyCredential))).scalars()
    )
    opts = generate_registration_options(
        rp_id=_rp_id(settings), rp_name="Custos",
        user_name=acct.username, user_id=b"operator",
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=c.credential_id) for c in existing
        ],
    )
    return options_to_json_dict(opts)


async def register_verify(session: AsyncSession, settings: Settings,
                          session_id: Any, credential: dict[str, Any]) -> None:
    import json

    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    try:
        client_data = credential["response"]["clientDataJSON"]
        cd = json.loads(base64url_to_bytes(client_data))
        challenge = base64url_to_bytes(cd["challenge"])
    except Exception:
        raise AppError("invalid", "malformed credential") from None
    await _consume_challenge(session, challenge, "register", session_id)
    try:
        verified = verify_registration_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=_rp_id(settings),
            expected_origin=_expected_origin(settings, cd.get("origin", "")),
            require_user_verification=True,
        )
    except Exception as exc:
        raise AppError("invalid", "registration verification failed") from exc
    label = credential.get("label", "")
    if not isinstance(label, str) or len(label) > 100:
        raise AppError("invalid", "invalid label")
    existing = (
        await session.execute(
            select(PasskeyCredential).where(
                PasskeyCredential.credential_id == verified.credential_id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise AppError("conflict", "credential already registered")
    session.add(
        PasskeyCredential(
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            label=label,
        )
    )
    await session.flush()


async def assertion_options(session: AsyncSession, settings: Settings) -> dict[str, Any]:
    challenge = await _new_challenge(session, "assert", None)
    creds = list((await session.execute(select(PasskeyCredential))).scalars())
    opts = generate_authentication_options(
        rp_id=_rp_id(settings), challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in creds],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json_dict(opts)


async def assertion_verify(session: AsyncSession, settings: Settings,
                           credential: dict[str, Any]) -> PasskeyCredential:
    from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

    try:
        cred_id = base64url_to_bytes(credential["id"])
    except (KeyError, TypeError, ValueError):
        raise AppError("invalid", "malformed credential") from None
    row = (
        await session.execute(
            select(PasskeyCredential).where(PasskeyCredential.credential_id == cred_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise AppError("unauthorized", "authentication failed")
    import json

    try:
        cd = credential["response"]["clientDataJSON"]
        cd_json = json.loads(base64url_to_bytes(cd))
        challenge = base64url_to_bytes(cd_json["challenge"])
    except Exception:
        raise AppError("invalid", "malformed credential") from None
    await _consume_challenge(session, challenge, "assert")
    try:
        verified = verify_authentication_response(
            credential=credential, expected_challenge=challenge,
            expected_rp_id=_rp_id(settings),
            expected_origin=_expected_origin(settings, cd_json.get("origin", "")),
            credential_public_key=row.public_key,
            # pass 0: the library's rule is stricter than §5 (it rejects a
            # counter-0 authenticator after any non-zero count). We apply the
            # spec rule below ourselves.
            credential_current_sign_count=0,
            require_user_verification=True,
        )
    except Exception as exc:
        raise AppError("unauthorized", "authentication failed") from exc
    # WebAuthn sign-count rule: reject only when both non-zero and asserted<=stored
    if (
        row.sign_count > 0
        and verified.new_sign_count > 0
        and verified.new_sign_count <= row.sign_count
    ):
        raise AppError("unauthorized", "authentication failed")
    # never decrease the stored high-water mark (clone detection)
    row.sign_count = max(row.sign_count, verified.new_sign_count)
    return row
