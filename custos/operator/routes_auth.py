"""Operator auth routes (design §5/§6). Grows task by task."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select

from custos.db.models import OperatorAccount, OperatorSession
from custos.errors import AppError
from custos.operator.account import ensure_setup_code, setup_account
from custos.operator.sessions import COOKIE_NAME, require_session
from custos.operator.stepup import require_step_up

_STEP_UP_TOTP = Depends(require_step_up("totp"))
_STEP_UP_RECOVERY = Depends(require_step_up("recovery"))
_STEP_UP_PASSKEY = Depends(require_step_up("passkey"))

router = APIRouter(prefix="/api/auth")


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    async with request.app.state.session_maker() as session:
        acct = (
            await session.execute(select(OperatorAccount))
        ).scalar_one_or_none()
    result: dict[str, Any] = {
        "setup_required": acct is None,
        "totp_required": bool(acct is not None and acct.totp_enabled),
        "turnstile_sitekey": request.app.state.settings.turnstile_sitekey,
        "passkey_available": bool(
            request.app.state.settings.webauthn_rp_id
            or request.app.state.settings.insecure_dev
        ),
    }
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie and not request.headers.get("authorization"):
        from custos.operator.sessions import resolve_session

        async with request.app.state.session_maker() as session:
            try:
                sess = await resolve_session(session, cookie)
                result["csrf_token"] = sess.csrf_token
            except AppError:
                pass  # dead cookie: status stays public
            await session.commit()
    return result


@router.post("/logout")
async def logout(
    request: Request, response: Response,
    sess: OperatorSession = Depends(require_session),
) -> dict[str, Any]:
    from custos.audit import record_audit
    from custos.operator.sessions import clear_session_cookie, revoke_session

    async with request.app.state.session_maker() as session:
        await revoke_session(session, sess.id)
        await session.commit()
    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator", action="operator.logout",
        item_name=None, ok=True, detail={},
    )
    clear_session_cookie(response)
    return {"logout": "complete"}


async def _totp_audit(request: Request, sess: OperatorSession, reason: str) -> None:
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator", action="operator.totp_change",
        item_name=None, ok=True, detail={"reason": reason},
    )


def _passkeys_enabled(request: Request) -> None:
    settings = request.app.state.settings
    if not settings.webauthn_rp_id and not settings.insecure_dev:
        raise AppError("not_found", "not found")


@router.post("/passkeys/register/options")
async def passkey_reg_options(
    request: Request, sess: OperatorSession = _STEP_UP_PASSKEY
) -> dict[str, Any]:
    from custos.operator import passkeys

    _passkeys_enabled(request)
    async with request.app.state.session_maker() as session:
        opts = await passkeys.registration_options(session, request.app.state.settings, sess.id)
        await session.commit()
    return opts


@router.post("/passkeys/register/verify")
async def passkey_reg_verify(
    request: Request, sess: OperatorSession = _STEP_UP_PASSKEY
) -> dict[str, Any]:
    from custos.operator import passkeys
    from custos.routes_agent import _json_body

    _passkeys_enabled(request)
    body = await _json_body(request)
    async with request.app.state.session_maker() as session:
        await passkeys.register_verify(session, request.app.state.settings, sess.id, body)
        await session.commit()
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator", action="operator.passkey_change",
        item_name=None, ok=True, detail={"reason": "register"},
    )
    return {"passkey": "registered"}


@router.get("/passkeys")
async def passkey_list(
    request: Request, sess: OperatorSession = _STEP_UP_PASSKEY
) -> dict[str, Any]:
    from custos.db.models import PasskeyCredential

    _passkeys_enabled(request)
    async with request.app.state.session_maker() as session:
        rows = (await session.execute(select(PasskeyCredential))).scalars().all()
    return {"passkeys": [{"id": str(r.id), "label": r.label} for r in rows]}


@router.delete("/passkeys/{cred_id}")
async def passkey_delete(
    cred_id: str, request: Request,
    sess: OperatorSession = _STEP_UP_PASSKEY,
) -> dict[str, Any]:
    import uuid as _uuid

    from custos.db.models import PasskeyCredential

    _passkeys_enabled(request)
    try:
        parsed_id = _uuid.UUID(cred_id)
    except ValueError:
        raise AppError("not_found", "not found") from None
    async with request.app.state.session_maker() as session:
        row = await session.get(PasskeyCredential, parsed_id)
        if row is None:
            raise AppError("not_found", "not found")
        await session.delete(row)
        await session.commit()
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator", action="operator.passkey_change",
        item_name=None, ok=True, detail={"reason": "remove"},
    )
    return {"passkey": "removed"}


@router.post("/passkeys/assert/options")
async def passkey_assert_options(request: Request) -> dict[str, Any]:
    from custos.operator import passkeys

    _passkeys_enabled(request)
    from custos.operator.login import resolve_client

    ip, _peer = resolve_client(request, request.app.state.settings)
    request.app.state.rate_limiter.check_unauth(ip)
    async with request.app.state.session_maker() as session:
        opts = await passkeys.assertion_options(session, request.app.state.settings)
        await session.commit()
    return opts


@router.post("/passkeys/assert/verify")
async def passkey_assert_verify(request: Request, response: Response) -> dict[str, Any]:
    from custos.operator import passkeys
    from custos.operator.sessions import create_session, set_session_cookie
    from custos.routes_agent import _json_body

    _passkeys_enabled(request)
    settings = request.app.state.settings
    body = await _json_body(request)
    from custos.operator.lockout import check_lockout
    from custos.operator.login import resolve_client

    ip, peer = resolve_client(request, settings)
    async with request.app.state.session_maker() as session:
        await check_lockout(session, ip=ip, account_exists=True,
                            counter=request.app.state.failure_counter)
    request.app.state.rate_limiter.check_unauth(ip)
    if settings.turnstile_secret:
        from custos.operator import turnstile as turnstile_mod

        token = body.get("turnstile")
        if token is not None and not isinstance(token, str):
            raise AppError("invalid", "turnstile must be a string")
        try:
            await turnstile_mod.verify_turnstile(
                settings, token, ip, client=request.app.state.turnstile_client
            )
        except AppError:
            from custos.audit import record_audit

            await record_audit(
                request.app.state.session_maker, actor_kind="anonymous", actor_id=None,
                actor_label="anonymous", action="auth.failure", item_name=None, ok=False,
                detail={"ip": ip, "reason": "turnstile"},
                budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
            raise
    try:
        async with request.app.state.session_maker() as session:
            await passkeys.assertion_verify(session, settings, body)
            row, cookie = await create_session(session, purpose="full")
            await session.commit()
    except AppError as exc:
        if exc.code == "unauthorized":
            from custos.audit import record_audit, record_auth_event

            await record_auth_event(
                request.app.state.session_maker, kind="login_passkey", ok=False,
                ip=ip, peer_ip=peer, budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
            await record_audit(
                request.app.state.session_maker, actor_kind="anonymous", actor_id=None,
                actor_label="anonymous", action="auth.failure", item_name=None, ok=False,
                detail={"ip": ip, "reason": "login_passkey"},
                budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
        raise
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(row.id), actor_label="operator", action="operator.login",
        item_name=None, ok=True, detail={"reason": "passkey"},
    )
    set_session_cookie(response, cookie, settings)
    return {"csrf_token": row.csrf_token}


@router.post("/device")
async def device_mint(request: Request) -> dict[str, Any]:
    from custos.operator.device import mint_device
    from custos.operator.login import resolve_client

    settings = request.app.state.settings
    ip, _peer = resolve_client(request, settings)
    request.app.state.rate_limiter.check_unauth(ip)
    ua = request.headers.get("user-agent", "")
    async with request.app.state.session_maker() as session:
        code, expires = await mint_device(session, ip=ip, user_agent=ua)
        await session.commit()
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="anonymous", actor_id=None,
        actor_label="anonymous", action="device.login", item_name=None, ok=True,
        detail={"stage": "mint"},
    )
    return {"device_code": code, "expires_at": expires.isoformat()}


@router.post("/device/lookup")
async def device_lookup(
    request: Request, sess: OperatorSession = Depends(require_session)
) -> dict[str, Any]:
    from custos.operator.device import lookup_device
    from custos.routes_agent import _json_body

    body = await _json_body(request)
    code = body.get("device_code")
    if not isinstance(code, str):
        raise AppError("invalid", "device_code is required")
    async with request.app.state.session_maker() as session:
        try:
            info = await lookup_device(session, code)
        except AppError:
            from custos.audit import record_audit

            await record_audit(
                request.app.state.session_maker, actor_kind="operator_session",
                actor_id=str(sess.id), actor_label="operator", action="device.login",
                item_name=None, ok=False, detail={"stage": "lookup"},
                budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
            raise
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator", action="device.login",
        item_name=None, ok=True, detail={"stage": "lookup"},
    )
    return info


@router.post("/device/approve")
async def device_approve(
    request: Request, sess: OperatorSession = Depends(require_session)
) -> dict[str, Any]:
    from custos.operator.device import approve_device
    from custos.routes_agent import _json_body

    body = await _json_body(request)
    code = body.get("device_code")
    if not isinstance(code, str):
        raise AppError("invalid", "device_code is required")
    from custos.audit import record_audit

    async with request.app.state.session_maker() as session:
        try:
            transfer, deadline = await approve_device(session, sess, code)
        except AppError:
            await record_audit(
                request.app.state.session_maker, actor_kind="operator_session",
                actor_id=str(sess.id), actor_label="operator", action="device.login",
                item_name=None, ok=False, detail={"stage": "approve"},
                budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
            raise
        await session.commit()
    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator", action="device.login",
        item_name=None, ok=True, detail={"stage": "approve"},
    )
    return {"transfer_code": transfer, "exchange_deadline": deadline.isoformat()}


@router.post("/device-exchange")
async def device_exchange(request: Request, response: Response) -> dict[str, Any]:
    from custos.operator.device import exchange_device
    from custos.operator.login import resolve_client
    from custos.operator.sessions import set_session_cookie
    from custos.routes_agent import _json_body

    settings = request.app.state.settings
    body = await _json_body(request)
    code = body.get("device_code")
    transfer = body.get("transfer_code")
    if not isinstance(code, str) or not isinstance(transfer, str):
        raise AppError("invalid", "device_code and transfer_code are required")
    try:
        code.encode("utf-8")
        transfer.encode("utf-8")
    except UnicodeEncodeError:
        raise AppError("invalid", "inputs must be valid UTF-8") from None
    ip, _peer = resolve_client(request, settings)
    request.app.state.rate_limiter.check_unauth(ip)
    from custos.audit import record_audit

    async with request.app.state.session_maker() as session:
        try:
            sess_row, cookie = await exchange_device(
                session, request.app.state.session_maker, code, transfer
            )
        except AppError:
            await record_audit(
                request.app.state.session_maker, actor_kind="anonymous", actor_id=None,
                actor_label="anonymous", action="device.login", item_name=None, ok=False,
                detail={"stage": "exchange", "ip": ip},
                budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
            raise
        await session.commit()
    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess_row.id), actor_label="operator", action="device.login",
        item_name=None, ok=True, detail={"stage": "exchange"},
    )
    set_session_cookie(response, cookie, settings)
    return {"csrf_token": sess_row.csrf_token}


@router.post("/step-up")
async def step_up_route(
    request: Request, sess: OperatorSession = Depends(require_session)
) -> dict[str, Any]:
    from custos.operator.login import resolve_client
    from custos.operator.stepup import mint_step_up
    from custos.routes_agent import _json_body

    body = await _json_body(request)
    password = body.get("password")
    if not isinstance(password, str):
        raise AppError("invalid", "password is required")
    totp = body.get("totp")
    recovery_code = body.get("recovery_code")
    for name, val in (("totp", totp), ("recovery_code", recovery_code)):
        if val is not None and not isinstance(val, str):
            raise AppError("invalid", f"{name} must be a string")
    if totp is not None and recovery_code is not None:
        raise AppError("invalid", "supply at most one second factor")
    try:
        password.encode("utf-8")
        for val in (totp, recovery_code):
            if val is not None:
                val.encode("utf-8")
    except UnicodeEncodeError:
        raise AppError("invalid", "inputs must be valid UTF-8") from None
    settings = request.app.state.settings
    ip, peer = resolve_client(request, settings)
    from custos.operator.lockout import check_lockout

    async with request.app.state.session_maker() as session:
        await check_lockout(session, ip=ip, account_exists=True,
                            counter=request.app.state.failure_counter)
        row = await session.get(OperatorSession, sess.id)
        token = await mint_step_up(
            session, request.app.state.session_maker, row, password=password,
            vault=request.app.state.vault, totp=totp, recovery_code=recovery_code,
            pepper=settings.pepper_raw, ip=ip, peer_ip=peer,
            budget=request.app.state.ledger_budget,
            counter=request.app.state.failure_counter,
            semaphore=request.app.state.auth_semaphore,
            executor=request.app.state.auth_executor,
            wait_cap=getattr(request.app.state, "auth_wait_cap", 10.0),
        )
        await session.commit()
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator", action="operator.step_up",
        item_name=None, ok=True, detail={},
    )
    return {"step_up_token": token}


@router.post("/password-change")
async def password_change_route(
    request: Request, response: Response,
    sess: OperatorSession = Depends(require_session),
) -> dict[str, Any]:
    from custos.operator.lockout import check_lockout
    from custos.operator.login import resolve_client
    from custos.operator.recovery import change_password
    from custos.operator.sessions import set_session_cookie
    from custos.operator.stepup import consume_step_up
    from custos.routes_agent import _json_body

    ip0, peer0 = resolve_client(request, request.app.state.settings)
    async with request.app.state.session_maker() as session:
        await check_lockout(session, ip=ip0, account_exists=True,
                            counter=request.app.state.failure_counter)
    request.app.state.rate_limiter.check_unauth(ip0)
    # full sessions require a step-up token; recovery_reset is waived (it
    # re-verifies current_password in the body, §5)
    if sess.purpose != "recovery_reset":
        token = request.headers.get("x-step-up-token", "")
        if not token:
            raise AppError("step_up_required", "step-up required")
        async with request.app.state.session_maker() as session:
            presenter = await session.get(OperatorSession, sess.id)
            await consume_step_up(session, token, presenter)
            await session.commit()

    body = await _json_body(request)
    current = body.get("current_password")
    new = body.get("new_password")
    if not isinstance(current, str) or not isinstance(new, str):
        raise AppError("invalid", "current_password and new_password are required")
    settings = request.app.state.settings
    from custos.audit import record_audit
    from custos.operator.login import resolve_client

    ip, peer = resolve_client(request, settings)
    async with request.app.state.session_maker() as session:
        row = await session.get(OperatorSession, sess.id)
        try:
            promoted, fresh_codes, cookie = await change_password(
                session, row, current=current, new=new, pepper=settings.pepper_raw,
                semaphore=request.app.state.auth_semaphore,
                executor=request.app.state.auth_executor,
                wait_cap=getattr(request.app.state, "auth_wait_cap", 10.0),
            )
        except AppError as exc:
            if exc.code == "unauthorized":
                # failed current-password: audit + lockout accounting (§5)
                from custos.audit import record_auth_event

                await record_auth_event(
                    request.app.state.session_maker, kind="login_password", ok=False,
                    ip=ip, peer_ip=peer, budget=request.app.state.ledger_budget,
                    counter=request.app.state.failure_counter,
                )
                await record_audit(
                    request.app.state.session_maker, actor_kind="operator_session",
                    actor_id=str(sess.id), actor_label="operator",
                    action="operator.password_change", item_name=None, ok=False,
                    detail={"reason": "bad_current_password"},
                    budget=request.app.state.ledger_budget,
                    counter=request.app.state.failure_counter,
                )
            raise
        await session.commit()
    if cookie:
        set_session_cookie(response, cookie, settings)
    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(promoted.id), actor_label="operator",
        action="operator.password_change", item_name=None, ok=True, detail={},
    )
    result: dict[str, Any] = {"password": "changed"}
    if fresh_codes:
        result["recovery_codes"] = fresh_codes
    if cookie:
        # full-session replacement: hand the console the new csrf token
        result["csrf_token"] = promoted.csrf_token
    return result


@router.post("/recovery/regen")
async def recovery_regen(
    request: Request, sess: OperatorSession = _STEP_UP_RECOVERY
) -> dict[str, Any]:
    from custos.operator.recovery import issue_codes

    settings = request.app.state.settings
    async with request.app.state.session_maker() as session:
        codes = await issue_codes(session, settings.pepper_raw)
        await session.commit()
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(sess.id), actor_label="operator",
        action="operator.recovery_regen", item_name=None, ok=True, detail={},
    )
    return {"recovery_codes": codes}


@router.post("/totp/setup")
async def totp_setup(
    request: Request, sess: OperatorSession = _STEP_UP_TOTP
) -> dict[str, Any]:
    from custos.operator.totp import begin_totp_setup

    async with request.app.state.session_maker() as session:
        secret, uri = await begin_totp_setup(session, request.app.state.vault)
        await session.commit()
    await _totp_audit(request, sess, "enable")
    return {"secret": secret, "provisioning_uri": uri}


@router.post("/totp/confirm")
async def totp_confirm(
    request: Request, sess: OperatorSession = _STEP_UP_TOTP
) -> dict[str, Any]:
    from custos.operator.totp import confirm_totp
    from custos.routes_agent import _json_body

    body = await _json_body(request)
    code = body.get("code")
    if not isinstance(code, str):
        raise AppError("invalid", "code is required")
    async with request.app.state.session_maker() as session:
        codes = await confirm_totp(
            session, request.app.state.vault, code, request.app.state.settings.pepper_raw
        )
        await session.commit()
    await _totp_audit(request, sess, "confirm")
    return {"totp": "enabled", "recovery_codes": codes}


@router.post("/totp/disable")
async def totp_disable(
    request: Request, sess: OperatorSession = _STEP_UP_TOTP
) -> dict[str, Any]:
    from custos.operator.totp import disable_totp

    async with request.app.state.session_maker() as session:
        await disable_totp(session)
        await session.commit()
    await _totp_audit(request, sess, "disable")
    return {"totp": "disabled"}


@router.post("/login")
async def login_route(request: Request, response: Response) -> dict[str, Any]:
    from custos.operator.login import login, resolve_client
    from custos.operator.sessions import set_session_cookie
    from custos.routes_agent import _json_body

    settings = request.app.state.settings
    body = await _json_body(request)
    username = body.get("username")
    password = body.get("password")
    totp = body.get("totp")
    recovery_code = body.get("recovery_code")
    if not isinstance(username, str):
        raise AppError("invalid", "username is required")
    if not isinstance(password, str):
        raise AppError("invalid", "password is required")
    for field_name, value in (("totp", totp), ("recovery_code", recovery_code)):
        if value is not None and not isinstance(value, str):
            raise AppError("invalid", f"{field_name} must be a string")
    if totp is not None and recovery_code is not None:
        raise AppError("invalid", "supply at most one second factor")
    ip, peer = resolve_client(request, settings)
    factor_hook = request.app.state.login_factor_hook
    from custos.operator.lockout import check_lockout

    async with request.app.state.session_maker() as session:
        acct_exists = (
            await session.execute(select(OperatorAccount.id))
        ).first() is not None
        await check_lockout(session, ip=ip, account_exists=acct_exists,
                            counter=request.app.state.failure_counter)
    request.app.state.rate_limiter.check_unauth(ip)  # 429 before verify, no ledger
    # Turnstile (when configured): after lockout+limiter, before credentials.
    # Failure is audit-only (no auth_events row -> never credential-lockout).
    if settings.turnstile_secret:
        from custos.audit import record_audit
        from custos.operator import turnstile as turnstile_mod

        token = body.get("turnstile")
        if token is not None and not isinstance(token, str):
            raise AppError("invalid", "turnstile must be a string")
        try:
            await turnstile_mod.verify_turnstile(
                settings, token, ip, client=request.app.state.turnstile_client
            )
        except AppError:
            await record_audit(
                request.app.state.session_maker, actor_kind="anonymous", actor_id=None,
                actor_label="anonymous", action="auth.failure", item_name=None, ok=False,
                detail={"ip": ip, "reason": "turnstile"},
                budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
            raise
    async with request.app.state.session_maker() as session:
        row, cookie = await login(
            session, request.app.state.session_maker,
            semaphore=request.app.state.auth_semaphore,
            executor=request.app.state.auth_executor,
            wait_cap=getattr(request.app.state, "auth_wait_cap", 10.0),
            username=username, password=password, totp=totp,
            recovery_code=recovery_code, factor_hook=factor_hook,
            vault=request.app.state.vault,
            pepper=settings.pepper_raw,
            ip=ip, peer_ip=peer, budget=request.app.state.ledger_budget,
            counter=request.app.state.failure_counter,
        )
        await session.commit()
    from custos.audit import record_audit

    await record_audit(
        request.app.state.session_maker, actor_kind="operator_session",
        actor_id=str(row.id), actor_label=username, action="operator.login",
        item_name=None, ok=True, detail={},
    )
    set_session_cookie(response, cookie, settings)
    return {"csrf_token": row.csrf_token}


@router.post("/setup")
async def setup(request: Request) -> dict[str, Any]:
    from custos.routes_agent import _json_body

    settings = request.app.state.settings
    body = await _json_body(request)
    username = body.get("username")
    setup_code = body.get("setup_code")
    if not isinstance(username, str) or not isinstance(setup_code, str):
        raise AppError("invalid", "username and setup_code are required")
    body_password = body.get("password")
    env_password = settings.operator_password
    if body_password is not None and env_password is not None:
        raise AppError("invalid", "password given both in body and environment")
    password = body_password if body_password is not None else env_password
    if not isinstance(password, str):
        raise AppError("invalid", "password is required")
    from custos.clientip import resolve_client_ip

    peer = request.client.host if request.client else "unknown"
    xff = ", ".join(request.headers.getlist("x-forwarded-for")) or None
    ip = resolve_client_ip(peer, xff, settings.trusted_proxies)
    async with request.app.state.session_maker() as session:
        # single-shot guard BEFORE any filesystem provisioning: post-setup
        # requests must never recreate the consumed code file
        existing = (
            await session.execute(select(OperatorAccount))
        ).scalar_one_or_none()
        if existing is not None:
            from custos.audit import record_audit

            await record_audit(
                request.app.state.session_maker, actor_kind="anonymous",
                actor_id=None, actor_label="anonymous", action="operator.setup",
                item_name=None, ok=False, detail={"reason": "setup_complete"},
                budget=request.app.state.ledger_budget,
                counter=request.app.state.failure_counter,
            )
            raise AppError("setup_complete", "setup already completed")
        from custos.operator.lockout import check_lockout

        await check_lockout(session, ip=ip, account_exists=False,
                            counter=request.app.state.failure_counter)
        request.app.state.rate_limiter.check_unauth(ip, setup=True)
        try:
            expected = request.app.state.setup_code or ensure_setup_code(settings)
        except OSError:
            raise AppError("internal_error", "setup provisioning unavailable") from None
        session.info["data_dir"] = str(settings.data_dir)
        await setup_account(
            session, request.app.state.session_maker,
            username=username, password=password, setup_code=setup_code,
            expected_code=expected, ip=ip, peer_ip=peer,
            budget=request.app.state.ledger_budget,
            counter=request.app.state.failure_counter,
            semaphore=request.app.state.auth_semaphore,
            executor=request.app.state.auth_executor,
            wait_cap=getattr(request.app.state, "auth_wait_cap", 10.0),
        )
        await session.commit()
    # durable now: consume the code and record success
    request.app.state.setup_code = None
    from pathlib import Path

    from custos.audit import record_audit

    code_path = Path(settings.data_dir) / "setup-code"
    if code_path.exists():
        code_path.unlink()
    await record_audit(
        request.app.state.session_maker, actor_kind="anonymous", actor_id=None,
        actor_label="anonymous", action="operator.setup", item_name=None,
        ok=True, detail={},
    )
    return {"setup": "complete"}
