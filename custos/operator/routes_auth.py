"""Operator auth routes (design §5/§6). Grows task by task."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select

from custos.db.models import OperatorAccount, OperatorSession
from custos.errors import AppError
from custos.operator.account import ensure_setup_code, setup_account
from custos.operator.sessions import COOKIE_NAME, require_session

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
        "passkey_available": False,
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
    async with request.app.state.session_maker() as session:
        row, cookie = await login(
            session, request.app.state.session_maker,
            semaphore=request.app.state.auth_semaphore,
            executor=request.app.state.auth_executor,
            wait_cap=getattr(request.app.state, "auth_wait_cap", 10.0),
            username=username, password=password, totp=totp,
            recovery_code=recovery_code, factor_hook=factor_hook,
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
