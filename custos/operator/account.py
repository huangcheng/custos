"""Operator account store + one-shot setup (design §5).

Argon2id parameters pinned for byte-compatibility with the Rust CLI's
break-glass writer: v0x13, m=65536 KiB, t=3, p=4, salt 16B, hash 32B.
The setup code is the gate (Turnstile-exempt); failures feed lockout.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from custos.audit import FailureCounter, LedgerBudget, record_audit, record_auth_event
from custos.config import MIN_PASSWORD_LEN, Settings
from custos.crypto import digests_equal
from custos.db.models import OperatorAccount
from custos.errors import AppError
from custos.limits import valid_item_name

_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)



def hash_password(password: str) -> str:
    return _HASHER.hash(password)


def verify_password(phc: str, password: str) -> bool:
    try:
        return _HASHER.verify(phc, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise AppError("invalid", f"password must be at least {MIN_PASSWORD_LEN} characters")


def _read_code_file(path: Path) -> str:
    """Same contract as config._secret_file: regular file, no symlink,
    nonblocking, mode 0600/0400 — the bootstrap credential must never come
    from a loose-mode or planted file (§5/§12)."""
    from custos.config import ConfigError

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise ConfigError(f"setup-code file cannot be opened: {reason}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError("setup-code path is not a regular file")
        if stat.S_IMODE(st.st_mode) not in (0o600, 0o400):
            raise ConfigError("setup-code file must be mode 0600 or 0400")
        try:
            with os.fdopen(fd, encoding="utf-8") as handle:
                fd = -1
                code = handle.read()
        except UnicodeDecodeError as exc:
            raise ConfigError("setup-code file is not valid UTF-8") from exc
        except OSError as exc:
            raise ConfigError("setup-code file cannot be read") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    code = code.strip()
    if len(code) < 22:
        # empty/short file (crash between create and write, stray mount):
        # fail closed — an empty compare_digest match must never gate setup
        raise ConfigError("setup-code file is empty or too short; remove it to regenerate")
    return code


def _refuse_loose_data_dir(data_dir: Path) -> None:
    """A group/other-writable data dir lets a local user plant or replace the
    setup-code file; refuse reuse instead of trusting whatever it contains."""
    from custos.config import ConfigError

    if stat.S_IMODE(data_dir.stat().st_mode) & 0o022:
        raise ConfigError(
            "data directory is group/other-writable; tighten it to 0700 "
            "before the setup-code file can be trusted"
        )


def ensure_setup_code(settings: Settings) -> str:
    """Env code wins; else a generated 0600 file, reused across restarts."""
    if settings.setup_code:
        return settings.setup_code
    path = Path(settings.data_dir) / "setup-code"
    if path.exists():
        _refuse_loose_data_dir(Path(settings.data_dir))
        return _read_code_file(path)
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkdir(exist_ok=True) leaves a pre-existing dir's mode untouched — refuse
    # a plantable data dir on the provisioning path too, before linking a code
    _refuse_loose_data_dir(Path(settings.data_dir))
    code = secrets.token_urlsafe(24)  # >=128-bit
    # atomic publish: random temp file + link — readers never observe a
    # half-written code; a failed write leaks nothing (finally unlinks)
    tmp = path.with_name(f".setup-code.{secrets.token_hex(8)}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(code + "\n")
        os.link(tmp, path)  # atomic; fails if a rival published first
    except FileExistsError:
        _refuse_loose_data_dir(Path(settings.data_dir))
        return _read_code_file(path)
    finally:
        tmp.unlink(missing_ok=True)
    return code


async def setup_account(
    session: AsyncSession,
    maker: async_sessionmaker[AsyncSession],
    *,
    username: str,
    password: str,
    setup_code: str,
    expected_code: str,
    ip: str,
    peer_ip: str,
    budget: LedgerBudget | None = None,
    counter: FailureCounter | None = None,
    semaphore: Any = None,
    executor: Any = None,
    wait_cap: float = 10.0,
) -> None:
    existing = (
        await session.execute(select(OperatorAccount))
    ).scalar_one_or_none()
    if existing is not None:
        await record_audit(
            maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
            action="operator.setup", item_name=None, ok=False,
            detail={"reason": "setup_complete"},
        )
        raise AppError("setup_complete", "setup already completed")
    if valid_item_name(username) is None:
        raise AppError("invalid", "invalid username")
    validate_password(password)
    try:
        presented_bytes = setup_code.encode()
        password.encode("utf-8")  # probe: lone surrogates must 422, not 500 in to_thread
    except UnicodeEncodeError:
        raise AppError("invalid", "inputs must be valid UTF-8") from None
    if not digests_equal(presented_bytes, expected_code.encode()):
        await record_auth_event(
            maker, kind="setup", ok=False, ip=ip, peer_ip=peer_ip,
            budget=budget, counter=counter,
        )
        await record_audit(
            maker, actor_kind="anonymous", actor_id=None, actor_label="anonymous",
            action="auth.failure", item_name=None, ok=False,
            detail={"ip": ip, "reason": "setup"},
            budget=budget, counter=counter,
        )
        raise AppError("unauthorized", "authentication failed")
    import asyncio

    loop = asyncio.get_running_loop()
    if semaphore is not None:
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=wait_cap)
        except TimeoutError:
            raise AppError("rate_limited", "authentication busy",
                           headers={"Retry-After": "1"}) from None
    try:
        if executor is not None:
            phc = await loop.run_in_executor(executor, hash_password, password)
        else:
            phc = await asyncio.to_thread(hash_password, password)
    finally:
        if semaphore is not None:
            semaphore.release()
    session.add(OperatorAccount(id=1, username=username, password_hash=phc))
    try:
        await session.flush()
    except IntegrityError:
        raise AppError("setup_complete", "setup already completed") from None
    # the success audit commits WITH the account row (route's transaction);
    # code consumption happens AFTER the route commits — a failed commit
    # must leave the code usable for a retry
