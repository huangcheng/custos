"""Agent-key mint/verify contract (design §5). Fake pepper/secret material only."""

import ast
import inspect
import re
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.crypto import credential_digest
from custos.db.models import AgentKey
from custos.keys import AgentAuthError, mint_agent_key, verify_agent_key

pytestmark = pytest.mark.usefixtures("pg_db")

FAKE_PEPPER = bytes([7]) * 32
TOKEN_RE = re.compile(r"^cu-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$")


@pytest.fixture
async def maker(pg_db: str):
    engine = create_async_engine(pg_db)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def test_minted_token_shape_and_digest() -> None:
    token, draft = mint_agent_key(FAKE_PEPPER)
    assert TOKEN_RE.match(token)
    secret_text = token.split(".", 1)[1]
    assert draft.digest == credential_digest(FAKE_PEPPER, secret_text)
    assert draft.key_id == token[3:15]
    assert not hasattr(draft, "secret")


async def test_verify_ok(maker) -> None:
    token, draft = mint_agent_key(FAKE_PEPPER)
    async with maker() as session:
        session.add(
            AgentKey(key_id=draft.key_id, digest=draft.digest, label="cu-test")
        )
        await session.commit()
    async with maker() as session:
        key = await verify_agent_key(session, FAKE_PEPPER, token)
        assert key.key_id == draft.key_id


async def test_all_failures_identical(maker) -> None:
    token, draft = mint_agent_key(FAKE_PEPPER)
    async with maker() as session:
        session.add(
            AgentKey(key_id=draft.key_id, digest=draft.digest, label="cu-test")
        )
        await session.commit()
    expired_token, expired_draft = mint_agent_key(FAKE_PEPPER)
    async with maker() as session:
        session.add(
            AgentKey(
                key_id=expired_draft.key_id, digest=expired_draft.digest, label="cu-test",
                expires_at=datetime.now(UTC) - timedelta(seconds=1),
            )
        )
        await session.commit()
    unknown_token, _ = mint_agent_key(FAKE_PEPPER)
    wrong_secret = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    messages = []
    for presented in (unknown_token, wrong_secret, expired_token, "garbage"):
        async with maker() as session:
            with pytest.raises(AgentAuthError) as exc_info:
                await verify_agent_key(session, FAKE_PEPPER, presented)
            messages.append(str(exc_info.value))
    assert len(set(messages)) == 1


def test_verify_single_compare_digest_call() -> None:
    source = inspect.getsource(verify_agent_key)
    tree = ast.parse(inspect.cleandoc(source))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "digests_equal"
    ]
    assert len(calls) == 1
