"""E2E scaffolding: seed agent keys directly into the throwaway DB.

Pre-operator-auth only (plan 1). Plan 2 replaces this with the real setup +
key-mint flow. Prints tokens as JSON to stdout — for the throwaway E2E
vault only, never a real deployment.
"""

import asyncio
import json

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.config import load_settings
from custos.db.models import AgentKey
from custos.keys import mint_agent_key


async def main() -> None:
    settings = load_settings()
    engine = create_async_engine(settings.database_url)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tokens = {}
    for name, mode, scopes in [
        ("rw", "read-write", ["*"]),
        ("ro", "read", ["*"]),
        ("scoped", "read-write", ["stock-*"]),
    ]:
        token, draft = mint_agent_key(settings.pepper_raw)
        async with maker() as session:
            session.add(
                AgentKey(
                    key_id=draft.key_id, digest=draft.digest, label=f"e2e-{name}",
                    mode=mode, scopes=scopes,
                )
            )
            await session.commit()
        tokens[name] = token
    await engine.dispose()
    print(json.dumps(tokens))


asyncio.run(main())
