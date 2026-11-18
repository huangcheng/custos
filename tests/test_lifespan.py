"""App lifespan: migrations on start, version assertion when skipped (§10)."""


import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.app import create_app
from custos.config import load_settings
from tests.test_config import env


async def test_skip_migrate_asserts_head(pg_db: str) -> None:
    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        assert app.state.session_maker is not None


async def test_skip_migrate_rejects_stale_schema(pg_db: str) -> None:
    engine = create_async_engine(pg_db)
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE alembic_version SET version_num = '0000'"))
    await engine.dispose()
    try:
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))
        app = create_app(settings)
        with pytest.raises(RuntimeError, match="schema version"):
            async with app.router.lifespan_context(app):
                pass
    finally:
        engine = create_async_engine(pg_db)
        async with engine.begin() as conn:
            await conn.execute(text("UPDATE alembic_version SET version_num = '0001'"))
        await engine.dispose()


async def test_default_startup_runs_migrations(pg_db: str) -> None:
    # alembic upgrade head is idempotent — exercises the real subprocess path
    settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db))
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        assert app.state.session_maker is not None


async def test_skip_migrate_missing_version_table(pg_db: str) -> None:
    engine = create_async_engine(pg_db)
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE alembic_version RENAME TO alembic_version_bak"))
    await engine.dispose()
    try:
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))
        app = create_app(settings)
        with pytest.raises(RuntimeError, match="schema version"):
            async with app.router.lifespan_context(app):
                pass
    finally:
        engine = create_async_engine(pg_db)
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE alembic_version_bak RENAME TO alembic_version"))
        await engine.dispose()


def test_head_revisions_excludes_superseded(tmp_path, monkeypatch) -> None:
    import custos.app as app_module

    versions = tmp_path / "alembic" / "versions"
    versions.mkdir(parents=True)
    (versions / "0001_a.py").write_text('revision = "0001"\ndown_revision = None\n')
    (versions / "0002_b.py").write_text('revision: str = "0002"\ndown_revision = "0001"\n')
    monkeypatch.setattr(app_module, "_REPO_ROOT", tmp_path)
    assert app_module._head_revisions() == {"0002"}


async def test_skip_migrate_rejects_partial_heads(pg_db: str) -> None:
    engine = create_async_engine(pg_db)
    async with engine.begin() as conn:
        await conn.execute(text("INSERT INTO alembic_version VALUES ('0000')"))
    await engine.dispose()
    try:
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))
        app = create_app(settings)
        with pytest.raises(RuntimeError, match="schema version"):
            async with app.router.lifespan_context(app):
                pass
    finally:
        engine = create_async_engine(pg_db)
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM alembic_version WHERE version_num = '0000'"))
        await engine.dispose()


def test_head_revisions_multiline_merge_tuple(tmp_path, monkeypatch) -> None:
    import custos.app as app_module

    versions = tmp_path / "alembic" / "versions"
    versions.mkdir(parents=True)
    (versions / "0001_a.py").write_text('revision = "0001"\ndown_revision = None\n')
    (versions / "0002_b.py").write_text('revision = "0002"\ndown_revision = None\n')
    (versions / "0003_m.py").write_text(
        'revision = "0003"\ndown_revision = (\n    "0001",\n    "0002",\n)\n'
    )
    monkeypatch.setattr(app_module, "_REPO_ROOT", tmp_path)
    assert app_module._head_revisions() == {"0003"}


async def test_file_form_deployment_migrates(pg_db: str, tmp_path, monkeypatch) -> None:
    dsn_file = tmp_path / "dsn.txt"
    dsn_file.write_text(pg_db)
    dsn_file.chmod(0o600)
    # real file-form deployment: the variable lives in the process environment
    monkeypatch.setenv("CUSTOS_DATABASE_URL_FILE", str(dsn_file))
    monkeypatch.delenv("CUSTOS_DATABASE_URL", raising=False)
    base = env()
    base.pop("CUSTOS_DATABASE_URL")
    settings = load_settings({**base, "CUSTOS_DATABASE_URL_FILE": str(dsn_file)})
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        assert app.state.session_maker is not None


async def test_startup_refuses_missing_key_version(pg_db: str) -> None:
    from sqlalchemy.ext.asyncio import create_async_engine as _cae

    from custos.db.models import Field, Item

    engine = _cae(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    import uuid as _uuid

    async with maker() as s:
        item = Item(name="kv-missing", notes="")
        s.add(item)
        await s.flush()
        s.add(Field(id=_uuid.uuid4(), item_id=item.id, name="K", secret=True,
                    ciphertext=b"x" * 40, key_version=99))
        await s.commit()
    await engine.dispose()
    try:
        settings = load_settings(env(CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1"))
        app = create_app(settings)
        with pytest.raises(RuntimeError, match="key version"):
            async with app.router.lifespan_context(app):
                pass
        # degraded escape works
        settings2 = load_settings(env(
            CUSTOS_DATABASE_URL=pg_db, CUSTOS_SKIP_MIGRATE="1",
            CUSTOS_ALLOW_MISSING_KEY_VERSION="1"))
        app2 = create_app(settings2)
        async with app2.router.lifespan_context(app2):
            pass
    finally:
        engine = _cae(pg_db)
        async with engine.begin() as conn:
            from sqlalchemy import text as _t
            await conn.execute(_t("DELETE FROM fields WHERE key_version=99"))
            await conn.execute(_t("DELETE FROM items WHERE name='kv-missing'"))
        await engine.dispose()
