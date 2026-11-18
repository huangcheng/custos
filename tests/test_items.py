"""Item write engine contract (design §4/§6) against real postgres."""

import asyncio
from dataclasses import dataclass, field

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from custos.crypto import Vault, parse_keyring
from custos.db.models import Field, FieldHistory, Item
from custos.errors import AppError
from custos.items import (
    create_item,
    force_drop,
    get_item,
    patch_item,
    put_item,
    soft_delete,
)
from tests.test_config import FAKE_KEYRING

pytestmark = pytest.mark.usefixtures("pg_db")


@dataclass
class Principal:
    actor_id: str = "abcdef012345"
    actor_label: str = "cu-test"
    mode: str = "read-write"
    scopes: list[str] = field(default_factory=lambda: ["*"])


@pytest.fixture
async def env(pg_db: str):
    engine = create_async_engine(pg_db)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    vault = Vault(parse_keyring(FAKE_KEYRING))
    yield maker, vault, Principal()
    await engine.dispose()


def body(name: str | None = None, notes: str = "", fields: list | None = None) -> dict:
    b: dict = {"notes": notes, "fields": fields or []}
    if name is not None:
        b["name"] = name
    return b


async def test_create_and_get(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        item = await create_item(
            s, maker, vault, p,
            body("engine-aliyun", "note", [{"name": "KEY", "secret": True, "value": "sk-fake"}]),
        )
        await s.commit()
    async with maker() as s:
        got = await get_item(s, maker, vault, p, "engine-aliyun")
        assert got["fields"][0]["value"] == "sk-fake"
        assert got["revision"] == item["revision"]


async def test_out_of_scope_identical_404(env) -> None:
    maker, vault, p = env
    p.scopes = ["other-*"]
    async with maker() as s:
        with pytest.raises(AppError) as e1:
            await get_item(s, maker, vault, p, "missing-item")
        await create_item(s, maker, vault, Principal(), body("scoped-item"))
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError) as e2:
            await get_item(s, maker, vault, p, "scoped-item")
    assert (e1.value.code, e1.value.message) == (e2.value.code, e2.value.message)


async def test_read_only_write_403(env) -> None:
    maker, vault, p = env
    p.mode = "read"
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await create_item(s, maker, vault, p, body("ro-item"))
        assert e.value.code == "read_only"


async def test_put_history_and_keep_placeholder(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("put-item", fields=[
                {"name": "A", "secret": True, "value": "old-secret"},
                {"name": "B", "secret": False, "value": "old-plain"},
            ]),
        )
        await s.commit()
    async with maker() as s:
        resp = await put_item(
            s, maker, vault, p, "put-item",
            body(notes="", fields=[
                {"name": "A", "secret": True},  # keep
                {"name": "B", "secret": False, "value": "new-plain"},
            ]),
        )
        await s.commit()
    assert {"name": "A", "secret": True, "kept": True} in resp["fields"]
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "put-item"))).scalar_one()
        hist = (
            (await s.execute(select(FieldHistory).where(FieldHistory.item_id == item.id)))
            .scalars().all()
        )
        assert [h.name for h in hist] == ["B"]  # only actual change snapshotted
        assert hist[0].value == "old-plain"


async def test_identical_resend_no_history(env) -> None:
    maker, vault, p = env
    fields = [{"name": "K", "secret": False, "value": "same"}]
    async with maker() as s:
        await create_item(s, maker, vault, p, body("noop-item", fields=fields))
        await s.commit()
    async with maker() as s:
        await put_item(s, maker, vault, p, "noop-item", body(fields=fields))
        await s.commit()
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "noop-item"))).scalar_one()
        hist = (
            (await s.execute(select(FieldHistory).where(FieldHistory.item_id == item.id)))
            .scalars().all()
        )
        assert hist == []


async def test_history_budget_20(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("budget-item", fields=[{"name": "K", "secret": False, "value": "v0"}]),
        )
        await s.commit()
    for i in range(1, 22):
        async with maker() as s:
            await put_item(
                s, maker, vault, p, "budget-item",
                body(fields=[{"name": "K", "secret": False, "value": f"v{i}"}]),
            )
            await s.commit()
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "budget-item"))).scalar_one()
        hist = (
            (await s.execute(select(FieldHistory).where(FieldHistory.item_id == item.id)))
            .scalars().all()
        )
        assert len(hist) == 20
        assert "v0" not in [h.value for h in hist]  # oldest evicted
        assert "v1" in [h.value for h in hist]


async def test_if_match(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(s, maker, vault, p, body("etag-item"))
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await put_item(s, maker, vault, p, "etag-item", body(), if_match='"99"')
        assert e.value.code == "conflict"
        await s.rollback()
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await put_item(s, maker, vault, p, "etag-item", body(), if_match="99")
        assert e.value.code == "invalid"
        await s.rollback()
    async with maker() as s:
        resp = await put_item(s, maker, vault, p, "etag-item", body(), if_match='"1"')
        await s.commit()
        assert resp["revision"] == 2


async def test_concurrent_puts_serialized(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("race-item", fields=[{"name": "K", "secret": False, "value": "v0"}]),
        )
        await s.commit()

    async def writer(value: str) -> None:
        async with maker() as s:
            await put_item(
                s, maker, vault, p, "race-item",
                body(fields=[{"name": "K", "secret": False, "value": value}]),
            )
            await s.commit()

    await asyncio.gather(writer("v1"), writer("v2"))
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "race-item"))).scalar_one()
        assert item.revision == 3
        hist = (
            (await s.execute(select(FieldHistory).where(FieldHistory.item_id == item.id)))
            .scalars().all()
        )
        assert len(hist) == 2  # both priors snapshotted, none lost


async def test_soft_delete_matrix(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(s, maker, vault, p, body("del-item"))
        await s.commit()
    async with maker() as s:
        await soft_delete(s, maker, vault, p, "del-item")
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await get_item(s, maker, vault, p, "del-item")
        assert e.value.code == "not_found"
        with pytest.raises(AppError) as e:
            await put_item(s, maker, vault, p, "del-item", body(), upsert=True)
        assert e.value.code == "conflict"
        await s.rollback()
    ro = Principal(mode="read")
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await put_item(s, maker, vault, ro, "del-item", body())
        assert e.value.code == "read_only"  # mode before existence


async def test_retype_pair_history_oracle(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("retype-item", fields=[{"name": "K", "secret": False, "value": "plain-v"}]),
        )
        await s.commit()
    async with maker() as s:
        await patch_item(
            s, maker, vault, p, "retype-item",
            {"fields": [
                {"name": "K", "value": None},
                {"name": "K", "secret": True, "value": "plain-v"},
            ]},
        )
        await s.commit()
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "retype-item"))).scalar_one()
        hist = (
            (await s.execute(select(FieldHistory).where(FieldHistory.item_id == item.id)))
            .scalars().all()
        )
        assert len(hist) == 1 and hist[0].secret is False and hist[0].value == "plain-v"
        live = (
            (await s.execute(select(Field).where(Field.item_id == item.id)))
            .scalars().all()
        )
        assert live[0].secret is True
        opened = vault.open("field", str(live[0].id), live[0].ciphertext, live[0].key_version)
        assert opened == b"plain-v"


async def test_downgrade_atomic(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("dg-item", fields=[
                {"name": "S", "secret": True, "value": "sealed"},
                {"name": "P", "secret": False, "value": "old"},
            ]),
        )
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError) as dg:
            await patch_item(
                s, maker, vault, p, "dg-item",
                {"fields": [
                    {"name": "P", "secret": False, "value": "new"},
                    {"name": "S", "value": None},
                    {"name": "S", "secret": False, "value": "x"},
                ]},
            )
        assert dg.value.code == "secret_downgrade_denied"
        await s.rollback()
    async with maker() as s:
        got = await get_item(s, maker, vault, p, "dg-item")
        values = {f["name"]: f.get("value") for f in got["fields"]}
        assert values == {"S": "sealed", "P": "old"}  # nothing partially applied


async def test_degraded_mode_and_force_drop(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("corrupt-item", fields=[
                {"name": "BAD", "secret": True, "value": "will-corrupt"},
                {"name": "GOOD", "secret": True, "value": "readable"},
            ]),
        )
        await s.commit()
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "corrupt-item"))).scalar_one()
        bad = (
            await s.execute(
                select(Field).where(Field.item_id == item.id, Field.name == "BAD")
            )
        ).scalar_one()
        bad.ciphertext = bad.ciphertext[:-1] + bytes([bad.ciphertext[-1] ^ 0xFF])
        await s.commit()
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await get_item(s, maker, vault, p, "corrupt-item")
        assert e.value.code == "key_unavailable"
        await s.rollback()
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await patch_item(s, maker, vault, p, "corrupt-item", {"notes": "x"})
        assert e.value.code == "key_unavailable"
        await s.rollback()
    async with maker() as s:
        await soft_delete(s, maker, vault, p, "corrupt-item")  # metadata-only succeeds
        await s.commit()
    async with maker() as s:
        dropped = await force_drop(s, maker, vault, p, "corrupt-item", actor_kind="local_process")
        await s.commit()
        assert dropped == 1
    async with maker() as s:
        # restore deleted_at manually (restore endpoint is plan 2); item writable again
        item = (await s.execute(select(Item).where(Item.name == "corrupt-item"))).scalar_one()
        item.deleted_at = None
        await s.commit()
    async with maker() as s:
        got = await get_item(s, maker, vault, p, "corrupt-item")
        assert [f["name"] for f in got["fields"]] == ["GOOD"]
        await patch_item(s, maker, vault, p, "corrupt-item", {"notes": "fixed"})
        await s.commit()


async def test_concurrent_creates_one_conflict(env) -> None:
    maker, vault, p = env

    async def creator() -> str:
        try:
            async with maker() as s:
                await create_item(s, maker, vault, p, body("race-create"))
                await s.commit()
            return "created"
        except AppError as e:
            return e.code

    results = await asyncio.gather(creator(), creator())
    assert sorted(results) == ["conflict", "created"]


async def test_patch_notes_null_clears(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(s, maker, vault, p, body("notes-item", "keep-me"))
        await s.commit()
    async with maker() as s:
        resp = await patch_item(s, maker, vault, p, "notes-item", {"notes": None})
        await s.commit()
        assert resp["notes"] == ""
    async with maker() as s:
        resp = await patch_item(s, maker, vault, p, "notes-item", {})
        assert resp["notes"] == ""  # absent keeps


async def test_if_match_star_requires_exists(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await put_item(s, maker, vault, p, "star-item", body(), if_match='"*"', upsert=True)
        assert e.value.code == "conflict"
        await s.rollback()
    async with maker() as s:
        await create_item(s, maker, vault, p, body("star-item"))
        await s.commit()
    async with maker() as s:
        resp = await put_item(s, maker, vault, p, "star-item", body(), if_match='"*"')
        await s.commit()
        assert resp["revision"] == 2


async def test_upsert_create_validates_put_body(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        with pytest.raises(AppError) as e:
            # notes missing: PUT-shaped body must 422 even on the create branch
            await put_item(
                s, maker, vault, p, "upsert-bad",
                {"fields": [{"name": "K", "secret": False, "value": "v"}]},
                upsert=True,
            )
        assert e.value.code == "invalid"


async def test_keep_plain_noop_response_has_value(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("keep-plain", fields=[{"name": "K", "secret": False, "value": "pv"}]),
        )
        await s.commit()
    async with maker() as s:
        resp = await patch_item(s, maker, vault, p, "keep-plain", {"fields": [{"name": "K"}]})
        await s.commit()
        entry = resp["fields"][0]
        assert entry.get("value") == "pv" and "kept" not in entry


async def test_create_gates_before_body_validation(env) -> None:
    maker, vault, p = env
    p.scopes = ["other-*"]
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await create_item(
                s, maker, vault, p, {"name": "some-item", "fields": "not-a-list"}
            )
        assert e.value.code == "not_found"  # scope gate first, not 422
    ro = Principal(mode="read")
    async with maker() as s:
        with pytest.raises(AppError) as e:
            await create_item(s, maker, vault, ro, {"name": "valid-name", "fields": "bad"})
        assert e.value.code == "read_only"


async def test_force_drop_bumps_revision(env) -> None:
    maker, vault, p = env
    async with maker() as s:
        await create_item(
            s, maker, vault, p,
            body("fd-rev", fields=[{"name": "BAD", "secret": True, "value": "x"}]),
        )
        await s.commit()
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "fd-rev"))).scalar_one()
        f = (await s.execute(select(Field).where(Field.item_id == item.id))).scalar_one()
        f.ciphertext = f.ciphertext[:-1] + bytes([f.ciphertext[-1] ^ 0xFF])
        await s.commit()
    async with maker() as s:
        await force_drop(s, maker, vault, p, "fd-rev", actor_kind="local_process")
        await s.commit()
    async with maker() as s:
        item = (await s.execute(select(Item).where(Item.name == "fd-rev"))).scalar_one()
        assert item.revision == 2
