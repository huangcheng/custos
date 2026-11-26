"""Name grammar (rev 45): item names accept Han ideographs; usernames do not."""

import importlib.util
from pathlib import Path

from custos.limits import valid_item_name, valid_username
from custos.names import ITEM_NAME_PATTERN


def test_item_names_accept_cjk() -> None:
    assert valid_item_name("密钥配置") == "密钥配置"
    assert valid_item_name("阿里云-百炼") == "阿里云-百炼"
    assert valid_item_name("dashscope-百炼.v2") == "dashscope-百炼.v2"
    assert valid_item_name("㐀") == "㐀"  # Ext A boundary
    assert valid_item_name("鿿") == "鿿"  # Unified boundary


def test_item_names_reject_outside_grammar() -> None:
    for bad in (
        "BadName",  # uppercase ASCII
        "bad name",  # space
        "密钥 配置",  # space between ideographs
        "密钥🚀",  # emoji
        "-leading-dash",
        "a/b",
        "",
    ):
        assert valid_item_name(bad) is None, bad


def test_usernames_stay_ascii() -> None:
    assert valid_username("operator") == "operator"
    assert valid_username("op.erator-1") == "op.erator-1"
    assert valid_username("操作员") is None
    assert valid_username("Operator") is None


def test_migration_pattern_matches_the_shared_grammar() -> None:
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0004_cjk_item_names.py"
    spec = importlib.util.spec_from_file_location("migration_0004", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.NAME_PATTERN == ITEM_NAME_PATTERN
