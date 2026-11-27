"""Item-name grammar (rev 48): display labels, structural rules only."""

import importlib.util
from pathlib import Path

from custos.limits import valid_item_name, valid_username
from custos.names import ITEM_NAME_MAX, ITEM_NAME_SQL_PATTERN


def test_item_names_are_free_display_labels() -> None:
    for good in (
        "Google Map",
        "googlemap",
        "谷歌地图",
        "密钥配置",
        "阿里云-百炼",
        "dashscope-百炼.v2",
        "O'Brien's Keys",
        "AWS Prod (eu-west-1)",
        "v1.2.3",
        "a b  c",
        "🚀 rocket",
        "密钥　配置",  # U+3000 ideographic space is visible text
        "word\u00a0word",  # NBSP pasted from a document
        "x" * ITEM_NAME_MAX,
    ):
        assert valid_item_name(good) == good, good


def test_item_names_reject_unaddressable_or_invisible() -> None:
    for bad in (
        "",  # empty
        " ",  # blank
        " x",  # leading space
        "x ",  # trailing space
        "x\ny",  # control character
        "x\ty",  # tab
        "x\u200by",  # zero-width space (format character)
        "x\u2028y",  # line separator (Zl)
        "x/y",  # path separator
        "x\\y",  # path separator
        ".",  # dot segment: unaddressable after URL normalisation
        "..",
        "x" * (ITEM_NAME_MAX + 1),
    ):
        assert valid_item_name(bad) is None, repr(bad)


def test_usernames_stay_ascii() -> None:
    assert valid_username("operator") == "operator"
    assert valid_username("op.erator-1") == "op.erator-1"
    assert valid_username("操作员") is None
    assert valid_username("Operator") is None


def test_migration_pattern_matches_the_shared_grammar() -> None:
    path = Path(__file__).resolve().parents[1] / "alembic/versions/0005_wide_item_names.py"
    spec = importlib.util.spec_from_file_location("migration_0005", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.NAME_PATTERN == ITEM_NAME_SQL_PATTERN
    assert f"'{ITEM_NAME_SQL_PATTERN}'" in module.NAME_CHECK
    assert "NOT IN ('.', '..')" in module.NAME_CHECK
