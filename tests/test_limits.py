"""Pure limits + write-body validation contract (design §4/§6)."""

import pytest

from custos.errors import AppError
from custos.limits import (
    FieldView,
    canonical_item_bytes,
    check_caps,
    plan_patch_ops,
    plan_put_ops,
    validate_post_body,
)


def fv(name: str, secret: bool = False, value: str = "v") -> FieldView:
    return FieldView(name=name, secret=secret, value=value)


def test_field_value_cap() -> None:
    check_caps("aliyun", "", [fv("K", value="x" * (16 * 1024))])
    with pytest.raises(AppError) as e:
        check_caps("aliyun", "", [fv("K", value="x" * (16 * 1024 + 1))])
    assert e.value.code == "payload_too_large" and e.value.status == 413


def test_notes_cap_raw_utf8() -> None:
    check_caps("aliyun", "x" * (4 * 1024), [])
    with pytest.raises(AppError):
        check_caps("aliyun", "x" * (4 * 1024 + 1), [])
    # multibyte measured as raw UTF-8 bytes
    with pytest.raises(AppError):
        check_caps("aliyun", "é" * (2 * 1024 + 1), [])


def test_field_count_cap() -> None:
    fields = [fv(f"K{i}") for i in range(32)]
    check_caps("aliyun", "", fields)
    with pytest.raises(AppError):
        check_caps("aliyun", "", [*fields, fv("K32")])


def test_canonical_shape() -> None:
    import json

    blob = canonical_item_bytes("aliyun", "", [fv("B"), fv("A")])
    obj = json.loads(blob)
    assert set(obj) == {"name", "notes", "fields"}
    assert [f["name"] for f in obj["fields"]] == ["A", "B"]  # sorted by name
    assert blob == canonical_item_bytes("aliyun", "", [fv("A"), fv("B")])  # order-free
    assert b" " not in blob  # no whitespace
    assert obj["notes"] == ""  # empty notes counted, not omitted


def test_canonical_ensure_ascii() -> None:
    blob = canonical_item_bytes("aliyun", "é", [])
    assert b"\\u00e9" in blob  # escaped form counted


def test_item_total_cap_escaped() -> None:
    # 16 fields x 16 KiB of 'é' escapes to 6 bytes/char -> way over 256 KiB
    fields = [fv(f"K{i}", value="é" * 8192) for i in range(16)]
    with pytest.raises(AppError):
        check_caps("aliyun", "", fields)


def test_post_requires_name() -> None:
    with pytest.raises(AppError) as e:
        validate_post_body({"fields": []})
    assert e.value.code == "invalid"


def test_post_secret_requires_value() -> None:
    with pytest.raises(AppError):
        validate_post_body({"name": "aliyun", "fields": [{"name": "K", "secret": True}]})


def test_put_name_must_match_or_absent() -> None:
    with pytest.raises(AppError):
        plan_put_ops("aliyun", {"name": "other", "notes": "", "fields": []}, existing={})
    plan_put_ops("aliyun", {"notes": "", "fields": []}, existing={})


def test_put_requires_notes() -> None:
    with pytest.raises(AppError):
        plan_put_ops("aliyun", {"fields": []}, existing={})


def test_patch_keep_secret_roundtrip() -> None:
    existing = {"K": fv("K", secret=True, value="sealed")}
    ops = plan_patch_ops({"fields": [{"name": "K", "secret": True}]}, existing=existing)
    assert ops[0].kind == "keep"


def test_patch_noop_entry() -> None:
    existing = {"K": fv("K")}
    ops = plan_patch_ops({"fields": [{"name": "K"}]}, existing=existing)
    assert ops[0].kind == "keep"


def test_patch_omission_on_plain_or_new_rejected() -> None:
    with pytest.raises(AppError):
        plan_patch_ops({"fields": [{"name": "K", "secret": True}]}, existing={"K": fv("K")})
    with pytest.raises(AppError):
        plan_patch_ops({"fields": [{"name": "NEW", "secret": True}]}, existing={})


def test_patch_duplicate_outside_pair_rejected() -> None:
    with pytest.raises(AppError):
        plan_patch_ops(
            {"fields": [{"name": "K", "value": "a"}, {"name": "K", "value": "b"}]},
            existing={},
        )


def test_patch_single_entry_flag_flip_rejected() -> None:
    with pytest.raises(AppError):
        plan_patch_ops(
            {"fields": [{"name": "K", "secret": True, "value": "x"}]},
            existing={"K": fv("K")},
        )


def test_patch_downgrade_pair_denied_atomically() -> None:
    from custos.limits import DowngradeError

    with pytest.raises(DowngradeError):
        plan_patch_ops(
            {"fields": [
                {"name": "K", "value": None},
                {"name": "K", "secret": False, "value": "x"},
            ]},
            existing={"K": fv("K", secret=True, value="sealed")},
        )


def test_patch_upgrade_pair_allowed() -> None:
    ops = plan_patch_ops(
        {"fields": [
            {"name": "K", "value": None},
            {"name": "K", "secret": True, "value": "x"},
        ]},
        existing={"K": fv("K")},
    )
    assert [o.kind for o in ops] == ["remove", "set"]


def test_put_downgrade_denied() -> None:
    from custos.limits import DowngradeError

    with pytest.raises(DowngradeError):
        plan_put_ops(
            "aliyun",
            {"notes": "", "fields": [{"name": "K", "secret": False, "value": "x"}]},
            existing={"K": fv("K", secret=True, value="sealed")},
        )


def test_patch_name_must_match_or_absent() -> None:
    with pytest.raises(AppError):
        plan_patch_ops({"name": "other", "fields": []}, existing={}, path_name="aliyun")
    plan_patch_ops({"name": "aliyun", "fields": []}, existing={}, path_name="aliyun")


def test_non_bool_secret_rejected() -> None:
    with pytest.raises(AppError):
        plan_patch_ops({"fields": [{"name": "K", "secret": 0, "value": "x"}]}, existing={})
    with pytest.raises(AppError):
        plan_patch_ops(
            {"fields": [{"name": "K", "secret": 1}]},
            existing={"K": fv("K", secret=True)},
        )


def test_notes_nul_and_surrogates_rejected() -> None:
    with pytest.raises(AppError):
        validate_post_body({"name": "aliyun", "notes": "a\x00b", "fields": []})
    with pytest.raises(AppError):
        validate_post_body({"name": "aliyun", "notes": "\ud800", "fields": []})
    with pytest.raises(AppError):
        validate_post_body(
            {"name": "aliyun", "fields": [{"name": "K", "secret": False, "value": "\ud800"}]}
        )


def test_names_reject_trailing_newline() -> None:
    with pytest.raises(AppError):
        validate_post_body({"name": "aliyun\n", "fields": []})
    with pytest.raises(AppError):
        validate_post_body(
            {"name": "aliyun", "fields": [{"name": "K\n", "secret": False, "value": "v"}]}
        )


def test_pair_second_entry_must_be_add() -> None:
    with pytest.raises(AppError):
        plan_patch_ops(
            {"fields": [{"name": "K", "value": None}, {"name": "K", "value": None}]},
            existing={"K": fv("K")},
        )
