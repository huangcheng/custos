"""Cursor contract: round-trip, binding, TTL, tamper."""

import time

import pytest

from custos.cursors import mint_cursor, read_cursor
from custos.errors import AppError

PEPPER = bytes([7]) * 32


def test_roundtrip_preserves_payload() -> None:
    token = mint_cursor({"after": "page-49"}, PEPPER, "list", "abcdef012345")
    assert read_cursor(token, PEPPER, "list", "abcdef012345") == {"after": "page-49"}


def test_foreign_principal_endpoint_rejected() -> None:
    token = mint_cursor({"after": "x"}, PEPPER, "list", "abcdef012345")
    with pytest.raises(AppError):
        read_cursor(token, PEPPER, "search", "abcdef012345")
    with pytest.raises(AppError):
        read_cursor(token, PEPPER, "list", "ffffff000000")
    with pytest.raises(AppError):
        read_cursor(token, bytes([8]) * 32, "list", "abcdef012345")


def test_tampered_and_garbage_rejected() -> None:
    for bad in ("garbage", "a.b", "....", "e30=.AAAA"):
        with pytest.raises(AppError) as e:
            read_cursor(bad, PEPPER, "list", "abcdef012345")
        assert e.value.code == "invalid"


def test_expired_rejected(monkeypatch) -> None:
    token = mint_cursor({"after": "x"}, PEPPER, "list", "abcdef012345")
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 1000)
    with pytest.raises(AppError):
        read_cursor(token, PEPPER, "list", "abcdef012345")


def test_oversize_cursor_rejected() -> None:
    with pytest.raises(AppError):
        read_cursor("A" * 5000, PEPPER, "list", "abcdef012345")
