"""Rate limiter contract (design §5): in-process buckets, single-worker."""

import pytest

from custos.errors import AppError
from custos.ratelimit import RateLimiter


def test_agent_request_bucket() -> None:
    limiter = RateLimiter()
    for _ in range(120):
        limiter.check_agent_request("key1")
    with pytest.raises(AppError) as exc_info:
        limiter.check_agent_request("key1")
    assert exc_info.value.code == "rate_limited"
    assert exc_info.value.headers is not None and "Retry-After" in exc_info.value.headers
    # a different key is unaffected
    limiter.check_agent_request("key2")


def test_agent_concurrency_cap() -> None:
    limiter = RateLimiter()
    for _ in range(8):
        limiter.acquire_agent_slot("key1")
    with pytest.raises(AppError) as exc_info:
        limiter.acquire_agent_slot("key1")
    assert exc_info.value.code == "rate_limited"
    limiter.release_agent_slot("key1")
    limiter.acquire_agent_slot("key1")


def test_failed_auth_gate() -> None:
    limiter = RateLimiter()
    for _ in range(30):
        limiter.check_failed_auth_gate("203.0.113.1")  # not full yet
        limiter.record_failed_auth("203.0.113.1")
    with pytest.raises(AppError) as exc_info:
        limiter.check_failed_auth_gate("203.0.113.1")
    assert exc_info.value.code == "rate_limited"
    limiter.check_failed_auth_gate("203.0.113.2")  # other IP unaffected


def test_failures_table_bounded_under_ip_rotation() -> None:
    limiter = RateLimiter()
    for i in range(5000):
        limiter.record_failed_auth(f"2001:db8::{i:x}")
    assert len(limiter._failures) <= 4096


def test_setup_global_quota_not_burned_by_rejected_ip() -> None:
    limiter = RateLimiter()
    # one IP exhausts its 3/min setup bucket; attempts 4+ are rejected per-IP
    for _ in range(3):
        limiter.check_unauth("203.0.113.1", setup=True)
    import contextlib

    for _ in range(20):
        with contextlib.suppress(AppError):
            limiter.check_unauth("203.0.113.1", setup=True)
    # a different IP must still get its setup attempts (global quota intact)
    limiter.check_unauth("203.0.113.2", setup=True)
