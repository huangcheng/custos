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
