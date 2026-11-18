"""XFF resolution contract (§5)."""

import ipaddress

from custos.clientip import resolve_client_ip

PROXIES = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.1/32")]


def test_unset_ignores_forwarded() -> None:
    assert resolve_client_ip("10.0.0.1", "1.2.3.4", []) == "10.0.0.1"


def test_untrusted_peer_ignores_forwarded() -> None:
    assert resolve_client_ip("203.0.113.9", "1.2.3.4", PROXIES) == "203.0.113.9"


def test_right_to_left_first_untrusted() -> None:
    assert resolve_client_ip("10.0.0.1", "9.9.9.9, 203.0.113.5, 10.1.2.3", PROXIES) == "203.0.113.5"


def test_spoofed_left_entries_ignored() -> None:
    # attacker prepends fake hops; the rightmost untrusted wins
    assert resolve_client_ip("127.0.0.1", "1.1.1.1, 203.0.113.7", PROXIES) == "203.0.113.7"


def test_all_trusted_falls_back_to_peer() -> None:
    assert resolve_client_ip("10.0.0.1", "10.1.1.1, 10.2.2.2", PROXIES) == "10.0.0.1"


def test_malformed_chain_falls_back() -> None:
    assert resolve_client_ip("10.0.0.1", "not-an-ip", PROXIES) == "10.0.0.1"


def test_ipv4_mapped_ipv6_peer() -> None:
    assert resolve_client_ip("::ffff:10.0.0.5", "203.0.113.8", PROXIES) == "203.0.113.8"


def test_canonical_hop_returned() -> None:
    assert resolve_client_ip("10.0.0.1", "::ffff:203.0.113.9", PROXIES) == "203.0.113.9"
