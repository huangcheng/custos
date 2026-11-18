"""Client IP resolution (design §5): trusted-proxy XFF walking.

Forwarded headers are honored ONLY when the direct peer is inside
CUSTOS_TRUSTED_PROXIES; then walk X-Forwarded-For right-to-left skipping
trusted hops — first untrusted address wins. All-trusted chain falls back
to the direct peer. Unset allowlist = ignore forwarded headers entirely.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) compares against IPv4 networks
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _trusted(addr: str, networks: Sequence[Network]) -> bool:
    ip = _parse(addr)
    if ip is None:
        return False
    return any(ip.version == net.version and ip in net for net in networks)


def resolve_client_ip(
    peer: str,
    forwarded_for: str | None,
    trusted_proxies: Sequence[Network],
) -> str:
    if not trusted_proxies or not forwarded_for or not _trusted(peer, trusted_proxies):
        return peer
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    for hop in reversed(hops):
        if not _trusted(hop, trusted_proxies):
            parsed = _parse(hop)
            if parsed is None:
                return peer  # malformed chain: fail back to the peer
            return str(parsed)  # canonical form, never raw header text
    return peer
