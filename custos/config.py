"""Configuration loading and startup validation (design §3, §10).

Env conventions: an empty-string value is unset; boolean flags accept
exactly "1". File forms of secrets must be mode 0600/0400. Validation
failures raise ConfigError and must abort startup — never warn-and-continue.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from custos.crypto import CryptoError, parse_keyring, parse_pepper

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ConfigError(Exception):
    """Startup configuration failure. Messages never contain secret material."""


@dataclass(frozen=True)
class Settings:
    bind: str
    port: int
    public_bind: bool
    insecure_dev: bool
    insecure_cookie: bool
    database_url: str = field(repr=False)
    data_dir: Path
    retention_days: int
    skip_migrate: bool
    allow_missing_key_version: bool
    trusted_proxies: tuple[Network, ...] = ()
    keyring_raw: str = field(default="", repr=False)
    pepper_raw: bytes = field(default=b"", repr=False)


def _get(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name, "")
    return value if value != "" else None


def _flag(env: Mapping[str, str], name: str) -> bool:
    value = _get(env, name)
    if value is None:
        return False
    if value != "1":
        raise ConfigError(f"{name} accepts exactly '1' or unset")
    return True


def _secret_file(env: Mapping[str, str], name: str) -> str | None:
    """Read a *_FILE secret with the 0600/0400 mode contract."""
    raw_path = _get(env, name)
    if raw_path is None:
        return None
    path = Path(raw_path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise ConfigError(f"{name}: cannot open file: {reason}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{name}: not a regular file")
        mode = stat.S_IMODE(st.st_mode)
        if mode not in (0o600, 0o400):
            raise ConfigError(f"{name}: file must be mode 0600 or 0400")
        try:
            with os.fdopen(fd, encoding="utf-8") as handle:
                fd = -1
                value = handle.read()
        except UnicodeDecodeError as exc:
            raise ConfigError(f"{name}: file is not valid UTF-8") from exc
        except OSError as exc:
            raise ConfigError(f"{name}: cannot read file") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    value = value.strip()
    if value == "":
        raise ConfigError(f"{name}: file is empty")
    return value


def _paired(env: Mapping[str, str], base: str) -> str | None:
    """env form + _FILE form: exactly one may be set."""
    direct = _get(env, base)
    if direct is not None and _get(env, f"{base}_FILE") is not None:
        raise ConfigError(f"{base} and {base}_FILE are mutually exclusive")
    if direct is not None:
        return direct
    return _secret_file(env, f"{base}_FILE")


def _is_loopback_literal(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _bind_is_loopback(bind: str) -> bool:
    """Loopback classifier (§3): IP literal in 127/8 or ::1, or the exact
    name 'localhost' resolved once — every returned address must be loopback."""
    if bind.lower() == "localhost":
        try:
            infos = socket.getaddrinfo(bind, None)
        except OSError as exc:
            raise ConfigError("CUSTOS_BIND=localhost does not resolve") from exc
        addrs = {str(info[4][0]) for info in infos}
        if not addrs or not all(_is_loopback_literal(a) for a in addrs):
            raise ConfigError("CUSTOS_BIND=localhost must resolve only to loopback addresses")
        return True
    return _is_loopback_literal(bind)


def _parse_proxies(raw: str | None) -> tuple[Network, ...]:
    if raw is None:
        return ()
    networks: list[Network] = []
    for part in raw.split(","):
        entry = part.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ConfigError("CUSTOS_TRUSTED_PROXIES contains a malformed CIDR") from exc
        if net.prefixlen == 0:
            raise ConfigError("CUSTOS_TRUSTED_PROXIES rejects /0 networks")
        if isinstance(net, ipaddress.IPv6Network):
            base = ipaddress.ip_address(net.network_address)
            if isinstance(base, ipaddress.IPv6Address) and base.ipv4_mapped is not None:
                raise ConfigError(
                    "CUSTOS_TRUSTED_PROXIES: use plain IPv4 CIDRs, not IPv4-mapped IPv6"
                )
        networks.append(net)
    if not networks:
        raise ConfigError("CUSTOS_TRUSTED_PROXIES is set but empty")
    return tuple(networks)


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    env = dict(os.environ) if env is None else env

    bind = _get(env, "CUSTOS_BIND") or "127.0.0.1"
    try:
        ipaddress.ip_address(bind)
    except ValueError:
        if bind.lower() != "localhost":
            raise ConfigError(
                "CUSTOS_BIND must be an IP literal or 'localhost'; use CUSTOS_PORT for the port"
            ) from None

    port_raw = _get(env, "CUSTOS_PORT")
    try:
        port = int(port_raw) if port_raw is not None else 8300
    except ValueError as exc:
        raise ConfigError("CUSTOS_PORT must be an integer") from exc
    if not (1 <= port <= 65535):
        raise ConfigError("CUSTOS_PORT out of range")

    public_bind = _flag(env, "CUSTOS_PUBLIC_BIND")
    insecure_dev = _flag(env, "CUSTOS_INSECURE_DEV")
    insecure_cookie = _flag(env, "CUSTOS_INSECURE_COOKIE")
    if public_bind and insecure_dev:
        raise ConfigError("CUSTOS_PUBLIC_BIND and CUSTOS_INSECURE_DEV are mutually exclusive")

    loopback = _bind_is_loopback(bind)
    if not loopback:
        if insecure_dev:
            raise ConfigError("CUSTOS_INSECURE_DEV requires a loopback bind")
        if not public_bind:
            raise ConfigError(
                "non-loopback bind requires CUSTOS_PUBLIC_BIND=1 (TLS terminates upstream)"
            )
    if insecure_cookie and not (insecure_dev and loopback):
        raise ConfigError("CUSTOS_INSECURE_COOKIE requires CUSTOS_INSECURE_DEV=1 and loopback")
    if insecure_dev:
        insecure_cookie = True

    trusted_proxies = _parse_proxies(_get(env, "CUSTOS_TRUSTED_PROXIES"))
    if public_bind and not trusted_proxies:
        raise ConfigError("CUSTOS_PUBLIC_BIND=1 requires non-empty CUSTOS_TRUSTED_PROXIES")

    retention_raw = _get(env, "CUSTOS_RETENTION_DAYS")
    try:
        retention_days = int(retention_raw) if retention_raw is not None else 365
    except ValueError as exc:
        raise ConfigError("CUSTOS_RETENTION_DAYS must be an integer") from exc
    if retention_days < 7:
        raise ConfigError("CUSTOS_RETENTION_DAYS minimum is 7")

    database_url = _paired(env, "CUSTOS_DATABASE_URL")
    if database_url is None:
        raise ConfigError("CUSTOS_DATABASE_URL (or _FILE) is required")
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if not database_url.startswith("postgresql+asyncpg://"):
        raise ConfigError("CUSTOS_DATABASE_URL must be a postgresql+asyncpg:// DSN")
    keyring_raw = _paired(env, "CUSTOS_SECRETS_KEY")
    if keyring_raw is None:
        raise ConfigError("CUSTOS_SECRETS_KEY (or _FILE) is required")
    pepper_text = _paired(env, "CUSTOS_PEPPER")
    if pepper_text is None:
        raise ConfigError("CUSTOS_PEPPER (or _FILE) is required")
    try:
        parse_keyring(keyring_raw)
        pepper_bytes = parse_pepper(pepper_text)
    except CryptoError as exc:
        raise ConfigError(str(exc)) from exc

    return Settings(
        bind=bind,
        port=port,
        public_bind=public_bind,
        insecure_dev=insecure_dev,
        insecure_cookie=insecure_cookie,
        database_url=database_url,
        data_dir=Path(_get(env, "CUSTOS_DATA_DIR") or "/var/lib/custos"),
        retention_days=retention_days,
        skip_migrate=_flag(env, "CUSTOS_SKIP_MIGRATE"),
        allow_missing_key_version=_flag(env, "CUSTOS_ALLOW_MISSING_KEY_VERSION"),
        trusted_proxies=trusted_proxies,
        keyring_raw=keyring_raw,
        pepper_raw=pepper_bytes,
    )
