"""Config loader contract tests (design §3 bind/TLS, §10 env conventions).

Fixtures use obviously fake secret material only.
"""

from __future__ import annotations

import base64
import socket
from pathlib import Path

import pytest

from custos.config import ConfigError, load_settings

FAKE_KEYRING = "k1:" + base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
FAKE_PEPPER = base64.urlsafe_b64encode(bytes([7]) * 32).rstrip(b"=").decode()

BASE_ENV = {
    "CUSTOS_DATABASE_URL": "postgresql+asyncpg://custos:cu-test@127.0.0.1:5432/custos",
    "CUSTOS_SECRETS_KEY": FAKE_KEYRING,
    "CUSTOS_PEPPER": FAKE_PEPPER,
}


def env(**extra: str) -> dict[str, str]:
    combined = {**BASE_ENV, **extra}
    if combined.get("CUSTOS_PUBLIC_BIND") == "1" and "CUSTOS_ALLOWED_ORIGINS" not in combined:
        combined["CUSTOS_ALLOWED_ORIGINS"] = "https://console.example"
    if combined.get("CUSTOS_ALLOWED_ORIGINS") and "CUSTOS_WEBAUTHN_RP_ID" not in combined:
        combined["CUSTOS_WEBAUTHN_RP_ID"] = "console.example"
    return combined


def test_defaults() -> None:
    s = load_settings(env())
    assert s.bind == "127.0.0.1"
    assert s.port == 8300
    assert s.retention_days == 365
    assert s.public_bind is False
    assert s.insecure_dev is False
    assert s.insecure_cookie is False
    assert s.trusted_proxies == ()
    assert s.data_dir == Path("/var/lib/custos")


def test_empty_env_is_unset() -> None:
    s = load_settings(env(CUSTOS_PORT="", CUSTOS_PUBLIC_BIND=""))
    assert s.port == 8300
    assert s.public_bind is False


@pytest.mark.parametrize("bad", ["0", "yes", "true", "2"])
def test_boolean_flags_reject_non_one(bad: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_PUBLIC_BIND=bad))


def test_boolean_flag_one_accepted() -> None:
    s = load_settings(
        env(
            CUSTOS_BIND="10.0.0.5",
            CUSTOS_PUBLIC_BIND="1",
            CUSTOS_TRUSTED_PROXIES="10.0.0.0/8",
        )
    )
    assert s.public_bind is True


def test_bind_host_port_rejected() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_BIND="127.0.0.1:8300"))


def test_non_loopback_ipv6_literal_allowed() -> None:
    s = load_settings(
        env(
            CUSTOS_BIND="2001:db8::1",
            CUSTOS_PUBLIC_BIND="1",
            CUSTOS_TRUSTED_PROXIES="2001:db8::/32",
        )
    )
    assert s.bind == "2001:db8::1"


def test_localhost_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple]:
        return [(socket.AF_INET, None, None, None, ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    s = load_settings(env(CUSTOS_BIND="LocalHost", CUSTOS_INSECURE_DEV="1"))
    assert s.insecure_dev is True


def test_settings_repr_redacts_secrets() -> None:
    s = load_settings(env())
    text = repr(s)
    assert FAKE_KEYRING not in text
    assert FAKE_PEPPER not in text
    assert "cu-test" not in text  # database_url password


def test_empty_secret_file_rejected(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_text("  \n")
    empty.chmod(0o600)
    with pytest.raises(ConfigError):
        load_settings(
            {
                "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
                "CUSTOS_SECRETS_KEY_FILE": str(empty),
                "CUSTOS_PEPPER": FAKE_PEPPER,
            }
        )


def test_non_utf8_secret_file_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"\xff\xfe\x00binary")
    bad.chmod(0o600)
    with pytest.raises(ConfigError):
        load_settings(
            {
                "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
                "CUSTOS_SECRETS_KEY_FILE": str(bad),
                "CUSTOS_PEPPER": FAKE_PEPPER,
            }
        )


def test_both_forms_reports_exclusion_before_file_read(tmp_path: Path) -> None:
    unreadable = tmp_path / "nope.txt"  # does not exist
    with pytest.raises(ConfigError, match="mutually exclusive"):
        load_settings(env(CUSTOS_SECRETS_KEY_FILE=str(unreadable)))


def test_non_loopback_requires_public_bind() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_BIND="0.0.0.0"))


def test_public_bind_requires_trusted_proxies() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_BIND="0.0.0.0", CUSTOS_PUBLIC_BIND="1"))


def test_dev_flag_loopback_only() -> None:
    with pytest.raises(ConfigError):
        load_settings(
            env(
                CUSTOS_BIND="0.0.0.0",
                CUSTOS_PUBLIC_BIND="1",
                CUSTOS_TRUSTED_PROXIES="10.0.0.0/8",
                CUSTOS_INSECURE_DEV="1",
            )
        )


def test_dev_and_public_mutually_exclusive() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_INSECURE_DEV="1", CUSTOS_PUBLIC_BIND="1"))


def test_dev_implies_insecure_cookie() -> None:
    s = load_settings(env(CUSTOS_INSECURE_DEV="1"))
    assert s.insecure_dev is True
    assert s.insecure_cookie is True


def test_loopback_classifier_literals() -> None:
    for addr in ("127.0.0.1", "127.5.5.5", "::1"):
        s = load_settings(env(CUSTOS_BIND=addr, CUSTOS_INSECURE_DEV="1"))
        assert s.insecure_dev is True


def test_localhost_all_loopback_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple]:
        return [(socket.AF_INET, None, None, None, ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    s = load_settings(env(CUSTOS_BIND="localhost", CUSTOS_INSECURE_DEV="1"))
    assert s.bind == "localhost"


def test_localhost_mixed_resolution_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple]:
        return [
            (socket.AF_INET, None, None, None, ("127.0.0.1", 0)),
            (socket.AF_INET, None, None, None, ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_BIND="localhost", CUSTOS_INSECURE_DEV="1"))


def test_trusted_proxies_validation() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TRUSTED_PROXIES="not-a-cidr"))
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TRUSTED_PROXIES="0.0.0.0/0"))
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_TRUSTED_PROXIES="::/0"))
    s = load_settings(env(CUSTOS_TRUSTED_PROXIES="127.0.0.1/32, 127.0.0.1, ::1"))
    assert [str(n) for n in s.trusted_proxies] == [
        "127.0.0.1/32",
        "127.0.0.1/32",
        "::1/128",
    ]


def test_retention_minimum() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_RETENTION_DAYS="6"))
    assert load_settings(env(CUSTOS_RETENTION_DAYS="7")).retention_days == 7


def test_insecure_cookie_requires_dev() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_INSECURE_COOKIE="1"))
    with pytest.raises(ConfigError):
        load_settings(
            env(
                CUSTOS_BIND="0.0.0.0",
                CUSTOS_PUBLIC_BIND="1",
                CUSTOS_TRUSTED_PROXIES="10.0.0.0/8",
                CUSTOS_INSECURE_COOKIE="1",
            )
        )


def test_required_secrets_missing() -> None:
    with pytest.raises(ConfigError):
        load_settings({"CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"]})


def test_file_forms_and_mode_check(tmp_path: Path) -> None:
    key_file = tmp_path / "keyring.txt"
    key_file.write_text(FAKE_KEYRING + "\n")
    key_file.chmod(0o600)
    pepper_file = tmp_path / "pepper.txt"
    pepper_file.write_text(FAKE_PEPPER + "\n")
    pepper_file.chmod(0o400)
    s = load_settings(
        {
            "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
            "CUSTOS_SECRETS_KEY_FILE": str(key_file),
            "CUSTOS_PEPPER_FILE": str(pepper_file),
        }
    )
    assert s.keyring_raw == FAKE_KEYRING
    assert s.pepper_raw == bytes([7]) * 32
    # both set -> error
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_SECRETS_KEY_FILE=str(key_file)))
    # group-readable -> error
    key_file.chmod(0o640)
    with pytest.raises(ConfigError):
        load_settings(
            {
                "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
                "CUSTOS_SECRETS_KEY_FILE": str(key_file),
                "CUSTOS_PEPPER": FAKE_PEPPER,
            }
        )


def test_bind_rejects_non_literal_hostname() -> None:
    with pytest.raises(ConfigError):
        load_settings(
            env(
                CUSTOS_BIND="vault.example.com",
                CUSTOS_PUBLIC_BIND="1",
                CUSTOS_TRUSTED_PROXIES="10.0.0.0/8",
            )
        )


def test_secret_file_mode_exact(tmp_path: Path) -> None:
    key_file = tmp_path / "keyring.txt"
    key_file.write_text(FAKE_KEYRING)
    key_file.chmod(0o700)  # owner-only but executable: contract pins 0600/0400
    with pytest.raises(ConfigError):
        load_settings(
            {
                "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
                "CUSTOS_SECRETS_KEY_FILE": str(key_file),
                "CUSTOS_PEPPER": FAKE_PEPPER,
            }
        )


def test_symlinked_secret_file_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.txt"
    real.write_text(FAKE_KEYRING)
    real.chmod(0o600)
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    with pytest.raises(ConfigError):
        load_settings(
            {
                "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
                "CUSTOS_SECRETS_KEY_FILE": str(link),
                "CUSTOS_PEPPER": FAKE_PEPPER,
            }
        )


def test_settings_hashable_and_immutable_proxies() -> None:
    s = load_settings(env(CUSTOS_TRUSTED_PROXIES="127.0.0.1/32"))
    assert isinstance(hash(s), int)
    assert isinstance(s.trusted_proxies, tuple)


def test_fifo_secret_file_rejected(tmp_path: Path) -> None:
    import os as _os

    fifo = tmp_path / "fifo"
    _os.mkfifo(fifo, 0o600)
    with pytest.raises(ConfigError):
        load_settings(
            {
                "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
                "CUSTOS_SECRETS_KEY_FILE": str(fifo),
                "CUSTOS_PEPPER": FAKE_PEPPER,
            }
        )


def test_missing_secret_file_message(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="No such file"):
        load_settings(
            {
                "CUSTOS_DATABASE_URL": BASE_ENV["CUSTOS_DATABASE_URL"],
                "CUSTOS_SECRETS_KEY_FILE": str(tmp_path / "absent.txt"),
                "CUSTOS_PEPPER": FAKE_PEPPER,
            }
        )


def test_config_validates_keyring_and_pepper_content() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_SECRETS_KEY="k1:not-base64url!!"))
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_SECRETS_KEY=f"k1:{FAKE_KEYRING.split(':')[1]},k1:{FAKE_KEYRING.split(':')[1]}"))
    # all-zero pepper rejected at startup
    zero_pepper = base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_PEPPER=zero_pepper))


def test_bare_postgresql_dsn_normalized() -> None:
    s = load_settings(
        {
            "CUSTOS_DATABASE_URL": "postgresql://custos:cu-test@127.0.0.1:5432/custos",
            "CUSTOS_SECRETS_KEY": FAKE_KEYRING,
            "CUSTOS_PEPPER": FAKE_PEPPER,
        }
    )
    assert s.database_url.startswith("postgresql+asyncpg://")


def test_allowed_origins_parsed_and_normalized() -> None:
    s = load_settings(env(CUSTOS_ALLOWED_ORIGINS="https://a.example, https://b.example"))
    assert s.allowed_origins == ("https://a.example", "https://b.example")
    # trailing slash normalized away (exact-match check_origin)
    s2 = load_settings(env(CUSTOS_ALLOWED_ORIGINS="https://c.example/",
                           CUSTOS_WEBAUTHN_RP_ID="c.example"))
    assert s2.allowed_origins == ("https://c.example",)
    assert load_settings(env()).allowed_origins == ()


def test_allowed_origins_rejects_bad_scheme() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_ALLOWED_ORIGINS="console.example.com"))  # no scheme
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_ALLOWED_ORIGINS="ftp://a.example"))
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_ALLOWED_ORIGINS="   "))  # whitespace-only


def test_public_bind_requires_origins() -> None:
    with pytest.raises(ConfigError):
        load_settings(env(CUSTOS_BIND="10.0.0.5", CUSTOS_PUBLIC_BIND="1",
                          CUSTOS_TRUSTED_PROXIES="10.0.0.0/8",
                          CUSTOS_ALLOWED_ORIGINS=""))  # explicit empty overrides helper
