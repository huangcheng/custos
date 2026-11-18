"""Crypto core contract tests (design §4). Fake key material only."""

import base64
import hashlib
import hmac

import pytest

from custos.crypto import (
    CryptoError,
    UnreadableError,
    Vault,
    credential_digest,
    digests_equal,
    field_aad,
    history_aad,
    operator_aad,
    operator_seal_key,
    parse_keyring,
    parse_pepper,
)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


K1 = bytes(32)
K2 = bytes([1]) * 32
K10 = bytes([2]) * 32
FAKE_PEPPER = bytes([7]) * 32


def test_keyring_numeric_max_wins() -> None:
    keys = parse_keyring(f"k2:{b64url(K2)},k10:{b64url(K10)}")
    assert set(keys) == {2, 10}
    assert Vault(keys).current_version == 10


def test_keyring_duplicate_version_rejected() -> None:
    with pytest.raises(CryptoError):
        parse_keyring(f"k1:{b64url(K1)},k1:{b64url(K2)}")


@pytest.mark.parametrize("suffix", ["+", "/", "="])
def test_keyring_standard_b64_chars_rejected(suffix: str) -> None:
    with pytest.raises(CryptoError):
        parse_keyring(f"k1:{b64url(K1)[:-1]}{suffix}")


def test_keyring_wrong_length_rejected() -> None:
    with pytest.raises(CryptoError):
        parse_keyring(f"k1:{b64url(bytes(31))}")
    with pytest.raises(CryptoError):
        parse_keyring(f"k1:{b64url(bytes(33))}")


@pytest.mark.parametrize("version", ["k0", "k-1", "kabc", "k01"])
def test_keyring_bad_version_rejected(version: str) -> None:
    with pytest.raises(CryptoError):
        parse_keyring(f"{version}:{b64url(K1)}")


def test_keyring_comments_and_whitespace() -> None:
    raw = f"# comment\n  k1:{b64url(K1)} , k2:{b64url(K2)}  \n"
    assert set(parse_keyring(raw)) == {1, 2}


def test_keyring_empty_rejected() -> None:
    with pytest.raises(CryptoError):
        parse_keyring("")
    with pytest.raises(CryptoError):
        parse_keyring("# only a comment\n")


def test_seal_open_roundtrip_all_domains() -> None:
    vault = Vault(parse_keyring(f"k1:{b64url(K1)},k2:{b64url(K2)}"))
    for domain, row_id in (("field", "row-1"), ("fieldh", "hist-1"), ("operator:totp", "")):
        blob, version = vault.seal(domain, row_id, b"cu-test.plaintext")
        assert version == 2
        assert len(blob) == 12 + len(b"cu-test.plaintext") + 16
        assert vault.open(domain, row_id, blob, version) == b"cu-test.plaintext"


def test_nonce_unique_per_seal() -> None:
    vault = Vault({1: K1})
    nonces = {vault.seal("field", "r", b"x")[0][:12] for _ in range(100)}
    assert len(nonces) == 100


def test_cross_domain_and_moved_row_rejected() -> None:
    vault = Vault({1: K1})
    blob, v = vault.seal("field", "row-1", b"secret")
    with pytest.raises(UnreadableError):
        vault.open("fieldh", "row-1", blob, v)
    with pytest.raises(UnreadableError):
        vault.open("field", "row-2", blob, v)


def test_wrong_and_missing_version_unified_error() -> None:
    vault = Vault({1: K1, 2: K2})
    blob, v = vault.seal("field", "r", b"secret")  # seals under 2
    with pytest.raises(UnreadableError):
        vault.open("field", "r", blob, 1)  # wrong version, key exists
    with pytest.raises(UnreadableError):
        vault.open("field", "r", blob, 99)  # missing version
    # corruption under an available version: same exception type
    corrupted = blob[:-1] + bytes([blob[-1] ^ 0xFF])
    with pytest.raises(UnreadableError):
        vault.open("field", "r", corrupted, v)


def test_aad_strings_frozen() -> None:
    assert field_aad("abc", 3) == b"field:abc|3"
    assert history_aad("abc", 3) == b"fieldh:abc|3"
    assert operator_aad(3) == b"operator:totp|3"


def test_pepper_validation() -> None:
    with pytest.raises(CryptoError):
        parse_pepper(b64url(bytes(31)))
    with pytest.raises(CryptoError):
        parse_pepper(b64url(bytes(32)))  # all-zero
    assert parse_pepper(b64url(FAKE_PEPPER)) == FAKE_PEPPER
    with pytest.raises(CryptoError):
        parse_pepper("not base64url!!")


def test_credential_digest_contract() -> None:
    secret_text = "cu-test." + b64url(bytes([9]) * 32)
    expected = hmac.new(FAKE_PEPPER, secret_text.encode(), hashlib.sha256).digest()
    assert credential_digest(FAKE_PEPPER, secret_text) == expected
    # presented text used as-is, never decoded
    decoded_msg = hmac.new(FAKE_PEPPER, bytes([9]) * 32, hashlib.sha256).digest()
    assert credential_digest(FAKE_PEPPER, secret_text) != decoded_msg


def test_digests_equal() -> None:
    assert digests_equal(b"a" * 32, b"a" * 32)
    assert not digests_equal(b"a" * 32, b"b" * 32)


def test_operator_seal_key_derivation() -> None:
    derived = operator_seal_key(K1)
    assert derived != K1
    assert len(derived) == 32
    assert derived == operator_seal_key(K1)  # deterministic
    assert derived != operator_seal_key(K2)


def test_operator_domain_uses_derived_key() -> None:
    vault = Vault({1: K1})
    blob, v = vault.seal("operator:totp", "", b"totp-seed")
    # opening with a vault built from the RAW key must fail: operator domain
    # seals under the HKDF-derived key, not the keyring key itself
    raw_vault = Vault({1: operator_seal_key(K1)})
    with pytest.raises(UnreadableError):
        raw_vault.open("operator:totp", "", blob, v)
    assert vault.open("operator:totp", "", blob, v) == b"totp-seed"
