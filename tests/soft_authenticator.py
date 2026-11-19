"""Soft WebAuthn authenticator for tests (fake ES256 credentials, no real
authenticator needed). Builds spec-shaped attestation/assertion responses.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url

RP_ID = "localhost"
ORIGIN = "http://localhost"


def _b64u(b: bytes) -> str:
    return bytes_to_base64url(b)


class SoftAuthenticator:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    def _cose_key(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2, 3: -7, -1: 1,
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        })

    def _auth_data(self, challenge_rp: str, sign_count: int, *, attested: bool,
                   uv: bool = True) -> bytes:
        rp_hash = hashlib.sha256(challenge_rp.encode()).digest()
        flags = 0x01  # UP
        if uv:
            flags |= 0x04
        if attested:
            flags |= 0x40
        auth = rp_hash + bytes([flags]) + struct.pack(">I", sign_count)
        if attested:
            aaguid = bytes(16)
            cred_id_len = struct.pack(">H", len(self.credential_id))
            auth += aaguid + cred_id_len + self.credential_id + self._cose_key()
        return auth

    def register(self, challenge: bytes, *, uv: bool = True) -> dict:
        client_data = {
            "type": "webauthn.create",
            "challenge": _b64u(challenge),
            "origin": ORIGIN,
        }
        cd_json = json.dumps(client_data).encode()
        auth_data = self._auth_data(RP_ID, 0, attested=True, uv=uv)
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64u(self.credential_id),
            "rawId": _b64u(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64u(cd_json),
                "attestationObject": _b64u(att_obj),
            },
            "clientExtensionResults": {},
        }

    def authenticate(self, challenge: bytes, *, uv: bool = True,
                     sign_count: int | None = None) -> dict:
        self.sign_count = self.sign_count + 1 if sign_count is None else sign_count
        client_data = {
            "type": "webauthn.get",
            "challenge": _b64u(challenge),
            "origin": ORIGIN,
        }
        cd_json = json.dumps(client_data).encode()
        auth_data = self._auth_data(RP_ID, self.sign_count, attested=False, uv=uv)
        cd_hash = hashlib.sha256(cd_json).digest()
        sig = self.key.sign(auth_data + cd_hash, ec.ECDSA(hashes.SHA256()))
        return {
            "id": _b64u(self.credential_id),
            "rawId": _b64u(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64u(cd_json),
                "authenticatorData": _b64u(auth_data),
                "signature": _b64u(sig),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
