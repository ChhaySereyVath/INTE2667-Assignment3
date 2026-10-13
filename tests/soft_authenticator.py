"""A software security key for tests (R08).

This will create a P-256 key pair to produce real WebAuthn signatures, so the server's checks run for real.
The app never imports this file; it exists only so tests can play the user's device.

"""
import base64
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class SoftAuthenticator:
    def __init__(self, rp_id="localhost", origin="http://localhost:5000", counts=True):
        """counts=False behaves like most phone passkeys, which always report a
        signature counter of 0. Then the counter cannot detect a replay, and the
        server's single-use challenge is the only protection."""
        self.rp_id = rp_id
        self.origin = origin
        self.counts = counts
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    def _rp_id_hash(self):
        return hashlib.sha256(self.rp_id.encode("ascii")).digest()

    def _cose_public_key(self):
        """The public key in COSE format: EC2 key type, ES256, curve P-256."""
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1,
                            -2: numbers.x.to_bytes(32, "big"),
                            -3: numbers.y.to_bytes(32, "big")})

    def _client_data(self, kind, challenge, origin):
        return json.dumps({"type": kind, "challenge": challenge,
                           "origin": origin or self.origin, "crossOrigin": False}).encode("utf-8")

    def register(self, options, origin=None):
        """Answer the server's registration options, like navigator.credentials.create()."""
        flags = 0x01 | 0x04 | 0x40  # user present, user verified, credential data included
        credential_data = (bytes(16)  # AAGUID: all zeros for a software key
                           + len(self.credential_id).to_bytes(2, "big")
                           + self.credential_id
                           + self._cose_public_key())
        auth_data = (self._rp_id_hash() + bytes([flags])
                     + self.sign_count.to_bytes(4, "big") + credential_data)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {"clientDataJSON": b64url(client_data),
                         "attestationObject": b64url(attestation)},
            "clientExtensionResults": {},
        }

    def authenticate(self, options, origin=None, bump_counter=True):
        """Sign the server's challenge, like navigator.credentials.get()."""
        if bump_counter and self.counts:
            self.sign_count += 1
        flags = 0x01 | 0x04  # user present, user verified
        auth_data = self._rp_id_hash() + bytes([flags]) + self.sign_count.to_bytes(4, "big")
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.private_key.sign(auth_data + hashlib.sha256(client_data).digest(),
                                          ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {"clientDataJSON": b64url(client_data),
                         "authenticatorData": b64url(auth_data),
                         "signature": b64url(signature)},
            "clientExtensionResults": {},
        }