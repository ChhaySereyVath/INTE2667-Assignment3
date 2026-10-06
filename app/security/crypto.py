"""R01: encryption of sensitive fileds at rest (Part 2 solution S11).
encrypted_field / decrypt_field use AES-256-GCM, which encrypts AND detects tampering.
blind_index makes a keyed fingerprint so encrypted values can still be looked up.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

TOKEN_VERSION = "v1"
NONCE_BYTES = 12

def _load_key(name):
    """ To read a 32-byte key (64 hex characters) from the app config. Never from code."""
    value = current_app.config.get(name)

    if not value:
        raise RuntimeError(f"Missing encryption key: {name}")

    key = bytes.fromhex(value)

    if len(key) != 32:
        raise RuntimeError(f"{name} must be 64 hex characters (32 bytes)")

    return key

def _key_id(key):
    """Short fingerprint of the key, stored with each value (helps future key rotation.)"""
    return hashlib.sha256(key).hexdigest()[:8]

def encrypt_field(plaintext, aad, key_name="DATA_ENC_KEY"):
    """Encrypt a string. Returns 'v1:<key id>:<base64 nonce+ciphertext>' None stays None."""
    if plaintext is None:
        return None

    key = _load_key(key_name)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(
        nonce, 
        plaintext.encode("utf-8"),
        aad.encode("utf-8")
    )

    payload = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return f"{TOKEN_VERSION}:{_key_id(key)}:{payload}"

def decrypt_field(token, aad, key_name="DATA_ENC_KEY"):
    """To decrypt a token from encrypt_field. Raises ValueError (no details) if anything is wrong."""
    if token is None:
        return None

    key = _load_key(key_name)

    try:
        version, key_id, payload = token.split(":", 2)

        if version != TOKEN_VERSION or key_id != _key_id(key):
            raise ValueError("wrong version or key")

        raw = base64.urlsafe_b64decode(payload.encode("ascii"))

        plaintext = AESGCM(key).decrypt(
            raw[:NONCE_BYTES],
            raw[NONCE_BYTES:],
            aad.encode("utf-8"),
        )

        return plaintext.decode("utf-8")

    except Exception:
        raise ValueError("Decryption failed") from None 

def record_aad(table, column, record_id):
    """Associated data that binds a ciphertext to ONE column of ONE row.
       A ciphertext copied to another row or column won't decrypt there."""

    return f"{table}:{column}:{record_id}"

