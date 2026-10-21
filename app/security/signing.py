"""Ed25519 digital signatures over canonical JSON (R14 anchors, R15 actions, R19 ballots).

A signature made with the private key can be checked by anyone holding the PUBLIC
key, so evidence can be verified without trusting this app or its database.
"""
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from flask import current_app


def canonical_json(data):
    """One exact byte string for the same data: sorted keys, no spaces. Two machines
    that sign or hash the same record always get the same bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _private_key(key_name):
    value = current_app.config.get(key_name)
    if not value:
        raise RuntimeError(f"Missing signing key: {key_name}")
    seed = bytes.fromhex(value)
    if len(seed) != 32:
        raise RuntimeError(f"{key_name} must be 64 hex characters (32 bytes)")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_hex(key_name):
    """The public half, safe to print, publish or copy to another machine."""
    raw = _private_key(key_name).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def sign(data, key_name):
    """Sign a dict (as canonical JSON). Returns the signature as hex."""
    return _private_key(key_name).sign(canonical_json(data).encode("utf-8")).hex()


def verify(data, signature_hex, public_hex):
    """True only if `signature_hex` is a valid signature of exactly this data."""
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        public.verify(bytes.fromhex(signature_hex), canonical_json(data).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False
