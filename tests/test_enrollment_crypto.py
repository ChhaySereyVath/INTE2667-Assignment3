"""R01: sensitive fields are encrypted at rest, tamper-evident, and keys stay out of the data."""
import base64
import pytest
from app.security.crypto import decrypt_field, encrypt_field, record_aad

AAD = "citizens:family_name:1111-2222"

def test_round_trip(app):
    with app.app_context():
        token =encrypt_field("Testperson", AAD)
        assert decrypt_field(token, AAD) == "Testperson"

def test_token_does_not_contain_the_plaintext(app):
    with app.app_context():
        token = encrypt_field("Testperson", AAD)
        assert "Testperson" not in token
        assert token.startswith("v1:")

def test_same_text_encrypts_differently_each_time(app):
    with app.app_context():
        assert encrypt_field("Testperson", AAD) != encrypt_field("Testperson", AAD)

def test_none_stays_none(app):
    with app.app_context():
        assert encrypt_field(None, AAD) is None
        assert decrypt_field(None, AAD) is None

def change_token(token, version=None, key_id=None, flip_byte=False):
    """Make a damaged copy of a token for the tamper tests."""
    old_version, old_key_id, payload = token.split(":", 2)

    raw = bytearray(base64.urlsafe_b64decode(payload))

    if flip_byte:
        raw[-1] ^= 0x01

    payload = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
    return f"{version or old_version}:{key_id or old_key_id}:{payload}"

def test_record_aad_format():
    assert record_aad("citizens", "family_name", "1111-2222") == AAD

def test_ciphertext_copied_to_another_record_fails(app):
    with app.app_context():
        token = encrypt_field("Testperson", AAD)
        other_row = record_aad("citizens", "family_name", "9999-0000")

        with pytest.raises(ValueError):
            decrypt_field(token, other_row)

def test_tampered_ciphertext_fails(app):
    with app.app_context():
        token = encrypt_field("Testperson", AAD)

        with pytest.raises(ValueError):
            decrypt_field(change_token(token, flip_byte=True), AAD)

def test_malformed_token_and_wrong_version_fail_with_one_generic_error(app):
    with app.app_context():
        token = encrypt_field("Testperson", AAD)

        for bad in (
            "not-a-token",
            change_token(token, version="v2"),
            change_token(token, key_id="00000000"),
        ):
            with pytest.raises(ValueError, match="^Decryption failed$"):
                decrypt_field(bad, AAD)
                


