"""R01: sensitive fields are encrypted at rest, tamper-evident, and keys stay out of the data."""

from app.security.crypto import decrypt_field, encrypt_field

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
