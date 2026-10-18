"""R02: personal details, passwords and tokens never reach logs or error messages."""
import logging

from app.security.redaction import redact
from tests.conftest import csrf_headers
from tests.test_auth_login import login, make_user

SECRETS = ("Correct-Horse-42", "alice@example.com", "1990-04-12", "12 Example Street",
           "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl")


# --- KE08 ---

def test_redact_masks_secrets_and_personal_details():
    line = ('login password=Correct-Horse-42 email="alice@example.com" '
            "{'date_of_birth': '1990-04-12', 'address_line': '12 Example Street'} "
            "Authorization: Bearer abc.def.ghi token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl")
    cleaned = redact(line)
    for secret in SECRETS:
        assert secret not in cleaned
    assert "abc.def.ghi" not in cleaned
    assert cleaned.startswith("login password=[redacted]")


def test_redact_leaves_ids_and_ordinary_words_alone():
    line = "access_denied actor=3f1c0b0e-1111-4222-8333-944445555666 action=read result=denied"
    assert redact(line) == line


def test_the_app_and_security_loggers_redact(app, caplog):
    caplog.set_level(logging.INFO)
    with app.test_request_context("/"):
        app.logger.warning("user typed password=%s", "Correct-Horse-42")
        logging.getLogger("evp.security").warning("email=%s", "alice@example.com")
    text = " ".join(record.getMessage() for record in caplog.records)
    assert "Correct-Horse-42" not in text and "alice@example.com" not in text
    assert text.count("[redacted]") == 2
