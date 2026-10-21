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

# --- KE09 ---

def add_failing_route(app):
    @app.route("/t/explode", methods=["POST"])
    def explode():
        # an exception message that quotes personal data, as a careless library might
        raise RuntimeError("failed for alice@example.com password=Correct-Horse-42 "
                           "SELECT * FROM users WHERE username='alice'")


def test_an_unexpected_error_shows_only_a_request_id(app, client, caplog):
    """R02: 'Error messages do not reveal database details, passwords or tokens.'"""
    add_failing_route(app)
    response = client.post("/t/explode")
    body = response.get_json()
    assert response.status_code == 500
    assert set(body) == {"error", "request_id"}
    assert body["error"] == "An unexpected error occurred"
    assert response.headers["X-Request-ID"] == body["request_id"]
    for leak in ("SELECT", "Traceback", "RuntimeError", "alice@example.com", "Correct-Horse-42"):
        assert leak not in response.get_data(as_text=True)

    # the server log has the details for the investigator, under the same id, redacted
    logged = [r for r in caplog.records if r.getMessage().endswith("Unhandled error")]
    assert logged and f"request_id={body['request_id']}" in logged[0].getMessage()
    assert "alice@example.com" not in logged[0].exc_text
    assert "Correct-Horse-42" not in logged[0].exc_text


def test_invalid_requests_do_not_echo_what_was_sent(app):
    """R02: 'Tests confirm that invalid requests do not leak PII.'"""
    with app.app_context():
        make_user()
    client = app.test_client()
    bad_login = client.post("/auth/login", json={
        "username": "alice", "password": 12345, "email": "alice@example.com"})
    assert bad_login.status_code == 400
    assert "alice@example.com" not in bad_login.get_data(as_text=True)

    login(client, "alice", "Correct-Horse-42")
    bad_enrol = client.post("/enrollment/me", headers=csrf_headers(client),
                            json={"given_name": "<script>", "date_of_birth": "1990-04-12x",
                                  "address_line": "12 Example Street", "secret_field": "x"})
    text = bad_enrol.get_data(as_text=True)
    assert bad_enrol.status_code == 400
    for leak in ("<script>", "1990-04-12x", "12 Example Street"):
        assert leak not in text


def test_every_response_carries_a_request_id(client):
    first, second = client.get("/"), client.get("/")
    assert len(first.headers["X-Request-ID"]) == 32
    assert first.headers["X-Request-ID"] != second.headers["X-Request-ID"]