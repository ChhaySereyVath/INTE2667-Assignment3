"""R04: injection and malformed input are rejected, and nothing is half-written."""
from app.models.enrollment_models import Enrolment, EnrolmentHistory
from app.models.user import User
from tests.conftest import csrf_headers
from tests.test_auth_login import login, make_user
from tests.test_enrollment_access import ENROLMENT, citizen_client, enrol

PAYLOADS = (
    "'; DROP TABLE enrolments; --",
    "' OR '1'='1",
    "1; DELETE FROM users WHERE 1=1; --",
    "<script>steal(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "../../etc/passwd",
    "{{7*7}}",
    "\x00binary",
)


def test_injection_payloads_in_enrolment_fields_are_rejected(app):
    client = citizen_client(app)
    for payload in PAYLOADS:
        for field in ("given_name", "family_name", "suburb", "postcode", "state"):
            response = enrol(client, **{field: payload})
            assert response.status_code == 400, f"{field} accepted {payload!r}"
    with app.app_context():
        assert Enrolment.query.count() == 0  # nothing was written by any of them


def test_the_tables_still_exist_after_the_payloads(app):
    client = citizen_client(app)
    for payload in PAYLOADS:
        enrol(client, family_name=payload)
    # if any payload had executed, these queries would fail or return nothing
    with app.app_context():
        assert User.query.filter_by(username="alice").count() == 1
        assert Enrolment.query.count() == 0
    assert enrol(client).status_code == 201


def test_injection_in_the_login_form_does_not_execute(app, client):
    with app.app_context():
        make_user()
    for payload in PAYLOADS:
        response = login(client, payload, "x")
        assert response.status_code in (400, 401, 429)
    with app.app_context():
        assert User.query.count() == 1  # the users table is untouched

def test_a_failed_validation_writes_nothing_at_all(app):
    """R04: 'Failed validation does not partially modify system data.'"""
    client = citizen_client(app)
    enrol(client)
    with app.app_context():
        before = Enrolment.query.one().get_field("address_line")
        history_before = EnrolmentHistory.query.count()

    # a valid address line with an invalid postcode in the same request
    response = client.patch("/enrollment/me/address", headers=csrf_headers(client),
                            json={"address_line": "99 New Road", "suburb": "Fitzroy",
                                  "postcode": "ABCDE", "state": "VIC"})
    assert response.status_code == 400
    with app.app_context():
        assert Enrolment.query.one().get_field("address_line") == before
        assert EnrolmentHistory.query.count() == history_before


def test_error_messages_never_echo_the_payload_back(app):
    client = citizen_client(app)
    for payload in PAYLOADS:
        body = client.patch("/enrollment/me/address", headers=csrf_headers(client),
                            json={"address_line": payload, "suburb": "Fitzroy",
                                  "postcode": "3053", "state": "VIC"}).get_data(as_text=True)
        assert payload not in body


def test_unknown_fields_cannot_set_the_status_or_the_owner(app):
    client = citizen_client(app)
    for extra in ({"status": "approved"}, {"user_id": "someone-else"},
                  {"registered_by": "someone-else"}, {"approved_by": "someone-else"}):
        assert enrol(client, **extra).status_code == 400
    with app.app_context():
        assert Enrolment.query.count() == 0


def test_an_oversized_request_is_refused(app):
    """R06: 'Oversized requests are rejected.'"""
    client = citizen_client(app)
    response = client.post("/enrollment/me", headers=csrf_headers(client),
                           json=dict(ENROLMENT, address_line="x" * 100_000))
    assert response.status_code == 413
    assert response.get_json() == {"error": "Request too large"}


def test_values_come_back_as_data_never_as_markup(app):
    """R04: 'User-controlled output is safely encoded.'

    The API answers in JSON, which escapes nothing into HTML, and the pages insert
    text with textContent. An address with punctuation is stored and returned as it
    was typed, not as markup.
    """
    client = citizen_client(app)
    enrol(client, address_line="12 O'Connell St #3")
    body = client.get("/enrollment/me")
    assert body.headers["Content-Type"].startswith("application/json")
    assert body.get_json()["enrolment"]["address_line"] == "12 O'Connell St #3"