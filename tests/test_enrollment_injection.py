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