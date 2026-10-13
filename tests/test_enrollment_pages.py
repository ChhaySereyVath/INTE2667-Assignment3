"""R03/R04: the citizen's enrolment page is protected and shows data safely."""
from tests.conftest import verify_mfa
from tests.test_auth_login import login, make_user
from tests.test_auth_pages import INLINE_SCRIPT
from tests.test_enrollment_access import citizen_client, enrol


def test_the_page_needs_a_login(client):
    response = client.get("/my-enrolment")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_a_citizen_gets_the_page_with_both_forms(app):
    client = citizen_client(app)
    response = client.get("/my-enrolment")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'id="enrol-form"' in body and 'id="address-form"' in body
    assert body.count('<option value="') == 16  # 8 states in each of the two forms
    assert INLINE_SCRIPT.search(body) is None
    assert response.headers["Cache-Control"] == "no-store"


def test_the_page_html_holds_no_personal_details(app):
    """Details arrive from /enrollment/me afterwards, so a cached copy holds nothing."""
    client = citizen_client(app)
    enrol(client)
    body = client.get("/my-enrolment").get_data(as_text=True)
    for detail in ("Testperson", "12 Example Street", "1990-04-12", "3053"):
        assert detail not in body


def test_staff_are_sent_back_to_their_dashboard(app, client):
    with app.app_context():
        make_user(username="emma", role="aec_employee")
    login(client, "emma", "Correct-Horse-42")
    verify_mfa(app)
    response = client.get("/my-enrolment")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")