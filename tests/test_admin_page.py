"""R12: the administration page is for administrators only (Ken)."""
from tests.conftest import csrf_headers, verify_mfa
from tests.test_auth_login import login, make_user
from tests.test_auth_pages import INLINE_SCRIPT


def signed_in(app, username, role, mfa=True):
    with app.app_context():
        make_user(username=username, role=role)
    client = app.test_client()
    login(client, username, "Correct-Horse-42")
    if mfa:
        verify_mfa(app)
    return client


def test_signed_out_visitors_are_sent_to_login(client):
    assert client.get("/admin").headers["Location"].endswith("/login")


def test_every_other_role_is_sent_back_to_the_dashboard(app):
    for number, role in enumerate(("citizen", "aec_employee", "commissioner_delegate", "auditor")):
        client = signed_in(app, f"user{number}", role)
        response = client.get("/admin")
        assert response.status_code == 302, role
        assert response.headers["Location"].endswith("/dashboard"), role


def test_an_administrator_without_mfa_must_add_their_key_first(app):
    admin = signed_in(app, "admin1", "administrator", mfa=False)
    assert admin.get("/admin").headers["Location"].endswith("/mfa")  # R08


def test_the_page_offers_every_state_and_staff_role_and_is_not_cached(app):
    from app.security.validators import STATES

    admin = signed_in(app, "admin1", "administrator")
    response = admin.get("/admin")
    body = response.get_data(as_text=True)
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert INLINE_SCRIPT.search(body) is None
    for state in STATES:
        assert f'value="{state}"' in body
    for role in ("aec_employee", "commissioner_delegate", "auditor", "administrator"):
        assert f'value="{role}"' in body
    assert 'id="field-errors"' in body  # where the form shows each field's problem


def test_bad_staff_details_come_back_as_field_errors_and_create_nothing(app):
    from app.models.user import User

    admin = signed_in(app, "admin1", "administrator")
    response = admin.post("/auth/admin/staff", headers=csrf_headers(admin), json={
        "username": "x", "email": "not-an-email", "role": "aec_employee",
        "states": ["VIC"], "temporary_password": "Correct-Horse-42"})
    assert response.status_code == 400
    assert set(response.get_json()["fields"]) == {"username", "email"}
    with app.app_context():
        assert User.query.count() == 1  # only the administrator