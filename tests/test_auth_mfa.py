"""R08: phishing-resistant MFA with WebAuthn, using a software security key."""
from datetime import timedelta

from app.models.auth_models import Notification, UserSession, WebAuthnCredential
from tests.conftest import csrf_headers
from tests.soft_authenticator import SoftAuthenticator
from tests.test_auth_admin import NEW_STAFF
from tests.test_auth_login import login, make_user


def post(client, path, body=None):
    return client.post(path, json=body or {}, headers=csrf_headers(client))


def sign_in_staff(app, client, username="emma", role="aec_employee"):
    with app.app_context():
        make_user(username=username, role=role)
    return login(client, username, "Correct-Horse-42")


def add_key(client, key):
    """Register a security key for the signed-in user. Returns the finish response."""
    options = post(client, "/auth/mfa/register/begin").get_json()["options"]
    return post(client, "/auth/mfa/register/finish", key.register(options))


def pass_mfa(client, key, **answer):
    options = post(client, "/auth/mfa/authenticate/begin").get_json()["options"]
    return post(client, "/auth/mfa/authenticate/finish", key.authenticate(options, **answer))


def session_row(app):
    with app.app_context():
        return UserSession.query.filter_by(revoked_at=None).order_by(UserSession.created_at.desc()).first()


# --- K43 ---

def test_staff_login_says_mfa_is_required(app, client):
    body = sign_in_staff(app, client).get_json()
    assert body["mfa_required"] is True
    assert body["mfa_enrolled"] is False


def test_citizen_login_does_not_ask_for_mfa(app, client):
    with app.app_context():
        make_user()
    body = login(client, "alice", "Correct-Horse-42").get_json()
    assert body["mfa_required"] is False


def test_staff_member_registers_a_first_key(app, client):
    sign_in_staff(app, client)
    key = SoftAuthenticator()
    response = add_key(client, key)
    assert response.status_code == 200
    with app.app_context():
        stored = WebAuthnCredential.query.one()
        # only the PUBLIC key is kept; the private key never leaves the device
        assert stored.public_key and stored.sign_count == 0
        assert Notification.query.filter_by(template="mfa_key_added").count() == 1
    assert session_row(app).mfa_verified is True


def test_registering_a_key_rotates_the_session_token(app, client):
    sign_in_staff(app, client)
    old_token = client.get_cookie("access_token_cookie").value
    add_key(client, SoftAuthenticator())
    assert client.get_cookie("access_token_cookie").value != old_token
    # the old, pre-MFA token no longer works (R21)
    client.set_cookie("access_token_cookie", old_token, secure=True, httponly=True)
    assert client.get("/auth/me").status_code == 401


def test_a_citizen_cannot_use_the_mfa_endpoints(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    assert post(client, "/auth/mfa/register/begin").status_code == 403


def test_a_second_key_needs_a_session_that_already_passed_mfa(app, client):
    """A stolen password must not be enough to add the thief's own key."""
    sign_in_staff(app, client)
    add_key(client, SoftAuthenticator())
    thief = app.test_client()
    login(thief, "emma", "Correct-Horse-42")  # password only
    assert post(thief, "/auth/mfa/register/begin").status_code == 403


def test_a_registration_from_another_website_is_refused(app, client):
    sign_in_staff(app, client)
    options = post(client, "/auth/mfa/register/begin").get_json()["options"]
    answer = SoftAuthenticator().register(options, origin="https://aec-login.example.com")
    assert post(client, "/auth/mfa/register/finish", answer).status_code == 400
    with app.app_context():
        assert WebAuthnCredential.query.count() == 0



# --- K44 ---

def test_staff_login_with_password_and_key_unlocks_privileged_routes(app, client):
    sign_in_staff(app, client, username="admin1", role="administrator")
    key = SoftAuthenticator()
    add_key(client, key)
    client.post("/auth/logout", headers=csrf_headers(client))

    login(client, "admin1", "Correct-Horse-42")
    # R08: password only, so the admin route is refused
    assert post(client, "/auth/admin/staff", NEW_STAFF).status_code == 403
    assert pass_mfa(client, key).status_code == 200
    assert post(client, "/auth/admin/staff", NEW_STAFF).status_code == 201


def test_a_failed_key_check_leaves_the_session_unprivileged(app, client):
    """R08: 'A privileged session is not created when MFA fails.'"""
    sign_in_staff(app, client, username="admin1", role="administrator")
    key = SoftAuthenticator()
    add_key(client, key)
    client.post("/auth/logout", headers=csrf_headers(client))
    login(client, "admin1", "Correct-Horse-42")

    impostor = SoftAuthenticator()
    impostor.credential_id = key.credential_id  # same id, different private key
    assert pass_mfa(client, impostor).status_code == 400
    assert session_row(app).mfa_verified is False
    assert post(client, "/auth/admin/staff", NEW_STAFF).status_code == 403