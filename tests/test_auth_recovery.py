"""R10: strict credential and MFA reset, with independent approval for staff."""
import json
from datetime import timedelta

import pytest

from app import db
from app.models.auth_models import Notification, RecoveryRequest, WebAuthnCredential
from app.models.user import User
from app.security.crypto import blind_index
from tests.conftest import csrf_headers, verify_mfa
from tests.soft_authenticator import SoftAuthenticator
from tests.test_auth_login import login, make_user
from tests.test_auth_mfa import add_key



NEW_PASSWORD = "Brand-New-Horse-77"

NEEDS_ENROLMENT = pytest.mark.skip(reason="waiting for Austin's Enrolment model and enrol() helper")



def make_account(app, username="alice", role="citizen", email=None):
    """A user with a registered email, which is the recovery evidence (R10)."""
    with app.app_context():
        user = make_user(username=username, role=role)
        user.email_bidx = blind_index(email or f"{username}@example.com")
        db.session.commit()
        return user.id


def ask(client, username="alice", email=None):
    return client.post("/auth/recovery/request",
                       json={"username": username, "email": email or f"{username}@example.com"})


def latest_token(app, template, username="alice"):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        row = (Notification.query.filter_by(user_id=user.id, template=template)
               .order_by(Notification.id.desc()).first())
        return json.loads(row.payload)["token"] if row else None


def confirm(client, token, **details):
    return client.post("/auth/recovery/confirm", json={"token": token, **details})


def reset(client, token, password=NEW_PASSWORD):
    return client.post("/auth/recovery/reset", json={"token": token, "new_password": password})


def admin_client(app, username="admin2"):
    make_account(app, username=username, role="administrator")
    client = app.test_client()
    login(client, username, "Correct-Horse-42")
    verify_mfa(app)
    return client


def pending_id(app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        return RecoveryRequest.query.filter_by(user_id=user.id).one().id

def approved_reset_token(app, username="alice"):
    """Put a request straight into the 'approved' state and return its reset-link token,
    so the reset step is tested on its own, without the enrolment check in step 2."""
    from app.security.auth_security import issue_token

    with app.app_context():
        user = User.query.filter_by(username=username).one()
        db.session.add(RecoveryRequest(user_id=user.id, status="approved"))
        db.session.commit()
        return issue_token(user, "recovery_reset", app.config["RECOVERY_TOKEN_HOURS"])

# --- K47 ---

def test_a_matching_request_emails_a_recovery_link(app, client):
    make_account(app)
    response = ask(client)
    assert response.status_code == 202
    assert latest_token(app, "recovery") is not None


def test_a_wrong_email_or_unknown_user_gets_the_same_answer(app, client):
    make_account(app)
    right = ask(client, email="wrong@example.com")
    ghost = ask(client, username="ghost")
    assert right.status_code == ghost.status_code == 202
    assert right.get_json() == ghost.get_json()
    with app.app_context():
        assert Notification.query.filter_by(template="recovery").count() == 0



# --- K48 ---
@NEEDS_ENROLMENT
def test_a_citizen_without_an_enrolment_gets_a_reset_link(app, client):
    make_account(app)
    ask(client)
    response = confirm(client, latest_token(app, "recovery"))
    assert response.status_code == 200
    assert latest_token(app, "recovery_reset") is not None


@NEEDS_ENROLMENT
def test_an_enrolled_citizen_must_also_know_their_details(app):
    make_account(app)
    voter = app.test_client()
    login(voter, "alice", "Correct-Horse-42")
    enrol(voter)  # born 1990-04-12, postcode 3053

    client = app.test_client()
    ask(client)
    # wrong details: refused, the request is closed and the owner is told
    assert confirm(client, latest_token(app, "recovery"),
                   date_of_birth="1990-04-12", postcode="3000").status_code == 400
    assert latest_token(app, "recovery_reset") is None
    with app.app_context():
        assert Notification.query.filter_by(template="recovery_failed").count() == 1

    # a fresh request with the right details works
    ask(client)
    assert confirm(client, latest_token(app, "recovery"),
                   date_of_birth="1990-04-12", postcode="3053").status_code == 200

@NEEDS_ENROLMENT
def test_each_emailed_link_allows_one_guess(app, client):
    """A wrong guess uses the link up, so details cannot be guessed over and over."""
    make_account(app)
    voter = app.test_client()
    login(voter, "alice", "Correct-Horse-42")
    enrol(voter)
    ask(client)
    token = latest_token(app, "recovery")
    assert confirm(client, token, date_of_birth="1990-01-01", postcode="3053").status_code == 400
    assert confirm(client, token, date_of_birth="1990-04-12", postcode="3053").status_code == 400


def test_the_recovery_link_expires(app, client, frozen_clock):
    make_account(app)
    ask(client)
    token = latest_token(app, "recovery")
    frozen_clock.advance(timedelta(minutes=31))
    assert confirm(client, token).status_code == 400

# --- K49 ---

def test_a_staff_recovery_waits_for_an_administrator(app, client):
    make_account(app, username="emma", role="aec_employee")
    ask(client, username="emma")
    response = confirm(client, latest_token(app, "recovery", "emma"))
    assert response.status_code == 202
    assert response.get_json()["status"] == "awaiting_approval"
    assert latest_token(app, "recovery_reset", "emma") is None  # nothing until approved


def test_a_second_administrator_approves_and_the_owner_gets_the_link(app, client):
    make_account(app, username="emma", role="aec_employee")
    ask(client, username="emma")
    confirm(client, latest_token(app, "recovery", "emma"))

    admin = admin_client(app)
    queue = admin.get("/auth/recovery/pending").get_json()["requests"]
    assert [row["username"] for row in queue] == ["emma"]
    assert set(queue[0]) == {"id", "username", "role", "requested_at"}  # nothing personal
    response = admin.post(f"/auth/recovery/{queue[0]['id']}/decision",
                          json={"decision": "approved"}, headers=csrf_headers(admin))
    assert response.status_code == 200
    assert latest_token(app, "recovery_reset", "emma") is not None


def test_an_administrator_cannot_approve_their_own_recovery(app, client):
    """R10: 'Self-approval is rejected.'"""
    admin = admin_client(app, username="admin1")
    ask(client, username="admin1")
    confirm(client, latest_token(app, "recovery", "admin1"))
    request_id = pending_id(app, "admin1")
    response = admin.post(f"/auth/recovery/{request_id}/decision",
                          json={"decision": "approved"}, headers=csrf_headers(admin))
    assert response.status_code == 403
    assert latest_token(app, "recovery_reset", "admin1") is None


def test_only_administrators_can_approve(app, client):
    make_account(app, username="emma", role="aec_employee")
    ask(client, username="emma")
    confirm(client, latest_token(app, "recovery", "emma"))
    request_id = pending_id(app, "emma")

    make_account(app, username="dana", role="commissioner_delegate")
    dana = app.test_client()
    login(dana, "dana", "Correct-Horse-42")
    verify_mfa(app)
    assert dana.post(f"/auth/recovery/{request_id}/decision", json={"decision": "approved"},
                     headers=csrf_headers(dana)).status_code == 403
    assert dana.get("/auth/recovery/pending").status_code == 403


def test_a_rejected_recovery_sends_no_reset_link(app, client):
    make_account(app, username="emma", role="aec_employee")
    ask(client, username="emma")
    confirm(client, latest_token(app, "recovery", "emma"))
    admin = admin_client(app)
    admin.post(f"/auth/recovery/{pending_id(app, 'emma')}/decision",
               json={"decision": "rejected"}, headers=csrf_headers(admin))
    assert latest_token(app, "recovery_reset", "emma") is None
    with app.app_context():
        assert Notification.query.filter_by(template="recovery_rejected").count() == 1

# --- K50 ---

def test_the_reset_changes_the_password_and_ends_every_session(app, client):
    make_account(app)
    laptop = app.test_client()
    login(laptop, "alice", "Correct-Horse-42")
    assert laptop.get("/auth/me").status_code == 200

    assert reset(client, approved_reset_token(app)).status_code == 200

    assert laptop.get("/auth/me").status_code == 401  # R10: existing sessions revoked
    assert login(client, "alice", "Correct-Horse-42").status_code == 401
    assert login(client, "alice", NEW_PASSWORD).status_code == 200
    with app.app_context():
        assert Notification.query.filter_by(template="recovery_completed").count() == 1


def test_a_staff_reset_removes_their_security_keys(app, client):
    """MFA reset: the old key is gone, so the person must add a new one."""
    make_account(app, username="emma", role="aec_employee")
    staff = app.test_client()
    login(staff, "emma", "Correct-Horse-42")
    add_key(staff, SoftAuthenticator())
    with app.app_context():
        assert WebAuthnCredential.query.count() == 1

    ask(client, username="emma")
    confirm(client, latest_token(app, "recovery", "emma"))
    admin = admin_client(app)
    admin.post(f"/auth/recovery/{pending_id(app, 'emma')}/decision",
               json={"decision": "approved"}, headers=csrf_headers(admin))
    assert reset(client, latest_token(app, "recovery_reset", "emma")).status_code == 200

    with app.app_context():
        assert WebAuthnCredential.query.count() == 0
    body = login(client, "emma", NEW_PASSWORD).get_json()
    assert body["mfa_required"] is True and body["mfa_enrolled"] is False


def test_the_reset_link_works_once(app, client):
    make_account(app)
    token = approved_reset_token(app)
    assert reset(client, token).status_code == 200
    assert reset(client, token, password="Another-New-Horse-88").status_code == 400


def test_a_weak_new_password_does_not_use_up_the_link(app, client):
    make_account(app)
    token = approved_reset_token(app)
    response = reset(client, token, password="administrator")
    assert response.status_code == 400
    assert response.get_json()["fields"] == {"new_password": "is too common"}
    assert reset(client, token).status_code == 200  # the link still works



# --- K51 ---

def test_the_recovery_pages_render_without_inline_scripts(client):
    from tests.test_auth_pages import INLINE_SCRIPT

    for path, form in (("/recover", "recover-request-form"),
                       ("/recover/confirm", "recover-confirm-form"),
                       ("/recover/reset", "recover-reset-form")):
        body = client.get(path).get_data(as_text=True)
        assert f'id="{form}"' in body, path
        assert INLINE_SCRIPT.search(body) is None, path


def test_the_login_page_links_to_recovery(client):
    assert 'href="/recover"' in client.get("/login").get_data(as_text=True)


def test_flask_outbox_prints_working_recovery_links(app, client):
    import re

    make_account(app)
    ask(client)
    output = app.test_cli_runner().invoke(args=["outbox"]).output
    assert re.search(r"/recover/confirm#token=[A-Za-z0-9_-]+", output)