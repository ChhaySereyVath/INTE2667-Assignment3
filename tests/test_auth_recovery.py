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