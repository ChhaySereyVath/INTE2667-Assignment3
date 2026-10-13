"""R09: registration and activation that never reveal which accounts exist."""
import json
from datetime import timedelta

from app import db
from app.models.auth_models import AuthToken, Notification
from app.models.user import User
from app.security.crypto import decrypt_field, record_aad
from tests.test_auth_login import login, make_user

GOOD = {"username": "newvoter", "email": "new.voter@example.com", "password": "Correct-Horse-42"}


def register(client, **overrides):
    body = dict(GOOD)
    body.update(overrides)
    return client.post("/auth/register", json=body)


def outbox(app, template):
    with app.app_context():
        return Notification.query.filter_by(template=template).all()


def activation_token(app):
    with app.app_context():
        row = Notification.query.filter_by(template="activation").first()
        return json.loads(row.payload)["token"]


def test_the_outbox_holds_no_personal_details(app, client):
    """R02: the simulated email row records who and what, never their details."""
    register(client)
    with app.app_context():
        row = Notification.query.filter_by(template="activation").one()
        text = f"{row.template}{row.payload}"
        assert GOOD["email"] not in text
        assert GOOD["username"] not in text
        assert row.user_id  # the user is referred to by id only


def test_registration_creates_a_pending_account(app, client):
    response = register(client)
    assert response.status_code == 202
    with app.app_context():
        user = User.query.filter_by(username="newvoter").one()
        assert user.status == "pending_activation"
        assert user.role == "citizen"


def test_the_email_address_is_encrypted_and_searchable(app, client):
    register(client)
    with app.app_context():
        user = User.query.filter_by(username="newvoter").one()
        # R01: the stored value is a token, not the address
        assert "new.voter@example.com" not in user.email_enc
        assert decrypt_field(user.email_enc, record_aad("users", "email", user.id)) == GOOD["email"]
        assert len(user.email_bidx) == 64


def test_a_taken_username_gets_the_same_answer_as_a_new_one(app, client):
    first = register(client)
    second = register(client)
    assert first.status_code == second.status_code == 202
    assert first.get_json() == second.get_json()
    with app.app_context():
        assert User.query.filter_by(username="newvoter").count() == 1
    # the owner of the address is warned instead
    assert len(outbox(app, "registration_attempt_existing")) == 1


def test_a_taken_email_with_a_new_username_also_looks_identical(app, client):
    register(client)
    response = register(client, username="someoneelse")
    assert response.status_code == 202
    with app.app_context():
        assert User.query.filter_by(username="someoneelse").first() is None


def test_bad_input_is_rejected_without_echoing_it_back(client):
    assert register(client, username="a").status_code == 400
    assert register(client, email="not-an-email").status_code == 400
    assert register(client, password="short").status_code == 400
    assert register(client, password="administrator").status_code == 400  # too common
    assert register(client, password="newvoter-newvoter").status_code == 400  # has the username
    sneaky = "<script>steal()</script>"
    response = register(client, username=sneaky)
    assert response.status_code == 400
    assert sneaky not in response.get_data(as_text=True)


def test_extra_fields_cannot_set_the_role(app, client):
    response = client.post("/auth/register", json={**GOOD, "role": "administrator"})
    assert response.status_code == 400
    with app.app_context():
        assert User.query.filter_by(username="newvoter").first() is None




def test_a_pending_account_cannot_log_in_until_it_is_activated(app, client):
    register(client)
    assert login(client, "newvoter", GOOD["password"]).status_code == 401
    assert client.post("/auth/activate", json={"token": activation_token(app)}).status_code == 200
    assert login(client, "newvoter", GOOD["password"]).status_code == 200


def test_an_activation_token_works_only_once(app, client):
    register(client)
    token = activation_token(app)
    assert client.post("/auth/activate", json={"token": token}).status_code == 200
    assert client.post("/auth/activate", json={"token": token}).status_code == 400


def test_an_expired_token_is_refused(app, client, frozen_clock):
    register(client)
    token = activation_token(app)
    frozen_clock.advance(timedelta(hours=25))
    assert client.post("/auth/activate", json={"token": token}).status_code == 400


def test_only_the_hash_of_the_token_is_stored(app, client):
    register(client)
    token = activation_token(app)
    with app.app_context():
        row = AuthToken.query.one()
        assert row.token_hash != token
        assert len(row.token_hash) == 64


def test_unknown_and_malformed_tokens_get_one_generic_answer(client):
    for body in ({"token": "nope"}, {"token": ""}, {}, {"token": 5}):
        response = client.post("/auth/activate", json=body)
        assert response.status_code == 400
        assert response.get_json()["error"] == "Invalid request"


def test_the_password_policy_rejects_weak_choices(app):
    from app.security.auth_security import password_problem

    with app.app_context():
        assert password_problem("Correct-Horse-42", "newvoter") is None
        assert password_problem("short", "x") == "must be at least 12 characters"
        assert password_problem("x" * 129, "x") == "must be at most 128 characters"
        # the 12-character rule already stops the short classics
        assert password_problem("qwerty", "x") == "must be at least 12 characters"
        # the blocklist catches the long but obvious ones
        assert password_problem("administrator", "x") == "is too common"
        assert password_problem("ADMINISTRATOR", "x") == "is too common"  # case does not help
        assert password_problem("newvoter-is-me", "newvoter") == "must not contain your username"
        assert password_problem(None, "x") is not None