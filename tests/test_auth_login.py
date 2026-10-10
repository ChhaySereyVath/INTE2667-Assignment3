"""R09: users must authenticate; passwords are never stored in plaintext."""
from app import db
from app.models.user import User


def make_user(username="alice", password="Correct-Horse-42", role="citizen", status="active"):
    user = User(username=username, role=role, status=status)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def test_password_is_stored_as_bcrypt_hash(app):
    with app.app_context():
        user = make_user()
        assert user.password_hash != "Correct-Horse-42"
        assert user.password_hash.startswith("$2b$12$")
        assert user.check_password("Correct-Horse-42")
        assert not user.check_password("wrong-password")


def test_to_dict_never_contains_the_hash(app):
    with app.app_context():
        data = make_user().to_dict()
        assert "password_hash" not in data
        assert set(data) == {"id", "username", "role", "status"}


def test_create_user_command_makes_an_active_account(app):
    runner = app.test_cli_runner()
    result = runner.invoke(
        args=["create-user", "bob", "--role", "aec_employee"],
        input="Correct-Horse-42\nCorrect-Horse-42\n",
    )
    assert result.exit_code == 0
    with app.app_context():
        bob = User.query.filter_by(username="bob").first()
        assert bob.role == "aec_employee"
        assert bob.status == "active"
        assert bob.check_password("Correct-Horse-42")

def login(client, username, password):
    # a browser always sends Origin on a fetch POST, so the helper does too (R21)
    return client.post(
        "/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": "https://localhost"},
    )


def test_correct_login_succeeds(app, client):
    with app.app_context():
        make_user()
    response = login(client, "alice", "Correct-Horse-42")
    assert response.status_code == 200
    assert response.get_json()["user"]["username"] == "alice"


def test_wrong_password_and_unknown_user_look_the_same(app, client):
    with app.app_context():
        make_user()
    wrong_password = login(client, "alice", "not-the-password")
    unknown_user = login(client, "nobody", "not-the-password")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.get_json() == unknown_user.get_json() == {"error": "Invalid credentials"}


def test_inactive_accounts_cannot_log_in_and_look_the_same(app, client):
    with app.app_context():
        make_user(username="pending", status="pending_activation")
        make_user(username="blocked", status="disabled")
    for username in ("pending", "blocked"):
        response = login(client, username, "Correct-Horse-42")
        assert response.status_code == 401
        assert response.get_json() == {"error": "Invalid credentials"}


def test_malformed_login_requests_are_rejected(client):
    assert client.post("/auth/login", data="not json").status_code == 400
    assert client.post("/auth/login", json=["a", "list"]).status_code == 400
    assert login(client, 123, "x").status_code == 400
    assert login(client, "a" * 41, "x").status_code == 400