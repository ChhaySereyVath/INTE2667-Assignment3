"""R21: sessions are server-side, unpredictable, expire, and end on logout."""
from app import db
from app.models.auth_models import UserSession
from app.security.shared_security import utcnow
from tests.test_auth_login import login, make_user
from datetime import timedelta
from tests.conftest import TEST_ORIGIN, csrf_headers


def test_session_ids_are_random_and_unique(app):
    with app.app_context():
        user = make_user()
        rows = [UserSession(user_id=user.id, absolute_expires_at=utcnow()) for _ in range(2)]
        db.session.add_all(rows)
        db.session.commit()
        assert rows[0].id != rows[1].id
        assert len(rows[0].id) == 36  # a random UUID, not 1, 2, 3...


def test_login_sets_httponly_secure_strict_cookie(app, client):
    with app.app_context():
        make_user()
    response = login(client, "alice", "Correct-Horse-42")
    cookies = response.headers.getlist("Set-Cookie")
    access = next(c for c in cookies if c.startswith("access_token_cookie="))
    assert "HttpOnly" in access
    assert "Secure" in access
    assert "SameSite=Strict" in access
    # the CSRF cookie must be readable by JavaScript, so it is NOT HttpOnly
    csrf = next(c for c in cookies if c.startswith("csrf_access_token="))
    assert "HttpOnly" not in csrf


def test_login_creates_a_server_side_session(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    with app.app_context():
        session_row = db.session.query(UserSession).one()
        assert session_row.revoked_at is None
        assert session_row.current_jti is not None

def test_me_needs_login(client):
    response = client.get("/auth/me")
    assert response.status_code == 401
    assert response.get_json() == {"error": "Authentication required"}


def test_me_works_after_login(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.get_json()["user"]["username"] == "alice"



def test_session_expires_after_15_idle_minutes(app, client, frozen_clock):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    frozen_clock.advance(timedelta(minutes=14))
    assert client.get("/auth/me").status_code == 200  # activity restarts the idle timer
    frozen_clock.advance(timedelta(minutes=16))
    assert client.get("/auth/me").status_code == 401


def test_session_has_an_absolute_limit_even_when_active(app, client, frozen_clock):
    with app.app_context():
        make_user()  # a citizen: 120-minute absolute limit
    login(client, "alice", "Correct-Horse-42")
    for _ in range(11):  # active every 10 minutes for 110 minutes
        frozen_clock.advance(timedelta(minutes=10))
        assert client.get("/auth/me").status_code == 200
    frozen_clock.advance(timedelta(minutes=10))  # now 120 minutes after login
    assert client.get("/auth/me").status_code == 401



def test_logout_needs_the_csrf_token(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    # a correct Origin but no X-CSRF-TOKEN header: the CSRF check alone must refuse it (S16)
    assert client.post("/auth/logout", headers={"Origin": TEST_ORIGIN}).status_code == 401
    assert client.get("/auth/me").status_code == 200  # still logged in

def test_logout_ends_the_session_on_the_server(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    stolen_token = client.get_cookie("access_token_cookie").value

    response = client.post("/auth/logout", headers=csrf_headers(client))
    assert response.status_code == 200
    assert response.headers["Clear-Site-Data"] == '"cookies", "storage"'

    # Replaying the old cookie must fail: the session is revoked on the server
    client.set_cookie("access_token_cookie", stolen_token, secure=True, httponly=True)
    assert client.get("/auth/me").status_code == 401



def test_rotating_a_session_invalidates_the_previous_token(app, client):
    """R21: 'Session identifiers rotate after login and privilege changes.'"""
    from app.security.auth_security import rotate_session

    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    with app.app_context():
        row = UserSession.query.one()
        session_id, deadline = row.id, row.absolute_expires_at
        new_token = rotate_session(row, mfa_verified=True)

    assert client.get("/auth/me").status_code == 401  # the old cookie is dead
    client.set_cookie("access_token_cookie", new_token, secure=True, httponly=True)
    assert client.get("/auth/me").status_code == 200

    with app.app_context():
        row = UserSession.query.one()
        assert row.mfa_verified is True
        # rotation must not extend the absolute deadline
        assert row.id == session_id and row.absolute_expires_at == deadline



def test_revoking_all_sessions_signs_out_every_device(app):
    from app.models.user import User
    from app.security.auth_security import revoke_all_sessions

    with app.app_context():
        make_user()
    phone, laptop = app.test_client(), app.test_client()
    login(phone, "alice", "Correct-Horse-42")
    login(laptop, "alice", "Correct-Horse-42")
    assert phone.get("/auth/me").status_code == 200
    assert laptop.get("/auth/me").status_code == 200

    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        assert revoke_all_sessions(alice, "tested") == 2
    assert phone.get("/auth/me").status_code == 401
    assert laptop.get("/auth/me").status_code == 401



def test_a_state_changing_request_from_another_site_is_refused(app, client):
    """R21: 'State-changing requests require valid CSRF or request-origin evidence.'"""
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    headers = csrf_headers(client)
    headers["Origin"] = "https://evil.example.com"
    assert client.post("/auth/logout", headers=headers).status_code == 403
    assert client.get("/auth/me").status_code == 200  # still signed in


def test_a_state_changing_request_with_no_origin_is_refused(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    token = client.get_cookie("csrf_access_token").value
    assert client.post("/auth/logout", headers={"X-CSRF-TOKEN": token}).status_code == 403
    assert client.get("/auth/me").status_code == 200