"""R21: sessions are server-side, unpredictable, expire, and end on logout."""
from app import db
from app.models.auth_models import UserSession
from app.security.shared_security import utcnow
from tests.test_auth_login import login, make_user


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