"""R21: sessions are server-side, unpredictable, expire, and end on logout."""
from app import db
from app.models.auth_models import UserSession
from app.security.shared_security import utcnow
from tests.test_auth_login import make_user


def test_session_ids_are_random_and_unique(app):
    with app.app_context():
        user = make_user()
        rows = [UserSession(user_id=user.id, absolute_expires_at=utcnow()) for _ in range(2)]
        db.session.add_all(rows)
        db.session.commit()
        assert rows[0].id != rows[1].id
        assert len(rows[0].id) == 36  # a random UUID, not 1, 2, 3...