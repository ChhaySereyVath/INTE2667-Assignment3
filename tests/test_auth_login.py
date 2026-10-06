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