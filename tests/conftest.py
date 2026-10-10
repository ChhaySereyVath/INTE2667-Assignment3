"""Shared pytest fixtures. Every test gets a fresh app and an empty in-memory database."""
import secrets
from datetime import datetime

import pytest

from app import create_app, db
from app.security.shared_security import clock


def make_test_config(**overrides):
    """Settings for a test app: random keys every run, in-memory SQLite, HTTPS test client."""
    config = {
        "TESTING": True,
        "SECRET_KEY": secrets.token_hex(32),
        "JWT_SECRET_KEY": secrets.token_hex(32),
        "DATA_ENC_KEY": secrets.token_hex(32),
        "BLIND_INDEX_KEY": secrets.token_hex(32),
        "SQLALCHEMY_DATABASE_URI": "sqlite://",  # in memory: nothing is written to disk
        "PREFERRED_URL_SCHEME": "https",  # the test client uses https, so Secure cookies work
    }
    config.update(overrides)
    return config


@pytest.fixture
def app():
    app = create_app(make_test_config())
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def frozen_clock():
    """Freeze utcnow() at a fixed time; move it with frozen_clock.advance(timedelta(...))."""
    clock.freeze(datetime(2026, 5, 2, 9, 0, 0))
    yield clock
    clock.unfreeze()

def csrf_headers(client):
    """Header that POST/PUT/PATCH/DELETE requests need after login (double-submit CSRF, S16)."""
    cookie = client.get_cookie("csrf_access_token")
    return {"X-CSRF-TOKEN": cookie.value}



def verify_mfa(app):
    """Mark every live session as MFA-verified.

    Round 3 builds the real WebAuthn flow (R08). Until then, tests for staff and
    admin routes use this to say "this session passed MFA".
    """
    from app import db
    from app.models.auth_models import UserSession
    from app.security.shared_security import utcnow

    with app.app_context():
        for row in UserSession.query.filter_by(revoked_at=None).all():
            row.mfa_verified = True
            row.mfa_verified_at = utcnow()
        db.session.commit()

# the test client's own address; the Origin check compares against it (R21)
TEST_ORIGIN = "https://localhost"


def csrf_headers(client):
    """Headers a state-changing request needs after login: the CSRF token (S16) and
    an Origin that matches our own site (R21)."""
    cookie = client.get_cookie("csrf_access_token")
    return {"X-CSRF-TOKEN": cookie.value, "Origin": TEST_ORIGIN}