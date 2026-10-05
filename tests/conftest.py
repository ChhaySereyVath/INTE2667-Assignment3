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