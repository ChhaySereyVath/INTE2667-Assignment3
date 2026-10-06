"""S13/S03: secure-by-default settings and generic errors shared by every subsystem."""
from datetime import timedelta

import pytest

from app import create_app
from app.security.shared_security import utcnow
from tests.conftest import make_test_config


def test_app_refuses_to_start_without_secret_key():
    with pytest.raises(RuntimeError):
        create_app(make_test_config(SECRET_KEY=""))


def test_app_refuses_to_start_without_jwt_secret_key():
    with pytest.raises(RuntimeError):
        create_app(make_test_config(JWT_SECRET_KEY=None))


def test_unknown_page_gets_a_generic_json_error(client):
    response = client.get("/no-such-page")
    assert response.status_code == 404
    assert response.get_json() == {"error": "Not found"}


def test_security_headers_are_present(client):
    response = client.get("/no-such-page")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_frozen_clock_can_be_moved(frozen_clock):
    start = utcnow()
    frozen_clock.advance(timedelta(minutes=16))
    assert utcnow() - start == timedelta(minutes=16)


def test_crash_returns_generic_500_without_details(app):
    def crash():
        raise ValueError("database password=hunter2 leaked")

    app.add_url_rule("/crash", "crash", crash)
    response = app.test_client().get("/crash")
    assert response.status_code == 500
    assert response.get_json() == {"error": "An unexpected error occurred"}
    assert "hunter2" not in response.get_data(as_text=True)