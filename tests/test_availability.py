"""R06: rate limits, request size limits and the prototype load test (Yufei)."""
import uuid

import pytest

from app import create_app, db
from tests.conftest import csrf_headers, make_test_config
from tests.test_auth_login import login, make_user


@pytest.fixture
def limited_app():
    """The normal test app, but with R06 rate limiting switched ON."""
    app = create_app(make_test_config(RATELIMIT_ENABLED=True))
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


# --- Y05 ---

def test_too_many_requests_get_a_controlled_429(limited_app):
    """R06: 'Excessive requests receive a controlled rejection response.'"""
    client = limited_app.test_client()
    statuses = [client.get("/").status_code for _ in range(301)]
    assert statuses[:300] == [200] * 300
    response = client.get("/")
    assert response.status_code == 429
    assert response.get_json() == {"error": "Too many requests"}
    assert int(response.headers["Retry-After"]) > 0


def test_signed_in_users_are_counted_per_account_not_per_ip(limited_app):
    """R06: 'Requests are rate-limited by IP, account or service identity.'"""
    from app.security.rate_limits import rate_key

    with limited_app.app_context():
        make_user()
    client = limited_app.test_client()
    with limited_app.test_request_context("/"):
        assert rate_key() == "ip:127.0.0.1"
    login(client, "alice", "Correct-Horse-42")
    cookie = client.get_cookie("access_token_cookie").value
    with limited_app.test_request_context("/", headers={"Cookie": f"access_token_cookie={cookie}"}):
        assert rate_key().startswith("user:")
