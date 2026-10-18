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


# --- Y06 ---

def test_login_attempts_are_limited_per_computer(limited_app):
    """R06: 'Failed-login and automated abuse attempts are throttled.' This is on top
    of Ken's per-account lock: it slows a script trying MANY usernames."""
    client = limited_app.test_client()
    statuses = [client.post("/auth/login", json={"username": f"user{n}", "password": "x" * 12}).status_code
                for n in range(11)]
    assert statuses[:10] == [401] * 10  # ten different usernames, all simply wrong
    assert statuses[10] == 429


def test_registration_and_recovery_are_limited(limited_app):
    client = limited_app.test_client()
    register = [client.post("/auth/register", json={"username": f"new{n}", "email": f"n{n}@example.com",
                                                    "password": "Correct-Horse-42"}).status_code
                for n in range(6)]
    assert register == [202] * 5 + [429]
    recover = [client.post("/auth/recovery/request", json={"username": "x", "email": "x@example.com"}).status_code
               for _ in range(4)]
    assert recover == [202] * 3 + [429]


# --- Y07 ---

def test_parallel_password_guesses_are_all_counted(tmp_path):
    """R06/R09: a script firing guesses in parallel must still hit the lock. Before
    this fix, simultaneous failures could crash (two rows) or overwrite each other's
    count, so 12 parallel guesses could count as 1."""
    import threading

    app = create_app(make_test_config(SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'guess.db'}"))
    with app.app_context():
        make_user()
    statuses = []

    def guess():
        client = app.test_client()
        response = client.post("/auth/login", json={"username": "alice", "password": "wrong-password-1"})
        statuses.append(response.status_code)

    threads = [threading.Thread(target=guess) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert 500 not in statuses
    assert login(app.test_client(), "alice", "Correct-Horse-42").status_code == 429  # locked
    with app.app_context():
        db.engine.dispose()
