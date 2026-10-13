"""R09: repeated failed logins are throttled, without locking a voter out for good."""
from datetime import timedelta

from app.models.auth_models import LoginThrottle, Notification
from tests.test_auth_login import login, make_user

PASSWORD = "Correct-Horse-42"


def fail_login(client, times, username="alice"):
    for _ in range(times):
        login(client, username, "wrong-password")


def test_five_wrong_passwords_lock_this_computer_out(app, client):
    with app.app_context():
        make_user()
    fail_login(client, 4)
    assert login(client, "alice", "wrong-password").status_code == 401  # the 5th trips it
    # even the CORRECT password is refused while the lock is on
    response = login(client, "alice", PASSWORD)
    assert response.status_code == 429
    assert response.get_json() == {"error": "Too many requests"}
    assert response.headers["Retry-After"] == "900"


def test_the_lock_expires_by_itself(app, client, frozen_clock):
    with app.app_context():
        make_user()
    fail_login(client, 5)
    assert login(client, "alice", PASSWORD).status_code == 429
    frozen_clock.advance(timedelta(minutes=16))
    assert login(client, "alice", PASSWORD).status_code == 200


def test_a_correct_password_clears_the_counter(app, client, frozen_clock):
    with app.app_context():
        make_user()
    fail_login(client, 4)
    assert login(client, "alice", PASSWORD).status_code == 200
    fail_login(client, 4)  # starting from zero again, so this does not lock
    assert login(client, "alice", PASSWORD).status_code == 200


def test_old_failures_stop_counting(app, client, frozen_clock):
    with app.app_context():
        make_user()
    fail_login(client, 4)
    frozen_clock.advance(timedelta(minutes=61))  # outside the one-hour window
    fail_login(client, 4)
    assert login(client, "alice", PASSWORD).status_code == 200


def test_an_unknown_username_is_throttled_the_same_way(app, client):
    # R09: the throttle must not reveal that the account does not exist
    fail_login(client, 5, username="ghost")
    response = login(client, "ghost", PASSWORD)
    assert response.status_code == 429


def test_the_throttle_table_stores_no_usernames_or_addresses(app, client):
    with app.app_context():
        make_user()
    fail_login(client, 2)
    with app.app_context():
        for row in LoginThrottle.query.all():
            assert "alice" not in row.key_hash  # R02: hashed, not readable
            assert len(row.key_hash) == 64



def test_an_attacker_cannot_lock_a_voter_out_permanently(app, client, frozen_clock):
    """R09: 'cannot be easily abused to permanently lock out voters.'"""
    with app.app_context():
        make_user()
    for round_number in range(8):  # 40 wrong passwords, well past the account limit
        fail_login(client, 5)
        frozen_clock.advance(timedelta(minutes=16))
    # the account-wide lock is short, so the real voter is back in within minutes
    frozen_clock.advance(timedelta(minutes=6))
    assert login(client, "alice", PASSWORD).status_code == 200


def test_the_owner_is_warned_when_the_account_limit_is_reached(app, client, frozen_clock):
    with app.app_context():
        make_user()
    for _ in range(4):
        fail_login(client, 5)
        frozen_clock.advance(timedelta(minutes=16))
    with app.app_context():
        assert Notification.query.filter_by(template="login_attempts_alert").count() >= 1