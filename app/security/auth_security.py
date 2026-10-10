"""Authentication logic: accounts, passwords, login checks and sessions (R09, R21)."""
import hashlib
import json
import secrets
from datetime import timedelta

import bcrypt
import click
from flask import current_app
from flask.cli import with_appcontext
from flask_jwt_extended import create_access_token, get_jti

from app import db
from app.models.auth_models import (AuthToken, LoginThrottle, Notification,
                                    StaffAssignment, UserSession)
from app.models.user import BCRYPT_ROUNDS, ROLES, User
from app.security.crypto import blind_index, encrypt_field, record_aad
from app.security.shared_security import utcnow

# R09: checked against when the username doesn't exist, so a wrong username takes
# as long as a wrong password and the timing doesn't reveal which accounts exist
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=BCRYPT_ROUNDS))


def authenticate(username, password):
    """Return the User if the username and password are right and the account is active.

    Returns None in every other case, so the caller can't tell WHY it failed (R09).
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)
        return None
    if not user.check_password(password):
        return None
    if user.status != "active":
        return None
    return user


def start_session(user):
    """Create a server-side session and a JWT tied to it. Returns the token (R21)."""
    now = utcnow()
    setting = "SESSION_ABSOLUTE_MINUTES_STAFF" if user.is_privileged else "SESSION_ABSOLUTE_MINUTES_CITIZEN"
    session_row = UserSession(
        user_id=user.id,
        created_at=now,
        last_activity_at=now,
        absolute_expires_at=now + timedelta(minutes=current_app.config[setting]),
    )
    db.session.add(session_row)
    db.session.flush()  # gives session_row its id before we build the token

    # S06: the token is signed with JWT_SECRET_KEY. It carries only ids, never roles:
    # roles are always read from the database on the server (R12).
    token = create_access_token(identity=user.id, additional_claims={"sid": session_row.id, "mfa": False})
    session_row.current_jti = get_jti(token)
    db.session.commit()
    return token

@click.command("create-user")
@click.argument("username")
@click.option("--role", default="citizen", type=click.Choice(ROLES), help="Role for the new account")
@with_appcontext
def create_user_command(username, role):
    """Create an active account for testing: flask create-user alice --role administrator"""
    if User.query.filter_by(username=username).first():
        raise click.ClickException("That username is taken")
    # R09: the password is typed at a hidden prompt, never put on the command line
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    user = User(username=username, role=role, status="active")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f"Created {role} account '{username}'")

def queue_notification(user, template, **fields):
    """R09/R10: 'send' a message by writing a row. Keep PII out of the payload."""
    db.session.add(Notification(user_id=user.id, template=template, payload=json.dumps(fields)))
    db.session.commit()

def register_account(username, email, password):
    """Create a pending account and 'email' an activation link.

    Returns nothing: the caller always answers the same way, so a stranger cannot
    learn whether a username or address is already registered (R09).
    """
    email_key = blind_index(email)
    taken = (User.query.filter_by(username=username).first()
             or User.query.filter_by(email_bidx=email_key).first())
    if taken is not None:
        # the address is already in use: warn its owner instead of creating anything
        queue_notification(taken, "registration_attempt_existing")
        return

    user = User(username=username, role="citizen", status="pending_activation", email_bidx=email_key)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()  # gives the row its id, which the encryption is bound to
    user.email_enc = encrypt_field(email, record_aad("users", "email", user.id))
    db.session.commit()

    token = issue_token(user, "activation", current_app.config["ACTIVATION_TOKEN_HOURS"])
    queue_notification(user, "activation", token=token)

def _hash_token(raw):
    return hashlib.sha256(raw.encode("ascii")).hexdigest()

def issue_token(user, purpose, hours):
    """Create a single-use token. Returns the raw value; only its hash is stored."""
    raw = secrets.token_urlsafe(32)
    db.session.add(AuthToken(
        user_id=user.id,
        purpose=purpose,
        token_hash=_hash_token(raw),
        expires_at=utcnow() + timedelta(hours=hours),
    ))
    db.session.commit()
    return raw

def redeem_token(raw, purpose):
    """Return the token's user if it is valid, then mark it used. None otherwise."""
    if not isinstance(raw, str) or not raw:
        return None
    row = AuthToken.query.filter_by(token_hash=_hash_token(raw), purpose=purpose).first()
    now = utcnow()
    if row is None or row.used_at is not None or row.expires_at <= now:
        return None
    row.used_at = now  # single use: a replay finds used_at already set
    user = db.session.get(User, row.user_id)
    db.session.commit()
    return user

# R09: the 12-character minimum already rules out "qwerty" and "password1", so this
# list is for the LONG but obvious choices that would otherwise pass. A real system
# would load a published list of a few hundred thousand.
COMMON_PASSWORDS = frozenset({
    "administrator", "password1234", "passwordpassword", "password12345",
    "qwerty123456", "qwertyuiop123", "letmein12345", "welcome12345",
    "iloveyou1234", "123456789012", "1234567890123", "abcdefghijkl",
    "aecvoting2026", "australia2026", "canberra2026", "electionday",
    "votingsystem", "changemenow12", "trustno1trustno1",
})

def password_problem(password, username=""):
    """Return a short reason the password is unacceptable, or None if it is fine.

    Saying why a PASSWORD is weak is safe: it reveals nothing about which
    accounts exist (R09).
    """
    minimum = current_app.config["PASSWORD_MIN_LENGTH"]
    if not isinstance(password, str) or len(password) < minimum:
        return f"must be at least {minimum} characters"
    if len(password) > 128:
        return "must be at most 128 characters"
    simple = password.strip().lower()
    if simple in COMMON_PASSWORDS:
        return "is too common"
    if username and username.lower() in simple:
        return "must not contain your username"
    return None

def _throttle_row(scope, username, ip):
    """One row per (scope, username, IP). The key is hashed, never readable (R02)."""
    material = f"{scope}|{username.lower()}|{ip if scope == 'account_ip' else ''}"
    key_hash = blind_index(material)
    row = LoginThrottle.query.filter_by(key_hash=key_hash).first()
    if row is None:
        row = LoginThrottle(key_hash=key_hash, scope=scope, failures=0, first_failure_at=utcnow())
        db.session.add(row)
    return row

def _limits(scope):
    if scope == "account_ip":
        return (current_app.config["LOGIN_MAX_FAILURES_PER_IP"],
                current_app.config["LOGIN_LOCK_MINUTES_PER_IP"])
    return (current_app.config["LOGIN_MAX_FAILURES_PER_ACCOUNT"],
            current_app.config["LOGIN_LOCK_MINUTES_PER_ACCOUNT"])

def login_is_locked(username, ip):
    """R09: True while either counter is in its lock period."""
    now = utcnow()
    for scope in ("account_ip", "account"):
        row = _throttle_row(scope, username, ip)
        if row.locked_until is not None and row.locked_until > now:
            return True
    db.session.commit()
    return False

def record_login_failure(username, ip):
    """Count the failure against this computer and against the account."""
    now = utcnow()
    window = timedelta(minutes=current_app.config["LOGIN_FAILURE_WINDOW_MINUTES"])
    for scope in ("account_ip", "account"):
        row = _throttle_row(scope, username, ip)
        if row.locked_until is not None and row.locked_until <= now:
            row.failures, row.locked_until = 0, None  # the lock has expired, start again
        if now - row.first_failure_at > window:
            row.failures, row.first_failure_at = 0, now  # old failures don't count forever
        row.failures += 1
        maximum, lock_minutes = _limits(scope)
        if row.failures >= maximum:
            row.locked_until = now + timedelta(minutes=lock_minutes)
            row.failures = 0
            if scope == "account":
                _alert_account_under_attack(username)
    db.session.commit()

def clear_login_failures(username, ip):
    """A correct password clears the counters for that computer."""
    row = _throttle_row("account_ip", username, ip)
    row.failures, row.locked_until, row.first_failure_at = 0, None, utcnow()
    db.session.commit()

def _alert_account_under_attack(username):
    """R09: tell the owner rather than locking them out permanently."""
    user = User.query.filter_by(username=username).first()
    if user is not None:
        db.session.add(Notification(
            user_id=user.id,
            template="login_attempts_alert",
            payload=json.dumps({"reason": "many failed sign-in attempts"}),
        ))


def rotate_session(session_row, mfa_verified=None):
    """R21: give the session a brand-new token and invalidate the old one.

    Used after a privilege change (MFA step-up, role grant). The session row keeps
    its id and its absolute deadline, so rotation cannot be used to stay signed in
    for ever.
    """
    if mfa_verified is not None:
        session_row.mfa_verified = mfa_verified
        session_row.mfa_verified_at = utcnow() if mfa_verified else None
    token = create_access_token(
        identity=session_row.user_id,
        additional_claims={"sid": session_row.id, "mfa": bool(session_row.mfa_verified)},
    )
    session_row.current_jti = get_jti(token)  # the previous token stops working here
    session_row.last_activity_at = utcnow()
    db.session.commit()
    return token

def revoke_all_sessions(user, reason, except_session_id=None):
    """R21: end every session this user has. Called on role change and recovery."""
    now = utcnow()
    count = 0
    for row in UserSession.query.filter_by(user_id=user.id, revoked_at=None).all():
        if row.id == except_session_id:
            continue
        row.revoked_at, row.revoke_reason = now, reason
        count += 1
    db.session.commit()
    return count

def create_staff_account(created_by, username, email, role, states, temporary_password):
    """R12: only an administrator reaches this, and the new account starts pending."""
    email_key = blind_index(email)
    if (User.query.filter_by(username=username).first()
            or User.query.filter_by(email_bidx=email_key).first()):
        return None  # the caller answers with a generic error

    user = User(username=username, role=role, status="pending_activation", email_bidx=email_key)
    user.set_password(temporary_password)
    db.session.add(user)
    db.session.flush()
    user.email_enc = encrypt_field(email, record_aad("users", "email", user.id))
    for state in states:
        db.session.add(StaffAssignment(user_id=user.id, state=state, granted_by=created_by.id))
    db.session.commit()

    token = issue_token(user, "activation", current_app.config["ACTIVATION_TOKEN_HOURS"])
    queue_notification(user, "activation", token=token)
    return user