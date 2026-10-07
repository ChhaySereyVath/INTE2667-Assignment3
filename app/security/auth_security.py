"""Authentication logic: accounts, passwords, login checks and sessions (R09, R21)."""
from datetime import timedelta

import bcrypt
import click
from flask import current_app
from flask.cli import with_appcontext
from flask_jwt_extended import create_access_token, get_jti

from app import db
from app.models.auth_models import UserSession
from app.models.user import BCRYPT_ROUNDS, ROLES, User
from app.security.shared_security import utcnow

_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

def authenticate(username, password):
    """Return the User if the username and password are right and the account is active.

    Returns None in every other case, so the caller can't tell WHY it failed (R09).
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        # R09: always do a bcrypt check, even if the username doesn't exist to avoid timing attacks
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