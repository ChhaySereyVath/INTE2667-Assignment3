"""Authentication logic: accounts, passwords, login checks and sessions (R09, R21)."""
import click
import bcrypt
from flask.cli import with_appcontext

from app import db
from app.models.user import BCRYPT_ROUNDS, ROLES, User

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