"""Authentication logic: accounts, passwords, login checks and sessions (R09, R21)."""
import click
from flask.cli import with_appcontext

from app import db
from app.models.user import ROLES, User


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