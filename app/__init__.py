"""Application factory shared by every subsystem (enrolment, auth, voting, audit)."""
import os
from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
jwt = JWTManager()

# S13: the app refuses to start without these. There are no default values.
REQUIRED_SECRETS = ("SECRET_KEY", "JWT_SECRET_KEY", "DATA_ENC_KEY", "BLIND_INDEX_KEY")


def create_app(test_config=None):
    """Create and configure the Flask app."""
    if test_config is None:
        load_dotenv()  # tests pass their own config and never read your .env

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///evp.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=64 * 1024,  # R06: reject request bodies over 64 KB
        # R21: the JWT lives only in an HttpOnly cookie that JavaScript can't read (S15),
        # is sent only over HTTPS (browsers treat http://localhost as secure), is never
        # sent by other websites (SameSite=Strict) and needs a CSRF token (S16)
        JWT_TOKEN_LOCATION=["cookies"],
        JWT_COOKIE_SECURE=True,
        JWT_COOKIE_SAMESITE="Strict",
        JWT_COOKIE_CSRF_PROTECT=True,
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=15),
        SESSION_IDLE_MINUTES=15,
        SESSION_ABSOLUTE_MINUTES_CITIZEN=120,
        SESSION_ABSOLUTE_MINUTES_STAFF=480,
    )
    for name in REQUIRED_SECRETS:
        app.config[name] = os.environ.get(name)
    if test_config:
        app.config.update(test_config)

    # S13: fail closed (the lab app fell back to "dev-secret-key", which is unsafe)
    for name in REQUIRED_SECRETS:
        if not app.config.get(name):
            raise RuntimeError(f"Missing required setting: {name}")

    db.init_app(app)
    jwt.init_app(app)
    from app.security.shared_security import register_security
    register_security(app) # S03: shared error handlers and security headers

    from app.security.auth_security import create_user_command
    app.cli.add_command(create_user_command) # R09: CLI command to create a test account

    

    # --- Blueprints: each subsystem registers its own here ---
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    with app.app_context():
        from app import models
        db.create_all()

    return app