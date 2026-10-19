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
REQUIRED_SECRETS += ("AUDIT_SIGNING_KEY", "ACTION_SIGNING_KEY")  # Keane: R14, R15, R19 signatures
REQUIRED_SECRETS += ("BALLOT_KEY",)  # Yufei: R01 encryption of ballot preferences


def create_app(test_config=None):
    """Create and configure the Flask app."""
    if test_config is None:
        load_dotenv()  # tests pass their own config and never read your .env

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///evp.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # R06/R17 (Yufei): when two requests write at once, the second WAITS (up to 30 s)
        # for SQLite's lock instead of failing at once with "database is locked"
        SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 30}},
        MAX_CONTENT_LENGTH=64 * 1024,  # R06: reject request bodies over 64 KB
        # R05: one full federal term (3 years) plus a year's margin
        HISTORY_RETENTION_DAYS=4 * 365,
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
        REQUIRE_MFA_FOR_PRIVILEGED=True,
        ACTIVATION_TOKEN_HOURS=24,
        PASSWORD_MIN_LENGTH=12,
        # R09: a wrong password from one computer locks that computer out of that
        # account for 15 minutes. The account-wide limit only ever causes a short
        # delay, so nobody can lock a voter out of their own account for good.
        LOGIN_MAX_FAILURES_PER_IP=5,
        LOGIN_LOCK_MINUTES_PER_IP=15,
        LOGIN_MAX_FAILURES_PER_ACCOUNT=20,
        LOGIN_LOCK_MINUTES_PER_ACCOUNT=5,
        LOGIN_FAILURE_WINDOW_MINUTES=60,
        # R08: WebAuthn. The RP ID is the site's domain; the origin is the exact
        # address the browser shows. A key's answer for any other origin is refused.
        WEBAUTHN_RP_ID="localhost",
        WEBAUTHN_RP_NAME="AEC Voting Platform",
        WEBAUTHN_ORIGIN=os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:5000"),
        MFA_CHALLENGE_SECONDS=120,
        RECOVERY_TOKEN_HOURS=0.5,  # R10: recovery links expire after 30 minutes,
        # R07: where backups and restore reports go, and how long backups are kept
        BACKUP_DIR="backups",
        BACKUP_RETENTION_DAYS=90,
        RESTORE_REPORT_DIR="docs/restore-reports",
        BACKUP_KEY=os.environ.get("BACKUP_KEY"),
        # R14: signed anchors of the audit trail live OUTSIDE the database
        AUDIT_ANCHOR_FILE="anchors/audit-anchors.jsonl",
        # R06: Flask-Limiter reads this. Tests switch it off unless they test R06.
        RATELIMIT_ENABLED=True,
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
    from app.security.redaction import install_redaction
    install_redaction(app)

    from app.security.shared_security import register_security
    register_security(app) # S03: shared error handlers and security headers

    from app.security.tls import make_cert_command
    app.cli.add_command(make_cert_command)

    from app.security.auth_security import create_user_command
    app.cli.add_command(create_user_command) # R09: CLI command to create a test account

    from app.security.auth_security import create_user_command, outbox_command
    app.cli.add_command(create_user_command)
    app.cli.add_command(outbox_command)

    from app.security.backup import backup_command, restore_command, verify_backup_command
    app.cli.add_command(backup_command)
    app.cli.add_command(verify_backup_command)
    app.cli.add_command(restore_command)

    from app.security.election_backup import restore_status_command
    app.cli.add_command(restore_status_command)

    from app.security.enrollment_security import purge_history_command
    app.cli.add_command(purge_history_command)

    from app.security.election_security import seed_election_command
    app.cli.add_command(seed_election_command)

    from app.security.load_test import load_test_command
    app.cli.add_command(load_test_command)

    from app.security.demo_data import demo_voters_command, demo_votes_command
    app.cli.add_command(demo_voters_command)
    app.cli.add_command(demo_votes_command)

    from app.routes.recovery import recovery_bp
    app.register_blueprint(recovery_bp, url_prefix="/auth/recovery")

    from app.security.audit_security import audit_anchor_command, audit_verify_command
    app.cli.add_command(audit_anchor_command)
    app.cli.add_command(audit_verify_command)

    from app.security.signed_actions import verify_actions_command
    app.cli.add_command(verify_actions_command)

    # --- Blueprints: each subsystem registers its own here ---
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    from app.routes.enrollment import enrollment_bp, enrollment_pages_bp
    app.register_blueprint(enrollment_bp, url_prefix="/enrollment")
    app.register_blueprint(enrollment_pages_bp)

    from app.routes.audit import audit_bp
    app.register_blueprint(audit_bp)
    
    from app.routes.elections import elections_bp
    app.register_blueprint(elections_bp)

    from app.routes.voting import voting_bp
    app.register_blueprint(voting_bp)

    from app.routes.candidates import candidates_bp
    app.register_blueprint(candidates_bp)

    from app.routes.pages import pages_bp
    app.register_blueprint(pages_bp)

    from app.security.rate_limits import install_rate_limits
    install_rate_limits(app)

    with app.app_context():
        from app import models
        db.create_all()
        
        from app.models.enrollment_models import protect_history
        protect_history(db.engine, app.config["HISTORY_RETENTION_DAYS"])
        
        from app.models.audit_models import protect_audit
        protect_audit(db.engine)

    return app