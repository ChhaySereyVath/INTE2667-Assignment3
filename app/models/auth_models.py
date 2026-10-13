"""Models used only by authentication: sessions (R21). Later: throttling, MFA, recovery."""
import uuid

from app import db
from app.security.shared_security import utcnow

class UserSession(db.Model):
    """One row per login. The server can end it at any time, unlike a plain JWT (R21)."""

    __tablename__ = "user_sessions"

    # R21: unpredictable id from the operating system's random generator
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    current_jti = db.Column(db.String(36))  # id of the only token that is valid right now
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    mfa_verified_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_activity_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    absolute_expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime)
    revoke_reason = db.Column(db.String(40))

    def __repr__(self):
        return f"<UserSession {self.id} user={self.user_id}>"

class StaffAssignment(db.Model):
    """R12/R11: which state an AEC employee may work in. Without a row here a
    staff member has a role but no records to use it on (least privilege)."""

    __tablename__ = "staff_assignments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    state = db.Column(db.String(3), nullable=False)
    granted_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    granted_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    __table_args__ = (db.UniqueConstraint("user_id", "state", name="uq_staff_state"),)

def user_states(user):
    """The states this user may act in. Austin's record checks call this (R11)."""
    rows = StaffAssignment.query.filter_by(user_id=user.id).all()
    return tuple(row.state for row in rows)

class Notification(db.Model):
    """R09/R10: the simulated email outbox. In a real deployment this is a mail
    provider; here the row is the message. It holds no PII beyond the user id."""

    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    template = db.Column(db.String(40), nullable=False)
    payload = db.Column(db.Text)  # JSON; treated as sensitive, admin-only
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

class AuthToken(db.Model):
    """Single-use tokens for activation and recovery. Only the SHA-256 hash is
    stored, so a stolen database copy cannot be used to activate accounts."""

    __tablename__ = "auth_tokens"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    purpose = db.Column(db.String(30), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)

class LoginThrottle(db.Model):
    """R09: failed-login counters. The key is a blind index, so this table never
    stores a username or an IP address in readable form (R02)."""

    __tablename__ = "login_throttles"

    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    scope = db.Column(db.String(20), nullable=False)  # account_ip or account
    failures = db.Column(db.Integer, nullable=False, default=0)
    first_failure_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    locked_until = db.Column(db.DateTime)


class WebAuthnCredential(db.Model):
    """R08: a registered security key or passkey. Only the PUBLIC key is stored:
    the private key never leaves the person's device, so a stolen database copy
    cannot be used to sign in."""

    __tablename__ = "webauthn_credentials"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    credential_id = db.Column(db.String(255), nullable=False, unique=True)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_used_at = db.Column(db.DateTime)


class MfaChallenge(db.Model):
    """R08: one random challenge per attempt, tied to one session, valid for two
    minutes and usable once. This is what makes a replayed answer worthless."""

    __tablename__ = "mfa_challenges"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    session_id = db.Column(db.String(36), db.ForeignKey("user_sessions.id"), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)  # register or authenticate
    challenge = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)


class RecoveryRequest(db.Model):
    """R10: one attempt to recover an account, and where it has got to.

    awaiting_owner     the owner has been emailed and must prove they hold the address
    awaiting_approval  staff only: a separate administrator must approve it
    approved           a single-use reset link has been sent to the owner
    completed          the password was reset (and staff keys removed)
    rejected           an administrator refused it
    """

    __tablename__ = "recovery_requests"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="awaiting_owner")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    owner_confirmed_at = db.Column(db.DateTime)
    decided_by = db.Column(db.String(36), db.ForeignKey("users.id"))
    decided_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)