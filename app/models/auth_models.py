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