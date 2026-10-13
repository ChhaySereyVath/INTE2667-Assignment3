"""Shared User model: one account per person. Enrolment and voting add their own columns."""
import uuid
import bcrypt

from app import db
from app.security.shared_security import utcnow

ROLES = ("citizen", "aec_employee", "commissioner_delegate", "administrator", "auditor")
STATUSES = ("pending_activation", "active", "disabled")
BCRYPT_ROUNDS = 12

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="citizen")
    status = db.Column(db.String(20), nullable=False, default="pending_activation")
    # R01: the address itself is encrypted; the blind index is what we search on
    email_enc = db.Column(db.Text)
    email_bidx = db.Column(db.String(64), unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    def set_password(self, password):
        # R09/R01: store only a slow, salted bcrypt hash, never the password itself
        salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")

    def check_password(self, password):
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("ascii"))

    @property
    def is_privileged(self):
        """Staff and admin roles (R08 will require MFA for these)."""
        return self.role != "citizen"

    def to_dict(self):
        # Never include password_hash in anything sent to a client
        return {"id": self.id, "username": self.username, "role": self.role, "status": self.status}

    def __repr__(self):
        return f"<User {self.username}>"