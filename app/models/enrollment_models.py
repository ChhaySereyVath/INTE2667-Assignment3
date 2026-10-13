"""Enrolment records and their change history (R03, R05).

Every personal field is stored encrypted (R01). `state` is the one exception: it is
kept in the clear because staff access is scoped by state (R11), and a state on its
own does not identify anyone.
"""
import uuid

from app import db
from app.security.crypto import decrypt_field, encrypt_field, record_aad
from app.security.shared_security import utcnow

STATUSES = ("pending", "approved", "rejected")

# which status may follow which. Anything not listed here is refused (R03).
ALLOWED_TRANSITIONS = {
    "pending": ("approved", "rejected"),
    "approved": (),
    "rejected": (),
}

ENCRYPTED_FIELDS = ("given_name", "family_name", "date_of_birth", "address_line", "suburb", "postcode")


class Enrolment(db.Model):
    __tablename__ = "enrolments"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, unique=True, index=True)

    given_name_enc = db.Column(db.Text, nullable=False)
    family_name_enc = db.Column(db.Text, nullable=False)
    date_of_birth_enc = db.Column(db.Text, nullable=False)
    # R03: one enrolment per person, even under a different account
    identity_bidx = db.Column(db.String(64), nullable=False, unique=True, index=True)

    address_line_enc = db.Column(db.Text, nullable=False)
    suburb_enc = db.Column(db.Text, nullable=False)
    postcode_enc = db.Column(db.Text, nullable=False)
    state = db.Column(db.String(3), nullable=False, index=True)

    status = db.Column(db.String(20), nullable=False, default="pending")
    registered_by = db.Column(db.String(36), db.ForeignKey("users.id"))
    approved_by = db.Column(db.String(36), db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    def set_field(self, name, value):
        """Encrypt one field, bound to this row and column (R01)."""
        setattr(self, f"{name}_enc", encrypt_field(value, record_aad("enrolments", name, self.id)))

    def get_field(self, name):
        token = getattr(self, f"{name}_enc")
        return decrypt_field(token, record_aad("enrolments", name, self.id))

    def to_dict(self):
        """What the owner of the record is allowed to see."""
        data = {name: self.get_field(name) for name in ENCRYPTED_FIELDS}
        data.update(id=self.id, state=self.state, status=self.status)
        return data

    def summary(self):
        """What a staff member sees in a list: no personal details at all (R02)."""
        return {"id": self.id, "state": self.state, "status": self.status}


class EnrolmentHistory(db.Model):
    """R05: who changed what, when, and from what to what. Append-only in use:
    nothing in the application ever updates or deletes a row here."""

    __tablename__ = "enrolment_history"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    enrolment_id = db.Column(db.String(36), db.ForeignKey("enrolments.id"), nullable=False, index=True)
    actor_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(30), nullable=False)
    field = db.Column(db.String(40), nullable=False)
    # R05: old and new values are personal data, so they are encrypted too
    old_value_enc = db.Column(db.Text)
    new_value_enc = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    def values(self):
        aad_old = record_aad("enrolment_history", "old_value", self.id)
        aad_new = record_aad("enrolment_history", "new_value", self.id)
        return decrypt_field(self.old_value_enc, aad_old), decrypt_field(self.new_value_enc, aad_new)

    def to_dict(self, include_values):
        """R05: 'Sensitive values are visible only to authorised roles.'"""
        data = {
            "id": self.id,
            "actor_user_id": self.actor_user_id,
            "action": self.action,
            "field": self.field,
            "created_at": self.created_at.isoformat(),
        }
        if include_values:
            old, new = self.values()
            data.update(old_value=old, new_value=new)
        return data