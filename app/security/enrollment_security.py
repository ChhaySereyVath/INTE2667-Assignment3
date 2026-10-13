"""Enrolment rules: who may touch which record, and the change history (R03, R05, R11)."""
from flask import abort

from app import db
from app.models.enrollment_models import ALLOWED_TRANSITIONS, Enrolment, EnrolmentHistory
from app.security.crypto import blind_index, encrypt_field, normalise_identity, record_aad
from app.security.shared_security import has_permission, utcnow


def identity_key(given_name, family_name, date_of_birth):
    """R03: the fingerprint that stops one person enrolling twice."""
    return blind_index(normalise_identity(given_name, family_name, date_of_birth))


def can_access(user, action, enrolment):
    """R11: the one place that decides access to an enrolment record.

    Owners reach their own record. Staff reach records in the states they are
    assigned to. Everyone else is refused, including administrators.
    """
    from app.models.auth_models import user_states

    if enrolment is None:
        return False
    if enrolment.user_id == user.id:
        return has_permission(user, f"enrolment:self:{action}")
    if not has_permission(user, f"enrolment:staff:{action}"):
        return False
    return enrolment.state in user_states(user)

def get_scoped_or_404(record_id, user, action):
    """Fetch a record only if this user may use it for this action (R11).

    A record that exists but belongs to someone else answers 404, exactly like one
    that does not exist, so changing the id in a request reveals nothing.
    """
    enrolment = db.session.get(Enrolment, str(record_id))
    if not can_access(user, action, enrolment):
        abort(404)
    return enrolment

def record_change(enrolment, actor, action, field, old_value, new_value):
    """R05: append one history row. Values are encrypted, bound to the row (R01)."""
    row = EnrolmentHistory(enrolment_id=enrolment.id, actor_user_id=actor.id,
                           action=action, field=field)
    db.session.add(row)
    db.session.flush()  # the row needs its id before the values can be bound to it
    row.old_value_enc = encrypt_field(old_value, record_aad("enrolment_history", "old_value", row.id))
    row.new_value_enc = encrypt_field(new_value, record_aad("enrolment_history", "new_value", row.id))
    
    return row