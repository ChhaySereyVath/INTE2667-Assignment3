"""Enrolment rules: who may touch which record, and the change history (R03, R05, R11)."""
from datetime import date

import click
from flask import abort, current_app
from flask.cli import with_appcontext

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

def change_status(enrolment, actor, new_status):
    """R03: 'Unauthorised workflow transitions are rejected.'

    Returns True if the move was allowed. Also enforces separation of duties: the
    staff member who registered someone cannot be the one who approves them.
    """
    if new_status not in ALLOWED_TRANSITIONS.get(enrolment.status, ()):
        return False
    if new_status == "approved" and enrolment.registered_by == actor.id:
        return False  # maker-checker
    previous, enrolment.status = enrolment.status, new_status
    enrolment.updated_at = utcnow()
    if new_status == "approved":
        enrolment.approved_by = actor.id
    record_change(enrolment, actor, f"status_{new_status}", "status", previous, new_status)
    
    return True

def verify_enrolment_details(user, date_of_birth, postcode):
    """R10: extra identity evidence for account recovery (Ken's recovery calls this).

    True only when this user has an enrolment AND both details match it. The
    comparison takes the same time whether the first character or the last one is
    wrong, so timing does not leak how close a guess was.
    """
    import hmac

    enrolment = Enrolment.query.filter_by(user_id=user.id).first()
    if enrolment is None or not isinstance(date_of_birth, str) or not isinstance(postcode, str):
        return False
    dob_ok = hmac.compare_digest(enrolment.get_field("date_of_birth"), date_of_birth.strip())
    postcode_ok = hmac.compare_digest(enrolment.get_field("postcode"), postcode.strip())
    return dob_ok and postcode_ok


def voting_details_for(user, on_date):
    """R16 hand-over for Yufei's eligibility check: only what the voting side needs.

    Returns whether the person has an APPROVED enrolment, its state, and whether they
    are 18 or over on `on_date`. Their name, address and birth date never leave this
    module (data minimisation), so the voting code has no personal data to leak.
    """
    from app.models.enrollment_models import Enrolment

    enrolment = Enrolment.query.filter_by(user_id=user.id, status="approved").first()
    if enrolment is None:
        return {"enrolled": False, "state": None, "old_enough": False}
    born = date.fromisoformat(enrolment.get_field("date_of_birth"))
    age = on_date.year - born.year - ((on_date.month, on_date.day) < (born.month, born.day))
    return {"enrolled": True, "state": enrolment.state, "old_enough": age >= 18}


def purge_old_history():
    """R05: remove history rows older than the retention period. Returns how many.

    The database trigger (protect_history) allows exactly these rows and no others,
    so even a wrong cutoff here could not delete recent history.
    """
    from datetime import timedelta

    cutoff = utcnow() - timedelta(days=current_app.config["HISTORY_RETENTION_DAYS"])
    count = EnrolmentHistory.query.filter(EnrolmentHistory.created_at < cutoff).delete()
    db.session.commit()
    return count


@click.command("purge-history")
@with_appcontext
def purge_history_command():
    """Delete enrolment history older than the retention period: flask purge-history"""
    count = purge_old_history()
    click.echo(f"Removed {count} history rows older than "
               f"{current_app.config['HISTORY_RETENTION_DAYS']} days.")