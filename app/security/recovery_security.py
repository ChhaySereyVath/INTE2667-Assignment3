"""R10: strict credential and MFA reset.

A citizen proves two things: they can read the registered email, and (if enrolled)
they know their date of birth and postcode. A staff member proves the email AND a
separate administrator approves, because a staff account is worth more to an
attacker. Every step is single-use and expires, and finishing it ends every session
on the account and tells the owner.
"""
from flask import current_app

from app import db
from app.models.auth_models import RecoveryRequest, WebAuthnCredential
from app.models.user import User
from app.security.auth_security import (issue_token, queue_notification, redeem_token,
                                        revoke_all_sessions, normalize_username)
from app.security.crypto import blind_index
from app.security.shared_security import utcnow


def _latest_request(user, status):
    return (RecoveryRequest.query.filter_by(user_id=user.id, status=status)
            .order_by(RecoveryRequest.created_at.desc()).first())


def start_recovery(username, email):
    """Step 1. Returns nothing: the caller answers the same way whether or not the
    username and email match an account, so it reveals nothing (R09)."""
    user = User.query.filter_by(username=normalize_username(username)).first()
    if user is None or user.status != "active" or user.email_bidx != blind_index(email):
        return
    db.session.add(RecoveryRequest(user_id=user.id, status="awaiting_owner"))
    db.session.commit()
    token = issue_token(user, "recovery", current_app.config["RECOVERY_TOKEN_HOURS"])
    queue_notification(user, "recovery", token=token)


def confirm_owner(token, date_of_birth=None, postcode=None):
    """Step 2: the owner opens the emailed link. Returns 'approved', 'awaiting_approval'
    or None. The emailed token is used up even when the details are wrong, so each
    email allows exactly ONE guess at the date of birth and postcode."""
    user = redeem_token(token, "recovery")
    if user is None:
        return None
    request_row = _latest_request(user, "awaiting_owner")
    if request_row is None:
        return None

    if user.is_privileged:
        # staff have no voter enrolment to check. R10: a SEPARATE administrator approves
        request_row.owner_confirmed_at = utcnow()
        request_row.status = "awaiting_approval"
        db.session.commit()
        return "awaiting_approval"

    from app.models.enrollment_models import Enrolment
    from app.security.enrollment_security import verify_enrolment_details

    enrolled = Enrolment.query.filter_by(user_id=user.id).first() is not None
    if enrolled and not verify_enrolment_details(user, date_of_birth, postcode):
        request_row.status = "rejected"
        db.session.commit()
        queue_notification(user, "recovery_failed")
        return None

    request_row.owner_confirmed_at = utcnow()
    _approve(request_row, user)
    return "approved"



def _approve(request_row, user, decided_by=None):
    request_row.status = "approved"
    request_row.decided_by = decided_by.id if decided_by else None
    request_row.decided_at = utcnow()
    db.session.commit()
    token = issue_token(user, "recovery_reset", current_app.config["RECOVERY_TOKEN_HOURS"])
    queue_notification(user, "recovery_reset", token=token)



def decide(request_id, approver, decision):
    """Step 3, staff only: a separate administrator approves or rejects.
    Returns 'ok', 'self' (refused: own request), or 'not_found'."""
    request_row = db.session.get(RecoveryRequest, str(request_id))
    if request_row is None or request_row.status != "awaiting_approval":
        return "not_found"
    if request_row.user_id == approver.id:
        return "self"  # R10: 'Self-approval is rejected.'
    owner = db.session.get(User, request_row.user_id)
    if decision == "approved":
        _approve(request_row, owner, decided_by=approver)
    else:
        request_row.status = "rejected"
        request_row.decided_by, request_row.decided_at = approver.id, utcnow()
        db.session.commit()
        queue_notification(owner, "recovery_rejected")
    return "ok"


def pending_requests():
    """What the administrator's queue shows: who and when, nothing personal."""
    rows = (RecoveryRequest.query.filter_by(status="awaiting_approval")
            .order_by(RecoveryRequest.created_at).all())
    result = []
    for row in rows:
        owner = db.session.get(User, row.user_id)
        result.append({"id": row.id, "username": owner.username, "role": owner.role,
                       "requested_at": row.created_at.isoformat()})
    return result



def complete_reset(token, new_password):
    """Step 4: set the new password with the single-use reset link. Returns True if done.

    Also removes every security key on a staff account (they must add a new one,
    which is the MFA reset), ends every session, and tells the owner.
    """
    user = redeem_token(token, "recovery_reset")
    if user is None:
        return False
    request_row = _latest_request(user, "approved")
    if request_row is None:
        return False

    user.set_password(new_password)
    WebAuthnCredential.query.filter_by(user_id=user.id).delete()
    request_row.status, request_row.completed_at = "completed", utcnow()
    db.session.commit()
    revoke_all_sessions(user, "recovery")  # R21/R10: old sessions die here
    queue_notification(user, "recovery_completed")
    return True