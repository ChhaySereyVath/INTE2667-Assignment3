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
                                        revoke_all_sessions)
from app.security.crypto import blind_index
from app.security.shared_security import utcnow


def _latest_request(user, status):
    return (RecoveryRequest.query.filter_by(user_id=user.id, status=status)
            .order_by(RecoveryRequest.created_at.desc()).first())


def start_recovery(username, email):
    """Step 1. Returns nothing: the caller answers the same way whether or not the
    username and email match an account, so it reveals nothing (R09)."""
    user = User.query.filter_by(username=username).first()
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

    # Austin's enrolment code: only needed once the token and request are valid
    from app.models.enrollment_models import Enrolment
    from app.security.enrollment_security import verify_enrolment_details

    enrolled = Enrolment.query.filter_by(user_id=user.id).first() is not None
    if enrolled and not verify_enrolment_details(user, date_of_birth, postcode):
        request_row.status = "rejected"
        db.session.commit()
        queue_notification(user, "recovery_failed")
        return None

    request_row.owner_confirmed_at = utcnow()
    if user.is_privileged:
        # R10: staff resets need a separate supervisor's approval
        request_row.status = "awaiting_approval"
        db.session.commit()
        return "awaiting_approval"

    _approve(request_row, user)
    return "approved"



def _approve(request_row, user, decided_by=None):
    request_row.status = "approved"
    request_row.decided_by = decided_by.id if decided_by else None
    request_row.decided_at = utcnow()
    db.session.commit()
    token = issue_token(user, "recovery_reset", current_app.config["RECOVERY_TOKEN_HOURS"])
    queue_notification(user, "recovery_reset", token=token)