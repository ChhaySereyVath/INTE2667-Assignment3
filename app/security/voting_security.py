"""Voting rules: eligibility (R16), one vote per contest (R17), ballot secrecy (R18)."""
import hashlib
import json
import uuid
from collections import namedtuple

from sqlalchemy import update

from app import db
from app.models.voting_models import VoteEntitlement
from app.security.crypto import decrypt_field, encrypt_field
from app.security.enrollment_security import voting_details_for
from app.security.shared_security import utcnow

Decision = namedtuple("Decision", "eligible reason entitlement")


def check_eligibility(user, election, contest_type):
    """R16: decide on the SERVER whether this person may vote in this contest now.

    Every fact comes from our own records and clock. Nothing the browser sends is
    trusted, so a client cannot claim to be eligible. The first failing rule is the
    reason given.
    """
    now = utcnow()
    if election.status != "polling_open":
        return Decision(False, "polling_not_open", None)
    if not election.polling_opens_at <= now < election.polling_closes_at:
        return Decision(False, "outside_polling_hours", None)
    details = voting_details_for(user, now.date())
    if not details["enrolled"]:
        return Decision(False, "not_enrolled", None)
    if not details["old_enough"]:
        return Decision(False, "under_18", None)
    entitlement = VoteEntitlement.query.filter_by(
        user_id=user.id, election_id=election.id, contest_type=contest_type).first()
    if entitlement is None:
        return Decision(False, "not_on_roll_for_this_election", None)
    if entitlement.status == "used":
        return Decision(False, "already_voted", entitlement)
    return Decision(True, "eligible", entitlement)


def record_decision(user, election, contest_type, decision):
    """R16: 'Eligibility decisions are recorded for investigation.'"""
    from app.security.audit_security import append_event

    append_event("eligibility_decision", "success" if decision.eligible else "denied", user,
                 "election", election.id, contest_type=contest_type, reason=decision.reason)
