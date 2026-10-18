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


# --- casting a ballot ---------------------------------------------------------

def ballot_aad(ballot_id, contest_id):
    """R01/R19: binds the encrypted preferences to ONE ballot in ONE contest, so a
    ciphertext copied onto another ballot row will not decrypt."""
    return f"ballots:preferences:{ballot_id}:{contest_id}"


def read_preferences(ballot):
    """Decrypt a ballot's preferences (counting only)."""
    return json.loads(decrypt_field(ballot.preferences_enc, ballot_aad(ballot.id, ballot.contest_id),
                                    key_name="BALLOT_KEY"))


def _key_hash(user, idempotency_key):
    return hashlib.sha256(f"{user.id}:{idempotency_key}".encode("utf-8")).hexdigest()


def submit_ballot(user, election, contest_type, preferences, idempotency_key):
    """R17: use the entitlement and store the ballot in ONE transaction.

    Returns "accepted", "already_accepted" (a retry of the same submission), or the
    reason it was refused.
    """
    decision = check_eligibility(user, election, contest_type)
    key_hash = _key_hash(user, idempotency_key)
    if decision.reason == "already_voted" and decision.entitlement.idempotency_key_hash == key_hash:
        return "already_accepted"  # R17: a retried or replayed request makes no second vote
    if not decision.eligible:
        record_decision(user, election, contest_type, decision)
        db.session.commit()
        return decision.reason

    if not preferences_are_valid(decision.entitlement.contest_id, preferences):
        return "invalid_preferences"

    # R17: the WHERE status = 'unused' makes this a compare-and-swap. If two requests
    # race, the database lets exactly one of them change the row; the other changes
    # nothing (rowcount 0) and is refused.
    used = db.session.execute(
        update(VoteEntitlement)
        .where(VoteEntitlement.id == decision.entitlement.id, VoteEntitlement.status == "unused")
        .values(status="used", used_on=utcnow().date(), idempotency_key_hash=key_hash)
    )
    if used.rowcount != 1:
        db.session.rollback()
        return "already_voted"

    from app.models.voting_models import Ballot

    ballot_id = str(uuid.uuid4())
    contest_id = decision.entitlement.contest_id
    ballot = Ballot(id=ballot_id, election_id=election.id, contest_id=contest_id,
                    preferences_enc=encrypt_field(json.dumps(preferences),
                                                  ballot_aad(ballot_id, contest_id),
                                                  key_name="BALLOT_KEY"))
    db.session.add(ballot)
    from app.security.audit_security import append_event

    # R13/R18: the trail records THAT this person voted in a contest, never the
    # ballot's id or its choices
    append_event("ballot_accepted", "success", user, "election", election.id, contest_type=contest_type)
    db.session.commit()  # R17/R20: success is reported only after this commit
    return "accepted"


def preferences_are_valid(contest_id, preferences):
    """R04: a ranked list of candidates standing in THIS contest, each at most once."""
    from app.models.election_models import Candidate

    standing = {c.id for c in Candidate.query.filter_by(contest_id=contest_id, withdrawn=False)}
    return (isinstance(preferences, list) and 0 < len(preferences) <= len(standing)
            and all(isinstance(p, str) for p in preferences)
            and len(set(preferences)) == len(preferences)
            and set(preferences) <= standing)
