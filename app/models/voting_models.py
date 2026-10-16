"""Who has voted (entitlements) and what was voted (ballots), kept apart (R17, R18).

The two tables share NO column: no user id, no session, no time, no counter. A ballot
cannot be traced back to the entitlement that was used for it.
"""
import uuid

from app import db

ENTITLEMENT_STATUSES = ("unused", "used")


class VoteEntitlement(db.Model):
    """R17: one right to vote, per person, per contest. Using it is a one-way change."""

    __tablename__ = "vote_entitlements"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    election_id = db.Column(db.String(36), db.ForeignKey("elections.id"), nullable=False)
    contest_id = db.Column(db.String(36), db.ForeignKey("contests.id"), nullable=False)
    contest_type = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="unused")
    # R18: the DAY only, never the time, so it cannot be matched to a ballot's arrival
    used_on = db.Column(db.Date)
    # R17: a retry with the same key gets "already accepted", not a second vote
    idempotency_key_hash = db.Column(db.String(64))

    # R17: the database itself refuses a second entitlement for the same contest
    __table_args__ = (db.UniqueConstraint("user_id", "election_id", "contest_type",
                                          name="uq_one_entitlement_per_contest"),)
