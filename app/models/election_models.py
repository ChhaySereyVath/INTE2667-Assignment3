"""Elections, contests and candidates (the public side of an election).

Nothing here is secret: candidate names and parties are printed on the ballot paper.
Who voted is in vote_entitlements and what they chose is in ballots (voting_models),
and those two tables share no column (R18).
"""
import uuid

from app import db
from app.security.shared_security import utcnow

ELECTION_STATUSES = ("draft", "nominations_open", "polling_open", "polling_closed", "results_published")

# R03-style workflow rule for elections: anything not listed is refused
ELECTION_TRANSITIONS = {
    "draft": ("nominations_open",),
    "nominations_open": ("polling_open",),
    "polling_open": ("polling_closed",),
    "polling_closed": ("results_published",),
    "results_published": (),
}

CONTEST_TYPES = ("house", "senate")

# Prototype simplification: one House contest per state (real elections have one per
# division). Senate seats as in a half-Senate election: 6 per state, 2 per territory.
SENATE_SEATS = {"NSW": 6, "VIC": 6, "QLD": 6, "WA": 6, "SA": 6, "TAS": 6, "ACT": 2, "NT": 2}


class Election(db.Model):
    __tablename__ = "elections"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="draft")
    polling_opens_at = db.Column(db.DateTime, nullable=False)
    polling_closes_at = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    contests = db.relationship("Contest", backref="election", order_by="Contest.state")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "polling_opens_at": self.polling_opens_at.isoformat(),
            "polling_closes_at": self.polling_closes_at.isoformat(),
        }


class Contest(db.Model):
    """One House or Senate race in one state."""

    __tablename__ = "contests"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    election_id = db.Column(db.String(36), db.ForeignKey("elections.id"), nullable=False, index=True)
    contest_type = db.Column(db.String(10), nullable=False)
    state = db.Column(db.String(3), nullable=False)
    seats = db.Column(db.Integer, nullable=False)

    candidates = db.relationship("Candidate", backref="contest", order_by="Candidate.ballot_position")

    __table_args__ = (db.UniqueConstraint("election_id", "contest_type", "state", name="uq_contest"),)

    def to_dict(self):
        return {
            "id": self.id,
            "contest_type": self.contest_type,
            "state": self.state,
            "seats": self.seats,
            "candidates": [c.to_dict() for c in self.candidates if not c.withdrawn],
        }


class Candidate(db.Model):
    __tablename__ = "candidates"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    contest_id = db.Column(db.String(36), db.ForeignKey("contests.id"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(60), nullable=False, default="Independent")
    ballot_position = db.Column(db.Integer, nullable=False)
    withdrawn = db.Column(db.Boolean, nullable=False, default=False)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "party": self.party,
                "ballot_position": self.ballot_position}
