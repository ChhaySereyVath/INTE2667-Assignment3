import uuid

from app import db
from app.security.shared_security import utcnow


class BallotSeal(db.Model):
    """R19: when polling closes, each contest is sealed: how many ballots it holds and
    a Merkle root (one hash over every ballot), signed with AUDIT_SIGNING_KEY. Any
    ballot altered, removed or added afterwards no longer matches the seal."""

    __tablename__ = "ballot_seals"

    contest_id = db.Column(db.String(36), db.ForeignKey("contests.id"), primary_key=True)
    ballot_count = db.Column(db.Integer, nullable=False)
    merkle_root = db.Column(db.String(64), nullable=False)
    sealed_at = db.Column(db.DateTime, nullable=False)
    signature = db.Column(db.String(128), nullable=False)

    def signed_fields(self):
        return {"contest_id": self.contest_id, "ballot_count": self.ballot_count,
                "merkle_root": self.merkle_root, "sealed_at": self.sealed_at.isoformat()}