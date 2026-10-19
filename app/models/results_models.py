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

class CountRun(db.Model):
    """One count of one contest. A run whose integrity check failed keeps no result
    and can never be approved (R19)."""

    __tablename__ = "count_runs"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    contest_id = db.Column(db.String(36), db.ForeignKey("contests.id"), nullable=False, index=True)
    run_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # completed | integrity_failed
    result = db.Column(db.Text)  # JSON from the counting functions
    problems = db.Column(db.Text)  # JSON list, for integrity_failed runs
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    approved_by = db.Column(db.String(36), db.ForeignKey("users.id"))
    approved_at = db.Column(db.DateTime)

    def to_dict(self):
        import json

        return {
            "id": self.id,
            "contest_id": self.contest_id,
            "status": self.status,
            "result": json.loads(self.result) if self.result else None,
            "problems": json.loads(self.problems) if self.problems else [],
            "created_at": self.created_at.isoformat(),
            "approved": self.approved_by is not None,
        }

class Exclusion(db.Model):
    """R15: a candidate left out of a recount. Two different delegates are needed:
    one proposes, another confirms. Only confirmed exclusions affect a count."""

    __tablename__ = "exclusions"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    contest_id = db.Column(db.String(36), db.ForeignKey("contests.id"), nullable=False, index=True)
    candidate_id = db.Column(db.String(36), db.ForeignKey("candidates.id"), nullable=False)
    proposed_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    confirmed_by = db.Column(db.String(36), db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)