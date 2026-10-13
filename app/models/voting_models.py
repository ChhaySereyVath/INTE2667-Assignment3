"""
Voting Subsystem Models
=======================
Implements:
  - One-time voting token           (Solution 20 — one-time voting token + service separation)
  - Encrypted vote storage          (Solution 11 — encryption at rest)
  - Tamper-detection integrity hash (R-19 — detect vote tampering)
  - Append-only audit log           (Solution 18 — WORM secure logging)
  - Candidate ballot data           (functional requirement)

All database access goes through SQLAlchemy ORM — no raw SQL anywhere in
this file. (AT05 countermeasure: parameterised queries by construction)

FK notes
--------
User.id is a String(36) UUID stored in the "users" table.
Every FK here uses db.String(36) to match.
utcnow() from shared_security returns a naive UTC datetime (no tzinfo),
consistent with what SQLite stores.
"""

import hashlib
import json
import secrets

from app import db
from app.security.shared_security import utcnow


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_LIFETIME_MINUTES = 30

class TokenStatus:
    UNUSED  = "UNUSED"
    USED    = "USED"
    EXPIRED = "EXPIRED"

class Chamber:
    HOUSE  = "house"
    SENATE = "senate"


# ---------------------------------------------------------------------------
# VotingToken — one-time token issued before ballot is shown (Solution 20)
# ---------------------------------------------------------------------------

class VotingToken(db.Model):
    """
    One-time voting token issued to an authenticated, enrolled voter.

    Lifecycle
    ---------
    UNUSED  → token is presented with ballot submission
    USED    → atomically invalidated when vote is recorded
    EXPIRED → marked expired if the voter never submitted within 30 minutes

    The token value is cryptographically random (secrets.token_urlsafe).
    Comparison uses secrets.compare_digest to prevent timing attacks.

    DB-level unique constraint on voter_id ensures only one live token
    can exist per voter at a time; this is enforced in addition to the
    application-level has_voted check.
    """
    __tablename__ = "voting_tokens"

    id         = db.Column(db.Integer, primary_key=True)
    voter_id   = db.Column(
                     db.String(36),
                     db.ForeignKey("users.id", ondelete="CASCADE"),
                     unique=True,          # one token per voter at a time
                     nullable=False,
                     index=True,
                 )
    token      = db.Column(db.String(128), unique=True, nullable=False, index=True)
    status     = db.Column(db.String(16), default=TokenStatus.UNUSED, nullable=False)
    issued_at  = db.Column(db.DateTime, default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at    = db.Column(db.DateTime, nullable=True)

    voter = db.relationship("User", backref=db.backref("voting_token", uselist=False))

    @staticmethod
    def generate() -> str:
        """Return a cryptographically secure random token string."""
        return secrets.token_urlsafe(64)  # 64 url-safe bytes → ~86 char string

    @classmethod
    def new_for_voter(cls, voter_id: str) -> "VotingToken":
        """
        Construct a new VotingToken for a voter.
        Caller is responsible for db.session.add() and commit().
        """
        from datetime import timedelta
        return cls(
            voter_id   = voter_id,
            token      = cls.generate(),
            status     = TokenStatus.UNUSED,
            expires_at = utcnow() + timedelta(minutes=TOKEN_LIFETIME_MINUTES),
        )

    def is_valid(self) -> bool:
        """True if the token is unused and has not expired."""
        return self.status == TokenStatus.UNUSED and utcnow() < self.expires_at

    def invalidate(self) -> None:
        """
        Mark the token as USED.
        Must be committed atomically with VoteRecord creation and
        voter.has_voted = True in a single db.session.commit().
        """
        self.status  = TokenStatus.USED
        self.used_at = utcnow()

    def __repr__(self) -> str:
        return f"<VotingToken voter_id={self.voter_id} status={self.status}>"


# ---------------------------------------------------------------------------
# VoteRecord — encrypted ballot + integrity hash (Solution 11 + R-19)
# ---------------------------------------------------------------------------

class VoteRecord(db.Model):
    """
    Stores a cast ballot in encrypted form with a tamper-detection hash.

    Encryption (Solution 11)
    ------------------------
    The vote payload (JSON preference ordering) is encrypted with
    AES-256-GCM (via app.security.crypto.encrypt_field) before being
    written to this table. The plaintext vote is NEVER stored.

    Tamper detection (R-19)
    -----------------------
    A SHA-256 integrity hash is computed over the critical fields at the
    moment of recording:
        SHA-256(voter_id || "|" || chamber || "|" || encrypted_vote || "|" || recorded_at)
    Recomputing and comparing this hash later reveals whether the record
    has been altered after initial storage.

    Receipt (Solution 21)
    ---------------------
    A unique receipt_code is returned to the voter so they can
    independently confirm their vote was recorded without revealing
    the content of their ballot.

    DB enforcement
    --------------
    unique=True on voter_id enforces one-vote-per-voter at the database
    level — a second INSERT for the same voter raises an IntegrityError.
    """
    __tablename__ = "vote_records"

    id             = db.Column(db.Integer, primary_key=True)
    voter_id       = db.Column(
                         db.String(36),
                         db.ForeignKey("users.id", ondelete="CASCADE"),
                         unique=True,      # ONE vote per voter — DB-enforced
                         nullable=False,
                         index=True,
                     )
    chamber        = db.Column(db.String(16), nullable=False)
    # AES-256-GCM ciphertext produced by crypto.encrypt_field(); never plaintext
    encrypted_vote = db.Column(db.Text, nullable=False)
    # SHA-256 hex digest for tamper detection (R-19)
    integrity_hash = db.Column(db.String(64), nullable=False)
    # Returned to voter for independent verification
    receipt_code   = db.Column(db.String(128), unique=True, nullable=False, index=True)
    recorded_at    = db.Column(db.DateTime, default=utcnow, nullable=False)

    voter = db.relationship("User", backref=db.backref("vote_record", uselist=False))

    @staticmethod
    def generate_receipt() -> str:
        """Return a unique, unpredictable receipt code (64-char hex)."""
        return secrets.token_hex(32)

    @staticmethod
    def compute_integrity_hash(
        voter_id: str,
        chamber: str,
        encrypted_vote: str,
        recorded_at,
    ) -> str:
        """
        Compute a SHA-256 integrity hash over the vote's critical fields.

        Called at recording time (stored) and again at verification time
        (recomputed and compared). A mismatch means the record was modified
        after initial storage.

        The fields are joined with '|'. None of the fields may contain '|',
        so there is no ambiguity.
        """
        payload = "|".join([
            str(voter_id),
            chamber,
            encrypted_vote,
            recorded_at.isoformat(),
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """
        Recompute the integrity hash and compare with the stored value.
        Returns True if the record is intact, False if it has been tampered.
        """
        expected = VoteRecord.compute_integrity_hash(
            voter_id       = self.voter_id,
            chamber        = self.chamber,
            encrypted_vote = self.encrypted_vote,
            recorded_at    = self.recorded_at,
        )
        return secrets.compare_digest(expected, self.integrity_hash)

    def __repr__(self) -> str:
        return f"<VoteRecord voter_id={self.voter_id} chamber={self.chamber}>"


# ---------------------------------------------------------------------------
# Candidate — ballot data for House and Senate elections
# ---------------------------------------------------------------------------

class Candidate(db.Model):
    """
    Represents a candidate standing in a House or Senate election.

    Used to:
      - Populate the ballot shown to a voter based on their electorate/state
      - Validate submitted preferences against the actual ballot
        (a voter cannot submit preferences for candidates outside
        their registered electorate — server-side validation)
    """
    __tablename__ = "candidates"

    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(256), nullable=False)
    party        = db.Column(db.String(256), nullable=False)
    electorate   = db.Column(db.String(128), nullable=False, index=True)
    chamber      = db.Column(db.String(16), nullable=False)   # "house" or "senate"
    state        = db.Column(db.String(64), nullable=True, index=True)
    ballot_order = db.Column(db.Integer, nullable=False)
    # Above-the-line group letter for Senate ATL voting (e.g. "A", "B", …)
    party_group  = db.Column(db.String(64), nullable=True)

    def to_dict(self) -> dict:
        """Serialise for API response. Safe to return to the client."""
        return {
            "id":           self.id,
            "name":         self.name,
            "party":        self.party,
            "electorate":   self.electorate,
            "chamber":      self.chamber,
            "state":        self.state,
            "ballot_order": self.ballot_order,
            "party_group":  self.party_group,
        }

    def __repr__(self) -> str:
        return f"<Candidate {self.name} ({self.party}) {self.electorate}>"


# ---------------------------------------------------------------------------
# VoteAuditLog — append-only security event log (Solution 18)
# ---------------------------------------------------------------------------

class VoteAuditLog(db.Model):
    """
    Append-only audit log for all voting-subsystem security events.

    Design principles
    -----------------
    - Entries are NEVER updated or deleted after creation.
    - Every security-relevant event is recorded: token issuance, vote cast,
      double-vote attempts, invalid tokens, tamper alerts, eligibility fails.
    - IP address is recorded for forensic tracing (AT03 countermeasure).
    - In production this table should be backed by WORM storage (Solution 18).

    Event types
    -----------
    TOKEN_ISSUED         — one-time voting token issued
    VOTE_CAST            — ballot successfully recorded
    DOUBLE_VOTE_ATTEMPT  — voter tried to vote after has_voted = True
    INVALID_TOKEN        — invalid, expired, or already-used token presented
    ELIGIBILITY_FAIL     — unenrolled or unknown voter attempted access
    TAMPER_DETECTED      — integrity hash mismatch found on a vote record
    VOTE_ERROR           — unexpected error during vote submission
    """
    __tablename__ = "vote_audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    voter_id   = db.Column(
                     db.String(36),
                     db.ForeignKey("users.id", ondelete="SET NULL"),
                     nullable=True,        # Some events have no associated voter
                     index=True,
                 )
    event_type = db.Column(db.String(64), nullable=False, index=True)
    event_data = db.Column(db.Text, nullable=True)  # JSON string
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp  = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    voter = db.relationship("User", backref=db.backref("vote_audit_logs", lazy="dynamic"))

    @classmethod
    def record(
        cls,
        event_type: str,
        voter_id: str | None = None,
        ip_address: str | None = None,
        **kwargs,
    ) -> "VoteAuditLog":
        """
        Create an audit log entry and add it to the session.
        Caller must commit (usually as part of a larger atomic transaction).

        Extra keyword arguments become the event_data JSON payload.
        Example:
            VoteAuditLog.record("VOTE_CAST", voter_id=uid, ip_address=ip,
                                chamber="house", receipt=code)
        """
        entry = cls(
            voter_id   = voter_id,
            event_type = event_type,
            event_data = json.dumps(kwargs) if kwargs else None,
            ip_address = ip_address,
        )
        db.session.add(entry)
        return entry

    def __repr__(self) -> str:
        return f"<VoteAuditLog {self.event_type} at {self.timestamp}>"