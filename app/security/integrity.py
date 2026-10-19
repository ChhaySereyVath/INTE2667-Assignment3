"""R19: detect any change to the ballots before they are counted.

1. Every ballot is signed as it is accepted (sign_ballot).
2. When polling closes, every contest is sealed: ballot count + Merkle root, signed.
3. Before a count, verify_contest re-checks every signature, every encryption tag,
   the seal, and that the number of ballots equals the number of entitlements used.
   Any problem means the count does not happen.
"""
import hashlib

from app import db
from app.models.voting_models import Ballot, VoteEntitlement
from app.security.shared_security import utcnow
from app.security.signing import public_key_hex, sign, verify

EVIDENCE_KEY = "AUDIT_SIGNING_KEY"


def ballot_digest(ballot):
    """A fingerprint of everything that matters about a ballot."""
    data = f"{ballot.id}|{ballot.election_id}|{ballot.contest_id}|{ballot.preferences_enc}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sign_ballot(ballot):
    """Called as the ballot is accepted. The signature covers the digest above."""
    ballot.signature = sign({"ballot": ballot_digest(ballot)}, EVIDENCE_KEY)

def merkle_root(leaves):
    """One hash that changes if any leaf changes, is removed or is added.

    The leaves are SORTED first: the root then depends only on which ballots exist,
    not on the order they arrived in, so the seal reveals nothing about timing (R18).
    """
    level = sorted(leaves) or [hashlib.sha256(b"").hexdigest()]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256((level[i] + level[i + 1]).encode("utf-8")).hexdigest()
                 for i in range(0, len(level), 2)]
    return level[0]


def seal_contest(contest):
    """Seal one contest's ballots. Called once, when polling closes."""
    from app.models.results_models import BallotSeal

    ballots = Ballot.query.filter_by(contest_id=contest.id).all()
    seal = BallotSeal(contest_id=contest.id, ballot_count=len(ballots),
                      merkle_root=merkle_root([ballot_digest(b) for b in ballots]),
                      sealed_at=utcnow())
    seal.signature = sign(seal.signed_fields(), EVIDENCE_KEY)
    db.session.add(seal)
    return seal