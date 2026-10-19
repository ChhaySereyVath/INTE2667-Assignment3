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