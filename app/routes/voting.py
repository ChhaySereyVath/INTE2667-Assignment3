"""
Voting subsystem routes — /voting/...
======================================
Implements:
  POST /voting/token        Issue a one-time voting token (Solution 20)
  GET  /voting/ballot       Return the voter's ballot for their electorate
  POST /voting/cast         Cast a vote (atomic, encrypted, integrity-hashed)
  GET  /voting/verify/<rc>  Verify a receipt code (R-19 integrity check)

  
"""

import json
import logging

from flask import Blueprint, g, jsonify, request
from sqlalchemy.exc import IntegrityError

from app import db
from app.models.voting_models import Candidate, VoteAuditLog, VoteRecord, VotingToken
from app.security.crypto import encrypt_field, record_aad
from app.security.shared_security import (
    login_required,
    permission_required,
    utcnow,
)

logger = logging.getLogger(__name__)
voting_bp = Blueprint("voting", __name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_ip() -> str:
    """Return the client IP address for audit logging."""
    return request.remote_addr or "unknown"


def _get_active_voter(current_user):
    """
    Return the voter if they are active, or a JSON error response.
    Citizens must have status='active' to vote; any other status is rejected
    before any DB write. Returns (user, None) on success or (None, response).
    """
    if current_user.status != "active":
        VoteAuditLog.record(
            "ELIGIBILITY_FAIL",
            voter_id   = current_user.id,
            ip_address = _client_ip(),
            reason     = "account_not_active",
        )
        db.session.commit()
        return None, (jsonify({"error": "Account is not active"}), 403)
    return current_user, None


# ---------------------------------------------------------------------------
# POST /voting/token — issue a one-time voting token (Solution 20)
# ---------------------------------------------------------------------------

@voting_bp.route("/token", methods=["POST"])
@permission_required("voting:self:token")
def issue_token(current_user):
    """
    Issue a one-time voting token to the authenticated voter.

    Security controls
    -----------------
    - Voter must be authenticated (login_required inside permission_required).
    - Voter must not have already voted (has_voted flag, checked server-side).
    - Any existing UNUSED token for this voter is expired before a new one
      is issued, preventing token accumulation.
    - The token value is never logged (R-02: PII/sensitive data redaction).
    - All outcomes are recorded in VoteAuditLog.
    """
    voter, err = _get_active_voter(current_user)
    if err:
        return err

    # R-11: server-side double-vote guard (also enforced at DB level via unique FK)
    if getattr(voter, "has_voted", False):
        VoteAuditLog.record(
            "DOUBLE_VOTE_ATTEMPT",
            voter_id   = voter.id,
            ip_address = _client_ip(),
            reason     = "has_voted_flag",
        )
        db.session.commit()
        return jsonify({"error": "Vote already cast"}), 409

    # Expire any existing UNUSED token for this voter before issuing a new one
    existing = db.session.query(VotingToken).filter_by(
        voter_id = voter.id,
        status   = "UNUSED",
    ).first()
    if existing:
        existing.status = "EXPIRED"

    new_token = VotingToken.new_for_voter(voter.id)
    db.session.add(new_token)

    VoteAuditLog.record(
        "TOKEN_ISSUED",
        voter_id   = voter.id,
        ip_address = _client_ip(),
    )

    db.session.commit()

    # Return the token to the voter — it is a one-time credential for the ballot
    return jsonify({
        "token":      new_token.token,
        "expires_at": new_token.expires_at.isoformat() + "Z",
    }), 201


# ---------------------------------------------------------------------------
# GET /voting/ballot — return the voter's ballot for their electorate
# ---------------------------------------------------------------------------

@voting_bp.route("/ballot", methods=["GET"])
@permission_required("voting:self:ballot")
def get_ballot(current_user):
    """
    Return the ballot for the authenticated voter's electorate and state.

    The voter's electorate and state are read from the database (never from
    the request). The request cannot influence which candidates are returned.

    Query parameters
    ----------------
    chamber : "house" or "senate" (required)
    """
    voter, err = _get_active_voter(current_user)
    if err:
        return err

    chamber = request.args.get("chamber", "").lower()
    if chamber not in ("house", "senate"):
        return jsonify({"error": "Invalid request: chamber must be 'house' or 'senate'"}), 400

    # R-11: electorate/state come from the DB — the voter cannot choose their own ballot
    electorate = getattr(voter, "electorate", None)
    state      = getattr(voter, "state", None)

    if not electorate:
        return jsonify({"error": "Enrolment details incomplete"}), 422

    query = db.session.query(Candidate).filter_by(
        chamber    = chamber,
        electorate = electorate,
    )
    if chamber == "senate" and state:
        query = query.filter_by(state=state)

    candidates = query.order_by(Candidate.ballot_order).all()

    return jsonify({
        "chamber":    chamber,
        "electorate": electorate,
        "state":      state,
        "candidates": [c.to_dict() for c in candidates],
    }), 200


# ---------------------------------------------------------------------------
# POST /voting/cast — cast a vote (atomic commit)
# ---------------------------------------------------------------------------

CAST_SCHEMA_REQUIRED = {"token", "chamber", "preferences"}

@voting_bp.route("/cast", methods=["POST"])
@permission_required("voting:self:cast")
def cast_vote(current_user):
    """
    Cast a ballot.

    Request body (JSON)
    -------------------
    {
        "token":       "<one-time voting token>",
        "chamber":     "house" | "senate",
        "preferences": { "<candidate_id>": <preference_number>, ... }
    }

    Response (success 201)
    ----------------------
    { "receipt": "<receipt_code>" }

    Atomic transaction
    ------------------
    All of the following happen in a single db.session.commit() or none:
      1. VotingToken.status → USED
      2. VoteRecord created (encrypted vote + integrity hash)
      3. voter.has_voted → True  (if the column exists on the User model)
      4. VoteAuditLog entry appended

    Security controls
    -----------------
    AT05/06/07/10  ORM only — no raw SQL.
    Solution 20    Token is consumed atomically; replaying the same token
                   fails because status is already USED.
    Solution 11    Vote payload is AES-256-GCM encrypted before storage.
    R-19           SHA-256 integrity hash is stored with every vote record.
    R-11           Server-side voter identity — we use current_user.id, not
                   any ID the client sends in the request body.
    Solution 18    Outcome is recorded in VoteAuditLog regardless of result.
    """
    voter, err = _get_active_voter(current_user)
    if err:
        return err

    # ----- Input validation ------------------------------------------------
    body = request.get_json(silent=True) or {}
    missing = CAST_SCHEMA_REQUIRED - set(body.keys())
    if missing:
        return jsonify({"error": "Invalid request"}), 400

    submitted_token = str(body.get("token", ""))
    chamber         = str(body.get("chamber", "")).lower()
    preferences     = body.get("preferences")

    if chamber not in ("house", "senate"):
        return jsonify({"error": "Invalid request"}), 400
    if not isinstance(preferences, dict) or not preferences:
        return jsonify({"error": "Invalid request"}), 400

    # ----- Double-vote guard (application layer) ---------------------------
    # The DB unique constraint on vote_records.voter_id is the last line of
    # defence; this check is the first so we log the attempt clearly.
    if getattr(voter, "has_voted", False):
        VoteAuditLog.record(
            "DOUBLE_VOTE_ATTEMPT",
            voter_id   = voter.id,
            ip_address = _client_ip(),
            reason     = "has_voted_flag",
        )
        db.session.commit()
        return jsonify({"error": "Vote already cast"}), 409

    # ----- One-time token validation (Solution 20) -------------------------
    token_row = db.session.query(VotingToken).filter_by(voter_id=voter.id).first()

    token_valid = (
        token_row is not None
        and secrets_compare(submitted_token, token_row.token)
        and token_row.is_valid()
    )
    if not token_valid:
        VoteAuditLog.record(
            "INVALID_TOKEN",
            voter_id   = voter.id,
            ip_address = _client_ip(),
        )
        db.session.commit()
        return jsonify({"error": "Invalid or expired token"}), 401

    # ----- Candidate validation (R-11: voter cannot choose their own ballot) -
    electorate = getattr(voter, "electorate", None)
    state      = getattr(voter, "state", None)

    valid_ids = {
        row.id
        for row in db.session.query(Candidate.id).filter_by(
            chamber    = chamber,
            electorate = electorate or "",
        ).all()
    }
    # Convert preference keys to int for comparison
    try:
        pref_ids = {int(k) for k in preferences.keys()}
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid request"}), 400

    if not pref_ids.issubset(valid_ids):
        # Voter submitted preferences for candidates outside their electorate
        VoteAuditLog.record(
            "VOTE_ERROR",
            voter_id   = voter.id,
            ip_address = _client_ip(),
            reason     = "invalid_candidate_ids",
        )
        db.session.commit()
        return jsonify({"error": "Invalid candidates in preferences"}), 422

    # ----- Encrypt the vote payload (Solution 11) ---------------------------
    vote_plaintext = json.dumps({"chamber": chamber, "preferences": preferences})
    aad            = record_aad("vote_records", "encrypted_vote", voter.id)
    try:
        encrypted_vote = encrypt_field(vote_plaintext, aad)
    except Exception:
        logger.exception("Encryption error during vote submission")
        return jsonify({"error": "An unexpected error occurred"}), 500

    # ----- Compute integrity hash (R-19) ------------------------------------
    now            = utcnow()
    receipt_code   = VoteRecord.generate_receipt()
    integrity_hash = VoteRecord.compute_integrity_hash(
        voter_id       = voter.id,
        chamber        = chamber,
        encrypted_vote = encrypted_vote,
        recorded_at    = now,
    )

    # ----- Atomic commit (Solution 20 + R-19 + Solution 18) ----------------
    try:
        # 1. Invalidate the one-time token
        token_row.invalidate()

        # 2. Create the vote record
        vote = VoteRecord(
            voter_id       = voter.id,
            chamber        = chamber,
            encrypted_vote = encrypted_vote,
            integrity_hash = integrity_hash,
            receipt_code   = receipt_code,
            recorded_at    = now,
        )
        db.session.add(vote)

        # 3. Mark the voter as having voted (if the column exists)
        if hasattr(voter, "has_voted"):
            voter.has_voted = True

        # 4. Append audit log entry
        VoteAuditLog.record(
            "VOTE_CAST",
            voter_id   = voter.id,
            ip_address = _client_ip(),
            chamber    = chamber,
            receipt    = receipt_code,
        )

        db.session.commit()

    except IntegrityError:
        db.session.rollback()
        # DB unique constraint fired — double-vote attempt or race condition
        VoteAuditLog.record(
            "DOUBLE_VOTE_ATTEMPT",
            voter_id   = voter.id,
            ip_address = _client_ip(),
            reason     = "integrity_error",
        )
        db.session.commit()
        return jsonify({"error": "Vote already cast"}), 409

    except Exception:
        db.session.rollback()
        logger.exception("Unexpected error during vote commit")
        VoteAuditLog.record(
            "VOTE_ERROR",
            voter_id   = voter.id,
            ip_address = _client_ip(),
            reason     = "commit_failed",
        )
        db.session.commit()
        return jsonify({"error": "An unexpected error occurred"}), 500

    return jsonify({"receipt": receipt_code}), 201


# ---------------------------------------------------------------------------
# GET /voting/verify/<receipt_code> — verify a receipt and integrity (R-19)
# ---------------------------------------------------------------------------

@voting_bp.route("/verify/<receipt_code>", methods=["GET"])
@login_required
def verify_receipt(current_user, receipt_code: str):
    """
    Verify that a receipt code corresponds to a recorded vote and that the
    vote record has not been tampered with (R-19).

    A voter may only verify their own receipt — the receipt_code is looked
    up against the authenticated voter's own VoteRecord. An attacker who
    guesses a receipt code for another voter gets only "not found".

    Response
    --------
    200  { "recorded": true,  "chamber": "...", "tampered": false }
    200  { "recorded": true,  "chamber": "...", "tampered": true  }  ← alert case
    404  { "error": "Not found" }
    """
    if not receipt_code or len(receipt_code) > 128:
        return jsonify({"error": "Not found"}), 404

    vote = db.session.query(VoteRecord).filter_by(
        voter_id     = current_user.id,   # R-11: own record only
        receipt_code = receipt_code,
    ).first()

    if vote is None:
        return jsonify({"error": "Not found"}), 404

    intact = vote.verify_integrity()

    if not intact:
        # Alert — log as a tamper event (R-19)
        VoteAuditLog.record(
            "TAMPER_DETECTED",
            voter_id      = current_user.id,
            ip_address    = _client_ip(),
            vote_record_id = vote.id,
        )
        db.session.commit()

    return jsonify({
        "recorded":    True,
        "chamber":     vote.chamber,
        "recorded_at": vote.recorded_at.isoformat() + "Z",
        "tampered":    not intact,
    }), 200


# ---------------------------------------------------------------------------
# Utility — constant-time string comparison (imported name matches stdlib)
# ---------------------------------------------------------------------------

import secrets as _secrets  # noqa: E402 — import after module body for clarity

def secrets_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return _secrets.compare_digest(
        a.encode("utf-8") if isinstance(a, str) else a,
        b.encode("utf-8") if isinstance(b, str) else b,
    )