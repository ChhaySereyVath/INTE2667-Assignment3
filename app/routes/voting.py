"""Voting endpoints: /voting/... (R16, R17, R18).

Direct ballot capture (a polling-place screen) is out of scope for the prototype, so
ballots arrive through this JSON API only, as they would from a polling terminal.
"""
import uuid

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from app import db
from app.models.election_models import CONTEST_TYPES, Election
from app.security.shared_security import has_permission, page_login_required, permission_required
from app.security.validators import validate
from app.security.voting_security import check_eligibility, record_decision

voting_bp = Blueprint("voting", __name__)

# R16: the request names the election and contest, nothing else. A client that adds
# "eligible": true (or anything else) is refused by the validator as an unknown field.
ELIGIBILITY_SCHEMA = {
    "election_id": {"type": "uuid", "required": True},
    "contest_type": {"type": str, "required": True, "enum": CONTEST_TYPES},
}

# what the voter is told for each refusal (never anything about anyone else)
REFUSALS = {
    "polling_not_open": "Voting is not open for this election.",
    "outside_polling_hours": "Voting is not open at this time.",
    "not_enrolled": "You are not enrolled to vote.",
    "under_18": "You must be 18 or older to vote.",
    "not_on_roll_for_this_election": "You are not on the roll for this election.",
    "already_voted": "You have already voted in this contest.",
    "invalid_preferences": "The preferences on this ballot are not valid.",
}


def _election_or_404(election_id):
    election = db.session.get(Election, str(election_id))
    if election is None:
        return None, (jsonify({"error": "Not found"}), 404)
    return election, None


@voting_bp.route("/voting/eligibility", methods=["POST"])
@permission_required("eligibility:self:check")
def eligibility(current_user):
    """R16: may I vote in this contest right now? Checked and recorded on the server."""
    ok, data, errors = validate(request.get_json(silent=True), ELIGIBILITY_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    election, missing = _election_or_404(data["election_id"])
    if missing:
        return missing
    decision = check_eligibility(current_user, election, data["contest_type"])
    record_decision(current_user, election, data["contest_type"], decision)
    db.session.commit()
    return jsonify({"eligible": decision.eligible, "reason": decision.reason,
                    "message": REFUSALS.get(decision.reason, "You may vote in this contest.")}), 200


BALLOT_SCHEMA = dict(ELIGIBILITY_SCHEMA, preferences={"type": list, "required": True, "max": 100})


@voting_bp.route("/voting/ballots", methods=["POST"])
@permission_required("ballot:submit")
def cast_ballot(current_user):
    """R16-R18: cast one ballot. Needs an Idempotency-Key header (a random UUID made by
    the terminal), so a retry after a lost response cannot vote twice."""
    from app.security.voting_security import submit_ballot

    try:
        idempotency_key = str(uuid.UUID(request.headers.get("Idempotency-Key", "")))
    except ValueError:
        return jsonify({"error": "Invalid request",
                        "fields": {"Idempotency-Key": "must be a UUID header"}}), 400
    ok, data, errors = validate(request.get_json(silent=True), BALLOT_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    election, missing = _election_or_404(data["election_id"])
    if missing:
        return missing

    outcome = submit_ballot(current_user, election, data["contest_type"], data["preferences"],
                            idempotency_key)
    # R18: the answer confirms the contest only: no ballot id, no copy of the choices
    if outcome == "accepted":
        return jsonify({"status": "accepted", "contest_type": data["contest_type"]}), 201
    if outcome == "already_accepted":
        return jsonify({"status": "already_accepted", "contest_type": data["contest_type"]}), 200
    if outcome == "invalid_preferences":
        return jsonify({"error": REFUSALS[outcome]}), 400
    if outcome == "already_voted":
        return jsonify({"error": REFUSALS[outcome]}), 409
    return jsonify({"error": REFUSALS[outcome], "reason": outcome}), 403
