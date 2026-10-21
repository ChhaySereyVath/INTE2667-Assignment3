"""Candidate management: /contests/<id>/candidates, /candidates/<id> (R12, R15).

A commissioner delegate manages candidates in the states they are assigned to, and
only while nominations are open. Every change, and every refused attempt, becomes a
signed record that names the verified person who made it.
"""
import re

from flask import Blueprint, jsonify, request

from app import db
from app.models.auth_models import user_states
from app.models.election_models import Candidate, Contest
from app.security.shared_security import permission_required
from app.security.signed_actions import record_signed_action, recent_mfa_required
from app.security.validators import NAME_RE, validate

candidates_bp = Blueprint("candidates", __name__)

PARTY_RE = re.compile(r"[A-Za-z0-9À-ÖØ-öø-ÿ&' .-]{2,60}")
CANDIDATE_SCHEMA = {
    "name": {"type": str, "required": True, "pattern": NAME_RE},
    "party": {"type": str, "required": True, "pattern": PARTY_RE},
}
EDITABLE = ("draft", "nominations_open")


def _refuse(actor, action, contest, candidate_id, reason):
    """R15: a refused attempt is signed and kept too, so it can be investigated."""
    record_signed_action(actor, action, "contest", contest.id if contest else None,
                         {"candidate_id": candidate_id, "reason": reason}, "denied")
    db.session.commit()


def _check(actor, contest, action, candidate_id=None):
    """Same rule for every candidate change. Returns an error response or None."""
    if contest is None:
        return jsonify({"error": "Not found"}), 404
    if contest.state not in user_states(actor):
        _refuse(actor, action, contest, candidate_id, "outside your states")
        return jsonify({"error": "Not found"}), 404  # R11-style: no hint the contest exists
    if contest.election.status not in EDITABLE:
        _refuse(actor, action, contest, candidate_id, "nominations closed")
        return jsonify({"error": "Nominations are closed for this election"}), 409
    return None


@candidates_bp.route("/contests/<contest_id>/candidates", methods=["POST"])
@permission_required("candidate:manage")
@recent_mfa_required
def add_candidate(current_user, contest_id):
    ok, data, errors = validate(request.get_json(silent=True), CANDIDATE_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    contest = db.session.get(Contest, contest_id)
    refused = _check(current_user, contest, "candidate_create")
    if refused:
        return refused
    candidate = Candidate(contest_id=contest.id, name=data["name"], party=data["party"],
                          ballot_position=len(contest.candidates) + 1)
    db.session.add(candidate)
    db.session.flush()
    record_signed_action(current_user, "candidate_create", "candidate", candidate.id,
                         {"contest_id": contest.id, "name": candidate.name, "party": candidate.party,
                          "ballot_position": candidate.ballot_position}, "success")
    db.session.commit()
    return jsonify({"candidate": candidate.to_dict()}), 201

@candidates_bp.route("/candidates/<candidate_id>", methods=["PATCH"])
@permission_required("candidate:manage")
@recent_mfa_required
def edit_candidate(current_user, candidate_id):
    ok, data, errors = validate(request.get_json(silent=True), CANDIDATE_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    candidate = db.session.get(Candidate, candidate_id)
    refused = _check(current_user, candidate.contest if candidate else None, "candidate_update", candidate_id)
    if refused:
        return refused
    before = {"name": candidate.name, "party": candidate.party}
    candidate.name, candidate.party = data["name"], data["party"]
    record_signed_action(current_user, "candidate_update", "candidate", candidate.id,
                         {"before": before, "after": data}, "success")
    db.session.commit()
    return jsonify({"candidate": candidate.to_dict()}), 200


@candidates_bp.route("/candidates/<candidate_id>/withdraw", methods=["POST"])
@permission_required("candidate:manage")
@recent_mfa_required
def withdraw_candidate(current_user, candidate_id):
    candidate = db.session.get(Candidate, candidate_id)
    refused = _check(current_user, candidate.contest if candidate else None, "candidate_withdraw", candidate_id)
    if refused:
        return refused
    candidate.withdrawn = True
    record_signed_action(current_user, "candidate_withdraw", "candidate", candidate.id,
                         {"name": candidate.name}, "success")
    db.session.commit()
    return jsonify({"message": "Candidate withdrawn"}), 200