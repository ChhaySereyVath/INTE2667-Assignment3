"""Election endpoints and page: /elections/... (R12, R16, R17).

Commissioner delegates create elections and move them through their workflow.
Anyone signed in may read them: contests and candidates are public information.
"""
from flask import Blueprint, g, jsonify, redirect, render_template, request, url_for

from app import db
from app.models.election_models import ELECTION_STATUSES, Election
from app.security.election_security import change_election_status, create_election
from app.security.shared_security import (has_permission, login_required, page_login_required,
                                          permission_required)
from app.security.validators import validate

elections_bp = Blueprint("elections", __name__)

ELECTION_SCHEMA = {
    "name": {"type": str, "required": True, "min": 3, "max": 100},
    "polling_opens_at": {"type": "datetime", "required": True},
    "polling_closes_at": {"type": "datetime", "required": True},
}
STATUS_SCHEMA = {"status": {"type": str, "required": True, "enum": ELECTION_STATUSES}}


@elections_bp.route("/elections", methods=["GET"])
@login_required
def list_elections(current_user):
    """Every election, newest first. No voter data is involved."""
    elections = Election.query.order_by(Election.created_at.desc()).all()
    return jsonify({"elections": [e.to_dict() for e in elections]}), 200


@elections_bp.route("/elections/<election_id>", methods=["GET"])
@login_required
def get_election(current_user, election_id):
    """One election with its contests and candidates (what a ballot paper shows)."""
    election = db.session.get(Election, election_id)
    if election is None:
        return jsonify({"error": "Not found"}), 404
    data = election.to_dict()
    data["contests"] = [c.to_dict() for c in election.contests]
    return jsonify({"election": data}), 200


@elections_bp.route("/elections", methods=["POST"])
@permission_required("election:manage")
def new_election(current_user):
    """R12: only a commissioner delegate (with MFA) creates an election."""
    ok, data, errors = validate(request.get_json(silent=True), ELECTION_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    if data["polling_closes_at"] <= data["polling_opens_at"]:
        return jsonify({"error": "Invalid request",
                        "fields": {"polling_closes_at": "must be after polling opens"}}), 400
    election = create_election(current_user, data["name"], data["polling_opens_at"],
                               data["polling_closes_at"])
    db.session.commit()
    return jsonify({"election": election.to_dict()}), 201


@elections_bp.route("/elections/<election_id>/status", methods=["POST"])
@permission_required("election:manage")
def set_status(current_user, election_id):
    """Move the election one step along its workflow. Skipping a step is refused."""
    ok, data, errors = validate(request.get_json(silent=True), STATUS_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    election = db.session.get(Election, election_id)
    if election is None:
        return jsonify({"error": "Not found"}), 404
    if not change_election_status(election, current_user, data["status"]):
        return jsonify({"error": "That change is not allowed from the current status"}), 409
    db.session.commit()
    return jsonify({"election": election.to_dict()}), 200


@elections_bp.route("/elections-admin")
@page_login_required
def elections_page(current_user):
    """The delegate's election screen. The API above enforces everything again."""
    if not has_permission(current_user, "election:manage"):
        return redirect(url_for("pages.dashboard"))
    return render_template("elections/elections.html")


@elections_bp.app_context_processor
def election_links():
    """Dashboard links for this subsystem, without editing pages.py."""
    user = g.get("page_user")
    return {
        "can_manage_elections": user is not None and has_permission(user, "election:manage"),
        "can_vote": user is not None and has_permission(user, "eligibility:self:check"),
    }
