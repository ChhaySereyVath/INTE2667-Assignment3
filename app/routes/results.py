"""Counts, approvals, exclusions and published results (R15, R19)."""
from flask import Blueprint, g, jsonify, redirect, render_template, request, url_for

from app import db
from app.models.auth_models import user_states
from app.models.election_models import Contest, Election
from app.models.results_models import CountRun
from app.security.results_security import run_count
from app.security.shared_security import has_permission, page_login_required, permission_required
from app.security.signed_actions import recent_mfa_required
from app.security.validators import validate

results_bp = Blueprint("results", __name__)

EXCLUSION_SCHEMA = {"candidate_id": {"type": "uuid", "required": True}}
APPROVAL_REFUSALS = {
    "integrity_failed": ("This count failed its integrity check and cannot be approved.", 409),
    "own_count": ("A different delegate must approve this count.", 403),
    "already_approved": ("A result for this contest is already approved.", 409),
}


def _contest_in_scope(actor, contest_id):
    """A contest the delegate may work on (their states), or None."""
    contest = db.session.get(Contest, contest_id)
    if contest is None or contest.state not in user_states(actor):
        return None
    return contest


@results_bp.route("/contests/<contest_id>/count", methods=["POST"])
@permission_required("count:run")
@recent_mfa_required
def count_contest(current_user, contest_id):
    """R19: count only after polling closes, and only if every ballot verifies."""
    contest = _contest_in_scope(current_user, contest_id)
    if contest is None:
        return jsonify({"error": "Not found"}), 404
    if contest.election.status not in ("polling_closed", "results_published"):
        return jsonify({"error": "Polling has not closed"}), 409
    run = run_count(contest, current_user)
    db.session.commit()
    return jsonify({"count_run": run.to_dict()}), 201 if run.status == "completed" else 409


@results_bp.route("/contests/<contest_id>/count-runs", methods=["GET"])
@permission_required("count:run")
def list_runs(current_user, contest_id):
    contest = _contest_in_scope(current_user, contest_id)
    if contest is None:
        return jsonify({"error": "Not found"}), 404
    runs = CountRun.query.filter_by(contest_id=contest.id).order_by(CountRun.created_at.desc()).all()
    return jsonify({"count_runs": [r.to_dict() for r in runs]}), 200

@results_bp.route("/count-runs/<run_id>/approve", methods=["POST"])
@permission_required("result:approve")
@recent_mfa_required
def approve(current_user, run_id):
    from app.security.results_security import approve_result

    run = db.session.get(CountRun, run_id)
    if run is None or _contest_in_scope(current_user, run.contest_id) is None:
        return jsonify({"error": "Not found"}), 404
    outcome = approve_result(run, current_user)
    db.session.commit()
    if outcome != "approved":
        message, code = APPROVAL_REFUSALS[outcome]
        return jsonify({"error": message}), code
    return jsonify({"count_run": run.to_dict()}), 200


@results_bp.route("/results/<election_id>", methods=["GET"])
def public_results(election_id):
    """Public: approved results of a PUBLISHED election. Nothing before that."""
    from app.security.results_security import published_results

    election = db.session.get(Election, election_id)
    if election is None or election.status != "results_published":
        return jsonify({"error": "Not found"}), 404
    return jsonify({"election": election.name, "contests": published_results(election)}), 200