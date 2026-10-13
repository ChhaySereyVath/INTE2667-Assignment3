"""Account recovery endpoints: /auth/recovery/... (R10)."""
from flask import Blueprint, jsonify, request

from app.security.recovery_security import confirm_owner, start_recovery, decide, pending_requests
from app.security.validators import EMAIL_RE, POSTCODE_RE, validate
from app.security.shared_security import permission_required

recovery_bp = Blueprint("recovery", __name__)

# R09: the same answer whether or not the details match an account
REQUEST_ACCEPTED = "If those details match an account, we have sent a recovery link."
LINK_INVALID = "This recovery link is not valid, or it has already been used or has expired."

REQUEST_SCHEMA = {
    "username": {"type": str, "required": True, "max": 40},
    "email": {"type": str, "required": True, "pattern": EMAIL_RE, "max": 254},
}

CONFIRM_SCHEMA = {
    "token": {"type": str, "required": True, "max": 100},
    "date_of_birth": {"type": str, "max": 10},
    "postcode": {"type": str, "pattern": POSTCODE_RE},
}

DECISION_SCHEMA = {"decision": {"type": str, "required": True, "enum": ("approved", "rejected")}}

@recovery_bp.route("/request", methods=["POST"])
def request_recovery():
    """Step 1: ask for a recovery link. Always 202, so it cannot find accounts."""
    ok, data, _ = validate(request.get_json(silent=True), REQUEST_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request"}), 400
    start_recovery(data["username"], data["email"])
    return jsonify({"message": REQUEST_ACCEPTED}), 202


@recovery_bp.route("/confirm", methods=["POST"])
def confirm_recovery():
    """Step 2: the owner proves they hold the email (and, if enrolled, their details)."""
    ok, data, _ = validate(request.get_json(silent=True), CONFIRM_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request"}), 400
    outcome = confirm_owner(data["token"], data.get("date_of_birth"), data.get("postcode"))
    if outcome is None:
        return jsonify({"error": LINK_INVALID}), 400
    if outcome == "awaiting_approval":
        return jsonify({"message": "Thanks. An administrator must now approve this recovery. "
                                   "We will email you a reset link when they do.",
                        "status": outcome}), 202
    return jsonify({"message": "Thanks. We have emailed you a link to choose a new password.",
                    "status": outcome}), 200

@recovery_bp.route("/pending", methods=["GET"])
@permission_required("admin:recovery:approve")
def list_pending(current_user):
    """Step 3 queue: staff recoveries waiting for an administrator."""
    return jsonify({"requests": pending_requests()}), 200


@recovery_bp.route("/<request_id>/decision", methods=["POST"])
@permission_required("admin:recovery:approve")
def decide_recovery(current_user, request_id):
    """Step 3: a SEPARATE administrator approves or rejects a staff recovery (R10)."""
    ok, data, _ = validate(request.get_json(silent=True), DECISION_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request"}), 400
    outcome = decide(request_id, current_user, data["decision"])
    if outcome == "self":
        return jsonify({"error": "Access denied"}), 403
    if outcome == "not_found":
        return jsonify({"error": "Not found"}), 404
    return jsonify({"message": f"Recovery {data['decision']}"}), 200