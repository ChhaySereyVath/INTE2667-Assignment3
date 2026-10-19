"""Auditor endpoints and page: /audit/... (R13, R14).

Only the auditor role can read the trail, and only after MFA (R08, R12). Nobody can
change it: there is no endpoint that edits or deletes an event.
"""
from flask import Blueprint, g, jsonify, redirect, render_template, request, url_for

from app.models.audit_models import AUDIT_ACTIONS, AuditEvent
from app.security.audit_security import verify_audit_trail
from app.security.shared_security import has_permission, page_login_required, permission_required

audit_bp = Blueprint("audit", __name__)

PAGE_SIZE = 50


@audit_bp.route("/audit/events", methods=["GET"])
@permission_required("audit:log:read")
def list_events(current_user):
    """Newest events first, 50 per page, optionally filtered by action."""
    page = request.args.get("page", "1")
    action = request.args.get("action", "")
    if not page.isdigit() or int(page) < 1 or (action and action not in AUDIT_ACTIONS):
        return jsonify({"error": "Invalid request"}), 400
    query = AuditEvent.query
    if action:
        query = query.filter_by(action=action)
    events = (query.order_by(AuditEvent.seq.desc())
              .offset((int(page) - 1) * PAGE_SIZE).limit(PAGE_SIZE).all())
    return jsonify({"events": [event.to_dict() for event in events], "page": int(page)}), 200


@audit_bp.route("/audit/verify", methods=["POST"])
@permission_required("audit:verify")
def verify(current_user):
    """R14: check the chain and the signed anchors now. A failure raises an alert."""
    problems = verify_audit_trail(current_user)
    return jsonify({"intact": not problems, "problems": problems}), 200

@audit_bp.route("/audit")
@page_login_required
def audit_page(current_user):
    """The auditor's screen. The API above enforces everything again."""
    if not has_permission(current_user, "audit:log:read"):
        return redirect(url_for("pages.dashboard"))
    return render_template("audit/audit.html", actions=AUDIT_ACTIONS)


@audit_bp.app_context_processor
def audit_link():
    """Lets the dashboard show the Audit link to auditors without editing pages.py."""
    user = g.get("page_user")
    return {"can_audit": user is not None and has_permission(user, "audit:log:read")}