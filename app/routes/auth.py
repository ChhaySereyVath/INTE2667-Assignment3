"""Authentication endpoints: /auth/... (R09, R21; later R08, R10, R12)."""
from flask import Blueprint, g, jsonify, request
from flask_jwt_extended import set_access_cookies, unset_jwt_cookies

from app import db
from app.models.user import User
from app.security.auth_security import (authenticate, clear_login_failures, create_staff_account,
                                        login_is_locked, password_problem, queue_notification,
                                        record_login_failure, redeem_token, register_account,
                                        revoke_all_sessions, rotate_session, start_session)
from app.security.mfa_security import (authentication_options, finish_authentication,
                                       finish_registration, has_security_key,
                                       registration_options)
from app.security.shared_security import login_required, permission_required, utcnow
from app.security.validators import EMAIL_RE, STATES, USERNAME_RE, validate
from app.models.user import User

auth_bp = Blueprint("auth", __name__)

INVALID_CREDENTIALS = "Invalid credentials"

LOGIN_SCHEMA = {
    "username": {"type": str, "required": True, "max": 40},
    "password": {"type": str, "required": True, "max": 128},
}

REGISTER_SCHEMA = {
    "username": {"type": str, "required": True, "pattern": USERNAME_RE},
    "email": {"type": str, "required": True, "pattern": EMAIL_RE, "max": 254},
    "password": {"type": str, "required": True, "max": 128},
}

ACTIVATE_SCHEMA = {"token": {"type": str, "required": True, "max": 100}}

# R09: the same answer whether or not the address is already registered
REGISTRATION_ACCEPTED = "If those details can be registered, we have sent an activation link."

@auth_bp.route("/login", methods=["POST"])
def login():
    """Log in with username and password."""
    ok, data, _ = validate(request.get_json(silent=True), LOGIN_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request"}), 400
    username, password = data["username"], data["password"]
    client_ip = request.remote_addr or "unknown"

    # R09: too many wrong passwords from this computer, or against this account
    if login_is_locked(username, client_ip):
        response = jsonify({"error": "Too many requests"})
        response.headers["Retry-After"] = "900"
        return response, 429

    user = authenticate(username, password)
    if user is None:
        record_login_failure(username, client_ip)
        return jsonify({"error": INVALID_CREDENTIALS}), 401
    clear_login_failures(username, client_ip)

    token = start_session(user)
    response = jsonify({
        "message": "Login successful",
        "user": user.to_dict(),
        # R08: staff must pass MFA before this session can do anything privileged
        "mfa_required": user.is_privileged,
        "mfa_enrolled": user.is_privileged and has_security_key(user),
    })
    set_access_cookies(response, token)  # R21: HttpOnly cookie + readable CSRF cookie
    return response, 200

@auth_bp.route("/me", methods=["GET"])
@login_required
def me(current_user):
    """Who am I? Useful for pages and for testing login_required."""
    return jsonify({"user": current_user.to_dict()}), 200

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout(current_user):
    """End the session on the server, not just in the browser (R21)."""
    g.current_session.revoked_at = utcnow()
    g.current_session.revoke_reason = "logout"
    db.session.commit()
    response = jsonify({"message": "Logged out"})
    unset_jwt_cookies(response)
    # R21: tell the browser to wipe cookies and storage (shared polling-place computers)
    response.headers["Clear-Site-Data"] = '"cookies", "storage"'
    return response, 200

@auth_bp.route("/register", methods=["POST"])
def register():
    """R09: self-registration. The answer is always the same 202, so this endpoint
    cannot be used to find out which usernames or addresses already exist."""
    ok, data, errors = validate(request.get_json(silent=True), REGISTER_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    problem = password_problem(data["password"], data["username"])
    if problem is not None:
        # safe to explain: this is about the password just typed, not about any account
        return jsonify({"error": "Invalid request", "fields": {"password": problem}}), 400

    register_account(data["username"], data["email"], data["password"])
    return jsonify({"message": REGISTRATION_ACCEPTED}), 202

@auth_bp.route("/activate", methods=["POST"])
def activate():
    """R09: turn a pending account into an active one with a single-use token."""
    ok, data, _ = validate(request.get_json(silent=True), ACTIVATE_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request"}), 400

    user = redeem_token(data["token"], "activation")
    if user is None or user.status != "pending_activation":
        # one generic answer for unknown, expired, already-used and wrong-purpose tokens
        return jsonify({"error": "Invalid request"}), 400

    user.status = "active"
    db.session.commit()
    return jsonify({"message": "Account activated. You can now log in."}), 200

STAFF_ROLES = ("aec_employee", "commissioner_delegate", "administrator", "auditor")

STAFF_SCHEMA = {
    "username": {"type": str, "required": True, "pattern": USERNAME_RE},
    "email": {"type": str, "required": True, "pattern": EMAIL_RE, "max": 254},
    "role": {"type": str, "required": True, "enum": STAFF_ROLES},
    "states": {"type": list, "required": True, "max": 8},
    "temporary_password": {"type": str, "required": True, "max": 128},
}

ROLE_SCHEMA = {
    "user_id": {"type": "uuid", "required": True},
    "role": {"type": str, "required": True, "enum": ("citizen",) + STAFF_ROLES},
}

@auth_bp.route("/admin/staff", methods=["POST"])
@permission_required("admin:user:create")
def create_staff(current_user):
    """R12: an administrator creates a staff account, scoped to named states."""
    ok, data, errors = validate(request.get_json(silent=True), STAFF_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400
    states = data["states"]
    if not states or any(state not in STATES for state in states):
        return jsonify({"error": "Invalid request", "fields": {"states": "is not an allowed value"}}), 400
    problem = password_problem(data["temporary_password"], data["username"])
    if problem is not None:
        return jsonify({"error": "Invalid request", "fields": {"temporary_password": problem}}), 400

    user = create_staff_account(current_user, data["username"], data["email"],
                                data["role"], states, data["temporary_password"])
    if user is None:
        return jsonify({"error": "Invalid request"}), 400
    return jsonify({"message": "Staff account created", "user": user.to_dict()}), 201

@auth_bp.route("/admin/roles", methods=["POST"])
@permission_required("admin:role:grant")
def grant_role(current_user):
    """R12: change someone's role. Nobody may change their own (separation of duties),
    and the change ends every session the target has, so an old token cannot keep
    the old permissions (R21)."""
    ok, data, errors = validate(request.get_json(silent=True), ROLE_SCHEMA)
    if not ok:
        return jsonify({"error": "Invalid request", "fields": errors}), 400

    target_id = str(data["user_id"])
    if target_id == current_user.id:
        # R12: self-promotion is the attack this blocks
        return jsonify({"error": "Access denied"}), 403

    target = db.session.get(User, target_id)
    if target is None:
        return jsonify({"error": "Not found"}), 404

    previous, target.role = target.role, data["role"]
    db.session.commit()
    revoke_all_sessions(target, "role_changed")
    queue_notification(target, "role_changed", previous_role=previous, new_role=target.role)
    return jsonify({"message": "Role updated", "user": target.to_dict()}), 200

# --- R08: WebAuthn MFA ------------------------------------------------------------

MFA_FAILED = "Security key check failed. Try again."


def _mfa_staff_check(current_user, adding_key):
    """Who may use the MFA endpoints. Returns an error response, or None if allowed.

    Citizens are never asked for MFA (R08 covers staff, delegates and admins).
    A staff member may add their FIRST key straight after signing in with their
    password; adding any further key needs a session that already passed MFA, so a
    stolen password cannot be used to slip in a second key.
    """
    if not current_user.is_privileged:
        return jsonify({"error": "Access denied"}), 403
    if adding_key and has_security_key(current_user) and not g.current_session.mfa_verified:
        return jsonify({"error": "Access denied"}), 403
    if not adding_key and not has_security_key(current_user):
        return jsonify({"error": "No security key registered"}), 409
    return None


def _mfa_passed_response(message):
    """R21: the privilege level changed, so the session gets a brand-new token."""
    token = rotate_session(g.current_session, mfa_verified=True)
    response = jsonify({"message": message})
    set_access_cookies(response, token)
    return response, 200


@auth_bp.route("/mfa/register/begin", methods=["POST"])
@login_required
def mfa_register_begin(current_user):
    """R08: options for navigator.credentials.create()."""
    refused = _mfa_staff_check(current_user, adding_key=True)
    if refused:
        return refused
    return jsonify({"options": registration_options(current_user, g.current_session)}), 200


@auth_bp.route("/mfa/register/finish", methods=["POST"])
@login_required
def mfa_register_finish(current_user):
    """R08: store the new key's public key, then treat this session as MFA-verified."""
    refused = _mfa_staff_check(current_user, adding_key=True)
    if refused:
        return refused
    credential = request.get_json(silent=True)
    if not isinstance(credential, dict) or not finish_registration(current_user, g.current_session, credential):
        return jsonify({"error": MFA_FAILED}), 400
    queue_notification(current_user, "mfa_key_added")
    return _mfa_passed_response("Security key added")


@auth_bp.route("/mfa/authenticate/begin", methods=["POST"])
@login_required
def mfa_authenticate_begin(current_user):
    """R08: options for navigator.credentials.get()."""
    refused = _mfa_staff_check(current_user, adding_key=False)
    if refused:
        return refused
    return jsonify({"options": authentication_options(current_user, g.current_session)}), 200


@auth_bp.route("/mfa/authenticate/finish", methods=["POST"])
@login_required
def mfa_authenticate_finish(current_user):
    """R08: check the key's signature. Only a valid answer raises the session to
    MFA-verified; any failure leaves it exactly as it was."""
    refused = _mfa_staff_check(current_user, adding_key=False)
    if refused:
        return refused
    credential = request.get_json(silent=True)
    if not isinstance(credential, dict) or not finish_authentication(current_user, g.current_session, credential):
        return jsonify({"error": MFA_FAILED}), 400
    return _mfa_passed_response("Security key accepted")