"""Authentication endpoints: /auth/... (R09, R21; later R08, R10, R12)."""
from flask import Blueprint, g, jsonify, request
from flask_jwt_extended import set_access_cookies, unset_jwt_cookies

from app import db
from app.security.auth_security import authenticate, start_session
from app.security.shared_security import login_required, utcnow

auth_bp = Blueprint("auth", __name__)

INVALID_CREDENTIALS = "Invalid credentials"

@auth_bp.route("/login", methods=["POST"])

def login():
    """Log in with username and password."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400
    username = data.get("username")
    password = data.get("password")
    # R04: basic type and length checks (Austin's validate() replaces this later)
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid request"}), 400
    if not 1 <= len(username) <= 40 or not 1 <= len(password) <= 128:
        return jsonify({"error": "Invalid request"}), 400

    user = authenticate(username.strip(), password)
    if user is None:
        # R09: same message and status for unknown user, wrong password or inactive account
        return jsonify({"error": INVALID_CREDENTIALS}), 401

    token = start_session(user)
    response = jsonify({"message": "Login successful", "user": user.to_dict()})
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