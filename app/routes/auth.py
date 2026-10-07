"""Authentication endpoints: /auth/... (R09, R21; later R08, R10, R12)."""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import set_access_cookies

from app.security.auth_security import authenticate, start_session

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