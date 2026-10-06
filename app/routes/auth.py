"""Authentication endpoints: /auth/... (R09, R21; later R08, R10, R12)."""
from flask import Blueprint, jsonify, request

from app.security.auth_security import authenticate

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

    return jsonify({"message": "Login successful", "user": user.to_dict()}), 200