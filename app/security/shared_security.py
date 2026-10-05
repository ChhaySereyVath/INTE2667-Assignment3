"""Security code shared by every subsystem: errors, headers, time, sessions, permissions."""
from flask import jsonify, request
from werkzeug.exceptions import HTTPException

from app import db


# S03: every error gets a short generic message and never the exception text
GENERIC_ERRORS = {
    400: "Invalid request",
    401: "Authentication required",
    403: "Access denied",
    404: "Not found",
    405: "Method not allowed",
    413: "Request too large",
    429: "Too many requests",
    500: "An unexpected error occurred",
}


def register_security(app):
    """Attach the shared error handlers and security headers to the app."""

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        code = error.code or 500
        return jsonify({"error": GENERIC_ERRORS.get(code, "Request failed")}), code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        db.session.rollback()  # undo any half-finished database work
        app.logger.exception("Unhandled error")  # details stay in the server log only
        return jsonify({"error": GENERIC_ERRORS[500]}), 500

    @app.after_request
    def add_security_headers(response):
        # S15: only load scripts, styles and images from our own site
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.path.startswith("/auth/"):
            response.headers["Cache-Control"] = "no-store"  # R21: never cache account data
        return response