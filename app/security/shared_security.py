"""Security code shared by every subsystem: errors, headers, time, sessions, permissions."""
from flask import jsonify, request
from werkzeug.exceptions import HTTPException

from app import db
from datetime import datetime, timezone

class Clock:
    """The app's only source of "now". Tests can freeze it to check expiry rules."""

    def __init__(self):
        self._frozen = None

    def now(self):
        # Naive UTC datetime, because SQLite stores datetimes without a timezone
        return self._frozen or datetime.now(timezone.utc).replace(tzinfo=None)

    def freeze(self, when):
        self._frozen = when

    def advance(self, delta):
        self._frozen = self.now() + delta

    def unfreeze(self):
        self._frozen = None


clock = Clock()


def utcnow():
    """Current time in UTC. Use this everywhere instead of datetime.utcnow()."""
    return clock.now()

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