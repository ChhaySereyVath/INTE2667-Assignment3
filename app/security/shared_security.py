"""Security code shared by every subsystem: errors, headers, time, sessions, permissions."""
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import current_app, g, jsonify, redirect, request, url_for
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask_jwt_extended.exceptions import JWTExtendedException
from jwt import PyJWTError
from werkzeug.exceptions import HTTPException

from app import db, jwt

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

# R12: the whole permission model in one place. A role that is not listed, or a
# permission that is not listed for a role, is DENIED. There is no wildcard.
ROLE_PERMISSIONS = {
    "citizen": frozenset({
        "enrolment:self:read",
        "enrolment:self:enrol",
        "enrolment:self:update_address",
    }),
    "aec_employee": frozenset({
        "enrolment:staff:read",
        "enrolment:staff:register",
    }),
    "commissioner_delegate": frozenset({
        "enrolment:staff:read",
        "enrolment:staff:register",
        "enrolment:staff:approve",
        "enrolment:history:read_sensitive",
    }),
    "administrator": frozenset({
        "admin:user:create",
        "admin:role:grant",
        "admin:recovery:approve",
    }),
    "auditor": frozenset({
        "audit:log:read",
    }),
}

# R12: least privilege. An administrator manages accounts; they do not get to read
# or change enrolment records, and nobody inherits another role's permissions.
PRIVILEGED_PERMISSIONS = frozenset(
    ROLE_PERMISSIONS["aec_employee"]
    | ROLE_PERMISSIONS["commissioner_delegate"]
    | ROLE_PERMISSIONS["administrator"]
)


def has_permission(user, permission):
    """R12: deny by default. An unknown role has no permissions at all."""
    return permission in ROLE_PERMISSIONS.get(user.role, frozenset())

def session_is_valid(session_row, jti):
    """R21: a token only works while its server-side session is alive."""
    if session_row is None or session_row.revoked_at is not None:
        return False
    if session_row.current_jti != jti:
        return False  # an older token from before the session was rotated
    now = utcnow()
    idle_limit = timedelta(minutes=current_app.config["SESSION_IDLE_MINUTES"])
    if now - session_row.last_activity_at > idle_limit:
        return False  # R21: idle timeout
    if now >= session_row.absolute_expires_at:
        return False  # R21: absolute timeout, even if the user stays active
    return True


def login_required(view):
    """Only let logged-in users with a valid session in. Passes current_user to the view."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        from app.models.user import User

        # Checks the JWT signature (S06), expiry, the CSRF token on POST/PUT/PATCH/DELETE (S16),
        # and calls check_session_is_revoked() below
        verify_jwt_in_request()
        user = db.session.get(User, get_jwt_identity())
        if user is None or user.status != "active":
            return jsonify({"error": GENERIC_ERRORS[401]}), 401
        g.current_session.last_activity_at = utcnow()  # R21: the idle timer restarts
        db.session.commit()
        return view(*args, current_user=user, **kwargs)

    return wrapper

"""Attach the shared error handlers, JWT checks and security headers to the app."""

@jwt.token_in_blocklist_loader
def check_session_is_revoked(jwt_header, jwt_payload):
    from app.models.auth_models import UserSession

    session_row = db.session.get(UserSession, jwt_payload.get("sid"))
    if not session_is_valid(session_row, jwt_payload["jti"]):
        return True  # True means "reject this token"
    g.current_session = session_row
    return False

def authentication_required(*_args):
    # S03: the same short message for missing, invalid, expired or revoked tokens
    return jsonify({"error": GENERIC_ERRORS[401]}), 401

jwt.unauthorized_loader(authentication_required)
jwt.invalid_token_loader(authentication_required)
jwt.expired_token_loader(authentication_required)
jwt.revoked_token_loader(authentication_required)

def page_login_required(view):
    """Same checks as login_required, but for HTML pages: send the visitor to the
    login page instead of a JSON 401, and never let the browser cache the page (R21)."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        from app.models.user import User

        try:
            verify_jwt_in_request()
            user = db.session.get(User, get_jwt_identity())
        except (JWTExtendedException, PyJWTError):
            user = None
        if user is None or user.status != "active":
            return redirect(url_for("pages.login_page"))
        g.current_session.last_activity_at = utcnow()
        db.session.commit()
        g.no_store = True   # read by add_security_headers below
        g.page_user = user  # read by the nav bar in base.html
        return view(*args, current_user=user, **kwargs)

    return wrapper

def permission_required(permission):
    """R12: the route states the one permission it needs. The check runs on the
    server, from the role stored in the database, never from anything the client sends."""

    def decorator(view):
        @wraps(view)
        def inner(*args, current_user, **kwargs):
            if not has_permission(current_user, permission):
                return jsonify({"error": GENERIC_ERRORS[403]}), 403
            if permission in PRIVILEGED_PERMISSIONS and not _mfa_satisfied(current_user):
                # R08: a privileged action needs more than a password
                return jsonify({"error": GENERIC_ERRORS[403]}), 403
            return view(*args, current_user=current_user, **kwargs)

        return login_required(inner)

    return decorator

def _mfa_satisfied(user):
    """R08: staff and admin sessions must be MFA-verified. Citizens are not asked."""
    if not user.is_privileged:
        return True
    if not current_app.config["REQUIRE_MFA_FOR_PRIVILEGED"]:
        return True  # only ever False in a developer setting, never in the demo
    return bool(g.current_session.mfa_verified)

def privileged_required(view):
    """R08: any staff or admin route, even one with no specific permission."""

    @wraps(view)
    def inner(*args, current_user, **kwargs):
        if not current_user.is_privileged or not _mfa_satisfied(current_user):
            return jsonify({"error": GENERIC_ERRORS[403]}), 403
        return view(*args, current_user=current_user, **kwargs)

    return login_required(inner)

def register_security(app):
    """Attach the shared error handlers and security headers to the app."""

    @app.before_request
    def check_request_origin():
        """R21: 'State-changing requests require valid CSRF or request-origin evidence.'

        The CSRF token is the first defence (flask-jwt-extended checks it). This is
        the second: a state-changing request that carries our session cookie must
        also say it came from our own site.
        """
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if "access_token_cookie" not in request.cookies:
            return None  # no session to abuse, so there is nothing to protect here
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if not origin:
            return jsonify({"error": GENERIC_ERRORS[403]}), 403
        expected = request.host_url.rstrip("/")
        if origin != expected and not origin.startswith(expected + "/"):
            return jsonify({"error": GENERIC_ERRORS[403]}), 403
        return None

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
        # R21: account data must not sit in the browser cache or the back button
        # after logout, which matters most on a shared polling-place computer
        if request.path.startswith("/auth/") or g.get("no_store"):
            response.headers["Cache-Control"] = "no-store"  # R21: never cache account data
        return response