"""Page routes: they only render templates. All data comes from the /auth and
/enrollment APIs, so the GUI is just another client of our REST services."""
from flask import Blueprint, current_app, g, redirect, render_template, url_for

from app.security.mfa_security import has_security_key
from app.security.shared_security import has_permission ,page_login_required

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    """Public landing page."""
    return render_template("index.html")

@pages_bp.route("/login")
def login_page():
    """Login form. The form posts to /auth/login with fetch()."""
    return render_template("auth/login.html")

@pages_bp.route("/mfa")
@page_login_required
def mfa_page(current_user):
    """R08: staff add or use their security key here before anything else opens."""
    if not current_user.is_privileged:
        return redirect(url_for("pages.dashboard"))  # citizens are never asked
    return render_template("auth/mfa.html", enrolled=has_security_key(current_user))

@pages_bp.route("/admin")
@page_login_required
def admin_page(current_user):
    """R10/R12: recovery approvals and staff accounts. Administrators only."""
    if not has_permission(current_user, "admin:recovery:approve"):
        return redirect(url_for("pages.dashboard"))
    from app.security.validators import STATES

    return render_template("admin/admin.html", states=STATES)

@pages_bp.route("/timeout")
def timeout_page():
    """Shown after the idle timer signs someone out."""
    return render_template("auth/timeout.html")

@pages_bp.route("/recover")
def recover_page():
    """R10 step 1: ask for a recovery link."""
    return render_template("recovery/request.html")


@pages_bp.route("/recover/confirm")
def recover_confirm_page():
    """R10 step 2: the emailed link opens this page; the token is in the fragment."""
    return render_template("recovery/confirm.html")


@pages_bp.route("/recover/reset")
def recover_reset_page():
    """R10 step 4: choose a new password with the single-use reset link."""
    return render_template("recovery/reset.html")

@pages_bp.app_context_processor
def inject_session_settings():
    """The SERVER decides what the nav bar shows. The lab app decided it in
    JavaScript from localStorage, which anyone could edit (R21, S15)."""
    return {
        "idle_minutes": current_app.config["SESSION_IDLE_MINUTES"],
        "signed_in": g.get("page_user") is not None,
    }

@pages_bp.route("/register")
def register_page():
    """Registration form. Posts to /auth/register with fetch()."""
    return render_template("auth/register.html")

@pages_bp.route("/activate")
def activate_page():
    """Activation page. The token is in the URL fragment, which never reaches
    this route: the page's script reads it and POSTs it (R09)."""
    return render_template("auth/activate.html")

@pages_bp.route("/dashboard")
@page_login_required
def dashboard(current_user):
    """Signed-in landing page. The session is checked here on the server, so the
    page cannot be opened by typing the URL (R21, R11)."""
    return render_template("auth/dashboard.html",
                        can_enrol=has_permission(current_user, "enrolment:self:read"),
                        can_staff=has_permission(current_user, "enrolment:staff:read"),
                        can_admin=has_permission(current_user, "admin:recovery:approve"))