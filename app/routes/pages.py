"""Page routes: they only render templates. All data comes from the /auth and
/enrollment APIs, so the GUI is just another client of our REST services."""
from flask import Blueprint, current_app, g, render_template

from app.security.shared_security import page_login_required

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    """Public landing page."""
    return render_template("index.html")

@pages_bp.route("/login")
def login_page():
    """Login form. The form posts to /auth/login with fetch()."""
    return render_template("auth/login.html")


@pages_bp.route("/timeout")
def timeout_page():
    """Shown after the idle timer signs someone out."""
    return render_template("auth/timeout.html")

@pages_bp.app_context_processor
def inject_session_settings():
    """The SERVER decides what the nav bar shows. The lab app decided it in
    JavaScript from localStorage, which anyone could edit (R21, S15)."""
    return {
        "idle_minutes": current_app.config["SESSION_IDLE_MINUTES"],
        "signed_in": g.get("page_user") is not None,
    }

@pages_bp.route("/dashboard")
@page_login_required
def dashboard(current_user):
    """Signed-in landing page. The session is checked here on the server, so the
    page cannot be opened by typing the URL (R21, R11)."""
    return render_template("auth/dashboard.html")