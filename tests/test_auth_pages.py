"""R21/R04: the GUI pages are served safely and the session is enforced on the server."""
import re

from tests.conftest import csrf_headers
from tests.test_auth_login import login, make_user

# matches an opening <script> tag that has no src= attribute, i.e. inline JavaScript
INLINE_SCRIPT = re.compile(r"<script(?![^>]*\ssrc=)[^>]*>", re.IGNORECASE)


def test_home_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Australian Electronic Voting Platform" in response.get_data(as_text=True)


def test_pages_keep_the_security_headers(client):
    response = client.get("/")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"

def test_login_page_renders_a_form(client):
    response = client.get("/login")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'id="login-form"' in body
    assert 'type="password"' in body


def test_pages_have_no_inline_scripts(client):
    # S15: our Content-Security-Policy blocks inline scripts, so an inline
    # <script> block would silently stop working in the browser.
    for path in ("/", "/login"):
        body = client.get(path).get_data(as_text=True)
        assert INLINE_SCRIPT.search(body) is None, f"inline <script> in {path}"



def test_dashboard_redirects_anonymous_visitors_to_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_dashboard_opens_after_login_and_is_never_cached(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_dashboard_html_contains_no_account_data(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    body = client.get("/dashboard").get_data(as_text=True)
    # the username arrives later from /auth/me, so it is not in the page source
    assert "alice" not in body


def test_the_server_decides_what_the_nav_bar_shows(app, client):
    # S15: the lab app decided this in JavaScript from localStorage, which the
    # visitor can edit. Ours decides it from the server-side session.
    assert "My account" not in client.get("/").get_data(as_text=True)
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    assert "My account" in client.get("/dashboard").get_data(as_text=True)


def test_logout_from_the_page_ends_the_session(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    assert client.post("/auth/logout", headers=csrf_headers(client)).status_code == 200
    # the back button must not get the page back from the server either
    assert client.get("/dashboard").status_code == 302


def test_no_get_request_can_end_a_session(app, client):
    # R21: "GET requests cannot modify enrolment, candidate or result data."
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    assert client.get("/auth/logout").status_code == 405
    assert client.get("/auth/me").status_code == 200  # still logged in


def test_timeout_page_shows_the_configured_idle_limit(client):
    body = client.get("/timeout").get_data(as_text=True)
    assert "15 minutes" in body


def test_pages_tell_the_browser_the_same_idle_limit_as_the_server(app, client):
    with app.app_context():
        make_user()
    login(client, "alice", "Correct-Horse-42")
    body = client.get("/dashboard").get_data(as_text=True)
    assert f'data-idle-minutes="{app.config["SESSION_IDLE_MINUTES"]}"' in body