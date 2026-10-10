# Ken — Part 1b: the web pages (K19–K22)

**Read `TASKS_Ken.md` first.** This sheet continues straight after **K18** (logout). It builds the
front end: the pages a person actually sees and clicks. Every snippet here was built and run
before it was written down: 12 new tests pass, and the whole login → account → logout flow was
driven in a real Chrome browser.

The assignment brief asks for *"front-end Graphical User Interfaces (GUIs), server-side back-end,
back-end RESTful web services and a database"*, with *"security at every level"*. After K18 you
have the back end, the REST services and the database. These four steps add the GUI level, so
security can be shown there too, rather than left to the last week.

| | |
|---|---|
| **Requirements** | R21 (sessions, CSRF, GET safety), R04 (output encoding), R09 (generic errors) |
| **Part 2 solutions** | S15 (CSP, HttpOnly), S16 (CSRF), S03 (generic errors), S06 (server-side authority) |
| **Steps** | K19, K20, K21, K22 — one commit and push each |
| **New tests** | 12, all in `tests/test_auth_pages.py` |

---

## 1. The pattern we copy, and what we change

We follow the shape of the lab app (`PythonRestBankingApp`): a blueprint whose routes only
`render_template(...)`, a `base.html` with Jinja blocks, pages that talk to the JSON API with
`fetch`. That keeps the GUI a **client of our REST services**, which is exactly the split the
brief describes.

The lab app is also the *insecure* example, so we change eight things. This table is worth
putting in the report almost as-is: it shows a security decision at the GUI level for each row.

| Lab app (`PythonRestBankingApp`) | Ours | Why |
|---|---|---|
| `localStorage.setItem('authToken', …)` | HttpOnly cookie set by the server (K15) | Any XSS script can read localStorage. Our cookie is invisible to JavaScript (R21, S15). |
| `Authorization: Bearer` header built in JS | Cookie sent automatically + `X-CSRF-TOKEN` header | R21 requires CSRF evidence on state-changing requests (S16). |
| All JavaScript inline in `<script>` | External files under `app/static/js/` | Our CSP (K05) blocks inline scripts. A test proves none slipped in. |
| `/dashboard` renders for anyone | `@page_login_required` checks the session on the server | R21 and R11: the decision is never left to the browser. |
| `updateNavbar()` reads localStorage | The server decides what the nav bar shows | A visitor can edit localStorage; they cannot edit our session row. |
| `showAlert(result.error)` with server detail | The generic message only | R09: errors must never reveal whether an account exists. |
| Bootstrap and JS from a CDN | One local stylesheet, no CDN | CSP `default-src 'self'`, and the demo then works offline. |
| Logout only deletes the local token | Logout revokes the session row and sends `Clear-Site-Data` (K18) | A copied token must stop working too. |
| `templates/` at the project root | `app/templates/` and `app/static/` | Our team README puts them inside `app/`, where Flask finds them with no extra setting. |

---

## 2. Files you create

```
app/templates/base.html              K19   the frame every page extends
app/templates/index.html             K19   public landing page
app/templates/auth/login.html        K20   login form
app/templates/auth/dashboard.html    K21   signed-in page (protected)
app/templates/auth/timeout.html      K22   shown after the idle timer fires
app/static/css/app.css               K19   one stylesheet, no CDN
app/static/js/api.js                 K19   fetch + CSRF + safe error display
app/static/js/login.js               K20   posts the login form
app/static/js/dashboard.js           K21   fills the page from /auth/me
app/static/js/session.js             K22   logout button and idle timer
app/routes/pages.py                  K19   page routes (render only)
tests/test_auth_pages.py             K19   12 tests by the end of K22
```

Changed: `app/__init__.py` (one blueprint registration) and
`app/security/shared_security.py` (the `page_login_required` decorator).

**The routine is unchanged:** `git pull` → do one step → `pytest -q` → `git add` → `git commit`
→ `git pull` → `git push` → post "Pushed K19".

---

## K19: The page frame, the stylesheet and the page blueprint

**Why:** page routes do one thing only — render a template. No database work, no decisions. All
data comes from the REST API, so the GUI can never become a second, weaker way into the system.
Everything the browser loads comes from our own site, because the CSP from K05 (`default-src
'self'`) blocks anything else, including inline scripts and CDN links.

**New file `app/templates/base.html`:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}Australian Electronic Voting Platform{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/app.css') }}">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="{{ url_for('pages.index') }}">AEC Voting Platform</a>
    <nav>
      <a href="{{ url_for('pages.index') }}">Home</a>
    </nav>
  </header>

  <main class="container">
    <div id="alert" class="alert" hidden></div>
    {% block content %}{% endblock %}
  </main>

  <footer class="footer">
    <p>Prototype for INTE2667 Assignment 3. Not a real electoral system.</p>
  </footer>

  <script src="{{ url_for('static', filename='js/api.js') }}"></script>
  {% block scripts %}{% endblock %}
</body>
</html>
```

**New file `app/templates/index.html`:**
```html
{% extends "base.html" %}
{% block title %}Home - AEC Voting Platform{% endblock %}
{% block content %}
<section class="card">
  <h1>Australian Electronic Voting Platform</h1>
  <p>Check your enrolment, update your address and vote securely.</p>
  <p><a class="button" href="{{ url_for('pages.login_page') }}">Log in</a></p>
</section>
{% endblock %}
```
*(`url_for('pages.login_page')` is added in K20 — do K19 and K20 in one sitting, or leave this
`<p>` out until then.)*

**New file `app/static/css/app.css`:**
```css
/* One stylesheet for the whole prototype. Loaded from our own site, so the
   Content-Security-Policy in shared_security.py allows it (S15). */
:root {
  --ink: #16202a;
  --muted: #5a6b7b;
  --line: #d7dee5;
  --brand: #11467b;
  --bad: #9a1c1c;
  --bad-bg: #fdf0f0;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, "Segoe UI", Arial, sans-serif;
  color: var(--ink);
  background: #f4f6f8;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.85rem 1.25rem;
  background: var(--brand);
  color: #fff;
}
.topbar a { color: #fff; text-decoration: none; }
.brand { font-weight: 700; letter-spacing: 0.01em; }
.topbar nav a { margin-left: 1rem; }
.topbar nav a:hover, .topbar a:hover { text-decoration: underline; }
.container { flex: 1; width: 100%; max-width: 44rem; margin: 2rem auto; padding: 0 1rem; }
.card {
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 1.5rem;
  margin-bottom: 1.25rem;
}
h1 { font-size: 1.5rem; margin-top: 0; }
label { display: block; font-weight: 600; margin-bottom: 0.3rem; }
input[type="text"], input[type="password"] {
  width: 100%;
  padding: 0.55rem 0.65rem;
  border: 1px solid var(--line);
  border-radius: 6px;
  font-size: 1rem;
  margin-bottom: 1rem;
}
input:focus { outline: 2px solid var(--brand); outline-offset: 1px; }
.button {
  display: inline-block;
  background: var(--brand);
  color: #fff;
  border: 0;
  border-radius: 6px;
  padding: 0.6rem 1.1rem;
  font-size: 1rem;
  text-decoration: none;
  cursor: pointer;
}
.button[disabled] { opacity: 0.6; cursor: progress; }
.button.secondary { background: #fff; color: var(--brand); border: 1px solid var(--brand); }
.alert {
  border: 1px solid var(--bad);
  background: var(--bad-bg);
  color: var(--bad);
  border-radius: 6px;
  padding: 0.7rem 0.9rem;
  margin-bottom: 1rem;
}
.muted { color: var(--muted); }
.footer { padding: 1rem; text-align: center; color: var(--muted); font-size: 0.875rem; }
dl.details dt { font-weight: 600; margin-top: 0.75rem; }
dl.details dd { margin: 0.15rem 0 0; }
```

**New file `app/static/js/api.js`:**
```javascript
// Shared helpers for every page. No inline <script> anywhere: the
// Content-Security-Policy only allows scripts served from our own site (S15).

// R21: the JWT is in an HttpOnly cookie that JavaScript cannot read. The browser
// attaches it automatically, so we only have to add the CSRF token (S16).
function csrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)csrf_access_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function apiRequest(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json" };
  if (method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-TOKEN"] = csrfToken();
  }
  const response = await fetch(path, {
    method: method,
    headers: headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: "same-origin",
  });
  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    data = {};
  }
  return { ok: response.ok, status: response.status, data: data };
}

// Always use textContent, never innerHTML: text from the server is shown as
// text and can never become HTML or script (R04, output encoding).
function showError(message) {
  const box = document.getElementById("alert");
  if (!box) return;
  box.textContent = message;
  box.hidden = false;
}

function clearError() {
  const box = document.getElementById("alert");
  if (!box) return;
  box.textContent = "";
  box.hidden = true;
}
```

**New file `app/routes/pages.py`:**
```python
"""Page routes: they only render templates. All data comes from the /auth and
/enrollment APIs, so the GUI is just another client of our REST services."""
from flask import Blueprint, render_template

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def index():
    """Public landing page."""
    return render_template("index.html")
```

**In `app/__init__.py`**, add below the `auth_bp` registration:
```python
    from app.routes.pages import pages_bp
    app.register_blueprint(pages_bp)
```

**New file `tests/test_auth_pages.py`:**
```python
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
```

**Check:** `pytest -q tests/test_auth_pages.py` → **2 passed**. Then `python run.py` and open
<http://localhost:5000/> — you should see the blue bar and the card.
**Commit:** `R04/S15: base template, stylesheet and page blueprint [K19]`

---

## K20: The login page

**Why (R09):** the form posts to the REST API with `fetch`, and the page shows **only** the
server's generic message. It never says "no such user" or "wrong password", because that would
tell an attacker which usernames exist. The session arrives as a cookie the server sets, so
nothing is stored in `localStorage` — that is the single biggest difference from the lab app.

**New file `app/templates/auth/login.html`:**
```html
{% extends "base.html" %}
{% block title %}Log in - AEC Voting Platform{% endblock %}
{% block content %}
<section class="card">
  <h1>Log in</h1>
  <form id="login-form" method="post" action="/auth/login" autocomplete="on">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" maxlength="40" required autocomplete="username">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" maxlength="128" required
           autocomplete="current-password">

    <button type="submit" class="button" id="login-button">Log in</button>
  </form>
  <p class="muted">Staff accounts need a security key after this step (R08).</p>
</section>
{% endblock %}
{% block scripts %}
<script src="{{ url_for('static', filename='js/login.js') }}"></script>
{% endblock %}
```

**New file `app/static/js/login.js`:**
```javascript
// Posts the login form to the REST API and redirects on success.
document.getElementById("login-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  clearError();

  const button = document.getElementById("login-button");
  button.disabled = true;
  try {
    const result = await apiRequest("/auth/login", {
      method: "POST",
      body: {
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      },
    });
    if (result.ok) {
      // The session cookie was set by the server. Nothing is stored in
      // localStorage, so an XSS bug cannot steal the session (R21).
      window.location.assign("/dashboard");
      return;
    }
    // R09: show the server's generic message only. The page must never say
    // whether the username exists or the password was wrong.
    showError(result.data.error || "Invalid credentials");
  } catch (error) {
    showError("Could not reach the server. Please try again.");
  } finally {
    button.disabled = false;
  }
});
```

**In `app/routes/pages.py`**, add at the end:
```python


@pages_bp.route("/login")
def login_page():
    """Login form. The form posts to /auth/login with fetch()."""
    return render_template("auth/login.html")
```

**In `app/templates/base.html`**, add the Log in link inside `<nav>`, under the Home link:
```html
      <a href="{{ url_for('pages.login_page') }}">Log in</a>
```

**Add to `tests/test_auth_pages.py`:**
```python


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
```

**Check:** `pytest -q tests/test_auth_pages.py` → **4 passed**. Then `flask create-user alice`,
`python run.py`, open <http://localhost:5000/login> and try a wrong password: you should see
*Invalid credentials* and nothing more. (The redirect to `/dashboard` 404s until K21.)
**Commit:** `R09: login page that shows only the generic error [K20]`

---

## K21: The protected account page

**Why (R21, R11):** typing `/dashboard` into the address bar must not work. The check happens on
the **server**, in `page_login_required`, which does the same work as `login_required` but sends
a visitor to the login page instead of returning JSON. The page is also marked `no-store`, so it
is not left in the browser cache or behind the back button after logout — which matters on a
shared polling-place computer. And the page HTML contains **no account data**: the username
arrives afterwards from `/auth/me`, so a cached copy holds nothing about the person.

**In `app/security/shared_security.py`**, change the import block at the top to:
```python
from flask import current_app, g, jsonify, redirect, request, url_for
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask_jwt_extended.exceptions import JWTExtendedException
from jwt import PyJWTError
from werkzeug.exceptions import HTTPException
```
add this function **above** `def register_security(app):`:
```python
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


```
and in `add_security_headers`, replace the `Cache-Control` line with:
```python
        # R21: account data must not sit in the browser cache or the back button
        # after logout, which matters most on a shared polling-place computer
        if request.path.startswith("/auth/") or g.get("no_store"):
            response.headers["Cache-Control"] = "no-store"
```

**New file `app/templates/auth/dashboard.html`:**
```html
{% extends "base.html" %}
{% block title %}My account - AEC Voting Platform{% endblock %}
{% block content %}
<section class="card">
  <h1>My account</h1>
  <dl class="details">
    <dt>Username</dt>
    <dd id="username">Loading...</dd>
    <dt>Role</dt>
    <dd id="role">Loading...</dd>
    <dt>Account status</dt>
    <dd id="status">Loading...</dd>
  </dl>
  <p class="muted">Enrolment details appear here once the enrolment pages are built.</p>
  <button type="button" class="button secondary" id="logout-button">Log out</button>
</section>
{% endblock %}
{% block scripts %}
<script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
{% endblock %}
```

**New file `app/static/js/dashboard.js`:**
```javascript
// Fills the page from /auth/me. The page itself contains no account data when
// it is served, so nothing leaks into the HTML source or a cached copy.
async function loadAccount() {
  const result = await apiRequest("/auth/me");
  if (!result.ok) {
    window.location.assign("/login");
    return;
  }
  const user = result.data.user;
  // textContent, never innerHTML: a username is shown as text, never as HTML (R04)
  document.getElementById("username").textContent = user.username;
  document.getElementById("role").textContent = user.role;
  document.getElementById("status").textContent = user.status;
}

document.addEventListener("DOMContentLoaded", loadAccount);
```

**In `app/routes/pages.py`:** change the first import line to
`from flask import Blueprint, g, render_template`, add
`from app.security.shared_security import page_login_required` below it, add this context
processor just under `pages_bp = Blueprint(...)`:
```python


@pages_bp.app_context_processor
def inject_session_settings():
    """The SERVER decides what the nav bar shows. The lab app decided it in
    JavaScript from localStorage, which anyone could edit (R21, S15)."""
    return {"signed_in": g.get("page_user") is not None}

```
and add the route at the end:
```python


@pages_bp.route("/dashboard")
@page_login_required
def dashboard(current_user):
    """Signed-in landing page. The session is checked here on the server, so the
    page cannot be opened by typing the URL (R21, R11)."""
    return render_template("auth/dashboard.html")
```

**In `app/templates/base.html`**, replace the Log in link in `<nav>` with:
```html
      {% if signed_in %}
        <a href="{{ url_for('pages.dashboard') }}">My account</a>
      {% else %}
        <a href="{{ url_for('pages.login_page') }}">Log in</a>
      {% endif %}
```

**Add to `tests/test_auth_pages.py`:**
```python


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
```

**Check:** `pytest -q tests/test_auth_pages.py` → **8 passed**. In the browser: log in as `alice`
and you land on the account page with your username filled in. Open a private window and type
`http://localhost:5000/dashboard` — you get sent to the login page.
**Commit:** `R21/R11: protected account page checked on the server [K21]`

---

## K22: Logout button, idle timer and the GET-safety test

**Why (R21):** three acceptance criteria land here. *"Logout invalidates old sessions"* — the
button calls the API, which revokes the session row. *"Shared-terminal sessions are cleared after
logout or timeout"* — a timer signs the person out after the same idle limit the server enforces.
*"GET requests cannot modify enrolment, candidate or result data"* — a test proves that
`GET /auth/logout` is rejected with 405, so a planted `<img src="/auth/logout">` on another site
cannot sign anyone out.

The browser timer is a convenience, not the control. The server already ends an idle session
(K17); this just makes the screen agree, instead of leaving someone's details on display.

**New file `app/static/js/session.js`:**
```javascript
// Logout button and the shared-terminal idle timer (R21).
// The server is the real authority: this only makes the browser agree with it,
// so a session is never left open on a polling-place computer.

const IDLE_MINUTES = Number(document.body.dataset.idleMinutes || 15);
let idleTimer = null;

async function endSession(destination) {
  try {
    await apiRequest("/auth/logout", { method: "POST" });
  } catch (error) {
    // the session still expires on the server, so finish signing out anyway
  }
  window.location.assign(destination);
}

function resetIdleTimer() {
  window.clearTimeout(idleTimer);
  idleTimer = window.setTimeout(function () {
    endSession("/timeout");
  }, IDLE_MINUTES * 60 * 1000);
}

document.addEventListener("DOMContentLoaded", function () {
  const button = document.getElementById("logout-button");
  if (button) {
    button.addEventListener("click", function () {
      endSession("/login");
    });
  }
  ["mousemove", "keydown", "click", "scroll"].forEach(function (name) {
    document.addEventListener(name, resetIdleTimer, { passive: true });
  });
  resetIdleTimer();
});
```

**New file `app/templates/auth/timeout.html`:**
```html
{% extends "base.html" %}
{% block title %}Signed out - AEC Voting Platform{% endblock %}
{% block content %}
<section class="card">
  <h1>You have been signed out</h1>
  <p>Your session ended after {{ idle_minutes }} minutes without activity. This protects
     your details on shared computers.</p>
  <p><a class="button" href="{{ url_for('pages.login_page') }}">Log in again</a></p>
</section>
{% endblock %}
```

**In `app/routes/pages.py`:** change the first import line to
`from flask import Blueprint, current_app, g, render_template`, add the idle limit to the context
processor so it reads:
```python
    return {
        "idle_minutes": current_app.config["SESSION_IDLE_MINUTES"],
        "signed_in": g.get("page_user") is not None,
    }
```
and add the route at the end:
```python


@pages_bp.route("/timeout")
def timeout_page():
    """Shown after the idle timer signs someone out."""
    return render_template("auth/timeout.html")
```

**In `app/templates/base.html`:** change `<body>` to
```html
<body data-idle-minutes="{{ idle_minutes }}">
```
*(the browser gets the limit from the server's own setting, so the two can never drift apart)*

**In `app/templates/auth/dashboard.html`**, add under the `dashboard.js` line:
```html
<script src="{{ url_for('static', filename='js/session.js') }}"></script>
```

**Add to `tests/test_auth_pages.py`:**
```python


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
```

**Check:** `pytest -q tests/test_auth_pages.py` → **12 passed**, and `pytest -q` → everything
green.
**Commit:** `R21: logout button, idle timer and GET-safety test [K22]`

---

## 3. See it yourself, and collect the report evidence

```powershell
flask create-user alice
python run.py
```
Open <http://localhost:5000/>. Walk through this once; it is also the demo script:

1. **Wrong password** → *Invalid credentials*. Try a username that doesn't exist → the **same**
   message (R09).
2. **Correct password** → you land on *My account* with your username filled in.
3. Press **F12 → Application → Cookies**. `access_token_cookie` shows ✔ under **HttpOnly** and
   **Secure**; `csrf_access_token` does not (JavaScript has to read that one).
4. In the **Console**, type `localStorage` → it is empty. In the lab app, your session token
   would be sitting there.
5. **F12 → Network** → click `/dashboard` → **Headers**: `Content-Security-Policy` and
   `Cache-Control: no-store`.
6. Click **Log out**, then press the browser's **Back** button. You are sent to the login page,
   not back to your account.
7. Open a private window and type `http://localhost:5000/dashboard` directly → login page.

**Screenshots worth keeping** (they map straight onto acceptance criteria): the identical error
for a wrong password and an unknown user; the cookie panel showing HttpOnly and Secure with an
empty localStorage; the `no-store` and CSP headers; the back button after logout; the timeout
page; and `pytest -q` passing.

To film the idle timeout without waiting 15 minutes, temporarily put `SESSION_IDLE_MINUTES=1` in
your `.env`, record it, then put it back. Don't commit that change.

---

## 4. What is deliberately **not** here

| Missing | Comes with |
|---|---|
| Register and activation pages | Part 2, after the registration endpoints |
| MFA pages (`webauthn.js`) | Part 2, R08 |
| Recovery pages | Part 2, R10 |
| Admin page (create staff, roles) | Part 2, R12 |
| Enrolment pages (check, self-enrol, change address) | **Austin**, same `base.html` and `api.js` |
| Voting and audit pages | Keane and Yufei, same pattern |
| HTML error pages | Right now a bad URL returns JSON `{"error": "Not found"}` even in a browser. Fine for the prototype; raise it with the team if you want a prettier 404. |

**Tell the team** that `base.html`, `app.css` and `api.js` are now shared: everyone extends
`base.html` and calls `apiRequest(...)` rather than writing their own `fetch` and their own CSRF
handling. That is what keeps the GUI consistent and the CSRF token in one place.

---

## 5. For the report

| Brief's words | Where it is |
|---|---|
| Front-end GUI | `app/templates/`, `app/static/` |
| Server-side back-end | `app/routes/pages.py`, `app/security/` |
| RESTful web services | `/auth/login`, `/auth/me`, `/auth/logout` (JSON, proper status codes) |
| Database | SQLAlchemy models, `users` and `user_sessions` |
| Security at every level | The nine-row table in section 1: each row is a GUI-level control |
| Design patterns | Front controller (app factory + blueprints), decorator (`page_login_required`), template method (`base.html` blocks), single source of truth (`idle_minutes` from the server config) |
| Security principles | Complete mediation (every page checked server-side), fail secure (any JWT failure redirects to login), least astonishment (one generic error), defence in depth (CSP + HttpOnly + SameSite + CSRF + server-side session) |
| Security testing | `tests/test_auth_pages.py`, 12 tests, run by CI on every push |
