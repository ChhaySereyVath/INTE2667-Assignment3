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