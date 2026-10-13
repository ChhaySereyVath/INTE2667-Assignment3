// The activation link looks like /activate#token=...
// Everything after "#" stays in the browser: it is never sent to the server in the
// page request, so the token does not land in server logs or a Referer header.
// This script reads it, removes it from the address bar, and POSTs it (R09).
(async function () {
  const status = document.getElementById("activate-status");
  const match = window.location.hash.match(/^#token=([A-Za-z0-9_-]{20,100})$/);
  // take the token out of the address bar and the history straight away
  history.replaceState(null, "", window.location.pathname);

  if (!match) {
    status.hidden = true;
    showError("This activation link is not valid. Check you copied all of it.");
    return;
  }
  try {
    const result = await apiRequest("/auth/activate", { method: "POST", body: { token: match[1] } });
    status.hidden = true;
    if (result.ok) {
      showNotice(result.data.message);
      document.getElementById("login-link").hidden = false;
    } else {
      showError("This activation link is not valid, or it has already been used or has expired.");
    }
  } catch (error) {
    status.hidden = true;
    showError("Could not reach the server. Please try again.");
  }
})();