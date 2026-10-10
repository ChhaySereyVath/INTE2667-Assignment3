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