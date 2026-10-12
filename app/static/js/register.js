// Posts the registration form. The server gives the same answer whether or not
// the username or email is already taken (R09), so the page does too.
document.getElementById("register-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  clearError();
  showFieldErrors({});

  const button = document.getElementById("register-button");
  button.disabled = true;
  try {
    const result = await apiRequest("/auth/register", {
      method: "POST",
      body: {
        username: document.getElementById("username").value,
        email: document.getElementById("email").value,
        password: document.getElementById("password").value,
      },
    });
    if (result.status === 202) {
      document.getElementById("register-form").hidden = true;
      showNotice(result.data.message);
      return;
    }
    showError(result.data.error || "Invalid request");
    showFieldErrors(result.data.fields);
  } catch (error) {
    showError("Could not reach the server. Please try again.");
  } finally {
    button.disabled = false;
  }
});