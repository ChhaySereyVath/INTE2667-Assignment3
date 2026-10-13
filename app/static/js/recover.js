// R10: the three recovery pages. Each page has one form; this wires whichever is present.

function wireForm(formId, buttonId, send) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    clearError();
    showFieldErrors({});
    const button = document.getElementById(buttonId);
    button.disabled = true;
    try {
      const result = await send();
      if (result.ok) {
        form.hidden = true;
        showNotice(result.data.message);
        const login = document.getElementById("login-link");
        if (login && result.status === 200) login.hidden = false;
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
}

function field(id) {
  const element = document.getElementById(id);
  return element && element.value ? element.value : undefined;
}

// Page 1: ask for a link. The answer is the same whether or not the details match.
wireForm("recover-request-form", "recover-request-button", function () {
  return apiRequest("/auth/recovery/request", {
    method: "POST",
    body: { username: field("username"), email: field("email") },
  });
});

// Pages 2 and 3 carry a token in the link. Read it once, as the page opens.
const recoveryToken = document.getElementById("recover-request-form") ? null : takeFragmentToken();
if (!document.getElementById("recover-request-form") && !recoveryToken) {
  showError("This recovery link is not valid. Check you copied all of it.");
}

wireForm("recover-confirm-form", "recover-confirm-button", function () {
  return apiRequest("/auth/recovery/confirm", {
    method: "POST",
    body: { token: recoveryToken, date_of_birth: field("date_of_birth"), postcode: field("postcode") },
  });
});

wireForm("recover-reset-form", "recover-reset-button", function () {
  return apiRequest("/auth/recovery/reset", {
    method: "POST",
    body: { token: recoveryToken, new_password: field("new_password") },
  });
});