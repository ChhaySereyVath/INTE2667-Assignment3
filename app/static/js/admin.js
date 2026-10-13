// R10/R12: the administrator's page. Every action here is checked again on the
// server (permission + MFA + not your own request); the page only collects clicks.

async function loadQueue() {
  const result = await apiRequest("/auth/recovery/pending");
  const rows = document.getElementById("queue-rows");
  rows.replaceChildren();
  if (!result.ok) {
    showError(result.data.error || "Could not load the queue");
    return;
  }
  const requests = result.data.requests;
  document.getElementById("queue").hidden = requests.length === 0;
  document.getElementById("queue-empty").hidden = requests.length !== 0;
  requests.forEach(function (item) {
    const row = document.createElement("tr");
    [item.username, item.role, item.requested_at.slice(0, 16).replace("T", " ")].forEach(function (text) {
      const cell = document.createElement("td");
      cell.textContent = text;  // textContent: a username can never become markup (R04)
      row.appendChild(cell);
    });
    const actions = document.createElement("td");
    ["approved", "rejected"].forEach(function (decision) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = decision === "approved" ? "button" : "button secondary";
      button.textContent = decision === "approved" ? "Approve" : "Reject";
      button.addEventListener("click", function () { decide(item.id, decision); });
      actions.appendChild(button);
    });
    row.appendChild(actions);
    rows.appendChild(row);
  });
}

async function decide(id, decision) {
  clearError();
  const result = await apiRequest("/auth/recovery/" + encodeURIComponent(id) + "/decision", {
    method: "POST",
    body: { decision: decision },
  });
  if (result.ok) {
    showNotice(result.data.message);
  } else {
    showError(result.status === 403 ? "You cannot decide this request (you cannot approve your own)."
                                     : (result.data.error || "Request failed"));
  }
  loadQueue();
}

document.getElementById("staff-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  clearError();
  showFieldErrors({});
  const states = Array.from(document.querySelectorAll('input[name="states"]:checked'))
    .map(function (box) { return box.value; });
  const result = await apiRequest("/auth/admin/staff", {
    method: "POST",
    body: {
      username: document.getElementById("staff_username").value,
      email: document.getElementById("staff_email").value,
      role: document.getElementById("staff_role").value,
      states: states,
      temporary_password: document.getElementById("staff_password").value,
    },
  });
  if (result.ok) {
    event.target.reset();
    showNotice("Account created for " + result.data.user.username + ". They have been emailed an activation link.");
  } else {
    showError(result.data.error || "Invalid request");
    showFieldErrors(result.data.fields);
  }
});

document.addEventListener("DOMContentLoaded", loadQueue);