// R13/R14: the auditor's page. It only reads the trail and asks the server to
// verify it; nothing on this page can change an event.

async function loadEvents() {
  const action = document.getElementById("action-filter").value;
  const path = "/audit/events" + (action ? "?action=" + encodeURIComponent(action) : "");
  const result = await apiRequest(path);
  const rows = document.getElementById("event-rows");
  rows.replaceChildren();
  if (!result.ok) {
    showError(result.data.error || "Could not load the audit trail");
    return;
  }
  document.getElementById("events-empty").hidden = result.data.events.length !== 0;
  result.data.events.forEach(function (event) {
    const row = document.createElement("tr");
    const target = event.target_type ? event.target_type + " " + (event.target_id || "") : "";
    [String(event.seq), event.occurred_at.slice(0, 19).replace("T", " "), event.action,
     event.result, event.actor_role ? event.actor_role + " " + event.actor_id.slice(0, 8) : "-",
     target].forEach(function (text) {
      const cell = document.createElement("td");
      cell.textContent = text;  // R04: data is always shown as text, never as HTML
      row.appendChild(cell);
    });
    rows.appendChild(row);
  });
}

document.getElementById("verify-button").addEventListener("click", async function () {
  clearError();
  const result = await apiRequest("/audit/verify", { method: "POST" });
  const box = document.getElementById("verify-result");
  if (!result.ok) {
    showError(result.data.error || "Verification failed to run");
    return;
  }
  box.textContent = result.data.intact
    ? "Intact: every event and anchor checks out."
    : "TAMPERING DETECTED: " + result.data.problems.join("; ");
  loadEvents();
});

document.getElementById("action-filter").addEventListener("change", loadEvents);
document.addEventListener("DOMContentLoaded", loadEvents);