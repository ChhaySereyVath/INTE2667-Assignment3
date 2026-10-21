// The delegate's election screen. The server checks the permission, MFA and the
// workflow on every click; this page only shows buttons and results.

const NEXT_STEP = {
  draft: ["nominations_open", "Open nominations"],
  nominations_open: ["polling_open", "Open polling"],
  polling_open: ["polling_closed", "Close polling"],
  polling_closed: ["results_published", "Publish results"],
};

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text;  // R04: shown as text, never as markup
  return td;
}

async function loadElections() {
  const result = await apiRequest("/elections");
  const rows = document.getElementById("election-rows");
  rows.replaceChildren();
  if (!result.ok) {
    showError(result.data.error || "Could not load elections");
    return;
  }
  const elections = result.data.elections;
  document.getElementById("elections").hidden = elections.length === 0;
  document.getElementById("elections-empty").hidden = elections.length !== 0;
  elections.forEach(function (election) {
    const row = document.createElement("tr");
    row.appendChild(cell(election.name));
    row.appendChild(cell(election.status.replace("_", " ")));
    row.appendChild(cell(election.polling_opens_at.replace("T", " ")));
    const actions = document.createElement("td");
    const next = NEXT_STEP[election.status];
    if (next) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button";
      button.textContent = next[1];
      button.addEventListener("click", function () { changeStatus(election.id, next[0]); });
      actions.appendChild(button);
    }
    row.appendChild(actions);
    rows.appendChild(row);
  });
}

async function changeStatus(id, status) {
  clearError();
  const result = await apiRequest("/elections/" + encodeURIComponent(id) + "/status", {
    method: "POST",
    body: { status: status },
  });
  if (result.ok) {
    showNotice("Election is now: " + result.data.election.status.replace("_", " "));
  } else {
    showError(result.data.error || "Request failed");
  }
  loadElections();
}

document.getElementById("election-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  clearError();
  showFieldErrors({});
  const result = await apiRequest("/elections", {
    method: "POST",
    body: {
      name: document.getElementById("election_name").value,
      polling_opens_at: document.getElementById("polling_opens_at").value,
      polling_closes_at: document.getElementById("polling_closes_at").value,
    },
  });
  if (result.ok) {
    event.target.reset();
    showNotice("Election created with a House and a Senate contest in every state.");
    loadElections();
  } else {
    showError(result.data.error || "Invalid request");
    showFieldErrors(result.data.fields);
  }
});

document.addEventListener("DOMContentLoaded", loadElections);
