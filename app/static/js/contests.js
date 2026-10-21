// R15/R19: candidates, counts and approvals for a delegate. The server checks the
// permission, the delegate's states, a fresh security-key check and the integrity of
// every ballot; this page only collects clicks and shows the answers as text.

let contests = [];
let names = {};

function textCell(text) {
  const cell = document.createElement("td");
  cell.textContent = text;  // R04: data is shown as text, never as markup
  return cell;
}

function selectedContest() {
  return contests.find(function (c) { return c.id === document.getElementById("contest-select").value; });
}

function explain(result) {
  if (result.data.reauthenticate) {
    showError("Please confirm with your security key again: open the MFA page, then retry.");
  } else {
    showError(result.data.error || "Request failed");
  }
}

async function loadElections() {
  const result = await apiRequest("/elections");
  const select = document.getElementById("election-select");
  select.replaceChildren();
  if (!result.ok) { explain(result); return; }
  result.data.elections.forEach(function (election) {
    const option = document.createElement("option");
    option.value = election.id;
    option.textContent = election.name + " (" + election.status.replace("_", " ") + ")";
    select.appendChild(option);
  });
  loadContests();
}

async function loadContests() {
  const id = document.getElementById("election-select").value;
  if (!id) return;
  const result = await apiRequest("/elections/" + encodeURIComponent(id));
  if (!result.ok) { explain(result); return; }
  contests = result.data.election.contests;
  const select = document.getElementById("contest-select");
  select.replaceChildren();
  contests.forEach(function (contest) {
    const option = document.createElement("option");
    option.value = contest.id;
    option.textContent = contest.state + " " + (contest.contest_type === "house" ? "House" : "Senate");
    select.appendChild(option);
  });
  showContest();
}

function showContest() {
  const contest = selectedContest();
  const list = document.getElementById("candidate-list");
  list.replaceChildren();
  if (!contest) return;
  names = {};
  contest.candidates.forEach(function (candidate) {
    names[candidate.id] = candidate.name;
    const item = document.createElement("li");
    item.textContent = candidate.name + " (" + candidate.party + ") ";
    const withdraw = document.createElement("button");
    withdraw.type = "button";
    withdraw.className = "button secondary";
    withdraw.textContent = "Withdraw";
    withdraw.addEventListener("click", function () { withdrawCandidate(candidate.id); });
    item.appendChild(withdraw);
    list.appendChild(item);
  });
  loadRuns();
}

async function withdrawCandidate(id) {
  clearError();
  const result = await apiRequest("/candidates/" + encodeURIComponent(id) + "/withdraw", { method: "POST" });
  if (result.ok) { showNotice("Candidate withdrawn (signed)."); loadContests(); } else { explain(result); }
}

async function loadRuns() {
  const contest = selectedContest();
  const rows = document.getElementById("run-rows");
  rows.replaceChildren();
  const result = await apiRequest("/contests/" + encodeURIComponent(contest.id) + "/count-runs");
  if (!result.ok) { document.getElementById("runs").hidden = true; return; }
  document.getElementById("runs").hidden = result.data.count_runs.length === 0;
  result.data.count_runs.forEach(function (run) {
    const row = document.createElement("tr");
    row.appendChild(textCell(run.created_at.slice(0, 19).replace("T", " ")));
    row.appendChild(textCell(run.status === "completed" ? "completed" : "INTEGRITY FAILED"));
    row.appendChild(textCell(run.result ? run.result.elected.map(function (id) { return names[id] || id; }).join(", ") : "-"));
    const approval = document.createElement("td");
    if (run.approved) {
      approval.textContent = "approved";
    } else if (run.status === "completed") {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button";
      button.textContent = "Approve";
      button.addEventListener("click", function () { approveRun(run.id); });
      approval.appendChild(button);
    }
    row.appendChild(approval);
    rows.appendChild(row);
  });
}

async function approveRun(id) {
  clearError();
  const result = await apiRequest("/count-runs/" + encodeURIComponent(id) + "/approve", { method: "POST" });
  if (result.ok) { showNotice("Result approved (signed)."); loadRuns(); } else { explain(result); }
}

document.getElementById("count-button").addEventListener("click", async function () {
  clearError();
  const contest = selectedContest();
  const result = await apiRequest("/contests/" + encodeURIComponent(contest.id) + "/count", { method: "POST" });
  if (result.ok) {
    showNotice("Count completed. A different delegate must approve it.");
  } else if (result.data.count_run) {
    showError("Integrity check FAILED, no result was produced: " + result.data.count_run.problems.join("; "));
  } else {
    explain(result);
  }
  loadRuns();
});

document.getElementById("candidate-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  clearError();
  showFieldErrors({});
  const contest = selectedContest();
  const result = await apiRequest("/contests/" + encodeURIComponent(contest.id) + "/candidates", {
    method: "POST",
    body: {
      name: document.getElementById("candidate_name").value,
      party: document.getElementById("candidate_party").value,
    },
  });
  if (result.ok) {
    event.target.reset();
    showNotice("Candidate added (signed).");
    loadContests();
  } else {
    explain(result);
    showFieldErrors(result.data.fields);
  }
});

document.getElementById("election-select").addEventListener("change", loadContests);
document.getElementById("contest-select").addEventListener("change", showContest);
document.addEventListener("DOMContentLoaded", loadElections);
