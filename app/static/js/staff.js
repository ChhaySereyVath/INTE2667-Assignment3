// R03/R05/R11: the staff enrolment screen. The page only collects clicks; every
// rule (your states only, maker-checker, who sees history values) is enforced by
// the API, so editing this script in the browser unlocks nothing.

const canApprove = document.getElementById("queue-card").dataset.canApprove === "yes";
let openId = null;

function cell(text) {
  const td = document.createElement("td");
  td.textContent = text === undefined || text === null ? "" : text;  // text only (R04)
  return td;
}

function when(iso) {
  return iso ? iso.slice(0, 16).replace("T", " ") : "";
}

async function loadQueue() {
  const result = await apiRequest("/enrollment/pending");
  const rows = document.getElementById("queue-rows");
  rows.replaceChildren();
  if (!result.ok) {
    showError(result.data.error || "Could not load the queue");
    return;
  }
  const items = result.data.enrolments;
  document.getElementById("queue").hidden = items.length === 0;
  document.getElementById("queue-empty").hidden = items.length !== 0;
  items.forEach(function (item) {
    const row = document.createElement("tr");
    row.append(cell(when(item.received_at)), cell(item.state), cell(item.status));
    const action = document.createElement("td");
    const open = document.createElement("button");
    open.type = "button";
    open.className = "button secondary";
    open.textContent = "Open";
    open.addEventListener("click", function () { openRecord(item); });
    action.appendChild(open);
    row.appendChild(action);
    rows.appendChild(row);
  });
}

async function openRecord(item) {
  clearError();
  const record = await apiRequest("/enrollment/" + encodeURIComponent(item.id));
  if (!record.ok) {
    showError(record.data.error || "Could not open this enrolment");
    return;
  }
  openId = item.id;
  const data = record.data.enrolment;
  ["given_name", "family_name", "date_of_birth", "address_line", "suburb", "state", "postcode", "status"]
    .forEach(function (name) { document.getElementById("rec-" + name).textContent = data[name]; });
  if (canApprove) {
    document.getElementById("own-registration").hidden = !item.registered_by_you;
    document.getElementById("decision-buttons").hidden = item.registered_by_you;
  }
  await loadHistory(item.id);
  document.getElementById("record-card").hidden = false;
}

async function loadHistory(id) {
  const result = await apiRequest("/enrollment/" + encodeURIComponent(id) + "/history");
  const rows = document.getElementById("history-rows");
  rows.replaceChildren();
  if (!result.ok) return;
  let valuesHidden = false;
  result.data.history.forEach(function (entry) {
    if (!("old_value" in entry)) valuesHidden = true;
    const row = document.createElement("tr");
    row.append(cell(when(entry.created_at)), cell(entry.action), cell(entry.field),
               cell(entry.old_value), cell(entry.new_value));
    rows.appendChild(row);
  });
  document.getElementById("history-note").hidden = !valuesHidden;
}

async function decide(decision) {
  if (!openId) return;
  clearError();
  const result = await apiRequest("/enrollment/" + encodeURIComponent(openId) + "/decision", {
    method: "POST",
    body: { decision: decision },
  });
  if (result.ok) {
    showNotice("Enrolment " + decision + ".");
    document.getElementById("record-card").hidden = true;
    openId = null;
    loadQueue();
  } else {
    showError(result.status === 403 ? "You cannot decide this enrolment." : (result.data.error || "Request failed"));
  }
}

if (canApprove) {
  document.getElementById("approve-button").addEventListener("click", function () { decide("approved"); });
  document.getElementById("reject-button").addEventListener("click", function () { decide("rejected"); });
}

document.addEventListener("DOMContentLoaded", loadQueue);