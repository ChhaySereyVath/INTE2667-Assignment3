// R16: the citizen's eligibility check. The page sends only which election and
// contest; the server decides, from its own records, and records the decision.

async function checkEligibility(electionId, contestType, output) {
  const result = await apiRequest("/voting/eligibility", {
    method: "POST",
    body: { election_id: electionId, contest_type: contestType },
  });
  output.textContent = result.ok ? result.data.message : (result.data.error || "Request failed");
}

async function loadOpenElections() {
  const result = await apiRequest("/elections");
  const list = document.getElementById("open-elections");
  list.replaceChildren();
  if (!result.ok) {
    showError(result.data.error || "Could not load elections");
    return;
  }
  const open = result.data.elections.filter(function (e) { return e.status === "polling_open"; });
  document.getElementById("voting-empty").hidden = open.length !== 0;
  open.forEach(function (election) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = election.name;  // R04: text only
    item.appendChild(title);
    ["house", "senate"].forEach(function (contestType) {
      const button = document.createElement("button");
      const output = document.createElement("p");
      button.type = "button";
      button.className = "button secondary";
      button.textContent = contestType === "house" ? "House of Representatives" : "Senate";
      button.addEventListener("click", function () {
        checkEligibility(election.id, contestType, output);
      });
      item.appendChild(button);
      item.appendChild(output);
    });
    list.appendChild(item);
  });
}

document.addEventListener("DOMContentLoaded", loadOpenElections);
