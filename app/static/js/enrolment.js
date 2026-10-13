// R03: a citizen checks their own enrolment, enrols, or changes their address.
// The page arrives with no personal details in it; they are fetched from
// /enrollment/me and written with textContent, so a name like O'Brien (or
// anything stranger) is always shown as text and never becomes markup (R04).

const FIELDS = ["given_name", "family_name", "date_of_birth", "address_line", "suburb", "state", "postcode"];

function show(id, visible) {
  document.getElementById(id).hidden = !visible;
}

function render(enrolment) {
  FIELDS.forEach(function (name) {
    document.getElementById("view-" + name).textContent = enrolment[name];
  });
  document.getElementById("enrolment-status").textContent = enrolment.status;
  document.getElementById("address_line").value = enrolment.address_line;
  document.getElementById("suburb").value = enrolment.suburb;
  document.getElementById("postcode").value = enrolment.postcode;
  document.getElementById("state").value = enrolment.state;
  show("enrolment-view", true);
  show("address-section", true);
  show("enrol-section", false);
}

async function load() {
  const result = await apiRequest("/enrollment/me");
  if (result.status === 404) {
    show("enrol-section", true);
    return;
  }
  if (!result.ok) {
    showError("Could not load your enrolment. Please sign in again.");
    return;
  }
  render(result.data.enrolment);
}

async function submit(event, request, buttonId, successMessage) {
  event.preventDefault();
  clearError();
  showFieldErrors({});
  const button = document.getElementById(buttonId);
  button.disabled = true;
  try {
    const result = await request();
    if (result.ok) {
      render(result.data.enrolment);
      showNotice(successMessage);
      return;
    }
    showError(result.status === 409 ? "You are already enrolled." : (result.data.error || "Invalid request"));
    showFieldErrors(result.data.fields);
  } catch (error) {
    showError("Could not reach the server. Please try again.");
  } finally {
    button.disabled = false;
  }
}

function value(id) {
  return document.getElementById(id).value;
}

document.getElementById("enrol-form").addEventListener("submit", function (event) {
  submit(event, function () {
    return apiRequest("/enrollment/me", {
      method: "POST",
      body: {
        given_name: value("given_name"), family_name: value("family_name"),
        date_of_birth: value("date_of_birth"), address_line: value("enrol_address_line"),
        suburb: value("enrol_suburb"), postcode: value("enrol_postcode"), state: value("enrol_state"),
      },
    });
  }, "enrol-button", "Thanks. Your enrolment has been received and is pending.");
});

document.getElementById("address-form").addEventListener("submit", function (event) {
  submit(event, function () {
    return apiRequest("/enrollment/me/address", {
      method: "PATCH",
      body: {
        address_line: value("address_line"), suburb: value("suburb"),
        postcode: value("postcode"), state: value("state"),
      },
    });
  }, "address-button", "Your address has been updated.");
});

document.addEventListener("DOMContentLoaded", load);