// Logout button and the shared-terminal idle timer (R21).
// The server is the real authority: this only makes the browser agree with it,
// so a session is never left open on a polling-place computer.

const IDLE_MINUTES = Number(document.body.dataset.idleMinutes || 15);
let idleTimer = null;

async function endSession(destination) {
  try {
    await apiRequest("/auth/logout", { method: "POST" });
  } catch (error) {
    // the session still expires on the server, so finish signing out anyway
  }
  window.location.assign(destination);
}

function resetIdleTimer() {
  window.clearTimeout(idleTimer);
  idleTimer = window.setTimeout(function () {
    endSession("/timeout");
  }, IDLE_MINUTES * 60 * 1000);
}

document.addEventListener("DOMContentLoaded", function () {
  const button = document.getElementById("logout-button");
  if (button) {
    button.addEventListener("click", function () {
      endSession("/login");
    });
  }
  ["mousemove", "keydown", "click", "scroll"].forEach(function (name) {
    document.addEventListener(name, resetIdleTimer, { passive: true });
  });
  resetIdleTimer();
});