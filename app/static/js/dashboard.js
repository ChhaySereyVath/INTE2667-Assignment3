// Fills the page from /auth/me. The page itself contains no account data when
// it is served, so nothing leaks into the HTML source or a cached copy.
async function loadAccount() {
  const result = await apiRequest("/auth/me");
  if (!result.ok) {
    window.location.assign("/login");
    return;
  }
  const user = result.data.user;
  // textContent, never innerHTML: a username is shown as text, never as HTML (R04)
  document.getElementById("username").textContent = user.username;
  document.getElementById("role").textContent = user.role;
  document.getElementById("status").textContent = user.status;
}

document.addEventListener("DOMContentLoaded", loadAccount);