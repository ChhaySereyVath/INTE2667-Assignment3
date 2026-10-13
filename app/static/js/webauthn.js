// R08: talks to the security key through the browser's WebAuthn API.
// The private key never leaves the key or the device. The browser adds this site's
// real address to what the key signs, which is why a look-alike site cannot reuse it.

function b64urlToBuffer(text) {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const bytes = atob(padded);
  return Uint8Array.from(bytes, function (c) { return c.charCodeAt(0); }).buffer;
}

function bufferToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let text = "";
  bytes.forEach(function (b) { text += String.fromCharCode(b); });
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function addSecurityKey() {
  const begin = await apiRequest("/auth/mfa/register/begin", { method: "POST" });
  if (!begin.ok) throw new Error(begin.data.error || "Could not start");
  const options = begin.data.options;
  options.challenge = b64urlToBuffer(options.challenge);
  options.user.id = b64urlToBuffer(options.user.id);
  (options.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuffer(c.id); });

  const credential = await navigator.credentials.create({ publicKey: options });
  return apiRequest("/auth/mfa/register/finish", {
    method: "POST",
    body: {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
        attestationObject: bufferToB64url(credential.response.attestationObject),
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    },
  });
}

async function useSecurityKey() {
  const begin = await apiRequest("/auth/mfa/authenticate/begin", { method: "POST" });
  if (!begin.ok) throw new Error(begin.data.error || "Could not start");
  const options = begin.data.options;
  options.challenge = b64urlToBuffer(options.challenge);
  (options.allowCredentials || []).forEach(function (c) { c.id = b64urlToBuffer(c.id); });

  const credential = await navigator.credentials.get({ publicKey: options });
  return apiRequest("/auth/mfa/authenticate/finish", {
    method: "POST",
    body: {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
        authenticatorData: bufferToB64url(credential.response.authenticatorData),
        signature: bufferToB64url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? bufferToB64url(credential.response.userHandle) : null,
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    },
  });
}

function wireButton(id, action) {
  const button = document.getElementById(id);
  if (!button) return;
  button.addEventListener("click", async function () {
    clearError();
    button.disabled = true;
    try {
      const result = await action();
      if (result.ok) {
        window.location.assign("/dashboard");
        return;
      }
      showError(result.data.error || "Security key check failed. Try again.");
    } catch (error) {
      // the person cancelled, the key timed out, or the browser has no WebAuthn
      showError("The security key step did not complete. Try again.");
    } finally {
      button.disabled = false;
    }
  });
}

wireButton("enrol-button", addSecurityKey);
wireButton("verify-button", useSecurityKey);