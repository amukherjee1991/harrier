// Sign-in page: show the right message, reveal-password toggle, and a busy state on submit.
const params = new URLSearchParams(location.search);
["failed", "locked", "throttled", "disabled", "signed_out"].forEach(k => { if (params.has(k)) document.getElementById(k).hidden = false; });
const pw = document.getElementById("password"), reveal = document.getElementById("reveal");
reveal.addEventListener("click", () => {
  const show = pw.type === "password";
  pw.type = show ? "text" : "password";
  reveal.setAttribute("aria-pressed", String(show));
  reveal.setAttribute("aria-label", show ? "Hide password" : "Show password");
  pw.focus();
});
document.getElementById("form").addEventListener("submit", () => {
  const b = document.getElementById("submit"); b.disabled = true; b.textContent = "Signing in…";
});
