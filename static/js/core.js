// Shared helpers: API calls, formatting, labels and small UI pieces used by every page.

export const $ = (s, root = document) => root.querySelector(s);
export const $$ = (s, root = document) => [...root.querySelectorAll(s)];
export const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
export const fmt = n => n == null ? "–" : Number(n).toLocaleString();

export async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, credentials: "same-origin", ...opts });
  if (r.status === 401) { location.href = "/login"; throw new Error("Signed out"); }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || `${r.status} ${r.statusText}`);
  return body;
}
export const post = (path, data, method = "POST") => api(path, { method, body: JSON.stringify(data || {}) });

export function toast(m) {
  const t = $("#toast"); t.textContent = m; t.classList.add("show");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 2600);
}

const pad = n => String(n).padStart(2, "0");
export { pad };
export function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
export function left(ts) {
  if (!ts) return "Permanent";
  const s = ts - Date.now() / 1000;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min left`;
  if (s < 86400) return `${Math.round(s / 3600)} h left`;
  return `${Math.round(s / 86400)} days left`;
}
export function when(ts) {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
export const clock = ts => { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };

export const SEV = { critical: ["Critical", "crit"], high: ["High", "crit"], medium: ["Medium", "warn"], low: ["Low", ""], info: ["Info", ""] };
export const LEVEL = { info: ["Calm", "ok"], low: ["Calm", "ok"], medium: ["Elevated", "warn"], high: ["High", "crit"], critical: ["Critical", "crit"] };
export const ACTION = { none: "No action", watch: "Keep watching", block_24h: "Block 24 h", block_7d: "Block 7 days",
                        block_30d: "Block 30 days", block_permanent: "Block permanently" };
export const KIND = {
  probe: "Probing", exploit: "Exploit attempt", manipulation: "Talking to the AI", scanner: "Attack tool", error_burst: "Error burst",
  brute_force: "Password guessing", login_fail: "Failed sign-in", learned_pattern: "Known attacker pattern", hostile_network: "Hostile network",
  ssh_fail: "Failed SSH login", ssh_login_after_failures: "SSH login after failures", port_scan: "Port scan", malicious_domain: "Malicious domain",
  new_device: "New device", dga: "Malware-style lookups", dns_tunnel: "Data hidden in DNS", beacon: "Regular check-ins", dns_spike: "Lookup spike",
  ssh_brute: "SSH guessing", unexpected_inbound: "Unexpected open port", suspicious_outbound: "Suspicious outgoing",
  callback_to_attacker: "Contacted an attacker", outbound_scan: "Scanning others",
};
export const SERIOUS = new Set(["exploit", "manipulation", "dga", "dns_tunnel", "callback_to_attacker", "outbound_scan", "ssh_login_after_failures"]);
export const INCIDENT_TYPE = { campaign: "Coordinated attack", domain: "Domain", device: "Home device", ip: "Single address" };

export const sevChip = s => `<span class="chip ${SEV[s] ? SEV[s][1] : ""}">${SEV[s] ? SEV[s][0] : esc(s)}</span>`;
export const isPrivate = ip => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|fe80:|fc|fd)/i.test(ip || "");
export const skel = n => `<div class="sk-rows" aria-busy="true" aria-label="Loading">${Array.from({ length: n }, (_, i) =>
  `<span class="sk" style="width:${[92, 68, 80, 55, 74][i % 5]}%"></span>`).join("")}</div>`;
export const empty = (title, line = "") => `<div class="empty"><b>${esc(title)}</b>${esc(line)}</div>`;
export function errBox(el, e, retry) {
  el.innerHTML = `<div class="err" role="alert"><span>Couldn't load this: ${esc(e.message)}</span><button class="btn" type="button">Retry</button></div>`;
  el.querySelector("button").addEventListener("click", retry);
}
export const icon = id => `<svg aria-hidden="true"><use href="#${id}"/></svg>`;
export function device(ua) {
  ua = ua || "";
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "Mac"
    : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "Unknown device";
  const br = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl/.test(ua) ? "curl" : "";
  return br ? `${br} on ${os}` : os;
}
export function setPressed(group, chosen) { $$("[aria-pressed]", group).forEach(b => b.setAttribute("aria-pressed", String(b === chosen))); }
