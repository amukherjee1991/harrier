// App shell: routing, header, notices and the shared overview poll. Each page lives in ./pages/.
import { $, $$, api, esc, ago, icon } from "./core.js";

export const ctx = { me: null, ov: null, listeners: new Set() };

const ROUTES = [
  { re: /^\/$/, nav: "dashboard", title: "Dashboard", load: () => import("./pages/dashboard.js") },
  { re: /^\/incidents\/?$/, nav: "incidents", title: "Incidents", load: () => import("./pages/incidents.js") },
  { re: /^\/incidents\/(\d+)$/, nav: "incidents", title: "Incident", load: () => import("./pages/incident.js") },
  { re: /^\/traffic(?:\/(web|dns|conn))?\/?$/, nav: "traffic", title: "Traffic", load: () => import("./pages/traffic.js") },
  { re: /^\/ai\/?$/, nav: "ai", title: "AI decisions", load: () => import("./pages/ai.js") },
  { re: /^\/blocked\/?$/, nav: "blocked", title: "Blocked", load: () => import("./pages/blocked.js") },
  { re: /^\/health\/?$/, nav: "health", title: "Health & learning", load: () => import("./pages/health.js") },
  { re: /^\/settings(?:\/(account|ai|response|watching|users|history|audit))?\/?$/, nav: "settings", title: "Settings", load: () => import("./pages/settings.js") },
];

let current = null, renderId = 0;

export function navigate(url, { replace = false } = {}) {
  if (url === location.pathname + location.search) return render();
  history[replace ? "replaceState" : "pushState"](null, "", url);
  render();
}

async function render() {
  const id = ++renderId, path = location.pathname;
  const route = ROUTES.find(r => r.re.test(path));
  if (current && current.unmount) current.unmount();
  current = null;
  $$(".nav a").forEach(a => a.dataset.nav === route?.nav ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"));
  const page = $("#page");
  if (!route) {
    document.title = "Not found · Harrier";
    page.innerHTML = `<div class="page-h"><div><h1 tabindex="-1">Page not found</h1><p>There's nothing at ${esc(path)}. <a href="/" data-link>Go to the dashboard</a>.</p></div></div>`;
    return;
  }
  const mod = await route.load();
  if (id !== renderId) return; // the user navigated again while this page was loading
  document.title = `${route.title} · Harrier`;
  current = mod;
  const params = path.match(route.re).slice(1);
  await mod.render(page, { params, query: new URLSearchParams(location.search), ctx });
  const h = page.querySelector("h1");
  if (h && document.activeElement === document.body) h.focus({ preventScroll: true });
}

// Same-origin links with data-link change pages without a reload.
document.addEventListener("click", e => {
  const a = e.target.closest("a[data-link]");
  if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || a.target) return;
  e.preventDefault();
  closeMenu();
  navigate(a.getAttribute("href"));
  window.scrollTo(0, 0);
});
window.addEventListener("popstate", render);

// ---- Header status, notices and badges (refreshed every 30 s) ----
export async function refresh() {
  let ov;
  try { ov = await api("/api/overview"); } catch {
    $("#state").innerHTML = `<span class="dot bad" aria-hidden="true"></span><span>Can't reach Harrier</span>`; return;
  }
  ctx.ov = ov;
  $("#host").textContent = ov.host_label || "this network";
  const g = ov.guard || {}, now = ov.now || Date.now() / 1000;
  const guardDown = !g.checked_at || now - g.checked_at > 60, stale = now - (ov.last_cycle || 0) > 120;
  $("#state").innerHTML = `<span class="dot ${(guardDown && !ov.dev) || stale ? "bad" : ""}" aria-hidden="true"></span>
    <span class="ago">Checked ${ago(ov.last_cycle)}</span>
    <span class="chip mode ${ov.mode === "auto" ? "acc" : "warn"}">${ov.mode === "auto" ? "Blocking automatically" : "Review only"}</span>`;
  const n = [];
  if (ctx.me && ctx.me.must_change_password) n.push(["warn", "You're using a temporary password. Choose your own now.", `<a class="btn" href="/settings/account" data-link>Change password</a>`]);
  if (ov.dev) n.push(["info", "Development copy: watch-only. Nothing here blocks traffic, and the AI and self-checks are off.", ""]);
  else if (guardDown) n.push(["crit", "The firewall guard isn't running, so blocks aren't being enforced. Check the harrier-guard container.", ""]);
  else if (g.error) n.push(["crit", `Firewall guard error: ${g.error}`, ""]);
  if (stale) n.push(["warn", "The log watcher hasn't run in the last 2 minutes.", ""]);
  if (ov.ai_error && ov.ai_enabled) n.push(["warn", `The AI investigator hit a problem: ${ov.ai_error}`, `<a class="btn" href="/settings/ai" data-link>AI settings</a>`]);
  if (ov.health_failed) n.push(["crit", `${ov.health_failed} self-check${ov.health_failed === 1 ? "" : "s"} failed.`, `<a class="btn" href="/health" data-link>See health</a>`]);
  $("#notices").innerHTML = n.map(([k, m, a]) => `<div class="notice ${k}" role="${k === "crit" ? "alert" : "status"}">${icon("i-alert")}<span>${esc(m)}</span>${a ? `<span class="act">${a}</span>` : ""}</div>`).join("");
  const np = $("#nPending"); np.hidden = !ov.pending; np.textContent = ov.pending; np.title = `${ov.pending} waiting for approval`;
  const nh = $("#nHealth"); nh.hidden = !ov.health_failed; nh.textContent = ov.health_failed;
  $("#foot").textContent = `Harrier ${ctx.me ? ctx.me.version : ""} · model ${ov.model}${ov.ai_enabled ? "" : " (AI off)"}${ov.ai_busy ? ` · investigating incident #${ov.ai_busy}` : ""}`;
  ctx.listeners.forEach(fn => fn(ov));
}

// ---- User menu ----
const ub = $("#userBtn"), um = $("#userMenu");
export function closeMenu() { um.setAttribute("data-closed", ""); ub.setAttribute("aria-expanded", "false"); }
ub.addEventListener("click", e => {
  e.stopPropagation();
  if (um.hasAttribute("data-closed")) { um.removeAttribute("data-closed"); ub.setAttribute("aria-expanded", "true"); um.querySelector("a").focus(); }
  else closeMenu();
});
document.addEventListener("click", e => { if (!e.target.closest(".user")) closeMenu(); });
document.addEventListener("keydown", e => { if (e.key === "Escape" && !um.hasAttribute("data-closed")) { closeMenu(); ub.focus(); } });

// ---- Start ----
(async () => {
  try { ctx.me = await api("/api/me"); } catch { return; }
  document.documentElement.dataset.palette = ctx.me.palette || "harbor";
  document.body.classList.toggle("viewer", ctx.me.role !== "admin");
  $("#userName").textContent = ctx.me.username;
  $("#menuUser").textContent = ctx.me.username;
  $("#menuRole").textContent = ctx.me.role === "admin" ? "Admin" : "Viewer (read-only)";
  await refresh();
  await render();
  setInterval(() => { if (!document.hidden) refresh(); }, 30000);
})();
