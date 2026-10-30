// /traffic/web|dns|conn?only=flagged&q=...: live traffic with Harrier's verdict on each row.
import { $, api, esc, fmt, when, clock, skel, empty, errBox, KIND, SERIOUS, ACTION, icon } from "../core.js";
import { navigate } from "../app.js";

const SRC = {
  web: ["Web", "Requests to your sites through Caddy.", "requests", "addresses"],
  dns: ["Home devices", "Every DNS lookup by every device, from Pi-hole.", "lookups", "devices"],
  conn: ["Connections", "In and out of this machine, its containers and the VPN.", "connections", "addresses"],
};
let timer = null, state = null;

export async function render(page, { params, query }) {
  const src = params[0] || "web";
  state = { src, only: query.get("only") === "flagged" ? "flagged" : "all", q: query.get("q") || "", after: 0, rows: [], open: null, live: true };
  const link = (s, only) => `/traffic/${s}${only === "flagged" ? "?only=flagged" : ""}`;
  page.innerHTML = `
    <div class="page-h"><div><h1 tabindex="-1">Traffic</h1><p>${SRC[src][1]} Select a row to see what the AI concluded about that address.</p></div></div>
    <div class="tools">
      <nav class="seg" aria-label="Source">${Object.entries(SRC).map(([k, [l]]) => `<a href="${link(k, state.only)}" data-link ${k === src ? 'aria-current="page"' : ""}>${l}</a>`).join("")}</nav>
      <nav class="seg" aria-label="Filter"><a href="${link(src, "all")}" data-link ${state.only === "all" ? 'aria-current="page"' : ""}>Everything</a><a href="${link(src, "flagged")}" data-link ${state.only === "flagged" ? 'aria-current="page"' : ""}>Flagged</a></nav>
      <div class="grow"><label class="sr" for="q">Filter</label><input type="search" id="q" placeholder="Filter by address, path, device…" value="${esc(state.q)}"></div>
      <button class="btn" type="button" id="live" aria-pressed="true"><span class="dot"></span>Live</button>
    </div>
    <div id="devs"></div>
    <p class="lead" id="stats">&nbsp;</p>
    <div class="list scroll"><table class="tbl"><thead><tr><th>Time</th><th>From</th><th>${src === "dns" ? "Lookup" : "Request"}</th><th>${src === "web" ? "Status" : src === "dns" ? "Answer" : "State"}</th><th class="num">Verdict</th></tr></thead>
      <tbody id="rows"><tr><td colspan="5">${skel(6)}</td></tr></tbody></table></div>`;
  let qt;
  $("#q").addEventListener("input", e => {
    clearTimeout(qt);
    qt = setTimeout(() => {
      state.q = e.target.value.trim();
      const u = new URLSearchParams(location.search); state.q ? u.set("q", state.q) : u.delete("q");
      history.replaceState(null, "", `${location.pathname}${u.toString() ? "?" + u : ""}`);
      poll(true);
    }, 300);
  });
  $("#live").addEventListener("click", e => {
    state.live = !state.live;
    e.currentTarget.setAttribute("aria-pressed", String(state.live));
    e.currentTarget.innerHTML = `<span class="dot ${state.live ? "" : "warn"}"></span>${state.live ? "Live" : "Paused"}`;
  });
  const body = $("#rows");
  const toggle = tr => { state.open = state.open === +tr.dataset.id ? null : +tr.dataset.id; draw(); };
  body.addEventListener("click", e => { const tr = e.target.closest("tr.click"); if (tr) toggle(tr); });
  body.addEventListener("keydown", e => { const tr = e.target.closest("tr.click"); if (tr && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggle(tr); } });
  if (src === "dns") loadDevices();
  try { await poll(true); } catch (e) { errBox(body.closest(".list"), e, () => navigate(location.pathname + location.search, { replace: true })); }
  timer = setInterval(() => { if (state.live && !document.hidden) poll(false).catch(() => {}); }, 4000);
}

export function unmount() { clearInterval(timer); }

async function poll(reset) {
  if (reset) { state.after = 0; state.rows = []; }
  const r = await api(`/api/traffic?source=${state.src}&after=${state.after}&only=${state.only}&q=${encodeURIComponent(state.q)}`);
  const fresh = new Set(reset ? [] : r.rows.map(x => x.id));
  if (r.rows.length) { state.after = Math.max(state.after, ...r.rows.map(x => x.id)); state.rows = [...r.rows, ...state.rows].slice(0, 300); }
  const [, , noun, who] = SRC[state.src];
  const st = $("#stats"); if (st) st.textContent = `${fmt(r.stats.requests)} ${noun} in 24 h · ${fmt(r.stats.addresses)} ${who} · updated ${clock(Date.now() / 1000)}`;
  draw(fresh);
}

function verdict(r) {
  const c = [];
  if (r.blocked) c.push(`<span class="chip crit">Blocked</span>`);
  (r.flags || []).slice(0, 2).forEach(k => c.push(`<span class="chip ${SERIOUS.has(k) ? "crit" : "warn"}">${esc(KIND[k] || k)}</span>`));
  if (r.source === "dns" && r.status === 1) c.push(`<span class="chip">Blocked by Pi-hole</span>`);
  if (!c.length) c.push(r.incident && ["open", "blocked"].includes(r.incident.status) ? `<span class="chip warn">Watched</span>` : `<span class="chip ok">Normal</span>`);
  return `<span class="chips" style="justify-content:flex-end">${c.join("")}</span>`;
}

function row(r, fresh) {
  let who = `<span class="mono">${esc(r.ip)}</span>`, what = "", status = "";
  if (r.source === "web") { what = `<span class="mono">${esc(r.method)} ${esc(r.host)}${esc(r.path)}</span>`; status = r.status; }
  if (r.source === "dns") { who = esc(r.host || r.ip); what = `<span class="mono">${esc(r.path)}</span> <span class="faint">${esc(r.method)}</span>`; status = esc(r.ua || ""); }
  if (r.source === "conn") {
    const [dir, proto] = (r.method || ":").split(":"), port = (r.path || "").split(":").pop();
    who = `<span class="mono">${esc(dir === "in" ? r.ip : r.host)}</span>`;
    what = dir === "in" ? `in → port ${esc(port)} <span class="faint">${esc(proto)}</span>` : `out → <span class="mono">${esc(r.ip)}:${esc(port)}</span> <span class="faint">${esc(proto)}</span>`;
    status = esc((r.ua || "").toLowerCase().replace(/_/g, " "));
  }
  const open = state.open === r.id;
  let html = `<tr class="click${fresh ? " fresh" : ""}${open ? " open" : ""}" data-id="${r.id}" tabindex="0" aria-expanded="${open}">
    <td class="c-sub">${clock(r.at)}</td><td class="c-main">${who}</td><td class="c-sub">${what}</td><td class="c-sub">${status}</td><td class="c-num">${verdict(r)}</td></tr>`;
  if (open) {
    const i = r.incident, ai = i && i.ai;
    html += `<tr class="detail"><td colspan="5" class="c-sub">${r.source === "web" ? `<div class="faint" style="margin:6px 0">User agent: <span class="mono">${esc(r.ua) || "(none)"}</span></div>` : ""}
      ${ai ? `<div class="note" style="margin-top:6px"><div class="lab">${icon("i-spark")}AI on this address · suggests ${esc(ACTION[ai.action] || ai.action)}</div><p>${esc(ai.summary)}</p></div>`
        : `<p class="faint" style="margin:6px 0 0">${i ? `Incident #${i.id}: not written up by the AI yet.` : "Nothing suspicious from this address, so the AI wasn't asked about it."}</p>`}
      ${i ? `<div class="acts"><a class="btn" href="/incidents/${i.id}" data-link>Open incident #${i.id}</a></div>` : ""}</td></tr>`;
  }
  return html;
}

function draw(fresh = new Set()) {
  const b = $("#rows"); if (!b) return;
  b.innerHTML = state.rows.length ? state.rows.map(r => row(r, fresh.has(r.id))).join("")
    : `<tr><td colspan="5">${empty("Nothing yet", state.only === "flagged" ? "No traffic from flagged addresses." : state.q ? "Nothing matches that filter." : "Traffic appears here as it arrives.")}</td></tr>`;
}

async function loadDevices() {
  const el = $("#devs"); el.innerHTML = `<div class="list" style="margin-bottom:16px">${skel(3)}</div>`;
  try {
    const r = await api("/api/devices");
    const learning = r.learning_until && r.learning_until > Date.now() / 1000;
    el.innerHTML = `${learning ? `<div class="notice info">${icon("i-alert")}<span>Learning what's normal for your network until ${when(r.learning_until)}. New-device and check-in alerts start after that. Malware-style lookups are flagged already.</span></div>` : ""}
      <div class="list scroll" style="margin-bottom:16px"><table class="tbl"><thead><tr><th>Device</th><th class="num">Lookups, 24 h</th><th class="num">Blocked</th><th class="num">Domains</th><th>First seen</th><th class="num">Status</th></tr></thead><tbody>
      ${r.devices.slice(0, 50).map(x => `<tr><td class="c-main">${esc(x.name || x.ip)}${x.name ? `<div class="faint mono">${esc(x.ip)}</div>` : ""}</td>
        <td class="c-sub num">${fmt(x.lookups)} lookups</td><td class="c-sub num">${x.lookups ? Math.round(100 * x.blocked / x.lookups) + "% blocked" : "–"}</td>
        <td class="c-sub num">${fmt(x.domains)} domains</td><td class="c-sub">${when(x.first_seen)}</td>
        <td class="c-num">${x.flags.length ? `<span class="chips" style="justify-content:flex-end">${[...new Set(x.flags)].slice(0, 2).map(k => `<span class="chip warn">${esc(KIND[k] || k)}</span>`).join("")}</span>` : `<span class="chip ok">Normal</span>`}</td></tr>`).join("")
        || `<tr><td colspan="6">${empty("No devices yet", "They appear as Pi-hole sees them.")}</td></tr>`}
      </tbody></table>${r.devices.length > 50 ? `<div class="more">Showing 50 of ${fmt(r.devices.length)} devices</div>` : ""}</div>`;
  } catch (e) { errBox(el, e, loadDevices); }
}
