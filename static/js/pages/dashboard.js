// Dashboard: the at-a-glance view. Summary tiles, hostile activity per hour, domains, latest incidents.
import { $, api, esc, fmt, ago, clock, pad, skel, empty, errBox, LEVEL, KIND } from "../core.js";
import { incidentRow, bindActions } from "../incidents-ui.js";
import { refresh } from "../app.js";

let listener = null, ctxRef = null;

export async function render(page, { ctx }) {
  ctxRef = ctx;
  page.innerHTML = `
    <div class="page-h"><div><h1 tabindex="-1">Dashboard</h1></div></div>
    <section class="kpis" id="kpis" aria-label="Summary">${skel(2)}</section>
    <section class="row2">
      <div class="panel"><div class="ph"><h2>Hostile activity</h2><span class="sub" id="chartSub">Last 24 hours, per hour</span></div><div class="chart" id="chart">${skel(4)}</div></div>
      <div class="panel"><div class="ph"><h2>Your domains</h2><span class="sub">Checked from outside every 15 min</span></div><div class="pb" id="domains">${skel(3)}</div></div>
    </section>
    <div class="panel"><div class="ph"><h2>Latest open incidents</h2><a href="/incidents" data-link>All incidents</a></div><div id="latest">${skel(3)}</div></div>`;
  bindActions($("#latest"), () => { refresh(); loadLatest(); });
  listener = ov => draw(ov);
  ctx.listeners.add(listener);
  if (ctx.ov) draw(ctx.ov);
  loadLatest();
}

export function unmount() { if (ctxRef && listener) ctxRef.listeners.delete(listener); }

function draw(ov) {
  const g = ov.guard || {}, [lvl, cls] = LEVEL[ov.level] || LEVEL.info;
  $("#kpis").innerHTML = `
    <a class="panel kpi lead" href="/incidents" data-link><span class="l">Open incidents <span class="chip ${cls}">${lvl}</span></span><span class="v" style="display:block">${fmt(ov.open_incidents)}</span>
      <span class="s" style="display:block">${ov.pending ? `${ov.pending} waiting for your approval` : "Nothing waiting for you"}</span></a>
    <a class="panel kpi" href="/blocked" data-link><span class="l">Blocked now</span><span class="v" style="display:block">${fmt(ov.blocked_now)}</span>
      <span class="s" style="display:block">${fmt((g.dropped_total || 0) + (g.dropped_now || 0))} packets dropped</span></a>
    <a class="panel kpi" href="/traffic/web?only=flagged" data-link><span class="l">Hostile requests, 24 h</span><span class="v" style="display:block">${fmt(ov.signals_24h)}</span>
      <span class="s" style="display:block">from ${fmt(ov.attackers_24h)} address${ov.attackers_24h === 1 ? "" : "es"}</span></a>
    <a class="panel kpi" href="/traffic/dns" data-link><span class="l">Devices watched</span><span class="v" style="display:block">${fmt(ov.devices)}</span>
      <span class="s" style="display:block">${ov.learning_until > (ov.now || 0) ? "Learning what's normal" : ov.new_devices_24h ? `${ov.new_devices_24h} new today` : "No new devices today"}</span></a>`;
  drawChart(ov.hourly || [], ov.now || Date.now() / 1000);
  drawDomains(ov.domains || []);
}

async function loadLatest() {
  const el = $("#latest"); if (!el) return;
  try {
    const rows = (await api("/api/incidents?status=active")).slice(0, 5);
    el.innerHTML = rows.length ? `<div>${rows.map(i => incidentRow(i, ctxRef.ov && ctxRef.ov.ai_enabled)).join("")}</div>` : empty("All quiet", "No open incidents. Harrier is watching.");
  } catch (e) { errBox(el, e, loadLatest); }
}

function drawChart(rows, now) {
  const box = $("#chart"); if (!box) return;
  const hourNow = Math.floor(now / 3600) * 3600, byT = Object.fromEntries(rows.map(r => [r.t, r]));
  const data = Array.from({ length: 24 }, (_, i) => { const t = hourNow - (23 - i) * 3600; return byT[t] || { t, signals: 0, addresses: 0 }; });
  $("#chartSub").textContent = `Last 24 hours, per hour · updated ${clock(now)}`;
  if (!data.some(d => d.signals)) { box.innerHTML = `<div class="empty-chart">No hostile activity in the last 24 hours.</div>`; return; }
  // Draw at the panel's real width so text stays 11px on phones instead of being scaled down.
  const W = Math.max(300, Math.round(box.clientWidth - 32)), H = W < 500 ? 170 : 200, L = 30, B = 22, T = 26, max = Math.max(...data.map(d => d.signals));
  const top = Math.max(4, Math.ceil(max / 4) * 4), step = (W - L) / 24, bw = Math.max(3, step - 6);
  const y = v => H - B - (H - B - T) * v / top;
  const nz = data.map(d => d.signals).filter(Boolean).sort((a, b) => a - b), median = nz[Math.floor(nz.length / 2)] || 0;
  const peak = data.findIndex(d => d.signals === max);
  const spike = max >= 5 && max >= 3 * median && data[peak].cause_kind ? peak : -1;
  let s = `<svg viewBox="0 0 ${W} ${H}" style="height:${H}px" role="img" aria-label="Hostile requests per hour over the last 24 hours. Peak of ${max} at ${pad(new Date(data[peak].t * 1000).getHours())}:00${data[peak].cause_kind ? `, mostly ${esc(KIND[data[peak].cause_kind] || data[peak].cause_kind)}` : ""}.">`;
  for (let i = 0; i <= 4; i++) {
    const v = top * i / 4, yy = y(v);
    s += `<line x1="${L}" x2="${W}" y1="${yy}" y2="${yy}" stroke="var(--line)"/><text x="${L - 6}" y="${yy + 4}" text-anchor="end">${v}</text>`;
  }
  data.forEach((d, i) => {
    const x = L + i * step + 3;
    if (d.signals) s += `<rect x="${x}" y="${y(d.signals)}" width="${bw}" height="${H - B - y(d.signals)}" rx="2" fill="${i === 23 ? "var(--accent)" : "var(--bar)"}"/>`;
    s += `<rect x="${x - 3}" y="${T}" width="${step}" height="${H - B - T}" fill="transparent" data-i="${i}"/>`;
    if ((W < 500 ? i % 8 === 7 : i % 6 === 5) || i === 23) s += `<text x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${i === 23 ? "now" : pad(new Date(d.t * 1000).getHours()) + ":00"}</text>`;
  });
  if (spike >= 0) {
    const d = data[spike], x = L + spike * step + 3 + bw / 2, anchor = spike > 16 ? "end" : spike < 6 ? "start" : "middle";
    s += `<line x1="${x}" x2="${x}" y1="${T - 8}" y2="${y(d.signals) - 2}" stroke="var(--ink)"/>
          <text class="ann" x="${x}" y="${T - 12}" text-anchor="${anchor}">${esc(`${KIND[d.cause_kind] || d.cause_kind} · ${d.cause_ip}`)}</text>`;
  }
  box.innerHTML = s + `</svg><div class="tip"></div>`;
  const tip = box.querySelector(".tip");
  box.querySelectorAll("rect[data-i]").forEach(r => {
    r.addEventListener("pointermove", e => {
      const d = data[r.dataset.i], bb = box.getBoundingClientRect();
      tip.innerHTML = `<b>${pad(new Date(d.t * 1000).getHours())}:00</b> · ${fmt(d.signals)} hostile from ${fmt(d.addresses)}${d.cause_kind ? `<br><span class="faint">Mostly ${esc(KIND[d.cause_kind] || d.cause_kind)}, ${esc(d.cause_ip)}</span>` : ""}`;
      tip.style.left = Math.min(Math.max(0, e.clientX - bb.left - 60), bb.width - 220) + "px";
      tip.style.top = (e.clientY - bb.top - 56) + "px"; tip.style.opacity = 1;
    });
    r.addEventListener("pointerleave", () => { tip.style.opacity = 0; });
  });
}

function drawDomains(list) {
  const el = $("#domains"); if (!el) return;
  if (!list.length) {
    el.innerHTML = empty("No domains yet", ctxRef.me.role === "admin" ? "Add the domains you own in Settings to watch them for hijacking and look-alikes." : "An admin can add domains in Settings.");
    return;
  }
  el.innerHTML = list.map(d => {
    const checked = !!d.checked_at, bad = (d.problems || []).length, parts = [];
    if (d.http && d.http.status) parts.push(`HTTP ${d.http.status}`);
    if (d.tls && d.tls.expires) parts.push(`certificate ${Math.round((d.tls.expires - Date.now() / 1000) / 86400)} days left`);
    return `<div class="dom"><span class="chip ${!checked ? "" : bad ? "crit" : "ok"}">${!checked ? "Pending" : bad ? "Problem" : "OK"}</span><span class="n">${esc(d.name)}</span>
      <span class="d">${bad ? esc(d.problems.join("; ")) : checked ? `${parts.join(" · ")} · ${ago(d.checked_at)}` : "Not checked yet"}</span></div>`;
  }).join("");
}
