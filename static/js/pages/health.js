// /health: Harrier's self-checks, and what it has learned.
import { $, api, post, esc, fmt, ago, when, skel, empty, errBox, toast, KIND } from "../core.js";

const SUITE = {
  live: ["Live system", "Firewall, logs, AI and domain checks on the running system"],
  replay: ["Attack replay", "Scripted attacks, false alarms, safety rules and accounts"],
  ai: ["AI red team", "Manipulation attempts and harmless look-alikes against the model"],
};
let timer = null;

export async function render(page) {
  page.innerHTML = `
    <div class="page-h"><div><h1 tabindex="-1">Health &amp; learning</h1><p>Harrier tests itself on a schedule and learns from confirmed attacks and from your decisions.</p></div></div>
    <div id="body">${skel(8)}</div>`;
  const el = $("#body");
  const load = async () => {
    try {
      const [h, l] = await Promise.all([api("/api/health"), api("/api/learned")]);
      const busy = !!(h.running || h.requested);
      el.innerHTML = `<div class="suites">${Object.entries(h.suites).map(([k, s]) => suite(k, s, h)).join("")}</div>
        <h2 class="sec">What Harrier has learned</h2>
        <p class="lead">Only from your decisions and from attackers it has confirmed, never from what traffic says. A new pattern needs at least two attackers and must never appear in normal visitors' traffic. Learning only adds detection; only "False alarm" decisions make Harrier less sensitive.</p>
        <div class="list">${l.lessons.length ? l.lessons.map(x => `<div class="lesson"><span class="faint">${when(x.at)}</span><span>${esc(x.detail)}</span></div>`).join("") : empty("Nothing learned yet", "Lessons appear as attackers are confirmed and as you mark incidents.")}</div>
        <h2 class="sec">Learned patterns</h2>
        <div class="list scroll">${l.intel.length ? `<table class="tbl"><thead><tr><th>Type</th><th>Pattern</th><th class="num">Attackers</th><th class="num">Matches</th><th data-admin><span class="sr">Actions</span></th></tr></thead><tbody>
          ${l.intel.map(x => `<tr><td class="c-sub">${{ path: "Path", ua: "Tool signature", network: "Network" }[x.kind] || esc(x.kind)}</td><td class="c-main mono">${esc(x.value)}</td>
            <td class="c-sub num">${x.sources.length} attackers</td><td class="c-num">${fmt(x.hits)}</td>
            <td class="c-act num" data-admin><button class="btn" type="button" data-intel="${x.id}" data-on="${x.active ? 0 : 1}">${x.active ? "Turn off" : "Turn on"}</button></td></tr>`).join("")}</tbody></table>`
          : empty("No learned patterns yet", "Paths, tools and networks used by confirmed attackers appear here.")}</div>
        <h2 class="sec">Sensitivity</h2>
        <p class="lead">How much each kind of signal counts, tuned by your approvals and false-alarm marks.</p>
        <div class="list scroll">${l.weights.length ? `<table class="tbl"><thead><tr><th>Signal</th><th class="num">Counts as</th><th class="num">Confirmed</th><th class="num">False alarms</th></tr></thead><tbody>
          ${l.weights.map(w => `<tr><td class="c-main">${esc(KIND[w.kind] || w.kind)}</td><td class="c-num">${w.weight}×</td><td class="c-sub num">${w.confirmed} confirmed</td><td class="c-sub num">${w.false_alarms} false alarms</td></tr>`).join("")}</tbody></table>`
          : empty("Default sensitivity", "Every signal counts 1× until you approve blocks or mark false alarms.")}</div>`;
      clearTimeout(timer);
      if (busy) timer = setTimeout(load, 5000);
    } catch (e) { errBox(el, e, load); }
  };
  el.addEventListener("click", async e => {
    const r = e.target.closest("[data-run]"), t = e.target.closest("[data-intel]");
    if (r) { r.disabled = true; try { await post("/api/health/run", { suite: r.dataset.run }); toast("Queued. Results appear here when it's done."); load(); } catch (err) { toast(err.message); } }
    if (t) { try { await post(`/api/learned/${t.dataset.intel}`, { active: t.dataset.on === "1" }); load(); } catch (err) { toast(err.message); } }
  });
  await load();
}

export function unmount() { clearTimeout(timer); }

function suite(k, s, h) {
  const last = s.last, ok = last && last.passed === last.total, running = h.running === k || h.requested === k;
  const every = s.every_hours >= 48 ? `${Math.round(s.every_hours / 24)} days` : `${s.every_hours} h`;
  return `<div class="panel suite"><div class="ph"><h2>${SUITE[k][0]}</h2><span class="sub">every ${every}</span></div>
    <div class="pb"><div class="faint" style="font-size:12.5px">${SUITE[k][1]}</div>
      <div class="big ${last ? (ok ? "ok" : "bad") : ""}">${last ? `${last.passed} / ${last.total}` : "–"}</div>
      <div class="faint" style="font-size:12.5px">${running ? "Running now…" : last ? `passed · ${ago(last.at)}` : "Not run yet"}</div>
      <div class="hist" aria-label="Recent runs">${s.history.slice().reverse().map(r => `<span class="${r.passed === r.total ? "" : "bad"}" style="height:${6 + 14 * r.passed / Math.max(1, r.total)}px" title="${r.passed}/${r.total}"></span>`).join("")}</div>
      <button class="btn" type="button" data-run="${k}" data-admin ${running ? "disabled" : ""}>${running ? "Running…" : "Run now"}</button>
      <details class="more-checks"><summary>${s.checks.length} checks</summary><div class="checks">${s.checks.map(c => `<div><span class="${c.status === "pass" ? "yes" : "no"}" aria-label="${c.status === "pass" ? "passed" : "failed"}">${c.status === "pass" ? "✓" : "✕"}</span><span>${esc(c.name)}</span>${c.detail ? `<span class="d">${esc(c.detail)}</span>` : ""}</div>`).join("")}</div></details></div></div>`;
}
