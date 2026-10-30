// /blocked: addresses blocked right now, and a form to block one by hand.
import { $, api, post, esc, ago, left, skel, empty, errBox, toast, icon } from "../core.js";
import { refresh } from "../app.js";

export async function render(page) {
  page.innerHTML = `
    <div class="page-h"><div><h1 tabindex="-1">Blocked</h1><p>Addresses that can't reach this machine or anything it serves. Blocks are applied before Docker, by the firewall guard.</p></div></div>
    <form class="tools" id="add" data-admin>
      <div class="grow"><label class="sr" for="ip">Address or range</label><input type="text" id="ip" placeholder="Address or range, e.g. 203.0.113.7" autocomplete="off" spellcheck="false"></div>
      <label class="sr" for="days">How long</label><select id="days"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option><option value="0">Permanent</option></select>
      <button class="btn primary" type="submit">${icon("i-ban")}Block</button></form>
    <div class="list scroll" id="list">${skel(4)}</div>`;
  const el = $("#list");
  const load = async () => {
    try {
      const rows = await api("/api/blocks");
      el.innerHTML = rows.length ? `<table class="tbl"><thead><tr><th>Address</th><th>Why</th><th>By</th><th>Since</th><th class="num">Ends</th><th data-admin><span class="sr">Actions</span></th></tr></thead><tbody>
        ${rows.map(r => `<tr><td class="c-main mono">${esc(r.ip)}</td><td class="c-sub">${r.incident_id ? `<a href="/incidents/${r.incident_id}" data-link>${esc(r.reason)}</a>` : esc(r.reason)}</td>
          <td class="c-sub">${{ rule: "Rules", ai: "AI", manual: "Person" }[r.source] || esc(r.source)}</td><td class="c-sub">${ago(r.created_at)}</td>
          <td class="c-num">${left(r.expires_at)}</td><td class="c-act num" data-admin><button class="btn" type="button" data-unblock="${esc(r.ip)}">Unblock</button></td></tr>`).join("")}</tbody></table>`
        : empty("Nothing blocked", "Clear-cut attackers are blocked here automatically, for a day at first.");
    } catch (e) { errBox(el, e, load); }
  };
  $("#add").addEventListener("submit", async e => {
    e.preventDefault();
    const ip = $("#ip").value.trim(); if (!ip) return;
    try { const r = await post("/api/blocks", { ip, days: +$("#days").value }); toast(r.ok ? `Blocked ${ip}` : r.error); if (r.ok) { $("#ip").value = ""; load(); refresh(); } }
    catch (err) { toast(err.message); }
  });
  el.addEventListener("click", async e => {
    const b = e.target.closest("[data-unblock]"); if (!b) return;
    b.disabled = true;
    try { await post(`/api/blocks/${encodeURIComponent(b.dataset.unblock)}`, {}, "DELETE"); toast(`Unblocked ${b.dataset.unblock}`); load(); refresh(); }
    catch (err) { toast(err.message); b.disabled = false; }
  });
  await load();
}
