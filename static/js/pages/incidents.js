// /incidents?status=active|pending|closed|all
import { $, api, skel, empty, errBox } from "../core.js";
import { incidentRow, bindActions } from "../incidents-ui.js";
import { refresh } from "../app.js";

const FILTERS = [["active", "Open"], ["pending", "Needs approval"], ["closed", "Closed"], ["all", "All"]];
const EMPTY = {
  active: ["All quiet", "No open incidents. Harrier is watching."],
  pending: ["Nothing to approve", "When the AI recommends a permanent block, it waits here for you."],
  closed: ["No closed incidents", "Resolved incidents and false alarms show up here."],
  all: ["No incidents yet", "They appear as soon as Harrier sees something hostile."],
};
let timer = null;

export async function render(page, { query, ctx }) {
  const status = FILTERS.some(([k]) => k === query.get("status")) ? query.get("status") : "active";
  const pending = ctx.ov ? ctx.ov.pending : 0;
  page.innerHTML = `
    <div class="page-h"><div><h1 tabindex="-1">Incidents</h1><p>Everything Harrier flagged, with the AI's write-up. Open one for its full evidence.</p></div></div>
    <nav class="tools" aria-label="Filter"><div class="seg">${FILTERS.map(([k, l]) =>
      `<a href="/incidents${k === "active" ? "" : `?status=${k}`}" data-link ${k === status ? 'aria-current="page"' : ""}>${l}${k === "pending" && pending ? `<span class="n">${pending}</span>` : ""}</a>`).join("")}</div></nav>
    <div class="list" id="list">${skel(5)}</div>`;
  const list = $("#list");
  const load = async () => {
    try {
      const rows = await api(`/api/incidents?status=${status}`);
      list.innerHTML = rows.length ? rows.map(i => incidentRow(i, ctx.ov && ctx.ov.ai_enabled)).join("") : empty(...EMPTY[status]);
    } catch (e) { errBox(list, e, load); }
  };
  bindActions(list, () => { refresh(); load(); });
  await load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 30000);
}

export function unmount() { clearInterval(timer); }
