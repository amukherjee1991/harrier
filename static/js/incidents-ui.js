// Incident rows and actions, shared by the dashboard, the incident list and the incident page.
import { esc, fmt, ago, when, post, toast, sevChip, isPrivate, icon, ACTION, INCIDENT_TYPE } from "./core.js";

export function ipsOf(i) { return i.ips && i.ips.length ? i.ips : (i.ip ? [i.ip] : []); }

export function statusChips(i) {
  const ai = i.ai, c = [`<span class="chip">${INCIDENT_TYPE[i.kind] || esc(i.kind)}</span>`];
  if (i.status === "blocked") c.push(`<span class="chip crit">Blocked</span>`);
  if (i.status === "false_positive") c.push(`<span class="chip ok">False alarm</span>`);
  if (i.status === "resolved") c.push(`<span class="chip">Resolved</span>`);
  if (ai && ai.manipulation_attempt) c.push(`<span class="chip crit">Tried to manipulate the AI</span>`);
  if (ai && ai.ai_agent_suspected) c.push(`<span class="chip warn">AI agent suspected</span>`);
  return `<div class="chips">${c.join("")}</div>`;
}

export function aiNote(i, aiEnabled) {
  const ai = i.ai, open = ["open", "blocked"].includes(i.status);
  if (ai) return `<div class="note"><div class="lab">${icon("i-spark")}AI investigation · ${esc(ai.attack_type)} · ${Math.round((ai.confidence || 0) * 100)}% sure · suggests ${esc(ACTION[ai.recommended_action] || ai.recommended_action)}</div>
    <p>${esc(ai.summary)}</p>${ai.next_steps ? `<p><b>What to check:</b> ${esc(ai.next_steps)}</p>` : ""}</div>`;
  if (open && aiEnabled && ["medium", "high", "critical"].includes(i.severity)) return `<div class="note"><div class="lab">${icon("i-spark")}AI investigation</div><p class="faint">Queued.</p></div>`;
  return "";
}

export function approval(i) {
  if (!i.pending_action || !["open", "blocked"].includes(i.status)) return "";
  const n = ipsOf(i).length;
  return `<div class="approve" data-admin><span>The AI recommends <b>${esc(ACTION[i.pending_action])}</b>${n > 1 ? ` for all ${n} addresses` : ""}. It needs your approval.</span>
    <span class="acts"><button class="btn primary" type="button" data-act="approve" data-id="${i.id}">Approve</button><button class="btn" type="button" data-act="dismiss" data-id="${i.id}">Dismiss</button></span></div>`;
}

export function actions(i) {
  const open = ["open", "blocked"].includes(i.status), a = [];
  if (!open) return "";
  if (i.kind !== "domain" && ipsOf(i).some(x => !isPrivate(x))) {
    if (i.status !== "blocked") a.push(`<button class="btn danger" type="button" data-act="block_7d" data-id="${i.id}">${icon("i-ban")}Block 7 days</button>`);
    a.push(`<button class="btn" type="button" data-act="block_permanent" data-id="${i.id}">Block permanently</button>`);
  }
  if (i.kind === "domain") a.push(`<button class="btn" type="button" data-act="accept_change" data-id="${i.id}">${icon("i-check")}That was me</button>`);
  a.push(`<button class="btn" type="button" data-act="resolve" data-id="${i.id}">Resolve</button>`);
  if (i.kind !== "domain") a.push(`<button class="btn ghost" type="button" data-act="false_positive" data-id="${i.id}">False alarm</button>`);
  a.push(`<button class="btn ghost" type="button" data-act="reinvestigate" data-id="${i.id}">Ask AI again</button>`);
  return `<div class="acts" data-admin>${a.join("")}</div>`;
}

export function incidentRow(i, aiEnabled) {
  const ips = ipsOf(i);
  return `<article class="inc"><div class="inc-h">${sevChip(i.severity)}
      <div><a class="t" href="/incidents/${i.id}" data-link>${esc(i.title)}</a>
        <div class="m">${ips.length ? `<span class="mono">${ips.slice(0, 4).map(esc).join(", ")}</span>${ips.length > 4 ? ` +${ips.length - 4}` : ""} · ` : ""}${fmt(i.signal_count)} signal${i.signal_count === 1 ? "" : "s"} · first seen ${when(i.first_at)}</div></div>
      <span class="when">${ago(i.last_at)}</span></div>
    <div class="body">${statusChips(i)}${aiNote(i, aiEnabled)}${approval(i)}${actions(i)}</div></article>`;
}

const CONFIRM = {
  block_permanent: "Block permanently? Only a person can undo it.",
  false_positive: "Mark as a false alarm? This unblocks the address and adds it to your never-block list.",
};

/** Wire incident action buttons inside `root`; `after` runs once an action succeeds. */
export function bindActions(root, after) {
  root.addEventListener("click", async e => {
    const b = e.target.closest("button[data-act]");
    if (!b) return;
    if (CONFIRM[b.dataset.act] && !confirm(CONFIRM[b.dataset.act])) return;
    b.disabled = true;
    try { await post(`/api/incidents/${b.dataset.id}`, { action: b.dataset.act }); toast("Done"); after(); }
    catch (err) { toast(err.message); b.disabled = false; }
  });
}
