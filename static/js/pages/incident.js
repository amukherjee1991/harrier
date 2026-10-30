// /incidents/:id: one incident with its full evidence, the AI's reasoning and the actions you can take.
import { $, api, esc, fmt, when, clock, left, skel, empty, errBox, sevChip, icon, KIND, ACTION } from "../core.js";
import { ipsOf, statusChips, approval, actions, bindActions } from "../incidents-ui.js";
import { refresh } from "../app.js";

export async function render(page, { params, ctx }) {
  const id = params[0];
  page.innerHTML = `<a class="crumb" href="/incidents" data-link>← Incidents</a><div id="inc">${skel(8)}</div>`;
  const el = $("#inc");
  const load = async () => {
    try {
      const i = await api(`/api/incidents/${id}`);
      document.title = `#${i.id} ${i.title} · Harrier`;
      const ai = i.ai, ips = ipsOf(i);
      el.innerHTML = `
        <div class="page-h"><div><div class="inline" style="margin-bottom:6px">${sevChip(i.severity)}<span class="faint">Incident #${i.id}</span></div>
          <h1 tabindex="-1">${esc(i.title)}</h1></div></div>
        <div class="detail-grid">
          <div>
            ${statusChips(i)}
            ${ai ? `<div class="note"><div class="lab">${icon("i-spark")}AI investigation · ${esc(ai.attack_type)} · ${Math.round((ai.confidence || 0) * 100)}% sure · suggests ${esc(ACTION[ai.recommended_action] || ai.recommended_action)}</div>
                <p>${esc(ai.summary)}</p><p><b>Why:</b> ${esc(ai.reasoning)}</p>${ai.next_steps ? `<p><b>What to check:</b> ${esc(ai.next_steps)}</p>` : ""}</div>`
              : `<div class="note"><div class="lab">${icon("i-spark")}AI investigation</div><p class="faint">${["medium", "high", "critical"].includes(i.severity) && ctx.ov && ctx.ov.ai_enabled ? "Queued." : "Not investigated: the AI writes up medium and higher incidents."}</p></div>`}
            ${approval(i)}${actions(i)}
            ${i.notes ? `<p class="muted" style="margin-top:12px">${esc(i.notes)}</p>` : ""}
            <h2 class="sec">Evidence</h2>
            <p class="lead">${fmt(i.signals.length)} signal${i.signals.length === 1 ? "" : "s"}, newest first. This is what the rules saw and what the AI was shown.</p>
            ${i.signals.length ? `<div class="evl">${i.signals.map(s => `<div>${clock(s.at)}  ${esc(s.ip)}  [${esc(KIND[s.kind] || s.kind)}]  ${esc(s.detail)}</div>`).join("")}</div>` : empty("No signals recorded")}
          </div>
          <aside class="panel"><div class="pb"><dl class="facts">
            <dt>Type</dt><dd>${esc({ campaign: "Coordinated attack", domain: "Domain", device: "Home device", ip: "Single address" }[i.kind] || i.kind)}</dd>
            <dt>Status</dt><dd>${esc({ open: "Open", blocked: "Blocked", resolved: "Resolved", false_positive: "False alarm" }[i.status] || i.status)}</dd>
            <dt>First seen</dt><dd>${when(i.first_at)}</dd><dt>Last seen</dt><dd>${when(i.last_at)}</dd>
            <dt>Signals</dt><dd>${fmt(i.signal_count)}</dd>
            ${ips.length ? `<dt>${ips.length === 1 ? "Address" : `Addresses (${ips.length})`}</dt><dd class="mono">${ips.slice(0, 30).map(esc).join("<br>")}${ips.length > 30 ? `<br>+${ips.length - 30} more` : ""}</dd>` : ""}
            ${i.blocks.length ? `<dt>Blocks</dt><dd>${i.blocks.map(b => `<span class="mono">${esc(b.ip)}</span> · ${b.active ? left(b.expires_at) : "lifted"}`).join("<br>")}</dd>` : ""}
          </dl></div></aside>
        </div>`;
    } catch (e) { errBox(el, e, load); }
  };
  bindActions(el, () => { refresh(); load(); });
  await load();
}
