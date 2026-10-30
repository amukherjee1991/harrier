// /ai: every investigation the AI has written.
import { $, api, esc, ago, skel, empty, errBox, sevChip, icon, ACTION } from "../core.js";

export async function render(page) {
  page.innerHTML = `
    <div class="page-h"><div><h1 tabindex="-1">AI decisions</h1><p>Every investigation the AI has written, newest first. The AI recommends; rules and people decide what happens.</p></div></div>
    <div class="list" id="list">${skel(5)}</div>`;
  const el = $("#list");
  const load = async () => {
    try {
      const rows = await api("/api/ai-feed");
      el.innerHTML = rows.length ? rows.map(i => {
        const a = i.ai;
        const outcome = i.pending_action ? `<span class="chip warn">Waiting for approval</span>` : i.status === "blocked" ? `<span class="chip crit">Blocked</span>` : `<span class="chip">Not blocked</span>`;
        return `<article class="inc"><div class="inc-h">${sevChip(i.severity)}
            <div><a class="t" href="/incidents/${i.id}" data-link>${esc(i.title)}</a><div class="m">Suggested ${esc(ACTION[a.recommended_action] || a.recommended_action)} · ${Math.round((a.confidence || 0) * 100)}% sure</div></div>
            <span class="when">${ago(i.ai_at)}</span></div>
          <div class="body"><div class="chips">${outcome}${a.manipulation_attempt ? `<span class="chip crit">Tried to manipulate the AI</span>` : ""}${a.ai_agent_suspected ? `<span class="chip warn">AI agent suspected</span>` : ""}</div>
          <div class="note"><div class="lab">${icon("i-spark")}${esc(a.attack_type)}</div><p>${esc(a.summary)}</p><p><b>Why:</b> ${esc(a.reasoning)}</p>${a.next_steps ? `<p><b>What to check:</b> ${esc(a.next_steps)}</p>` : ""}</div></div></article>`;
      }).join("") : empty("No investigations yet", "The AI writes up medium and high incidents as they happen.");
    } catch (e) { errBox(el, e, load); }
  };
  await load();
}
