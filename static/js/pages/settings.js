// /settings/:section
import { $, $$, api, post, esc, ago, when, skel, empty, errBox, toast, device, setPressed, icon } from "../core.js";
import { refresh } from "../app.js";

const SECTIONS = [
  ["account", "Your account", false], ["ai", "AI model", true], ["response", "Response", true], ["watching", "What to watch", true],
  ["users", "Users", true], ["history", "Sign-in history", false], ["audit", "Audit log", true],
];
const PAL = [["harbor", "Harbor", "#1f6f7f"], ["ocean", "Ocean", "#1f5fa8"], ["forest", "Forest", "#2a6e46"], ["graphite", "Graphite", "#3b434c"]];
let timer = null;

export async function render(page, { params, ctx }) {
  const admin = ctx.me.role === "admin";
  const allowed = SECTIONS.filter(([, , adminOnly]) => admin || !adminOnly);
  const section = allowed.some(([k]) => k === params[0]) ? params[0] : "account";
  const title = SECTIONS.find(([k]) => k === section)[1];
  document.title = `${title} · Settings · Harrier`;
  page.innerHTML = `
    <div class="page-h"><div><h1 tabindex="-1">Settings</h1></div></div>
    <div class="settings">
      <nav class="subnav" aria-label="Settings">${allowed.map(([k, l]) => `<a href="/settings/${k}" data-link ${k === section ? 'aria-current="page"' : ""}>${l}</a>`).join("")}</nav>
      <div class="set" id="sec">${skel(6)}</div>
    </div>`;
  const el = $("#sec");
  const load = { account, ai, response, watching, users, history, audit }[section];
  try { await load(el, ctx); } catch (e) { errBox(el, e, () => load(el, ctx)); }
}

export function unmount() { clearTimeout(timer); }

const panel = (title, sub, body) => `<div class="panel"><div class="ph"><h2>${title}</h2>${sub ? `<span class="sub">${sub}</span>` : ""}</div><div class="pb">${body}</div></div>`;

/* ---------- Your account ---------- */
async function account(el, ctx) {
  const me = ctx.me, sessions = await api("/api/me/sessions");
  el.innerHTML = panel("Password", `${esc(me.username)} · ${me.role === "admin" ? "Admin" : "Viewer"}`, `
      <form id="pw" class="field"><div class="help">At least 10 characters. Your other devices are signed out when you change it.</div>
        <div class="inline"><label class="sr" for="cur">Current password</label><input type="password" id="cur" placeholder="Current password" autocomplete="current-password" required>
        <label class="sr" for="new">New password</label><input type="password" id="new" placeholder="New password" autocomplete="new-password" minlength="10" required>
        <button class="btn primary" type="submit">Change password</button></div></form>`)
    + panel("Colour", "", `<div class="swatches" role="group" aria-label="Colour">${PAL.map(([k, l, c]) => `<button class="swatch" type="button" data-pal="${k}" aria-pressed="${me.palette === k}"><i style="background:${c}"></i>${l}</button>`).join("")}</div>`)
    + panel("Signed in on", `${sessions.length} device${sessions.length === 1 ? "" : "s"}`, `
      <div class="list scroll"><table class="tbl"><tbody>${sessions.map(x => `<tr><td class="c-main">${esc(device(x.user_agent))}${x.current ? ` <span class="chip acc">This device</span>` : ""}</td>
        <td class="c-sub mono">${esc(x.ip)}</td><td class="c-sub">active ${ago(x.last_seen_at)}</td><td class="c-act num">${x.current ? "" : `<button class="btn" type="button" data-revoke="${x.id}">Sign out</button>`}</td></tr>`).join("")}</tbody></table></div>
      ${sessions.length > 1 ? `<div class="acts"><button class="btn" type="button" data-revoke="">Sign out everywhere else</button></div>` : ""}`);
  $("#pw").addEventListener("submit", async e => {
    e.preventDefault();
    try { await post("/api/me/password", { current: $("#cur").value, new: $("#new").value }); me.must_change_password = false; toast("Password changed. Your other devices were signed out."); refresh(); account(el, ctx); }
    catch (err) { toast(err.message); }
  });
  $$("[data-pal]", el).forEach(b => b.addEventListener("click", async () => {
    me.palette = b.dataset.pal; document.documentElement.dataset.palette = me.palette; setPressed(b.parentElement, b);
    await post("/api/me/palette", { palette: me.palette }).catch(err => toast(err.message));
  }));
  $$("[data-revoke]", el).forEach(b => b.addEventListener("click", async () => {
    await post("/api/me/sessions/revoke", { id: b.dataset.revoke }).catch(err => toast(err.message)); toast("Signed out"); account(el, ctx);
  }));
}

/* ---------- AI model ---------- */
async function ai(el) {
  const m = await api("/api/models");
  const have = new Set(m.installed.map(x => x.name)), p = m.pull, busy = p && !p.done;
  el.innerHTML = panel("Model in use", esc(m.ollama_url), `
      ${m.error ? `<div class="notice crit">${icon("i-alert")}<span>${esc(m.error)}</span></div>` : ""}
      <div class="field"><div class="help">Any Ollama model with JSON output works. After switching, run the AI red team under Health to see how it holds up.</div>
        <div class="inline"><label class="sr" for="model">Model</label><select id="model">${[...new Set([m.current, ...m.installed.map(x => x.name)])].map(n => `<option ${n === m.current ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>
        <button class="btn primary" type="button" id="use">Use this model</button></div></div>
      ${busy ? `<div class="field"><label class="h">Downloading ${esc(p.name)}</label><div class="progress"><i style="width:${p.percent || 0}%"></i></div><div class="help" style="margin-top:4px">${esc(p.status)} · ${p.percent || 0}%</div></div>`
        : p && p.error ? `<div class="notice crit">${icon("i-alert")}<span>Download of ${esc(p.name)} ${esc(p.status)}</span></div>` : ""}`)
    + panel("Download a model", m.ollama_url.includes("//ollama:") ? "Into Harrier's own Ollama" : "Into the Ollama shared with your other apps", `
      <div class="list scroll"><table class="tbl"><tbody>${m.recommended.map(r => `<tr><td class="c-main mono">${esc(r.name)}${r.note ? ` <span class="chip acc">${esc(r.note)}</span>` : ""}</td>
        <td class="c-sub">${esc(r.needs)}</td><td class="c-sub num">${r.size_gb} GB</td>
        <td class="c-act num">${have.has(r.name) ? `<span class="chip ok">Installed</span>` : `<button class="btn" type="button" data-pull="${esc(r.name)}" ${busy ? "disabled" : ""}>Download</button>`}</td></tr>`).join("")}</tbody></table></div>
      <form class="inline" id="other"><label class="sr" for="name">Other model</label><input type="text" id="name" placeholder="Other model, e.g. llama3.1:8b" spellcheck="false"><button class="btn" type="submit" ${busy ? "disabled" : ""}>Download</button></form>`);
  $("#use").addEventListener("click", async () => {
    try { await post("/api/settings", { model: $("#model").value }); toast(`Now using ${$("#model").value}`); refresh(); } catch (err) { toast(err.message); }
  });
  const pull = async name => { try { await post("/api/models/pull", { name }); toast(`Downloading ${name}`); ai(el); } catch (err) { toast(err.message); } };
  $$("[data-pull]", el).forEach(b => b.addEventListener("click", () => pull(b.dataset.pull)));
  $("#other").addEventListener("submit", e => { e.preventDefault(); const n = $("#name").value.trim(); if (n) pull(n); });
  clearTimeout(timer);
  if (busy) timer = setTimeout(() => location.pathname === "/settings/ai" && ai(el), 2000);
}

/* ---------- Response ---------- */
async function response(el) {
  const s = await api("/api/settings");
  el.innerHTML = panel("When an attack is clear-cut", "", `
      <div class="help">Automatic blocks on its own, always time-limited: 1 day, then 7, then 30 for repeat offenders. Review only suggests.</div>
      <div class="seg" role="group" aria-label="Mode" id="mode"><button type="button" data-v="auto" aria-pressed="${s.mode === "auto"}">Block automatically</button><button type="button" data-v="review" aria-pressed="${s.mode === "review"}">Review only</button></div>`)
    + panel("AI investigator", "", `
      <div class="help">Writes up medium and high incidents and recommends a response. It can only add or lengthen blocks; permanent blocks always need a person.</div>
      <div class="seg" role="group" aria-label="AI investigator" id="aiOn"><button type="button" data-v="1" aria-pressed="${!!s.ai_enabled}">On</button><button type="button" data-v="0" aria-pressed="${!s.ai_enabled}">Off</button></div>`);
  const save = async body => { try { await post("/api/settings", body); toast("Saved"); refresh(); } catch (err) { toast(err.message); } };
  $$("#mode button", el).forEach(b => b.addEventListener("click", () => { setPressed($("#mode"), b); save({ mode: b.dataset.v }); }));
  $$("#aiOn button", el).forEach(b => b.addEventListener("click", () => { setPressed($("#aiOn"), b); save({ ai_enabled: b.dataset.v === "1" }); }));
}

/* ---------- What to watch ---------- */
async function watching(el) {
  const s = await api("/api/settings");
  el.innerHTML = panel("What to watch", "", `
      <div class="field"><label class="h" for="dom">Your domains</label><div class="help">One per line. Checked from outside for DNS hijacking, defacement, certificate problems and downtime, wherever they're hosted.</div><textarea id="dom" spellcheck="false">${esc(s.domains.join("\n"))}</textarea></div>
      <div class="field"><label class="h" for="brand">Look-alike word</label><div class="help">New certificates for domains containing this word that aren't yours are flagged as possible phishing.</div><input type="text" id="brand" value="${esc(s.brand)}" spellcheck="false"></div>
      <div class="field"><label class="h" for="allow">Never block</label><div class="help">Addresses or ranges, one per line. Home, VPN and private ranges${s.own_ip ? `, and your public IP (${esc(s.own_ip)})` : ""} are always protected.</div><textarea id="allow" spellcheck="false">${esc(s.allowlist.join("\n"))}</textarea></div>
      <div class="field"><label class="h" for="ntfy">Phone alerts</label><div class="help">An <a href="https://ntfy.sh" target="_blank" rel="noopener">ntfy</a> topic URL. Install the ntfy app and subscribe to the same topic.</div>
        <div class="inline"><input type="url" id="ntfy" value="${esc(s.notify_url)}" placeholder="https://ntfy.sh/a-long-random-name"><button class="btn" type="button" id="test">Send test</button></div></div>
      <div class="acts"><button class="btn primary" type="button" id="save">Save</button></div>`);
  const lines = id => $(`#${id}`).value.split(/\n/).map(x => x.trim()).filter(Boolean);
  $("#save").addEventListener("click", async () => {
    try { await post("/api/settings", { domains: lines("dom"), brand: $("#brand").value, allowlist: lines("allow"), notify_url: $("#ntfy").value }); toast("Saved"); refresh(); }
    catch (err) { toast(err.message); }
  });
  $("#test").addEventListener("click", async () => {
    try { await post("/api/settings", { notify_url: $("#ntfy").value }); await post("/api/test-notify"); toast("Test alert sent"); } catch (err) { toast(err.message); }
  });
}

/* ---------- Users ---------- */
async function users(el, ctx) {
  const rows = await api("/api/users"), now = Date.now() / 1000;
  el.innerHTML = panel("Users", "Admins can change everything; viewers can only look", `
      <div class="list scroll"><table class="tbl"><thead><tr><th>User</th><th>Role</th><th>Last sign-in</th><th><span class="sr">Actions</span></th></tr></thead><tbody>
      ${rows.map(u => `<tr><td class="c-main">${esc(u.username)}${u.disabled ? ` <span class="chip">Disabled</span>` : ""}${u.locked_until > now ? ` <span class="chip warn">Locked</span>` : ""}${u.id === ctx.me.id ? ` <span class="chip acc">You</span>` : ""}</td>
        <td class="c-num"><label class="sr" for="role${u.id}">Role for ${esc(u.username)}</label><select id="role${u.id}" data-role="${u.id}" ${u.id === ctx.me.id ? "disabled" : ""}><option value="admin" ${u.role === "admin" ? "selected" : ""}>Admin</option><option value="viewer" ${u.role === "viewer" ? "selected" : ""}>Viewer</option></select></td>
        <td class="c-sub">${u.last_login_at ? ago(u.last_login_at) : "never"}</td>
        <td class="c-act num">${u.id === ctx.me.id ? "" : `<span class="inline" style="justify-content:flex-end">${u.locked_until > now ? `<button class="btn" type="button" data-u="${u.id}" data-op="unlock">Unlock</button>` : ""}
          <button class="btn" type="button" data-u="${u.id}" data-op="reset">Reset password</button><button class="btn" type="button" data-u="${u.id}" data-op="${u.disabled ? "enable" : "disable"}">${u.disabled ? "Enable" : "Disable"}</button>
          <button class="btn danger" type="button" data-u="${u.id}" data-op="delete">Delete</button></span>`}</td></tr>`).join("")}</tbody></table></div>
      <form class="inline" id="addUser"><label class="sr" for="nu">New username</label><input type="text" id="nu" placeholder="New username" autocomplete="off" spellcheck="false" required>
        <label class="sr" for="nr">Role</label><select id="nr"><option value="viewer">Viewer</option><option value="admin">Admin</option></select><button class="btn primary" type="submit">Add user</button></form>
      <div id="reveal"></div>`);
  const reveal = (who, pw) => { $("#reveal").innerHTML = `<div class="reveal">Temporary password for <b>${esc(who)}</b>, shown once: <code>${esc(pw)}</code>. They'll be asked to change it.</div>`; };
  $("#addUser").addEventListener("submit", async e => {
    e.preventDefault(); const name = $("#nu").value.trim();
    try { const r = await post("/api/users", { username: name, role: $("#nr").value }); await users(el, ctx); reveal(name, r.temporary_password); } catch (err) { toast(err.message); }
  });
  $$("[data-role]", el).forEach(s => s.addEventListener("change", async () => {
    try { await post(`/api/users/${s.dataset.role}`, { role: s.value }); toast("Role changed"); } catch (err) { toast(err.message); users(el, ctx); }
  }));
  $$("[data-op]", el).forEach(b => b.addEventListener("click", async () => {
    const id = b.dataset.u, op = b.dataset.op, name = rows.find(u => String(u.id) === id).username;
    if (op === "delete" && !confirm(`Delete ${name}? This can't be undone.`)) return;
    try {
      if (op === "delete") { await post(`/api/users/${id}`, {}, "DELETE"); return users(el, ctx); }
      const r = await post(`/api/users/${id}`, op === "reset" ? { reset_password: true } : op === "unlock" ? { unlock: true } : { disabled: op === "disable" });
      await users(el, ctx); if (r.temporary_password) reveal(name, r.temporary_password);
    } catch (err) { toast(err.message); }
  }));
}

/* ---------- Sign-in history ---------- */
async function history(el, ctx) {
  const rows = (await api("/api/login-history")).slice(0, 100);
  el.innerHTML = `<div class="panel"><div class="ph"><h2>Sign-in history</h2><span class="sub">${ctx.me.role === "admin" ? "Everyone" : "Your account"}</span></div>
    ${rows.length ? `<div class="scroll"><table class="tbl"><thead><tr><th>When</th><th>User</th><th>From</th><th>Device</th><th class="num">Result</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td class="c-sub">${when(r.at)}</td><td class="c-main">${esc(r.username)}</td><td class="c-sub mono">${esc(r.ip)}</td><td class="c-sub">${esc(device(r.user_agent))}</td>
      <td class="c-num">${r.success ? `<span class="chip ok">Signed in</span>` : `<span class="chip crit" title="${esc(r.reason)}">Failed: ${esc(r.reason)}</span>`}</td></tr>`).join("")}</tbody></table></div>`
      : empty("No sign-ins yet")}</div>`;
}

/* ---------- Audit log ---------- */
async function audit(el) {
  const rows = (await api("/api/activity")).slice(0, 200);
  const who = { harrier: "Rules", "harrier-ai": "AI", health: "Self-check" };
  el.innerHTML = `<div class="panel"><div class="ph"><h2>Audit log</h2><span class="sub">Every change, and who made it</span></div>
    ${rows.length ? `<div class="scroll"><table class="tbl"><thead><tr><th>When</th><th>Who</th><th>What</th><th>Target</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td class="c-sub">${when(r.at)}</td><td class="c-main">${esc(who[r.actor] || r.actor)}</td><td class="c-sub">${esc(r.action.replace(/_/g, " "))}${r.detail ? ` <span class="faint">${esc(r.detail.slice(0, 80))}</span>` : ""}</td>
      <td class="c-num mono">${esc(r.target)}</td></tr>`).join("")}</tbody></table></div>` : empty("Nothing yet")}</div>`;
}
