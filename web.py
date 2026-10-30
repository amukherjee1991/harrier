"""Harrier dashboard; also runs the watcher, the AI investigator and the domain checks in the background."""
import ipaddress
import json
import logging
import os
import threading
import time

import requests
from flask import Flask, abort, g, jsonify, redirect, request, send_from_directory
from waitress import serve

import auth
import harrier
import health
import learn

VERSION = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")).read().strip()
HERE = os.path.dirname(__file__)
COOKIE = "harrier_session"
OPEN_PATHS = {"/login", "/logout", "/healthz"}
SELF_SERVICE = ("/api/me",)  # what viewers may change: their own password, colours and sessions
# Requests through a reverse proxy on these networks carry the real client in X-Forwarded-For.
TRUSTED_PROXIES = [ipaddress.ip_network(n.strip()) for n in
                   os.environ.get("TRUSTED_PROXIES", "127.0.0.0/8,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16").split(",") if n.strip()]
SECURE_COOKIE = os.environ.get("SECURE_COOKIE", "false").lower() in ("1", "true", "yes")

app = Flask(__name__, static_folder=None)
app.config.update(MAX_CONTENT_LENGTH=1_000_000)


def db():
    if "db" not in g:
        g.db = harrier.open_db()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    if "db" in g:
        g.db.close()


def client_ip():
    """The visitor's address, trusting X-Forwarded-For only from a proxy on a trusted network."""
    peer = request.remote_addr or ""
    a = harrier.parse_ip(peer)
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd and a and any(a in n for n in TRUSTED_PROXIES if n.version == a.version):
        last = fwd.split(",")[-1].strip()  # the entry our own proxy appended
        if harrier.parse_ip(last):
            return last
    return peer


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.before_request
def require_login():
    g.user, g.session = None, None
    if request.path in OPEN_PATHS or request.path.startswith("/static/"):
        return None
    user, h = auth.session_user(db(), request.cookies.get(COOKIE))
    if not user:
        if request.path.startswith("/api/"):
            return jsonify({"error": "login required"}), 401
        return redirect("/login")
    g.user, g.session = user, h
    if request.method not in ("GET", "HEAD") and user["role"] != "admin" and not request.path.startswith(SELF_SERVICE):
        return jsonify({"error": "Viewers can look but not change anything. Ask an admin."}), 403
    if request.method not in ("GET", "HEAD") and request.path.startswith("/api/") and not request.is_json:
        return jsonify({"error": "JSON required"}), 415  # blocks cross-site form posts
    return None


def admin_only():
    if g.user["role"] != "admin":
        abort(403)


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "version": VERSION})


@app.get("/login")
def login_page():
    user, _ = auth.session_user(db(), request.cookies.get(COOKIE))
    if user:
        return redirect("/")
    return send_from_directory(HERE, "login.html")


def failed_signin(username, reason):
    """Someone failed to sign in: that's evidence too, for Harrier's own detection."""
    ip = client_ip()
    s = harrier.sig(time.time(), "web", ip, "login_fail", 1, f"Failed dashboard sign-in as {username[:40]!r} ({reason})",
                    request.headers.get("User-Agent", ""), "harrier dashboard", "login:harrier-dashboard")
    d = db()
    d.execute("insert into signals (at, source, ip, kind, score, detail, ua, host, fp) values "
              "(?, ?, ?, ?, ?, ?, ?, ?, ?)", (s["at"], s["source"], s["ip"], s["kind"], s["score"], s["detail"], s["ua"], s["host"], s["fp"]))
    harrier.correlate(d, [s])


@app.post("/login")
def login():
    ip, ua = client_ip(), request.headers.get("User-Agent", "")
    try:
        user = auth.authenticate(db(), request.form.get("username", ""), request.form.get("password", ""), ip, ua,
                                 on_failure=failed_signin)
    except auth.AuthError as e:
        time.sleep(0.5)
        msg = str(e)
        code = "locked" if "locked" in msg else "throttled" if "Too many" in msg else "disabled" if "disabled" in msg else "failed"
        return redirect(f"/login?{code}=1")
    remember = request.form.get("remember") == "on"
    token, expires = auth.start_session(db(), user["id"], ip, ua, remember)
    resp = redirect("/")
    resp.set_cookie(COOKIE, token, max_age=int(expires - time.time()) if remember else None, httponly=True,
                    samesite="Strict", secure=SECURE_COOKIE, path="/")
    return resp


@app.post("/logout")
def logout():
    user, h = auth.session_user(db(), request.cookies.get(COOKIE))
    if user:
        db().execute("update sessions set revoked = 1 where token_hash = ?", (h,))
    resp = redirect("/login?signed_out=1")
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/static/<path:name>")
def static_file(name):
    return send_from_directory(os.path.join(HERE, "static"), name, max_age=86400)


# Every page of the app is a real URL. They all load the same shell; the page module comes from the path.
PAGE_ROUTES = ["/", "/incidents", "/incidents/<int:incident_id>", "/traffic", "/traffic/<any(web, dns, conn):source>", "/ai",
               "/blocked", "/health", "/settings", "/settings/<any(account, ai, response, watching, users, history, audit):section>"]


def page(**_):
    return send_from_directory(HERE, "app.html", max_age=0)


for i, rule in enumerate(PAGE_ROUTES):
    app.add_url_rule(rule, f"page{i}", page)


@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not found"}), 404
    return send_from_directory(HERE, "app.html"), 404


# --- Your account ------------------------------------------------------------------------------
@app.get("/api/me")
def me():
    u = g.user
    return jsonify({"id": u["id"], "username": u["username"], "role": u["role"], "palette": u["palette"],
                    "must_change_password": bool(u["must_change_password"]), "version": VERSION})


@app.post("/api/me/password")
def change_password():
    body = request.get_json(silent=True) or {}
    u = db().execute("select * from users where id = ?", (g.user["id"],)).fetchone()
    try:
        auth.ph.verify(u["password_hash"], body.get("current", ""))
    except Exception:
        return jsonify({"ok": False, "error": "Your current password is wrong."}), 400
    try:
        auth.set_password(db(), u["id"], body.get("new", ""))
    except auth.AuthError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    auth.revoke(db(), u["id"], keep=g.session)  # other devices must sign in again
    harrier.record(db(), u["username"], "change_password", u["username"])
    return jsonify({"ok": True})


@app.post("/api/me/palette")
def set_palette():
    p = (request.get_json(silent=True) or {}).get("palette")
    if p not in auth.PALETTES:
        abort(400)
    db().execute("update users set palette = ? where id = ?", (p, g.user["id"]))
    return jsonify({"ok": True})


@app.get("/api/me/sessions")
def my_sessions():
    rows = db().execute("select token_hash, created_at, last_seen_at, expires_at, ip, user_agent from sessions "
                        "where user_id = ? and revoked = 0 and expires_at > ? order by last_seen_at desc",
                        (g.user["id"], time.time())).fetchall()
    return jsonify([{"id": r["token_hash"][:16], "current": r["token_hash"] == g.session, "created_at": r["created_at"],
                     "last_seen_at": r["last_seen_at"], "ip": r["ip"], "user_agent": r["user_agent"]} for r in rows])


@app.post("/api/me/sessions/revoke")
def revoke_sessions():
    sid = (request.get_json(silent=True) or {}).get("id")
    auth.revoke(db(), g.user["id"], session_id=sid if sid else None, keep=g.session)
    return jsonify({"ok": True})


# --- Users (admins) ----------------------------------------------------------------------------
@app.get("/api/users")
def users():
    admin_only()
    rows = db().execute("select id, username, role, created_at, last_login_at, locked_until, disabled from users "
                        "order by username").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/users")
def add_user():
    admin_only()
    body = request.get_json(silent=True) or {}
    temp = auth.temporary_password()
    try:
        uid = auth.create_user(db(), str(body.get("username", "")), temp, body.get("role", "viewer"), must_change=True)
    except auth.AuthError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    harrier.record(db(), g.user["username"], "add_user", body.get("username", ""), body.get("role", "viewer"))
    return jsonify({"ok": True, "id": uid, "temporary_password": temp})


@app.post("/api/users/<int:uid>")
def change_user(uid):
    admin_only()
    body = request.get_json(silent=True) or {}
    d = db()
    u = d.execute("select * from users where id = ?", (uid,)).fetchone() or abort(404)
    out = {"ok": True}
    if "role" in body:
        if body["role"] not in auth.ROLES:
            abort(400)
        if u["role"] == "admin" and body["role"] != "admin" and not auth.admins_left(d, excluding=uid):
            return jsonify({"ok": False, "error": "There must always be at least one admin."}), 400
        d.execute("update users set role = ? where id = ?", (body["role"], uid))
    if "disabled" in body:
        if body["disabled"] and (uid == g.user["id"] or (u["role"] == "admin" and not auth.admins_left(d, excluding=uid))):
            return jsonify({"ok": False, "error": "You can't disable yourself or the last admin."}), 400
        d.execute("update users set disabled = ? where id = ?", (1 if body["disabled"] else 0, uid))
        if body["disabled"]:
            auth.revoke(d, uid)
    if body.get("unlock"):
        d.execute("update users set locked_until = 0, failed_count = 0 where id = ?", (uid,))
    if body.get("reset_password"):
        temp = auth.temporary_password()
        auth.set_password(d, uid, temp, must_change=True)
        auth.revoke(d, uid)
        out["temporary_password"] = temp
    if body.get("sign_out_everywhere"):
        auth.revoke(d, uid, keep=g.session if uid == g.user["id"] else None)
    harrier.record(d, g.user["username"], "change_user", u["username"],
                   json.dumps({k: v for k, v in body.items() if k != "password"}))
    return jsonify(out)


@app.delete("/api/users/<int:uid>")
def delete_user(uid):
    admin_only()
    d = db()
    u = d.execute("select * from users where id = ?", (uid,)).fetchone() or abort(404)
    if uid == g.user["id"] or (u["role"] == "admin" and not auth.admins_left(d, excluding=uid)):
        return jsonify({"ok": False, "error": "You can't delete yourself or the last admin."}), 400
    d.execute("delete from users where id = ?", (uid,))
    harrier.record(d, g.user["username"], "delete_user", u["username"])
    return jsonify({"ok": True})


@app.get("/api/login-history")
def login_history():
    d = db()
    if g.user["role"] == "admin":
        rows = d.execute("select * from login_events order by id desc limit 300").fetchall()
    else:
        rows = d.execute("select * from login_events where user_id = ? order by id desc limit 100", (g.user["id"],)).fetchall()
    return jsonify([dict(r) for r in rows])


# --- AI models -------------------------------------------------------------------------------
RECOMMENDED_MODELS = [
    {"name": "gemma4:12b", "size_gb": 8.0, "needs": "GPU with 10+ GB, or 16 GB RAM (slow on CPU)", "note": "Tested with Harrier's red team"},
    {"name": "gemma3:12b", "size_gb": 8.1, "needs": "GPU with 10+ GB, or 16 GB RAM (slow on CPU)", "note": ""},
    {"name": "qwen2.5:7b", "size_gb": 4.7, "needs": "GPU with 6+ GB, or 12 GB RAM", "note": ""},
    {"name": "llama3.1:8b", "size_gb": 4.9, "needs": "GPU with 6+ GB, or 12 GB RAM", "note": ""},
    {"name": "gemma3:4b", "size_gb": 3.3, "needs": "8 GB RAM, CPU is fine", "note": "For small machines; less reliable"},
]
_pull_lock = threading.Lock()


@app.get("/api/models")
def models():
    d = db()
    installed, error = [], ""
    try:
        r = requests.get(f"{harrier.OLLAMA_URL}/api/tags", timeout=10)
        r.raise_for_status()
        installed = [{"name": m["name"], "size_gb": round(m.get("size", 0) / 1e9, 1)} for m in r.json().get("models", [])]
    except requests.RequestException as e:
        error = f"Can't reach Ollama at {harrier.OLLAMA_URL}: {e}"
    return jsonify({"current": harrier.get_settings(d)["model"], "installed": installed, "recommended": RECOMMENDED_MODELS,
                    "ollama_url": harrier.OLLAMA_URL, "error": error, "pull": harrier.get_state(d, "model_pull")})


def _pull(name):
    d = harrier.open_db()
    try:
        with requests.post(f"{harrier.OLLAMA_URL}/api/pull", json={"name": name, "stream": True}, stream=True, timeout=3600) as r:
            r.raise_for_status()
            last = 0
            for line in r.iter_lines():
                if not line:
                    continue
                ev = json.loads(line)
                if ev.get("error"):
                    raise RuntimeError(ev["error"])
                done = ev.get("completed") and ev.get("total") and round(100 * ev["completed"] / ev["total"])
                if time.time() - last > 1:
                    harrier.set_state(d, "model_pull", {"name": name, "status": ev.get("status", ""), "percent": done or 0, "done": False})
                    last = time.time()
        harrier.set_state(d, "model_pull", {"name": name, "status": "ready", "percent": 100, "done": True})
    except Exception as e:
        harrier.set_state(d, "model_pull", {"name": name, "status": f"failed: {e}"[:200], "percent": 0, "done": True, "error": True})
    finally:
        _pull_lock.release()
        d.close()


@app.post("/api/models/pull")
def pull_model():
    name = str((request.get_json(silent=True) or {}).get("name", "")).strip()
    if not name or len(name) > 100 or not all(c.isalnum() or c in ":._-/" for c in name):
        abort(400)
    if not _pull_lock.acquire(blocking=False):
        return jsonify({"ok": False, "error": "Already downloading a model."}), 409
    harrier.set_state(db(), "model_pull", {"name": name, "status": "starting", "percent": 0, "done": False})
    harrier.record(db(), g.user["username"], "pull_model", name)
    threading.Thread(target=_pull, args=(name,), daemon=True).start()
    return jsonify({"ok": True})


def incident_json(r):
    d = dict(r)
    d["ips"] = json.loads(d["ips"] or "[]")
    d["ai"] = json.loads(d["ai"]) if d["ai"] else None
    return d


@app.get("/api/overview")
def overview():
    d, now = db(), time.time()
    day = now - 86400
    open_sev = [r[0] for r in d.execute("select severity from incidents where status in ('open', 'blocked') "
                                        "and last_at > ?", (day,))]
    level = max(open_sev, key=harrier.SEVERITIES.index) if open_sev else "info"
    hourly = {}
    for r in d.execute("select floor(at / 3600) * 3600 h, count(*) n, count(distinct ip) ips from signals "
                       "where at > ? and score > 0 group by h", (day,)):
        hourly[r["h"]] = {"t": r["h"], "signals": r["n"], "addresses": r["ips"]}
    # What drove each hour: the most common signal and the address behind most of it.
    causes = {}
    for r in d.execute("select floor(at / 3600) * 3600 h, kind, ip, count(*) n from signals where at > ? and score > 0 "
                       "group by h, kind, ip order by n desc", (day,)):
        causes.setdefault(r["h"], (r["kind"], r["ip"], r["n"]))
    for h, v in hourly.items():
        if h in causes:
            v["cause_kind"], v["cause_ip"] = causes[h][0], causes[h][1]
    settings = harrier.get_settings(d)
    return jsonify({
        "now": time.time(),
        "dev": os.environ.get("HARRIER_DEV", "").lower() in ("1", "true", "yes"),
        "learning_until": harrier.get_state(d, "dns_baseline_until"),
        "host_label": os.environ.get("HOST_LABEL") or harrier.get_state(d, "own_ip") or "",
        "devices": d.execute("select count(*) from devices").fetchone()[0],
        "new_devices_24h": d.execute("select count(*) from devices where first_seen > ?", (day,)).fetchone()[0],
        "level": level,
        "incidents_24h": d.execute("select count(*) from incidents where first_at > ?", (day,)).fetchone()[0],
        "open_incidents": d.execute("select count(*) from incidents where status = 'open'").fetchone()[0],
        "pending": d.execute("select count(*) from incidents where pending_action is not null "
                             "and status in ('open', 'blocked')").fetchone()[0],
        "blocked_now": d.execute("select count(*) from blocks where active = 1").fetchone()[0],
        "signals_24h": d.execute("select count(*) from signals where at > ? and score > 0", (day,)).fetchone()[0],
        "attackers_24h": d.execute("select count(distinct ip) from signals where at > ? and score > 0 and ip != ''",
                                   (day,)).fetchone()[0],
        "hourly": [hourly[h] for h in sorted(hourly)],
        "guard": harrier.get_state(d, "guard", {}),
        "last_cycle": harrier.get_state(d, "last_cycle", 0),
        "ai_busy": harrier.get_state(d, "ai_busy"),
        "ai_error": harrier.get_state(d, "ai_error", ""),
        "own_ip": harrier.get_state(d, "own_ip"),
        "health_failed": sum((st["total"] - st["passed"]) for st in
                             (harrier.get_state(d, f"health:{k}") for k in ("live", "replay", "ai")) if st),
        "mode": settings["mode"], "ai_enabled": settings["ai_enabled"], "model": settings["model"],
        "domains": [{"name": n, **harrier.get_state(d, f"domain:{n}", {})} for n in settings["domains"]],
    })


@app.get("/api/incidents")
def incidents():
    status = request.args.get("status", "active")
    where = {"active": "status in ('open', 'blocked')", "pending": "pending_action is not null and status in ('open', 'blocked')",
             "all": "1=1", "closed": "status in ('resolved', 'false_positive')"}.get(status, "1=1")
    rows = db().execute(f"select * from incidents where {where} order by "
                        "case when status in ('open', 'blocked') then 0 else 1 end, last_at desc limit 300").fetchall()
    return jsonify([incident_json(r) for r in rows])


@app.get("/api/incidents/<int:inc_id>")
def incident(inc_id):
    d = db()
    r = d.execute("select * from incidents where id = ?", (inc_id,)).fetchone() or abort(404)
    inc = incident_json(r)
    ips = inc["ips"] or ([inc["ip"]] if inc["ip"] else [])
    if ips:
        sigs = d.execute(f"select * from signals where ip in ({','.join('?' * len(ips))}) and at >= ? "
                         "order by at desc limit 200", ips + [inc["first_at"] - 600]).fetchall()
    else:
        sigs = d.execute("select * from signals where source = 'domain' and detail like ? order by at desc limit 20",
                         (f"%{inc['title'].split(':')[0]}%",)).fetchall()
    inc["signals"] = [dict(s) for s in sigs]
    inc["blocks"] = [dict(b) for b in d.execute(
        f"select * from blocks where ip in ({','.join('?' * len(ips))})", ips)] if ips else []
    return jsonify(inc)


@app.post("/api/incidents/<int:inc_id>")
def act(inc_id):
    d = db()
    inc = d.execute("select * from incidents where id = ?", (inc_id,)).fetchone() or abort(404)
    action = (request.get_json(silent=True) or {}).get("action")
    ips = [ip for ip in (json.loads(inc["ips"] or "[]") or [inc["ip"]]) if ip]
    if action == "approve" and inc["pending_action"]:
        secs = {"block_24h": 86400, "block_7d": 7 * 86400, "block_30d": 30 * 86400, "block_permanent": 0}[inc["pending_action"]]
        for ip in ips:
            harrier.block(d, ip, f"Approved: {inc['title']}", inc_id, "manual", secs, actor=g.user["username"])
        d.execute("update incidents set pending_action = null, status = 'blocked' where id = ?", (inc_id,))
    elif action == "dismiss":
        d.execute("update incidents set pending_action = null where id = ?", (inc_id,))
    elif action in ("block_7d", "block_permanent"):
        for ip in ips:
            harrier.block(d, ip, f"Blocked by you: {inc['title']}", inc_id, "manual",
                          0 if action == "block_permanent" else 7 * 86400, actor=g.user["username"])
        d.execute("update incidents set status = 'blocked', pending_action = null where id = ?", (inc_id,))
    elif action == "resolve":
        d.execute("update incidents set status = 'resolved', pending_action = null where id = ?", (inc_id,))
    elif action == "false_positive":
        # Unblock and allowlist: only you can do this, never the AI.
        for ip in ips:
            harrier.unblock(d, ip, actor=g.user["username"])
        s = harrier.get_settings(d)
        new = {str(ipaddress.ip_network(ip, strict=False)) for ip in ips if not harrier.is_private(ip)}
        harrier.save_settings(d, {"allowlist": sorted(set(s["allowlist"]) | new)})
        d.execute("update incidents set status = 'false_positive', pending_action = null where id = ?", (inc_id,))
    elif action == "reinvestigate":
        d.execute("update incidents set ai_at = 0 where id = ?", (inc_id,))
    elif action == "accept_change" and inc["kind"] == "domain":
        harrier.accept_domain_baseline(d, inc["title"].split(":")[0])
        d.execute("update incidents set status = 'resolved' where id = ?", (inc_id,))
    else:
        abort(400)
    d.commit()
    harrier.record(d, g.user["username"], action, f"incident #{inc_id}")
    learn.feedback(d, inc, action)
    return jsonify({"ok": True})


@app.get("/api/blocks")
def blocks():
    rows = db().execute("select b.*, i.title from blocks b left join incidents i on i.id = b.incident_id "
                        "where b.active = 1 order by b.created_at desc").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/blocks")
def add_block():
    body = request.get_json(silent=True) or {}
    ip = str(body.get("ip", "")).strip()
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        abort(400)
    days = int(body.get("days", 7))
    ok = harrier.block(db(), ip, body.get("reason") or "Blocked by you", None, "manual",
                       0 if days == 0 else days * 86400, actor=g.user["username"])
    return jsonify({"ok": ok, "error": None if ok else "Protected address (home, VPN or allowlist) or already blocked"})


@app.delete("/api/blocks/<path:ip>")
def remove_block(ip):
    harrier.unblock(db(), ip, actor=g.user["username"])
    return jsonify({"ok": True})


@app.get("/api/activity")
def activity():
    return jsonify([dict(r) for r in db().execute("select * from actions order by id desc limit 200")])


@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    d = db()
    if request.method == "GET":
        return jsonify({**harrier.get_settings(d), "own_ip": harrier.get_state(d, "own_ip"),
                        "hard_allow": [str(n) for n in harrier.HARD_ALLOW]})
    body = request.get_json(force=True)
    changes = {}
    if body.get("mode") in ("auto", "review"):
        changes["mode"] = body["mode"]
    if "ai_enabled" in body:
        changes["ai_enabled"] = bool(body["ai_enabled"])
    if body.get("model"):
        changes["model"] = str(body["model"]).strip()
    if "domains" in body:
        changes["domains"] = sorted({x.strip().lower() for x in body["domains"] if "." in x.strip()})
    if "brand" in body:
        changes["brand"] = str(body["brand"]).strip().lower()
    if "notify_url" in body:
        changes["notify_url"] = str(body["notify_url"]).strip()
    if "allowlist" in body:
        good = []
        for c in body["allowlist"]:
            try:
                good.append(str(ipaddress.ip_network(c.strip(), strict=False)))
            except ValueError:
                pass
        changes["allowlist"] = sorted(set(good))
    return jsonify(harrier.save_settings(d, changes, actor=g.user["username"]))


@app.get("/api/traffic")
def traffic():
    """Recent requests, each with what Harrier made of it."""
    d = db()
    after = int(request.args.get("after", 0) or 0)
    only = request.args.get("only", "all")
    q = request.args.get("q", "").strip()
    source = request.args.get("source", "web")
    if source not in ("web", "dns", "conn"):
        abort(400)
    sql, args = "select * from traffic where source = ? and id > ?", [source, after]
    if q:
        sql += " and (ip like ? or path like ? or ua like ? or host like ?)"
        args += [f"%{q}%"] * 4
    if only == "flagged":
        sql += " and ip in (select distinct ip from signals where score > 0 and at > ?)"
        args.append(time.time() - 86400)
    rows = [dict(r) for r in d.execute(sql + " order by id desc limit 200", args)]
    ips = sorted({r["ip"] for r in rows})
    if ips:
        marks = ",".join("?" * len(ips))
        sigs = {}
        for s_ in d.execute(f"select ip, at, kind from signals where ip in ({marks}) and at > ? and score > 0",
                            ips + [min(r["at"] for r in rows) - 2]):
            sigs.setdefault(s_["ip"], []).append((s_["at"], s_["kind"]))
        blocked = {r[0] for r in d.execute(f"select ip from blocks where active = 1 and ip in ({marks})", ips)}
        incs = {}
        for i in d.execute(f"select id, ip, severity, status, ai from incidents where ip in ({marks}) order by id", ips):
            incs[i["ip"]] = i
        for r in rows:
            r["flags"] = sorted({k for at, k in sigs.get(r["ip"], []) if abs(at - r["at"]) < 1.5})
            r["blocked"] = r["ip"] in blocked
            r["home"] = harrier.is_private(r["ip"])
            i = incs.get(r["ip"])
            if i:
                ai = json.loads(i["ai"]) if i["ai"] else None
                r["incident"] = {"id": i["id"], "severity": i["severity"], "status": i["status"],
                                 "ai": {"summary": ai["summary"], "action": ai["recommended_action"],
                                        "manipulation": ai["manipulation_attempt"], "agent": ai["ai_agent_suspected"]} if ai else None}
    day = time.time() - 86400
    stats = d.execute("select count(*) n, count(distinct ip) ips from traffic where source = ? and at > ?", (source, day)).fetchone()
    flagged = d.execute("select count(distinct ip) from signals where at > ? and score > 0", (day,)).fetchone()[0]
    return jsonify({"rows": rows, "stats": {"requests": stats["n"], "addresses": stats["ips"], "flagged_addresses": flagged}})


@app.get("/api/devices")
def devices():
    """Every device Pi-hole has seen, with its last day of DNS activity and anything flagged."""
    d = db()
    day = time.time() - 86400
    counts = {r[0]: (r[1], r[2], r[3]) for r in d.execute(
        "select ip, count(*), sum(status), count(distinct path) from traffic where source = 'dns' and at > ? group by ip", (day,))}
    flags = {}
    for r in d.execute("select ip, kind, count(*) n from signals where source in ('dns', 'conn') and at > ? and score > 0 "
                       "group by ip, kind", (day,)):
        flags.setdefault(r["ip"], []).append(r["kind"])
    out = []
    for r in d.execute("select * from devices order by last_seen desc"):
        n, blocked, domains = counts.get(r["ip"], (0, 0, 0))
        out.append({**dict(r), "lookups": n, "blocked": blocked or 0, "domains": domains, "flags": flags.get(r["ip"], [])})
    return jsonify({"devices": out, "learning_until": harrier.get_state(d, "dns_baseline_until"),
                    "flows": harrier.get_state(d, "flows", {})})


@app.get("/api/ai-feed")
def ai_feed():
    rows = db().execute("select * from incidents where ai is not null order by ai_at desc limit 40").fetchall()
    return jsonify([incident_json(r) for r in rows])


@app.get("/api/health")
def health_status():
    d = db()
    health.setup(d)
    out = {}
    for suite in health.SCHEDULE:
        st = harrier.get_state(d, f"health:{suite}")
        checks = [dict(r) for r in d.execute("select name, status, detail, seconds from checks where run = ? order by id",
                                             (st["run"],))] if st else []
        hist = [dict(r) for r in d.execute("select run, min(at) at, count(*) filter (where status = 'pass') passed, count(*) total from checks "
                                           "where suite = ? group by run order by at desc limit 10", (suite,))]
        out[suite] = {"last": st, "checks": checks, "history": hist, "every_hours": health.SCHEDULE[suite] / 3600}
    return jsonify({"suites": out, "running": harrier.get_state(d, "health_running"),
                    "requested": harrier.get_state(d, "health_request")})


@app.post("/api/health/run")
def health_run():
    suite = (request.get_json(silent=True) or {}).get("suite")
    if suite not in health.SCHEDULE:
        abort(400)
    harrier.set_state(db(), "health_request", suite)
    return jsonify({"ok": True})


@app.get("/api/learned")
def learned():
    d = db()
    return jsonify({
        "weights": [dict(r) for r in d.execute("select * from weights order by kind")],
        "intel": [{**dict(r), "sources": json.loads(r["sources"] or "[]")} for r in
                  d.execute("select * from intel order by active desc, first_at desc limit 300")],
        "lessons": [dict(r) for r in d.execute("select * from lessons order by id desc limit 100")],
        "learned_at": harrier.get_state(d, "learned_at"),
    })


@app.post("/api/learned/<int:intel_id>")
def toggle_learned(intel_id):
    active = 1 if (request.get_json(silent=True) or {}).get("active") else 0
    d = db()
    d.execute("update intel set active = ? where id = ?", (active, intel_id))
    d.commit()
    harrier.refresh_intel(d)
    harrier.record(d, g.user["username"], "enable_pattern" if active else "disable_pattern", f"pattern #{intel_id}")
    return jsonify({"ok": True})


@app.post("/api/test-notify")
def test_notify():
    harrier.notify(db(), "Harrier test", "Notifications from Harrier are working.")
    return jsonify({"ok": True})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    _db = harrier.open_db()
    if auth.ensure_admin(_db, os.environ.get("ADMIN_USERNAME", ""), os.environ.get("ADMIN_PASSWORD", "")):
        logging.info("created admin user %s", os.environ.get("ADMIN_USERNAME"))
    _db.close()
    harrier.start_background()
    serve(app, host="0.0.0.0", port=8095, threads=4)
