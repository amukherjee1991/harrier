"""Accounts: passwords, lockouts, roles, sessions and sign-in history."""
import time

from helpers import Env

import auth

PW = "correct horse battery"


def app_for(e):
    import importlib
    import web
    return importlib.reload(web).app


def signin(app, user, pw=PW, remember=True, ip="192.168.1.20"):
    c = app.test_client()
    r = c.post("/login", data={"username": user, "password": pw, **({"remember": "on"} if remember else {})},
               environ_base={"REMOTE_ADDR": ip})
    return c, r


def test_passwords_are_argon2_and_tokens_are_hashed():
    e = Env()
    auth.create_user(e.db, "alice", PW, "admin")
    h = e.db.execute("select password_hash from users where username = 'alice'").fetchone()[0]
    assert h.startswith("$argon2id$") and PW not in h
    c, r = signin(app_for(e), "alice")
    cookie = r.headers["Set-Cookie"]
    token = cookie.split("=", 1)[1].split(";", 1)[0]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie, cookie
    stored = [x[0] for x in e.db.execute("select token_hash from sessions")]
    assert token not in stored and auth.token_hash(token) in stored


def test_wrong_password_and_lockout():
    e = Env()
    auth.create_user(e.db, "alice", PW, "admin")
    app = app_for(e)
    for _ in range(5):
        _, r = signin(app, "alice", "nope")
    assert r.headers["Location"].endswith("locked=1"), r.headers["Location"]
    _, r = signin(app, "alice", PW)
    assert "locked=1" in r.headers["Location"], "the right password must not work while locked"
    e.db.execute("update users set locked_until = ? where username = 'alice'", (time.time() - 1,))
    _, r = signin(app, "alice", PW)
    assert r.headers["Location"].endswith("/")


def test_address_throttle_and_failures_feed_detection():
    e = Env()
    app = app_for(e)
    for k in range(22):
        _, r = signin(app, f"nobody{k}", "x", ip="203.0.113.99")
    assert "throttled=1" in r.headers["Location"], r.headers["Location"]
    kinds = {x[0] for x in e.db.execute("select kind from signals where ip = '203.0.113.99'")}
    assert "login_fail" in kinds


def test_unknown_users_and_wrong_passwords_look_the_same():
    e = Env()
    auth.create_user(e.db, "alice", PW, "admin")
    app = app_for(e)
    _, a = signin(app, "alice", "wrong")
    _, b = signin(app, "mallory", "wrong")
    assert a.headers["Location"] == b.headers["Location"]


def test_viewers_can_look_but_not_touch():
    e = Env()
    auth.create_user(e.db, "bob", PW, "viewer")
    c, _ = signin(app_for(e), "bob")
    assert c.get("/api/overview").status_code == 200
    assert c.post("/api/blocks", json={"ip": "203.0.113.5"}).status_code == 403
    assert c.post("/api/settings", json={"mode": "review"}).status_code == 403
    assert c.get("/api/users").status_code == 403
    assert c.post("/api/me/palette", json={"palette": "forest"}).status_code == 200
    assert c.post("/api/me/password", json={"current": PW, "new": "a much better passphrase"}).status_code == 200


def test_admin_manages_users_but_never_removes_the_last_admin():
    e = Env()
    me = auth.create_user(e.db, "alice", PW, "admin")
    c, _ = signin(app_for(e), "alice")
    r = c.post("/api/users", json={"username": "carol", "role": "viewer"}).get_json()
    assert r["ok"] and len(r["temporary_password"]) >= 12
    assert e.db.execute("select must_change_password from users where username = 'carol'").fetchone()[0] == 1
    assert c.post(f"/api/users/{me}", json={"role": "viewer"}).status_code == 400
    assert c.post(f"/api/users/{me}", json={"disabled": True}).status_code == 400
    assert c.delete(f"/api/users/{me}", json={}).status_code == 400
    assert c.post("/api/users", json={"username": "x", "role": "viewer"}).status_code == 400  # too short


def test_password_change_signs_out_other_devices():
    e = Env()
    auth.create_user(e.db, "alice", PW, "admin")
    app = app_for(e)
    phone, _ = signin(app, "alice")
    laptop, _ = signin(app, "alice")
    assert laptop.post("/api/me/password", json={"current": PW, "new": "a brand new passphrase"}).get_json()["ok"]
    assert phone.get("/api/overview").status_code == 401
    assert laptop.get("/api/overview").status_code == 200
    assert laptop.post("/api/me/password", json={"current": "wrong", "new": "another passphrase"}).status_code == 400


def test_sign_out_everywhere_and_disabled_accounts():
    e = Env()
    auth.create_user(e.db, "alice", PW, "admin")
    bob = auth.create_user(e.db, "bob", PW, "viewer")
    app = app_for(e)
    a, _ = signin(app, "alice")
    b, _ = signin(app, "bob")
    assert a.post(f"/api/users/{bob}", json={"disabled": True}).get_json()["ok"]
    assert b.get("/api/overview").status_code == 401
    _, r = signin(app, "bob")
    assert "disabled=1" in r.headers["Location"]
    a2, _ = signin(app, "alice")
    assert a.post("/api/me/sessions/revoke", json={}).get_json()["ok"]
    assert a2.get("/api/overview").status_code == 401 and a.get("/api/overview").status_code == 200


def test_forwarded_for_is_only_trusted_from_a_named_proxy():
    """By default nobody may set the client address; only proxies named in TRUSTED_PROXIES can."""
    import ipaddress
    import web
    e = Env()
    auth.create_user(e.db, "alice", PW, "admin")
    app = app_for(e)
    c = app.test_client()
    c.post("/login", data={"username": "alice", "password": "x"}, headers={"X-Forwarded-For": "198.51.100.9"},
           environ_base={"REMOTE_ADDR": "192.168.1.50"})  # a LAN device forging its address: ignored by default
    assert e.db.execute("select ip from login_events order by id desc limit 1").fetchone()[0] == "192.168.1.50"
    web.TRUSTED_PROXIES = [ipaddress.ip_network("172.30.77.3/32")]
    e.db.execute("delete from login_events")
    c.post("/login", data={"username": "alice", "password": "x"}, headers={"X-Forwarded-For": "1.2.3.4"},
           environ_base={"REMOTE_ADDR": "203.0.113.50"})  # straight from the internet: header ignored
    c.post("/login", data={"username": "alice", "password": "x"}, headers={"X-Forwarded-For": "6.6.6.6, 198.51.100.7"},
           environ_base={"REMOTE_ADDR": "172.30.77.3"})  # via our proxy: its last hop is the real client
    ips = [r[0] for r in e.db.execute("select ip from login_events order by id")]
    assert ips == ["203.0.113.50", "198.51.100.7"], ips


def test_login_history_and_security_headers():
    e = Env()
    auth.create_user(e.db, "alice", PW, "admin")
    app = app_for(e)
    signin(app, "alice", "nope")
    c, _ = signin(app, "alice")
    hist = c.get("/api/login-history").get_json()
    assert [h["success"] for h in hist][:2] == [1, 0], hist
    r = c.get("/api/overview")
    assert r.headers["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"


def test_first_start_creates_the_admin_once():
    e = Env()
    assert auth.ensure_admin(e.db, "root-admin", PW)
    assert not auth.ensure_admin(e.db, "second", PW)
    assert [r[0] for r in e.db.execute("select role from users")] == ["admin"]
