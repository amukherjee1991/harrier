"""Log following, domain watch and the dashboard API."""
import os

from helpers import Env, web

import harrier


def test_log_rotation_and_restart_keep_reading_without_duplicates():
    e = Env()
    e.write("CADDY_LOG", [web("203.0.113.1", "/.env")])
    assert e.run() == 1
    assert e.run() == 0  # nothing new, nothing re-read
    os.rename(harrier.CADDY_LOG, harrier.CADDY_LOG + ".1")  # Caddy rolls the file
    e.write("CADDY_LOG", [web("203.0.113.2", "/.git/config")])
    assert e.run() == 1


def test_garbage_lines_dont_break_anything():
    e = Env()
    e.write("CADDY_LOG", ["not json", "{}", '{"request": 5}', "\x00\x01", web("203.0.113.3", "/.env")])
    e.write("AUTH_LOG", ["garbage", "sshd[1]: Failed password for"])
    e.write("UFW_LOG", ["[UFW BLOCK] IN=eno1 SRC=bad"])
    assert e.run() == 1


def fake_domain(dns=None, http=None, tls=None):
    harrier.dns_records = lambda d: dns or {"CNAME": [], "A": ["216.239.32.21"], "AAAA": [], "NS": ["dns1.registrar-servers.com."], "MX": []}
    harrier.http_info = lambda d: http or {"status": 200, "final_url": f"https://{d}/", "title": "Example"}
    harrier.tls_info = lambda d: tls or {"issuer": "Google Trust Services", "expires": harrier.time.time() + 80 * 86400}


def test_domain_hijack_defacement_and_downtime():
    e = Env()
    fake_domain()
    harrier.check_domain(e.db, "example.com")
    assert not e.incidents()  # first look is the baseline
    fake_domain(dns={"CNAME": [], "A": ["6.6.6.6"], "AAAA": [], "NS": ["ns1.evil.example."], "MX": []})
    harrier.check_domain(e.db, "example.com")
    sev = {i["title"]: i["severity"] for i in e.incidents()}
    assert sev.get("example.com: NS records changed") == "critical", sev
    assert sev.get("example.com: A records changed") == "critical", sev
    fake_domain(http={"status": 200, "final_url": "https://example.com/", "title": "Hacked by X"})
    harrier.check_domain(e.db, "example.com")
    assert any("title changed" in i["title"] for i in e.incidents())
    n = len(e.incidents())
    harrier.http_info = lambda d: (_ for _ in ()).throw(harrier.requests.ConnectionError("down"))
    harrier.check_domain(e.db, "example.com")
    assert len(e.incidents()) == n  # one failure is a blip
    harrier.check_domain(e.db, "example.com")
    assert any("unreachable" in i["title"] for i in e.incidents())


def test_accepting_a_domain_change_stops_alerts():
    e = Env()
    fake_domain()
    harrier.check_domain(e.db, "example.com")
    fake_domain(http={"status": 200, "final_url": "https://example.com/", "title": "New design"})
    harrier.check_domain(e.db, "example.com")
    harrier.accept_domain_baseline(e.db, "example.com")
    e.db.execute("update incidents set status = 'resolved'")
    harrier.check_domain(e.db, "example.com")
    assert not e.incidents(status="open")


def client(e, role="admin"):
    """A signed-in dashboard test client for this test's database."""
    import importlib
    import auth
    import web as webmod
    webmod = importlib.reload(webmod)
    auth.create_user(e.db, f"{role}-user", "correct horse battery", role)
    c = webmod.app.test_client()
    c.post("/login", data={"username": f"{role}-user", "password": "correct horse battery"})
    return c


def test_dashboard_requires_login_and_actions_work():
    e = Env()
    e.write("CADDY_LOG", [web("203.0.113.10", p, "nuclei", t=i) for i, p in enumerate(["/.env", "/?x=${jndi:x}"])])
    e.run()
    c = client(e)
    anon = c.application.test_client()
    assert anon.get("/api/overview").status_code == 401
    assert anon.post("/login", data={"username": "admin-user", "password": "nope"}).headers["Location"].endswith("failed=1")
    assert c.get("/api/overview").status_code == 200
    inc = e.incident_for("203.0.113.10")
    assert c.post(f"/api/incidents/{inc['id']}", json={"action": "false_positive"}).status_code == 200
    assert "203.0.113.10" not in e.blocked()
    assert "203.0.113.10/32" in harrier.get_settings(e.db)["allowlist"]
    r = c.post("/api/blocks", json={"ip": "192.168.1.9", "days": 0}).get_json()
    assert not r["ok"]
    assert c.post("/api/blocks", json={"ip": "not-an-ip"}).status_code == 400


def test_every_dashboard_endpoint_works_with_real_data():
    """Smoke test: each page's API must answer 200 once there are incidents, AI verdicts, blocks and lessons."""
    import learn
    e = Env()
    for k in range(3):
        e.write("CADDY_LOG", [web(f"203.0.113.{k + 1}", p, "nuclei", t=k * 10 + j)
                              for j, p in enumerate(["/.env", "/?x=${jndi:x}", "/oddpath"])])
    e.run()
    inc = e.db.execute("select * from incidents order by id limit 1").fetchone()
    harrier.apply_verdict(e.db, inc, {"summary": "s", "attack_type": "scan", "severity": "high", "confidence": 0.9,
                                      "automated": True, "ai_agent_suspected": True, "manipulation_attempt": False,
                                      "recommended_action": "block_permanent", "reasoning": "r", "next_steps": "n"})
    learn.learn_patterns(e.db)
    learn.feedback(e.db, inc, "approve")
    c = client(e)
    for path in ("/", "/api/overview", "/api/incidents?status=active", "/api/incidents?status=pending",
                 "/api/incidents?status=closed", f"/api/incidents/{inc['id']}", "/api/blocks", "/api/activity",
                 "/api/settings", "/api/traffic", "/api/traffic?only=flagged&q=203", "/api/ai-feed",
                 "/api/health", "/api/learned", "/api/devices", "/api/traffic?source=dns", "/api/traffic?source=conn",
                 "/api/me", "/api/me/sessions", "/api/users", "/api/login-history"):
        r = c.get(path)
        assert r.status_code == 200, f"{path} -> {r.status_code}"
    feed = c.get("/api/ai-feed").get_json()
    assert feed and feed[0]["ai"]["recommended_action"] == "block_permanent", feed


def test_every_page_has_a_real_url():
    e = Env()
    c = client(e)
    for path in ("/", "/incidents", "/incidents?status=pending", "/incidents/1", "/traffic", "/traffic/web", "/traffic/dns",
                 "/traffic/conn", "/ai", "/blocked", "/health", "/settings", "/settings/account", "/settings/users", "/settings/audit"):
        r = c.get(path)
        assert r.status_code == 200 and b'<div id="page">' in r.data, f"{path} -> {r.status_code}"
    assert c.get("/nope").status_code == 404 and c.get("/traffic/bogus").status_code == 404
    assert c.get("/api/nope").get_json() == {"error": "not found"}
    anon = c.application.test_client()
    assert anon.get("/incidents/1").headers["Location"].endswith("/login")
    csp = c.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self';" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    for asset in ("/static/js/app.js", "/static/css/app.css", "/static/js/pages/settings.js", "/static/favicon.svg"):
        assert anon.get(asset).status_code == 200, asset
