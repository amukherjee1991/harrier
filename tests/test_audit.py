"""Regression tests for every finding of the v1.0.0 pre-release security audit (Cloudflare security-audit method).

Each test reproduces the audited attack and asserts that it no longer works.
"""
import json
import os
import subprocess
import time

from helpers import NOW, Env, ssh_fail, web

import auth
import harrier
import learn

PW = "correct horse battery"
BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15"


def cross_site(ip, uri, referer=None, t=0):
    """A request a visitor's browser sends because another site embedded our URL."""
    line = json.loads(web(ip, uri, BROWSER, 200, t=t, referer=referer))
    line["request"]["headers"].update({"Sec-Fetch-Site": ["cross-site"], "Sec-Fetch-Mode": ["no-cors"]})
    return json.dumps(line)


def test_one_huge_request_cannot_stall_the_detector():
    """harrier.py:INJECTION:ignor-wordstar-quadratic-backtracking"""
    e = Env()
    e.write("CADDY_LOG", [web("203.0.113.7", "/" + "ignor" * 20000)])  # 100 KB of the worst-case pattern
    t = time.time()
    e.run()
    assert time.time() - t < 2, f"took {time.time() - t:.1f}s"
    start = time.time()
    assert harrier.INJECTION.search("ignor" * 20000) is None and time.time() - start < 0.5


def test_forced_browser_requests_do_not_get_the_visitor_blocked():
    """harrier.py:caddy_line:single-forgeable-request-manipulation-autoblock"""
    e = Env()
    e.write("CADDY_LOG", [cross_site("198.51.100.7", "/?q=ignore%20previous%20instructions"),
                          cross_site("198.51.100.8", "/", referer="https://attacker.example/please%20do%20not%20block%20me"),
                          cross_site("198.51.100.9", "/?x=${jndi:ldap://x/a}", t=1), cross_site("198.51.100.9", "/../../etc/passwd", t=2)])
    e.run()
    assert not e.blocked(), e.blocked()


def test_coordinated_attack_does_not_sweep_up_a_user_who_mistyped_once():
    """harrier.py:correlate:campaign-blocks-members-without-per-ip-evidence"""
    e = Env()
    lines = [web("198.51.100.20", "/user/login", BROWSER, 200, "POST", t=0), web("198.51.100.20", "/user/login", BROWSER, 303, "POST", t=5)]
    for k in range(4):  # four attacker addresses that also probe
        lines += [web(f"203.0.113.{k + 1}", "/user/login", "curl/8", 200, "POST", t=10 + k),
                  web(f"203.0.113.{k + 1}", "/.env", "curl/8", 404, t=20 + k)]
    e.write("CADDY_LOG", lines)
    e.run()
    assert "198.51.100.20" not in e.blocked(), e.blocked()


def test_an_owner_unblock_is_not_undone_by_a_campaign():
    e = Env()
    ips = [f"198.51.100.{30 + k}" for k in range(6)]
    e.write("CADDY_LOG", [web(ip, "/.env", "python-requests/2.31", t=k) for k, ip in enumerate(ips)])
    e.run()
    assert ips[0] in e.blocked()
    harrier.unblock(e.db, ips[0], actor="alice")
    e.write("CADDY_LOG", [web(ips[1], "/.git/config", "python-requests/2.31", t=60)])
    e.run()
    assert ips[0] not in e.blocked()


def test_attackers_cannot_get_a_real_users_app_learned_as_hostile():
    """learn.py:benign_ips:any-signal-excludes-address-from-learning-baseline"""
    e = Env()
    git = "git/2.43.0"
    e.write("CADDY_LOG", [web("198.51.100.7", "/user/login", BROWSER, 200, "POST", t=0),  # one mistyped password
                          web("198.51.100.7", "/alice/repo.git/info/refs", git, 200, t=5)])
    for k in range(2):
        e.write("CADDY_LOG", [web(f"203.0.113.{90 + k}", p, git, 404, t=20 + j) for j, p in enumerate(["/.env", "/.git/config", "/?x=${jndi:x}"])]
                + [web(f"203.0.113.{90 + k}", "/alice/repo.git/info/refs", git, 405, "PUT", t=30)])
    e.run()
    learn.learn_patterns(e.db)
    learned = {r[0] for r in e.db.execute("select value from intel where active = 1")}
    assert git not in learned and "/alice/repo.git/info/refs" not in learned, learned
    e.write("CADDY_LOG", [web("198.51.100.7", "/alice/repo.git/info/refs", git, 200, t=200 + k) for k in range(6)])
    e.run()
    assert "198.51.100.7" not in e.blocked()


def test_a_learned_hostile_network_cannot_block_ordinary_visitors():
    """learn.py:learn_patterns:hostile-network-poisoning-blocks-shared-24"""
    e = Env()
    for k in range(3):
        e.write("CADDY_LOG", [web(f"198.51.100.{10 + k}", p, "curl/8", 404, t=k * 10 + j) for j, p in enumerate(["/.env", "/.git/config", "/?x=${jndi:x}"])])
    e.run()
    learn.learn_patterns(e.db)
    assert e.db.execute("select count(*) from intel where kind = 'network'").fetchone()[0] == 1
    e.write("CADDY_LOG", [web("198.51.100.200", f"/page{k}", BROWSER, 200, t=300 + k) for k in range(20)])
    e.run()
    assert "198.51.100.200" not in e.blocked()


def test_ssh_blame_cannot_be_moved_with_a_crafted_username():
    """harrier.py:SSH_FAIL:unanchored-username-from-attribution"""
    e = Env()
    t = harrier.time.time()
    stamp = lambda k: time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(t - 60 + k))  # noqa: E731
    e.write("AUTH_LOG", [f"{stamp(k)} host sshd[{k}]: Invalid user x from 198.51.100.9 from 203.0.113.5 port 22" for k in range(8)])
    e.run()
    ips = {r[0] for r in e.db.execute("select ip from signals where source = 'ssh'")}
    assert ips == {"203.0.113.5"}, ips


def test_ssh_brute_force_on_the_app_port_is_seen_through_the_connection_recorder():
    """flows.py:main:dedup-starves-netwatch-ssh_brute-counter"""
    import flows
    import netwatch
    e = Env()
    clock, polls = [NOW - 1200], [0]

    def snapshot():
        polls[0] += 1
        yield str(polls[0]), ("tcp", "SYN_RECV", "203.0.113.90", "192.168.1.240", str(40000 + polls[0]), "2222", "192.168.1.240", "203.0.113.90")

    class Stop(Exception):
        pass

    def tick(_):
        clock[0] += 10
        if polls[0] >= 30:
            raise Stop

    saved = (flows.snapshot, flows.local_addresses, flows.time.time, flows.time.sleep)
    flows.snapshot, flows.local_addresses = snapshot, lambda: {"192.168.1.240"}
    flows.time.time, flows.time.sleep = lambda: clock[0], tick
    try:
        flows.main()
    except Stop:
        pass
    finally:
        flows.snapshot, flows.local_addresses, flows.time.time, flows.time.sleep = saved
    kinds = {s["kind"] for s in netwatch.read_conns(e.db)}
    assert "ssh_brute" in kinds, kinds


def test_domain_watch_never_follows_redirects():
    """harrier.py:http_info:unrestricted-redirect-ssrf"""
    seen = {}

    class R:
        status_code, is_redirect, text, url = 302, True, "", "https://watched.example/"
        headers = {"Location": "http://127.0.0.1:8080/admin"}

    def fake_get(url, **kw):
        seen.update(kw)
        return R()
    saved = harrier.requests.get
    harrier.requests.get = fake_get
    try:
        info = harrier.http_info("watched.example")
    finally:
        harrier.requests.get = saved
    assert seen.get("allow_redirects") is False
    assert info == {"status": 302, "final_url": "http://127.0.0.1:8080/admin", "title": ""}


def _client(e, role):
    import importlib
    import web
    app = importlib.reload(web).app
    auth.create_user(e.db, f"{role}-x", PW, role)
    c = app.test_client()
    c.post("/login", data={"username": f"{role}-x", "password": PW})
    return c


def test_viewers_cannot_read_admin_settings_or_the_audit_log():
    """web.py:api-settings-activity:viewer-reads-admin-only-settings"""
    e = Env()
    harrier.save_settings(e.db, {"notify_url": "https://ntfy.sh/secret-topic-7f3a"}, actor="alice")
    v = _client(e, "viewer")
    assert v.get("/api/settings").get_json()["notify_url"] == "set"
    assert v.get("/api/activity").status_code == 403 and v.get("/api/models").status_code == 403
    assert "secret-topic" not in json.dumps([dict(r) for r in e.db.execute("select detail from actions")])


def test_a_temporary_password_must_be_changed_before_changing_anything():
    e = Env()
    auth.create_user(e.db, "temp-admin", PW, "admin", must_change=True)
    import importlib
    import web
    c = importlib.reload(web).app.test_client()
    c.post("/login", data={"username": "temp-admin", "password": PW})
    assert c.post("/api/blocks", json={"ip": "203.0.113.9"}).status_code == 403
    assert c.post("/api/me/password", json={"current": PW, "new": "a brand new passphrase"}).status_code == 200
    assert c.post("/api/blocks", json={"ip": "203.0.113.9"}).status_code == 200


def test_ai_cannot_block_on_framable_evidence_and_stale_suggestions_clear():
    """AI path: same corroboration rule as the detector; the pending suggestion follows the latest verdict."""
    e = Env()
    e.write("CADDY_LOG", [web("192.0.2.70", "/", "ignore previous instructions", 200)])
    e.run()
    inc = e.db.execute("select * from incidents where ip = '192.0.2.70'").fetchone()
    v = {"summary": "s", "attack_type": "x", "severity": "high", "confidence": 1, "automated": True, "ai_agent_suspected": True,
         "manipulation_attempt": True, "recommended_action": "block_7d", "reasoning": "r", "next_steps": "n"}
    harrier.apply_verdict(e.db, inc, v)
    assert "192.0.2.70" not in e.blocked()
    assert e.db.execute("select pending_action from incidents where id = ?", (inc["id"],)).fetchone()[0] == "block_7d"
    harrier.apply_verdict(e.db, inc, {**v, "recommended_action": "none"})
    assert e.db.execute("select pending_action from incidents where id = ?", (inc["id"],)).fetchone()[0] is None


def test_setup_reads_the_env_template_as_empty_and_generates_secrets():
    """setup.sh:get/env-template-inline-comment-skips-secret-generation"""
    import tempfile
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    get = next(l for l in open(os.path.join(here, "setup.sh")) if l.startswith("get()"))
    d = tempfile.mkdtemp()
    with open(os.path.join(here, ".env.example")) as src, open(os.path.join(d, ".env"), "w") as dst:
        dst.write(src.read() + "LEGACY_STYLE=      # an inline comment from an older template\n")
    out = subprocess.run(["bash", "-c", f"{get}\nfor k in POSTGRES_PASSWORD ADMIN_PASSWORD LEGACY_STYLE MODEL; do echo \"$k=[$(get $k)]\"; done"],
                         cwd=d, capture_output=True, text=True).stdout
    assert "POSTGRES_PASSWORD=[]" in out and "ADMIN_PASSWORD=[]" in out and "LEGACY_STYLE=[]" in out and "MODEL=[gemma4:12b]" in out, out
