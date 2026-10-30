"""Learning: it must get better from real attacks and your feedback, and attackers must not be able to teach it."""
from helpers import Env, web

import harrier
import learn

BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15"


def attack(e, ip, extra_paths, ua="Mozilla/5.0 zgrab/0.x", t=0):
    """A confirmed attacker: exploit attempts (gets blocked) plus whatever else it requested."""
    e.write("CADDY_LOG", [web(ip, p, ua, 404, t=t + k) for k, p in enumerate(["/.env", "/.git/config", "/?x=${jndi:x}"] + extra_paths)])


def test_learns_new_attack_path_seen_from_several_attackers():
    e = Env()
    for k in range(3):
        attack(e, f"203.0.113.{10 + k}", ["/internal/debug-panel"], t=k * 30)
    e.run()
    assert learn.learn_patterns(e.db) >= 1
    learned = {r["value"] for r in e.db.execute("select value from intel where active = 1")}
    assert "/internal/debug-panel" in learned, learned
    # A new attacker using only that path is now recognised.
    e.write("CADDY_LOG", [web("198.51.100.99", "/internal/debug-panel", BROWSER, 404, t=200)])
    e.run()
    kinds = {r[0] for r in e.db.execute("select kind from signals where ip = '198.51.100.99'")}
    assert "learned_pattern" in kinds, kinds


def test_attackers_cannot_teach_it_your_real_pages():
    """Poisoning: attackers also request normal pages so Harrier would learn to flag your visitors."""
    e = Env()
    e.write("CADDY_LOG", [web("8.8.4.4", "/alice/project", BROWSER, 200), web("8.8.8.8", "/explore/repos", BROWSER, 200)])
    for k in range(4):
        attack(e, f"203.0.113.{20 + k}", ["/alice/project", "/explore/repos"], t=k * 30)
    e.run()
    learn.learn_patterns(e.db)
    learned = {r["value"] for r in e.db.execute("select value from intel")}
    assert not learned & {"/alice/project", "/explore/repos"}, learned


def test_one_attacker_is_not_enough_evidence():
    e = Env()
    attack(e, "203.0.113.30", ["/only-this-guy"])
    e.run()
    learn.learn_patterns(e.db)
    assert not e.db.execute("select count(*) from intel where value = '/only-this-guy'").fetchone()[0]


def test_never_learns_browser_user_agents_or_static_files():
    e = Env()
    for k in range(3):
        attack(e, f"203.0.113.{40 + k}", ["/favicon.ico", "/assets/app.js"], ua=BROWSER, t=k * 30)
    e.run()
    learn.learn_patterns(e.db)
    learned = {r["value"] for r in e.db.execute("select value from intel")}
    assert BROWSER not in learned and not learned & {"/favicon.ico", "/assets/app.js"}, learned


def test_learns_attack_tool_signatures():
    e = Env()
    for k in range(2):
        attack(e, f"203.0.113.{50 + k}", [], ua="Swarm-Agent/3.1 (+recon)", t=k * 30)
    e.run()
    learn.learn_patterns(e.db)
    assert e.db.execute("select count(*) from intel where kind = 'ua' and value = 'Swarm-Agent/3.1 (+recon)'").fetchone()[0]


def test_learns_hostile_networks():
    e = Env()
    for k in range(3):
        attack(e, f"45.155.205.{10 + k}", [], t=k * 30)
    e.run()
    learn.learn_patterns(e.db)
    e.write("CADDY_LOG", [web("45.155.205.200", "/", BROWSER, 200, t=300)])
    e.run()
    kinds = {r[0] for r in e.db.execute("select kind from signals where ip = '45.155.205.200'")}
    assert "hostile_network" in kinds, kinds


def test_false_alarm_feedback_lowers_sensitivity_but_never_for_exploits():
    e = Env()
    e.write("CADDY_LOG", [web("203.0.113.60", p, "curl/8", 404, t=k) for k, p in enumerate(["/.env", "/?x=${jndi:x}", "/wp-login.php"])])
    e.run()
    inc = e.db.execute("select * from incidents where ip = '203.0.113.60'").fetchone()
    for _ in range(4):
        learn.feedback(e.db, inc, "false_positive")
    w = {r["kind"]: r["weight"] for r in e.db.execute("select kind, weight from weights")}
    assert w["probe"] < 1, w
    assert w["exploit"] >= 1, w


def test_false_alarm_unlearns_patterns_from_that_address():
    e = Env()
    for k in range(2):
        attack(e, f"203.0.113.{70 + k}", ["/weird-path"], t=k * 30)
    e.run()
    learn.learn_patterns(e.db)
    assert e.db.execute("select active from intel where value = '/weird-path'").fetchone()[0] == 1
    inc = e.db.execute("select * from incidents where ip = '203.0.113.70'").fetchone()
    learn.feedback(e.db, inc, "false_positive")
    assert e.db.execute("select active from intel where value = '/weird-path'").fetchone()[0] == 0


def test_ai_sees_your_past_decisions():
    e = Env()
    e.write("CADDY_LOG", [web("203.0.113.80", p, "curl/8", 404, t=k) for k, p in enumerate(["/.env", "/.git/config"])])
    e.run()
    first = e.db.execute("select * from incidents where ip = '203.0.113.80'").fetchone()
    harrier.record(e.db, "you", "false_positive", f"incident #{first['id']}")
    e.write("CADDY_LOG", [web("203.0.113.81", p, "curl/8", 404, t=50 + k) for k, p in enumerate(["/.env", "/.git/config"])])
    e.run()
    second = e.db.execute("select * from incidents where ip = '203.0.113.81'").fetchone()
    ev = harrier.evidence_for(e.db, second)
    assert ev["owner_decisions_on_similar_incidents"] and \
        ev["owner_decisions_on_similar_incidents"][0]["owner_decided"] == "false alarm", ev["owner_decisions_on_similar_incidents"]
