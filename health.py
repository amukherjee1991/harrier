"""Harrier checks itself: live checks of the running system, the replay suite, and the AI red team.

Live checks every 6 hours, replay suite nightly, AI red team weekly (it uses the GPU for ~2 min).
Results go to the `checks` table and the dashboard's Health tab; failures raise an alert.
"""
import json
import logging
import os
import subprocess
import sys
import time
import uuid

import requests

import harrier

log = logging.getLogger("harrier.health")
HERE = os.path.dirname(os.path.abspath(__file__))
SCHEDULE = {"live": 6 * 3600, "replay": 24 * 3600, "ai": 7 * 86400}
TEST_IP = "192.0.2.250"  # reserved documentation address, never routed on the internet


def setup(db):
    """The checks table is part of the main schema (db.py)."""


def wait_for(cond, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(1)
    return cond()


def live_checks(db):
    out = []

    def check(name, fn):
        t = time.time()
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"[:300]
        out.append((name, "pass" if ok else "fail", detail, round(time.time() - t, 1)))

    now = time.time
    check("Log watcher is running", lambda: ((now() - harrier.get_state(db, "last_cycle", 0)) < 60,
                                             f"last ran {now() - harrier.get_state(db, 'last_cycle', 0):.0f}s ago"))
    guard = lambda: harrier.get_state(db, "guard", {})  # noqa: E731
    check("Firewall guard is running", lambda: (now() - guard().get("checked_at", 0) < 30 and not guard().get("error"),
                                                guard().get("error") or f"last check {now() - guard().get('checked_at', 0):.0f}s ago"))

    def enforcement():
        harrier.block(db, TEST_IP, "health check", None, "manual", 120, actor="health")
        on = wait_for(lambda: f"{TEST_IP}/32" in guard().get("elements", []), 20)
        harrier.unblock(db, TEST_IP, actor="health")
        off = wait_for(lambda: f"{TEST_IP}/32" not in guard().get("elements", []), 20)
        return on and off, f"block applied: {on}, removed: {off}"
    check("Blocks reach the firewall and can be lifted", enforcement)
    flows = lambda: harrier.get_state(db, "flows", {})  # noqa: E731
    check("Connection recorder is running", lambda: (now() - flows().get("checked_at", 0) < 60 and not flows().get("error"),
                                                     flows().get("error") or f"tracking {flows().get('tracked', 0)} connections"))

    def dns():
        last = db.execute("select max(at) from traffic where source = 'dns'").fetchone()[0] or 0
        return now() - last < 600, f"last lookup recorded {(now() - last) / 60:.0f} min ago"
    check("Home devices' DNS is being recorded", dns)

    def protected():
        hits = [ip for ip in ("192.168.1.1", "10.8.0.2", "127.0.0.1") if harrier.block(db, ip, "health", None, "manual", 60, actor="health")]
        for ip in hits:
            harrier.unblock(db, ip, actor="health")
        return not hits, f"wrongly blockable: {hits}" if hits else "home, VPN and loopback refused"
    check("Home and VPN addresses can't be blocked", protected)

    site = os.environ.get("WEB_SITE", "").strip()  # a site served by your Caddy, to test the log end to end
    if site:
        def flow():
            marker = f"/harrier-selftest-{uuid.uuid4().hex[:10]}"
            requests.get(f"https://{site}{marker}", headers={"User-Agent": harrier.SELFTEST_UA}, timeout=15)
            seen = wait_for(lambda: db.execute("select count(*) from traffic where path = ?", (marker,)).fetchone()[0] > 0, 45)
            return seen, "request showed up in the traffic log" if seen else "not seen in 45s: is Caddy writing its log?"
        check(f"Web traffic on {site} reaches Harrier", flow)

        def notice():
            r = requests.get(f"https://{site}/.env", headers={"User-Agent": harrier.SELFTEST_UA}, timeout=15)
            return r.status_code == 403 and "automated agents" in r.text, f"HTTP {r.status_code}"
        check("Attack probes get the 403 notice", notice)

    for d in harrier.get_settings(db)["domains"]:
        st = harrier.get_state(db, f"domain:{d}", {})
        check(f"Domain watch: {d}", lambda st=st: (now() - st.get("checked_at", 0) < 1200 and not st.get("problems"),
                                                    ", ".join(st.get("problems", [])) or f"checked {(now() - st.get('checked_at', 0)) / 60:.0f} min ago"))

    def model():
        m = harrier.get_settings(db)["model"]
        tags = requests.get(f"{harrier.OLLAMA_URL}/api/tags", timeout=10).json()["models"]
        return any(t["name"] == m for t in tags), f"{m} {'available' if any(t['name'] == m for t in tags) else 'missing'}"
    check("AI model is available", model)
    return out


def test_database():
    """Tests run in their own database (harrier_test), never in the live one."""
    url = harrier.dbmod.DATABASE_URL
    base, _, name = url.rpartition("/")
    test_url = f"{base}/{name.split('?')[0]}_test"
    try:
        c = harrier.dbmod.connect()
        if not c.execute("select 1 from pg_database where datname = ?", (name.split("?")[0] + "_test",)).fetchone():
            c.execute(f"create database {name.split('?')[0]}_test")
        c.close()
    except Exception as e:
        log.warning("couldn't prepare the test database: %s", e)
    return test_url


def suite(args, timeout):
    """Run tests/run.py in a separate process: tests swap internals, so they must not share ours."""
    report = os.path.join(HERE, "tests", "report.json")
    t = time.time()
    p = subprocess.run([sys.executable, os.path.join(HERE, "tests", "run.py"), *args],
                       capture_output=True, text=True, timeout=timeout, cwd=HERE,
                       env={**os.environ, "DATABASE_URL": test_database()})
    try:
        with open(report) as f:
            r = json.load(f)
        if r["at"] < t:
            raise ValueError("stale report")
        return [(x["test"].split(".", 1)[1].replace("test_", "").replace("_", " "), x["status"], x["detail"][:500], x["seconds"])
                for x in r["results"]]
    except (OSError, ValueError, KeyError):
        return [("test runner", "error", (p.stdout + p.stderr)[-500:], round(time.time() - t, 1))]


def run(db, which):
    setup(db)
    results = {"live": lambda: live_checks(db),
               "replay": lambda: suite([], 600),
               "ai": lambda: suite(["--ai", "test_ai"], 1800)}[which]()
    run_id, at = uuid.uuid4().hex[:8], time.time()
    db.executemany("insert into checks (run, at, suite, name, status, detail, seconds) values (?, ?, ?, ?, ?, ?, ?)",
                   [(run_id, at, which, *r) for r in results])
    db.execute("delete from checks where at < ?", (at - 60 * 86400,))
    db.commit()
    failed = [r[0] for r in results if r[1] != "pass"]
    harrier.set_state(db, f"health:{which}", {"at": at, "run": run_id, "passed": len(results) - len(failed), "total": len(results)})
    if failed:
        harrier.notify(db, f"Harrier self-check: {len(failed)} {which} check(s) failed", "; ".join(failed)[:500])
    log.info("%s checks: %d/%d passed", which, len(results) - len(failed), len(results))
    return results


def loop(stop):
    db = harrier.open_db()
    setup(db)
    stop.wait(90)  # let the watcher, guard and domain checks warm up first
    while not stop.is_set():
        for which, every in SCHEDULE.items():
            requested = harrier.get_state(db, "health_request") == which
            last = harrier.get_state(db, f"health:{which}", {}).get("at", 0)
            if requested or time.time() - last > every:
                harrier.set_state(db, "health_request", None)
                harrier.set_state(db, "health_running", which)
                try:
                    run(db, which)
                except Exception as e:
                    log.exception("%s checks crashed: %s", which, e)
                harrier.set_state(db, "health_running", None)
        stop.wait(15)
