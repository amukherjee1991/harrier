"""How Harrier gets better on its own, without becoming persuadable.

It learns from two sources only: your decisions in the dashboard, and the behaviour of attackers it
has confirmed (blocked, and not marked as a false alarm by you). Nothing a request *says* is ever a
lesson. Every learned pattern must also never appear in normal visitors' traffic, so an attacker
can't teach Harrier to flag your real pages, and learning can only add detection; it never removes
any. Only you can make Harrier less sensitive, by marking false alarms.

1. Weights: your feedback tunes how much each kind of signal counts.
2. Attack memory: paths, tools (user agents) and networks used by confirmed attackers become new
   detection patterns, after checking them against normal traffic.
3. The AI sees your past decisions on similar incidents (see harrier.evidence_for).
"""
import ipaddress
import json
import logging
import re
import time

import harrier

log = logging.getLogger("harrier.learn")
NEVER_WEAKER = {"manipulation", "exploit", "ssh_login_after_failures", "learned_pattern", "hostile_network"}
BROWSER_UA = re.compile(r"^Mozilla/5\.0 \((Windows|Macintosh|X11|Linux|iPhone|iPad)")
MIN_ATTACKERS = 2
BASELINE_DAYS = 14


def lesson(db, kind, detail):
    db.execute("insert into lessons (at, kind, detail) values (?, ?, ?)", (time.time(), kind, detail[:500]))
    db.commit()
    log.info("learned (%s): %s", kind, detail)


# --- 1. Your feedback ---------------------------------------------------------------------------
def feedback(db, inc, action):
    """Called when you act on an incident in the dashboard."""
    if action not in ("false_positive", "approve", "block_7d", "block_permanent"):
        return
    ips = json.loads(inc["ips"] or "[]") or [inc["ip"]]
    kinds = [r[0] for r in db.execute(
        f"select distinct kind from signals where ip in ({','.join('?' * len(ips))}) and at >= ?",
        ips + [inc["first_at"] - 600])]
    good = action != "false_positive"
    for k in kinds:
        db.execute("insert into weights (kind) values (?) on conflict(kind) do nothing", (k,))
        db.execute(f"update weights set {'confirmed = confirmed + 1' if good else 'false_alarms = false_alarms + 1'} "
                   "where kind = ?", (k,))
        r = db.execute("select * from weights where kind = ?", (k,)).fetchone()
        floor = 1.0 if k in NEVER_WEAKER else 0.25
        w = round(min(2.0, max(floor, 1 + 0.15 * r["confirmed"] - 0.25 * r["false_alarms"])), 2)
        if w != r["weight"]:
            db.execute("update weights set weight = ? where kind = ?", (w, k))
            lesson(db, "weight", f"'{k}' signals now count {w}x (you confirmed {r['confirmed']}, "
                                 f"marked {r['false_alarms']} false alarm{'s' if r['false_alarms'] != 1 else ''})")
    if not good:  # anything learned from these addresses was learned from a mistake
        for ip in ips:
            for row in db.execute("select id, value from intel where active = 1 and sources like ?", (f'%"{ip}"%',)).fetchall():
                db.execute("update intel set active = 0 where id = ?", (row["id"],))
                lesson(db, "unlearned", f"Dropped pattern {row['value']!r}: it came from {ip}, which you marked a false alarm")
    db.commit()


# --- 2. Attack memory ---------------------------------------------------------------------------
def confirmed_attackers(db, since):
    """Addresses blocked (by rules, AI or you) that you didn't mark as false alarms."""
    fp = set()
    for r in db.execute("select ips from incidents where status = 'false_positive'"):
        fp |= set(json.loads(r[0] or "[]"))
    rows = db.execute("select ip from blocks where created_at > ?", (since,)).fetchall()
    return {r[0] for r in rows if r[0] not in fp and "/" not in r[0]}


def benign_ips(db, since, attackers):
    """Everyone who sent traffic except confirmed attackers. A real user with one mistyped password is still normal."""
    return {r[0] for r in db.execute("select distinct ip from traffic where at > ?", (since,))} - set(attackers)


def candidates(db, attackers, since):
    if not attackers:
        return {}
    marks = ",".join("?" * len(attackers))
    out = {"path": {}, "ua": {}}
    for r in db.execute(f"select ip, path, status, ua from traffic where ip in ({marks}) and at > ?", list(attackers) + [since]):
        path = r["path"].split("?", 1)[0]
        if r["status"] in (400, 401, 403, 404, 405) and len(path) > 3 and path != "/":
            out["path"].setdefault(path, set()).add(r["ip"])
        ua = (r["ua"] or "").strip()
        if len(ua) >= 8 and not BROWSER_UA.match(ua):
            out["ua"].setdefault(ua, set()).add(r["ip"])
    return out


def learn_patterns(db):
    since = time.time() - BASELINE_DAYS * 86400
    attackers = confirmed_attackers(db, since)
    if not attackers:
        return 0
    benign = benign_ips(db, since, attackers)
    benign_paths, benign_uas = set(), set()
    if benign:
        marks = ",".join("?" * len(benign))
        for r in db.execute(f"select path, ua from traffic where ip in ({marks}) and at > ?", list(benign) + [since]):
            benign_paths.add(r["path"].split("?", 1)[0])
            benign_uas.add((r["ua"] or "").strip())
    # A page that ever served anyone normally (2xx/3xx) is a real page, whoever else poked at it.
    for r in db.execute("select distinct path from traffic where source = 'web' and status < 400 and at > ?", (since,)):
        benign_paths.add(r["path"].split("?", 1)[0])
    existing = {(r["kind"], r["value"]) for r in db.execute("select kind, value from intel")}
    new = 0
    for kind, items in candidates(db, attackers, since).items():
        baseline = benign_paths if kind == "path" else benign_uas
        for value, ips in items.items():
            if len(ips) < MIN_ATTACKERS or value in baseline or (kind, value) in existing:
                continue
            if kind == "path" and harrier.STATIC.search(value):
                continue  # never learn ordinary assets as hostile
            db.execute("insert into intel (kind, value, sources, first_at, active) values (?, ?, ?, ?, 1)",
                       (kind, value[:300], json.dumps(sorted(ips)[:20]), time.time()))
            lesson(db, "pattern", f"New {'path' if kind == 'path' else 'tool signature'} {value[:120]!r}: used by "
                                  f"{len(ips)} confirmed attackers, never by normal visitors")
            new += 1
    # Networks that keep producing attackers.
    nets = {}
    for ip in attackers:
        a = harrier.parse_ip(ip)
        if a and a.version == 4:
            nets.setdefault(str(ipaddress.ip_network(f"{ip}/24", strict=False)), set()).add(ip)
    for net, ips in nets.items():
        if len(ips) >= 3 and ("network", net) not in existing and not any(
                harrier.parse_ip(b) in ipaddress.ip_network(net) for b in benign if harrier.parse_ip(b) and harrier.parse_ip(b).version == 4):
            db.execute("insert into intel (kind, value, sources, first_at, active) values ('network', ?, ?, ?, 1)",
                       (net, json.dumps(sorted(ips)[:20]), time.time()))
            lesson(db, "network", f"Network {net} produced {len(ips)} attackers: anything new from it starts out suspicious")
            new += 1
    db.commit()
    harrier.refresh_intel(db)
    return new


def loop(stop):
    db = harrier.open_db()
    stop.wait(120)
    while not stop.is_set():
        try:
            learn_patterns(db)
        except Exception as e:
            log.exception("learning failed: %s", e)
        harrier.set_state(db, "learned_at", time.time())
        stop.wait(3600)
