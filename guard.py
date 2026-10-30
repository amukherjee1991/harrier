"""Harrier guard: turns the block list into firewall rules. Runs on the host network with NET_ADMIN.

Deliberately small and dumb: it reads active blocks from the database, removes anything that
overlaps a protected range (home, VPN, loopback, your allowlist and public IP) or is wider than a
/16, and atomically replaces its own nftables table. Nothing else (no AI, no web, no parsing of
attacker-controlled text) runs in this process.

Its table hooks prerouting before Docker's rules, so blocked addresses can't reach the host or any
container. Remove everything with:  nft delete table inet harrier
"""
import hashlib
import ipaddress
import json
import logging
import subprocess
import sys
import time

import harrier

TABLE = "harrier"
MIN_PREFIX = {4: 16, 6: 48}
log = logging.getLogger("harrier.guard")


def wanted(db):
    nets = harrier.allow_nets(db)
    out = {4: [], 6: []}
    rows = db.execute("select ip from blocks where active = 1 and (expires_at is null or expires_at > ?)",
                      (time.time(),)).fetchall()
    for r in rows:
        try:
            n = ipaddress.ip_network(r["ip"], strict=False)
        except ValueError:
            continue
        if n.prefixlen < MIN_PREFIX[n.version] or any(n.overlaps(a) for a in nets if a.version == n.version):
            continue
        out[n.version].append(n)
    return {v: sorted(ipaddress.collapse_addresses(ns)) for v, ns in out.items()}


def ruleset(nets):
    def elements(v):
        return f" elements = {{ {', '.join(map(str, nets[v]))} }};" if nets[v] else ""
    return f"""table inet {TABLE} {{}}
delete table inet {TABLE}
table inet {TABLE} {{
  set blocked4 {{ type ipv4_addr; flags interval;{elements(4)} }}
  set blocked6 {{ type ipv6_addr; flags interval;{elements(6)} }}
  chain pre {{
    type filter hook prerouting priority -300; policy accept;
    ip saddr @blocked4 counter drop
    ip6 saddr @blocked6 counter drop
  }}
}}
"""


def dropped():
    """Packets dropped since the table was last written."""
    try:
        out = subprocess.run(["nft", "-j", "list", "table", "inet", TABLE], capture_output=True, text=True, timeout=10)
        items = json.loads(out.stdout).get("nftables", []) if out.returncode == 0 else []
    except (ValueError, subprocess.SubprocessError):
        return 0
    total = 0
    for it in items:
        for e in it.get("rule", {}).get("expr", []):
            if "counter" in e:
                total += e["counter"].get("packets", 0)
    return total


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s guard: %(message)s")
    db = harrier.open_db()
    applied = None
    while True:
        try:
            nets = wanted(db)
            rules = ruleset(nets)
            digest = hashlib.sha256(rules.encode()).hexdigest()
            state = harrier.get_state(db, "guard", {"dropped_total": 0})
            if digest != applied:
                state["dropped_total"] = state.get("dropped_total", 0) + dropped()  # counters reset on rewrite
                r = subprocess.run(["nft", "-f", "-"], input=rules, capture_output=True, text=True, timeout=20)
                if r.returncode != 0:
                    raise RuntimeError(r.stderr.strip()[:300])
                applied = digest
                log.info("firewall updated: %d IPv4, %d IPv6 ranges blocked", len(nets[4]), len(nets[6]))
            harrier.set_state(db, "guard", {
                "dropped_total": state.get("dropped_total", 0), "dropped_now": dropped(),
                "blocked": len(nets[4]) + len(nets[6]), "checked_at": time.time(), "error": "",
                "elements": [str(n) for n in nets[4] + nets[6]][:2000]})
        except Exception as e:
            log.error("%s", e)
            harrier.set_state(db, "guard", {**harrier.get_state(db, "guard", {}), "error": str(e)[:300],
                                            "checked_at": time.time()})
        time.sleep(5)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "print":
        print(ruleset(wanted(harrier.open_db())))
    else:
        main()
