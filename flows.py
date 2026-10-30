"""Harrier flows: records connections in and out of this machine (host, containers, VPN) from conntrack.

Runs on the host network with NET_ADMIN, read-only in spirit: it lists the kernel's connection
table every 10 seconds and writes new connections to the traffic log. Analysis happens in the main
Harrier process (netwatch.read_conns). DNS (port 53) is left out: Pi-hole's own log covers it.
"""
import ipaddress
import logging
import os
import re
import subprocess
import time

import harrier

log = logging.getLogger("harrier.flows")
LINE = re.compile(r"^(\w+)\s+\d+\s+(?:\d+\s+)?(?:([A-Z_]+)\s+)?src=(\S+) dst=(\S+) (?:sport=(\d+) dport=(\d+) )?.*?"
                  r"src=(\S+) dst=(\S+)")
DEDUP_SECONDS = 600
SSH_PORT = int(os.environ.get("APP_SSH_PORT", "2222"))


def local_addresses():
    out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True).stdout
    return {m.split("/")[0] for m in re.findall(r"inet6? (\S+)", out)}


def snapshot():
    r = subprocess.run(["conntrack", "-L", "-o", "id"], capture_output=True, text=True, timeout=30)
    for line in r.stdout.splitlines():
        m = LINE.match(line)
        cid = re.search(r"id=(\d+)", line)
        if m and cid:
            yield cid.group(1), m.groups()


def classify(g, mine):
    proto, state, src, dst, sport, dport, rsrc, rdst = g
    if dport is None or dport == "53" or sport == "53":
        return None
    for ip in (src, dst):
        a = harrier.parse_ip(ip)
        if a is None or a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified:
            return None  # local announcements and machine-internal traffic, not "in or out"
    if dst in mine:  # someone connecting to us (or to a container published on our ports)
        return ("in", src, dst, int(dport), proto, state or "")
    a = harrier.parse_ip(src)
    if a and (src in mine or a.is_private):  # we, a container or a VPN device connecting out
        remote = rsrc if rsrc not in mine else dst  # after Docker's NAT the real far end is the reply source
        if harrier.parse_ip(remote) and harrier.parse_ip(remote).is_private and harrier.parse_ip(dst).is_private:
            return None  # LAN-to-LAN chatter between local machines is not "in or out"
        return ("out", remote, src, int(dport), proto, state or "")
    return None


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s flows: %(message)s")
    db = harrier.open_db()
    seen_ids, recent = set(), {}
    mine, mine_at = local_addresses(), time.time()
    while True:
        try:
            now = time.time()
            if now - mine_at > 300:
                mine, mine_at = local_addresses(), now
            rows, ids = [], set()
            for cid, g in snapshot():
                ids.add(cid)
                if cid in seen_ids:
                    continue
                c = classify(g, mine)
                if not c:
                    continue
                direction, remote, me, port, proto, state = c
                # Each new connection to the watched SSH port counts (password guessing); others are summarised.
                key = (direction, remote, me, port, proto) + ((cid,) if direction == "in" and port == SSH_PORT else ())
                if now - recent.get(key, 0) < DEDUP_SECONDS:
                    continue
                recent[key] = now
                rows.append((now, "conn", remote, me, f"{direction}:{proto}", f"{me}:{port}", 0, state))
            seen_ids = ids
            recent = {k: v for k, v in recent.items() if now - v < DEDUP_SECONDS}
            if rows:
                db.executemany("insert into traffic (at, source, ip, host, method, path, status, ua) values (?, ?, ?, ?, ?, ?, ?, ?)", rows)
                db.commit()
            harrier.set_state(db, "flows", {"checked_at": now, "tracked": len(ids), "error": ""})
        except Exception as e:
            log.error("%s", e)
            harrier.set_state(db, "flows", {"checked_at": time.time(), "error": str(e)[:300]})
        time.sleep(10)


if __name__ == "__main__":
    main()
