"""Network watch: every device's DNS activity (from Pi-hole) and this machine's connections (from flows.py).

This PC isn't the router, so it can't see other devices' packets. But every device asks Pi-hole
before it connects anywhere, so DNS shows what each device talks to. Behaviour that points at
malware or a compromised device becomes signals like any other:

  new_device          a device that has never been seen before
  dga                 lookups of random-looking domains that don't exist (malware hunting for its server)
  dns_tunnel          long random subdomains used to smuggle data out through DNS
  beacon              a device checking in with the same rare domain at clockwork intervals
  dns_spike           a device suddenly making far more lookups than usual
  ssh_brute           repeated connections to Forgejo's SSH port (2222) from one address
  unexpected_inbound  an outside address reaching a port that shouldn't be open
  suspicious_outbound this PC, a container or a VPN device connecting out on ports malware uses
  callback_to_attacker  a connection out to an address Harrier has blocked as an attacker
  outbound_scan       one local machine trying many addresses on the same port that don't answer or refuse
                      (scanning); normal browsing completes its connections, so it never counts
"""
import ipaddress
import logging
import math
import os
import statistics
import threading
import time

import requests

import harrier

log = logging.getLogger("harrier.net")
PIHOLE_URL = os.environ.get("PIHOLE_URL", "http://pihole").rstrip("/")
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")
BLOCKED_STATUSES = {"GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
                    "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "SPECIAL_DOMAIN"}
# Big services that legitimately poll on a timer or use long hashed names; never beacon/tunnel suspects.
COMMON = ("apple.com", "icloud.com", "mzstatic.com", "google.com", "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com",
          "googlevideo.com", "youtube.com", "ytimg.com", "doubleclick.net", "microsoft.com", "windows.com", "msftncsi.com",
          "live.com", "office.com", "azure.com", "amazon.com", "amazonaws.com", "a2z.com", "netflix.com", "nflxvideo.net",
          "spotify.com", "scdn.co", "whatsapp.net", "whatsapp.com", "facebook.com", "fbcdn.net", "instagram.com",
          "samsung.com", "samsungcloud.com", "roku.com", "ntp.org", "cloudflare.com", "akamai.net", "akamaiedge.net",
          "akadns.net", "cloudfront.net", "fastly.net", "github.com", "githubusercontent.com", "ubuntu.com",
          "snapcraft.io", "docker.io", "docker.com", "ollama.com", "nvidia.com", "steamserver.net", "steampowered.com",
          "arpa", "local", "lan", "home.local", "ghs.googlehosted.com")
ODD_PORTS = {23: "telnet", 2323: "telnet", 4444: "metasploit", 1337: "backdoor", 31337: "backdoor", 6667: "IRC botnet",
             6697: "IRC botnet", 3333: "crypto mining", 14444: "crypto mining", 5555: "ADB/backdoor",
             45700: "crypto mining", 9001: "Tor", 9030: "Tor", 1080: "SOCKS proxy"}
# Ports your router forwards to this machine on purpose (web, WireGuard, Forgejo SSH by default).
EXPECTED_INBOUND = {int(p) for p in os.environ.get("EXPECTED_INBOUND_PORTS", "80,443,51820,2222").split(",") if p.strip()}
SSH_PORT = int(os.environ.get("APP_SSH_PORT", "2222"))
LAN = [ipaddress.ip_network(n) for n in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12")]


# --- Pi-hole ----------------------------------------------------------------------------------
class Pihole:
    def __init__(self):
        self.http, self.sid, self.lock = requests.Session(), None, threading.Lock()

    def queries(self, since, until):
        with self.lock:
            for attempt in range(2):
                if not self.sid:
                    r = self.http.post(f"{PIHOLE_URL}/api/auth", json={"password": PIHOLE_PASSWORD}, timeout=15)
                    r.raise_for_status()
                    self.sid = r.json()["session"]["sid"]
                    if not self.sid:
                        raise RuntimeError("Pi-hole rejected the password (PIHOLE_PASSWORD in ~/harrier/.env)")
                r = self.http.get(f"{PIHOLE_URL}/api/queries", headers={"X-FTL-SID": self.sid}, timeout=60,
                                  params={"from": int(since), "until": int(until) + 1, "length": 10000})
                if r.status_code == 401 and attempt == 0:
                    self.sid = None
                    continue
                r.raise_for_status()
                return r.json()["queries"]


pihole = Pihole()


def fetch_queries(since, until):
    return pihole.queries(since, until) if PIHOLE_PASSWORD else []


# --- Domain shape -----------------------------------------------------------------------------
def registrable(domain):
    parts = domain.rstrip(".").lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def is_common(domain):
    d = domain.lower().rstrip(".")
    return any(d == c or d.endswith("." + c) for c in COMMON)


def random_looking(label):
    """Machine-made names: long, high entropy, odd consonant runs or digits mixed in."""
    if len(label) < 12:
        return False
    vowels = sum(c in "aeiou" for c in label)
    digits = sum(c.isdigit() for c in label)
    longest_consonants = max((len(r) for r in "".join(c if c.isalpha() and c not in "aeiou" else " " for c in label).split()), default=0)
    return entropy(label) >= 3.3 and (vowels / len(label) < 0.25 or longest_consonants >= 5 or 0.15 < digits / len(label) < 0.7)


# --- DNS sensor -------------------------------------------------------------------------------
dga_hits = harrier.Counter(600, 8)
tunnel_hits = harrier.Counter(600, 20)


def reset():
    global dga_hits, tunnel_hits
    dga_hits, tunnel_hits = harrier.Counter(600, 8), harrier.Counter(600, 20)


def device_name(db, ip, name):
    return name or (db.execute("select name from devices where ip = ?", (ip,)).fetchone() or [None])[0] or ip


BASELINE_SECONDS = 86400  # first day: learn which devices and domains are normal here


def read_dns(db):
    now = time.time()
    baseline_until = harrier.get_state(db, "dns_baseline_until")
    if baseline_until is None:
        baseline_until = now + BASELINE_SECONDS
        harrier.set_state(db, "dns_baseline_until", baseline_until)
    learning = now < baseline_until
    since = harrier.get_state(db, "dns_since") or now - 600
    last_id = harrier.get_state(db, "dns_last_id", 0)
    queries = sorted((q for q in fetch_queries(since - 5, now) if q["id"] > last_id), key=lambda q: q["id"])
    out = []
    if now - harrier.get_state(db, "dns_behaviour_at", 0) > 300:
        out += behaviour(db, now)
        harrier.set_state(db, "dns_behaviour_at", now)
    if not queries:
        harrier.set_state(db, "dns_since", now - 5)
        return out
    rows = []
    known = {r[0] for r in db.execute("select ip from devices")}
    for q in queries:
        ip, name = q["client"]["ip"], q["client"].get("name") or ""
        domain, at = (q["domain"] or "").lower(), q["time"]
        blocked = q["status"] in BLOCKED_STATUSES
        reply = (q.get("reply") or {}).get("type") or ""
        rows.append((at, "dns", ip, name[:100], q["type"], domain[:300], 1 if blocked else 0, reply))
        if ip not in known:
            known.add(ip)
            db.execute("insert into devices (ip, name, first_seen) values (?, ?, ?) on conflict do nothing", (ip, name, at))
            if not learning:  # during the first day every device is just learned
                out.append(harrier.sig(at, "dns", ip, "new_device", 5,
                                       f"New device on the network: {name or ip} (first lookup: {domain})", host=name))
        who = name or ip
        reg = registrable(domain)
        if reply == "NXDOMAIN" and random_looking(reg.split(".")[0]) and not is_common(domain):
            if n := dga_hits.add(ip, at, domain):
                out.append(harrier.sig(at, "dns", ip, "dga", 8, f"{who} looked up {n} random-looking domains that don't "
                                       f"exist in 10 min (e.g. {domain}): typical of malware searching for its server",
                                       host=name, fp="dga"))
        sub = domain[: -len(reg)].rstrip(".") if reg and domain.endswith(reg) else ""
        if (len(sub) > 50 or any(len(l) > 40 for l in sub.split("."))) and entropy(sub.replace(".", "")) > 3.8 \
                and not is_common(domain):
            if n := tunnel_hits.add(f"{ip}|{reg}", at, sub):
                out.append(harrier.sig(at, "dns", ip, "dns_tunnel", 8, f"{who} sent {n} long random lookups under {reg} "
                                       f"in 10 min: data may be leaking out through DNS", host=name, fp=f"tunnel:{reg}"))
    db.executemany("insert into traffic (at, source, ip, host, method, path, status, ua) values (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    db.executemany("insert into dns_domains (reg, first_seen) values (?, ?) on conflict do nothing",
                   [(registrable(r[5]), r[0]) for r in rows if r[5]])
    db.execute("update devices set last_seen = ?, name = coalesce(nullif(?, ''), name) where ip = ?",
               (queries[-1]["time"], queries[-1]["client"].get("name") or "", queries[-1]["client"]["ip"]))
    db.commit()
    harrier.set_state(db, "dns_last_id", queries[-1]["id"])
    harrier.set_state(db, "dns_since", queries[-1]["time"])
    return out


def behaviour(db, now):
    """Slower checks over the last hours of DNS: beaconing and volume spikes."""
    out = []
    baseline_until = harrier.get_state(db, "dns_baseline_until", now)
    if now < baseline_until:
        return out
    young = {r[0] for r in db.execute("select reg from dns_domains where first_seen > ? and first_seen > ?",
                                      (baseline_until, now - 7 * 86400))}
    rows = db.execute("select ip, host, path, at from traffic where source = 'dns' and at > ? order by at", (now - 7200,)).fetchall()
    by_pair, askers = {}, {}
    for r in rows:
        reg = registrable(r["path"])
        if is_common(r["path"]):
            continue
        by_pair.setdefault((r["ip"], reg), []).append(r["at"])
        askers.setdefault(reg, set()).add(r["ip"])
    for (ip, reg), times in by_pair.items():
        if len(times) < 10 or len(askers[reg]) > 1 or reg not in young:
            continue  # malware check-ins go to domains new to this network that only one device talks to
        if now - harrier.get_state(db, f"beacon:{ip}|{reg}", 0) < 86400:
            continue  # already reported today
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 2]
        if len(gaps) < 8:
            continue
        mean = statistics.mean(gaps)
        if 30 <= mean <= 3600 and statistics.pstdev(gaps) / mean < 0.1:
            name = device_name(db, ip, "")
            harrier.set_state(db, f"beacon:{ip}|{reg}", now)
            out.append(harrier.sig(now, "dns", ip, "beacon", 4, f"{name} contacts {reg} like clockwork, every "
                                   f"{mean:.0f}s ({len(times)} times in 2 h), and no other device does: possible "
                                   f"malware checking in", fp=f"beacon:{reg}"))
    hour = {r[0]: r[1] for r in db.execute("select ip, count(*) from traffic where source = 'dns' and at > ? group by ip", (now - 3600,))}
    base = {r[0]: r[1] / 24 for r in db.execute("select ip, count(*) from traffic where source = 'dns' and at between ? and ? "
                                                "group by ip", (now - 25 * 3600, now - 3600))}
    for ip, n in hour.items():
        if n > 600 and base.get(ip, 0) > 0 and n > 5 * base[ip]:
            out.append(harrier.sig(now, "dns", ip, "dns_spike", 4, f"{device_name(db, ip, '')} made {n} lookups in the "
                                   f"last hour, {n / base[ip]:.0f}x its usual rate"))
    return out


# --- Connections (written by flows.py) --------------------------------------------------------
ssh_conns = harrier.Counter(600, 10)
fanout = harrier.Counter(600, 30)
UNANSWERED = {"SYN_SENT", "CLOSE"}  # conntrack states of connection attempts that got no answer or were refused


def local(ip):
    a = harrier.parse_ip(ip)
    return a is not None and (a.is_loopback or a.is_link_local or a.is_multicast
                              or any(a in n for n in LAN if n.version == a.version))


def read_conns(db):
    last = harrier.get_state(db, "conn_last_id", 0)
    rows = db.execute("select * from traffic where source = 'conn' and id > ? order by id limit 20000", (last,)).fetchall()
    if not rows:
        return []
    out = []
    blocked = {r[0] for r in db.execute("select ip from blocks")}
    for r in rows:
        direction, port = r["method"].split(":", 1)[0], int(r["path"].rsplit(":", 1)[-1] or 0)
        remote, me, at = r["ip"], r["host"], r["at"]
        if direction == "in" and not local(remote):
            if port == SSH_PORT and (n := ssh_conns.add(remote, at)):
                out.append(harrier.sig(at, "conn", remote, "ssh_brute", 6, f"{n} connections to SSH on port {port} in 10 min",
                                       fp=f"ssh{port}"))
            elif port not in EXPECTED_INBOUND:
                out.append(harrier.sig(at, "conn", remote, "unexpected_inbound", 3,
                                       f"Outside address reached port {port} on {me}: check your router's port forwards"))
        elif direction == "out":
            if remote in blocked:
                out.append(harrier.sig(at, "conn", me, "callback_to_attacker", 8,
                                       f"{me} connected out to {remote}:{port}, an address Harrier blocked as an attacker"))
            if port in ODD_PORTS and not local(remote):
                out.append(harrier.sig(at, "conn", me, "suspicious_outbound", 6,
                                       f"{me} connected to {remote}:{port} ({ODD_PORTS[port]})", fp=f"port:{port}"))
            if not local(remote) and r["ua"] in UNANSWERED and (n := fanout.add(f"{me}|{port}", at, remote)):
                out.append(harrier.sig(at, "conn", me, "outbound_scan", 8, f"{me} tried {n} different addresses on "
                                       f"port {port} in 10 min: it may be compromised and attacking others"))
    harrier.set_state(db, "conn_last_id", rows[-1]["id"])
    return out
