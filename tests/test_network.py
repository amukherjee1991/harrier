"""Network watch: home devices' DNS behaviour and this machine's connections."""
import random
import string

from helpers import NOW, Env

import harrier
import netwatch

_id = [0]


def q(ip, domain, t, reply="IP", status="FORWARDED", name="Pixel-8"):
    _id[0] += 1
    return {"id": _id[0], "time": NOW - 900 + t, "type": "A", "status": status, "domain": domain,
            "reply": {"type": reply}, "client": {"ip": ip, "name": name}}


def dns_env(first=()):
    """An Env whose first-day baseline already saw the devices and domains in `first`, and has ended."""
    e = Env()
    netwatch.reset()
    feed = {"rows": list(first)}
    netwatch.fetch_queries = lambda since, until: [x for x in feed["rows"] if since <= x["time"] <= until]
    harrier.set_state(e.db, "dns_since", NOW - 1000)
    e.run()  # baseline: who's here and what they normally use
    harrier.set_state(e.db, "dns_baseline_until", NOW - 950)
    return e, feed


def conn(e, direction, remote, me, port, t=0, state="ESTABLISHED"):
    e.db.execute("insert into traffic (at, source, ip, host, method, path, status, ua) values (?, 'conn', ?, ?, ?, ?, 0, ?)",
                 (NOW - 600 + t, remote, me, f"{direction}:tcp", f"{me}:{port}", state))
    e.db.commit()


def rnd(n, seed):
    r = random.Random(seed)
    return "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def test_normal_home_browsing_raises_nothing():
    domains = ["www.google.com", "i.ytimg.com", "api.spotify.com", "www.bbc.co.uk", "en.wikipedia.org", "github.com",
               "static.xx.fbcdn.net", "gateway.icloud.com", "www.nytimes.com", "cdn.jsdelivr.net", "time.apple.com"]
    e, feed = dns_env([q("192.168.1.31", d, 0) for d in domains])
    feed["rows"] += [q("192.168.1.31", domains[k % len(domains)], 10 + k * 7) for k in range(120)]
    feed["rows"] += [q("192.168.1.31", "ads.doubleclick.net", 20 + k * 30, status="GRAVITY") for k in range(10)]
    e.run()
    assert not e.incidents(), e.incidents()


def test_new_device_is_noticed_but_not_blocked():
    e, feed = dns_env([q("192.168.1.31", "www.google.com", 0)])
    feed["rows"].append(q("192.168.1.77", "connectivitycheck.gstatic.com", 30, name="unknown-device"))
    e.run()
    inc = e.incident_for("192.168.1.77")
    assert inc and inc["kind"] == "device" and inc["severity"] == "medium", inc
    assert not e.blocked()


def test_malware_dga_lookups_are_flagged():
    e, feed = dns_env([q("192.168.1.42", "www.google.com", 0, name="iPad")])
    feed["rows"] += [q("192.168.1.42", f"{rnd(16, k)}.com", 10 + k * 5, reply="NXDOMAIN", name="iPad") for k in range(12)]
    e.run()
    inc = e.incident_for("192.168.1.42")
    assert inc and "malware-style lookups" in inc["title"], e.incidents()


def test_dns_tunnel_is_flagged():
    e, feed = dns_env([q("192.168.1.55", "www.google.com", 0, name="Work-Laptop")])
    feed["rows"] += [q("192.168.1.55", f"{rnd(52, k)}.{rnd(20, k + 99)}.exfil-example.net", 10 + k * 3, name="Work-Laptop")
                     for k in range(25)]
    e.run()
    inc = e.incident_for("192.168.1.55")
    assert inc and "data hidden in DNS" in inc["title"], e.incidents()


def test_beaconing_to_a_rare_domain_is_noticed():
    e, feed = dns_env([q("192.168.1.60", "www.google.com", 0, name="Smart-Speaker")])
    # every 5 minutes for 70 minutes, ending 15 minutes ago, to a domain first seen after the learning day
    harrier.set_state(e.db, "dns_baseline_until", NOW - 6000)
    harrier.set_state(e.db, "dns_since", NOW - 6000)
    feed["rows"] += [q("192.168.1.60", "update.c2-example.xyz", -4200 + k * 300, name="Smart-Speaker") for k in range(14)]
    e.run()
    harrier.set_state(e.db, "dns_behaviour_at", 0)
    e.run()
    kinds = {r[0] for r in e.db.execute("select kind from signals where ip = '192.168.1.60'")}
    assert "beacon" in kinds, kinds


def test_forgejo_ssh_brute_force_is_blocked():
    e = Env()
    for k in range(25):
        conn(e, "in", "203.0.113.90", "192.168.1.240", 2222, t=k * 5)
    e.run()
    inc = e.incident_for("203.0.113.90")
    assert inc, e.incidents()
    kinds = {r[0] for r in e.db.execute("select kind from signals where ip = '203.0.113.90'")}
    assert "ssh_brute" in kinds, kinds


def test_compromised_container_scanning_out_is_flagged():
    e = Env()
    for k in range(60):
        conn(e, "out", f"198.51.100.{k + 1}", "172.30.77.20", 22, t=k, state="SYN_SENT" if k % 3 else "CLOSE")
    e.run()
    inc = e.incident_for("172.30.77.20")
    assert inc and "scanning other machines" in inc["title"], e.incidents()
    assert not e.blocked()


def test_callback_to_known_attacker_and_mining_port():
    e = Env()
    harrier.block(e.db, "203.0.113.66", "earlier attack", None, "rule")
    conn(e, "out", "203.0.113.66", "192.168.1.240", 443)
    conn(e, "out", "185.71.65.1", "172.30.77.10", 3333, t=5)
    e.run()
    k1 = {r[0] for r in e.db.execute("select kind from signals where ip = '192.168.1.240'")}
    k2 = {r[0] for r in e.db.execute("select kind from signals where ip = '172.30.77.10'")}
    assert "callback_to_attacker" in k1 and "suspicious_outbound" in k2, (k1, k2)


def test_normal_server_connections_raise_nothing():
    e = Env()
    for k, (remote, port) in enumerate([("140.82.112.4", 443), ("151.101.1.69", 443), ("1.1.1.1", 443), ("91.189.91.38", 80)]):
        conn(e, "out", remote, "192.168.1.240", port, t=k)
    for k in range(30):
        conn(e, "in", f"203.0.113.{k + 1}", "192.168.1.240", 443, t=10 + k)
    conn(e, "in", "203.0.113.200", "192.168.1.240", 51820, t=50)
    conn(e, "in", "127.0.0.1", "127.0.0.1", 5054, t=51)  # machine-internal
    conn(e, "in", "fe80::6bc:9fff:fe94:8d8a", "fe80::5a57:54d5:9c46:5330", 546, t=52)  # IPv6 link-local DHCP
    e.run()
    assert not e.incidents(), e.incidents()


def test_flow_parser_reads_conntrack_lines():
    import flows
    mine = {"192.168.1.240", "172.30.77.1"}
    lines = {
        "in": "tcp      6 431999 ESTABLISHED src=203.0.113.5 dst=192.168.1.240 sport=51000 dport=443 src=172.30.77.3 dst=203.0.113.5 sport=443 dport=51000 [ASSURED] mark=0 use=1 id=11",
        "out": "tcp      6 117 TIME_WAIT src=172.30.77.10 dst=140.82.112.4 sport=40000 dport=443 src=140.82.112.4 dst=192.168.1.240 sport=443 dport=40000 [ASSURED] mark=0 use=1 id=12",
        "dns": "udp      17 29 src=192.168.1.31 dst=192.168.1.240 sport=5353 dport=53 src=192.168.1.240 dst=192.168.1.31 sport=53 dport=5353 mark=0 use=1 id=13",
    }
    lines.update({
        "mdns": "udp      17 29 src=172.20.0.1 dst=224.0.0.251 sport=5353 dport=5353 [UNREPLIED] src=224.0.0.251 dst=172.20.0.1 sport=5353 dport=5353 mark=0 use=1 id=14",
        "loopback": "tcp      6 431999 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=40000 dport=5054 src=127.0.0.1 dst=127.0.0.1 sport=5054 dport=40000 [ASSURED] mark=0 use=1 id=15",
        "linklocal": "udp      17 29 src=fe80::1 dst=ff02::1:2 sport=546 dport=547 [UNREPLIED] src=ff02::1:2 dst=fe80::1 sport=547 dport=546 mark=0 use=1 id=16",
    })
    got = {}
    for name, line in lines.items():
        m = flows.LINE.match(line)
        got[name] = flows.classify(m.groups(), mine) if m else "unparsed"
    assert got["in"] == ("in", "203.0.113.5", "192.168.1.240", 443, "tcp", "ESTABLISHED"), got
    assert got["out"] == ("out", "140.82.112.4", "172.30.77.10", 443, "tcp", "TIME_WAIT"), got
    assert got["dns"] is None and got["mdns"] is None and got["loopback"] is None and got["linklocal"] is None, got


def test_busy_but_normal_machine_is_not_a_scanner():
    """A PC browsing and pulling updates connects to many addresses on 443, and they answer."""
    e = Env()
    for k in range(80):
        conn(e, "out", f"151.101.{k // 250}.{k % 250 + 1}", "192.168.1.240", 443, t=k, state="ESTABLISHED" if k % 2 else "TIME_WAIT")
    for k in range(5):
        conn(e, "out", f"203.0.113.{k + 1}", "192.168.1.240", 443, t=100 + k, state="SYN_SENT")  # a few dead servers
    e.run()
    assert not e.incidents(), e.incidents()
