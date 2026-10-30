"""Test scaffolding: a throwaway database and log folder per scenario, and log-line builders."""
import json
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone

import harrier

NOW = time.time()


class Env:
    """Fresh Harrier state: its own DB, Caddy/auth/ufw logs, and counters."""

    def __init__(self, mode="auto", **settings):
        self.dir = tempfile.mkdtemp(prefix="harrier-test-")
        for name in ("CADDY_LOG", "AUTH_LOG", "UFW_LOG", "KESTREL_DB"):
            setattr(harrier, name, os.path.join(self.dir, name.lower()))
        harrier.reset_counters()
        harrier.INTEL.update({"path": set(), "ua": set(), "network": []})
        harrier.notify = lambda db, title, msg: self.notes.append(title)
        self.notes = []
        self.schema = f"t_{uuid.uuid4().hex[:12]}"
        admin = harrier.dbmod.connect()
        admin.execute(f"create schema {self.schema}")
        admin.close()
        harrier.SCHEMA = self.schema
        self.db = harrier.open_db(self.schema)
        harrier.save_settings(self.db, {"mode": mode, "ai_enabled": False, "domains": [], **settings}, actor="test")

    def write(self, name, lines):
        with open(getattr(harrier, name), "a") as f:
            f.write("".join(l + "\n" for l in lines))

    def run(self):
        return harrier.cycle(self.db)

    # --- queries ---
    def incidents(self, **where):
        rows = [dict(r) for r in self.db.execute("select * from incidents order by id")]
        return [r for r in rows if all(r[k] == v for k, v in where.items())]

    def incident_for(self, ip):
        return next((r for r in self.incidents() if r["ip"] == ip or ip in json.loads(r["ips"])), None)

    def blocked(self):
        return {r["ip"] for r in self.db.execute("select ip from blocks where active = 1")}


def web(ip, uri, ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
        status=404, method="GET", t=0, host="git.example.com", referer=None):
    headers = {"User-Agent": [ua]}
    if referer:
        headers["Referer"] = [referer]
    return json.dumps({"ts": NOW - 600 + t, "status": status, "request": {
        "client_ip": ip, "remote_ip": ip, "host": host, "method": method, "uri": uri, "headers": headers}})


def iso(t):
    return datetime.fromtimestamp(NOW - 600 + t, timezone.utc).astimezone().isoformat()


def ssh_fail(ip, t, user="root"):
    return f"{iso(t)} host sshd[{1000 + int(t)}]: Failed password for {user} from {ip} port 4{int(t)} ssh2"


def ssh_ok(ip, t, user="alice"):
    return f"{iso(t)} host sshd[{2000 + int(t)}]: Accepted password for {user} from {ip} port 5 ssh2"


def ufw(ip, port, t, flags="SYN"):
    return (f"{iso(t)} host kernel: [UFW BLOCK] IN=eno1 OUT= MAC=x SRC={ip} DST=192.168.1.240 LEN=44 TOS=0x00 "
            f"PREC=0x00 TTL=50 ID=1 PROTO=TCP SPT=5555 DPT={port} WINDOW=1024 RES=0x00 {flags} URGP=0 ")
