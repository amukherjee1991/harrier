#!/usr/bin/env bash
# What Harrier saw and did about one address, e.g. after running attack.sh from outside.
#   ~/harrier/tests/live_report.sh 203.0.113.7
set -u
[ $# -eq 1 ] || { echo "usage: $0 IP"; exit 2; }
docker exec -i harrier python - "$1" <<'EOF'
import harrier, json, sys, time
ip, db = sys.argv[1], harrier.open_db()
t = lambda x: time.strftime("%H:%M:%S", time.localtime(x)) if x else "-"
reqs = db.execute("select count(*), min(at), max(at) from traffic where ip = ?", (ip,)).fetchone()
print(f"Requests logged: {reqs[0]} ({t(reqs[1])} to {t(reqs[2])})")
print("\nSignals:")
for s in db.execute("select at, kind, score, detail from signals where ip = ? order by at", (ip,)):
    print(f"  {t(s['at'])}  {s['kind']:<24} +{s['score']:<3} {s['detail'][:90]}")
print("\nIncidents:")
for i in db.execute("select * from incidents where ip = ? or ips like ? order by id", (ip, f'%"{ip}"%')):
    print(f"  #{i['id']} [{i['severity']}] {i['status']}: {i['title']}")
    if i["ai"]:
        a = json.loads(i["ai"])
        print(f"     AI: {a['summary']}\n     AI suggests {a['recommended_action']}, manipulation={a['manipulation_attempt']}, "
              f"agent={a['ai_agent_suspected']}" + (f"  (waiting for your approval: {i['pending_action']})" if i["pending_action"] else ""))
b = db.execute("select * from blocks where ip = ?", (ip,)).fetchone()
first = db.execute("select min(at) from signals where ip = ?", (ip,)).fetchone()[0]
if b and b["active"]:
    print(f"\nBlocked by {b['source']} at {t(b['created_at'])}"
          + (f", {b['created_at'] - first:.0f}s after the first hostile request" if first else "")
          + (f", until {time.strftime('%Y-%m-%d %H:%M', time.localtime(b['expires_at']))}" if b["expires_at"] else ", permanently"))
    print(f"Unblock: docker exec harrier python harrier.py unblock {ip}   (or the dashboard's Blocked tab)")
else:
    print("\nNot blocked.")
EOF
