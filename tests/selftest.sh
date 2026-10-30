#!/usr/bin/env bash
# Checks the RUNNING Harrier from this machine: containers, firewall enforcement, log flow,
# probe notice, domain watch, AI model, dashboard auth and protections. Safe to run any time:
# it only blocks a reserved test address (192.0.2.250, never routed on the internet) for a moment.
#   ~/harrier/tests/selftest.sh
set -u
pass=0; fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1${2:+ — $2}"; fail=$((fail+1)); }
py()   { docker exec -i harrier python - "$@"; }
cd "$(dirname "$0")/.." || exit 1
set -a; [ -f .env ] && . ./.env; set +a
SITE=${WEB_SITE:-}
DASH=http://127.0.0.1:${HARRIER_PORT:-8095}
CURL=(curl -s --max-time 10 --resolve "$SITE:443:127.0.0.1" -A harrier-selftest)

for c in harrier harrier-guard; do
  [ "$(docker inspect -f '{{.State.Running}}' $c 2>/dev/null)" = true ] && ok "container $c running" || bad "container $c running"
done

age=$(py <<'EOF'
import harrier, time; g = harrier.get_state(harrier.open_db(), "guard", {}); print(int(time.time() - g.get("checked_at", 0)))
EOF
)
[ "${age:-999}" -lt 30 ] && ok "guard heartbeat (${age}s ago)" || bad "guard heartbeat" "${age}s ago"
docker exec harrier-guard nft list table inet harrier >/dev/null 2>&1 && ok "firewall table present" || bad "firewall table present"

# Enforcement round trip with a reserved documentation address.
docker exec harrier python harrier.py block 192.0.2.250 >/dev/null
for i in $(seq 1 15); do docker exec harrier-guard nft list set inet harrier blocked4 2>/dev/null | grep -q 192.0.2.250 && break; sleep 1; done
docker exec harrier-guard nft list set inet harrier blocked4 2>/dev/null | grep -q 192.0.2.250 && ok "block reaches the firewall (${i}s)" || bad "block reaches the firewall"
docker exec harrier python harrier.py unblock 192.0.2.250
for i in $(seq 1 15); do docker exec harrier-guard nft list set inet harrier blocked4 2>/dev/null | grep -q 192.0.2.250 || break; sleep 1; done
docker exec harrier-guard nft list set inet harrier blocked4 2>/dev/null | grep -q 192.0.2.250 && bad "unblock clears the firewall" || ok "unblock clears the firewall (${i}s)"

refused=$(py <<'EOF'
import harrier; db = harrier.open_db()
print(all(not harrier.block(db, ip, "selftest", None, "manual", 0) for ip in ("192.168.1.1", "10.8.0.2", "127.0.0.1")))
EOF
)
[ "$refused" = True ] && ok "home/VPN/loopback can't be blocked" || bad "home/VPN/loopback can't be blocked"

# Web log flows into Harrier.
marker="/harrier-selftest-$RANDOM$RANDOM"
"${CURL[@]}" -o /dev/null "https://$SITE$marker"
for i in $(seq 1 40); do
  n=$(py "$marker" <<'EOF'
import harrier, sys; print(harrier.open_db().execute("select count(*) from traffic where path = ?", (sys.argv[1],)).fetchone()[0])
EOF
)
  [ "$n" -ge 1 ] && break; sleep 1
done
[ "${n:-0}" -ge 1 ] && ok "web request logged by Harrier (${i}s)" || bad "web request logged by Harrier" "not seen in 40s"

body=$("${CURL[@]}" -w '|%{http_code}' "https://$SITE/.env")
[[ "$body" == *"Notice to automated agents"*"|403" ]] && ok "probe gets the 403 notice" || bad "probe gets the 403 notice" "${body: -40}"
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "https://$SITE/")
[ "$code" = 200 ] && ok "site itself still works" || bad "site itself still works" "HTTP $code"

while IFS='|' read -r st msg; do [ "$st" = ok ] && ok "$msg" || bad "$msg"; done < <(py <<'EOF'
import harrier, time; db = harrier.open_db(); s = harrier.get_settings(db)
for d in s["domains"]:
    st = harrier.get_state(db, f"domain:{d}", {})
    age = time.time() - st.get("checked_at", 0)
    print(f"{'ok' if age < 1200 else 'bad'}|domain watch {d} ({int(age // 60)} min ago, {', '.join(st.get('problems', [])) or 'healthy'})")
EOF
)

model=$(py <<'EOF'
import harrier, requests
db = harrier.open_db(); m = harrier.get_settings(db)["model"]
try:
    tags = requests.get(f"{harrier.OLLAMA_URL}/api/tags", timeout=10).json()["models"]
    print("ok" if any(t["name"] == m for t in tags) else f"missing {m}")
except Exception as e:
    print(f"unreachable {e}")
EOF
)
[ "$model" = ok ] && ok "AI model available" || bad "AI model available" "$model"

[ "$(curl -s -o /dev/null -w '%{http_code}' $DASH/api/overview)" = 401 ] && ok "dashboard API needs login" || bad "dashboard API needs login"
[ "$(curl -s -o /dev/null -w '%{http_code}' $DASH/login)" = 200 ] && ok "dashboard login page" || bad "dashboard login page"

echo; echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
