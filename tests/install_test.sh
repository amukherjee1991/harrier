#!/usr/bin/env bash
# End-to-end install test on a throwaway "fresh machine": a Docker-in-Docker container with its own Docker engine,
# network and firewall, so nothing touches the host's containers or firewall.
#
#   tests/install_test.sh                 # test this checkout (tracked files, including uncommitted edits)
#   tests/install_test.sh <git-url>       # test a real clone, e.g. https://github.com/amukherjee1991/harrier
#   KEEP=1 tests/install_test.sh          # leave the test machine running afterwards for a look around
#
# Scenario A: no Ollama on the machine -> setup starts the bundled one.
# Scenario B: an Ollama container is already running -> setup shares it and must NOT start another.
# Each: fresh clone, ./setup.sh --yes, then sign-in, containers, a real firewall block, the model, re-running setup,
# and a simulated reboot. Needs internet (images and a ~1 GB model) and a few minutes.
set -uo pipefail
SRC=${1:-$(cd "$(dirname "$0")/.." && pwd)}
MODEL=${MODEL:-qwen3.5:0.8b}   # small, so the test is quick on a CPU
NAME=harrier-installtest
pass=0; fail=0
ok()  { echo "  PASS $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1${2:+ — $2}"; fail=$((fail + 1)); }
vm()  { docker exec "$NAME" sh -c "$1"; }

cleanup() { [ "${KEEP:-0}" = 1 ] || { docker rm -f "$NAME" >/dev/null 2>&1; docker volume rm -f "$NAME-docker" >/dev/null 2>&1; }; }
trap cleanup EXIT

echo "== Starting a fresh machine (Docker-in-Docker)"
docker rm -f "$NAME" >/dev/null 2>&1; docker volume rm -f "$NAME-docker" >/dev/null 2>&1
docker run -d --name "$NAME" --privileged -v "$NAME-docker:/var/lib/docker" docker:29.4.3-dind >/dev/null
for _ in $(seq 1 60); do vm "docker info >/dev/null 2>&1" && break; sleep 2; done
vm "docker info >/dev/null 2>&1" || { echo "inner Docker didn't start"; exit 1; }
vm "apk add --no-cache bash git curl python3 iproute2 >/dev/null" || { echo "couldn't install base tools"; exit 1; }

get_source() {  # $1 = target dir inside the machine
  if [ -d "$SRC" ]; then
    (cd "$SRC" && git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf -) | docker exec -i "$NAME" sh -c "rm -rf $1 && mkdir -p $1 && tar -xf - -C $1"
  else
    vm "rm -rf $1 && git clone -q '$SRC' $1"
  fi
}

check_install() {  # $1 = scenario label, $2 = expect bundled ollama (yes/no)
  local dir=/root/harrier out pw
  out=$(vm "cd $dir && HARRIER_MODEL=$MODEL ./setup.sh --yes 2>&1"); rc=$?
  [ $rc -eq 0 ] && ok "$1: ./setup.sh --yes exits 0" || { bad "$1: ./setup.sh --yes" "exit $rc"; echo "$out" | tail -20; return; }
  echo "$out" | grep -q "Sign in as 'admin'" && ok "$1: setup printed the admin sign-in" || bad "$1: admin sign-in printed"
  pw=$(vm "sed -n 's/^ADMIN_PASSWORD=//p' $dir/.env")
  [ ${#pw} -ge 20 ] && ok "$1: a real admin password was generated" || bad "$1: admin password" "got '${pw:0:12}…'"
  [ "$(vm "stat -c %a $dir/.env")" = 600 ] && ok "$1: .env is private (600)" || bad "$1: .env permissions"
  for c in harrier harrier-guard harrier-flows harrier-postgres; do
    [ "$(vm "docker inspect -f '{{.State.Running}}' $c 2>/dev/null")" = true ] && ok "$1: $c running" || bad "$1: $c running"
  done
  if [ "$2" = yes ]; then
    [ "$(vm "docker inspect -f '{{.State.Running}}' harrier-ollama 2>/dev/null")" = true ] && ok "$1: bundled Ollama started" || bad "$1: bundled Ollama started"
  else
    vm "docker inspect harrier-ollama >/dev/null 2>&1" && bad "$1: did NOT start a second Ollama" "harrier-ollama exists" || ok "$1: shared the existing Ollama, no second one"
  fi
  [ "$(vm "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/healthz")" = 200 ] && ok "$1: dashboard answers" || bad "$1: dashboard answers"
  vm "curl -s -c /tmp/cj -o /dev/null -d 'username=admin&password=$pw' http://127.0.0.1:8095/login"
  [ "$(vm "curl -s -b /tmp/cj -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/api/overview")" = 200 ] && ok "$1: sign-in with the printed password works" || bad "$1: sign-in works"
  [ "$(vm "curl -s -o /dev/null -w '%{http_code}' -d 'username=admin&password=wrong' http://127.0.0.1:8095/login -b /dev/null -c /tmp/cj2; curl -s -b /tmp/cj2 -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/api/overview" | tail -c 3)" = 401 ] && ok "$1: a wrong password is refused" || bad "$1: wrong password refused"
  vm "docker exec harrier python harrier.py block 192.0.2.250 >/dev/null"
  for _ in $(seq 1 20); do vm "docker exec harrier-guard nft list set inet harrier blocked4 2>/dev/null | grep -q 192.0.2.250" && break; sleep 1; done
  vm "docker exec harrier-guard nft list set inet harrier blocked4 2>/dev/null | grep -q 192.0.2.250" && ok "$1: a block reaches the firewall" || bad "$1: block reaches the firewall"
  vm "docker exec harrier python harrier.py unblock 192.0.2.250"
  vm "docker exec harrier python -c \"import requests,harrier; print([m['name'] for m in requests.get(harrier.OLLAMA_URL+'/api/tags',timeout=20).json()['models']])\"" | grep -q "$MODEL" \
    && ok "$1: the AI model is available ($MODEL)" || bad "$1: AI model available"
  # Re-running setup must keep the same secrets and still work.
  vm "cd $dir && HARRIER_MODEL=$MODEL ./setup.sh --yes >/dev/null 2>&1"
  [ "$(vm "sed -n 's/^ADMIN_PASSWORD=//p' $dir/.env")" = "$pw" ] && ok "$1: re-running setup keeps the same password" || bad "$1: re-run keeps password"
  # Simulated reboot: everything stops, the engine restarts the containers on its own.
  vm "docker stop -t 5 \$(docker ps -q) >/dev/null; docker start \$(docker ps -aq --filter label=com.docker.compose.project) >/dev/null 2>&1" ; sleep 1
  vm "cd $dir && docker compose up -d >/dev/null 2>&1"
  for _ in $(seq 1 60); do [ "$(vm "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/healthz")" = 200 ] && break; sleep 2; done
  [ "$(vm "curl -s -b /tmp/cj -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/api/overview")" = 200 ] && ok "$1: back after a restart, session still valid" || bad "$1: back after restart"
}

echo "== Scenario A: fresh machine, no Ollama"
get_source /root/harrier
check_install "A" yes
vm "cd /root/harrier && docker compose --profile ollama down -v >/dev/null 2>&1; rm -rf /root/harrier"

echo "== Scenario B: an Ollama is already running (shared with other apps)"
vm "docker network create apps >/dev/null 2>&1; docker run -d --name ollama --network apps -v ollama-models:/root/.ollama ollama/ollama:0.40.13 >/dev/null"
get_source /root/harrier
check_install "B" no

echo; echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
