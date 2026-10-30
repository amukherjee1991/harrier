#!/usr/bin/env bash
# Harrier setup: creates .env, finds what's already running, and starts Harrier.
#
#   ./setup.sh                          interactive
#   ./setup.sh --yes                    accept every default (no questions)
#   ./setup.sh --import /path/old.db    also bring over data from a pre-1.0 Harrier (SQLite)
#
# Ollama: if one is already running (in Docker or on this machine), Harrier uses it and does NOT
# start another. The bundled Ollama is only started when none is found.
set -euo pipefail
cd "$(dirname "$0")"

YES=0; IMPORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --import) IMPORT="${2:?--import needs a path}"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
  shift
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '  \033[33m! %s\033[0m\n' "$*"; }
ask() {  # ask "Question" default -> echoes answer
  local a
  if [ "$YES" = 1 ] || [ ! -t 0 ]; then echo "$2"; return; fi
  read -r -p "  $1 [$2] " a; echo "${a:-$2}"
}
# A value from .env: last assignment wins, surrounding spaces and any trailing "# comment" are ignored.
get() { sed -n "s/^$1=//p" .env | tail -1 | sed -e 's/[[:space:]]#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
set_env() {  # set_env KEY VALUE: replace or append, keeping the file private
  if grep -q "^$1=" .env; then
    # Values travel in the environment, not argv: other local users can read process arguments.
    SET_K="$1" SET_V="$2" python3 - <<'PY'
import os, re
k, v = os.environ["SET_K"], os.environ["SET_V"]
s = open(".env").read()
s = re.sub(rf"^{re.escape(k)}=.*$", lambda m: f"{k}={v}", s, count=1, flags=re.M)
open(".env", "w").write(s)
PY
  else
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
}
secret() { python3 -c 'import secrets; print(secrets.token_urlsafe(18))'; }

bold "Harrier setup"

# --- Requirements ---------------------------------------------------------------------------
command -v docker >/dev/null || { echo "Docker is required: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required (the 'docker compose' plugin)."; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required (only for this setup script)."; exit 1; }
[ "$(uname -s)" = Linux ] || warn "Blocking needs Linux (nftables). On other systems Harrier can watch but not block."

# --- .env -----------------------------------------------------------------------------------
umask 077
[ -f .env ] || { cp .env.example .env; info "Created .env from .env.example"; }
chmod 600 .env
[ -n "$(get POSTGRES_PASSWORD)" ] || set_env POSTGRES_PASSWORD "$(secret)"
NEW_ADMIN_PW=""
if [ -z "$(get ADMIN_PASSWORD)" ]; then
  set_env ADMIN_USERNAME "$(ask 'Admin username?' "$(get ADMIN_USERNAME | sed 's/^$/admin/')")"
  NEW_ADMIN_PW="$(secret)"; set_env ADMIN_PASSWORD "$NEW_ADMIN_PW"
fi
mkdir -p data/no-caddy data/no-kestrel
COMPOSE_FILES="docker-compose.yml"; PROFILES=""

# --- Ollama: reuse what's running ---------------------------------------------------------------
bold "Looking for Ollama"
OLLAMA_CONTAINER=$(docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /^ollama\/ollama/ && $1 != "harrier-ollama" {print $1; exit}')
if [ -n "$OLLAMA_CONTAINER" ]; then
  NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$OLLAMA_CONTAINER" | tr ' ' '\n' | grep -vxE 'bridge|host|none|' | head -1 || true)
  if [ -n "$NET" ]; then
    info "Found Ollama in container '$OLLAMA_CONTAINER' on network '$NET': sharing it."
    set_env OLLAMA_URL "http://$OLLAMA_CONTAINER:11434"; set_env EXTERNAL_NETWORK "$NET"
    COMPOSE_FILES="$COMPOSE_FILES:compose.network.yml"
  else
    PORT=$(docker port "$OLLAMA_CONTAINER" 11434/tcp 2>/dev/null | head -1 | sed 's/.*://')
    if [ -n "$PORT" ]; then
      info "Found Ollama in container '$OLLAMA_CONTAINER' published on port $PORT: sharing it."
      set_env OLLAMA_URL "http://host.docker.internal:$PORT"
    else
      warn "Ollama container '$OLLAMA_CONTAINER' is on the default bridge and not published. Put it on a user network or publish 11434, then rerun."
    fi
  fi
elif curl -s --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  info "Found Ollama running on this machine: sharing it."
  set_env OLLAMA_URL "http://host.docker.internal:11434"
  if ss -ltn 2>/dev/null | grep -q '127.0.0.1:11434'; then
    warn "It only listens on 127.0.0.1, which containers can't reach. Set OLLAMA_HOST=0.0.0.0 for the ollama service"
    warn "(sudo systemctl edit ollama -> Environment=\"OLLAMA_HOST=0.0.0.0\"), then restart it."
  fi
else
  info "No Ollama found: Harrier will run its own."
  set_env OLLAMA_URL "http://ollama:11434"; PROFILES="ollama"
  if command -v nvidia-smi >/dev/null && docker info 2>/dev/null | grep -qi nvidia; then
    info "NVIDIA GPU and container toolkit found: giving it to Ollama."; COMPOSE_FILES="$COMPOSE_FILES:compose.gpu.yml"
  fi
fi

# --- Model: suggest one that fits this machine ----------------------------------------------------
VRAM=$(command -v nvidia-smi >/dev/null && nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | sort -n | tail -1 || echo 0)
RAM=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 8)
if [ "${VRAM:-0}" -ge 10000 ]; then SUGGEST=gemma4:12b
elif [ "${VRAM:-0}" -ge 6000 ] || [ "$RAM" -ge 16 ]; then SUGGEST=qwen2.5:7b
else SUGGEST=gemma3:4b; fi
CUR=$(get MODEL); [ -n "$CUR" ] || CUR=$SUGGEST
info "GPU memory: ${VRAM:-0} MB, RAM: ${RAM} GB -> suggested model: $SUGGEST"
set_env MODEL "$(ask 'AI model?' "$CUR")"

# --- Pi-hole (optional) ---------------------------------------------------------------------------
PIHOLE_CONTAINER=$(docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /^pihole\/pihole/ {print $1; exit}')
if [ -n "$PIHOLE_CONTAINER" ] && [ -z "$(get PIHOLE_PASSWORD)" ]; then
  info "Found Pi-hole ('$PIHOLE_CONTAINER'). Add its admin password as PIHOLE_PASSWORD in .env to watch every device's DNS."
  set_env PIHOLE_URL "http://$PIHOLE_CONTAINER"
fi

# --- Home IPv6 -----------------------------------------------------------------------------------
# Private IPv4 ranges are always protected, but home devices may also use global IPv6 addresses from your ISP.
# Add this machine's global /64 prefixes to the never-block list so they're protected too.
V6=$(ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | python3 -c "
import sys, ipaddress
nets = sorted({str(ipaddress.ip_interface(l.strip()).network.supernet(new_prefix=64)) for l in sys.stdin if l.strip()
               if not ipaddress.ip_interface(l.strip()).ip.is_private})
print(','.join(nets))" 2>/dev/null || true)
if [ -n "$V6" ]; then
  CUR_ALLOW=$(get ALLOW)
  NEW_ALLOW=$(printf '%s,%s' "$CUR_ALLOW" "$V6" | tr ',' '\n' | grep -v '^$' | sort -u | paste -sd, -)
  set_env ALLOW "$NEW_ALLOW"; info "Protected your home IPv6 prefix(es): $V6"
fi

set_env COMPOSE_FILE "$COMPOSE_FILES"
set_env COMPOSE_PROFILES "$PROFILES"

# --- Start ------------------------------------------------------------------------------------
bold "Starting Harrier"
docker compose up -d --build
PORT=$(get HARRIER_PORT); PORT=${PORT:-8095}
for _ in $(seq 1 60); do curl -s "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 2; done
curl -s "http://127.0.0.1:$PORT/healthz" >/dev/null || { warn "Harrier didn't answer yet: docker compose logs harrier"; exit 1; }

MODEL=$(get MODEL)
HAVE=$(docker exec harrier python -c "import requests,harrier; print(any(m['name']=='$MODEL' for m in requests.get(harrier.OLLAMA_URL+'/api/tags',timeout=10).json()['models']))" 2>/dev/null || echo False)
if [ "$HAVE" != True ]; then
  if [ "$PROFILES" = ollama ] || [ "$(ask "Download $MODEL into your existing Ollama?" y)" = y ]; then
    info "Downloading $MODEL (several GB, this can take a while)..."
    docker exec harrier python -c "import requests,harrier; r=requests.post(harrier.OLLAMA_URL+'/api/pull',json={'name':'$MODEL','stream':False},timeout=7200); r.raise_for_status(); print('  done')"
  else
    warn "Pick or download a model later in Settings."
  fi
fi

if [ -n "$IMPORT" ]; then
  bold "Importing data from $IMPORT"
  docker compose run --rm -v "$(cd "$(dirname "$IMPORT")" && pwd):/old:ro" harrier python tools/migrate_from_sqlite.py "/old/$(basename "$IMPORT")"
fi

bold "Harrier is running: http://localhost:$PORT"
if [ -n "$NEW_ADMIN_PW" ]; then
  info "Sign in as '$(get ADMIN_USERNAME)' with this password (shown once, also in .env): $NEW_ADMIN_PW"
  info "Change it after signing in (Settings -> Your account)."
fi
