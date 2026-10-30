#!/usr/bin/env bash
# Rebuild, run the full test suite against Postgres, and restart Harrier only if every test passes.
set -euo pipefail
cd "$(dirname "$0")"
log=$(mktemp)
trap 'rm -f "$log"' EXIT
docker compose build -q
docker compose up -d postgres
docker compose exec -T postgres sh -c 'psql -U harrier -tc "select 1 from pg_database where datname = '"'"'harrier_test'"'"'" | grep -q 1 || createdb -U harrier harrier_test'
# The password goes through the environment (-e NAME with no value), never into command arguments.
DATABASE_URL="postgresql://harrier:$(sed -n 's/^POSTGRES_PASSWORD=//p' .env | tail -1)@postgres:5432/harrier_test"
export DATABASE_URL
if ! docker compose run --rm -T -e DATABASE_URL harrier python tests/run.py > "$log" 2>&1; then
  grep -E '^(FAIL|ERR )|^     |passed in' "$log"
  echo "Tests failed: not deploying."; exit 1
fi
tail -1 "$log"
docker compose up -d "$@"
