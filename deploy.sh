#!/usr/bin/env bash
# Rebuild, run the full test suite against Postgres, and restart Harrier only if every test passes.
set -euo pipefail
cd "$(dirname "$0")"
docker compose build -q
docker compose up -d postgres
docker compose exec -T postgres sh -c 'psql -U harrier -tc "select 1 from pg_database where datname = '"'"'harrier_test'"'"'" | grep -q 1 || createdb -U harrier harrier_test'
PW=$(sed -n 's/^POSTGRES_PASSWORD=//p' .env)
if ! docker compose run --rm -T -e DATABASE_URL="postgresql://harrier:$PW@postgres:5432/harrier_test" harrier python tests/run.py > /tmp/harrier-tests.log 2>&1; then
  grep -E '^(FAIL|ERR )|^     |passed in' /tmp/harrier-tests.log
  echo "Tests failed: not deploying."; exit 1
fi
tail -1 /tmp/harrier-tests.log
docker compose up -d "$@"
