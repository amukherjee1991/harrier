"""Copy data from a pre-1.0 Harrier (SQLite) into Postgres, so switching versions loses nothing.

  docker compose run --rm -v /path/to/old/data:/old:ro harrier python tools/migrate_from_sqlite.py /old/harrier.db

Incidents, blocks, learned patterns, device baselines, history and settings all come across.
Safe to re-run: tables that already have rows are skipped unless you pass --replace.
"""
import os
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import harrier  # noqa: E402

TABLES = ["state", "signals", "incidents", "blocks", "traffic", "weights", "intel", "devices", "dns_domains",
          "lessons", "actions", "checks"]
SERIAL = {"signals", "incidents", "traffic", "intel", "lessons", "actions", "checks"}
# Runtime state that belongs to the old install. Log read positions ("tail:") DO come across: both installs
# read the same host log files, and without them the new one would re-read recent logs and duplicate events.
SKIP_STATE = ("guard", "flows", "health_running", "health_request", "ai_busy")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    replace = "--replace" in sys.argv
    if not args or not os.path.exists(args[0]):
        sys.exit("usage: migrate_from_sqlite.py /path/to/harrier.db [--replace]")
    # Work on a copy: the source may be read-only and in WAL mode.
    tmp = tempfile.mkdtemp()
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(args[0] + suffix):
            shutil.copy(args[0] + suffix, os.path.join(tmp, "old.db" + suffix))
    src = sqlite3.connect(os.path.join(tmp, "old.db"))
    src.row_factory = sqlite3.Row
    dst = harrier.open_db()
    have = {r[0] for r in src.execute("select name from sqlite_master where type = 'table'")}
    for t in TABLES:
        if t not in have:
            continue
        existing = dst.execute(f"select count(*) from {t}").fetchone()[0]
        if existing and not replace:
            print(f"{t:12} skipped (already has {existing} rows; use --replace)")
            continue
        if replace:
            dst.execute(f"delete from {t}")
        src_cols = [r[1] for r in src.execute(f"pragma table_info({t})")]
        dst_cols = {r[0] for r in dst.execute("select column_name from information_schema.columns "
                                              "where table_name = ? and table_schema = current_schema()", (t,))}
        cols = [c for c in src_cols if c in dst_cols]
        rows = [tuple(r[c] for c in cols) for r in src.execute(f"select {', '.join(cols)} from {t}")]
        if t == "state":
            rows = [r for r in rows if not str(r[0]).startswith(SKIP_STATE)]
        dst.executemany(f"insert into {t} ({', '.join(cols)}) values ({', '.join('?' * len(cols))}) on conflict do nothing", rows)
        if t in SERIAL and rows:
            dst.execute(f"select setval(pg_get_serial_sequence('{t}', 'id'), (select max(id) from {t}))")
        print(f"{t:12} {len(rows)} rows")
    shutil.rmtree(tmp, ignore_errors=True)
    print("Done.")


if __name__ == "__main__":
    main()
