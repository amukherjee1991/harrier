"""Postgres access for Harrier.

A thin wrapper so the rest of the code can write `db.execute(sql, params)` with `?` placeholders
and read rows by name (`row["ip"]`) or position (`row[0]`). Connections are autocommit; use
`with db.transaction():` (or `executemany`) when several writes must land together.
"""
import os
import re

import psycopg

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://harrier:harrier@postgres:5432/harrier")

SCHEMA = [
    """create table if not exists state (key text primary key, value text)""",
    """create table if not exists signals (
        id bigserial primary key, at double precision, source text, ip text, kind text, score integer,
        detail text, ua text, host text, fp text)""",
    "create index if not exists signals_ip on signals (ip, at)",
    "create index if not exists signals_at on signals (at)",
    "create index if not exists signals_fp on signals (fp, at)",
    """create table if not exists incidents (
        id bigserial primary key, key text, kind text, ip text, ips text default '[]', title text,
        severity text, score integer, first_at double precision, last_at double precision,
        signal_count integer default 0, status text default 'open', ai text, ai_at double precision,
        pending_action text, notes text default '')""",
    "create index if not exists incidents_key on incidents (key, status)",
    "create index if not exists incidents_ip on incidents (ip)",
    """create table if not exists blocks (
        ip text primary key, reason text, incident_id bigint, source text, created_at double precision,
        expires_at double precision, active integer default 1, times integer default 1)""",
    """create table if not exists traffic (
        id bigserial primary key, at double precision, source text, ip text, host text, method text, path text,
        status integer, ua text, detail text)""",
    "create index if not exists traffic_ip on traffic (ip, at)",
    "create index if not exists traffic_at on traffic (source, at)",
    """create table if not exists weights (
        kind text primary key, weight double precision default 1.0, confirmed integer default 0,
        false_alarms integer default 0)""",
    """create table if not exists intel (
        id bigserial primary key, kind text, value text, sources text, first_at double precision,
        hits integer default 0, active integer default 1, unique (kind, value))""",
    "create table if not exists devices (ip text primary key, name text, first_seen double precision, last_seen double precision)",
    "create table if not exists dns_domains (reg text primary key, first_seen double precision)",
    "create table if not exists lessons (id bigserial primary key, at double precision, kind text, detail text)",
    """create table if not exists actions (
        id bigserial primary key, at double precision, actor text, action text, target text, detail text)""",
    """create table if not exists checks (
        id bigserial primary key, run text, at double precision, suite text, name text, status text,
        detail text, seconds double precision)""",
    # Accounts
    """create table if not exists users (
        id bigserial primary key, username text unique not null, password_hash text not null,
        role text not null default 'viewer', created_at double precision, last_login_at double precision,
        failed_count integer default 0, locked_until double precision default 0, disabled integer default 0,
        palette text default 'harbor', must_change_password integer default 0)""",
    """create table if not exists sessions (
        token_hash text primary key, user_id bigint references users(id) on delete cascade,
        created_at double precision, last_seen_at double precision, expires_at double precision,
        ip text, user_agent text, revoked integer default 0)""",
    "create index if not exists sessions_user on sessions (user_id)",
    """create table if not exists login_events (
        id bigserial primary key, at double precision, username text, user_id bigint, ip text,
        user_agent text, success integer, reason text)""",
    "create index if not exists login_events_at on login_events (at)",
]


class Row(tuple):
    """A result row readable by column name or by position."""

    def __new__(cls, values, names):
        r = super().__new__(cls, values)
        r._names = names
        return r

    def __getitem__(self, key):
        if isinstance(key, str):
            return super().__getitem__(self._names[key])
        return super().__getitem__(key)

    def keys(self):
        return list(self._names)

    def get(self, key, default=None):
        return self[key] if key in self._names else default


def row_factory(cursor):
    names = {c.name: i for i, c in enumerate(cursor.description or [])}
    return lambda values: Row(values, names)


PLACEHOLDER = re.compile(r"\?")
NAMED = re.compile(r"(?<![:\w]):([A-Za-z_]\w*)")


def pg(sql, named=False):
    """SQLite-style `?` / `:name` placeholders to psycopg's `%s` / `%(name)s` (literal % doubled first)."""
    sql = sql.replace("%", "%%")
    return NAMED.sub(r"%(\1)s", sql) if named else PLACEHOLDER.sub("%s", sql)


class DB:
    def __init__(self, url=None, schema=None):
        opts = f"-c search_path={schema}" if schema else None
        self.conn = psycopg.connect(url or DATABASE_URL, autocommit=True, row_factory=row_factory, options=opts)

    def execute(self, sql, params=()):
        return self.conn.execute(pg(sql, isinstance(params, dict)), params)

    def executemany(self, sql, rows):
        rows = list(rows)
        if not rows:
            return
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.executemany(pg(sql, isinstance(rows[0], dict)), rows)

    def transaction(self):
        return self.conn.transaction()

    def commit(self):
        """Autocommit: every statement is already saved. Kept so callers read naturally."""

    def close(self):
        self.conn.close()


def connect(url=None, schema=None):
    db = DB(url, schema)
    return db


def create_schema(db):
    with db.transaction():
        db.execute("select pg_advisory_xact_lock(4242)")  # several containers start at once
        for stmt in SCHEMA:
            db.execute(stmt)
