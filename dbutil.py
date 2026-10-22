"""PostgreSQL-Zugriff mit sqlite-ähnlicher API (?-Platzhalter, rowcount, lastrowid)."""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
except ImportError:  # pragma: no cover
    psycopg2 = None


INSERT_OR_IGNORE_RE = re.compile(
    r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+(\w+)\s*",
    re.IGNORECASE,
)


class CursorProxy:
    def __init__(self, cur, lastrowid=None):
        self._cur = cur
        self.rowcount = cur.rowcount
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def close(self):
        self._cur.close()


class PgConnection:
    def __init__(self, dsn: str):
        if psycopg2 is None:
            raise RuntimeError("psycopg2 fehlt – bitte python3-psycopg2 installieren")
        self.dsn = dsn
        self._local = threading.local()
        self._lock = threading.Lock()

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            conn = psycopg2.connect(self.dsn)
            conn.autocommit = False
            self._local.conn = conn
        return conn

    def _adapt(self, sql: str) -> str:
        text = sql
        match = INSERT_OR_IGNORE_RE.match(text)
        if match:
            table = match.group(1).lower()
            text = INSERT_OR_IGNORE_RE.sub(f"INSERT INTO {table} ", text, count=1)
            if table == "events" and "ON CONFLICT" not in text.upper():
                if "RETURNING" not in text.upper():
                    text = text.rstrip().rstrip(";") + " ON CONFLICT (ts, ip, kind) DO NOTHING RETURNING id"
                else:
                    text = text.rstrip().rstrip(";") + " ON CONFLICT (ts, ip, kind) DO NOTHING"
        text = text.replace("?", "%s")
        # Postgres braucht Alias bei DELETE … NOT IN (SELECT … LIMIT)
        if "DELETE FROM hits WHERE id NOT IN" in text and "AS _keep" not in text:
            text = text.replace(
                "DELETE FROM hits WHERE id NOT IN (SELECT id FROM hits ORDER BY ts DESC, id DESC LIMIT %s)",
                "DELETE FROM hits WHERE id NOT IN ("
                "SELECT id FROM (SELECT id FROM hits ORDER BY ts DESC, id DESC LIMIT %s) AS _keep)",
            )
        return text

    def execute(self, sql, params=()):
        conn = self._conn()
        try:
            cur = conn.cursor()
            adapted = self._adapt(sql)
            cur.execute(adapted, params or ())
        except Exception:
            conn.rollback()
            raise
        lastrowid = None
        if "RETURNING" in adapted.upper():
            row = cur.fetchone()
            if row:
                lastrowid = row[0]
                return CursorProxy(_OneRowCursor(row, 1), lastrowid=lastrowid)
            return CursorProxy(_OneRowCursor(None, 0), lastrowid=None)
        return CursorProxy(cur, lastrowid=lastrowid)

    def executemany(self, sql, seq_of_params):
        conn = self._conn()
        cur = conn.cursor()
        adapted = self._adapt(sql)
        # ON CONFLICT RETURNING makes executemany awkward – strip RETURNING for bulk
        adapted_bulk = re.sub(r"\s+RETURNING\s+id\s*$", "", adapted, flags=re.IGNORECASE)
        cur.executemany(adapted_bulk, list(seq_of_params))
        return CursorProxy(cur, lastrowid=None)

    def commit(self):
        self._conn().commit()

    def rollback(self):
        conn = getattr(self._local, "conn", None)
        if conn and not conn.closed:
            conn.rollback()

    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn and not conn.closed:
            conn.close()
            self._local.conn = None


class _OneRowCursor:
    def __init__(self, row, rowcount):
        self._row = row
        self.rowcount = rowcount if row is not None else 0
        self.description = [("id",)]
        self._done = False

    def fetchone(self):
        if self._done:
            return None
        self._done = True
        return self._row

    def fetchall(self):
        row = self.fetchone()
        return [row] if row else []

    def close(self):
        return


def connect_sqlite(path: Path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_schema(db, engine: str):
    if engine == "postgres":
        db.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id BIGSERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                ip TEXT NOT NULL,
                kind TEXT NOT NULL,
                cc TEXT,
                name TEXT,
                lat DOUBLE PRECISION,
                lon DOUBLE PRECISION,
                UNIQUE (ts, ip, kind)
            )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
        db.execute(
            """CREATE TABLE IF NOT EXISTS hits (
                id BIGSERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                ip TEXT NOT NULL,
                kind TEXT NOT NULL,
                role TEXT NOT NULL,
                org TEXT,
                org_name TEXT,
                cc TEXT,
                name TEXT,
                lat DOUBLE PRECISION,
                lon DOUBLE PRECISION,
                method TEXT,
                path TEXT,
                status INTEGER,
                bytes BIGINT,
                referer TEXT,
                ua TEXT,
                host TEXT
            )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS hits_ts ON hits(ts)")
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at BIGINT NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                ip TEXT,
                user_agent TEXT
            )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at)")
        db.execute(
            """CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"""
        )
        ensure_accounts(db, "postgres")
        db.commit()
    else:
        db.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                ip TEXT NOT NULL,
                kind TEXT NOT NULL,
                cc TEXT,
                name TEXT,
                lat REAL,
                lon REAL,
                UNIQUE(ts, ip, kind)
            )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
        db.execute(
            """CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                ip TEXT NOT NULL,
                kind TEXT NOT NULL,
                role TEXT NOT NULL,
                org TEXT,
                org_name TEXT,
                cc TEXT,
                name TEXT,
                lat REAL,
                lon REAL,
                method TEXT,
                path TEXT,
                status INTEGER,
                bytes INTEGER,
                referer TEXT,
                ua TEXT,
                host TEXT
            )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS hits_ts ON hits(ts)")
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                ip TEXT,
                user_agent TEXT
            )"""
        )
        db.execute(
            """CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"""
        )
        ensure_accounts(db, "sqlite")
        db.commit()


def ensure_accounts(db, engine: str):
    invites = """CREATE TABLE IF NOT EXISTS invites (
            id {pk},
            username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            binding TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_ip TEXT NOT NULL,
            admin_pw_hash TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL,
            used_at BIGINT
        )"""
    if engine == "postgres":
        db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'viewer'")
        db.execute(invites.format(pk="BIGSERIAL PRIMARY KEY"))
        return
    cols = [row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()]
    if "role" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'")
    db.execute(invites.format(pk="INTEGER PRIMARY KEY"))


def migrate_sqlite_to_pg(pg: PgConnection, sqlite_path: Path):
    if not sqlite_path.exists():
        return 0, 0
    count = pg.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if count:
        return 0, 0
    src = sqlite3.connect(str(sqlite_path))
    events = src.execute(
        "SELECT ts, ip, kind, cc, name, lat, lon FROM events ORDER BY id"
    ).fetchall()
    hits = src.execute(
        """SELECT ts, ip, kind, role, org, org_name, cc, name, lat, lon,
                  method, path, status, bytes, referer, ua, host FROM hits ORDER BY id"""
    ).fetchall()
    src.close()
    if events:
        pg.executemany(
            "INSERT INTO events (ts, ip, kind, cc, name, lat, lon) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT (ts, ip, kind) DO NOTHING",
            events,
        )
    if hits:
        pg.executemany(
            """INSERT INTO hits
               (ts, ip, kind, role, org, org_name, cc, name, lat, lon, method, path, status, bytes, referer, ua, host)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            hits,
        )
    pg.commit()
    return len(events), len(hits)


def open_database(database_url: str | None, sqlite_path: Path):
    url = (database_url or "").strip()
    if url:
        db = PgConnection(url)
        init_schema(db, "postgres")
        migrated = migrate_sqlite_to_pg(db, sqlite_path)
        return db, "postgres", migrated
    db = connect_sqlite(sqlite_path)
    init_schema(db, "sqlite")
    return db, "sqlite", (0, 0)
