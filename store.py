import base64
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager


DATA_DIR = os.environ.get("PM_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
os.makedirs(DATA_DIR, exist_ok=True)
DB_FILE = os.path.join(DATA_DIR, "proxy_manager.db")


@contextmanager
def connect():
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=10000")
    try:
        yield db
        db.commit()
    finally:
        db.close()


def init_db():
    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS working_keys (
                raw TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                security TEXT NOT NULL,
                network TEXT NOT NULL,
                country TEXT NOT NULL DEFAULT '',
                ping INTEGER,
                speed REAL,
                score INTEGER NOT NULL,
                checked_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                token TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                body TEXT NOT NULL,
                count INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS source_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                count INTEGER NOT NULL,
                checked_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                country TEXT NOT NULL,
                checked_at INTEGER NOT NULL
            );
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(working_keys)")}
        if "country" not in columns:
            db.execute("ALTER TABLE working_keys ADD COLUMN country TEXT NOT NULL DEFAULT ''")


def preferred_keys():
    with connect() as db:
        return {row["raw"] for row in db.execute(
            "SELECT raw FROM working_keys ORDER BY score DESC, checked_at DESC LIMIT 1000"
        )}


def save_result(item):
    info = item["info"]
    p = info["params"]
    with connect() as db:
        db.execute("""
            INSERT INTO working_keys
                (raw, name, host, port, security, network, country, ping, speed, score, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(raw) DO UPDATE SET
                name=excluded.name, host=excluded.host, port=excluded.port,
                security=excluded.security, network=excluded.network, country=excluded.country,
                ping=excluded.ping, speed=excluded.speed, score=excluded.score,
                checked_at=excluded.checked_at
        """, (
            info["raw"], info["name"] or f"{info['host']}:{info['port']}",
            info["host"], info["port"], p.get("security", "none"),
            p.get("type", "tcp"), info.get("country", ""),
            item.get("ping"), item.get("speed"),
            item["score"], int(time.time()),
        ))


def list_working(limit=100):
    with connect() as db:
        rows = db.execute(
            "SELECT * FROM working_keys ORDER BY score DESC, checked_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_source_counts(counts):
    now = int(time.time())
    with connect() as db:
        db.executemany(
            "INSERT INTO source_history(source, count, checked_at) VALUES (?, ?, ?)",
            [(source, count, now) for source, count in counts.items()],
        )


def get_geo(ips, max_age_days=30):
    ips = list(dict.fromkeys(ips))
    if not ips:
        return {}
    cutoff = int(time.time()) - max_age_days * 86400
    out = {}
    with connect() as db:
        for offset in range(0, len(ips), 500):
            chunk = ips[offset:offset + 500]
            marks = ",".join("?" for _ in chunk)
            rows = db.execute(
                f"SELECT ip, country FROM geo_cache WHERE checked_at >= ? AND ip IN ({marks})",
                [cutoff, *chunk],
            ).fetchall()
            out.update({row["ip"]: row["country"] for row in rows})
    return out


def save_geo(items):
    now = int(time.time())
    with connect() as db:
        db.executemany("""
            INSERT INTO geo_cache(ip, country, checked_at) VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                country=excluded.country, checked_at=excluded.checked_at
        """, [(ip, country, now) for ip, country in items.items() if country])


def create_subscription(keys, name, ttl_minutes=None):
    token = secrets.token_urlsafe(12)
    body = base64.b64encode("\n".join(keys).encode("utf-8")).decode("ascii")
    now = int(time.time())
    expires = now + ttl_minutes * 60 if ttl_minutes else None
    with connect() as db:
        db.execute(
            "INSERT INTO subscriptions VALUES (?, ?, ?, ?, ?, ?)",
            (token, name or "VLESS subscription", body, len(keys), now, expires),
        )
    return token, expires


def get_subscription(token):
    with connect() as db:
        row = db.execute("SELECT * FROM subscriptions WHERE token = ?", (token,)).fetchone()
    if not row or (row["expires_at"] and row["expires_at"] <= int(time.time())):
        return None
    return dict(row)
