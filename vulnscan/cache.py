# vulnscan/cache.py
"""Simple SQLite cache wrapper used by cve lookup code.

DB path can be overridden for tests by setting the ENV var VULNSCAN_CACHE_DB.
"""
import sqlite3
import json
import os
from pathlib import Path
from typing import Optional

DEFAULT_DB = Path("vulnscan_cache.db")

def _db_path() -> Path:
    env = os.getenv("VULNSCAN_CACHE_DB")
    return Path(env) if env else DEFAULT_DB

def init_db() -> None:
    p = _db_path()
    con = sqlite3.connect(p)
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        response TEXT,
        fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    con.commit()
    con.close()

def get_cached(key: str) -> Optional[dict]:
    p = _db_path()
    if not p.exists():
        return None
    con = sqlite3.connect(p)
    cur = con.cursor()
    cur.execute("SELECT response FROM cache WHERE key=?", (key,))
    row = cur.fetchone()
    con.close()
    return json.loads(row[0]) if row else None

def set_cached(key: str, response: dict) -> None:
    p = _db_path()
    con = sqlite3.connect(p)
    cur = con.cursor()
    # ensure table exists (safe to call multiple times)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        response TEXT,
        fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    cur.execute("REPLACE INTO cache(key, response) VALUES (?, ?)", (key, json.dumps(response)))
    con.commit()
    con.close()
